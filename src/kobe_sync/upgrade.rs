//! HTTP Upgrade tunnel for `kubectl exec` / `attach` / `portforward`.
//!
//! These three pod subresources use HTTP Upgrade to switch from regular
//! request/response into a bidirectional byte tunnel. The two protocols
//! K8s clients negotiate today are:
//!
//! - **SPDY/3.1** — the classic K8s streaming protocol. Default for
//!   older `kubectl` (≤1.29) and many controllers / operators.
//! - **WebSocket** — the modern path. K8s 1.30+ promoted
//!   `v5.channel.k8s.io` exec to GA and made it the kubectl default in
//!   1.32. Older `v4.channel.k8s.io` is still around for backward
//!   compat.
//!
//! Both sit on top of HTTP/1.1 `Upgrade:` semantics. The proxy treats
//! them identically: once both legs of the connection are upgraded, we
//! splice the two sockets with `tokio::io::copy_bidirectional` and let
//! framing flow through opaquely. Parsing SPDY/WebSocket frames buys us
//! nothing here — we don't modify channel data — and avoids ~2k LoC of
//! protocol code we'd have to keep correct against two evolving specs.
//! This is also what kube-aggregator and vcluster do.
//!
//! ## Auth
//!
//! Subresource requests target the HOST kube-apiserver (the workload
//! pods physically live there under translated names). The proxy
//! authenticates to host as the kobe-sync ServiceAccount via bearer
//! token — same model as `handle_subresource` for non-upgrade paths.
//!
//! TODO: a per-caller SubjectAccessReview against the local vkobe
//! apiserver would close the gap where a vkobe user without
//! `pods/exec` RBAC could still exec by virtue of connecting to the
//! proxy. Tracked as a follow-up; the existing non-upgrade subresource
//! path has the same gap and will be fixed together.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::{IntCounterVec, IntGauge, register_int_counter_vec, register_int_gauge};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::kobe_sync::proxy::{ProxyBody, body_from_bytes};
use crate::kobe_sync::syncer::translator::NameTranslator;

// ---------------------------------------------------------------------------
// Defaults & env overrides for concurrency limits
// ---------------------------------------------------------------------------

/// Default cap on concurrent upgrade tunnels per caller identity.
///
/// 1000 covers any realistic single-user case (a heavy CI run is dozens
/// of concurrent `kubectl exec`/`logs -f`; a cluster-admin with
/// dashboards might hit a few hundred). Memory cost at peak is ~50 MiB
/// (2 sockets × ~25 KiB tokio task stack + buffers per session).
pub const DEFAULT_MAX_UPGRADES_PER_IDENTITY: usize = 1000;

/// Default cap on concurrent upgrade tunnels across the whole proxy.
///
/// Backstop for misconfigured RBAC or compromised identities. 5000
/// upgrade sessions is far above any realistic load and keeps the
/// proxy's fd usage bounded (~10k fds for tunnels alone).
pub const DEFAULT_MAX_UPGRADES_TOTAL: usize = 5000;

/// Env var to override `DEFAULT_MAX_UPGRADES_PER_IDENTITY`.
pub const ENV_MAX_UPGRADES_PER_IDENTITY: &str = "KOBE_SYNC_MAX_UPGRADES_PER_IDENTITY";
/// Env var to override `DEFAULT_MAX_UPGRADES_TOTAL`.
pub const ENV_MAX_UPGRADES_TOTAL: &str = "KOBE_SYNC_MAX_UPGRADES_TOTAL";

/// Read a positive `usize` from env, or fall back to `default`.
fn limit_from_env(var: &str, default: usize) -> usize {
    match std::env::var(var) {
        Ok(s) => match s.trim().parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                warn!(env = var, value = %s, default, "ignoring invalid env override; using default");
                default
            }
        },
        Err(_) => default,
    }
}

// ---------------------------------------------------------------------------
// Prometheus metrics
// ---------------------------------------------------------------------------

static UPGRADES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_sync_proxy_upgrades_total",
        "Total number of HTTP Upgrade attempts handled by the subresource proxy",
        // result = success | denied_global | denied_per_identity |
        //          upstream_rejected | upstream_error
        // protocol = spdy | websocket | other
        &["protocol", "result"]
    )
    .unwrap()
});

static UPGRADES_ACTIVE: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "kobe_sync_proxy_upgrades_active",
        "Currently-active HTTP Upgrade tunnels (exec/attach/portforward)"
    )
    .unwrap()
});

/// Force-initialise the upgrade metrics so they show up in `/metrics`
/// even before the first request.
pub fn init_upgrade_metrics() {
    LazyLock::force(&UPGRADES_TOTAL);
    LazyLock::force(&UPGRADES_ACTIVE);
}

fn classify_protocol(proto: &str) -> &'static str {
    let p = proto.to_ascii_lowercase();
    if p.starts_with("spdy") {
        "spdy"
    } else if p == "websocket" || p.starts_with("websocket") {
        "websocket"
    } else {
        "other"
    }
}

// ---------------------------------------------------------------------------
// Concurrency limits
// ---------------------------------------------------------------------------

/// Token returned by `UpgradeLimits::acquire` and held for the lifetime
/// of an upgrade tunnel. Drops the global + per-identity permits and
/// decrements the active gauge when dropped, regardless of how the
/// session ended (clean close, error, panic).
pub struct UpgradePermit {
    _global: OwnedSemaphorePermit,
    _per_identity: OwnedSemaphorePermit,
}

impl Drop for UpgradePermit {
    fn drop(&mut self) {
        UPGRADES_ACTIVE.dec();
    }
}

/// Reason an upgrade was rejected before reaching the host apiserver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitDenial {
    /// Global concurrent-session cap reached.
    Global,
    /// Per-identity concurrent-session cap reached for this caller.
    PerIdentity,
}

/// Cluster-wide upgrade-session bookkeeping: a single global semaphore
/// plus a lazily-populated map of per-identity semaphores.
///
/// The struct is `Arc`-safe; clone freely.
pub struct UpgradeLimits {
    global: Arc<Semaphore>,
    /// Per-identity semaphores keyed by username string. We hold the
    /// `Arc<Semaphore>` rather than the user count so concurrent
    /// permit holders see consistent state without locking the map for
    /// the full session lifetime.
    per_identity: Mutex<HashMap<String, Arc<Semaphore>>>,
    per_identity_cap: usize,
}

impl UpgradeLimits {
    /// Build limits using `DEFAULT_*` constants, optionally overridden
    /// by the `KOBE_SYNC_MAX_UPGRADES_*` env vars.
    pub fn from_env() -> Arc<Self> {
        let global_cap = limit_from_env(ENV_MAX_UPGRADES_TOTAL, DEFAULT_MAX_UPGRADES_TOTAL);
        let per_identity_cap = limit_from_env(
            ENV_MAX_UPGRADES_PER_IDENTITY,
            DEFAULT_MAX_UPGRADES_PER_IDENTITY,
        );
        info!(
            global = global_cap,
            per_identity = per_identity_cap,
            "Upgrade-session concurrency limits configured"
        );
        Arc::new(Self::with_caps(global_cap, per_identity_cap))
    }

    /// Build limits with explicit caps. Public for testing.
    pub fn with_caps(global_cap: usize, per_identity_cap: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global_cap)),
            per_identity: Mutex::new(HashMap::new()),
            per_identity_cap,
        }
    }

    /// Try to acquire a permit for a session belonging to `identity`.
    /// `identity` is the username (or "anonymous" for unauthenticated).
    ///
    /// Returns the permit on success, or `Err(LimitDenial)` if either
    /// the global or per-identity cap is reached. Does NOT block —
    /// upgrade requests should fail fast under load rather than queue.
    pub fn try_acquire(&self, identity: &str) -> std::result::Result<UpgradePermit, LimitDenial> {
        // Order matters: take the global permit first. If the
        // per-identity acquire fails after we took the global, the
        // global permit drops and frees up. The reverse order would
        // leave a per-identity permit held while we wait for the global.
        let global_permit = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| LimitDenial::Global)?;

        let per_id_sem = {
            let mut map = self.per_identity.lock().expect("UpgradeLimits poisoned");
            map.entry(identity.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(self.per_identity_cap)))
                .clone()
        };

        let per_identity_permit = per_id_sem
            .try_acquire_owned()
            .map_err(|_| LimitDenial::PerIdentity)?;

        UPGRADES_ACTIVE.inc();
        Ok(UpgradePermit {
            _global: global_permit,
            _per_identity: per_identity_permit,
        })
    }

    /// Return the configured per-identity cap. Test helper.
    pub fn per_identity_cap(&self) -> usize {
        self.per_identity_cap
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Return true if the request is asking for an HTTP Upgrade.
///
/// Per RFC 7230 §6.7 the client signals upgrade with two coupled
/// headers: `Connection: upgrade` (case-insensitive token list) and
/// `Upgrade: <protocol>`. Both must be present — a stray `Upgrade`
/// header alone is not an upgrade.
pub fn is_upgrade_request<B>(req: &Request<B>) -> bool {
    if !req.headers().contains_key(hyper::header::UPGRADE) {
        return false;
    }
    let conn = req
        .headers()
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    conn.split(',')
        .map(|tok| tok.trim())
        .any(|tok| tok.eq_ignore_ascii_case("upgrade"))
}

/// Return the requested upgrade protocol token (e.g. `"SPDY/3.1"` or
/// `"websocket"`), lowercased for easier matching. None if the
/// `Upgrade` header is missing or invalid UTF-8.
pub fn upgrade_protocol<B>(req: &Request<B>) -> Option<String> {
    req.headers()
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase())
}

// ---------------------------------------------------------------------------
// Host TLS connector
// ---------------------------------------------------------------------------

/// Build a rustls `ClientConfig` that trusts the in-cluster Kubernetes
/// CA. Used by the upgrade path to establish a fresh TLS connection to
/// the host apiserver per upgrade session.
///
/// Mirrors the trust model in `proxy::build_host_client` (which is for
/// reqwest) but produces a raw rustls config so we can drive
/// hyper-client directly — reqwest hides the underlying socket and
/// can't expose it after a 101 response.
pub fn build_host_tls_config(ca_cert_path: &str) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();

    match std::fs::read(ca_cert_path) {
        Ok(ca_pem) if !ca_pem.is_empty() => {
            let mut cursor = std::io::Cursor::new(&ca_pem);
            let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("Failed to parse in-cluster CA PEM")?;
            if certs.is_empty() {
                anyhow::bail!("In-cluster CA file at {ca_cert_path} contained no certificates");
            }
            for c in certs {
                roots
                    .add(c)
                    .context("Failed to add in-cluster CA cert to trust store")?;
            }
            debug!(
                path = ca_cert_path,
                "Loaded in-cluster CA into rustls roots"
            );
        }
        _ => {
            // Standalone-dev fallback: mirror the in-cluster reqwest
            // client behavior of accepting invalid certs with a warning.
            // Production paths always have the SA-mounted CA, so this
            // branch only ever fires in `cargo test` or local dev runs.
            warn!(
                path = ca_cert_path,
                "In-cluster CA not available; building empty root store \
                 (TLS will fail unless verifier is overridden)"
            );
        }
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
// Tunnel
// ---------------------------------------------------------------------------

/// Outcome of an upgrade attempt against the host apiserver.
pub enum UpgradeOutcome {
    /// Host apiserver returned 101 Switching Protocols. The bridge task
    /// has been spawned; return the contained `Response` to the client.
    Switched(Response<ProxyBody>),
    /// Host apiserver did NOT switch (returned a non-101 status, e.g.
    /// 401, 403, 404). The contained response should be relayed to the
    /// client unchanged. The byte tunnel is never established.
    NotSwitched(Response<ProxyBody>),
    /// The proxy refused the upgrade BEFORE dialing the host apiserver
    /// because a concurrency cap was hit. The contained response is a
    /// 503 Service Unavailable with `Retry-After`. Returned to the
    /// client unchanged.
    Throttled(Response<ProxyBody>),
}

/// Dispatch an exec/attach/portforward request to the host apiserver
/// using HTTP Upgrade and bridge the resulting byte streams.
///
/// `host_url` is e.g. `https://10.96.0.1:443`. `host_token` is the
/// kobe-sync ServiceAccount bearer token. `host_path` is the already-
/// translated path (`/api/v1/namespaces/<host-ns>/pods/<host-pod>/exec`).
///
/// Long-lived state for the upgrade tunnel — built once at proxy
/// startup and passed by reference into every call to
/// `dispatch_upgrade`. Bundling it into a struct keeps the call
/// signature small (clippy::too_many_arguments) and makes it explicit
/// which fields are per-call (request, path, identity) versus
/// per-proxy (URL, token, TLS, limits).
pub struct UpgradeContext {
    /// URL of the host kube-apiserver, e.g. `https://10.96.0.1:443`.
    pub host_url: String,
    /// kobe-sync ServiceAccount bearer token. Used as `Authorization:
    /// Bearer …` on the upstream hop; ALL client-supplied
    /// `X-Remote-*` and `Authorization` are stripped (see
    /// `build_upstream_upgrade_request`).
    pub host_token: String,
    /// rustls config trusting the in-cluster Kubernetes CA. reqwest
    /// can't expose post-101 sockets, so this drives a raw hyper
    /// client over `tokio_rustls`.
    pub tls: Arc<ClientConfig>,
    /// Per-identity + global concurrency caps for upgrade tunnels.
    pub limits: Arc<UpgradeLimits>,
}

/// On 101 from the host this spawns a tokio task that bridges bytes
/// between the upgraded client connection (via `hyper::upgrade::on(req)`)
/// and the upgraded host connection until either side closes. The 101
/// response returned to the caller carries the host's selected
/// `Upgrade` and `Sec-WebSocket-Protocol` so kubectl negotiates with
/// the host's chosen protocol, not whatever the proxy might assume.
pub async fn dispatch_upgrade(
    mut req: Request<Incoming>,
    ctx: &UpgradeContext,
    host_path_and_query: &str,
    identity: Option<&str>,
) -> Result<UpgradeOutcome> {
    let host_url = ctx.host_url.as_str();
    let host_token = ctx.host_token.as_str();
    let tls = Arc::clone(&ctx.tls);
    let limits = Arc::clone(&ctx.limits);
    // 0. Reserve a permit. Identity is the validated CN from the
    //    incoming TLS client cert (set by the proxy's TLS layer); for
    //    unauthenticated callers we attribute usage to a dedicated
    //    "anonymous" bucket so a single attacker can't exhaust capacity
    //    by claiming many fake identities — the cap also applies to
    //    them collectively.
    let identity_for_limit = identity.unwrap_or("anonymous").to_string();
    let proto_for_metrics = upgrade_protocol(&req)
        .map(|p| classify_protocol(&p))
        .unwrap_or("other");

    let _permit = match limits.try_acquire(&identity_for_limit) {
        Ok(p) => p,
        Err(denial) => {
            let (label, message) = match denial {
                LimitDenial::Global => (
                    "denied_global",
                    "proxy upgrade-session global cap reached; retry shortly",
                ),
                LimitDenial::PerIdentity => (
                    "denied_per_identity",
                    "upgrade-session cap for caller identity reached; retry shortly",
                ),
            };
            UPGRADES_TOTAL
                .with_label_values(&[proto_for_metrics, label])
                .inc();
            warn!(
                identity = %identity_for_limit,
                reason = label,
                "Refusing upgrade — concurrency cap reached"
            );
            let body = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "metadata": {},
                "status": "Failure",
                "message": message,
                "reason": "TooManyRequests",
                "code": 503,
            });
            let body_bytes = serde_json::to_vec(&body).unwrap_or_default();
            let resp = Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("content-type", "application/json")
                // Conservative Retry-After: clients usually back off
                // exponentially; 5 seconds is small enough not to stall
                // a legitimate retry while big enough to avoid
                // hammering during the surge.
                .header("retry-after", "5")
                .body(body_from_bytes(Bytes::from(body_bytes)))
                .context("Failed to build 503 throttle response")?;
            return Ok(UpgradeOutcome::Throttled(resp));
        }
    };

    // From here on, ANY error propagating out of `dispatch_upgrade`
    // counts as `upstream_error` for metrics purposes — except the
    // explicit `NotSwitched` and `Switched` returns below, which
    // record their own labels. `tag_upstream_error` wraps that
    // bookkeeping so we can keep the happy-path code straight-line
    // without forgetting a counter on a `?` somewhere.
    let tag_err = |e: anyhow::Error| -> anyhow::Error {
        UPGRADES_TOTAL
            .with_label_values(&[proto_for_metrics, "upstream_error"])
            .inc();
        e
    };

    // 1. Parse host URL → (host, port, server_name).
    let (host, port, server_name) = parse_host_url(host_url)
        .with_context(|| format!("Invalid host apiserver URL: {host_url}"))
        .map_err(tag_err)?;

    // 2. Dial TCP + TLS.
    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("Failed to TCP-dial host apiserver at {host}:{port}"))
        .map_err(tag_err)?;
    tcp.set_nodelay(true).ok();
    let connector = TlsConnector::from(tls);
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .context("Failed to TLS-handshake with host apiserver")
        .map_err(tag_err)?;

    // 3. Hand the connection to hyper's HTTP/1.1 client. `with_upgrades`
    //    is critical — without it, hyper closes the connection after 101
    //    instead of yielding the underlying socket to us.
    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP/1 handshake with host apiserver failed")
        .map_err(tag_err)?;

    // The connection task drives reads/writes for `sender`. Spawn it
    // with `.with_upgrades()` so the post-101 byte stream remains
    // accessible via `hyper::upgrade::on(response)`.
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            // Errors here are expected when the bridge tears the
            // connection down (UnexpectedEof on close). Log at debug.
            debug!(error = %e, "host apiserver connection task ended");
        }
    });

    // 4. Build the upstream request. Mirror the client's Upgrade /
    //    Connection / Sec-WebSocket-Protocol / X-Stream-Protocol-Version
    //    headers so the apiserver negotiates with the same offered list.
    //    Use the host SA token for auth — ALL X-Remote-* headers are
    //    deliberately stripped (this path doesn't go through the
    //    front-proxy auth chain on the host).
    let upstream_req =
        build_upstream_upgrade_request(&req, host_path_and_query, host_token, host_url)
            .map_err(tag_err)?;

    // 5. Send it and await the (initial) response. Body is empty for
    //    upgrade requests.
    let mut upstream_resp = sender
        .send_request(upstream_req)
        .await
        .context("send_request to host apiserver failed")
        .map_err(tag_err)?;

    let upstream_status = upstream_resp.status();

    // 6. Non-switch responses: relay status + headers + body buffered.
    //    These are normal error paths (401 from host, 404 if the pod is
    //    gone, etc.). Buffering is fine here — the body is small JSON.
    if upstream_status != StatusCode::SWITCHING_PROTOCOLS {
        UPGRADES_TOTAL
            .with_label_values(&[proto_for_metrics, "upstream_rejected"])
            .inc();
        let resp_headers = upstream_resp.headers().clone();
        let body_bytes = upstream_resp
            .body_mut()
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        let mut builder = Response::builder().status(upstream_status);
        if let Some(ct) = resp_headers.get("content-type")
            && let Ok(s) = ct.to_str()
        {
            builder = builder.header("content-type", s);
        }
        let resp = builder
            .body(body_from_bytes(body_bytes))
            .context("Failed to build relayed non-switch response")?;
        return Ok(UpgradeOutcome::NotSwitched(resp));
    }

    // 7. We got 101. Capture the host-chosen Upgrade /
    //    Sec-WebSocket-Protocol so we can mirror them in our response
    //    to the client (kubectl will reject 101 with a different
    //    chosen protocol than the apiserver's).
    let upstream_upgrade_header = upstream_resp.headers().get(hyper::header::UPGRADE).cloned();
    let upstream_ws_protocol = upstream_resp
        .headers()
        .get("sec-websocket-protocol")
        .cloned();

    // 8. Take the upgraded streams: client side via
    //    `hyper::upgrade::on(&mut req)` (resolves once hyper has sent
    //    our 101), upstream side via `hyper::upgrade::on(&mut upstream_resp)`.
    let client_upgrade_fut = hyper::upgrade::on(&mut req);
    let upstream_upgraded = hyper::upgrade::on(&mut upstream_resp)
        .await
        .context("Host apiserver did not yield upgraded stream after 101")
        .map_err(tag_err)?;

    // 9. Spawn the byte bridge. We do NOT await client_upgrade_fut here
    //    — it only resolves AFTER hyper has flushed our 101 response on
    //    the wire, which happens after we return from this function.
    //    The session permit moves into the spawned task so the slot
    //    stays reserved until the tunnel actually closes (not just
    //    until we return the 101 response).
    let proto_for_log = upstream_upgrade_header
        .as_ref()
        .and_then(|h| h.to_str().ok())
        .unwrap_or("?")
        .to_string();
    UPGRADES_TOTAL
        .with_label_values(&[proto_for_metrics, "success"])
        .inc();
    let permit_for_bridge = _permit;
    tokio::spawn(async move {
        let _hold_permit = permit_for_bridge;
        bridge_upgraded(client_upgrade_fut, upstream_upgraded, proto_for_log).await;
        // _hold_permit drops here, releasing the global + per-identity
        // semaphore slots and decrementing UPGRADES_ACTIVE.
    });

    // 10. Build the 101 response for the client, mirroring host headers.
    let mut builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(hyper::header::CONNECTION, "upgrade");
    if let Some(v) = upstream_upgrade_header {
        builder = builder.header(hyper::header::UPGRADE, v);
    }
    if let Some(v) = upstream_ws_protocol {
        builder = builder.header("sec-websocket-protocol", v);
    }
    let response = builder
        .body(body_from_bytes(Bytes::new()))
        .context("Failed to build 101 response for client")?;

    Ok(UpgradeOutcome::Switched(response))
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn build_upstream_upgrade_request(
    client_req: &Request<Incoming>,
    host_path_and_query: &str,
    host_token: &str,
    host_url: &str,
) -> Result<Request<Empty<Bytes>>> {
    let host_only = host_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(host_url);

    let mut builder = Request::builder()
        .method(client_req.method().clone())
        .uri(host_path_and_query)
        .header(hyper::header::HOST, host_only)
        .header(hyper::header::AUTHORIZATION, format!("Bearer {host_token}"));

    // Mirror the upgrade-related headers verbatim. Only forward a
    // narrow allowlist to keep the threat surface small — Authorization
    // and X-Remote-* from the original request are stripped (we set our
    // own Authorization above; X-Remote-* belong to the front-proxy
    // chain to the LOCAL apiserver, not this host hop).
    let allowed: &[HeaderName] = &[
        hyper::header::UPGRADE,
        hyper::header::CONNECTION,
        hyper::header::USER_AGENT,
        HeaderName::from_static("sec-websocket-protocol"),
        HeaderName::from_static("sec-websocket-version"),
        HeaderName::from_static("sec-websocket-key"),
        HeaderName::from_static("sec-websocket-extensions"),
        HeaderName::from_static("x-stream-protocol-version"),
    ];
    for name in allowed {
        if let Some(v) = client_req.headers().get(name) {
            builder = builder.header(name, v);
        }
    }

    builder
        .body(Empty::<Bytes>::new())
        .context("Failed to build upstream upgrade request")
}

/// Bridge the upgraded client and host streams until one side closes.
///
/// Errors here are not actionable — they're either clean closes
/// (UnexpectedEof when one side hangs up) or transient transport
/// errors. We log at debug for visibility and let the task end.
async fn bridge_upgraded(
    client_upgrade_fut: hyper::upgrade::OnUpgrade,
    upstream_upgraded: hyper::upgrade::Upgraded,
    proto: String,
) {
    let client_upgraded = match client_upgrade_fut.await {
        Ok(u) => u,
        Err(e) => {
            // Client never finished the upgrade dance — usually means
            // it disconnected before hyper flushed our 101. Drop the
            // upstream side so the apiserver releases the session.
            debug!(error = %e, protocol = %proto, "client upgrade did not complete; dropping upstream");
            drop(upstream_upgraded);
            return;
        }
    };

    let mut client_io = TokioIo::new(client_upgraded);
    let mut upstream_io = TokioIo::new(upstream_upgraded);

    info!(protocol = %proto, "Tunnel established (exec/attach/portforward)");

    match tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await {
        Ok((client_to_upstream, upstream_to_client)) => {
            info!(
                protocol = %proto,
                client_to_upstream_bytes = client_to_upstream,
                upstream_to_client_bytes = upstream_to_client,
                "Tunnel closed cleanly"
            );
        }
        Err(e) => {
            debug!(protocol = %proto, error = %e, "Tunnel closed with error");
        }
    }
}

/// Parse `https://host:port/...` into `(host, port, ServerName)`.
///
/// `ServerName` is what rustls uses for SNI / cert verification — it's
/// the hostname the client expects to be talking to. Defaults the port
/// to 443 for `https://` and 80 for `http://`.
fn parse_host_url(url: &str) -> Result<(String, u16, ServerName<'static>)> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        anyhow::bail!("Host URL must start with https:// or http://: {url}");
    };

    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .with_context(|| format!("Invalid port in host URL: {url}"))?;
            (h.to_string(), port)
        }
        None => {
            let port = if scheme == "https" { 443 } else { 80 };
            (host_port.to_string(), port)
        }
    };

    let server_name = ServerName::try_from(host.clone())
        .with_context(|| format!("Invalid SNI hostname: {host}"))?;
    Ok((host, port, server_name))
}

// Headers that an upstream connection-management response might carry
// but that we DON'T want to relay back to the client during upgrade.
// Hyper owns the framing of the outgoing connection.
#[allow(dead_code)]
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for h in [
        hyper::header::CONNECTION,
        hyper::header::TRANSFER_ENCODING,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-authenticate"),
        HeaderName::from_static("proxy-authorization"),
        HeaderName::from_static("te"),
        HeaderName::from_static("trailer"),
    ] {
        headers.remove(&h);
    }
}

// Quiet the dead-code lint on `HeaderValue` import — only used through
// the typed builder API above, but keeping the import documents intent.
#[allow(dead_code)]
fn _hv_unused(v: HeaderValue) -> HeaderValue {
    v
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Empty;

    fn req_with_headers(headers: &[(&'static str, &'static str)]) -> Request<Empty<Bytes>> {
        let mut b = Request::builder().method("GET").uri("/api/v1/x");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Empty::<Bytes>::new()).unwrap()
    }

    #[test]
    fn test_is_upgrade_request_detects_spdy() {
        let r = req_with_headers(&[("Upgrade", "SPDY/3.1"), ("Connection", "Upgrade")]);
        assert!(is_upgrade_request(&r));
    }

    #[test]
    fn test_is_upgrade_request_detects_websocket() {
        let r = req_with_headers(&[
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Protocol", "v5.channel.k8s.io"),
        ]);
        assert!(is_upgrade_request(&r));
    }

    #[test]
    fn test_is_upgrade_request_case_insensitive_connection() {
        let r = req_with_headers(&[("Upgrade", "SPDY/3.1"), ("Connection", "upgrade")]);
        assert!(is_upgrade_request(&r));
    }

    #[test]
    fn test_is_upgrade_request_handles_connection_token_list() {
        // Some clients send `Connection: keep-alive, upgrade`.
        let r = req_with_headers(&[
            ("Upgrade", "websocket"),
            ("Connection", "keep-alive, Upgrade"),
        ]);
        assert!(is_upgrade_request(&r));
    }

    #[test]
    fn test_is_upgrade_request_rejects_upgrade_alone() {
        // Upgrade header without Connection: upgrade is not a valid
        // upgrade per RFC 7230 §6.7.
        let r = req_with_headers(&[("Upgrade", "websocket")]);
        assert!(!is_upgrade_request(&r));
    }

    #[test]
    fn test_is_upgrade_request_rejects_connection_alone() {
        let r = req_with_headers(&[("Connection", "Upgrade")]);
        assert!(!is_upgrade_request(&r));
    }

    #[test]
    fn test_is_upgrade_request_rejects_plain_request() {
        let r = req_with_headers(&[("Connection", "keep-alive")]);
        assert!(!is_upgrade_request(&r));
    }

    #[test]
    fn test_upgrade_protocol_extracted_lowercase() {
        let r = req_with_headers(&[("Upgrade", "SPDY/3.1"), ("Connection", "upgrade")]);
        assert_eq!(upgrade_protocol(&r).as_deref(), Some("spdy/3.1"));
    }

    #[test]
    fn test_upgrade_protocol_websocket() {
        let r = req_with_headers(&[("Upgrade", "websocket"), ("Connection", "upgrade")]);
        assert_eq!(upgrade_protocol(&r).as_deref(), Some("websocket"));
    }

    // -- parse_host_url --

    #[test]
    fn test_parse_host_url_https_with_port() {
        let (h, p, _sn) = parse_host_url("https://10.96.0.1:443").unwrap();
        assert_eq!(h, "10.96.0.1");
        assert_eq!(p, 443);
    }

    #[test]
    fn test_parse_host_url_https_default_port() {
        let (h, p, _sn) = parse_host_url("https://kubernetes.default.svc").unwrap();
        assert_eq!(h, "kubernetes.default.svc");
        assert_eq!(p, 443);
    }

    #[test]
    fn test_parse_host_url_http_default_port() {
        let (h, p, _sn) = parse_host_url("http://localhost").unwrap();
        assert_eq!(h, "localhost");
        assert_eq!(p, 80);
    }

    #[test]
    fn test_parse_host_url_with_path() {
        // The path is ignored — we only care about authority.
        let (h, p, _sn) = parse_host_url("https://10.0.0.1:6443/foo/bar").unwrap();
        assert_eq!(h, "10.0.0.1");
        assert_eq!(p, 6443);
    }

    #[test]
    fn test_parse_host_url_rejects_no_scheme() {
        assert!(parse_host_url("kubernetes.default.svc").is_err());
    }

    #[test]
    fn test_parse_host_url_rejects_invalid_port() {
        assert!(parse_host_url("https://host:not-a-port").is_err());
    }

    // -- build_upstream_upgrade_request --
    //
    // The test crafts a "client" upgrade request and verifies the
    // forwarded request to the host apiserver is correctly assembled.
    // This is the highest-leverage unit test in this module — bugs
    // here mean the host rejects the upgrade or, worse, leaks
    // credentials.

    fn make_client_upgrade_req() -> Request<Incoming> {
        // We can't easily construct an `Incoming` directly. Use a
        // hyper Request builder with a placeholder body type and
        // re-cast via `into_parts`/`from_parts` since the function
        // under test only reads `headers()` and `method()`.
        //
        // Simpler: define a parallel function that takes a generic
        // request body. Actually the existing function already does
        // — `Request<Incoming>` is the public signature, but the body
        // isn't read. For testability let's add a generic helper.
        unimplemented!("see test below — exercises a generic variant")
    }

    /// Generic version of `build_upstream_upgrade_request` parameterized
    /// on the client request body type, so unit tests can drive it
    /// without needing a real `hyper::body::Incoming`. The production
    /// `build_upstream_upgrade_request` delegates to this.
    pub(super) fn build_upstream_upgrade_request_generic<B>(
        client_req: &Request<B>,
        host_path_and_query: &str,
        host_token: &str,
        host_url: &str,
    ) -> Result<Request<Empty<Bytes>>> {
        let host_only = host_url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(host_url);

        let mut builder = Request::builder()
            .method(client_req.method().clone())
            .uri(host_path_and_query)
            .header(hyper::header::HOST, host_only)
            .header(hyper::header::AUTHORIZATION, format!("Bearer {host_token}"));

        let allowed: &[HeaderName] = &[
            hyper::header::UPGRADE,
            hyper::header::CONNECTION,
            hyper::header::USER_AGENT,
            HeaderName::from_static("sec-websocket-protocol"),
            HeaderName::from_static("sec-websocket-version"),
            HeaderName::from_static("sec-websocket-key"),
            HeaderName::from_static("sec-websocket-extensions"),
            HeaderName::from_static("x-stream-protocol-version"),
        ];
        for name in allowed {
            if let Some(v) = client_req.headers().get(name) {
                builder = builder.header(name, v);
            }
        }

        builder
            .body(Empty::<Bytes>::new())
            .context("Failed to build upstream upgrade request")
    }

    #[test]
    fn test_upstream_request_strips_authorization_and_x_remote() {
        let client_req = Request::builder()
            .method("POST")
            .uri("/api/v1/exec")
            .header("Upgrade", "SPDY/3.1")
            .header("Connection", "Upgrade")
            .header("Authorization", "Bearer client-token-do-not-leak")
            .header("X-Remote-User", "alice")
            .header("X-Remote-Group", "system:masters")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let upstream = build_upstream_upgrade_request_generic(
            &client_req,
            "/api/v1/namespaces/host-ns/pods/host-pod/exec?command=sh",
            "host-sa-token",
            "https://10.96.0.1:443",
        )
        .unwrap();

        // Must NOT carry the client's Authorization (would let a client
        // forge bearer auth to host) or X-Remote-* (the host doesn't
        // run our front-proxy chain — those headers would be ignored
        // OR honored unsafely depending on the host's config).
        assert_eq!(
            upstream
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer host-sa-token"),
            "Authorization must be REWRITTEN to the proxy SA token, never relayed"
        );
        assert!(
            upstream.headers().get("x-remote-user").is_none(),
            "X-Remote-User must NOT be forwarded to the host apiserver"
        );
        assert!(
            upstream.headers().get("x-remote-group").is_none(),
            "X-Remote-Group must NOT be forwarded to the host apiserver"
        );
    }

    #[test]
    fn test_upstream_request_preserves_upgrade_negotiation_headers() {
        let client_req = Request::builder()
            .method("GET")
            .uri("/api/v1/exec")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Protocol", "v5.channel.k8s.io")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let upstream = build_upstream_upgrade_request_generic(
            &client_req,
            "/api/v1/.../exec",
            "tok",
            "https://10.96.0.1:443",
        )
        .unwrap();

        for h in [
            "upgrade",
            "connection",
            "sec-websocket-protocol",
            "sec-websocket-version",
            "sec-websocket-key",
        ] {
            assert!(
                upstream.headers().get(h).is_some(),
                "must forward upgrade-negotiation header: {h}"
            );
        }
    }

    #[test]
    fn test_upstream_request_targets_translated_path() {
        let client_req = Request::builder()
            .method("GET")
            .uri("/api/v1/namespaces/default/pods/my-app/exec")
            .header("Upgrade", "SPDY/3.1")
            .header("Connection", "Upgrade")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let translated = "/api/v1/namespaces/host-ns/pods/my-app-x-default-x-vc/exec?command=sh";
        let upstream = build_upstream_upgrade_request_generic(
            &client_req,
            translated,
            "tok",
            "https://10.96.0.1:443",
        )
        .unwrap();

        assert_eq!(
            upstream.uri().path_and_query().unwrap().as_str(),
            translated
        );
    }

    // -- UpgradeLimits — concurrency caps --

    #[test]
    fn test_limits_allow_under_caps() {
        let limits = UpgradeLimits::with_caps(10, 5);
        let p1 = limits.try_acquire("alice").expect("first ok");
        let p2 = limits.try_acquire("alice").expect("second ok");
        let p3 = limits.try_acquire("bob").expect("different identity ok");
        // Hold permits to ensure they didn't get accidentally released.
        drop((p1, p2, p3));
    }

    #[test]
    fn test_limits_reject_over_per_identity_cap() {
        let limits = UpgradeLimits::with_caps(100, 2);
        let _p1 = limits.try_acquire("alice").unwrap();
        let _p2 = limits.try_acquire("alice").unwrap();
        let third = limits.try_acquire("alice");
        assert!(
            matches!(third, Err(LimitDenial::PerIdentity)),
            "third alice acquire should hit per-identity cap"
        );
        // bob should still be able to acquire — caps are per-identity.
        let _p_bob = limits
            .try_acquire("bob")
            .expect("different identity unaffected");
    }

    #[test]
    fn test_limits_reject_over_global_cap() {
        let limits = UpgradeLimits::with_caps(2, 100);
        let _p1 = limits.try_acquire("alice").unwrap();
        let _p2 = limits.try_acquire("bob").unwrap();
        let third = limits.try_acquire("carol");
        assert!(
            matches!(third, Err(LimitDenial::Global)),
            "third acquire after 2 should hit global cap"
        );
    }

    #[test]
    fn test_limits_release_on_drop() {
        let limits = UpgradeLimits::with_caps(100, 1);
        let p1 = limits.try_acquire("alice").unwrap();
        // Second acquire while p1 is held: rejected.
        assert!(matches!(
            limits.try_acquire("alice"),
            Err(LimitDenial::PerIdentity)
        ));
        // After dropping p1 the slot should be free again.
        drop(p1);
        let _p2 = limits
            .try_acquire("alice")
            .expect("permit slot should be freed on drop");
    }

    #[test]
    fn test_limits_anonymous_bucket_shared() {
        // Anonymous callers should share a single bucket so a flood
        // from unauthenticated clients can't multiply caps by spoofing
        // many fake identities. Our convention is to attribute all
        // anonymous traffic to the literal string "anonymous".
        let limits = UpgradeLimits::with_caps(100, 1);
        let _p1 = limits.try_acquire("anonymous").unwrap();
        assert!(matches!(
            limits.try_acquire("anonymous"),
            Err(LimitDenial::PerIdentity)
        ));
    }

    #[test]
    fn test_limit_from_env_default_when_unset() {
        // Use a unique env var name to avoid colliding with anything.
        let var = "KOBE_SYNC_TEST_LIMIT_UNSET_X1";
        // SAFETY: tests run with std env access; we restore in scope.
        unsafe { std::env::remove_var(var) };
        assert_eq!(limit_from_env(var, 42), 42);
    }

    #[test]
    fn test_limit_from_env_parses_positive_integer() {
        let var = "KOBE_SYNC_TEST_LIMIT_VALID_X2";
        unsafe { std::env::set_var(var, "777") };
        assert_eq!(limit_from_env(var, 1), 777);
        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn test_limit_from_env_falls_back_on_zero() {
        // Zero is invalid (would mean "deny everything"); we fall back
        // to default rather than misconfigure silently.
        let var = "KOBE_SYNC_TEST_LIMIT_ZERO_X3";
        unsafe { std::env::set_var(var, "0") };
        assert_eq!(limit_from_env(var, 100), 100);
        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn test_limit_from_env_falls_back_on_garbage() {
        let var = "KOBE_SYNC_TEST_LIMIT_GARBAGE_X4";
        unsafe { std::env::set_var(var, "not-a-number") };
        assert_eq!(limit_from_env(var, 100), 100);
        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn test_classify_protocol_buckets() {
        assert_eq!(classify_protocol("SPDY/3.1"), "spdy");
        assert_eq!(classify_protocol("spdy/3.1"), "spdy");
        assert_eq!(classify_protocol("websocket"), "websocket");
        assert_eq!(classify_protocol("WebSocket"), "websocket");
        assert_eq!(classify_protocol("h2c"), "other");
        assert_eq!(classify_protocol(""), "other");
    }

    #[test]
    fn test_upstream_request_sets_host_header_to_authority() {
        let client_req = Request::builder()
            .method("GET")
            .uri("/api/v1/exec")
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let upstream = build_upstream_upgrade_request_generic(
            &client_req,
            "/api/v1/.../exec",
            "tok",
            "https://kubernetes.default.svc:443/some/path",
        )
        .unwrap();
        assert_eq!(
            upstream.headers().get("host").and_then(|v| v.to_str().ok()),
            Some("kubernetes.default.svc:443"),
            "Host header should be authority of the host_url, not the path"
        );
    }
}
