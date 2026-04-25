use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::TryStreamExt;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use http_body_util::combinators::BoxBody;
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use prometheus::{
    Encoder, HistogramVec, IntCounterVec, TextEncoder, register_histogram_vec,
    register_int_counter_vec,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::kobe_sync::syncer::translator::NameTranslator;

// ---------------------------------------------------------------------------
// Response body types
// ---------------------------------------------------------------------------
//
// The proxy must STREAM upstream responses to the client rather than
// buffering them in memory: K8s `watch` and `logs -f` endpoints return
// chunked HTTP responses that may stay open indefinitely (until the
// client cancels). Buffering them with `resp.bytes().await` would break
// every controller / informer (they all use watch) and OOM the proxy on
// busy clusters.
//
// `ProxyBody` is a boxed, dynamically-typed `Body` so we can return either:
//   - `Full<Bytes>` for synthesized responses (errors, /healthz)
//   - `StreamBody<…>` wrapping reqwest's `bytes_stream()` for forwarded
//     responses, which propagates upstream chunks frame-by-frame and
//     cancels the upstream connection when the client disconnects.

/// Boxed error type used by the proxy's response body. Covers both
/// reqwest stream errors (transport went away mid-response) and any
/// other body adapter errors.
pub(crate) type ProxyError = Box<dyn std::error::Error + Send + Sync>;

/// Dynamic body type returned by every proxy handler. Lets the same
/// `Response<ProxyBody>` carry either a buffered `Full<Bytes>` (errors,
/// health, small synthesized payloads) or a streamed `StreamBody`
/// (forwarded apiserver responses) without forcing a buffered shape on
/// long-lived watches.
pub(crate) type ProxyBody = BoxBody<Bytes, ProxyError>;

/// Wrap `bytes` in a buffered `ProxyBody`. Used for tiny synthesized
/// responses (errors, /healthz, /metrics).
pub(crate) fn body_from_bytes(bytes: Bytes) -> ProxyBody {
    Full::new(bytes)
        .map_err(|e: Infallible| match e {})
        .boxed()
}

/// Convert an upstream `reqwest::Response` into a streamed
/// `Response<ProxyBody>`.
///
/// Preserves the upstream status code and a curated set of headers
/// relevant to the wire framing (`content-type`, `content-encoding`,
/// `content-length` if present, `cache-control`). The body is wrapped in
/// a `StreamBody` over `bytes_stream()` so chunks flow through to the
/// client as the apiserver emits them — essential for `watch` and
/// `logs -f`.
///
/// On any upstream chunk error the stream yields an error frame; hyper
/// then closes the client connection with a chunked-encoding terminator,
/// signaling the failure cleanly. Dropping the response body on the
/// client side cancels the upstream stream and closes the upstream
/// connection.
fn stream_upstream_response(resp: reqwest::Response) -> Response<ProxyBody> {
    let status = resp.status().as_u16();
    let resp_headers = resp.headers().clone();

    let stream = resp
        .bytes_stream()
        .map_ok(Frame::data)
        .map_err(|e| -> ProxyError { Box::new(e) });
    let body: ProxyBody = StreamBody::new(stream).boxed();

    let mut builder = Response::builder().status(status);
    // Forward only headers that affect how the client decodes the body
    // or caches it. Connection-management headers (Transfer-Encoding,
    // Connection, Keep-Alive) are intentionally NOT forwarded — hyper
    // owns the framing of the outgoing response and will pick whatever
    // makes sense for the client connection.
    for h in [
        "content-type",
        "content-encoding",
        "cache-control",
        "etag",
        "last-modified",
        "vary",
    ] {
        if let Some(v) = resp_headers.get(h) {
            if let Ok(s) = v.to_str() {
                builder = builder.header(h, s);
            }
        }
    }

    builder.body(body).unwrap_or_else(|_| {
        // The only way `builder.body()` fails is invalid headers we
        // already filtered for, but keep the fallback so the type
        // checker is happy and we never panic on a request path.
        error_response(StatusCode::INTERNAL_SERVER_ERROR, "Response build error")
    })
}

// ---------------------------------------------------------------------------
// TLS / Host client helpers
// ---------------------------------------------------------------------------

/// Path to the in-cluster Kubernetes CA certificate.
const IN_CLUSTER_CA_CERT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

/// Build an HTTP client configured for talking to the host Kubernetes API server.
///
/// When running in-cluster, loads the CA certificate from the service account
/// mount so that TLS verification works against the cluster's own CA.
/// When running outside a cluster (e.g., during development), falls back to
/// accepting invalid certificates with a warning.
pub fn build_host_client() -> anyhow::Result<reqwest::Client> {
    build_host_client_with_ca_path(IN_CLUSTER_CA_CERT_PATH)
}

/// Internal: build the client using the given CA cert path.
///
/// Factored out so tests can supply a custom path without overriding a const.
fn build_host_client_with_ca_path(ca_cert_path: &str) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();

    match std::fs::read(ca_cert_path) {
        Ok(ca_pem) if !ca_pem.is_empty() => match reqwest::Certificate::from_pem(&ca_pem) {
            Ok(cert) => {
                builder = builder.add_root_certificate(cert);
            }
            Err(e) => {
                warn!(
                    path = ca_cert_path,
                    error = %e,
                    "Failed to parse in-cluster CA certificate; \
                     falling back to danger_accept_invalid_certs for development"
                );
                builder = builder.danger_accept_invalid_certs(true);
            }
        },
        Ok(_) => {
            // File exists but is empty.
            warn!(
                path = ca_cert_path,
                "In-cluster CA certificate file is empty; \
                 falling back to danger_accept_invalid_certs for development"
            );
            builder = builder.danger_accept_invalid_certs(true);
        }
        Err(_) => {
            // File does not exist (not running in-cluster).
            warn!(
                path = ca_cert_path,
                "In-cluster CA certificate not found; \
                 falling back to danger_accept_invalid_certs for development"
            );
            builder = builder.danger_accept_invalid_certs(true);
        }
    }

    builder
        .build()
        .context("Failed to build HTTP client for host API server")
}

// ---------------------------------------------------------------------------
// Prometheus metrics for the proxy
// ---------------------------------------------------------------------------

static PROXY_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_sync_proxy_requests_total",
        "Total number of requests handled by the proxy",
        &["method", "status"]
    )
    .unwrap()
});

static PROXY_ERRORS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "kobe_sync_proxy_errors_total",
        "Total number of proxy errors",
        &["kind"]
    )
    .unwrap()
});

static PROXY_REQUEST_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "kobe_sync_proxy_request_duration_seconds",
        "Request duration in seconds",
        &["method"],
        vec![
            0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
        ]
    )
    .unwrap()
});

/// Force-initialize all proxy metrics so they are registered at startup.
pub fn init_proxy_metrics() {
    LazyLock::force(&PROXY_REQUESTS_TOTAL);
    LazyLock::force(&PROXY_ERRORS_TOTAL);
    LazyLock::force(&PROXY_REQUEST_DURATION);
}


// ---------------------------------------------------------------------------
// Host configuration helpers
// ---------------------------------------------------------------------------

/// Load the host Kubernetes API URL and service account token from the
/// standard in-cluster paths.
pub fn load_host_config() -> Result<(String, String)> {
    let host = std::env::var("KUBERNETES_SERVICE_HOST")
        .context("KUBERNETES_SERVICE_HOST not set (not running in-cluster?)")?;
    let port = std::env::var("KUBERNETES_SERVICE_PORT")
        .context("KUBERNETES_SERVICE_PORT not set (not running in-cluster?)")?;
    let token = std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
        .context("Failed to read service account token")?;
    Ok((format!("https://{host}:{port}"), token.trim().to_string()))
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

/// Build a simple 200 OK response with a text body.
fn ok_response(body: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(body_from_bytes(Bytes::from(body.to_string())))
        .unwrap()
}

/// Build an error response with the given status code and message in Kubernetes
/// Status format.
fn error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let body = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Status",
        "metadata": {},
        "status": "Failure",
        "message": message,
        "code": status.as_u16()
    });
    let body_bytes = serde_json::to_vec(&body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body_from_bytes(Bytes::from(body_bytes)))
        .unwrap()
}

// ---------------------------------------------------------------------------
// Body size limits
// ---------------------------------------------------------------------------

/// Maximum body size (bytes) the proxy will buffer from a client before
/// rejecting the request with 413 Payload Too Large.
///
/// Matches the upstream kube-apiserver default for `--max-request-bytes`
/// (3 MiB), which is the limit applied to request bodies for create and
/// update verbs and is comfortable for the largest realistic payloads
/// (Helm-encoded ConfigMaps/Secrets, big CRD apply manifests, decent-size
/// Job/Deployment specs).
///
/// Without this cap, `BodyExt::collect()` on the incoming hyper body would
/// allocate unbounded memory: a single attacker-controlled connection
/// could OOM the kobe-sync container by streaming an arbitrarily large
/// body into a single request.
pub(crate) const MAX_REQUEST_BODY_BYTES: usize = 3 * 1024 * 1024;

/// Buffer a body up to `limit` bytes, rejecting larger payloads.
///
/// On overflow returns a 413 Payload Too Large response in K8s `Status`
/// JSON shape. On other body errors returns 400. The caller substitutes
/// this response when this function returns `Err`.
///
/// Generic over any `hyper::body::Body<Data = Bytes>` so unit tests can
/// drive it with a synthetic `Full<Bytes>` body without spinning up a
/// real hyper server.
async fn collect_body_bounded<B>(
    body: B,
    limit: usize,
) -> Result<Bytes, Response<ProxyBody>>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let limited = Limited::new(body, limit);
    match limited.collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(e) => {
            // `Limited::collect()` errors with a boxed
            // `LengthLimitError` once the cap is exceeded; other errors
            // mean the underlying transport went away mid-body.
            let too_large = e
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some();
            if too_large {
                PROXY_ERRORS_TOTAL
                    .with_label_values(&["body_too_large"])
                    .inc();
                Err(error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &format!("request body exceeds proxy limit of {limit} bytes"),
                ))
            } else {
                PROXY_ERRORS_TOTAL.with_label_values(&["body_read"]).inc();
                Err(error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("failed to read request body: {e}"),
                ))
            }
        }
    }
}

/// Convenience wrapper around `collect_body_bounded` using
/// `MAX_REQUEST_BODY_BYTES` as the cap.
async fn collect_body_with_limit(body: Incoming) -> Result<Bytes, Response<ProxyBody>> {
    collect_body_bounded(body, MAX_REQUEST_BODY_BYTES).await
}

// ===========================================================================
// Subresource interception
// ===========================================================================
//
// Pod subresource requests (exec, logs, attach, portforward) target real
// running containers. In a vkobe virtual cluster the workload pods live in
// the host cluster under translated names, so we intercept these requests,
// rewrite the path, and proxy them to the host apiserver instead of the
// local one.

/// A parsed Pod subresource request (exec, logs, attach, portforward).
#[derive(Debug, Clone, PartialEq)]
pub struct SubresourceRequest {
    pub namespace: String,
    pub pod_name: String,
    pub subresource: String,
}

/// Subresources that kobe-sync intercepts and proxies to the host cluster.
const INTERCEPTED_SUBRESOURCES: &[&str] = &["exec", "attach", "portforward", "log"];

/// Parse a request path to detect if it targets an intercepted Pod subresource.
///
/// Matches: `/api/v1/namespaces/{ns}/pods/{name}/{subresource}`
///
/// Only pod subresources listed in [`INTERCEPTED_SUBRESOURCES`] are matched.
/// All other paths (including non-pod subresources like `services/*/proxy`)
/// return `None`.
pub fn parse_subresource(path: &str) -> Option<SubresourceRequest> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    // Expected: ["api", "v1", "namespaces", "{ns}", "pods", "{name}", "{subresource}"]
    if parts.len() == 7
        && parts[0] == "api"
        && parts[1] == "v1"
        && parts[2] == "namespaces"
        && parts[4] == "pods"
        && INTERCEPTED_SUBRESOURCES.contains(&parts[6])
    {
        return Some(SubresourceRequest {
            namespace: parts[3].into(),
            pod_name: parts[5].into(),
            subresource: parts[6].into(),
        });
    }
    None
}

/// Translate a virtual subresource request to the host cluster path.
///
/// Returns `(host_path, host_namespace)` where `host_path` is the full API path
/// targeting the translated pod name in the host namespace.
pub fn translate_subresource_to_host(
    sub: &SubresourceRequest,
    translator: &NameTranslator,
) -> (String, String) {
    let host_name = translator.to_host_name(&sub.pod_name, &sub.namespace);
    let host_ns = translator.host_namespace().to_string();
    let host_path = format!(
        "/api/v1/namespaces/{}/pods/{}/{}",
        host_ns, host_name, sub.subresource
    );
    (host_path, host_ns)
}

// ===========================================================================
// VirtualClusterProxyV2 — front-proxy gateway for vkobe virtual clusters
// ===========================================================================
//
// The proxy presents the virtual cluster's TLS endpoint to clients (kubectl,
// flux, controllers, …) and forwards requests to the LOCAL kube-apiserver
// running as a sidecar in the same pod. It uses the K8s "front-proxy"
// authentication pattern (the same one kube-aggregator uses for extension
// API servers) so that the local apiserver enforces RBAC against the
// caller's real identity rather than against the proxy's own credentials.
//
// Auth handoff:
//
//     client ──TLS w/ client-cert (signed by ca.crt)──> proxy
//                │
//                │ rustls validates cert against ca.crt
//                │ proxy parses Subject DN: CN → username, O → groups
//                │
//                └──mTLS w/ front-proxy-client cert───> local apiserver
//                       + X-Remote-User: <CN>
//                       + X-Remote-Group: <O>* (one per Organization RDN)
//
// The apiserver is configured with:
//   --requestheader-client-ca-file=/pki/front-proxy-ca.crt
//   --requestheader-allowed-names=front-proxy-client
//   --requestheader-username-headers=X-Remote-User
//   --requestheader-group-headers=X-Remote-Group
//   --requestheader-extra-headers-prefix=X-Remote-Extra-
//
// so it ONLY trusts the X-Remote-* headers when the underlying TLS
// connection presents the front-proxy-client cert. End-clients cannot spoof
// identity by injecting headers because their cert chain is not trusted by
// `requestheader-client-ca-file`.
//
// Pod subresource requests (exec/logs/attach/portforward) are intercepted
// and proxied to the HOST cluster's apiserver instead — the actual workload
// pods live in the host namespace under translated names.

/// Identity extracted from the peer's TLS client certificate.
///
/// Mirrors what kube-apiserver derives from a client cert:
/// - Subject CN → user name (RFC 1779 / RFC 2253 CN attribute)
/// - Subject O  → group(s); a cert may have multiple O attributes
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub username: String,
    pub groups: Vec<String>,
}

/// Reject any string that contains characters which could break HTTP header
/// framing or sneak in additional headers / impersonation attributes.
///
/// Belt-and-suspenders: `reqwest::RequestBuilder::header` already rejects
/// these via `HeaderValue::from_str`, but we want to fail fast with a
/// useful log line rather than silently dropping the value or panicking
/// somewhere deep in hyper. The cluster CA only ever signs certs we
/// generate ourselves (see `pki::generate_signed_cert`) — control chars
/// in CN/O would mean either a bug in our cert generation or a CA
/// compromise. Either way, refuse the identity.
fn header_value_is_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| !c.is_control() && c != '\r' && c != '\n' && c.is_ascii())
}

/// Parse a single peer cert (DER) and extract `(CN, [O])`.
///
/// Returns `None` if the cert can't be parsed, if the cert has no
/// recognizable identity (neither CN nor O), or if any of the extracted
/// values contain control characters that would be unsafe to inject into
/// HTTP headers.
pub fn extract_peer_identity_from_der(cert_der: &[u8]) -> Option<PeerIdentity> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let subject = cert.subject();

    let username = subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("")
        .to_string();

    let groups: Vec<String> = subject
        .iter_organization()
        .filter_map(|o| o.as_str().ok().map(|s| s.to_string()))
        .collect();

    if username.is_empty() && groups.is_empty() {
        return None;
    }

    // Reject anything that wouldn't be a valid HTTP header value — header
    // injection via a malformed Subject DN would let an attacker forge
    // X-Remote-Group entries or extra impersonation headers.
    if !username.is_empty() && !header_value_is_safe(&username) {
        warn!(
            "Rejecting peer cert: CN contains characters unsafe for HTTP header injection"
        );
        return None;
    }
    for g in &groups {
        if !header_value_is_safe(g) {
            warn!(
                "Rejecting peer cert: Organization contains characters unsafe for HTTP header injection"
            );
            return None;
        }
    }

    Some(PeerIdentity { username, groups })
}

/// Configuration for [`VirtualClusterProxyV2`].
pub struct ProxyConfigV2 {
    /// TLS server configuration (validates incoming client certs against
    /// the cluster CA via `WebPkiClientVerifier`).
    pub tls_config: Arc<rustls::ServerConfig>,
    /// URL of the local kube-apiserver sidecar (e.g. `https://127.0.0.1:6443`).
    pub apiserver_url: String,
    /// PEM-encoded cluster CA — used to verify the local apiserver's
    /// serving cert when the proxy connects to it via mTLS.
    pub apiserver_ca_pem: String,
    /// PEM-encoded front-proxy-client certificate (signed by
    /// `front-proxy-ca.crt`). Used as the proxy's client identity when
    /// connecting to the local apiserver.
    pub front_proxy_client_cert_pem: String,
    /// PEM-encoded front-proxy-client private key.
    pub front_proxy_client_key_pem: String,
    /// URL of the host kube-apiserver — used only for pod subresource
    /// proxying (exec/logs/attach/portforward).
    pub host_apiserver_url: String,
    /// ServiceAccount token for authenticating to the host apiserver
    /// during subresource proxying.
    pub host_token: String,
    /// Virtual-to-host name translator (subresource targeting).
    pub translator: Arc<NameTranslator>,
    /// Listen port for the HTTPS proxy.
    pub proxy_port: u16,
    /// Listen port for the plain-HTTP metrics/health server.
    pub metrics_port: u16,
}

/// Front-proxy gateway in front of a vkobe local kube-apiserver.
pub struct VirtualClusterProxyV2 {
    tls_acceptor: TlsAcceptor,
    apiserver_url: String,
    /// reqwest client pre-configured with mTLS (front-proxy-client identity)
    /// and the cluster CA root for verifying the local apiserver.
    apiserver_client: reqwest::Client,
    host_apiserver_url: String,
    host_token: String,
    /// reqwest client for talking to the host apiserver (subresource
    /// forwarding). Uses the in-cluster ServiceAccount token + CA.
    host_client: reqwest::Client,
    translator: Arc<NameTranslator>,
    proxy_port: u16,
    metrics_port: u16,
}

impl VirtualClusterProxyV2 {
    /// Build a new V2 proxy from the given configuration.
    pub fn new(config: ProxyConfigV2) -> Result<Self> {
        // mTLS client to local apiserver: present front-proxy-client cert,
        // verify the apiserver's serving cert against the cluster CA.
        let mut identity_pem = config.front_proxy_client_cert_pem.clone().into_bytes();
        if !identity_pem.ends_with(b"\n") {
            identity_pem.push(b'\n');
        }
        identity_pem.extend_from_slice(config.front_proxy_client_key_pem.as_bytes());
        let identity = reqwest::Identity::from_pem(&identity_pem)
            .context("Failed to parse front-proxy-client identity PEM")?;

        let apiserver_ca = reqwest::Certificate::from_pem(config.apiserver_ca_pem.as_bytes())
            .context("Failed to parse cluster CA PEM for apiserver verification")?;

        let apiserver_client = reqwest::Client::builder()
            .identity(identity)
            .add_root_certificate(apiserver_ca)
            // The local apiserver's serving cert SAN list contains
            // `localhost` and `127.0.0.1`, so name verification works
            // when we connect to https://127.0.0.1:6443.
            .build()
            .context("Failed to build mTLS client for local apiserver")?;

        let host_client = build_host_client()
            .context("Failed to build HTTP client for host apiserver subresource proxying")?;

        let tls_acceptor = TlsAcceptor::from(config.tls_config);

        Ok(Self {
            tls_acceptor,
            apiserver_url: config.apiserver_url,
            apiserver_client,
            host_apiserver_url: config.host_apiserver_url,
            host_token: config.host_token,
            host_client,
            translator: config.translator,
            proxy_port: config.proxy_port,
            metrics_port: config.metrics_port,
        })
    }

    /// Main run loop: accepts TLS connections, extracts peer identity, and
    /// serves HTTP requests with that identity attached as a request
    /// extension.
    pub async fn run(
        self: &Arc<Self>,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.proxy_port));
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind proxy listener on {addr}"))?;

        info!(addr = %addr, "Virtual API server (V2) listening (mTLS front-proxy)");

        let builder = ServerBuilder::new(TokioExecutor::new());

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("Proxy V2 shutdown signal received");
                    break;
                }
                result = listener.accept() => {
                    let (tcp_stream, peer_addr) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(error = %e, "Failed to accept TCP connection");
                            PROXY_ERRORS_TOTAL.with_label_values(&["accept"]).inc();
                            continue;
                        }
                    };

                    let tls_acceptor = self.tls_acceptor.clone();
                    let proxy = Arc::clone(self);
                    let builder = builder.clone();

                    tokio::spawn(async move {
                        let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                debug!(peer = %peer_addr, error = %e, "TLS handshake failed");
                                PROXY_ERRORS_TOTAL.with_label_values(&["tls"]).inc();
                                return;
                            }
                        };

                        // Extract peer identity from the rustls connection
                        // BEFORE handing off to hyper. The connection's
                        // peer_certificates() returns the chain the client
                        // presented; we identify the leaf as cert[0]. The
                        // verifier already validated the chain against
                        // ca.crt, so we just need to parse Subject DN.
                        let peer_identity = {
                            let (_io, conn) = tls_stream.get_ref();
                            conn.peer_certificates()
                                .and_then(|certs| certs.first())
                                .and_then(|leaf| extract_peer_identity_from_der(leaf.as_ref()))
                        };
                        let peer_identity = Arc::new(peer_identity);

                        let service = service_fn(move |mut req: Request<Incoming>| {
                            let proxy = Arc::clone(&proxy);
                            let peer_identity = Arc::clone(&peer_identity);
                            async move {
                                if let Some(id) = peer_identity.as_ref().clone() {
                                    req.extensions_mut().insert(id);
                                }
                                proxy.handle_request(req).await
                            }
                        });

                        let io = hyper_util::rt::TokioIo::new(tls_stream);
                        if let Err(e) = builder.serve_connection(io, service).await {
                            debug!(peer = %peer_addr, error = %e, "Connection error");
                        }
                    });
                }
            }
        }

        Ok(())
    }

    /// Serve plain-HTTP `/healthz`, `/readyz`, `/livez`, `/metrics`.
    ///
    /// Identical surface to V1's metrics server so the existing pod probes
    /// and Prometheus scrape config keep working.
    pub async fn run_metrics_server(
        &self,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.metrics_port));
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind metrics listener on {addr}"))?;

        info!(addr = %addr, "Metrics/health server (V2) listening (HTTP)");

        let builder = ServerBuilder::new(TokioExecutor::new());

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("Metrics server shutdown signal received");
                    break;
                }
                result = listener.accept() => {
                    let (tcp_stream, _peer_addr) = match result {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(error = %e, "Failed to accept metrics connection");
                            continue;
                        }
                    };

                    let builder = builder.clone();
                    tokio::spawn(async move {
                        let service = service_fn(|req: Request<Incoming>| async move {
                            let path = req.uri().path().to_string();
                            let response = match path.as_str() {
                                "/healthz" | "/readyz" | "/livez" => ok_response("ok"),
                                "/metrics" => {
                                    let encoder = TextEncoder::new();
                                    let metric_families = prometheus::gather();
                                    let mut buffer = Vec::new();
                                    let _ = encoder.encode(&metric_families, &mut buffer);
                                    let body =
                                        String::from_utf8(buffer).unwrap_or_default();
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header(
                                            "content-type",
                                            "text/plain; version=0.0.4; charset=utf-8",
                                        )
                                        .body(body_from_bytes(Bytes::from(body)))
                                        .unwrap_or_else(|_| ok_response(""))
                                }
                                _ => error_response(StatusCode::NOT_FOUND, "Not Found"),
                            };
                            Ok::<_, hyper::Error>(response)
                        });

                        let io = hyper_util::rt::TokioIo::new(tcp_stream);
                        if let Err(e) = builder.serve_connection(io, service).await {
                            debug!(error = %e, "Metrics connection error");
                        }
                    });
                }
            }
        }

        Ok(())
    }

    /// Top-level dispatch: route to subresource handler or local-apiserver
    /// forward.
    pub async fn handle_request(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<ProxyBody>, hyper::Error> {
        let start = std::time::Instant::now();
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        let response = if let Some(sub) = parse_subresource(&path) {
            self.handle_subresource(req, sub).await
        } else {
            self.forward_to_apiserver(req).await
        };

        let response = match response {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        let status = response.status().as_u16().to_string();
        let elapsed = start.elapsed().as_secs_f64();
        let method_str = method.as_str();

        PROXY_REQUESTS_TOTAL
            .with_label_values(&[method_str, &status])
            .inc();
        PROXY_REQUEST_DURATION
            .with_label_values(&[method_str])
            .observe(elapsed);

        Ok(response)
    }

    /// Forward a request to the LOCAL kube-apiserver via mTLS using the
    /// front-proxy-client identity, and inject `X-Remote-User` /
    /// `X-Remote-Group` headers carrying the original caller's identity
    /// (or anonymous if no client cert was presented).
    ///
    /// The response body is **streamed** chunk-by-chunk back to the
    /// client rather than buffered. This is mandatory for `watch`
    /// requests (long-poll, never close) and for `logs -f` / chunked
    /// responses, which would otherwise grow unbounded in proxy memory
    /// and never reach the client. When the client disconnects the
    /// `StreamBody` is dropped, which drops the upstream reqwest
    /// response, which closes the upstream connection — so abandoned
    /// watches don't leak fd's at the apiserver.
    async fn forward_to_apiserver(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<ProxyBody>, hyper::Error> {
        let uri = req.uri().clone();
        let method = req.method().clone();
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let target_url = format!("{}{}", self.apiserver_url, path);

        let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap();
        let identity = req.extensions().get::<PeerIdentity>().cloned();

        // Capture the headers we want to forward before consuming the body.
        let headers = req.headers().clone();
        // Enforce a hard cap on body size so a single attacker-controlled
        // connection cannot OOM the proxy by streaming an unbounded body.
        // See `MAX_REQUEST_BODY_BYTES`.
        let body_bytes = match collect_body_with_limit(req.into_body()).await {
            Ok(b) => b,
            Err(resp) => return Ok(resp),
        };

        let mut req_builder = self
            .apiserver_client
            .request(reqwest_method, &target_url);

        // Inject the validated peer-cert identity as front-proxy headers.
        // These are only honored by the apiserver because we connected
        // with the front-proxy-client cert (CN=front-proxy-client signed
        // by front-proxy-ca.crt); clients CANNOT set them themselves on
        // the wire because the proxy strips client-supplied X-Remote-*
        // headers in the loop below.
        //
        // When NO client cert was presented, deliberately do NOT inject
        // an explicit "system:anonymous" identity. Sending headers would
        // authenticate the request via requestheader auth, bypassing the
        // apiserver's own `--anonymous-auth` policy. Instead, leave the
        // headers off entirely so the apiserver's authentication chain
        // runs normally (anonymous-auth, if enabled, applies the canonical
        // system:anonymous + system:unauthenticated identity; if disabled,
        // the request is rejected with 401 — which is the correct
        // behavior).
        if let Some(id) = identity {
            req_builder = req_builder.header("X-Remote-User", id.username);
            for group in id.groups {
                req_builder = req_builder.header("X-Remote-Group", group);
            }
        }

        // Forward a narrow allowlist of pass-through headers.
        //
        // Explicitly NOT forwarded (privilege escalation vectors):
        //   - Authorization: would let a client supply a bearer token the
        //     apiserver might honor in addition to/instead of our headers.
        //   - X-Remote-User / X-Remote-Group / X-Remote-Extra-*: the
        //     apiserver would honor these (we presented the front-proxy
        //     cert) — clients cannot be allowed to forge their own
        //     identity.
        //
        // Forwarded:
        //   - Content negotiation (content-type, accept, accept-encoding).
        //   - Diagnostic / cache (user-agent, if-match, if-none-match,
        //     kubectl-command).
        //   - K8s impersonation (Impersonate-User/Group/Uid/Extra-*) is
        //     forwarded: the apiserver authorizes impersonation against
        //     the X-Remote-User identity via the `impersonate` verb in
        //     RBAC, so passing these through is safe and required for
        //     `kubectl --as` to work.
        for (name, value) in headers.iter() {
            let n = name.as_str().to_ascii_lowercase();
            let forward = matches!(
                n.as_str(),
                "content-type"
                    | "accept"
                    | "accept-encoding"
                    | "user-agent"
                    | "if-match"
                    | "if-none-match"
                    | "kubectl-command"
                    | "impersonate-user"
                    | "impersonate-group"
                    | "impersonate-uid"
            ) || n.starts_with("impersonate-extra-");
            if forward {
                if let Ok(v) = value.to_str() {
                    req_builder = req_builder.header(name.as_str(), v);
                }
            }
        }

        if !body_bytes.is_empty() {
            req_builder = req_builder.body(body_bytes.to_vec());
        }

        let resp = match req_builder.send().await {
            Ok(r) => r,
            Err(e) => {
                error!(error = %e, url = %target_url, "Failed to forward to local apiserver");
                PROXY_ERRORS_TOTAL.with_label_values(&["forward"]).inc();
                return Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("Proxy error: {e}"),
                ));
            }
        };

        Ok(stream_upstream_response(resp))
    }

    /// Forward a pod subresource (exec/logs/attach/portforward) to the
    /// HOST kube-apiserver, translating the pod name from virtual to host
    /// coordinates.
    ///
    /// Like `forward_to_apiserver`, the response body is **streamed**
    /// rather than buffered — `kubectl logs -f` is the canonical use case
    /// and would otherwise hang forever waiting for a body that never
    /// arrives.
    async fn handle_subresource(
        &self,
        req: Request<Incoming>,
        sub: SubresourceRequest,
    ) -> Result<Response<ProxyBody>, hyper::Error> {
        let (host_path, _host_ns) = translate_subresource_to_host(&sub, &self.translator);
        let query = req
            .uri()
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        let method = req.method().clone();

        info!(
            virtual_pod = %sub.pod_name,
            virtual_ns = %sub.namespace,
            host_path = %host_path,
            subresource = %sub.subresource,
            "Intercepting subresource request"
        );

        // TODO: exec/attach/portforward additionally need HTTP Upgrade
        // support (SPDY/3.1 or WebSocket v5.channel.k8s.io) — handled in
        // a separate follow-up. The current code supports `logs` (and
        // `logs -f` thanks to streaming below) but exec/attach return a
        // streamed body that the client will reject as malformed.

        let target_url = format!("{}{}{}", self.host_apiserver_url, host_path, query);

        let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap();
        // Same body cap as forward_to_apiserver. log/exec/attach/portforward
        // requests typically carry tiny bodies (or none), so the 3 MiB
        // ceiling is generous.
        let body_bytes = match collect_body_with_limit(req.into_body()).await {
            Ok(b) => b,
            Err(resp) => return Ok(resp),
        };

        let resp = match self
            .host_client
            .request(reqwest_method, &target_url)
            .bearer_auth(&self.host_token)
            .body(body_bytes.to_vec())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                PROXY_ERRORS_TOTAL.with_label_values(&["subresource"]).inc();
                return Ok(error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("Subresource proxy error: {e}"),
                ));
            }
        };

        Ok(stream_upstream_response(resp))
    }
}

// ===========================================================================
// V2 Tests
// ===========================================================================

#[cfg(test)]
mod tests_v2 {
    use super::*;

    // -- parse_subresource tests --

    #[test]
    fn test_detect_exec_subresource() {
        let path = "/api/v1/namespaces/default/pods/my-app/exec";
        let result = parse_subresource(path);
        assert!(result.is_some());
        let sub = result.unwrap();
        assert_eq!(sub.namespace, "default");
        assert_eq!(sub.pod_name, "my-app");
        assert_eq!(sub.subresource, "exec");
    }

    #[test]
    fn test_detect_logs_subresource() {
        let path = "/api/v1/namespaces/default/pods/my-app/log";
        let result = parse_subresource(path);
        assert!(result.is_some());
        let sub = result.unwrap();
        assert_eq!(sub.subresource, "log");
    }

    #[test]
    fn test_detect_portforward_subresource() {
        let path = "/api/v1/namespaces/default/pods/my-app/portforward";
        let result = parse_subresource(path);
        assert!(result.is_some());
        let sub = result.unwrap();
        assert_eq!(sub.subresource, "portforward");
    }

    #[test]
    fn test_detect_attach_subresource() {
        let path = "/api/v1/namespaces/default/pods/my-app/attach";
        let result = parse_subresource(path);
        assert!(result.is_some());
    }

    #[test]
    fn test_non_subresource_path() {
        let path = "/api/v1/namespaces/default/pods";
        assert!(parse_subresource(path).is_none());
    }

    #[test]
    fn test_non_pod_subresource_ignored() {
        // Only pod subresources are intercepted
        let path = "/api/v1/namespaces/default/services/my-svc/proxy";
        assert!(parse_subresource(path).is_none());
    }

    #[test]
    fn test_pod_list_not_intercepted() {
        let path = "/api/v1/namespaces/default/pods/my-app";
        assert!(parse_subresource(path).is_none());
    }

    #[test]
    fn test_non_intercepted_subresource_ignored() {
        // "status" is a valid pod subresource but not one we intercept
        let path = "/api/v1/namespaces/default/pods/my-app/status";
        assert!(parse_subresource(path).is_none());
    }

    #[test]
    fn test_root_path_not_intercepted() {
        let path = "/";
        assert!(parse_subresource(path).is_none());
    }

    #[test]
    fn test_healthz_not_intercepted() {
        let path = "/healthz";
        assert!(parse_subresource(path).is_none());
    }

    // -- translate_subresource_to_host tests --

    #[test]
    fn test_translate_subresource_path() {
        let translator = NameTranslator::new("pool-test".into());
        let sub = SubresourceRequest {
            namespace: "default".into(),
            pod_name: "my-app".into(),
            subresource: "exec".into(),
        };
        let (host_path, host_ns) = translate_subresource_to_host(&sub, &translator);
        assert_eq!(
            host_path,
            "/api/v1/namespaces/pool-test/pods/my-app-x-default-x-vc/exec"
        );
        assert_eq!(host_ns, "pool-test");
    }

    #[test]
    fn test_translate_portforward_subresource() {
        let translator = NameTranslator::new("pool-prod".into());
        let sub = SubresourceRequest {
            namespace: "kube-system".into(),
            pod_name: "coredns".into(),
            subresource: "portforward".into(),
        };
        let (host_path, host_ns) = translate_subresource_to_host(&sub, &translator);
        assert_eq!(
            host_path,
            "/api/v1/namespaces/pool-prod/pods/coredns-x-kube-system-x-vc/portforward"
        );
        assert_eq!(host_ns, "pool-prod");
    }

    #[test]
    fn test_translate_log_subresource() {
        let translator = NameTranslator::new("pool-dev".into());
        let sub = SubresourceRequest {
            namespace: "staging".into(),
            pod_name: "web-server".into(),
            subresource: "log".into(),
        };
        let (host_path, _) = translate_subresource_to_host(&sub, &translator);
        assert_eq!(
            host_path,
            "/api/v1/namespaces/pool-dev/pods/web-server-x-staging-x-vc/log"
        );
    }

    // -- extract_peer_identity_from_der tests --
    //
    // These exercise the front-proxy auth path: a client connects to the
    // V2 proxy with a TLS client cert; the proxy must extract Subject CN
    // (username) and Subject O (groups) and forward them as
    // X-Remote-User / X-Remote-Group impersonation headers.

    /// Build a self-signed DER-encoded cert with the given CN and Organization.
    /// Used as a stand-in for a client cert presented during mTLS.
    ///
    /// Note: rcgen's `DistinguishedName::push` replaces by `DnType`, so we
    /// only test the single-Organization shape here. That matches what
    /// `VkobeBackend::generate_client_cert` actually produces (CN=<name>-admin,
    /// O=system:masters). Multi-group certs would require lower-level DER
    /// construction; not worth it given the production code path is single-O.
    fn make_test_client_cert_der(cn: &str, org: Option<&str>) -> Vec<u8> {
        use rcgen::{CertificateParams, DnType, KeyPair};

        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, cn);
        if let Some(o) = org {
            params.distinguished_name.push(DnType::OrganizationName, o);
        }
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn test_extract_peer_identity_cn_only() {
        let der = make_test_client_cert_der("alice@example.com", None);
        let id = extract_peer_identity_from_der(&der).expect("should parse identity");
        assert_eq!(id.username, "alice@example.com");
        assert!(id.groups.is_empty());
    }

    #[test]
    fn test_extract_peer_identity_kubeconfig_admin_shape() {
        // Mirrors the kubeconfig client cert produced by VkobeBackend in
        // src/backend/vkobe.rs: CN=<name>-admin, O=system:masters. This is
        // the cert that flux/kubectl will present when bootstrapping a
        // virtual cluster, so the proxy must report it as a cluster-admin
        // identity to the local apiserver.
        let der = make_test_client_cert_der("ci-vkobe-flux-01-admin", Some("system:masters"));
        let id = extract_peer_identity_from_der(&der).expect("should parse identity");
        assert_eq!(id.username, "ci-vkobe-flux-01-admin");
        assert_eq!(id.groups, vec!["system:masters".to_string()]);
    }

    #[test]
    fn test_extract_peer_identity_invalid_der() {
        // Garbage bytes -> None, never panics.
        assert!(extract_peer_identity_from_der(b"not a real cert").is_none());
        assert!(extract_peer_identity_from_der(&[]).is_none());
    }

    // -- header_value_is_safe — header injection sanitization --

    #[test]
    fn test_header_value_is_safe_accepts_normal_identities() {
        assert!(header_value_is_safe("alice"));
        assert!(header_value_is_safe("system:masters"));
        assert!(header_value_is_safe("ci-vkobe-flux-01-admin"));
        assert!(header_value_is_safe("user@example.com"));
    }

    #[test]
    fn test_header_value_is_safe_rejects_empty() {
        assert!(!header_value_is_safe(""));
    }

    #[test]
    fn test_header_value_is_safe_rejects_crlf() {
        // The classic header-injection payload: a CRLF closes the
        // X-Remote-User header and opens a new one (e.g. an extra
        // X-Remote-Group: system:masters).
        assert!(!header_value_is_safe("alice\r\nX-Remote-Group: system:masters"));
        assert!(!header_value_is_safe("alice\rsystem:masters"));
        assert!(!header_value_is_safe("alice\nsystem:masters"));
    }

    #[test]
    fn test_header_value_is_safe_rejects_other_control_chars() {
        assert!(!header_value_is_safe("alice\0"));
        assert!(!header_value_is_safe("alice\t"));
        assert!(!header_value_is_safe("alice\x1b"));
    }

    #[test]
    fn test_header_value_is_safe_rejects_non_ascii() {
        // Conservative: reject anything outside ASCII to keep parity with
        // typical apiserver header expectations.
        assert!(!header_value_is_safe("álice"));
        assert!(!header_value_is_safe("👤"));
    }

    // -- collect_body_bounded — body-size DoS guard --

    #[tokio::test]
    async fn test_collect_body_bounded_accepts_under_limit() {
        let body = Full::new(Bytes::from(vec![b'x'; 100]));
        let result = collect_body_bounded(body, 1024).await;
        let bytes = result.expect("should accept body under the limit");
        assert_eq!(bytes.len(), 100);
    }

    #[tokio::test]
    async fn test_collect_body_bounded_accepts_at_exact_limit() {
        let body = Full::new(Bytes::from(vec![b'x'; 1024]));
        let result = collect_body_bounded(body, 1024).await;
        assert!(
            result.is_ok(),
            "body equal to the cap should be accepted, not rejected"
        );
    }

    #[tokio::test]
    async fn test_collect_body_bounded_rejects_over_limit_with_413() {
        // Single attacker-controlled connection trying to OOM the proxy
        // with a 1 KiB body when the cap is 100 bytes.
        let body = Full::new(Bytes::from(vec![b'x'; 1024]));
        let result = collect_body_bounded(body, 100).await;
        let resp = result.expect_err("should be rejected as too large");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // Body should be a K8s-style Status response so kubectl/clients
        // see a structured error, not a bare HTTP message.
        let body_bytes = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(v["kind"], "Status");
        assert_eq!(v["status"], "Failure");
        assert_eq!(v["code"], 413);
    }

    #[tokio::test]
    async fn test_collect_body_bounded_zero_limit_rejects_any_body() {
        // Edge case: a 0-byte cap rejects any non-empty body. (Empty
        // body: no Frame is yielded, so `Limited` never errors and we
        // return an empty Bytes. The hyper Body trait permits a body
        // that produces no frames for size_hint.)
        let body = Full::new(Bytes::from_static(b"x"));
        let result = collect_body_bounded(body, 0).await;
        let resp = result.expect_err("non-empty body should fail with cap=0");
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn test_max_request_body_bytes_matches_apiserver_default() {
        // Belt-and-suspenders: lock in the canonical kube-apiserver
        // request-body limit (3 MiB). Bumping this should be a deliberate
        // policy decision, not a silent change.
        assert_eq!(MAX_REQUEST_BODY_BYTES, 3 * 1024 * 1024);
    }

    // -- streaming response bodies --
    //
    // These tests assert the proxy DOES stream rather than buffer. The
    // distinction matters because watch/logs -f bodies never close: a
    // buffering proxy hangs forever; a streaming proxy delivers chunks
    // as they arrive at the apiserver.

    /// Drive a `ProxyBody` to completion and return all data frames as a
    /// `Vec<Bytes>` so tests can assert per-frame delivery (i.e. the
    /// body wasn't silently coalesced into one big chunk).
    async fn collect_frames(body: ProxyBody) -> Vec<Bytes> {
        let mut frames: Vec<Bytes> = Vec::new();
        let mut body = body;
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        frames.push(data);
                    }
                }
                Some(Err(_)) | None => break,
            }
        }
        frames
    }

    #[tokio::test]
    async fn test_body_from_bytes_is_a_proxybody() {
        // Buffered synthesized responses (errors, /healthz) round-trip
        // through ProxyBody as a single frame, no streaming overhead.
        let body = body_from_bytes(Bytes::from_static(b"hello"));
        let frames = collect_frames(body).await;
        let total: Vec<u8> = frames.iter().flat_map(|f| f.iter().copied()).collect();
        assert_eq!(total, b"hello");
    }

    #[tokio::test]
    async fn test_streamed_body_delivers_multiple_frames() {
        use futures::stream;
        // Synthesize a multi-chunk stream — exactly the shape of a
        // chunked HTTP watch response (one frame per event).
        let chunks: Vec<Result<Bytes, ProxyError>> = vec![
            Ok(Bytes::from_static(b"{\"type\":\"ADDED\"}\n")),
            Ok(Bytes::from_static(b"{\"type\":\"MODIFIED\"}\n")),
            Ok(Bytes::from_static(b"{\"type\":\"DELETED\"}\n")),
        ];
        let stream = stream::iter(chunks).map_ok(Frame::data);
        let body: ProxyBody = StreamBody::new(stream).boxed();

        let frames = collect_frames(body).await;
        assert_eq!(frames.len(), 3, "expected 3 separate frames, got {frames:?}");
        assert_eq!(frames[0], Bytes::from_static(b"{\"type\":\"ADDED\"}\n"));
        assert_eq!(frames[1], Bytes::from_static(b"{\"type\":\"MODIFIED\"}\n"));
        assert_eq!(frames[2], Bytes::from_static(b"{\"type\":\"DELETED\"}\n"));
    }

    /// Spin up a minimal HTTP/1.1 server that writes a chunked response
    /// with timed chunks, returning its bound `SocketAddr`. The server
    /// accepts exactly one connection and then exits.
    ///
    /// Used to drive `stream_upstream_response` end-to-end with a real
    /// `reqwest::Response`, asserting the response actually streams from
    /// the wire rather than buffering. A pure-stream-mock test (above)
    /// can prove `StreamBody` does the right thing in isolation but
    /// cannot prove the reqwest → StreamBody seam.
    async fn spawn_chunked_server(
        status_line: &'static str,
        headers: &'static [&'static str],
        chunks: Vec<&'static [u8]>,
    ) -> std::net::SocketAddr {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Drain request bytes (we don't care what kind of request).
            // Wait briefly for the request line + headers; that's enough
            // for reqwest to send the request.
            let mut buf = [0u8; 1024];
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                tokio::io::AsyncReadExt::read(&mut sock, &mut buf),
            )
            .await;

            sock.write_all(format!("{status_line}\r\n").as_bytes())
                .await
                .unwrap();
            for h in headers {
                sock.write_all(format!("{h}\r\n").as_bytes()).await.unwrap();
            }
            sock.write_all(b"Transfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            for chunk in chunks {
                sock.write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await
                    .unwrap();
                sock.write_all(chunk).await.unwrap();
                sock.write_all(b"\r\n").await.unwrap();
                // Flush so reqwest sees each chunk as it arrives —
                // critical to test that streaming works (vs. the kernel
                // coalescing all writes into one segment).
                sock.flush().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            sock.write_all(b"0\r\n\r\n").await.unwrap();
            sock.flush().await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn test_stream_upstream_response_proxies_chunked_body() {
        // End-to-end: a real chunked HTTP server (the apiserver
        // analogue) → reqwest → stream_upstream_response → ProxyBody →
        // collect_frames. Asserts:
        //   - Status code is preserved.
        //   - content-type header is preserved.
        //   - All bytes from all chunks flow through.
        //   - Connection-management headers (Transfer-Encoding) are
        //     NOT forwarded (hyper owns the outgoing framing).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let addr = spawn_chunked_server(
            "HTTP/1.1 200 OK",
            &["Content-Type: application/json"],
            vec![
                b"{\"type\":\"ADDED\"}\n",
                b"{\"type\":\"MODIFIED\"}\n",
                b"{\"type\":\"DELETED\"}\n",
            ],
        )
        .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect("upstream request");

        let response = stream_upstream_response(resp);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert!(
            response.headers().get("transfer-encoding").is_none(),
            "Transfer-Encoding from upstream must NOT be propagated; \
             hyper owns outgoing connection framing"
        );

        let frames = collect_frames(response.into_body()).await;
        let total: Vec<u8> = frames.iter().flat_map(|f| f.iter().copied()).collect();
        assert_eq!(
            total,
            b"{\"type\":\"ADDED\"}\n{\"type\":\"MODIFIED\"}\n{\"type\":\"DELETED\"}\n"
        );
    }

    #[tokio::test]
    async fn test_stream_upstream_response_preserves_status_code() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let addr = spawn_chunked_server(
            "HTTP/1.1 404 Not Found",
            &["Content-Type: application/json"],
            vec![b"{\"kind\":\"Status\",\"code\":404}"],
        )
        .await;

        let client = reqwest::Client::new();
        let resp = client.get(format!("http://{addr}/")).send().await.unwrap();
        let response = stream_upstream_response(resp);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_streamed_body_propagates_errors() {
        use futures::stream;
        // Simulate the apiserver dropping mid-stream (e.g. its TCP
        // connection died). The proxy must surface the error rather
        // than silently truncate, so hyper closes the client connection
        // with a chunked-encoding error rather than a clean EOF that
        // looks like end-of-watch.
        let err: ProxyError = "upstream connection reset".into();
        let chunks: Vec<Result<Bytes, ProxyError>> = vec![
            Ok(Bytes::from_static(b"{\"type\":\"ADDED\"}\n")),
            Err(err),
        ];
        let stream = stream::iter(chunks).map_ok(Frame::data);
        let body: ProxyBody = StreamBody::new(stream).boxed();

        let mut body = body;
        let first = body.frame().await.expect("first frame").expect("first ok");
        assert_eq!(first.into_data().unwrap(), Bytes::from_static(b"{\"type\":\"ADDED\"}\n"));
        let second = body.frame().await.expect("second frame");
        assert!(second.is_err(), "second frame must propagate the upstream error");
    }
}
