use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use prometheus::{
    register_histogram_vec, register_int_counter_vec, Encoder, HistogramVec, IntCounterVec,
    TextEncoder,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::kobe_sync::syncer::translator::NameTranslator;

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
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
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
// v1 API path parsing & proxy infrastructure
// ---------------------------------------------------------------------------
// TODO(v2-migration): The v1 proxy (ApiPath, parse_api_path, ProxyConfig,
// VirtualClusterProxy, translate_path, translate_request_body,
// translate_response_body, etc.) is still used by the kobe_sync binary.
// Replace with VirtualClusterProxyV2 once it has full HTTP forwarding and
// subresource proxying, then remove this section.

/// Parsed representation of a Kubernetes API path.
#[derive(Debug, Clone, PartialEq)]
pub enum ApiPath {
    /// `/api/v1/namespaces`
    NamespaceList,
    /// `/api/v1/namespaces/{name}`
    NamespaceGet { name: String },
    /// `/api/v1/namespaces/{ns}/{resource}`
    NamespacedList {
        namespace: String,
        resource: String,
        api_prefix: String,
    },
    /// `/api/v1/namespaces/{ns}/{resource}/{name}`
    NamespacedResource {
        namespace: String,
        resource: String,
        name: String,
        api_prefix: String,
    },
    /// `/api/v1/namespaces/{ns}/{resource}/{name}/{subresource}`
    Subresource {
        namespace: String,
        resource: String,
        name: String,
        subresource: String,
        api_prefix: String,
    },
    /// `/apis/{group}/{version}/namespaces/{ns}/{resource}/{name}`
    ExtensionResource {
        namespace: String,
        resource: String,
        name: String,
        group: String,
        version: String,
    },
    /// `/apis/{group}/{version}/namespaces/{ns}/{resource}`
    ExtensionList {
        namespace: String,
        resource: String,
        group: String,
        version: String,
    },
    /// Cluster-scoped or unrecognized -- forward as-is.
    PassThrough,
}

/// Parse a Kubernetes API path into a structured `ApiPath`.
pub fn parse_api_path(path: &str) -> ApiPath {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    // /apis/{group}/{version}/namespaces/{ns}/...
    if segments.len() >= 2 && segments[0] == "apis" {
        if segments.len() >= 5 && segments[3] == "namespaces" {
            let group = segments[1].to_string();
            let version = segments[2].to_string();
            let ns = segments[4].to_string();

            return match segments.len() {
                // /apis/{group}/{version}/namespaces/{ns}/{resource}
                6 => ApiPath::ExtensionList {
                    namespace: ns,
                    resource: segments[5].to_string(),
                    group,
                    version,
                },
                // /apis/{group}/{version}/namespaces/{ns}/{resource}/{name}
                7 => ApiPath::ExtensionResource {
                    namespace: ns,
                    resource: segments[5].to_string(),
                    name: segments[6].to_string(),
                    group,
                    version,
                },
                // /apis/{group}/{version}/namespaces/{ns}/{resource}/{name}/{subresource...}
                8.. => {
                    let api_prefix = format!("/apis/{}/{}", group, version);
                    ApiPath::Subresource {
                        namespace: ns,
                        resource: segments[5].to_string(),
                        name: segments[6].to_string(),
                        subresource: segments[7..].join("/"),
                        api_prefix,
                    }
                }
                _ => ApiPath::PassThrough,
            };
        }
        return ApiPath::PassThrough;
    }

    // /api/v1/...
    if segments.len() >= 2 && segments[0] == "api" {
        let api_version = segments[1]; // e.g., "v1"
        let api_prefix = format!("/api/{api_version}");

        // Check for namespaced paths: /api/v1/namespaces/...
        if segments.len() >= 3 && segments[2] == "namespaces" {
            return match segments.len() {
                // /api/v1/namespaces
                3 => ApiPath::NamespaceList,
                // /api/v1/namespaces/{name}
                4 => ApiPath::NamespaceGet {
                    name: segments[3].to_string(),
                },
                // /api/v1/namespaces/{ns}/{resource}
                5 => ApiPath::NamespacedList {
                    namespace: segments[3].to_string(),
                    resource: segments[4].to_string(),
                    api_prefix,
                },
                // /api/v1/namespaces/{ns}/{resource}/{name}
                6 => ApiPath::NamespacedResource {
                    namespace: segments[3].to_string(),
                    resource: segments[4].to_string(),
                    name: segments[5].to_string(),
                    api_prefix,
                },
                // /api/v1/namespaces/{ns}/{resource}/{name}/{subresource...}
                7.. => ApiPath::Subresource {
                    namespace: segments[3].to_string(),
                    resource: segments[4].to_string(),
                    name: segments[5].to_string(),
                    subresource: segments[6..].join("/"),
                    api_prefix,
                },
                _ => ApiPath::PassThrough,
            };
        }

        // Cluster-scoped core API: /api/v1/{resource} or /api/v1/{resource}/{name}
        return ApiPath::PassThrough;
    }

    ApiPath::PassThrough
}

// ---------------------------------------------------------------------------
// Proxy configuration
// ---------------------------------------------------------------------------

/// Configuration for the `VirtualClusterProxy`.
pub struct ProxyConfig {
    /// TLS server configuration (produced by `CertificateManager::build_server_config()`).
    pub tls_config: Arc<rustls::ServerConfig>,
    /// URL of the host kube-apiserver (e.g., `https://10.0.0.1:6443`).
    pub host_api_url: String,
    /// ServiceAccount token for authenticating with the host API server.
    pub host_token: String,
    /// Name/namespace translator.
    pub translator: Arc<NameTranslator>,
    /// Set of virtual namespaces tracked by the proxy and syncers.
    pub virtual_namespaces: Arc<tokio::sync::RwLock<HashSet<String>>>,
    /// Port for the HTTPS proxy.
    pub proxy_port: u16,
    /// Port for the plain HTTP health/metrics server.
    pub metrics_port: u16,
}

// ---------------------------------------------------------------------------
// VirtualClusterProxy
// ---------------------------------------------------------------------------

/// Reverse proxy that presents a virtual Kubernetes API server.
///
/// Translates names and namespaces between the virtual cluster view and the
/// host cluster, forwarding requests to the real API server after translation.
pub struct VirtualClusterProxy {
    tls_acceptor: TlsAcceptor,
    host_api_url: String,
    host_token: String,
    translator: Arc<NameTranslator>,
    virtual_namespaces: Arc<tokio::sync::RwLock<HashSet<String>>>,
    proxy_port: u16,
    metrics_port: u16,
    http_client: reqwest::Client,
}

impl VirtualClusterProxy {
    /// Create a new proxy from the given configuration.
    pub fn new(config: ProxyConfig) -> Result<Self> {
        let http_client =
            build_host_client().context("Failed to build HTTP client for host API forwarding")?;

        let tls_acceptor = TlsAcceptor::from(config.tls_config);

        Ok(Self {
            tls_acceptor,
            host_api_url: config.host_api_url,
            host_token: config.host_token,
            translator: config.translator,
            virtual_namespaces: config.virtual_namespaces,
            proxy_port: config.proxy_port,
            metrics_port: config.metrics_port,
            http_client,
        })
    }

    /// Main run loop: accepts TLS connections and serves HTTP requests.
    ///
    /// Stops when the cancellation token is triggered.
    pub async fn run(
        self: &Arc<Self>,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.proxy_port));
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind proxy listener on {addr}"))?;

        info!(addr = %addr, "Virtual API server listening (TLS)");

        let builder = ServerBuilder::new(TokioExecutor::new());

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("Proxy shutdown signal received");
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

                    debug!(peer = %peer_addr, "Accepted connection");

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

                        let service = service_fn(move |req: Request<Incoming>| {
                            let proxy = Arc::clone(&proxy);
                            async move { proxy.handle_request(req).await }
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

    /// Handle a single HTTP request from the virtual API client.
    async fn handle_request(
        self: &Arc<Self>,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let start = std::time::Instant::now();
        let method = req.method().clone();
        let uri = req.uri().clone();
        let path = uri.path().to_string();
        let query = uri.query().map(|q| q.to_string());

        debug!(method = %method, path = %path, "Handling request");

        let response = match self
            .route_request(method.clone(), &path, query.as_deref(), req)
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                error!(error = %e, path = %path, "Request handling error");
                PROXY_ERRORS_TOTAL.with_label_values(&["handler"]).inc();
                error_response(StatusCode::BAD_GATEWAY, &format!("Proxy error: {e}"))
            }
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

    /// Route a request to the appropriate handler.
    async fn route_request(
        &self,
        method: Method,
        path: &str,
        query: Option<&str>,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>> {
        // Health endpoints.
        if path == "/healthz" || path == "/readyz" || path == "/livez" {
            return Ok(ok_response("ok"));
        }

        // Parse the Kubernetes API path.
        let parsed = parse_api_path(path);

        match &parsed {
            // Virtual namespace management.
            ApiPath::NamespaceList => {
                return match method {
                    Method::GET => Ok(self.handle_namespace_list().await),
                    Method::POST => {
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|b| b.to_bytes())
                            .unwrap_or_default();
                        Ok(self.handle_namespace_create(&body).await)
                    }
                    _ => Ok(error_response(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "Method not allowed",
                    )),
                };
            }

            ApiPath::NamespaceGet { name } => {
                let name = name.clone();
                return match method {
                    Method::GET => Ok(self.handle_namespace_get(&name).await),
                    Method::DELETE => Ok(self.handle_namespace_delete(&name).await),
                    _ => Ok(error_response(
                        StatusCode::METHOD_NOT_ALLOWED,
                        "Method not allowed",
                    )),
                };
            }

            _ => {}
        }

        // Collect the request body.
        let headers = req.headers().clone();
        let body = req
            .into_body()
            .collect()
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();

        // For PassThrough, forward the original path as-is.
        if parsed == ApiPath::PassThrough {
            return self
                .forward_request(method, path, query, headers, body)
                .await;
        }

        // Translate the body if it contains JSON with name/namespace fields.
        let translated_body = self.translate_request_body(&parsed, &body);

        // Translate the path to host-cluster coordinates.
        let translated_path = self.translate_path(&parsed);

        // Forward to the host API server.
        self.forward_request(method, &translated_path, query, headers, translated_body)
            .await
    }

    /// Translate a parsed API path into the host-cluster path.
    fn translate_path(&self, parsed: &ApiPath) -> String {
        let host_ns = self.translator.host_namespace();

        match parsed {
            ApiPath::NamespaceList | ApiPath::NamespaceGet { .. } => {
                // These are handled before reaching translate_path.
                "/api/v1/namespaces".to_string()
            }

            ApiPath::NamespacedList {
                namespace: _,
                resource,
                api_prefix,
            } => {
                format!("{api_prefix}/namespaces/{host_ns}/{resource}")
            }

            ApiPath::NamespacedResource {
                namespace,
                resource,
                name,
                api_prefix,
            } => {
                let host_name = self.translator.to_host_name(name, namespace);
                format!("{api_prefix}/namespaces/{host_ns}/{resource}/{host_name}")
            }

            ApiPath::Subresource {
                namespace,
                resource,
                name,
                subresource,
                api_prefix,
            } => {
                let host_name = self.translator.to_host_name(name, namespace);
                format!("{api_prefix}/namespaces/{host_ns}/{resource}/{host_name}/{subresource}")
            }

            ApiPath::ExtensionList {
                namespace: _,
                resource,
                group,
                version,
            } => {
                format!("/apis/{group}/{version}/namespaces/{host_ns}/{resource}")
            }

            ApiPath::ExtensionResource {
                namespace,
                resource,
                name,
                group,
                version,
            } => {
                let host_name = self.translator.to_host_name(name, namespace);
                format!("/apis/{group}/{version}/namespaces/{host_ns}/{resource}/{host_name}")
            }

            ApiPath::PassThrough => {
                // Should not be called for PassThrough; the caller forwards the
                // original path directly.
                String::new()
            }
        }
    }

    /// Forward a request to the host API server and translate the response.
    async fn forward_request(
        &self,
        method: Method,
        path: &str,
        query: Option<&str>,
        headers: hyper::HeaderMap,
        body: Bytes,
    ) -> Result<Response<Full<Bytes>>> {
        let url = format!(
            "{}{}{}",
            self.host_api_url,
            path,
            query.map(|q| format!("?{q}")).unwrap_or_default()
        );

        debug!(url = %url, method = %method, "Forwarding to host API");

        let mut req_builder = self
            .http_client
            .request(method.clone(), &url)
            .bearer_auth(&self.host_token);

        // Forward relevant headers.
        if let Some(ct) = headers.get("content-type") {
            if let Ok(ct_str) = ct.to_str() {
                req_builder = req_builder.header("content-type", ct_str);
            }
        }
        if let Some(accept) = headers.get("accept") {
            if let Ok(accept_str) = accept.to_str() {
                req_builder = req_builder.header("accept", accept_str);
            }
        }
        if let Some(user_agent) = headers.get("user-agent") {
            if let Ok(ua_str) = user_agent.to_str() {
                req_builder = req_builder.header("user-agent", ua_str);
            }
        }

        if !body.is_empty() {
            req_builder = req_builder.body(body.to_vec());
        }

        let resp = req_builder
            .send()
            .await
            .with_context(|| format!("Failed to forward {method} request to {url}"))?;

        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let content_type = resp_headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let resp_body = resp
            .bytes()
            .await
            .context("Failed to read response body from host API")?;

        // Translate the response body (reverse name translation).
        let translated_body = self.translate_response_body(&resp_body, content_type.as_deref());

        let mut builder = Response::builder().status(status);
        if let Some(ref ct) = content_type {
            builder = builder.header("content-type", ct.as_str());
        }

        let response = builder
            .body(Full::new(translated_body))
            .unwrap_or_else(|_| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "Response build error")
            });

        Ok(response)
    }

    /// Translate a response body, reversing host names back to virtual names.
    ///
    /// Only operates on JSON responses. Non-JSON bodies are returned as-is.
    fn translate_response_body(&self, body: &[u8], content_type: Option<&str>) -> Bytes {
        let is_json = content_type.map(|ct| ct.contains("json")).unwrap_or(false);

        if !is_json || body.is_empty() {
            return Bytes::copy_from_slice(body);
        }

        match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(mut value) => {
                self.translate_json_value(&mut value);
                match serde_json::to_vec(&value) {
                    Ok(translated) => Bytes::from(translated),
                    Err(_) => Bytes::copy_from_slice(body),
                }
            }
            Err(_) => Bytes::copy_from_slice(body),
        }
    }

    /// Recursively walk a JSON value and reverse-translate host names to virtual names.
    ///
    /// When a field named `"name"` matches the host translation pattern
    /// (`{vname}-x-{vns}-x-vc`), the name is replaced with `vname` and the
    /// sibling `"namespace"` field (if any) is set to `vns`.
    fn translate_json_value(&self, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                // Translate metadata.name if present and matches host pattern.
                if let Some(name_val) = map.get("name") {
                    if let Some(name_str) = name_val.as_str() {
                        if let Some((virtual_name, virtual_ns)) =
                            self.translator.to_virtual(name_str)
                        {
                            map.insert("name".to_string(), serde_json::Value::String(virtual_name));
                            // Also set the namespace to the virtual namespace.
                            map.insert(
                                "namespace".to_string(),
                                serde_json::Value::String(virtual_ns),
                            );
                        }
                    }
                }

                // Recurse into all values.
                for (_, v) in map.iter_mut() {
                    self.translate_json_value(v);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.translate_json_value(item);
                }
            }
            _ => {}
        }
    }

    /// Translate a request body, replacing virtual names with host names.
    fn translate_request_body(&self, parsed: &ApiPath, body: &Bytes) -> Bytes {
        if body.is_empty() {
            return Bytes::new();
        }

        let virtual_ns = match parsed {
            ApiPath::NamespacedList { namespace, .. }
            | ApiPath::NamespacedResource { namespace, .. }
            | ApiPath::Subresource { namespace, .. }
            | ApiPath::ExtensionList { namespace, .. }
            | ApiPath::ExtensionResource { namespace, .. } => namespace.clone(),
            _ => return body.clone(),
        };

        match serde_json::from_slice::<serde_json::Value>(body) {
            Ok(mut value) => {
                self.translate_request_json(&mut value, &virtual_ns);
                match serde_json::to_vec(&value) {
                    Ok(translated) => Bytes::from(translated),
                    Err(_) => body.clone(),
                }
            }
            Err(_) => body.clone(),
        }
    }

    /// Translate a request JSON value: replace virtual names with host names.
    fn translate_request_json(&self, value: &mut serde_json::Value, virtual_ns: &str) {
        if let serde_json::Value::Object(map) = value {
            // Handle metadata.name translation.
            if let Some(serde_json::Value::Object(meta_map)) = map.get_mut("metadata") {
                if let Some(name_val) = meta_map.get("name") {
                    if let Some(name_str) = name_val.as_str() {
                        let host_name = self.translator.to_host_name(name_str, virtual_ns);
                        meta_map.insert("name".to_string(), serde_json::Value::String(host_name));
                    }
                }
                // Replace namespace with host namespace.
                meta_map.insert(
                    "namespace".to_string(),
                    serde_json::Value::String(self.translator.host_namespace().to_string()),
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Virtual namespace management
    // -----------------------------------------------------------------------

    /// Return a synthetic namespace list from the virtual namespaces set.
    async fn handle_namespace_list(&self) -> Response<Full<Bytes>> {
        let namespaces = self.virtual_namespaces.read().await;
        let items: Vec<serde_json::Value> = namespaces
            .iter()
            .map(|ns| make_namespace_object(ns))
            .collect();

        let list = serde_json::json!({
            "apiVersion": "v1",
            "kind": "NamespaceList",
            "metadata": {
                "resourceVersion": "1"
            },
            "items": items
        });

        json_response(StatusCode::OK, &list)
    }

    /// Return a synthetic namespace object if it exists.
    async fn handle_namespace_get(&self, name: &str) -> Response<Full<Bytes>> {
        let namespaces = self.virtual_namespaces.read().await;
        if namespaces.contains(name) {
            let ns = make_namespace_object(name);
            json_response(StatusCode::OK, &ns)
        } else {
            let status = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "metadata": {},
                "status": "Failure",
                "message": format!("namespaces \"{name}\" not found"),
                "reason": "NotFound",
                "details": {
                    "name": name,
                    "kind": "namespaces"
                },
                "code": 404
            });
            json_response(StatusCode::NOT_FOUND, &status)
        }
    }

    /// Create a virtual namespace.
    async fn handle_namespace_create(&self, body: &Bytes) -> Response<Full<Bytes>> {
        let parsed: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                return error_response(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {e}"));
            }
        };

        let name = parsed
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str());

        let name = match name {
            Some(n) => n.to_string(),
            None => {
                return error_response(StatusCode::BAD_REQUEST, "metadata.name is required");
            }
        };

        let mut namespaces = self.virtual_namespaces.write().await;
        if namespaces.contains(&name) {
            let status = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "metadata": {},
                "status": "Failure",
                "message": format!("namespaces \"{name}\" already exists"),
                "reason": "AlreadyExists",
                "details": {
                    "name": name,
                    "kind": "namespaces"
                },
                "code": 409
            });
            return json_response(StatusCode::CONFLICT, &status);
        }

        namespaces.insert(name.clone());
        info!(namespace = %name, "Created virtual namespace");

        let ns = make_namespace_object(&name);
        json_response(StatusCode::CREATED, &ns)
    }

    /// Delete a virtual namespace.
    async fn handle_namespace_delete(&self, name: &str) -> Response<Full<Bytes>> {
        let mut namespaces = self.virtual_namespaces.write().await;
        if namespaces.remove(name) {
            info!(namespace = %name, "Deleted virtual namespace");
            let ns = make_namespace_object(name);
            json_response(StatusCode::OK, &ns)
        } else {
            let status = serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "metadata": {},
                "status": "Failure",
                "message": format!("namespaces \"{name}\" not found"),
                "reason": "NotFound",
                "details": {
                    "name": name,
                    "kind": "namespaces"
                },
                "code": 404
            });
            json_response(StatusCode::NOT_FOUND, &status)
        }
    }

    // -----------------------------------------------------------------------
    // Metrics / health server
    // -----------------------------------------------------------------------

    /// Run a plain HTTP server on the metrics port, serving `/healthz` and `/metrics`.
    pub async fn run_metrics_server(
        &self,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.metrics_port));
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind metrics listener on {addr}"))?;

        info!(addr = %addr, "Metrics/health server listening (HTTP)");

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
                                        .body(Full::new(Bytes::from(body)))
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
fn ok_response(body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// Build an error response with the given status code and message in Kubernetes
/// Status format.
fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
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
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap()
}

/// Build a JSON response.
fn json_response(status: StatusCode, value: &serde_json::Value) -> Response<Full<Bytes>> {
    let body_bytes = serde_json::to_vec(value).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap()
}

/// Create a synthetic Kubernetes Namespace object.
fn make_namespace_object(name: &str) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": name,
            "uid": format!("virtual-{name}"),
            "resourceVersion": "1",
            "creationTimestamp": "2024-01-01T00:00:00Z"
        },
        "spec": {
            "finalizers": ["kubernetes"]
        },
        "status": {
            "phase": "Active"
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_api_path tests --

    #[test]
    fn test_parse_namespace_list() {
        assert_eq!(parse_api_path("/api/v1/namespaces"), ApiPath::NamespaceList);
    }

    #[test]
    fn test_parse_namespace_get() {
        assert_eq!(
            parse_api_path("/api/v1/namespaces/default"),
            ApiPath::NamespaceGet {
                name: "default".to_string()
            }
        );
    }

    #[test]
    fn test_parse_namespaced_list() {
        assert_eq!(
            parse_api_path("/api/v1/namespaces/default/pods"),
            ApiPath::NamespacedList {
                namespace: "default".to_string(),
                resource: "pods".to_string(),
                api_prefix: "/api/v1".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_namespaced_resource() {
        assert_eq!(
            parse_api_path("/api/v1/namespaces/default/pods/my-pod"),
            ApiPath::NamespacedResource {
                namespace: "default".to_string(),
                resource: "pods".to_string(),
                name: "my-pod".to_string(),
                api_prefix: "/api/v1".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_subresource() {
        assert_eq!(
            parse_api_path("/api/v1/namespaces/default/pods/my-pod/log"),
            ApiPath::Subresource {
                namespace: "default".to_string(),
                resource: "pods".to_string(),
                name: "my-pod".to_string(),
                subresource: "log".to_string(),
                api_prefix: "/api/v1".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_subresource_exec() {
        assert_eq!(
            parse_api_path("/api/v1/namespaces/default/pods/my-pod/exec"),
            ApiPath::Subresource {
                namespace: "default".to_string(),
                resource: "pods".to_string(),
                name: "my-pod".to_string(),
                subresource: "exec".to_string(),
                api_prefix: "/api/v1".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_service_proxy_subresource() {
        assert_eq!(
            parse_api_path("/api/v1/namespaces/default/services/my-svc/proxy"),
            ApiPath::Subresource {
                namespace: "default".to_string(),
                resource: "services".to_string(),
                name: "my-svc".to_string(),
                subresource: "proxy".to_string(),
                api_prefix: "/api/v1".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_extension_resource() {
        assert_eq!(
            parse_api_path("/apis/apps/v1/namespaces/default/deployments/my-deploy"),
            ApiPath::ExtensionResource {
                namespace: "default".to_string(),
                resource: "deployments".to_string(),
                name: "my-deploy".to_string(),
                group: "apps".to_string(),
                version: "v1".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_extension_list() {
        assert_eq!(
            parse_api_path("/apis/apps/v1/namespaces/default/deployments"),
            ApiPath::ExtensionList {
                namespace: "default".to_string(),
                resource: "deployments".to_string(),
                group: "apps".to_string(),
                version: "v1".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_extension_subresource() {
        assert_eq!(
            parse_api_path("/apis/apps/v1/namespaces/default/deployments/my-deploy/scale"),
            ApiPath::Subresource {
                namespace: "default".to_string(),
                resource: "deployments".to_string(),
                name: "my-deploy".to_string(),
                subresource: "scale".to_string(),
                api_prefix: "/apis/apps/v1".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_cluster_scoped() {
        assert_eq!(parse_api_path("/api/v1/nodes"), ApiPath::PassThrough);
        assert_eq!(parse_api_path("/api/v1/nodes/node-1"), ApiPath::PassThrough);
    }

    #[test]
    fn test_parse_passthrough() {
        assert_eq!(parse_api_path("/version"), ApiPath::PassThrough);
        assert_eq!(parse_api_path("/openapi/v2"), ApiPath::PassThrough);
        assert_eq!(parse_api_path("/"), ApiPath::PassThrough);
    }

    #[test]
    fn test_parse_apis_cluster_scoped() {
        assert_eq!(
            parse_api_path("/apis/apiextensions.k8s.io/v1/customresourcedefinitions"),
            ApiPath::PassThrough
        );
    }

    // -- translate_path tests (standalone, without proxy instance) --

    fn make_translator() -> Arc<NameTranslator> {
        Arc::new(NameTranslator::new("pool-e2e-basic-0".to_string()))
    }

    #[test]
    fn test_translate_namespaced_resource_path() {
        let translator = make_translator();
        let parsed = ApiPath::NamespacedResource {
            namespace: "default".to_string(),
            resource: "pods".to_string(),
            name: "my-pod".to_string(),
            api_prefix: "/api/v1".to_string(),
        };

        let host_ns = translator.host_namespace();
        let result = match &parsed {
            ApiPath::NamespacedResource {
                namespace,
                resource,
                name,
                api_prefix,
            } => {
                let host_name = translator.to_host_name(name, namespace);
                format!("{api_prefix}/namespaces/{host_ns}/{resource}/{host_name}")
            }
            _ => unreachable!(),
        };

        assert_eq!(
            result,
            "/api/v1/namespaces/pool-e2e-basic-0/pods/my-pod-x-default-x-vc"
        );
    }

    #[test]
    fn test_translate_namespaced_list_path() {
        let translator = make_translator();
        let host_ns = translator.host_namespace();

        let parsed = ApiPath::NamespacedList {
            namespace: "default".to_string(),
            resource: "services".to_string(),
            api_prefix: "/api/v1".to_string(),
        };

        let result = match &parsed {
            ApiPath::NamespacedList {
                resource,
                api_prefix,
                ..
            } => {
                format!("{api_prefix}/namespaces/{host_ns}/{resource}")
            }
            _ => unreachable!(),
        };

        assert_eq!(result, "/api/v1/namespaces/pool-e2e-basic-0/services");
    }

    #[test]
    fn test_translate_extension_resource_path() {
        let translator = make_translator();
        let host_ns = translator.host_namespace();

        let parsed = ApiPath::ExtensionResource {
            namespace: "kube-system".to_string(),
            resource: "deployments".to_string(),
            name: "nginx".to_string(),
            group: "apps".to_string(),
            version: "v1".to_string(),
        };

        let result = match &parsed {
            ApiPath::ExtensionResource {
                namespace,
                resource,
                name,
                group,
                version,
            } => {
                let host_name = translator.to_host_name(name, namespace);
                format!("/apis/{group}/{version}/namespaces/{host_ns}/{resource}/{host_name}")
            }
            _ => unreachable!(),
        };

        assert_eq!(
            result,
            "/apis/apps/v1/namespaces/pool-e2e-basic-0/deployments/nginx-x-kube-system-x-vc"
        );
    }

    #[test]
    fn test_translate_subresource_path() {
        let translator = make_translator();
        let host_ns = translator.host_namespace();

        let parsed = ApiPath::Subresource {
            namespace: "default".to_string(),
            resource: "pods".to_string(),
            name: "my-pod".to_string(),
            subresource: "log".to_string(),
            api_prefix: "/api/v1".to_string(),
        };

        let result = match &parsed {
            ApiPath::Subresource {
                namespace,
                resource,
                name,
                subresource,
                api_prefix,
            } => {
                let host_name = translator.to_host_name(name, namespace);
                format!("{api_prefix}/namespaces/{host_ns}/{resource}/{host_name}/{subresource}")
            }
            _ => unreachable!(),
        };

        assert_eq!(
            result,
            "/api/v1/namespaces/pool-e2e-basic-0/pods/my-pod-x-default-x-vc/log"
        );
    }

    // -- JSON translation tests --

    /// Standalone translate_json_value for tests (mirrors VirtualClusterProxy method).
    fn translate_json_value_standalone(translator: &NameTranslator, value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(name_val) = map.get("name") {
                    if let Some(name_str) = name_val.as_str() {
                        if let Some((virtual_name, virtual_ns)) = translator.to_virtual(name_str) {
                            map.insert("name".to_string(), serde_json::Value::String(virtual_name));
                            map.insert(
                                "namespace".to_string(),
                                serde_json::Value::String(virtual_ns),
                            );
                        }
                    }
                }
                for (_, v) in map.iter_mut() {
                    translate_json_value_standalone(translator, v);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr.iter_mut() {
                    translate_json_value_standalone(translator, item);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn test_translate_response_json_single_resource() {
        let translator = make_translator();

        let mut host_response = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "my-pod-x-default-x-vc",
                "namespace": "pool-e2e-basic-0"
            }
        });

        translate_json_value_standalone(&translator, &mut host_response);

        let meta = host_response.get("metadata").unwrap();
        assert_eq!(meta.get("name").unwrap().as_str().unwrap(), "my-pod");
        assert_eq!(meta.get("namespace").unwrap().as_str().unwrap(), "default");
    }

    #[test]
    fn test_translate_response_json_list() {
        let translator = make_translator();

        let mut host_response = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PodList",
            "items": [
                {
                    "metadata": {
                        "name": "web-x-default-x-vc",
                        "namespace": "pool-e2e-basic-0"
                    }
                },
                {
                    "metadata": {
                        "name": "api-x-staging-x-vc",
                        "namespace": "pool-e2e-basic-0"
                    }
                }
            ]
        });

        translate_json_value_standalone(&translator, &mut host_response);

        let items = host_response.get("items").unwrap().as_array().unwrap();

        let meta0 = items[0].get("metadata").unwrap();
        assert_eq!(meta0.get("name").unwrap().as_str().unwrap(), "web");
        assert_eq!(meta0.get("namespace").unwrap().as_str().unwrap(), "default");

        let meta1 = items[1].get("metadata").unwrap();
        assert_eq!(meta1.get("name").unwrap().as_str().unwrap(), "api");
        assert_eq!(meta1.get("namespace").unwrap().as_str().unwrap(), "staging");
    }

    #[test]
    fn test_translate_response_leaves_untranslated_names() {
        let translator = make_translator();

        let mut host_response = serde_json::json!({
            "metadata": {
                "name": "some-random-name",
                "namespace": "pool-e2e-basic-0"
            }
        });

        translate_json_value_standalone(&translator, &mut host_response);

        let meta = host_response.get("metadata").unwrap();
        assert_eq!(
            meta.get("name").unwrap().as_str().unwrap(),
            "some-random-name"
        );
    }

    #[test]
    fn test_translate_response_nested_objects() {
        let translator = make_translator();

        let mut host_response = serde_json::json!({
            "metadata": {
                "name": "svc-x-default-x-vc",
                "namespace": "pool-e2e-basic-0"
            },
            "spec": {
                "selector": {
                    "app": "web"
                }
            }
        });

        translate_json_value_standalone(&translator, &mut host_response);

        let meta = host_response.get("metadata").unwrap();
        assert_eq!(meta.get("name").unwrap().as_str().unwrap(), "svc");
        assert_eq!(meta.get("namespace").unwrap().as_str().unwrap(), "default");
    }

    // -- Namespace object tests --

    #[test]
    fn test_make_namespace_object() {
        let ns = make_namespace_object("default");
        assert_eq!(ns.get("kind").unwrap().as_str().unwrap(), "Namespace");
        assert_eq!(
            ns.get("metadata")
                .unwrap()
                .get("name")
                .unwrap()
                .as_str()
                .unwrap(),
            "default"
        );
        assert_eq!(
            ns.get("status")
                .unwrap()
                .get("phase")
                .unwrap()
                .as_str()
                .unwrap(),
            "Active"
        );
    }

    #[test]
    fn test_ok_response() {
        let resp = ok_response("ok");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_error_response_format() {
        let resp = error_response(StatusCode::NOT_FOUND, "not found");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_json_response_format() {
        let value = serde_json::json!({"key": "value"});
        let resp = json_response(StatusCode::OK, &value);
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // -- TLS host client tests --

    #[test]
    fn test_build_host_client_falls_back_outside_cluster() {
        // Outside a real cluster the CA file won't exist, so the builder
        // should fall back to danger_accept_invalid_certs and still succeed.
        let client = build_host_client();
        assert!(
            client.is_ok(),
            "build_host_client should succeed even without in-cluster CA: {:?}",
            client.err()
        );
    }

    #[test]
    fn test_missing_ca_file_falls_back() {
        let client = build_host_client_with_ca_path("/nonexistent/path/ca.crt");
        assert!(
            client.is_ok(),
            "Should succeed with fallback when CA file is missing: {:?}",
            client.err()
        );
    }

    #[test]
    fn test_empty_ca_file_falls_back() {
        let dir = std::env::temp_dir().join("kobe_sync_test_empty_ca");
        let _ = std::fs::create_dir_all(&dir);
        let ca_path = dir.join("ca.crt");
        std::fs::write(&ca_path, b"").unwrap();

        let client = build_host_client_with_ca_path(ca_path.to_str().unwrap());
        assert!(
            client.is_ok(),
            "Should succeed with fallback when CA file is empty: {:?}",
            client.err()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ===========================================================================
// V2 — Thin TLS Gateway
// ===========================================================================
//
// The v2 proxy acts as a thin TLS gateway in front of the local kube-apiserver.
// Most requests are forwarded as-is. Only Pod subresource requests (exec, logs,
// attach, portforward) are intercepted, translated to host pod names, and
// proxied to the host kube-apiserver.
//
// The v1 proxy code above is still used by the binary and will be
// removed when VirtualClusterProxyV2 has full HTTP forwarding.
// ===========================================================================

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

/// V2 proxy that acts as a thin TLS gateway in front of the local kube-apiserver.
///
/// Most requests are forwarded as-is to the local apiserver. Only Pod subresource
/// requests (exec, logs, attach, portforward) are intercepted, translated to host
/// pod names, and proxied to the host kube-apiserver.
pub struct VirtualClusterProxyV2 {
    /// Address of the local kube-apiserver to forward to.
    pub apiserver_url: String,
    /// URL of the host kube-apiserver for subresource proxying.
    pub host_apiserver_url: String,
    /// ServiceAccount token for authenticating with the host API server.
    pub host_token: String,
    /// Name translator for virtual-to-host name mapping.
    pub translator: Arc<NameTranslator>,
    /// TLS configuration for the proxy's frontend.
    pub tls_config: Arc<rustls::ServerConfig>,
    /// Port to listen on.
    pub listen_port: u16,
}

impl VirtualClusterProxyV2 {
    /// Handle an incoming request -- either forward to local apiserver or intercept subresource.
    pub async fn handle_request(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let path = req.uri().path().to_string();

        if let Some(sub) = parse_subresource(&path) {
            // Intercepted subresource -- translate and proxy to host
            self.handle_subresource(req, sub).await
        } else {
            // Pass-through to local kube-apiserver
            self.forward_to_apiserver(req).await
        }
    }

    async fn forward_to_apiserver(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let uri = req.uri().clone();
        let method = req.method().clone();
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        // Forward to local apiserver.
        let target_url = format!("{}{}", self.apiserver_url, path);

        // Build forwarded request using reqwest.
        // Localhost apiserver uses self-signed certs from our own PKI, so we
        // accept invalid certs for this local-only connection.
        let client = match reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(format!("Client build error: {e}"))))
                    .unwrap());
            }
        };

        let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap();
        let body_bytes = BodyExt::collect(req.into_body())
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();

        let resp = match client
            .request(reqwest_method, &target_url)
            .body(body_bytes.to_vec())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                PROXY_ERRORS_TOTAL.with_label_values(&["forward"]).inc();
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(format!("Proxy error: {e}"))))
                    .unwrap());
            }
        };

        let status = resp.status().as_u16();
        let resp_bytes = resp.bytes().await.unwrap_or_default();

        Ok(Response::builder()
            .status(status)
            .body(Full::new(resp_bytes))
            .unwrap())
    }

    async fn handle_subresource(
        &self,
        req: Request<Incoming>,
        sub: SubresourceRequest,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
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

        // TODO: For exec/attach/portforward, SPDY/WebSocket upgrade is needed.
        // This implementation handles basic HTTP forwarding (e.g. logs).
        // Streaming upgrade support will be added in a follow-up task.

        let target_url = format!("{}{}{}", self.host_apiserver_url, host_path, query);

        // Use build_host_client() which loads the in-cluster CA for proper
        // TLS verification against the host API server.
        let client = match build_host_client() {
            Ok(c) => c,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(format!("Client build error: {e}"))))
                    .unwrap());
            }
        };

        let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap();
        let body_bytes = BodyExt::collect(req.into_body())
            .await
            .map(|b| b.to_bytes())
            .unwrap_or_default();

        let resp = match client
            .request(reqwest_method, &target_url)
            .bearer_auth(&self.host_token)
            .body(body_bytes.to_vec())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                PROXY_ERRORS_TOTAL.with_label_values(&["subresource"]).inc();
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(format!(
                        "Subresource proxy error: {e}"
                    ))))
                    .unwrap());
            }
        };

        let status = resp.status().as_u16();
        let resp_bytes = resp.bytes().await.unwrap_or_default();

        Ok(Response::builder()
            .status(status)
            .body(Full::new(resp_bytes))
            .unwrap())
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
}
