//! HTTP Upgrade tunnel for the connect proxy (`kubectl exec` / `attach` /
//! `port-forward` through a lease kubeconfig).
//!
//! These pod subresources switch from regular request/response into a
//! bidirectional byte tunnel via HTTP/1.1 `Upgrade:` semantics. The two
//! protocols K8s clients negotiate are **SPDY/3.1** (older kubectl, many
//! controllers) and **WebSocket** (`v5.channel.k8s.io`, the kubectl default
//! since 1.32). The proxy treats them identically: once both legs are
//! upgraded, we splice the sockets with `tokio::io::copy_bidirectional` and
//! let framing flow through opaquely — we never modify channel data, so
//! parsing SPDY/WebSocket frames buys us nothing. This mirrors what
//! `kobe-sync` does host-side (see `src/kobe_sync/upgrade.rs`).
//!
//! Unlike the buffered reqwest path, reqwest can't surface the underlying
//! socket after a 101, so this drives a raw hyper client over `tokio_rustls`
//! using the rustls config from `build_backend_tls_config`.
//!
//! ## Auth & validation
//!
//! All lease-token validation, phase/expiry checks, and backend resolution
//! happen in `connect_proxy_inner` BEFORE we get here. The upstream request
//! re-injects the backend bearer token (if any) and strips the caller's
//! `Authorization` / `X-Remote-*` so a caller can't forge backend auth.

use std::sync::LazyLock;

use axum::body::Body;
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONNECTION, HOST, UPGRADE};
use http::{HeaderName, StatusCode};
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

use crate::api::connect::BackendUpgradeAccess;

/// Default cap on concurrent upgrade tunnels across the whole connect proxy.
/// A heavy CI run is dozens of concurrent `kubectl exec`/`logs -f`; 64 covers
/// realistic interactive load while keeping fd usage bounded. Overridable via
/// `KOBE_CONNECT_UPGRADE_MAX`.
const DEFAULT_MAX_UPGRADES: usize = 64;
const ENV_MAX_UPGRADES: &str = "KOBE_CONNECT_UPGRADE_MAX";

/// Process-global concurrency guard for connect-proxy upgrade tunnels. A
/// permit is held for the full lifetime of each tunnel; exhaustion fails fast
/// with 503 rather than queueing.
static UPGRADE_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| {
    let cap = match std::env::var(ENV_MAX_UPGRADES) {
        Ok(s) => match s.trim().parse::<usize>() {
            Ok(n) if n > 0 => n,
            _ => {
                warn!(
                    env = ENV_MAX_UPGRADES,
                    value = %s,
                    default = DEFAULT_MAX_UPGRADES,
                    "ignoring invalid env override; using default upgrade cap"
                );
                DEFAULT_MAX_UPGRADES
            }
        },
        Err(_) => DEFAULT_MAX_UPGRADES,
    };
    Semaphore::new(cap)
});

/// Upgrade-negotiation headers we mirror from the client onto the upstream
/// request. Deliberately a narrow allowlist: the caller's `Authorization` and
/// any `X-Remote-*` are NOT forwarded — we set our own backend auth, and the
/// backend doesn't run our front-proxy chain.
///
/// Returned by value (not a `const`) because `HeaderName` has interior
/// mutability and can't live in a `const` array (E0492).
fn forwarded_upgrade_headers() -> [HeaderName; 8] {
    [
        UPGRADE,
        CONNECTION,
        http::header::USER_AGENT,
        HeaderName::from_static("sec-websocket-protocol"),
        HeaderName::from_static("sec-websocket-version"),
        HeaderName::from_static("sec-websocket-key"),
        HeaderName::from_static("sec-websocket-extensions"),
        HeaderName::from_static("x-stream-protocol-version"),
    ]
}

/// Tunnel an HTTP-Upgrade request (exec/attach/port-forward) through to the
/// leased cluster's apiserver.
///
/// `path_and_query` is the already-built backend request path, e.g.
/// `/api/v1/namespaces/default/pods/foo/exec?command=sh`.
///
/// On a 101 from the backend, this spawns a task that bridges the two upgraded
/// sockets and returns a 101 to the client (mirroring the backend's chosen
/// `Upgrade` / `Sec-WebSocket-Protocol`). Non-101 responses and all error
/// paths return a generic status to the client; details are logged server-side.
pub(crate) async fn tunnel_upgrade(
    mut req: Request,
    access: BackendUpgradeAccess,
    path_and_query: &str,
) -> Response {
    // 0. Reserve a concurrency slot. Fail fast under load.
    let permit = match UPGRADE_SEMAPHORE.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            warn!("Connect proxy upgrade rejected — concurrency cap reached");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [("retry-after", "5")],
                "Too many concurrent streaming sessions; retry shortly",
            )
                .into_response();
        }
    };

    // 1. Capture the client OnUpgrade future BEFORE consuming the request. It
    //    resolves only after axum/hyper has flushed our 101 on the wire.
    let client_on_upgrade = hyper::upgrade::on(&mut req);
    let method = req.method().clone();
    let client_headers = req.headers().clone();

    // 2. Parse the backend server URL into host/port + SNI name.
    let (host, port, server_name) = match parse_server_url(&access.server) {
        Ok(parts) => parts,
        Err(err) => {
            warn!(error = %err, server = %access.server, "Connect proxy upgrade: invalid backend server URL");
            return upgrade_error(StatusCode::BAD_GATEWAY, "Invalid backend server URL");
        }
    };

    // 3. Dial TCP + TLS.
    let tcp = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(err) => {
            warn!(error = %err, host = %host, port, "Connect proxy upgrade: TCP dial failed");
            return upgrade_error(StatusCode::BAD_GATEWAY, "Failed to reach leased cluster");
        }
    };
    tcp.set_nodelay(true).ok();

    let connector = TlsConnector::from(access.tls.clone());
    let tls_stream = match connector.connect(server_name, tcp).await {
        Ok(s) => s,
        Err(err) => {
            warn!(error = %err, host = %host, "Connect proxy upgrade: TLS handshake failed");
            return upgrade_error(StatusCode::BAD_GATEWAY, "Failed to reach leased cluster");
        }
    };

    // 4. HTTP/1.1 handshake. `with_upgrades()` is critical — without it hyper
    //    closes the connection after 101 instead of yielding the socket.
    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(err) => {
            warn!(error = %err, host = %host, "Connect proxy upgrade: HTTP/1 handshake failed");
            return upgrade_error(StatusCode::BAD_GATEWAY, "Failed to reach leased cluster");
        }
    };
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            // Expected on teardown (UnexpectedEof when the bridge closes).
            debug!(error = %e, "Connect proxy upgrade: backend connection task ended");
        }
    });

    // 5. Build the upstream request (re-injects backend auth, strips caller's).
    let upstream_req = match build_upstream_upgrade_request(
        &method,
        &client_headers,
        path_and_query,
        &host,
        port,
        access.bearer_token.as_deref(),
    ) {
        Ok(r) => r,
        Err(err) => {
            warn!(error = %err, "Connect proxy upgrade: failed to build upstream request");
            return upgrade_error(StatusCode::BAD_GATEWAY, "Failed to build backend request");
        }
    };

    // 6. Send it and await the (initial) response.
    let mut upstream_resp = match sender.send_request(upstream_req).await {
        Ok(r) => r,
        Err(err) => {
            warn!(error = %err, host = %host, "Connect proxy upgrade: send_request failed");
            return upgrade_error(StatusCode::BAD_GATEWAY, "Failed to reach leased cluster");
        }
    };

    let status = upstream_resp.status();

    // 7. Non-101: the backend rejected the upgrade (401/403/404 etc.). Do NOT
    //    leak the raw upstream body — relay only the status with a generic
    //    message, and log server-side.
    if status != StatusCode::SWITCHING_PROTOCOLS {
        warn!(
            host = %host,
            status = status.as_u16(),
            "Connect proxy upgrade: backend did not switch protocols"
        );
        let client_status =
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        return upgrade_error(
            client_status,
            "Leased cluster rejected the streaming request",
        );
    }

    // 8. We got 101. Mirror the backend-chosen upgrade-response headers so the
    //    client completes the handshake against the backend's negotiation.
    let upstream_upgrade_header = upstream_resp.headers().get(UPGRADE).cloned();
    let upstream_ws_protocol = upstream_resp
        .headers()
        .get("sec-websocket-protocol")
        .cloned();
    // Sec-WebSocket-Accept is computed by the apiserver from the client's
    // Sec-WebSocket-Key (which we forwarded), so kubectl's websocket client
    // REQUIRES it back or it rejects the handshake right after the 101. (SPDY
    // has no such header — these are simply absent there.)
    let upstream_ws_accept = upstream_resp.headers().get("sec-websocket-accept").cloned();
    let upstream_ws_extensions = upstream_resp
        .headers()
        .get("sec-websocket-extensions")
        .cloned();

    let upstream_on_upgrade = hyper::upgrade::on(&mut upstream_resp);
    let proto_for_log = upstream_upgrade_header
        .as_ref()
        .and_then(|h| h.to_str().ok())
        .unwrap_or("?")
        .to_string();

    // 9. Spawn the byte bridge. The permit moves into the task so the slot
    //    stays reserved until the tunnel actually closes. We do NOT await the
    //    client OnUpgrade here — it only resolves after our 101 is flushed,
    //    which happens after we return.
    tokio::spawn(async move {
        let _hold_permit = permit;
        bridge_upgraded(client_on_upgrade, upstream_on_upgrade, proto_for_log).await;
    });

    // 10. Build the 101 response for the client.
    let mut builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(CONNECTION, "upgrade");
    if let Some(v) = upstream_upgrade_header {
        builder = builder.header(UPGRADE, v);
    }
    if let Some(v) = upstream_ws_protocol {
        builder = builder.header("sec-websocket-protocol", v);
    }
    if let Some(v) = upstream_ws_accept {
        builder = builder.header("sec-websocket-accept", v);
    }
    if let Some(v) = upstream_ws_extensions {
        builder = builder.header("sec-websocket-extensions", v);
    }
    match builder.body(Body::empty()) {
        Ok(resp) => resp,
        Err(err) => {
            warn!(error = %err, "Connect proxy upgrade: failed to build 101 response");
            upgrade_error(StatusCode::BAD_GATEWAY, "Failed to establish stream")
        }
    }
}

/// Generic plain-text error response. We never relay raw upstream bodies on
/// the upgrade path (redaction policy, matching `connect_error`).
fn upgrade_error(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        [("content-type", "text/plain; charset=utf-8")],
        message,
    )
        .into_response()
}

/// Build the upstream upgrade request: same method, the translated path, the
/// backend `Host`, the backend bearer token (if any), and the allowlisted
/// upgrade-negotiation headers from the client. The caller's `Authorization`
/// and `X-Remote-*` are NOT forwarded.
fn build_upstream_upgrade_request(
    method: &http::Method,
    client_headers: &http::HeaderMap,
    path_and_query: &str,
    host: &str,
    port: u16,
    bearer_token: Option<&str>,
) -> anyhow::Result<http::Request<Empty<Bytes>>> {
    let authority = format!("{host}:{port}");

    let mut builder = http::Request::builder()
        .method(method.clone())
        .uri(path_and_query)
        .header(HOST, authority);

    if let Some(token) = bearer_token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }

    for name in forwarded_upgrade_headers() {
        if let Some(v) = client_headers.get(&name) {
            builder = builder.header(&name, v);
        }
    }

    builder
        .body(Empty::<Bytes>::new())
        .map_err(|e| anyhow::anyhow!("Failed to build upstream upgrade request: {e}"))
}

/// Bridge the upgraded client and backend streams until one side closes.
/// Errors here are not actionable (clean closes or transient transport
/// errors); logged at debug.
async fn bridge_upgraded(
    client_on_upgrade: hyper::upgrade::OnUpgrade,
    upstream_on_upgrade: hyper::upgrade::OnUpgrade,
    proto: String,
) {
    let upstream_upgraded = match upstream_on_upgrade.await {
        Ok(u) => u,
        Err(e) => {
            debug!(error = %e, protocol = %proto, "Connect proxy upgrade: backend did not yield upgraded stream");
            return;
        }
    };
    let client_upgraded = match client_on_upgrade.await {
        Ok(u) => u,
        Err(e) => {
            // Client disconnected before our 101 was flushed. Drop the
            // backend side so the apiserver releases the session.
            debug!(error = %e, protocol = %proto, "Connect proxy upgrade: client upgrade did not complete; dropping backend");
            drop(upstream_upgraded);
            return;
        }
    };

    let mut client_io = TokioIo::new(client_upgraded);
    let mut upstream_io = TokioIo::new(upstream_upgraded);

    info!(protocol = %proto, "Connect proxy tunnel established (exec/attach/port-forward)");

    match tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await {
        Ok((c2u, u2c)) => {
            info!(
                protocol = %proto,
                client_to_upstream_bytes = c2u,
                upstream_to_client_bytes = u2c,
                "Connect proxy tunnel closed cleanly"
            );
        }
        Err(e) => {
            debug!(protocol = %proto, error = %e, "Connect proxy tunnel closed with error");
        }
    }
}

/// Parse `https://host:port/...` into `(host, port, ServerName)`. Defaults the
/// port to 443 for `https://` and 80 for `http://`.
fn parse_server_url(url: &str) -> anyhow::Result<(String, u16, ServerName<'static>)> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        anyhow::bail!("Backend server URL must start with https:// or http://: {url}");
    };

    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid port in backend server URL: {url}"))?;
            (h.to_string(), port)
        }
        None => {
            let port = if scheme == "https" { 443 } else { 80 };
            (host_port.to_string(), port)
        }
    };

    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| anyhow::anyhow!("Invalid SNI hostname in backend server URL: {host}"))?;
    Ok((host, port, server_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    fn client_headers(pairs: &[(&'static str, &'static str)]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_static(k),
                http::HeaderValue::from_static(v),
            );
        }
        h
    }

    // -- parse_server_url --

    #[test]
    fn parse_server_url_https_with_port() {
        let (h, p, _sn) = parse_server_url("https://host.svc:6443").unwrap();
        assert_eq!(h, "host.svc");
        assert_eq!(p, 6443);
    }

    #[test]
    fn parse_server_url_https_default_port() {
        let (h, p, _sn) = parse_server_url("https://kubernetes.default.svc").unwrap();
        assert_eq!(h, "kubernetes.default.svc");
        assert_eq!(p, 443);
    }

    #[test]
    fn parse_server_url_strips_path() {
        let (h, p, _sn) = parse_server_url("https://10.0.0.1:6443/connect/lease-x").unwrap();
        assert_eq!(h, "10.0.0.1");
        assert_eq!(p, 6443);
    }

    #[test]
    fn parse_server_url_rejects_no_scheme() {
        assert!(parse_server_url("host.svc:6443").is_err());
    }

    #[test]
    fn parse_server_url_rejects_bad_port() {
        assert!(parse_server_url("https://host.svc:notaport").is_err());
    }

    // -- build_upstream_upgrade_request --

    #[test]
    fn upstream_request_rewrites_auth_and_strips_caller_creds() {
        let headers = client_headers(&[
            ("upgrade", "SPDY/3.1"),
            ("connection", "Upgrade"),
            ("authorization", "Bearer caller-token-do-not-leak"),
            ("x-remote-user", "alice"),
            ("x-remote-group", "system:masters"),
        ]);
        let req = build_upstream_upgrade_request(
            &Method::POST,
            &headers,
            "/api/v1/namespaces/ns/pods/p/exec?command=sh",
            "host.svc",
            6443,
            Some("backend-sa-token"),
        )
        .unwrap();

        assert_eq!(
            req.headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer backend-sa-token"),
            "Authorization must be rewritten to the backend token, never relayed"
        );
        assert!(req.headers().get("x-remote-user").is_none());
        assert!(req.headers().get("x-remote-group").is_none());
        assert_eq!(
            req.headers().get("host").and_then(|v| v.to_str().ok()),
            Some("host.svc:6443")
        );
        assert_eq!(
            req.uri().path_and_query().unwrap().as_str(),
            "/api/v1/namespaces/ns/pods/p/exec?command=sh"
        );
    }

    #[test]
    fn upstream_request_forwards_negotiation_headers() {
        let headers = client_headers(&[
            ("upgrade", "websocket"),
            ("connection", "Upgrade"),
            ("sec-websocket-protocol", "v5.channel.k8s.io"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ]);
        let req = build_upstream_upgrade_request(
            &Method::GET,
            &headers,
            "/api/v1/.../exec",
            "host.svc",
            443,
            None,
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
                req.headers().get(h).is_some(),
                "must forward upgrade-negotiation header: {h}"
            );
        }
        // No bearer token configured -> no Authorization injected.
        assert!(req.headers().get("authorization").is_none());
    }
}
