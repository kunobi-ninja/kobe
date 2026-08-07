//! Test-only helpers shared by the kobe-sync unit tests.
//!
//! Compiled under `#[cfg(test)]` only. The operator binary has its own
//! equivalent in `src/testutil.rs`; kobe-sync cannot reuse it because
//! `src/kobe_sync_bin.rs` deliberately does not pull in the operator's
//! module tree (`crate::backend`, `crate::crd`, …).

use std::sync::Arc;

use kube::Client;
use wiremock::MockServer;

use super::syncer::traits::SyncerContext;
use super::syncer::translator::NameTranslator;

/// Host namespace used by every syncer test, matching the pool-member
/// naming the real deployment uses.
pub const HOST_NS: &str = "pool-test";

/// Build a `kube::Client` that talks plain HTTP to a local
/// [`wiremock::MockServer`].
///
/// `root_cert: Some(vec![])` is deliberate: it hands kube an empty trust
/// store instead of letting it fall through to `with_native_roots()`.
/// The connection is plain HTTP so the store is never consulted, and
/// skipping the native load avoids the macOS Security-framework
/// `-36 I/O error` that surfaces when many tests build clients in
/// parallel.
///
/// The provider install is not optional. This build enables both `ring`
/// and `aws-lc-rs`, so rustls cannot pick a process-level
/// `CryptoProvider` on its own and `Client::try_from` panics unless one
/// was already installed. Without this line the kobe-sync tests pass
/// only when some earlier test in the same binary happened to install
/// it first — so the suite goes green while any single test run in
/// isolation (`cargo test --exact <name>`, or a filtered run) panics.
/// `install_default` returns `Err` once a provider exists, which is the
/// normal case here and is deliberately ignored.
pub fn mock_client(server: &MockServer) -> Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = kube::Config {
        cluster_url: server.uri().parse().unwrap(),
        default_namespace: HOST_NS.into(),
        root_cert: Some(Vec::new()),
        ..kube::Config::new(server.uri().parse().unwrap())
    };
    Client::try_from(config).unwrap()
}

/// Build a [`SyncerContext`] whose *host* client points at `server`.
///
/// The virtual client points at the same server; syncer event handlers
/// only ever touch the host side (the virtual side is the watch stream,
/// which tests feed directly as [`kube::runtime::watcher::Event`]s).
pub fn syncer_ctx(server: &MockServer, skip_namespaces: &[&str]) -> SyncerContext {
    SyncerContext {
        virtual_client: mock_client(server),
        host_client: mock_client(server),
        translator: Arc::new(NameTranslator::new(HOST_NS.to_string())),
        host_namespace: HOST_NS.to_string(),
        skip_namespaces: skip_namespaces.iter().map(|s| s.to_string()).collect(),
    }
}

/// Kubernetes-style 404 `Status` body, as returned by a real apiserver
/// for a missing namespaced object.
pub fn k8s_not_found(resource: &str, name: &str) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Status",
        "metadata": {},
        "status": "Failure",
        "message": format!("{resource} \"{name}\" not found"),
        "reason": "NotFound",
        "details": { "name": name, "kind": resource },
        "code": 404,
    })
}
