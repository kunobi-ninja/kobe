mod api;
mod backend;
mod controllers;
mod crd;
mod diagnostics;
mod leader;
mod metrics;
pub mod pki;
mod pool;
mod telemetry;
mod velero;

use velero::VeleroCoordinator;

use std::sync::Arc;

use kube::Client;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use api::auth::JwtAuthenticator;
use api::routes::{build_router, AppState};
use backend::{BackendDispatch, BackendFactory, K3kBackend};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the rustls crypto provider before any TLS usage.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");

    let _otel_provider = telemetry::init()?;

    metrics::init();
    info!("Starting kunobi-pool-operator");

    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create Kubernetes client: {e}");
            eprintln!("FATAL: Failed to create Kubernetes client: {e}");
            return Err(e.into());
        }
    };
    let namespace = std::env::var("OPERATOR_NAMESPACE").unwrap_or_else(|_| "kunobi-pool".into());

    info!(namespace = %namespace, "Connected to Kubernetes");

    info!("Available backends: k3k, direct-k3s, direct-k0s, capi, kobe-sync");

    // Wait for our CRDs to be established before starting controllers.
    // This prevents a crash-loop when the operator starts before the Helm chart
    // has finished installing CRDs (e.g. during initial rollout or CRD migration).
    wait_for_crds(&client).await?;

    // Optional shared PostgreSQL datastore for direct-k3s and direct-k0s backends.
    let pg_base_url = std::env::var("POSTGRES_URL").ok();
    let pg_pool = if let Some(ref url) = pg_base_url {
        match sqlx::PgPool::connect(url).await {
            Ok(pool) => {
                info!("PostgreSQL connected — direct-k3s and direct-k0s golden templates enabled");
                Some(pool)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to connect to PostgreSQL, direct backends will use embedded datastore"
                );
                None
            }
        }
    } else {
        None
    };

    // BackendFactory produces the right backend per profile.
    let factory = BackendFactory::new(client.clone(), pg_pool, pg_base_url);

    // Default backend for API routes and backward compatibility.
    let backend = BackendDispatch::K3k(K3kBackend::new(client.clone()));

    let leader_rx =
        leader::run_leader_election(client.clone(), &namespace, "kunobi-pool-operator").await?;

    let shutdown = CancellationToken::new();

    let pools = Arc::new(RwLock::new(std::collections::HashMap::new()));

    let authenticator = Arc::new(JwtAuthenticator::new());

    // Start AuthPolicy watcher
    let auth_client = client.clone();
    let auth_ns = namespace.clone();
    let auth_authenticator = authenticator.clone();
    let auth_shutdown = shutdown.clone();
    let auth_handle = tokio::spawn(async move {
        controllers::auth_policy::run_auth_policy_watcher(
            auth_client,
            &auth_ns,
            auth_authenticator,
            auth_shutdown,
        )
        .await;
    });

    // Detect Velero CRDs for snapshot support
    let velero = detect_velero(&client).await;

    // Start profile controller
    let profile_client = client.clone();
    let profile_ns = namespace.clone();
    let profile_pools = pools.clone();
    let profile_shutdown = shutdown.clone();
    let profile_backend = backend.clone();
    let profile_velero = velero.clone();
    let profile_factory = factory.clone();
    let profile_handle = tokio::spawn(async move {
        controllers::profile::run_profile_controller(
            profile_client,
            &profile_ns,
            profile_backend,
            profile_pools,
            profile_velero,
            Some(profile_factory),
            profile_shutdown,
        )
        .await;
    });

    // Start claim controller
    let claim_client = client.clone();
    let claim_ns = namespace.clone();
    let claim_pools = pools.clone();
    let claim_authenticator = authenticator.clone();
    let claim_shutdown = shutdown.clone();
    let claim_backend = backend.clone();
    let claim_factory = factory.clone();
    let claim_handle = tokio::spawn(async move {
        controllers::claim::run_claim_controller(
            claim_client,
            &claim_ns,
            claim_backend,
            claim_pools,
            claim_authenticator,
            Some(claim_factory),
            claim_shutdown,
        )
        .await;
    });

    // Monitor controller tasks — if any panics or exits, trigger shutdown
    let controller_shutdown = shutdown.clone();
    tokio::spawn(async move {
        tokio::select! {
            result = auth_handle => {
                match result {
                    Ok(()) => warn!("Auth policy watcher exited unexpectedly"),
                    Err(e) => error!("Auth policy watcher panicked: {e}"),
                }
            }
            result = profile_handle => {
                match result {
                    Ok(()) => warn!("Profile controller exited unexpectedly"),
                    Err(e) => error!("Profile controller panicked: {e}"),
                }
            }
            result = claim_handle => {
                match result {
                    Ok(()) => warn!("Claim controller exited unexpectedly"),
                    Err(e) => error!("Claim controller panicked: {e}"),
                }
            }
        }
        error!("Controller died, initiating shutdown");
        controller_shutdown.cancel();
    });

    // Build HTTP server
    let state = AppState {
        client,
        authenticator,
        namespace,
        pools: pools.clone(),
        backend,
    };

    let app = build_router(state);

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!(addr = %bind_addr, "HTTP server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(leader_rx, shutdown))
        .await?;

    telemetry::shutdown(_otel_provider);
    Ok(())
}

/// Wait for required CRDs to be established, retrying with backoff.
///
/// The operator depends on `ClusterPoolProfile`, `ClusterClaim`, `AuthPolicy`,
/// and `DataStore` CRDs. If these are not yet installed (e.g. Helm CRD
/// installation is still in progress), we retry rather than crash.
async fn wait_for_crds(client: &Client) -> anyhow::Result<()> {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;

    let required_crds = [
        "clusterpoolprofiles.kobe.kunobi.ninja",
        "clusterclaims.kobe.kunobi.ninja",
        "authpolicies.kobe.kunobi.ninja",
        "datastores.kobe.kunobi.ninja",
    ];

    let crd_api: kube::api::Api<CustomResourceDefinition> = kube::api::Api::all(client.clone());
    let mut delay = std::time::Duration::from_secs(2);
    let max_delay = std::time::Duration::from_secs(30);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(300);

    loop {
        let mut missing = Vec::new();
        for crd_name in &required_crds {
            match crd_api.get(crd_name).await {
                Ok(crd) => {
                    let established = crd
                        .status
                        .as_ref()
                        .and_then(|s| s.conditions.as_ref())
                        .map(|conditions| {
                            conditions
                                .iter()
                                .any(|c| c.type_ == "Established" && c.status == "True")
                        })
                        .unwrap_or(false);
                    if !established {
                        missing.push(*crd_name);
                    }
                }
                Err(_) => missing.push(*crd_name),
            }
        }

        if missing.is_empty() {
            info!("All required CRDs are established");
            return Ok(());
        }

        if tokio::time::Instant::now() > deadline {
            anyhow::bail!(
                "Timed out waiting for CRDs after 5 minutes. Missing: {}",
                missing.join(", ")
            );
        }

        warn!(
            missing = %missing.join(", "),
            retry_in = ?delay,
            "Required CRDs not yet established, waiting..."
        );
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(max_delay);
    }
}

/// Detect whether Velero CRDs are installed in the cluster.
///
/// Returns `Some(VeleroCoordinator)` if the `backups.velero.io` CRD exists,
/// `None` otherwise. This enables graceful degradation when Velero is not installed.
async fn detect_velero(client: &Client) -> Option<VeleroCoordinator> {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    let crd_api: kube::api::Api<CustomResourceDefinition> = kube::api::Api::all(client.clone());
    match crd_api.get("backups.velero.io").await {
        Ok(_) => {
            info!("Velero CRDs detected, snapshot support enabled");
            Some(VeleroCoordinator::new(client.clone()))
        }
        Err(_) => {
            info!("Velero CRDs not found, snapshot support disabled");
            None
        }
    }
}

async fn shutdown_signal(
    mut leader_rx: tokio::sync::watch::Receiver<bool>,
    shutdown: CancellationToken,
) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    let leader_lost = async {
        loop {
            if leader_rx.changed().await.is_err() {
                warn!("Leader election watch channel closed unexpectedly");
                break;
            }
            if !*leader_rx.borrow() {
                break;
            }
        }
    };

    tokio::select! {
        _ = ctrl_c => info!("Received Ctrl+C, shutting down"),
        _ = terminate => info!("Received SIGTERM, shutting down"),
        _ = leader_lost => info!("Lost leader lease, shutting down"),
    }

    shutdown.cancel();
    info!("Shutdown signal sent to all background tasks");
}

#[cfg(test)]
mod testutil;

/// Force the `controllers` module to be compiled for tests.
/// Without this, the test harness eliminates the module as dead code
/// because it is only used inside `main()`.
#[cfg(test)]
mod controllers_test_anchor {
    #[allow(unused_imports)]
    use crate::controllers::claim;
    #[allow(unused_imports)]
    use crate::controllers::profile;
}

/// Force the `diagnostics` module to be compiled for tests.
#[cfg(test)]
mod diagnostics_test_anchor {
    #[allow(unused_imports)]
    use crate::diagnostics::bundle;
}

#[cfg(test)]
mod detect_velero_tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn mock_client(server: &MockServer) -> Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::testutil::mock_k8s_client(server)
    }

    #[tokio::test]
    async fn test_detect_velero_found() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        let crd_response = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {
                "name": "backups.velero.io"
            },
            "spec": {
                "group": "velero.io",
                "names": { "kind": "Backup", "plural": "backups" },
                "scope": "Namespaced"
            }
        });

        Mock::given(method("GET"))
            .and(path(
                "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/backups.velero.io",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(crd_response))
            .expect(1)
            .mount(&server)
            .await;

        let result = detect_velero(&client).await;
        assert!(
            result.is_some(),
            "detect_velero should return Some when CRD exists"
        );
    }

    #[tokio::test]
    async fn test_detect_velero_not_found() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        Mock::given(method("GET"))
            .and(path(
                "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/backups.velero.io",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "customresourcedefinitions",
                    "backups.velero.io",
                )),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = detect_velero(&client).await;
        assert!(
            result.is_none(),
            "detect_velero should return None when CRD not found"
        );
    }

    #[tokio::test]
    async fn test_detect_velero_api_error() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        let error_response = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Status",
            "metadata": {},
            "status": "Failure",
            "message": "Internal server error",
            "reason": "InternalError",
            "code": 500
        });

        Mock::given(method("GET"))
            .and(path(
                "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/backups.velero.io",
            ))
            .respond_with(ResponseTemplate::new(500).set_body_json(error_response))
            .expect(1)
            .mount(&server)
            .await;

        let result = detect_velero(&client).await;
        assert!(
            result.is_none(),
            "detect_velero should return None on API error (graceful degradation)"
        );
    }
}
