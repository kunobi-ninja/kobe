mod api;
mod backend;
mod controllers;
mod crd;
mod diagnostics;
mod lease_binding;
mod metrics;
pub mod pki;
mod pool;
mod sandbox;
mod sandbox_runtime;
mod telemetry;
mod velero;

use velero::VeleroCoordinator;

use std::sync::Arc;

use kube::Client;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use api::auth::JwtAuthenticator;
use api::routes::{AppState, build_router};
use backend::{BackendDispatch, BackendFactory, K3sBackend};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the rustls crypto provider before any TLS usage.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");

    let _otel_provider = telemetry::init()?;

    metrics::init();

    // Set the IPAM pool capacity gauge once at startup. The plan is a
    // Rust constant today (see `pool::cidr_alloc::ipam_plan`), so the
    // capacity is fixed for the lifetime of this process. If the plan
    // ever moves to runtime config (a `CIDRPool` CRD), this should be
    // re-evaluated on every spec change instead of once-at-startup.
    metrics::IPAM_POOL_CAPACITY
        .with_label_values::<&str>(&[])
        .set(pool::cidr_alloc::ipam_plan().capacity() as i64);

    info!("Starting kobe-operator");

    // Refuse an unimplemented or unrecognised Agent Sandbox mode at STARTUP.
    // Deferring it to the first Sandbox request would leave a cluster running
    // that looks healthy and fails only when someone tries to use it.
    let agent_sandbox_mode = match sandbox_runtime::mode_from_env() {
        Ok(mode) => {
            info!(?mode, "Agent Sandbox runtime mode");
            mode
        }
        Err(err) => {
            error!(reason = err.reason_code(), "{err}");
            std::process::exit(1);
        }
    };

    let client = Client::try_default().await?;

    // In `external` mode the runtime is the operator's to install, so verify it
    // is actually there and compatible before anything depends on it. Refused
    // at startup rather than per-request: a cluster that looks healthy and only
    // fails when someone tries to use Sandbox is the worse failure.
    //
    // Deliberately no create/delete canary — writing a real SandboxClaim is one
    // of the effects paused on #72. Presence and version are a weaker signal
    // than a canary, and that limit is stated rather than hidden.
    if agent_sandbox_mode == sandbox_runtime::AgentSandboxMode::External {
        match sandbox_runtime::validate_external_runtime(&client).await {
            Ok(()) => info!("Agent Sandbox runtime validated (external, operator-installed)"),
            Err(err) => {
                error!(reason = err.reason_code(), "{err}");
                std::process::exit(1);
            }
        }
    }

    let namespace = std::env::var("OPERATOR_NAMESPACE").unwrap_or_else(|_| "kunobi-pool".into());
    let pod_namespace = std::env::var("POD_NAMESPACE").unwrap_or_else(|_| namespace.clone());

    info!(namespace = %namespace, "Connected to Kubernetes");

    // Wait for our CRDs to be established before starting controllers.
    wait_for_crds(&client).await?;

    info!("Available backends: k3s, k0s, vkobe, capi");

    // Optional shared PostgreSQL datastore for k3s and k0s backends.
    // `POSTGRES_URL_DIR` (a mounted Secret) enables credential hot-reload on
    // rotation; `POSTGRES_URL` is the static legacy path. See SharedDatastore.
    let datastore = crate::backend::datastore::SharedDatastore::from_env().await;

    let factory = BackendFactory::new(client.clone(), datastore.clone());
    let backend = BackendDispatch::K3s(K3sBackend::new(client.clone(), datastore.clone()));
    let shutdown = CancellationToken::new();
    let pools = Arc::new(RwLock::new(std::collections::HashMap::new()));
    let ssh_namespace =
        std::env::var("KOBE_SSH_NAMESPACE").unwrap_or_else(|_| "kobe-system".to_string());
    let authenticator = Arc::new(JwtAuthenticator::new(ssh_namespace));

    // ── Start HTTP server immediately (all replicas serve API + health) ──
    let state = AppState {
        client: client.clone(),
        authenticator: authenticator.clone(),
        namespace: namespace.clone(),
        backend: backend.clone(),
        factory: Some(factory.clone()),
        datastore: datastore.clone(),
        connect_cache: Default::default(),
        sandbox_admission_limiter: Default::default(),
    };

    let app = build_router(state);
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!(addr = %bind_addr, "HTTP server listening");

    let http_shutdown = shutdown.clone();
    let http_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move { http_shutdown.cancelled().await })
            .await
    });

    // ── Start AccessPolicy watcher on ALL replicas (auth is needed everywhere) ──
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

    // ── Wait for leader election before starting controllers ──
    //
    // Lease-based leader election via the shared `kunobi-ha` crate. Acquire
    // blocks until this replica owns the Lease; `changed()` on the guard
    // fires when the Lease is lost (renewal past the renew deadline).
    let leader_election =
        kunobi_ha::leader::LeaderElection::builder(client.clone(), &namespace, "kobe-operator")
            .build();
    let leader_guard = leader_election.acquire().await?;

    // Live-set ConfigMap reconciler (writes kobe-system/kobe-live-instances).
    // Leader-only; consumed by the kobe-host-reaper DaemonSet to decide
    // which `/var/lib/kobe/leases/<name>/` directories are stale.
    let live_set_client = client.clone();
    let live_set_ns = pod_namespace.clone();
    let live_set_shutdown = shutdown.clone();
    let live_set_handle = tokio::spawn(async move {
        controllers::live_set::run_live_set_controller(
            live_set_client,
            &live_set_ns,
            live_set_shutdown,
        )
        .await;
    });

    // Detect Velero CRDs for snapshot support
    let velero = detect_velero(&client).await;

    // Snapshot operator-level config that affects rendered backend
    // resources. Folded into the per-pool spec hash so a sidecar image
    // bump in the operator Deployment env triggers vkobe pool recycling
    // automatically (see `pool::manager::RenderContext`). Read once at
    // startup — env changes already require a Deployment rollout, which
    // restarts the operator and re-evaluates this.
    let render_ctx = pool::RenderContext::from_env();
    info!(
        kobe_sync_image = %render_ctx.kobe_sync_image,
        "Render context initialised"
    );

    // Start profile controller
    let profile_client = client.clone();
    let profile_ns = namespace.clone();
    let profile_pools = pools.clone();
    let profile_shutdown = shutdown.clone();
    let profile_velero = velero.clone();
    let profile_factory = factory.clone();
    let profile_render_ctx = render_ctx.clone();
    let profile_handle = tokio::spawn(async move {
        controllers::profile::run_profile_controller(
            profile_client,
            &profile_ns,
            profile_pools,
            profile_velero,
            Some(profile_factory),
            profile_render_ctx,
            profile_shutdown,
        )
        .await;
    });

    // Start instance controller
    let instance_client = client.clone();
    let instance_ns = namespace.clone();
    let instance_shutdown = shutdown.clone();
    let instance_backend = backend.clone();
    let instance_factory = factory.clone();
    let instance_velero = velero.clone();
    let instance_handle = tokio::spawn(async move {
        controllers::instance::run_instance_controller(
            instance_client,
            &instance_ns,
            instance_backend,
            Some(instance_factory),
            instance_velero,
            instance_shutdown,
        )
        .await;
    });

    // Start lease controller
    let lease_client = client.clone();
    let lease_ns = namespace.clone();
    let lease_pools = pools.clone();
    let lease_authenticator = authenticator.clone();
    let lease_shutdown = shutdown.clone();
    let lease_backend = backend.clone();
    let lease_factory = factory.clone();
    let lease_handle = tokio::spawn(async move {
        controllers::lease::run_lease_controller(
            lease_client,
            &lease_ns,
            lease_backend,
            lease_pools,
            lease_authenticator,
            Some(lease_factory),
            lease_shutdown,
        )
        .await;
    });

    // Start the Sandbox admission reaper. Reservations are created before a
    // SandboxLease is admitted and are garbage-collected only when that lease
    // is DELETED — so a request that dies in between leaves a `pending` lease
    // no controller will ever touch, with its quota slot and alias consumed
    // forever. Recovery cannot depend on the affected caller retrying, so this
    // sweeps for every principal. Independent of Sandbox placement (#73): it
    // only touches admission objects.
    let sandbox_reaper_client = client.clone();
    let sandbox_reaper_ns = namespace.clone();
    let sandbox_reaper_shutdown = shutdown.clone();
    let sandbox_reaper_handle = tokio::spawn(async move {
        api::sandbox::run_sandbox_admission_reaper(
            sandbox_reaper_client,
            &sandbox_reaper_ns,
            sandbox_reaper_shutdown,
        )
        .await;
    });

    // Start Sandbox placement, but ONLY when a validated runtime is present.
    // Spawning it in `disabled` mode would have it watch CRDs that may not
    // exist and log errors forever; spawning it without the #72 validation
    // would let it write objects an incompatible runtime cannot reconcile.
    if agent_sandbox_mode == sandbox_runtime::AgentSandboxMode::External {
        let sandbox_client = client.clone();
        let sandbox_ns = namespace.clone();
        let sandbox_shutdown = shutdown.clone();
        tokio::spawn(async move {
            controllers::sandbox::run_sandbox_controller(
                sandbox_client,
                &sandbox_ns,
                sandbox_shutdown,
            )
            .await;
        });

        // Stream revocation runs on EVERY replica that serves Sandbox
        // operations, not just the controller leader. A replica can only
        // cancel connections it is holding itself — the socket lives in one
        // process — so a leader-elected revoker would leave live streams on
        // every other replica with nobody watching them.
        // Executions left Running by a process that disappeared are settled
        // here. The reserve-then-spawn order buys "never a duplicate spawn"
        // and pays for it with records nobody is left to finish; this is what
        // turns those into an honest `Unknown` rather than a poll that never
        // ends.
        let execution_reaper_client = client.clone();
        let execution_reaper_ns = namespace.clone();
        let execution_reaper_shutdown = shutdown.clone();
        tokio::spawn(async move {
            api::sandbox_executions::run_execution_reaper(
                execution_reaper_client,
                &execution_reaper_ns,
                std::time::Duration::from_secs(60),
                execution_reaper_shutdown,
            )
            .await;
        });

        // Terminal lease records are retired here. `Released` and `Expired`
        // stop consuming capacity when they are written, so nothing leaks —
        // the objects just accumulate, one per Sandbox ever leased, until
        // etcd carries a row for every Sandbox that ever existed. The window
        // is measured in days because the record is an audit trail, and the
        // tick is hourly because nothing on that scale is worth a minute's
        // list churn against the API server.
        let lease_reaper_client = client.clone();
        let lease_reaper_ns = namespace.clone();
        let lease_reaper_shutdown = shutdown.clone();
        let lease_retention = api::sandbox::sandbox_lease_retention(
            std::env::var(api::sandbox::ENV_SANDBOX_LEASE_RETENTION)
                .ok()
                .as_deref(),
        );
        tokio::spawn(async move {
            api::sandbox::run_sandbox_lease_reaper(
                lease_reaper_client,
                &lease_reaper_ns,
                std::time::Duration::from_secs(3600),
                lease_retention,
                lease_reaper_shutdown,
            )
            .await;
        });

        let revoker_client = client.clone();
        let revoker_ns = namespace.clone();
        let revoker_shutdown = shutdown.clone();
        tokio::spawn(async move {
            api::sandbox_streams::run_stream_revoker(
                revoker_client,
                &revoker_ns,
                api::sandbox_streams::registry().clone(),
                revoker_shutdown,
            )
            .await;
        });
    } else {
        info!("Sandbox placement not started (agentSandbox.mode is not external)");
    }

    // Start IPAM controller. Reconciles `CIDRClaim`s against the
    // hardcoded `pool::cidr_alloc::ipam_plan`. The instance controller
    // creates one claim per `ClusterInstance` (with ownerReference);
    // IPAM binds the claim; instance reads back `claim.status` and
    // provisions the backend. See `controllers::ipam` for the design.
    let ipam_client = client.clone();
    let ipam_ns = namespace.clone();
    let ipam_shutdown = shutdown.clone();
    let ipam_handle = tokio::spawn(async move {
        controllers::ipam::run_ipam_controller(ipam_client, &ipam_ns, ipam_shutdown).await;
    });

    // Start KobeStore health controller. Watches `KobeStore` CRs,
    // observes the backing Deployment/StatefulSet pods, and patches a
    // `Healthy` condition into `status.conditions` based on OOMKill /
    // restart loop / NotReady signals. The profile controller reads
    // this condition before creating new ClusterInstances and pauses
    // creates against degraded backends — breaking the bootstrap-
    // fail-recycle loop that compounds load on a failing kine.
    let health_client = client.clone();
    let health_ns = namespace.clone();
    let health_shutdown = shutdown.clone();
    let health_handle = tokio::spawn(async move {
        controllers::kobestore_health::run_kobestore_health_controller(
            health_client,
            &health_ns,
            health_shutdown,
        )
        .await;
    });

    // Monitor all tasks — if any dies, trigger shutdown
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
            result = instance_handle => {
                match result {
                    Ok(()) => warn!("Instance controller exited unexpectedly"),
                    Err(e) => error!("Instance controller panicked: {e}"),
                }
            }
            result = lease_handle => {
                match result {
                    Ok(()) => warn!("Lease controller exited unexpectedly"),
                    Err(e) => error!("Lease controller panicked: {e}"),
                }
            }
            result = ipam_handle => {
                match result {
                    Ok(()) => warn!("IPAM controller exited unexpectedly"),
                    Err(e) => error!("IPAM controller panicked: {e}"),
                }
            }
            result = sandbox_reaper_handle => {
                match result {
                    Ok(()) => warn!("Sandbox admission reaper exited unexpectedly"),
                    Err(e) => error!("Sandbox admission reaper panicked: {e}"),
                }
            }
            result = health_handle => {
                match result {
                    Ok(()) => warn!("KobeStore health controller exited unexpectedly"),
                    Err(e) => error!("KobeStore health controller panicked: {e}"),
                }
            }
            result = live_set_handle => {
                match result {
                    Ok(()) => warn!("Live-set controller exited unexpectedly"),
                    Err(e) => error!("Live-set controller panicked: {e}"),
                }
            }
        }
        error!("Controller died, initiating shutdown");
        controller_shutdown.cancel();
    });

    // Wait for shutdown signal, then stop everything
    shutdown_signal(leader_guard, shutdown).await;

    // Wait for HTTP server to drain
    if let Err(e) = http_handle.await {
        error!("HTTP server error: {e}");
    }

    telemetry::shutdown(_otel_provider);
    Ok(())
}

/// Wait for required CRDs to be established, retrying with backoff.
async fn wait_for_crds(client: &Client) -> anyhow::Result<()> {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;

    let required_crds = [
        "clusterpools.kobe.kunobi.ninja",
        "clusterleases.kobe.kunobi.ninja",
        "clusterinstances.kobe.kunobi.ninja",
        "accesspolicies.kobe.kunobi.ninja",
        "bootstrapconfigs.kobe.kunobi.ninja",
        "kobestores.kobe.kunobi.ninja",
        "cidrclaims.kobe.kunobi.ninja",
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
    mut leader_guard: kunobi_ha::leader::LeaderGuard,
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

    // `lost()` resolves once the renewal task has signalled stepdown —
    // either because the lease expired, another replica took it, or our
    // own renewal task was aborted. No need for a manual poll loop or an
    // is_leader() check; this is the kunobi-ha API designed to drop
    // straight into a tokio::select!.
    let leader_lost = leader_guard.lost();

    tokio::select! {
        _ = ctrl_c => info!("Received Ctrl+C, shutting down"),
        _ = terminate => info!("Received SIGTERM, shutting down"),
        _ = leader_lost => info!("Lost leader lease, shutting down"),
    }

    // Cooperative step-down so the next replica picks up the Lease quickly
    // (within retry_period) instead of waiting for the full lease TTL to
    // expire.
    leader_guard.step_down().await;

    shutdown.cancel();
    info!("Shutdown signal sent to all background tasks");
}

#[cfg(test)]
mod testutil;

/// Force the `controllers` module to be compiled for tests.
#[cfg(test)]
mod controllers_test_anchor {
    #[allow(unused_imports)]
    use crate::controllers::lease;
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
