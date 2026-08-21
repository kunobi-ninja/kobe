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
mod sandbox_access_ledger;
mod sandbox_ledger;
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

// One fully usable aliased Sandbox with an active operation needs a gate, a
// quota token, an alias token, and its principal ledger simultaneously.
const MIN_SANDBOX_LEDGER_OBJECT_LIMIT: u32 = 4;

fn parse_sandbox_ledger_object_limit(value: &str) -> Option<u32> {
    value
        .parse::<u32>()
        .ok()
        .filter(|limit| *limit >= MIN_SANDBOX_LEDGER_OBJECT_LIMIT)
}

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

    // Build identity, stated once per process and exported as a gauge.
    //
    // "Starting kobe-operator" already marked a restart, but carried no fields,
    // so which build produced a given log line could only be inferred by
    // correlating the ReplicaSet hash in the pod name against rollout history.
    // Both values are baked by build.rs and already used elsewhere
    // (`api::routes` serves the version; the profile controller stamps it into
    // `provenance.operatorVersion`) — they were simply never announced.
    let build_version = env!("BUILD_VERSION");
    let build_commit = env!("BUILD_COMMIT");
    metrics::BUILD_INFO
        .with_label_values(&[build_version, build_commit])
        .set(1);
    info!(
        version = build_version,
        commit = build_commit,
        "Starting kobe-operator"
    );

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
    let namespace = std::env::var("OPERATOR_NAMESPACE").unwrap_or_else(|_| "kunobi-pool".into());
    let pod_namespace = std::env::var("POD_NAMESPACE").unwrap_or_else(|_| namespace.clone());
    let pod_name = std::env::var("POD_NAME").unwrap_or_default();

    // Do not bind the HTTP listener until every replica has certified the
    // pinned controller, webhook and a real Pod-owned Claim lifecycle. This is
    // intentionally stronger than CRD discovery: a wedged controller or a
    // broken webhook must make the whole Sandbox surface fail closed.
    if agent_sandbox_mode.enabled() {
        if pod_name.is_empty() {
            error!("POD_NAME is required for the crash-safe Agent Sandbox runtime canary");
            std::process::exit(1);
        }
        match sandbox_runtime::wait_for_runtime(&client, &pod_namespace, &pod_name).await {
            Ok(()) => info!(?agent_sandbox_mode, "Agent Sandbox runtime certified"),
            Err(err) => {
                error!(reason = err.reason_code(), "{err}");
                std::process::exit(1);
            }
        }
    }

    let sandbox_reservation_namespace = std::env::var("KOBE_SANDBOX_RESERVATION_NAMESPACE")
        .unwrap_or_else(|_| format!("{namespace}-sandbox-ledger"));
    if agent_sandbox_mode.enabled()
        && (sandbox_reservation_namespace == namespace
            || !crate::pool::is_valid_k8s_name(&sandbox_reservation_namespace))
    {
        error!(
            namespace = %sandbox_reservation_namespace,
            "KOBE_SANDBOX_RESERVATION_NAMESPACE must be a valid, dedicated Kubernetes namespace"
        );
        std::process::exit(1);
    }
    if agent_sandbox_mode.enabled() {
        let policy_name = match std::env::var("KOBE_SANDBOX_LEDGER_POLICY_NAME") {
            Ok(value) if crate::pool::is_valid_k8s_name(&value) => value,
            _ => {
                error!("KOBE_SANDBOX_LEDGER_POLICY_NAME must name the enforced ledger controls");
                std::process::exit(1);
            }
        };
        let operator_username = match std::env::var("KOBE_OPERATOR_SERVICE_ACCOUNT_USERNAME") {
            Ok(value) if value.starts_with("system:serviceaccount:") => value,
            _ => {
                error!(
                    "KOBE_OPERATOR_SERVICE_ACCOUNT_USERNAME must be the exact operator identity"
                );
                std::process::exit(1);
            }
        };
        let object_limit = match std::env::var("KOBE_SANDBOX_LEDGER_OBJECT_LIMIT")
            .ok()
            .and_then(|value| parse_sandbox_ledger_object_limit(&value))
        {
            Some(limit) => limit,
            None => {
                error!("KOBE_SANDBOX_LEDGER_OBJECT_LIMIT must be an integer of at least 4");
                std::process::exit(1);
            }
        };
        if let Err(err) = sandbox_ledger::validate(
            &client,
            &sandbox_reservation_namespace,
            &policy_name,
            &operator_username,
            object_limit,
        )
        .await
        {
            error!(error = %err, "Sandbox admission ledger validation failed");
            std::process::exit(1);
        }
        info!(
            namespace = %sandbox_reservation_namespace,
            object_limit,
            "Sandbox admission ledger validated"
        );
    }

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

    let sandbox_serving_replica = if agent_sandbox_mode.enabled() {
        let replica = crate::sandbox_access_ledger::ServingReplica {
            namespace: pod_namespace.clone(),
            pod_name: std::env::var("POD_NAME")
                .map_err(|_| anyhow::anyhow!("POD_NAME is required when Sandbox is enabled"))?,
            pod_uid: std::env::var("POD_UID")
                .map_err(|_| anyhow::anyhow!("POD_UID is required when Sandbox is enabled"))?,
            boot_id: uuid::Uuid::new_v4().to_string(),
        };
        replica.validate()?;
        Some(replica)
    } else {
        None
    };

    // Stream revocation is a per-replica API responsibility, not a leader
    // controller. Start it before this process can serve Sandbox routes and
    // before leader acquisition can block indefinitely. The handle remains
    // supervised below: silently losing the watch would leave upgraded exec,
    // attach, and port-forward connections alive after their lease ends.
    let mut stream_revoker_handle = if agent_sandbox_mode.enabled() {
        let revoker_client = client.clone();
        let revoker_ns = namespace.clone();
        let revoker_shutdown = shutdown.clone();
        let (revoker_ready_tx, revoker_ready_rx) = tokio::sync::oneshot::channel();
        let mut handle = tokio::spawn(async move {
            api::sandbox_streams::run_stream_revoker(
                revoker_client,
                &revoker_ns,
                api::sandbox_streams::registry().clone(),
                revoker_ready_tx,
                revoker_shutdown,
            )
            .await;
        });
        await_critical_task_readiness(
            revoker_ready_rx,
            &mut handle,
            "Sandbox stream revoker",
            &shutdown,
        )
        .await?;
        crate::sandbox_access_ledger::recover_replica(
            &client,
            &sandbox_reservation_namespace,
            sandbox_serving_replica
                .as_ref()
                .expect("enabled Sandbox mode has replica identity"),
        )
        .await?;
        Some(handle)
    } else {
        None
    };

    // ── Start HTTP server immediately (all replicas serve API + health) ──
    let state = AppState {
        client: client.clone(),
        authenticator: authenticator.clone(),
        namespace: namespace.clone(),
        sandbox_reservation_namespace: sandbox_reservation_namespace.clone(),
        sandbox_serving_replica: sandbox_serving_replica.clone(),
        backend: backend.clone(),
        factory: Some(factory.clone()),
        datastore: datastore.clone(),
        connect_cache: Default::default(),
        sandbox_admission_limiter: Default::default(),
        shutdown: shutdown.clone(),
        sandbox_enabled: agent_sandbox_mode.enabled(),
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
    let leader_guard = if let Some(revoker_handle) = stream_revoker_handle.as_mut() {
        acquire_while_critical_task_runs(
            async move { Ok(leader_election.acquire().await?) },
            revoker_handle,
            "Sandbox stream revoker",
            &shutdown,
        )
        .await?
    } else {
        leader_election.acquire().await?
    };

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
    // SandboxLease is admitted and deliberately remain independent from lease
    // garbage collection, so a request that dies in between leaves a `pending`
    // lease with its quota slot and alias consumed. Recovery cannot depend on
    // the affected caller retrying, so this exact-shape-fenced sweep runs for
    // every principal against the dedicated ledger namespace.
    let sandbox_reaper_client = client.clone();
    let sandbox_reaper_ns = namespace.clone();
    let sandbox_reaper_reservation_ns = sandbox_reservation_namespace.clone();
    let sandbox_reaper_shutdown = shutdown.clone();
    let sandbox_reaper_handle = tokio::spawn(async move {
        api::sandbox::run_sandbox_admission_reaper(
            sandbox_reaper_client,
            &sandbox_reaper_ns,
            &sandbox_reaper_reservation_ns,
            sandbox_reaper_shutdown,
        )
        .await;
    });

    let access_ledger_reaper_handle = if agent_sandbox_mode.enabled() {
        let access_client = client.clone();
        let access_sandbox_ns = namespace.clone();
        let access_ledger_ns = sandbox_reservation_namespace.clone();
        let access_shutdown = shutdown.clone();
        Some(tokio::spawn(async move {
            crate::sandbox_access_ledger::run_reaper(
                access_client,
                access_sandbox_ns,
                access_ledger_ns,
                access_shutdown,
            )
            .await;
        }))
    } else {
        None
    };

    // Start Sandbox placement, but ONLY when a validated runtime is present.
    // Spawning it in `disabled` mode would have it watch CRDs that may not
    // exist and log errors forever; spawning it without the #72 validation
    // would let it write objects an incompatible runtime cannot reconcile.
    let (sandbox_controller_handle, execution_reaper_handle) = if agent_sandbox_mode.enabled() {
        let sandbox_client = client.clone();
        let sandbox_ns = namespace.clone();
        let sandbox_reservation_ns = sandbox_reservation_namespace.clone();
        let sandbox_shutdown = shutdown.clone();
        let handle = tokio::spawn(async move {
            controllers::sandbox::run_sandbox_controller(
                sandbox_client,
                &sandbox_ns,
                &sandbox_reservation_ns,
                agent_sandbox_mode,
                sandbox_shutdown,
            )
            .await;
        });

        // Queued executions whose setup owner disappeared are settled here.
        // Running executions remain fail-closed until the exact runner
        // reports a terminal result (or NotFound); elapsed wall time alone
        // is never evidence that their process stopped.
        let execution_reaper_client = client.clone();
        let execution_reaper_ns = namespace.clone();
        let execution_reaper_reservation_ns = sandbox_reservation_namespace.clone();
        let execution_reaper_shutdown = shutdown.clone();
        let execution_reaper_handle = tokio::spawn(async move {
            api::sandbox_executions::run_execution_reaper(
                execution_reaper_client,
                &execution_reaper_ns,
                &execution_reaper_reservation_ns,
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

        (Some(handle), Some(execution_reaper_handle))
    } else {
        info!("Sandbox placement not started (agentSandbox.mode is disabled)");
        (None, None)
    };

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
            result = await_optional_critical_task(access_ledger_reaper_handle) => {
                match result {
                    Ok(()) => warn!("Sandbox access-ledger reaper exited unexpectedly"),
                    Err(e) => error!("Sandbox access-ledger reaper panicked: {e}"),
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
            result = await_optional_critical_task(stream_revoker_handle) => {
                match result {
                    Ok(()) => warn!("Sandbox stream revoker exited unexpectedly"),
                    Err(e) => error!("Sandbox stream revoker panicked: {e}"),
                }
            }
            result = await_optional_critical_task(sandbox_controller_handle) => {
                match result {
                    Ok(()) => warn!("Sandbox placement controller exited unexpectedly"),
                    Err(e) => error!("Sandbox placement controller panicked: {e}"),
                }
            }
            result = await_optional_critical_task(execution_reaper_handle) => {
                match result {
                    Ok(()) => warn!("Sandbox execution reaper exited unexpectedly"),
                    Err(e) => error!("Sandbox execution reaper panicked: {e}"),
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

/// Acquire leadership while proving a pre-leader critical task stays alive.
///
/// Every replica can wait indefinitely for the leader Lease, so merely keeping
/// a task's [`tokio::task::JoinHandle`] for the post-election monitor is not
/// enough. If that task exits while acquisition is pending, cancel the shared
/// shutdown token and fail startup instead of leaving a degraded API replica
/// serving forever.
async fn acquire_while_critical_task_runs<T>(
    acquire: impl std::future::Future<Output = anyhow::Result<T>>,
    critical_task: &mut tokio::task::JoinHandle<()>,
    task_name: &'static str,
    shutdown: &CancellationToken,
) -> anyhow::Result<T> {
    tokio::pin!(acquire);
    tokio::select! {
        result = &mut acquire => result,
        result = &mut *critical_task => {
            shutdown.cancel();
            match result {
                Ok(()) => anyhow::bail!("{task_name} exited unexpectedly before leadership was acquired"),
                Err(error) => anyhow::bail!("{task_name} failed before leadership was acquired: {error}"),
            }
        }
    }
}

/// Wait until a critical per-replica task has established its startup safety
/// invariant, while treating an early return or panic as a startup failure.
///
/// For the Sandbox stream revoker this barrier is the watcher's `InitDone`:
/// the HTTP listener is not created until the initial lease LIST has been
/// completely consumed, so no replica can accept a Sandbox operation with an
/// incomplete revocation baseline.
async fn await_critical_task_readiness(
    readiness: tokio::sync::oneshot::Receiver<Result<(), String>>,
    critical_task: &mut tokio::task::JoinHandle<()>,
    task_name: &'static str,
    shutdown: &CancellationToken,
) -> anyhow::Result<()> {
    tokio::select! {
        readiness = readiness => match readiness {
            Ok(Ok(())) => Ok(()),
            Ok(Err(reason)) => {
                shutdown.cancel();
                anyhow::bail!("{task_name} failed initial synchronization: {reason}")
            }
            Err(error) => {
                shutdown.cancel();
                anyhow::bail!("{task_name} dropped its initial synchronization barrier: {error}")
            }
        },
        result = &mut *critical_task => {
            shutdown.cancel();
            match result {
                Ok(()) => anyhow::bail!("{task_name} exited before initial synchronization"),
                Err(error) => anyhow::bail!("{task_name} failed before initial synchronization: {error}"),
            }
        }
    }
}

/// Await a mode-dependent critical task without waking when it is disabled.
///
/// This lets the single fatal-task monitor supervise Sandbox tasks in
/// `external` mode while retaining the same select topology in `disabled`
/// mode, where no Sandbox task exists.
async fn await_optional_critical_task(
    handle: Option<tokio::task::JoinHandle<()>>,
) -> Result<(), tokio::task::JoinError> {
    match handle {
        Some(handle) => handle.await,
        None => std::future::pending::<Result<(), tokio::task::JoinError>>().await,
    }
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

const LEADER_STEP_DOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Broadcast process shutdown before bounded cooperative leader step-down.
///
/// `LeaderGuard::step_down` performs Kubernetes I/O and can block during the
/// same outage that triggered termination. HTTP graceful shutdown and every
/// cancellation-aware controller must observe the token first; leadership
/// release is then a time-bounded best-effort availability optimization, never
/// the gate on process draining or exit. Returns whether step-down completed.
async fn cancel_before_step_down<F, Fut>(
    shutdown: &CancellationToken,
    timeout: std::time::Duration,
    step_down: F,
) -> bool
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    shutdown.cancel();
    tokio::time::timeout(timeout, step_down()).await.is_ok()
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
        _ = shutdown.cancelled() => error!("Critical background task exited, shutting down"),
    }

    // Wake HTTP and every controller before cooperative step-down. The latter
    // may block on the very API outage that caused shutdown; it must not hold
    // graceful drain hostage.
    if !cancel_before_step_down(&shutdown, LEADER_STEP_DOWN_TIMEOUT, || {
        leader_guard.step_down()
    })
    .await
    {
        warn!(
            timeout = ?LEADER_STEP_DOWN_TIMEOUT,
            "Leader step-down timed out; continuing shutdown"
        );
    }
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
mod sandbox_ledger_config_tests {
    use super::{MIN_SANDBOX_LEDGER_OBJECT_LIMIT, parse_sandbox_ledger_object_limit};

    /// The runtime validator must agree with the chart/schema contract. One
    /// aliased lease with an active operation simultaneously consumes exactly
    /// four objects: gate + quota + alias + principal ledger.
    #[test]
    fn object_limit_covers_gate_quota_alias_and_principal_ledger() {
        assert_eq!(MIN_SANDBOX_LEDGER_OBJECT_LIMIT, 4);
        assert_eq!(parse_sandbox_ledger_object_limit("4"), Some(4));
        assert_eq!(parse_sandbox_ledger_object_limit("3"), None);
        assert_eq!(parse_sandbox_ledger_object_limit("not-a-number"), None);
    }
}

#[cfg(test)]
mod critical_task_supervision_tests {
    use super::{
        acquire_while_critical_task_runs, await_critical_task_readiness,
        await_optional_critical_task, cancel_before_step_down,
    };
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    /// A follower must fail closed if its per-replica revoker exits while
    /// leader acquisition is still pending.
    #[tokio::test]
    async fn critical_task_exit_before_leadership_cancels_shutdown() {
        let shutdown = CancellationToken::new();
        let mut critical_task = tokio::spawn(async {});

        let result = acquire_while_critical_task_runs(
            std::future::pending::<anyhow::Result<()>>(),
            &mut critical_task,
            "test revoker",
            &shutdown,
        )
        .await;

        assert!(
            result
                .expect_err("a dead critical task must fail leader acquisition")
                .to_string()
                .contains("exited unexpectedly before leadership was acquired")
        );
        assert!(
            shutdown.is_cancelled(),
            "critical task exit must wake process shutdown"
        );
    }

    /// A panic is the same availability and safety failure as a clean early
    /// return: neither may leave a follower serving Sandbox routes unwatched.
    #[tokio::test]
    async fn critical_task_panic_before_leadership_cancels_shutdown() {
        let shutdown = CancellationToken::new();
        let mut critical_task = tokio::spawn(async { panic!("revoker panic") });

        let result = acquire_while_critical_task_runs(
            std::future::pending::<anyhow::Result<()>>(),
            &mut critical_task,
            "test revoker",
            &shutdown,
        )
        .await;

        assert!(
            result
                .expect_err("a panicked critical task must fail leader acquisition")
                .to_string()
                .contains("failed before leadership was acquired")
        );
        assert!(shutdown.is_cancelled());
    }

    /// Successful election transfers the still-live task to the normal fatal
    /// monitor instead of consuming or cancelling it.
    #[tokio::test]
    async fn leadership_keeps_critical_task_live_for_post_election_monitoring() {
        let shutdown = CancellationToken::new();
        let mut critical_task = tokio::spawn(std::future::pending::<()>());

        let leader = acquire_while_critical_task_runs(
            async { Ok::<_, anyhow::Error>("leader") },
            &mut critical_task,
            "test revoker",
            &shutdown,
        )
        .await
        .expect("leadership should win while the critical task is healthy");

        assert_eq!(leader, "leader");
        assert!(!shutdown.is_cancelled());
        assert!(!critical_task.is_finished());
        critical_task.abort();
        let _ = critical_task.await;
    }

    /// Startup may proceed only after the critical task explicitly opens its
    /// initial-sync barrier, and the task must remain available to monitor.
    #[tokio::test]
    async fn readiness_barrier_keeps_critical_task_live_for_monitoring() {
        let shutdown = CancellationToken::new();
        let mut critical_task = tokio::spawn(std::future::pending::<()>());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        ready_tx.send(Ok(())).unwrap();

        await_critical_task_readiness(ready_rx, &mut critical_task, "test revoker", &shutdown)
            .await
            .expect("an explicit InitDone signal should open startup");

        assert!(!shutdown.is_cancelled());
        assert!(!critical_task.is_finished());
        critical_task.abort();
        let _ = critical_task.await;
    }

    /// Initial LIST/watch failure must prevent the HTTP startup path and wake
    /// process shutdown.
    #[tokio::test]
    async fn readiness_failure_cancels_shutdown() {
        let shutdown = CancellationToken::new();
        let mut critical_task = tokio::spawn(std::future::pending::<()>());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        ready_tx
            .send(Err("initial list failed".to_string()))
            .unwrap();

        let error =
            await_critical_task_readiness(ready_rx, &mut critical_task, "test revoker", &shutdown)
                .await
                .expect_err("startup must fail closed without an initial lease baseline");

        assert!(error.to_string().contains("initial list failed"));
        assert!(shutdown.is_cancelled());
        critical_task.abort();
        let _ = critical_task.await;
    }

    /// Disabled mode contributes no synthetic completion to the fatal-task
    /// select; other controllers remain the only possible wakeups.
    #[tokio::test]
    async fn absent_optional_critical_task_never_wakes_monitor() {
        let result = tokio::time::timeout(
            Duration::from_millis(10),
            await_optional_critical_task(None),
        )
        .await;

        assert!(result.is_err(), "an absent task must stay pending");
    }

    /// A Kubernetes outage may block cooperative leader release forever. HTTP
    /// draining and admission handoff must already have observed shutdown.
    #[tokio::test]
    async fn shutdown_is_broadcast_and_blocked_leader_step_down_is_bounded() {
        let shutdown = CancellationToken::new();
        let observed = shutdown.clone();
        let completed = tokio::time::timeout(
            Duration::from_secs(1),
            cancel_before_step_down(&shutdown, Duration::from_millis(20), move || {
                assert!(
                    observed.is_cancelled(),
                    "step_down must not start before shutdown is visible"
                );
                std::future::pending::<()>()
            }),
        )
        .await
        .expect("the shutdown helper itself must return after its step-down bound");

        assert!(!completed, "a pending step_down must report timeout");
        assert!(shutdown.is_cancelled());
    }
}

#[cfg(test)]
mod build_identity_tests {
    /// The startup path must not be able to panic the operator.
    ///
    /// `with_label_values` panics when the slice arity disagrees with the
    /// metric's label set, and this call runs in the first few lines of `main`
    /// — before the controllers start and before anything is serving. A
    /// mismatch introduced by later editing the metric's labels without the
    /// call site would crash-loop the operator on rollout, which is a far worse
    /// failure than the missing observability this whole change adds. So
    /// exercise the exact call, not a paraphrase of it.
    #[test]
    fn build_info_gauge_matches_its_call_site() {
        let version = env!("BUILD_VERSION");
        let commit = env!("BUILD_COMMIT");

        crate::metrics::BUILD_INFO
            .with_label_values(&[version, commit])
            .set(1);

        assert_eq!(
            crate::metrics::BUILD_INFO
                .with_label_values(&[version, commit])
                .get(),
            1,
            "build_info must read 1 for the running build's labels"
        );
    }

    /// build.rs must always define both values, so `env!` resolves and the
    /// binary can state its identity. `env!` already fails the compile when a
    /// variable is absent; this catches the subtler case of build.rs emitting
    /// an EMPTY value, which compiles fine and yields a metric labelled with
    /// the empty string.
    #[test]
    fn build_identity_is_never_empty() {
        assert!(
            !env!("BUILD_VERSION").is_empty(),
            "build.rs must fall back to CARGO_PKG_VERSION, never an empty version"
        );
        assert!(
            !env!("BUILD_COMMIT").is_empty(),
            "build.rs must fall back to `unknown`, never an empty commit"
        );
    }
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
