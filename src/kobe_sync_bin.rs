//! kobe-sync binary entry point.
//!
//! This is the main entry point for the kobe-sync virtual cluster runtime.
//! The kube-apiserver and KCM run as separate containers in the same
//! pod. kobe-sync's job is to:
//!
//! 1. Wait for the local kube-apiserver to be healthy
//! 2. Build a kube client for the virtual apiserver (localhost)
//! 3. Start resource syncers (virtual -> host)
//! 4. Start the TLS reverse proxy
//! 5. Serve until shutdown
//!
//! kobe-sync is a "dumb runtime" -- it knows nothing about Kobe, claims,
//! TTLs, or pools. It receives its configuration from environment variables
//! and/or a ConfigMap, and runs until terminated.

mod kobe_sync;
mod pki;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use kobe_sync::certs::CertificateManager;
use kobe_sync::config::KobeSyncRuntimeConfig;
use kobe_sync::proxy::{ProxyConfig, VirtualClusterProxy};
use kobe_sync::syncer::translator::NameTranslator;
use kobe_sync::syncer::{self, SyncerContext};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    info!("Starting kobe-sync virtual cluster runtime");

    // 2. Load configuration
    let config = KobeSyncRuntimeConfig::load_from_env()
        .context("Failed to load configuration from environment")?;

    info!(
        host_namespace = %config.host_namespace,
        cluster_name = %config.cluster_name,
        proxy_port = config.proxy_port,
        metrics_port = config.metrics_port,
        virtual_api_url = %config.virtual_api_url,
        syncers = ?config.enabled_syncers,
        "Configuration loaded"
    );

    // 3. Initialize host kube client (in-cluster)
    let host_client = kube::Client::try_default()
        .await
        .context("Failed to create in-cluster Kubernetes client")?;

    // 4. Load/generate PKI and build TLS config
    let service_name = format!("{}-api", config.cluster_name);
    let sans = vec![
        service_name.clone(),
        format!("{}.{}", service_name, config.host_namespace),
        format!("{}.{}.svc", service_name, config.host_namespace),
        format!(
            "{}.{}.svc.cluster.local",
            service_name, config.host_namespace
        ),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];

    let cert_manager = CertificateManager::load_or_generate(
        &host_client,
        &config.cluster_name,
        &config.host_namespace,
        sans,
    )
    .await
    .context("Failed to initialize certificate manager")?;

    info!("Certificate manager initialized");

    let tls_config = cert_manager
        .build_server_config()
        .context("Failed to build TLS server config")?;

    // 5. Wait for local kube-apiserver to be healthy
    info!(
        url = %config.virtual_api_url,
        "Waiting for virtual kube-apiserver"
    );
    wait_for_apiserver(&config.virtual_api_url).await?;
    info!("Virtual kube-apiserver is ready");

    // 5b. Bootstrap kobe-sync RBAC on the virtual apiserver.
    //
    //    The vkobe virtual apiserver does not run the standard RBAC
    //    bootstrap that creates `system:kube-controller-manager`,
    //    `system:basic-user`, `system:discovery`, etc. — every watcher
    //    authenticating as one of those subjects dies on first list with
    //    `clusterrole "..." not found`. Rather than depend on those
    //    built-in roles, we install our own kobe-sync ClusterRole +
    //    ClusterRoleBinding here using a one-shot bootstrap kubeconfig
    //    issued under O=system:masters (the apiserver's hard-coded
    //    superuser short-circuit). The bootstrap client is dropped
    //    immediately after the apply succeeds; from this point on, every
    //    connection uses the runtime kubeconfig (CN=system:kobe-sync,
    //    O=system:kobe-sync) bound only to the role we just installed.
    //
    //    See `crate::kobe_sync::bootstrap::ensure_rbac` for the rule set.
    {
        let bootstrap_kubeconfig_yaml = CertificateManager::generate_sync_bootstrap_kubeconfig(
            cert_manager.ca_cert_pem(),
            cert_manager.ca_key_pem(),
            &config.virtual_api_url,
        )
        .context("Failed to mint kobe-sync bootstrap kubeconfig")?;
        let bootstrap_kubeconfig = kube::config::Kubeconfig::from_yaml(&bootstrap_kubeconfig_yaml)?;
        let bootstrap_kube_config =
            kube::Config::from_custom_kubeconfig(bootstrap_kubeconfig, &Default::default()).await?;
        let bootstrap_client = kube::Client::try_from(bootstrap_kube_config)
            .context("Failed to build kobe-sync bootstrap client")?;

        kobe_sync::bootstrap::ensure_rbac(&bootstrap_client)
            .await
            .context("Failed to bootstrap kobe-sync RBAC on virtual apiserver")?;

        // bootstrap_client (and the system:masters cert it carries) is
        // dropped here — the runtime client built below uses the
        // system:kobe-sync identity that the binding above just gave
        // proper permissions.
    }
    info!("kobe-sync RBAC bootstrap complete");

    // 6. Build virtual cluster client (connects to localhost apiserver)
    let virtual_client = build_virtual_client(&config.virtual_api_url, &cert_manager)
        .await
        .context("Failed to build virtual cluster kube client")?;

    // 7. Build syncer context (dual-client: virtual + host)
    let translator = Arc::new(NameTranslator::new(config.host_namespace.clone()));
    let ctx = Arc::new(SyncerContext {
        virtual_client,
        host_client: host_client.clone(),
        translator: translator.clone(),
        host_namespace: config.host_namespace.clone(),
        skip_namespaces: config.skip_namespaces.clone(),
    });

    let shutdown = CancellationToken::new();

    // 8. Start always-on syncers — these are *infrastructural*, not
    //    workload-shaped. They run regardless of the user's
    //    `enabled_syncers` because vkobe simply cannot function for
    //    realistic workloads without them:
    //
    //      - `fake_nodes`: virtual cluster has no scheduler running
    //        inside; FakeNodeSyncer mirrors host nodes into the
    //        virtual apiserver so the operator's StatusSyncer can
    //        bind virtual pods to a node-name that exists.
    //      - `status`: virtual pods need their `.status` patched from
    //        the projected host-side counterpart so users see real
    //        Pending/Running/etc.
    //      - `service_accounts`: any pod referencing a custom SA
    //        (flux's controllers, kunobi-ci's controllers, basically
    //        every realistic workload) gets rejected by the host
    //        apiserver at admission with `serviceaccount "<name>" not
    //        found` if the SA isn't mirrored. That breaks the chain
    //        that materializes fake nodes (`FakeNodeSyncer` is
    //        reactive on host pods → no host pods → no fake nodes →
    //        nothing schedules).
    //
    //    This list grew to include `service_accounts` after a v0.22.x
    //    series of regressions where user-supplied
    //    `spec.backend.vkobe.syncers` lists silently omitted it,
    //    leaving production vkobe clusters silently nodeless. Making
    //    it always-on means a stale manifest can never reintroduce
    //    that failure mode.
    let always_on = vec![
        "fake_nodes".to_string(),
        "status".to_string(),
        "service_accounts".to_string(),
    ];
    let always_on_handles = syncer::start_syncers(ctx.clone(), &always_on, shutdown.clone());
    info!(count = always_on_handles.len(), "Always-on syncers started");

    // 9. Start configurable resource syncers — anything in the
    //    user's `enabled_syncers` list that isn't already started by
    //    step 8. The dedup is important: starting the same syncer
    //    twice would put two watchers on the same virtual-apiserver
    //    stream, racing to handle each event and potentially
    //    double-applying or thrashing on patch conflicts.
    let configurable_syncers: Vec<String> = config
        .enabled_syncers
        .iter()
        .filter(|name| !always_on.contains(name))
        .cloned()
        .collect();
    let suppressed: Vec<&String> = config
        .enabled_syncers
        .iter()
        .filter(|name| always_on.contains(name))
        .collect();
    if !suppressed.is_empty() {
        info!(
            ?suppressed,
            "Skipping configurable syncers already started as always-on"
        );
    }
    let syncer_handles =
        syncer::start_syncers(ctx.clone(), &configurable_syncers, shutdown.clone());
    info!(count = syncer_handles.len(), "resource syncers started");

    // 10. Start TLS proxy (front-proxy gateway)
    //     The proxy terminates client TLS, validates client certs against the
    //     cluster CA, and forwards requests to the LOCAL kube-apiserver
    //     sidecar via mTLS using the front-proxy-client cert. The original
    //     caller's identity is carried in X-Remote-User / X-Remote-Group
    //     headers — the same K8s front-proxy auth pattern that
    //     kube-aggregator uses for extension API servers.
    //
    //     Pod subresources (exec/logs/attach/portforward) are intercepted
    //     and proxied to the host apiserver instead, since the actual
    //     workload pods live there under translated names.
    let (host_api_url, host_token) =
        load_host_config().context("Failed to load host API server configuration")?;

    info!(host_api_url = %host_api_url, "Host API server configured");

    let front_proxy_client_cert = cert_manager
        .front_proxy_client_cert_pem()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Front-proxy client certificate not found in {}-certs Secret. \
                 The vkobe pool operator must pre-create the Secret with the full \
                 PKI tree before kobe-sync starts.",
                config.cluster_name
            )
        })?
        .to_string();
    let front_proxy_client_key = cert_manager
        .front_proxy_client_key_pem()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Front-proxy client key not found in {}-certs Secret. \
                 The vkobe pool operator must pre-create the Secret with the full \
                 PKI tree before kobe-sync starts.",
                config.cluster_name
            )
        })?
        .to_string();

    let proxy_config = ProxyConfig {
        tls_config,
        apiserver_url: config.virtual_api_url.clone(),
        apiserver_ca_pem: cert_manager.ca_cert_pem().to_string(),
        front_proxy_client_cert_pem: front_proxy_client_cert,
        front_proxy_client_key_pem: front_proxy_client_key,
        host_apiserver_url: host_api_url,
        host_token,
        translator: translator.clone(),
        proxy_port: config.proxy_port,
        metrics_port: config.metrics_port,
    };

    let proxy = Arc::new(VirtualClusterProxy::new(proxy_config).context("Failed to create proxy")?);

    let proxy_handle = tokio::spawn({
        let proxy = proxy.clone();
        let shutdown = shutdown.clone();
        async move {
            if let Err(e) = proxy.run(shutdown).await {
                error!(error = %e, "Proxy server error");
            }
        }
    });

    let metrics_handle = tokio::spawn({
        let proxy = proxy.clone();
        let shutdown = shutdown.clone();
        async move {
            if let Err(e) = proxy.run_metrics_server(shutdown).await {
                error!(error = %e, "Metrics server error");
            }
        }
    });

    info!(
        proxy_port = config.proxy_port,
        metrics_port = config.metrics_port,
        "kobe-sync is ready"
    );

    // 11. Wait for shutdown signal
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

    tokio::select! {
        _ = ctrl_c => info!("Received Ctrl+C, shutting down"),
        _ = terminate => info!("Received SIGTERM, shutting down"),
    }

    // 12. Graceful shutdown with timeout
    info!("Initiating graceful shutdown");
    shutdown.cancel();

    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        for handle in syncer_handles {
            let _ = handle.await;
        }
        for handle in always_on_handles {
            let _ = handle.await;
        }
        let _ = proxy_handle.await;
        let _ = metrics_handle.await;
    })
    .await;

    info!("kobe-sync shutdown complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: wait for local kube-apiserver
// ---------------------------------------------------------------------------

/// Wait until the local kube-apiserver is accepting TCP connections.
///
/// The kube-apiserver runs as a sidecar container in the same pod. We use a
/// simple TCP connect probe rather than an HTTP healthcheck because the server
/// uses self-signed TLS and we don't want to pull in a full HTTP client just
/// for the readiness check.
async fn wait_for_apiserver(url: &str) -> Result<()> {
    // Extract host:port from the URL (e.g., "https://localhost:6443" -> "localhost:6443")
    let addr = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    for attempt in 0..120u32 {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(_) => {
                info!(
                    attempt,
                    addr, "Virtual kube-apiserver is accepting connections"
                );
                // Give the apiserver a moment to finish initialization after
                // the TCP listener is up.
                tokio::time::sleep(Duration::from_secs(2)).await;
                return Ok(());
            }
            Err(_) => {
                if attempt % 10 == 0 {
                    info!(attempt, url, "Waiting for virtual kube-apiserver...");
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    anyhow::bail!("Timed out waiting for virtual kube-apiserver at {url}")
}

// ---------------------------------------------------------------------------
// Helper: build virtual cluster client
// ---------------------------------------------------------------------------

/// Build a `kube::Client` that talks to the local virtual kube-apiserver
/// using the kobe-sync **runtime** identity (CN=`system:kobe-sync`,
/// O=`system:kobe-sync`). The cluster RBAC bound to that identity is
/// installed by `kobe_sync::bootstrap::ensure_rbac` earlier in startup,
/// so this client is least-privilege from the moment it is created.
///
/// Earlier revisions reused `generate_kcm_kubeconfig` here, which gave
/// the syncer the `system:kube-controller-manager` identity — that
/// fails on the vkobe virtual apiserver because the standard RBAC
/// bootstrap roles are not present, and the watcher 403'd forever.
async fn build_virtual_client(
    url: &str,
    cert_manager: &CertificateManager,
) -> Result<kube::Client> {
    let kubeconfig_yaml = CertificateManager::generate_sync_kubeconfig(
        cert_manager.ca_cert_pem(),
        cert_manager.ca_key_pem(),
        url,
    )?;

    let kubeconfig = kube::config::Kubeconfig::from_yaml(&kubeconfig_yaml)?;
    let config = kube::Config::from_custom_kubeconfig(kubeconfig, &Default::default()).await?;
    Ok(kube::Client::try_from(config)?)
}

// ---------------------------------------------------------------------------
// Helper: load host API server config
// ---------------------------------------------------------------------------

/// Load host API server URL and ServiceAccount token from in-cluster paths.
fn load_host_config() -> Result<(String, String)> {
    let host = std::env::var("KUBERNETES_SERVICE_HOST")
        .context("KUBERNETES_SERVICE_HOST not set -- are we running in-cluster?")?;
    let port =
        std::env::var("KUBERNETES_SERVICE_PORT").context("KUBERNETES_SERVICE_PORT not set")?;
    let token = std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
        .context("Failed to read ServiceAccount token -- are we running in-cluster?")?;

    Ok((format!("https://{host}:{port}"), token.trim().to_string()))
}
