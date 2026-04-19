//! kobe-sync v2 binary entry point.
//!
//! This is the main entry point for the kobe-sync virtual cluster runtime.
//! In v2, the kube-apiserver and KCM run as separate containers in the same
//! pod. kobe-sync's job is to:
//!
//! 1. Wait for the local kube-apiserver to be healthy
//! 2. Build a kube client for the virtual apiserver (localhost)
//! 3. Start v2 resource syncers (virtual -> host)
//! 4. Start the TLS reverse proxy
//! 5. Serve until shutdown
//!
//! kobe-sync is a "dumb runtime" -- it knows nothing about Kobe, claims,
//! TTLs, or pools. It receives its configuration from environment variables
//! and/or a ConfigMap, and runs until terminated.

mod kobe_sync;
mod pki;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use kobe_sync::certs::CertificateManager;
use kobe_sync::config::KobeSyncRuntimeConfig;
use kobe_sync::proxy::{ProxyConfig, VirtualClusterProxy};
use kobe_sync::syncer::translator::NameTranslator;
use kobe_sync::syncer::{self, SyncerContextV2};

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

    info!("Starting kobe-sync v2 virtual cluster runtime");

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

    // 6. Build virtual cluster client (connects to localhost apiserver)
    let virtual_client = build_virtual_client(&config.virtual_api_url, &cert_manager)
        .await
        .context("Failed to build virtual cluster kube client")?;

    // 7. Build v2 syncer context (dual-client: virtual + host)
    let translator = Arc::new(NameTranslator::new(config.host_namespace.clone()));
    let ctx = Arc::new(SyncerContextV2 {
        virtual_client,
        host_client: host_client.clone(),
        translator: translator.clone(),
        host_namespace: config.host_namespace.clone(),
        skip_namespaces: config.skip_namespaces.clone(),
    });

    let shutdown = CancellationToken::new();

    // 8. Start v2 resource syncers
    let syncer_handles =
        syncer::start_syncers_v2(ctx.clone(), &config.enabled_syncers, shutdown.clone());
    info!(count = syncer_handles.len(), "v2 resource syncers started");

    // 9. Start always-on syncers (fake nodes, status) -- these run regardless
    //    of the enabled_syncers config since they are essential for cluster health.
    let always_on = vec!["fake_nodes".to_string(), "status".to_string()];
    let always_on_handles = syncer::start_syncers_v2(ctx.clone(), &always_on, shutdown.clone());
    info!(count = always_on_handles.len(), "Always-on syncers started");

    // 10. Start TLS proxy
    //     For now we use the v1 VirtualClusterProxy infrastructure which does
    //     full request rewriting. VirtualClusterProxyV2 (thin TLS gateway) has
    //     placeholder handlers and will be wired in a future task.
    let virtual_namespaces = Arc::new(RwLock::new(
        config
            .default_namespaces
            .iter()
            .cloned()
            .collect::<HashSet<String>>(),
    ));

    let (host_api_url, host_token) =
        load_host_config().context("Failed to load host API server configuration")?;

    info!(host_api_url = %host_api_url, "Host API server configured");

    let proxy_config = ProxyConfig {
        tls_config,
        host_api_url,
        host_token,
        translator: translator.clone(),
        virtual_namespaces,
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
        "kobe-sync v2 is ready"
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

    info!("kobe-sync v2 shutdown complete");
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

/// Build a `kube::Client` that talks to the local virtual kube-apiserver.
///
/// Uses `CertificateManager::generate_kcm_kubeconfig()` to produce a
/// kubeconfig with embedded client certificates signed by the cluster CA,
/// then constructs a `kube::Client` from it.
async fn build_virtual_client(
    url: &str,
    cert_manager: &CertificateManager,
) -> Result<kube::Client> {
    let kubeconfig_yaml = CertificateManager::generate_kcm_kubeconfig(
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
