use std::time::Duration;

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Secret;
use kube::Client;
use kube::api::{Api, ObjectMeta, Patch, PatchParams};
use std::collections::BTreeMap;
use tracing::info;

const DEFAULT_KUBECONFIG_PATH: &str = "/var/lib/k0s/pki/admin.conf";
const DEFAULT_CLUSTER_DOMAIN: &str = "cluster.local";

/// Rewrite the kubeconfig's loopback server URL to the FQDN of the
/// cluster's Service. The FQDN form (4 dots) avoids the musl libc
/// resolver bug — Alpine images don't fall back to `search` domains
/// after an absolute NXDOMAIN, so the short `.svc` form (2 dots,
/// matching `ndots:2`) silently fails to resolve inside the leased
/// cluster.
fn rewrite_kubeconfig_server(
    cluster_name: &str,
    namespace: &str,
    cluster_domain: &str,
    kubeconfig: &str,
) -> String {
    let server = format!("https://{cluster_name}-server.{namespace}.svc.{cluster_domain}:6443");
    kubeconfig
        .replace("https://localhost:6443", &server)
        .replace("https://127.0.0.1:6443", &server)
}

async fn wait_for_kubeconfig(path: &str) -> Result<String> {
    loop {
        match tokio::fs::read_to_string(path).await {
            Ok(contents) if !contents.trim().is_empty() => return Ok(contents),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("Failed reading {path}")),
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn publish_secret(namespace: &str, cluster_name: &str, kubeconfig: &str) -> Result<()> {
    let client = Client::try_default().await?;
    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    let secret_name = format!("{cluster_name}-kubeconfig");

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.clone()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        string_data: Some({
            let mut data = BTreeMap::new();
            data.insert("kubeconfig".to_string(), kubeconfig.to_string());
            data
        }),
        ..Default::default()
    };

    secrets
        .patch(
            &secret_name,
            &PatchParams::apply("kubeconfig-publisher").force(),
            &Patch::Apply(&secret),
        )
        .await
        .with_context(|| format!("Failed to apply kubeconfig Secret {secret_name}"))?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .without_time()
        .init();

    let cluster_name = std::env::var("CLUSTER_NAME").context("CLUSTER_NAME is required")?;
    let namespace = std::env::var("NAMESPACE").context("NAMESPACE is required")?;
    let cluster_domain =
        std::env::var("CLUSTER_DOMAIN").unwrap_or_else(|_| DEFAULT_CLUSTER_DOMAIN.to_string());
    let kubeconfig_path =
        std::env::var("KUBECONFIG_PATH").unwrap_or_else(|_| DEFAULT_KUBECONFIG_PATH.to_string());

    info!(cluster = %cluster_name, path = %kubeconfig_path, "Waiting for kubeconfig file");
    let kubeconfig = wait_for_kubeconfig(&kubeconfig_path).await?;
    let kubeconfig =
        rewrite_kubeconfig_server(&cluster_name, &namespace, &cluster_domain, &kubeconfig);

    info!(cluster = %cluster_name, "Publishing kubeconfig Secret");
    publish_secret(&namespace, &cluster_name, &kubeconfig).await?;
    info!(cluster = %cluster_name, "Kubeconfig Secret published");

    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
