use std::collections::BTreeMap;

use anyhow::{Context, Result};
use base64::Engine;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::{Client, ResourceExt};
use rand::Rng;
use reqwest::{Certificate, Identity};
use serde::Serialize;
use serde_yaml_ng::Value;

use crate::crd::ClusterLease;

const CONNECT_TOKEN_KEY: &str = "token";

#[derive(Debug)]
pub(crate) struct BackendAccess {
    pub server: String,
    pub client: reqwest::Client,
    pub bearer_token: Option<String>,
}

#[derive(Serialize)]
struct UserFacingKubeconfig<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    clusters: Vec<NamedCluster<'a>>,
    contexts: Vec<NamedContext<'a>>,
    #[serde(rename = "current-context")]
    current_context: &'a str,
    users: Vec<NamedUser<'a>>,
}

#[derive(Serialize)]
struct NamedCluster<'a> {
    name: &'a str,
    cluster: ClusterConfig<'a>,
}

#[derive(Serialize)]
struct ClusterConfig<'a> {
    server: &'a str,
}

#[derive(Serialize)]
struct NamedContext<'a> {
    name: &'a str,
    context: ContextConfig<'a>,
}

#[derive(Serialize)]
struct ContextConfig<'a> {
    cluster: &'a str,
    user: &'a str,
}

#[derive(Serialize)]
struct NamedUser<'a> {
    name: &'a str,
    user: UserConfig<'a>,
}

#[derive(Serialize)]
struct UserConfig<'a> {
    token: &'a str,
}

pub(crate) fn build_connect_kubeconfig(
    server_url: &str,
    lease_id: &str,
    cluster_name: Option<&str>,
    token: &str,
) -> Result<String> {
    let cluster = cluster_name.unwrap_or(lease_id);
    let kubeconfig = UserFacingKubeconfig {
        api_version: "v1",
        kind: "Config",
        clusters: vec![NamedCluster {
            name: cluster,
            cluster: ClusterConfig { server: server_url },
        }],
        contexts: vec![NamedContext {
            name: lease_id,
            context: ContextConfig {
                cluster,
                user: lease_id,
            },
        }],
        current_context: lease_id,
        users: vec![NamedUser {
            name: lease_id,
            user: UserConfig { token },
        }],
    };
    serde_yaml_ng::to_string(&kubeconfig).context("Failed to serialize user-facing kubeconfig")
}

pub(crate) fn backend_access_from_kubeconfig(raw_kubeconfig: &str) -> Result<BackendAccess> {
    let doc: Value =
        serde_yaml_ng::from_str(raw_kubeconfig).context("Failed to parse backend kubeconfig")?;

    let cluster = doc
        .get("clusters")
        .and_then(Value::as_sequence)
        .and_then(|clusters| clusters.first())
        .and_then(|entry| entry.get("cluster"))
        .ok_or_else(|| anyhow::anyhow!("Backend kubeconfig has no cluster entry"))?;

    let server = cluster
        .get("server")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Backend kubeconfig has no server URL"))?
        .to_string();

    let user = doc
        .get("users")
        .and_then(Value::as_sequence)
        .and_then(|users| users.first())
        .and_then(|entry| entry.get("user"))
        .ok_or_else(|| anyhow::anyhow!("Backend kubeconfig has no user entry"))?;

    let mut builder = reqwest::Client::builder();

    if let Some(ca_data) = cluster
        .get("certificate-authority-data")
        .and_then(Value::as_str)
    {
        let ca_pem = base64::engine::general_purpose::STANDARD
            .decode(ca_data)
            .context("Failed to decode backend CA data")?;
        let cert = Certificate::from_pem(&ca_pem).context("Failed to parse backend CA cert")?;
        builder = builder.add_root_certificate(cert);
    }

    if let (Some(cert_data), Some(key_data)) = (
        user.get("client-certificate-data").and_then(Value::as_str),
        user.get("client-key-data").and_then(Value::as_str),
    ) {
        let cert_pem = base64::engine::general_purpose::STANDARD
            .decode(cert_data)
            .context("Failed to decode backend client certificate")?;
        let key_pem = base64::engine::general_purpose::STANDARD
            .decode(key_data)
            .context("Failed to decode backend client key")?;
        let mut identity_pem = cert_pem;
        if !identity_pem.ends_with(b"\n") {
            identity_pem.push(b'\n');
        }
        identity_pem.extend_from_slice(&key_pem);
        let identity =
            Identity::from_pem(&identity_pem).context("Failed to parse backend client identity")?;
        builder = builder.identity(identity);
    }

    // Virtual clusters use generated/self-signed serving certs and are accessed over
    // cluster-internal service DNS. Match the same trust model as the internal
    // kube-rs health checks so the connect proxy can reach leased clusters
    // consistently even when the serving certificate SANs are narrow.
    builder = builder.danger_accept_invalid_certs(true);

    let client = builder
        .build()
        .context("Failed to build backend proxy client")?;

    Ok(BackendAccess {
        server,
        client,
        bearer_token: user
            .get("token")
            .and_then(Value::as_str)
            .map(|token| token.to_string()),
    })
}

pub(crate) async fn ensure_lease_connect_token(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
) -> Result<String> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let name = connect_secret_name(&lease.name_any());

    match secrets.get(&name).await {
        Ok(secret) => read_token(&secret),
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            let token = random_token();
            let uid = lease
                .metadata
                .uid
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Lease {} has no UID", lease.name_any()))?;

            let secret = Secret {
                metadata: ObjectMeta {
                    name: Some(name.clone()),
                    namespace: Some(namespace.to_string()),
                    owner_references: Some(vec![OwnerReference {
                        api_version: "kobe.kunobi.ninja/v1alpha1".to_string(),
                        kind: "ClusterLease".to_string(),
                        name: lease.name_any(),
                        uid,
                        controller: Some(false),
                        block_owner_deletion: Some(false),
                    }]),
                    ..Default::default()
                },
                string_data: Some({
                    let mut data = BTreeMap::new();
                    data.insert(CONNECT_TOKEN_KEY.to_string(), token.clone());
                    data
                }),
                type_: Some("Opaque".to_string()),
                ..Default::default()
            };

            match secrets.create(&PostParams::default(), &secret).await {
                Ok(_) => Ok(token),
                Err(kube::Error::Api(ae)) if ae.code == 409 => {
                    let existing = secrets
                        .get(&name)
                        .await
                        .with_context(|| format!("Failed to read existing connect token {name}"))?;
                    read_token(&existing)
                }
                Err(e) => Err(e).with_context(|| format!("Failed to create connect token {name}")),
            }
        }
        Err(e) => Err(e).with_context(|| format!("Failed to read connect token {name}")),
    }
}

pub(crate) async fn validate_lease_connect_token(
    client: &Client,
    namespace: &str,
    lease_id: &str,
    presented_token: &str,
) -> Result<bool> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let name = connect_secret_name(lease_id);
    match secrets.get(&name).await {
        Ok(secret) => Ok(read_token(&secret)? == presented_token),
        Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(false),
        Err(e) => Err(e).with_context(|| format!("Failed to read connect token {name}")),
    }
}

fn connect_secret_name(lease_id: &str) -> String {
    format!("{lease_id}-connect-token")
}

fn read_token(secret: &Secret) -> Result<String> {
    let data = secret
        .data
        .as_ref()
        .and_then(|data| data.get(CONNECT_TOKEN_KEY))
        .ok_or_else(|| anyhow::anyhow!("Connect token secret is missing token data"))?;
    String::from_utf8(data.0.clone()).context("Connect token is not valid UTF-8")
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_connect_kubeconfig_uses_lease_scoped_names() {
        let kubeconfig = build_connect_kubeconfig(
            "https://kobe.example/connect/lease-abc",
            "lease-abc",
            Some("pool-ci-small-6"),
            "token-123",
        )
        .unwrap();

        assert!(kubeconfig.contains("server: https://kobe.example/connect/lease-abc"));
        assert!(kubeconfig.contains("name: lease-abc"));
        assert!(kubeconfig.contains("cluster: pool-ci-small-6"));
        assert!(kubeconfig.contains("user: lease-abc"));
        assert!(kubeconfig.contains("token: token-123"));
        assert!(!kubeconfig.contains("current-context: default"));
    }

    #[test]
    fn backend_access_parses_client_cert_kubeconfig() {
        let raw = r#"apiVersion: v1
kind: Config
clusters:
- name: default
  cluster:
    server: https://pool-ci-small-6-server.kobe-system.svc:6443
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg==
users:
- name: default
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg==
    client-key-data: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCg==
"#;

        let err = backend_access_from_kubeconfig(raw).unwrap_err();
        assert!(
            err.to_string().contains("parse backend CA cert")
                || err.to_string().contains("parse backend client identity")
        );
    }
}
