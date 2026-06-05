use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::{Client, ResourceExt};
use rand::Rng;
use reqwest::{Certificate, Identity};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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

/// Backend access primitives needed to drive a *raw* hyper client through
/// an HTTP Upgrade tunnel (exec / attach / port-forward). reqwest hides the
/// underlying socket and can't expose it after a 101 response, so the upgrade
/// path builds a `tokio_rustls` connection directly. Mirrors `BackendAccess`
/// but yields a rustls `ClientConfig` instead of a reqwest client.
pub(crate) struct BackendUpgradeAccess {
    pub server: String,
    pub tls: Arc<ClientConfig>,
    pub bearer_token: Option<String>,
}

impl std::fmt::Debug for BackendUpgradeAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the bearer token and don't try to format the (non-Debug)
        // rustls config — just note its presence.
        f.debug_struct("BackendUpgradeAccess")
            .field("server", &self.server)
            .field("tls", &"<rustls::ClientConfig>")
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Navigated views into a parsed kubeconfig: the first cluster's `cluster`
/// block, the first user's `user` block, and the server URL. Shared by the
/// reqwest (`backend_access_from_kubeconfig`) and rustls
/// (`build_backend_tls_config`) builders so the YAML navigation lives in one
/// place.
struct ParsedKubeconfig {
    server: String,
    cluster: Value,
    user: Value,
}

fn parse_kubeconfig_fields(raw_kubeconfig: &str) -> Result<ParsedKubeconfig> {
    let doc: Value =
        serde_yaml_ng::from_str(raw_kubeconfig).context("Failed to parse backend kubeconfig")?;

    let cluster = doc
        .get("clusters")
        .and_then(Value::as_sequence)
        .and_then(|clusters| clusters.first())
        .and_then(|entry| entry.get("cluster"))
        .ok_or_else(|| anyhow::anyhow!("Backend kubeconfig has no cluster entry"))?
        .clone();

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
        .ok_or_else(|| anyhow::anyhow!("Backend kubeconfig has no user entry"))?
        .clone();

    Ok(ParsedKubeconfig {
        server,
        cluster,
        user,
    })
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
    let ParsedKubeconfig {
        server,
        cluster,
        user,
    } = parse_kubeconfig_fields(raw_kubeconfig)?;

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

/// Build a `BackendUpgradeAccess` (server URL + rustls `ClientConfig` + bearer
/// token) from the backend kubeconfig, for the HTTP Upgrade tunnel path.
///
/// Mirrors `backend_access_from_kubeconfig`'s parsing and trust model exactly,
/// but produces a raw rustls config so the upgrade path can drive a hyper
/// client over `tokio_rustls` (reqwest can't surface the post-101 socket).
///
/// Trust: leased virtual clusters use generated/self-signed serving certs with
/// narrow SANs and are reached over cluster-internal service DNS, so the
/// reqwest path sets `danger_accept_invalid_certs(true)`. We replicate that
/// here with a no-verify server certificate verifier — the upgrade tunnel must
/// reach the same clusters the buffered proxy already reaches.
pub(crate) fn build_backend_tls_config(raw_kubeconfig: &str) -> Result<BackendUpgradeAccess> {
    let ParsedKubeconfig {
        server,
        cluster: _cluster,
        user,
    } = parse_kubeconfig_fields(raw_kubeconfig)?;

    // Optional client-certificate auth. Parsed up front so a malformed
    // cert/key surfaces a clear error instead of a TLS handshake failure later.
    let client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> = match (
        user.get("client-certificate-data").and_then(Value::as_str),
        user.get("client-key-data").and_then(Value::as_str),
    ) {
        (Some(cert_data), Some(key_data)) => {
            let cert_pem = base64::engine::general_purpose::STANDARD
                .decode(cert_data)
                .context("Failed to decode backend client certificate")?;
            let key_pem = base64::engine::general_purpose::STANDARD
                .decode(key_data)
                .context("Failed to decode backend client key")?;

            let mut cert_cursor = std::io::Cursor::new(&cert_pem);
            let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_cursor)
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("Failed to parse backend client certificate")?;
            if certs.is_empty() {
                anyhow::bail!("Backend client certificate contained no certificates");
            }

            let mut key_cursor = std::io::Cursor::new(&key_pem);
            let key = rustls_pemfile::private_key(&mut key_cursor)
                .context("Failed to parse backend client key")?
                .ok_or_else(|| anyhow::anyhow!("Backend client key contained no private key"))?;

            Some((certs, key))
        }
        _ => None,
    };

    // Match the reqwest trust model (`danger_accept_invalid_certs(true)`): the
    // leased clusters' serving certs aren't anchored to a CA we can verify
    // here, so we skip server-cert verification. The connection is still TLS
    // (encrypted) and only reaches in-cluster service DNS.
    let builder = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(no_verify::NoVerify::new()));

    let config = match client_auth {
        Some((certs, key)) => builder
            .with_client_auth_cert(certs, key)
            .context("Failed to configure backend client auth")?,
        None => builder.with_no_client_auth(),
    };

    Ok(BackendUpgradeAccess {
        server,
        tls: Arc::new(config),
        bearer_token: user
            .get("token")
            .and_then(Value::as_str)
            .map(|token| token.to_string()),
    })
}

/// A rustls `ServerCertVerifier` that accepts any certificate. Used ONLY by the
/// connect-proxy upgrade tunnel, to match the buffered path's
/// `danger_accept_invalid_certs(true)` trust model for leased virtual clusters
/// (self-signed serving certs, narrow SANs, in-cluster service DNS).
mod no_verify {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    pub(super) struct NoVerify {
        schemes: Vec<SignatureScheme>,
    }

    impl NoVerify {
        pub(super) fn new() -> Self {
            // Advertise the active crypto provider's signature schemes so the
            // (still-performed) handshake-signature checks succeed. Fall back
            // to a broad set if no provider is installed yet (e.g. in tests
            // before `install_default`).
            let schemes = CryptoProvider::get_default()
                .map(|p| p.signature_verification_algorithms.supported_schemes())
                .unwrap_or_else(|| {
                    vec![
                        SignatureScheme::RSA_PKCS1_SHA256,
                        SignatureScheme::RSA_PKCS1_SHA384,
                        SignatureScheme::RSA_PKCS1_SHA512,
                        SignatureScheme::ECDSA_NISTP256_SHA256,
                        SignatureScheme::ECDSA_NISTP384_SHA384,
                        SignatureScheme::RSA_PSS_SHA256,
                        SignatureScheme::RSA_PSS_SHA384,
                        SignatureScheme::RSA_PSS_SHA512,
                        SignatureScheme::ED25519,
                    ]
                });
            Self { schemes }
        }
    }

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            let provider = CryptoProvider::get_default().ok_or(rustls::Error::General(
                "no crypto provider installed".into(),
            ))?;
            verify_tls12_signature(
                message,
                cert,
                dss,
                &provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            let provider = CryptoProvider::get_default().ok_or(rustls::Error::General(
                "no crypto provider installed".into(),
            ))?;
            verify_tls13_signature(
                message,
                cert,
                dss,
                &provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.schemes.clone()
        }
    }
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
        // Constant-time comparison: this gates connect-proxy access to the
        // leased cluster, so the match must not leak a per-byte timing signal.
        Ok(secret) => Ok(kunobi_auth::secret_eq(
            &read_token(&secret)?,
            presented_token,
        )),
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

    fn install_test_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn build_backend_tls_config_parses_token_only_kubeconfig() {
        install_test_crypto_provider();
        let raw = r#"apiVersion: v1
kind: Config
clusters:
- name: default
  cluster:
    server: https://pool-ci-small-6-server.kobe-system.svc:6443
users:
- name: default
  user:
    token: backend-bearer-token
"#;

        let access = build_backend_tls_config(raw).expect("token-only kubeconfig should parse");
        assert_eq!(
            access.server,
            "https://pool-ci-small-6-server.kobe-system.svc:6443"
        );
        assert_eq!(access.bearer_token.as_deref(), Some("backend-bearer-token"));
    }

    #[test]
    fn build_backend_tls_config_parses_client_cert_kubeconfig() {
        install_test_crypto_provider();

        // Generate a rustls-compatible self-signed client cert + key with
        // rcgen (the OpenSSL fixture trips ring's stricter cert validation in
        // `with_client_auth_cert`). This exercises the client-auth branch of
        // `build_backend_tls_config` end-to-end.
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["client".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        let cert_b64 = b64.encode(cert.pem());
        let key_b64 = b64.encode(key.serialize_pem());

        let raw = format!(
            "apiVersion: v1\nkind: Config\nclusters:\n- name: default\n  cluster:\n    server: https://host.svc:6443\nusers:\n- name: default\n  user:\n    client-certificate-data: {cert_b64}\n    client-key-data: {key_b64}\n"
        );

        let access = build_backend_tls_config(&raw)
            .expect("client-cert kubeconfig should build a TLS config");
        assert_eq!(access.server, "https://host.svc:6443");
        // Client-cert kubeconfigs typically carry no bearer token.
        assert!(access.bearer_token.is_none());
    }

    #[test]
    fn build_backend_tls_config_rejects_missing_server() {
        install_test_crypto_provider();
        let raw = r#"apiVersion: v1
kind: Config
clusters:
- name: default
  cluster: {}
users:
- name: default
  user:
    token: t
"#;
        let err = build_backend_tls_config(raw).unwrap_err();
        assert!(err.to_string().contains("no server URL"));
    }

    #[test]
    fn build_backend_tls_config_rejects_malformed_client_cert() {
        install_test_crypto_provider();
        // Valid base64 but not a PEM certificate.
        let raw = r#"apiVersion: v1
kind: Config
clusters:
- name: default
  cluster:
    server: https://host.svc:6443
users:
- name: default
  user:
    client-certificate-data: bm90LWEtcGVt
    client-key-data: bm90LWEta2V5
"#;
        let err = build_backend_tls_config(raw).unwrap_err();
        assert!(
            err.to_string().contains("client certificate")
                || err.to_string().contains("client key"),
            "unexpected error: {err}"
        );
    }
}
