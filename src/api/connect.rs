use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::Engine;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{Api, DeleteParams, ObjectMeta, PostParams};
use kube::{Client, ResourceExt};
use rand::Rng;
use reqwest::{Certificate, Identity};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Serialize;
use serde_yaml_ng::Value;

use crate::crd::{
    CheckResult, ClusterLease, KubernetesResourceIdentity, LeaseBinding, TeardownCheck,
    TeardownSubject,
};

const CONNECT_TOKEN_KEY: &str = "token";

// `Clone` is cheap: `reqwest::Client` is internally `Arc`, and the two
// `String`s are short. The connect-proxy per-lease cache clones a
// `BackendAccess` out of the map on every hit, so cloning must stay cheap.
#[derive(Debug, Clone)]
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

/// Create the lease-scoped token before publishing a reciprocal binding and
/// return the exact Secret identity that must be persisted in that binding.
pub(crate) async fn provision_lease_connect_token(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
) -> Result<KubernetesResourceIdentity> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let name = connect_secret_name(&lease.name_any());
    let lease_uid = lease
        .metadata
        .uid
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Lease {} has no UID", lease.name_any()))?;

    match secrets.get(&name).await {
        Ok(secret) => {
            require_connect_token_owner(&secret, &lease.name_any(), &lease_uid)?;
            connect_token_identity(&secret, namespace)
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            let token = random_token();

            let secret = Secret {
                metadata: ObjectMeta {
                    name: Some(name.clone()),
                    namespace: Some(namespace.to_string()),
                    owner_references: Some(vec![OwnerReference {
                        api_version: "kobe.kunobi.ninja/v1alpha1".to_string(),
                        kind: "ClusterLease".to_string(),
                        name: lease.name_any(),
                        uid: lease_uid.clone(),
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
                Ok(created) => connect_token_identity(&created, namespace),
                Err(kube::Error::Api(ae)) if ae.code == 409 => {
                    let existing = secrets
                        .get(&name)
                        .await
                        .with_context(|| format!("Failed to read existing connect token {name}"))?;
                    require_connect_token_owner(&existing, &lease.name_any(), &lease_uid)?;
                    connect_token_identity(&existing, namespace)
                }
                Err(e) => Err(e).with_context(|| format!("Failed to create connect token {name}")),
            }
        }
        Err(e) => Err(e).with_context(|| format!("Failed to read connect token {name}")),
    }
}

/// Read an already-provisioned token for a Bound lease. New bindings must carry
/// the exact Secret UID; this function never recreates such a Secret after
/// teardown. A legacy Standard binding may still lazily provision once so an
/// in-place operator upgrade does not revoke every existing lease.
pub(crate) async fn ensure_lease_connect_token(
    client: &Client,
    namespace: &str,
    lease: &ClusterLease,
    binding: &LeaseBinding,
) -> Result<String> {
    let expected = match binding.connect_token.as_ref() {
        Some(expected) => expected.clone(),
        None if !binding.cleanup_mode.requires_receipt() => {
            provision_lease_connect_token(client, namespace, lease).await?
        }
        None => anyhow::bail!("verified binding has no connect-token footprint"),
    };
    require_connect_token_identity_shape(&expected, namespace, &lease.name_any())?;
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let secret = secrets
        .get(&expected.name)
        .await
        .with_context(|| format!("Failed to read connect token {}", expected.name))?;
    require_connect_token_owner(
        &secret,
        &lease.name_any(),
        lease
            .metadata
            .uid
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Lease {} has no UID", lease.name_any()))?,
    )?;
    if connect_token_identity(&secret, namespace)? != expected {
        anyhow::bail!("connect token Secret identity changed after binding");
    }
    read_token(&secret)
}

pub(crate) async fn validate_lease_connect_token(
    client: &Client,
    namespace: &str,
    lease_id: &str,
    presented_token: &str,
) -> Result<Option<ValidatedConnectToken>> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let name = connect_secret_name(lease_id);
    match secrets.get(&name).await {
        // Constant-time comparison: this gates connect-proxy access to the
        // leased cluster, so the match must not leak a per-byte timing signal.
        Ok(secret) => {
            let Some(lease_uid) = connect_token_owner_uid(&secret, lease_id) else {
                return Ok(None);
            };
            if kunobi_auth::secret_eq(&read_token(&secret)?, presented_token) {
                Ok(Some(ValidatedConnectToken {
                    lease_uid: lease_uid.to_string(),
                    identity: connect_token_identity(&secret, namespace)?,
                }))
            } else {
                Ok(None)
            }
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(None),
        Err(e) => Err(e).with_context(|| format!("Failed to read connect token {name}")),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedConnectToken {
    pub lease_uid: String,
    pub identity: KubernetesResourceIdentity,
}

/// Explicitly delete the lease's connect-token Secret.
///
/// Called from the lease controller at release/expiry so the token is gone
/// immediately, instead of lingering until owner-ref GC reaps it when the lease
/// CRD is finally deleted at the end of recycling (#178). `validate_lease_connect_token`
/// returns `false` on a 404, so deleting the Secret denies any non-cached
/// request at once; combined with the proxy's per-request phase/expiry re-check
/// (#116), access is cut as soon as the lease leaves `Bound`. Idempotent: a 404
/// (token never minted, or already gone) is success.
pub(crate) async fn delete_lease_connect_token(
    client: &Client,
    namespace: &str,
    lease_id: &str,
    lease_uid: &str,
) -> Result<()> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let name = connect_secret_name(lease_id);
    let secret = match secrets.get(&name).await {
        Ok(secret) => secret,
        Err(kube::Error::Api(ae)) if ae.code == 404 => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("Failed to read connect token {name}")),
    };
    require_connect_token_owner(&secret, lease_id, lease_uid)?;
    let secret_uid = secret
        .metadata
        .uid
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Connect token Secret {name} has no UID"))?;
    let delete_params = DeleteParams {
        preconditions: Some(kube::api::Preconditions {
            uid: Some(secret_uid),
            resource_version: secret.resource_version(),
        }),
        ..Default::default()
    };
    match secrets.delete(&name, &delete_params).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(()),
        Err(e) => Err(e).with_context(|| format!("Failed to delete connect token {name}")),
    }
}

/// Delete and then observe absence of the exact connect-token Secret recorded
/// in the reciprocal binding. The returned check is suitable for the durable
/// teardown receipt: only an observed 404 for this UID is `Verified`.
pub(crate) async fn delete_lease_connect_token_verified(
    client: &Client,
    namespace: &str,
    lease_id: &str,
    lease_uid: &str,
    expected: &KubernetesResourceIdentity,
) -> TeardownCheck {
    let verified = vec![expected.canonical_id()];
    let result = async {
        require_connect_token_identity_shape(expected, namespace, lease_id)?;
        let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
        let current = match secrets.get(&expected.name).await {
            Ok(secret) => Some(secret),
            Err(kube::Error::Api(response)) if response.code == 404 => None,
            Err(error) => return Err(error).context("connect-token lookup failed"),
        };
        if let Some(secret) = current {
            require_connect_token_owner(&secret, lease_id, lease_uid)?;
            if connect_token_identity(&secret, namespace)? != *expected {
                anyhow::bail!("connect-token same-name replacement detected");
            }
            let delete_params = DeleteParams {
                preconditions: Some(kube::api::Preconditions {
                    uid: Some(expected.uid.clone()),
                    resource_version: secret.resource_version(),
                }),
                ..Default::default()
            };
            match secrets.delete(&expected.name, &delete_params).await {
                Ok(_) => {}
                Err(kube::Error::Api(response)) if response.code == 404 => {}
                Err(error) => return Err(error).context("connect-token delete failed"),
            }
        }

        // DELETE acceptance is not proof. Wait briefly for an observed 404;
        // every retry remains UID-fenced and a replacement is an error.
        for _ in 0..20 {
            match secrets.get(&expected.name).await {
                Err(kube::Error::Api(response)) if response.code == 404 => return Ok(()),
                Ok(secret) => {
                    if secret.metadata.uid.as_deref() != Some(expected.uid.as_str()) {
                        anyhow::bail!("connect-token same-name replacement detected");
                    }
                }
                Err(error) => return Err(error).context("connect-token absence proof failed"),
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        anyhow::bail!("connect-token still present after delete")
    }
    .await;

    match result {
        Ok(()) => TeardownCheck {
            subject: TeardownSubject::ConnectTokenSecret,
            result: CheckResult::Verified,
            reason: None,
            verified,
        },
        Err(error) => {
            tracing::warn!(lease = lease_id, error = %error, "connect-token absence is unproven");
            TeardownCheck {
                subject: TeardownSubject::ConnectTokenSecret,
                result: CheckResult::Unknown,
                reason: Some("connect_token_unproven".into()),
                verified: Vec::new(),
            }
        }
    }
}

/// Revoke a token created before a verified binding intent became durable.
/// There is no binding footprint yet, so authenticate it through the exact
/// lease owner UID, derive its live UID, and use the same observed-absence
/// proof before allowing the receipt-retention finalizer to be removed.
pub(crate) async fn delete_unbound_lease_connect_token_verified(
    client: &Client,
    namespace: &str,
    lease_id: &str,
    lease_uid: &str,
) -> Result<()> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let name = connect_secret_name(lease_id);
    let secret = match secrets.get(&name).await {
        Ok(secret) => secret,
        Err(kube::Error::Api(response)) if response.code == 404 => return Ok(()),
        Err(error) => return Err(error).context("unbound connect-token lookup failed"),
    };
    require_connect_token_owner(&secret, lease_id, lease_uid)?;
    let identity = connect_token_identity(&secret, namespace)?;
    let check =
        delete_lease_connect_token_verified(client, namespace, lease_id, lease_uid, &identity)
            .await;
    if check.result == CheckResult::Verified {
        Ok(())
    } else {
        anyhow::bail!("unbound connect-token absence remains unproven")
    }
}

fn connect_secret_name(lease_id: &str) -> String {
    format!("{lease_id}-connect-token")
}

fn connect_token_identity(secret: &Secret, namespace: &str) -> Result<KubernetesResourceIdentity> {
    Ok(KubernetesResourceIdentity {
        api_version: "v1".into(),
        kind: "Secret".into(),
        namespace: Some(namespace.to_string()),
        name: secret
            .metadata
            .name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("Connect token Secret has no name"))?,
        uid: secret
            .metadata
            .uid
            .clone()
            .filter(|uid| !uid.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("Connect token Secret has no UID"))?,
    })
}

pub(crate) fn require_connect_token_identity_shape(
    identity: &KubernetesResourceIdentity,
    namespace: &str,
    lease_id: &str,
) -> Result<()> {
    if identity.api_version == "v1"
        && identity.kind == "Secret"
        && identity.namespace.as_deref() == Some(namespace)
        && identity.name == connect_secret_name(lease_id)
        && !identity.uid.trim().is_empty()
    {
        Ok(())
    } else {
        anyhow::bail!("connect-token footprint is malformed")
    }
}

fn connect_token_owner_uid<'a>(secret: &'a Secret, lease_name: &str) -> Option<&'a str> {
    secret
        .metadata
        .owner_references
        .as_ref()?
        .iter()
        .find_map(|owner| {
            (owner.api_version == "kobe.kunobi.ninja/v1alpha1"
                && owner.kind == "ClusterLease"
                && owner.name == lease_name
                && !owner.uid.is_empty())
            .then_some(owner.uid.as_str())
        })
}

fn require_connect_token_owner(secret: &Secret, lease_name: &str, lease_uid: &str) -> Result<()> {
    if connect_token_owner_uid(secret, lease_name) == Some(lease_uid) {
        Ok(())
    } else {
        anyhow::bail!("connect token owner UID does not match lease")
    }
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

    fn token_secret(uid: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "lease-a-connect-token",
                "namespace": "test-ns",
                "uid": uid,
                "resourceVersion": "7",
                "ownerReferences": [{
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterLease",
                    "name": "lease-a",
                    "uid": "lease-uid",
                    "controller": false
                }]
            },
            "data": { "token": "dG9rZW4=" }
        })
    }

    fn token_identity(uid: &str) -> KubernetesResourceIdentity {
        KubernetesResourceIdentity {
            api_version: "v1".into(),
            kind: "Secret".into(),
            namespace: Some("test-ns".into()),
            name: "lease-a-connect-token".into(),
            uid: uid.into(),
        }
    }

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

    #[tokio::test]
    async fn verified_token_delete_rejects_a_same_named_replacement_without_delete() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/lease-a-connect-token",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_secret("replacement-uid")))
            .mount(&server)
            .await;

        let check = delete_lease_connect_token_verified(
            &client,
            "test-ns",
            "lease-a",
            "lease-uid",
            &token_identity("original-uid"),
        )
        .await;
        assert_eq!(check.result, CheckResult::Unknown);
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method != http::Method::DELETE)
        );
    }

    #[tokio::test]
    async fn verified_token_delete_requires_an_observed_404() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let secret_path = "/api/v1/namespaces/test-ns/secrets/lease-a-connect-token";
        Mock::given(method("GET"))
            .and(path(secret_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_secret("token-uid")))
            .with_priority(1)
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(secret_path))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "secrets",
                    "lease-a-connect-token",
                )),
            )
            .with_priority(2)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(secret_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(token_secret("token-uid")))
            .expect(1)
            .mount(&server)
            .await;

        let identity = token_identity("token-uid");
        let check = delete_lease_connect_token_verified(
            &client,
            "test-ns",
            "lease-a",
            "lease-uid",
            &identity,
        )
        .await;
        assert_eq!(check.result, CheckResult::Verified);
        assert_eq!(check.verified, vec![identity.canonical_id()]);
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
