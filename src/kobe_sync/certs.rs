use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use tracing::{debug, info};

// Re-export VirtualClusterPki from the shared PKI module so existing callers
// (e.g. tests) can still access it via `certs::VirtualClusterPki`.
pub use crate::pki::VirtualClusterPki;

/// Manages CA and serving certificates for the kobe-sync virtual API server.
///
/// Handles generation of a self-signed CA, issuance of serving certificates
/// signed by that CA, and construction of rustls server configurations for
/// mutual TLS.
pub struct CertificateManager {
    ca_cert_pem: String,
    ca_key_pem: String,
    serving_cert_pem: String,
    serving_key_pem: String,
}

impl CertificateManager {
    /// Create a new CertificateManager with pre-generated PEM material.
    pub fn new(
        ca_cert_pem: String,
        ca_key_pem: String,
        serving_cert_pem: String,
        serving_key_pem: String,
    ) -> Self {
        Self {
            ca_cert_pem,
            ca_key_pem,
            serving_cert_pem,
            serving_key_pem,
        }
    }

    /// Generate a new self-signed CA certificate and private key.
    ///
    /// Returns `(cert_pem, key_pem)`.
    pub fn generate_ca() -> Result<(String, String)> {
        let mut params = CertificateParams::new(vec!["kobe-sync-ca".to_string()])?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "kobe-sync CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "kobe-sync");

        // Use rcgen defaults for not_before/not_after (1975 to 4096), which
        // provide a generous validity window suitable for internal CA usage.

        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;

        debug!("Generated new CA certificate");
        Ok((cert.pem(), key.serialize_pem()))
    }

    /// Generate a serving certificate signed by the provided CA.
    ///
    /// `sans` should include the DNS names that the server will be accessed by,
    /// for example:
    /// - `kobe-sync-api`
    /// - `kobe-sync-api.pool-ns`
    /// - `kobe-sync-api.pool-ns.svc`
    /// - `kobe-sync-api.pool-ns.svc.cluster.local`
    /// - `localhost`
    ///
    /// Returns `(cert_pem, key_pem)`.
    pub fn generate_serving_cert(
        ca_cert_pem: &str,
        ca_key_pem: &str,
        sans: Vec<String>,
    ) -> Result<(String, String)> {
        // Reconstruct the CA from PEM so we can sign with it.
        let ca_key = KeyPair::from_pem(ca_key_pem).context("Failed to parse CA private key")?;
        let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
            .context("Failed to parse CA certificate PEM")?;
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .context("Failed to reconstruct CA certificate for signing")?;

        // Build the serving cert params.
        let mut params = CertificateParams::new(sans)?;
        params
            .distinguished_name
            .push(DnType::CommonName, "kobe-sync");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "kobe-sync");

        // Use rcgen defaults for not_before/not_after.

        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &ca_cert, &ca_key)?;

        debug!("Generated new serving certificate");
        Ok((cert.pem(), key.serialize_pem()))
    }

    /// Build a `rustls::ServerConfig` for the virtual API server.
    ///
    /// The configuration:
    /// - Presents the serving certificate to clients.
    /// - Optionally verifies client certificates against the CA (mutual TLS).
    /// - Allows unauthenticated connections for health check endpoints.
    pub fn build_server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        let mut root_store = RootCertStore::empty();
        let ca_certs: Vec<CertificateDer<'_>> =
            rustls_pemfile::certs(&mut self.ca_cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to parse CA certificate PEM for root store")?;
        for cert in &ca_certs {
            root_store
                .add(cert.clone())
                .context("Failed to add CA cert to root store")?;
        }

        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .allow_unauthenticated()
            .build()
            .context("Failed to build client certificate verifier")?;

        let server_certs: Vec<CertificateDer<'_>> =
            rustls_pemfile::certs(&mut self.serving_cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to parse serving certificate PEM")?;

        let server_key = rustls_pemfile::private_key(&mut self.serving_key_pem.as_bytes())
            .context("Failed to read serving private key PEM")?
            .ok_or_else(|| anyhow::anyhow!("No private key found in serving key PEM"))?;

        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certs, server_key)
            .context("Failed to build rustls ServerConfig")?;

        Ok(Arc::new(config))
    }

    /// PEM-encoded CA certificate.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// PEM-encoded CA private key.
    pub fn ca_key_pem(&self) -> &str {
        &self.ca_key_pem
    }

    /// PEM-encoded serving certificate.
    pub fn serving_cert_pem(&self) -> &str {
        &self.serving_cert_pem
    }

    /// PEM-encoded serving private key.
    pub fn serving_key_pem(&self) -> &str {
        &self.serving_key_pem
    }

    /// Store the CA certificate and key in a Kubernetes Secret.
    ///
    /// Creates or updates a Secret named `{name}-certs` in the given namespace
    /// with keys `ca.crt` and `ca.key`.
    pub async fn store_ca_secret(
        client: &kube::Client,
        name: &str,
        namespace: &str,
        ca_cert: &str,
        ca_key: &str,
    ) -> Result<()> {
        use k8s_openapi::api::core::v1::Secret;
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
        use k8s_openapi::ByteString;
        use kube::api::{Api, PostParams};
        use std::collections::BTreeMap;

        let secret_name = format!("{name}-certs");
        let api: Api<Secret> = Api::namespaced(client.clone(), namespace);

        let mut data = BTreeMap::new();
        data.insert(
            "ca.crt".to_string(),
            ByteString(ca_cert.as_bytes().to_vec()),
        );
        data.insert("ca.key".to_string(), ByteString(ca_key.as_bytes().to_vec()));

        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(secret_name.clone()),
                namespace: Some(namespace.to_string()),
                labels: Some({
                    let mut labels = BTreeMap::new();
                    labels.insert(
                        "app.kubernetes.io/managed-by".to_string(),
                        "kobe-sync".to_string(),
                    );
                    labels
                }),
                ..Default::default()
            },
            data: Some(data),
            type_: Some("Opaque".to_string()),
            ..Default::default()
        };

        // Try to create first; if it already exists, replace it.
        match api.create(&PostParams::default(), &secret).await {
            Ok(_) => {
                info!(
                    secret = %secret_name,
                    namespace = %namespace,
                    "Created CA secret"
                );
            }
            Err(kube::Error::Api(ref api_err)) if api_err.code == 409 => {
                // Secret already exists, replace it.
                api.replace(&secret_name, &PostParams::default(), &secret)
                    .await
                    .with_context(|| format!("Failed to update CA secret {secret_name}"))?;
                info!(
                    secret = %secret_name,
                    namespace = %namespace,
                    "Updated existing CA secret"
                );
            }
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to create CA secret {secret_name}"));
            }
        }

        Ok(())
    }

    /// Load or generate certificates for the virtual API server.
    ///
    /// Attempts to load the CA from the `{name}-certs` Secret (which may have
    /// been pre-created by the pool-operator with full PKI material). If the
    /// Secret does not exist, generates a new CA and stores it. Always generates
    /// fresh serving certificates.
    pub async fn load_or_generate(
        client: &kube::Client,
        name: &str,
        namespace: &str,
        sans: Vec<String>,
    ) -> Result<Self> {
        use k8s_openapi::api::core::v1::Secret;
        use kube::api::Api;

        let secret_name = format!("{name}-certs");
        let api: Api<Secret> = Api::namespaced(client.clone(), namespace);

        let (ca_cert_pem, ca_key_pem) = match api.get(&secret_name).await {
            Ok(secret) => {
                info!(secret = %secret_name, "Loaded existing CA from Secret");
                let data = secret
                    .data
                    .ok_or_else(|| anyhow::anyhow!("CA secret {secret_name} has no data"))?;

                let ca_cert_bytes = data
                    .get("ca.crt")
                    .ok_or_else(|| anyhow::anyhow!("CA secret missing 'ca.crt' key"))?;
                let ca_key_bytes = data
                    .get("ca.key")
                    .ok_or_else(|| anyhow::anyhow!("CA secret missing 'ca.key' key"))?;

                let ca_cert = String::from_utf8(ca_cert_bytes.0.clone())
                    .context("CA cert is not valid UTF-8")?;
                let ca_key = String::from_utf8(ca_key_bytes.0.clone())
                    .context("CA key is not valid UTF-8")?;

                (ca_cert, ca_key)
            }
            Err(kube::Error::Api(ref api_err)) if api_err.code == 404 => {
                info!("CA secret not found, generating new CA");
                let (ca_cert, ca_key) = Self::generate_ca()?;
                Self::store_ca_secret(client, name, namespace, &ca_cert, &ca_key).await?;
                (ca_cert, ca_key)
            }
            Err(e) => {
                return Err(e).context("Failed to check for existing CA secret");
            }
        };

        // Always generate fresh serving certificates.
        let (serving_cert_pem, serving_key_pem) =
            Self::generate_serving_cert(&ca_cert_pem, &ca_key_pem, sans)?;

        Ok(Self {
            ca_cert_pem,
            ca_key_pem,
            serving_cert_pem,
            serving_key_pem,
        })
    }

    /// Generate a full PKI tree for a virtual cluster.
    ///
    /// Delegates to [`crate::pki::VirtualClusterPki::generate`].
    pub fn generate_pki(cluster_name: &str, sans: &[&str]) -> Result<VirtualClusterPki> {
        crate::pki::VirtualClusterPki::generate(cluster_name, sans)
    }

    /// Generate a KCM (kube-controller-manager) kubeconfig.
    ///
    /// Delegates to [`crate::pki::generate_kcm_kubeconfig`].
    pub fn generate_kcm_kubeconfig(
        ca_cert: &str,
        ca_key: &str,
        server_url: &str,
    ) -> Result<String> {
        crate::pki::generate_kcm_kubeconfig(ca_cert, ca_key, server_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ca() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_pem, key_pem) = CertificateManager::generate_ca().unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert_pem.contains("END CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(key_pem.contains("END PRIVATE KEY"));
    }

    #[test]
    fn test_generate_serving_cert() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert, ca_key) = CertificateManager::generate_ca().unwrap();
        let sans = vec![
            "kobe-sync-api".to_string(),
            "kobe-sync-api.pool-ns".to_string(),
            "kobe-sync-api.pool-ns.svc".to_string(),
            "kobe-sync-api.pool-ns.svc.cluster.local".to_string(),
            "localhost".to_string(),
        ];
        let (cert_pem, key_pem) =
            CertificateManager::generate_serving_cert(&ca_cert, &ca_key, sans).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_build_server_config() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert, ca_key) = CertificateManager::generate_ca().unwrap();
        let sans = vec!["localhost".to_string()];
        let (serving_cert, serving_key) =
            CertificateManager::generate_serving_cert(&ca_cert, &ca_key, sans).unwrap();

        let mgr = CertificateManager::new(ca_cert, ca_key, serving_cert, serving_key);
        let config = mgr.build_server_config();
        assert!(config.is_ok(), "build_server_config should succeed");
    }

    #[test]
    fn test_accessors() {
        let mgr = CertificateManager::new(
            "ca-cert".into(),
            "ca-key".into(),
            "srv-cert".into(),
            "srv-key".into(),
        );
        assert_eq!(mgr.ca_cert_pem(), "ca-cert");
        assert_eq!(mgr.ca_key_pem(), "ca-key");
        assert_eq!(mgr.serving_cert_pem(), "srv-cert");
        assert_eq!(mgr.serving_key_pem(), "srv-key");
    }

    #[test]
    fn test_serving_cert_different_from_ca() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert, ca_key) = CertificateManager::generate_ca().unwrap();
        let sans = vec!["localhost".to_string()];
        let (serving_cert, serving_key) =
            CertificateManager::generate_serving_cert(&ca_cert, &ca_key, sans).unwrap();

        // The serving cert should be different from the CA cert.
        assert_ne!(ca_cert, serving_cert);
        assert_ne!(ca_key, serving_key);
    }

    #[test]
    fn test_generate_ca_twice_produces_different_certs() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert1, key1) = CertificateManager::generate_ca().unwrap();
        let (cert2, key2) = CertificateManager::generate_ca().unwrap();

        // Two independent CA generations should produce different material.
        assert_ne!(cert1, cert2);
        assert_ne!(key1, key2);
    }

    // ---- v2 PKI tests (delegate to shared pki module) ----

    #[test]
    fn test_generate_full_pki() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = CertificateManager::generate_pki(
            "test-cluster",
            &[
                "kubernetes",
                "kubernetes.default",
                "kubernetes.default.svc",
                "kubernetes.default.svc.cluster.local",
                "localhost",
            ],
        )
        .unwrap();

        // All fields must be non-empty and contain expected PEM markers.
        assert!(pki.ca_cert.contains("BEGIN CERTIFICATE"), "ca_cert missing PEM header");
        assert!(pki.ca_key.contains("BEGIN PRIVATE KEY"), "ca_key missing PEM header");
        assert!(pki.apiserver_cert.contains("BEGIN CERTIFICATE"), "apiserver_cert missing PEM header");
        assert!(pki.apiserver_key.contains("BEGIN PRIVATE KEY"), "apiserver_key missing PEM header");
        assert!(
            pki.front_proxy_ca_cert.contains("BEGIN CERTIFICATE"),
            "front_proxy_ca_cert missing PEM header"
        );
        assert!(
            pki.front_proxy_ca_key.contains("BEGIN PRIVATE KEY"),
            "front_proxy_ca_key missing PEM header"
        );
        assert!(
            pki.front_proxy_client_cert.contains("BEGIN CERTIFICATE"),
            "front_proxy_client_cert missing PEM header"
        );
        assert!(
            pki.front_proxy_client_key.contains("BEGIN PRIVATE KEY"),
            "front_proxy_client_key missing PEM header"
        );
        assert!(pki.sa_key.contains("BEGIN PRIVATE KEY"), "sa_key missing PEM header");
        assert!(pki.sa_pub.contains("BEGIN PUBLIC KEY"), "sa_pub missing PEM header");

        // No field should be empty.
        assert!(!pki.ca_cert.is_empty());
        assert!(!pki.ca_key.is_empty());
        assert!(!pki.apiserver_cert.is_empty());
        assert!(!pki.apiserver_key.is_empty());
        assert!(!pki.front_proxy_ca_cert.is_empty());
        assert!(!pki.front_proxy_ca_key.is_empty());
        assert!(!pki.front_proxy_client_cert.is_empty());
        assert!(!pki.front_proxy_client_key.is_empty());
        assert!(!pki.sa_key.is_empty());
        assert!(!pki.sa_pub.is_empty());
    }

    #[test]
    fn test_generate_kcm_kubeconfig() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert, ca_key) = CertificateManager::generate_ca().unwrap();
        let kubeconfig = CertificateManager::generate_kcm_kubeconfig(
            &ca_cert,
            &ca_key,
            "https://10.0.0.1:6443",
        )
        .unwrap();

        assert!(
            kubeconfig.contains("certificate-authority-data:"),
            "kubeconfig missing certificate-authority-data"
        );
        assert!(
            kubeconfig.contains("client-certificate-data:"),
            "kubeconfig missing client-certificate-data"
        );
        assert!(
            kubeconfig.contains("client-key-data:"),
            "kubeconfig missing client-key-data"
        );
        assert!(
            kubeconfig.contains("https://10.0.0.1:6443"),
            "kubeconfig missing server URL"
        );
        assert!(
            kubeconfig.contains("system:kube-controller-manager"),
            "kubeconfig missing KCM user name"
        );
        assert!(
            kubeconfig.contains("apiVersion: v1"),
            "kubeconfig missing apiVersion"
        );
    }

    #[test]
    fn test_pki_secrets_map() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = CertificateManager::generate_pki(
            "test-cluster",
            &["kubernetes", "localhost"],
        )
        .unwrap();

        let secrets = pki.to_secret_data();

        let expected_keys = [
            "ca.crt",
            "ca.key",
            "apiserver.crt",
            "apiserver.key",
            "front-proxy-ca.crt",
            "front-proxy-ca.key",
            "front-proxy-client.crt",
            "front-proxy-client.key",
            "sa.key",
            "sa.pub",
        ];

        assert_eq!(
            secrets.len(),
            expected_keys.len(),
            "secret data should have exactly {} keys, got {}",
            expected_keys.len(),
            secrets.len()
        );

        for key in &expected_keys {
            assert!(
                secrets.contains_key(*key),
                "secret data missing expected key: {key}"
            );
            assert!(
                !secrets[*key].is_empty(),
                "secret data value for {key} is empty"
            );
        }
    }

    #[test]
    fn test_apiserver_cert_has_sans() {
        use x509_parser::pem::parse_x509_pem;
        use x509_parser::prelude::*;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let expected_sans = [
            "kubernetes",
            "kubernetes.default",
            "kubernetes.default.svc",
            "kubernetes.default.svc.cluster.local",
            "localhost",
        ];

        let pki = CertificateManager::generate_pki("test-cluster", &expected_sans).unwrap();

        // Parse the apiserver cert from PEM using x509-parser.
        let (_, pem_block) = parse_x509_pem(pki.apiserver_cert.as_bytes())
            .expect("Failed to parse apiserver cert PEM");
        let cert = pem_block
            .parse_x509()
            .expect("Failed to parse apiserver cert X.509");

        // Extract SANs from the certificate.
        let san_ext = cert
            .extensions()
            .iter()
            .find(|ext| ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME)
            .expect("apiserver cert has no SAN extension");

        let parsed_san = match san_ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => san,
            _ => panic!("Failed to parse SAN extension"),
        };

        let dns_names: Vec<&str> = parsed_san
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::DNSName(name) => Some(*name),
                _ => None,
            })
            .collect();

        for expected in &expected_sans {
            assert!(
                dns_names.contains(expected),
                "apiserver cert missing SAN: {expected}, found: {dns_names:?}"
            );
        }
    }

    #[test]
    fn test_front_proxy_separate_chain() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = CertificateManager::generate_pki(
            "test-cluster",
            &["kubernetes", "localhost"],
        )
        .unwrap();

        // The front-proxy CA must be different from the kubernetes CA.
        assert_ne!(
            pki.ca_cert, pki.front_proxy_ca_cert,
            "front-proxy CA cert should differ from kubernetes CA cert"
        );
        assert_ne!(
            pki.ca_key, pki.front_proxy_ca_key,
            "front-proxy CA key should differ from kubernetes CA key"
        );
    }
}
