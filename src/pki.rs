//! Shared PKI generation for virtual Kubernetes clusters.
//!
//! This module provides the core PKI primitives used by both the
//! pool-operator (to pre-create the `{name}-certs` Secret before the
//! Deployment) and the kobe-sync runtime binary (to load existing certs
//! or fall back to self-generation).
//!
//! The key entry points are:
//! - [`VirtualClusterPki::generate`] -- generate a complete PKI tree
//! - [`generate_kcm_kubeconfig`] -- build a KCM kubeconfig with embedded client certs
//! - [`create_pki_secret`] -- generate PKI + KCM kubeconfig and store in a K8s Secret

// This module is shared between the pool-operator and kobe-sync binaries.
// Each binary uses a different subset of the API, so allow dead_code to
// avoid false positives.
#![allow(dead_code)]

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use base64::Engine as _;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// VirtualClusterPki -- full PKI material for a virtual Kubernetes cluster
// ---------------------------------------------------------------------------

/// Full PKI material for a virtual Kubernetes cluster.
///
/// Contains all certificates and keys needed by kube-apiserver and
/// kube-controller-manager.
#[derive(Debug, Clone)]
pub struct VirtualClusterPki {
    /// Kubernetes CA certificate (PEM).
    pub ca_cert: String,
    /// Kubernetes CA private key (PEM).
    pub ca_key: String,
    /// API server serving certificate signed by the CA (PEM).
    pub apiserver_cert: String,
    /// API server serving private key (PEM).
    pub apiserver_key: String,
    /// Front-proxy CA certificate -- separate trust chain (PEM).
    pub front_proxy_ca_cert: String,
    /// Front-proxy CA private key (PEM).
    pub front_proxy_ca_key: String,
    /// Front-proxy client certificate signed by the front-proxy CA (PEM).
    pub front_proxy_client_cert: String,
    /// Front-proxy client private key (PEM).
    pub front_proxy_client_key: String,
    /// ServiceAccount token signing private key (PEM, ECDSA P256).
    pub sa_key: String,
    /// ServiceAccount token verification public key (PEM, ECDSA P256).
    pub sa_pub: String,
}

impl VirtualClusterPki {
    /// Generate a full PKI tree for a virtual cluster.
    ///
    /// Produces all certificate material needed by kube-apiserver and
    /// kube-controller-manager:
    /// - Kubernetes CA + apiserver serving cert (signed by CA)
    /// - Front-proxy CA + front-proxy client cert (separate chain)
    /// - ServiceAccount signing keypair (ECDSA)
    ///
    /// `cluster_name` is used in distinguished names.
    /// `sans` are the Subject Alternative Names for the apiserver serving cert.
    pub fn generate(cluster_name: &str, sans: &[&str]) -> Result<Self> {
        // 1. Kubernetes CA
        let (ca_cert, ca_key) = generate_named_ca(
            &format!("{cluster_name}-ca"),
            &format!("{cluster_name} CA"),
            cluster_name,
        )?;

        // 2. API server serving cert signed by Kubernetes CA
        let apiserver_sans: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
        let (apiserver_cert, apiserver_key) =
            generate_signed_cert(&ca_cert, &ca_key, "kube-apiserver", cluster_name, apiserver_sans)?;

        // 3. Front-proxy CA (separate chain)
        let (front_proxy_ca_cert, front_proxy_ca_key) = generate_named_ca(
            &format!("{cluster_name}-front-proxy-ca"),
            "front-proxy-ca",
            cluster_name,
        )?;

        // 4. Front-proxy client cert signed by front-proxy CA
        let (front_proxy_client_cert, front_proxy_client_key) = generate_signed_cert(
            &front_proxy_ca_cert,
            &front_proxy_ca_key,
            "front-proxy-client",
            cluster_name,
            vec![],
        )?;

        // 5. ServiceAccount signing keypair (ECDSA P256)
        let sa_keypair = KeyPair::generate().context("Failed to generate SA signing keypair")?;
        let sa_key = sa_keypair.serialize_pem();
        let sa_pub = sa_keypair.public_key_pem();

        debug!(cluster = %cluster_name, "Generated full virtual cluster PKI");

        Ok(Self {
            ca_cert,
            ca_key,
            apiserver_cert,
            apiserver_key,
            front_proxy_ca_cert,
            front_proxy_ca_key,
            front_proxy_client_cert,
            front_proxy_client_key,
            sa_key,
            sa_pub,
        })
    }

    /// Convert the PKI material into a map suitable for a Kubernetes Secret's
    /// `data` field.
    ///
    /// Keys match the conventional names used by kubeadm-style clusters.
    pub fn to_secret_data(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("ca.crt".to_string(), self.ca_cert.clone());
        m.insert("ca.key".to_string(), self.ca_key.clone());
        m.insert("apiserver.crt".to_string(), self.apiserver_cert.clone());
        m.insert("apiserver.key".to_string(), self.apiserver_key.clone());
        m.insert(
            "front-proxy-ca.crt".to_string(),
            self.front_proxy_ca_cert.clone(),
        );
        m.insert(
            "front-proxy-ca.key".to_string(),
            self.front_proxy_ca_key.clone(),
        );
        m.insert(
            "front-proxy-client.crt".to_string(),
            self.front_proxy_client_cert.clone(),
        );
        m.insert(
            "front-proxy-client.key".to_string(),
            self.front_proxy_client_key.clone(),
        );
        m.insert("sa.key".to_string(), self.sa_key.clone());
        m.insert("sa.pub".to_string(), self.sa_pub.clone());
        m
    }
}

// ---------------------------------------------------------------------------
// KCM kubeconfig generation
// ---------------------------------------------------------------------------

/// Generate a KCM (kube-controller-manager) kubeconfig.
///
/// Creates a client certificate with CN=system:kube-controller-manager
/// signed by the provided CA, and builds a kubeconfig YAML with embedded
/// base64-encoded certificates.
pub fn generate_kcm_kubeconfig(
    ca_cert: &str,
    ca_key: &str,
    server_url: &str,
) -> Result<String> {
    let (client_cert, client_key) = generate_signed_cert(
        ca_cert,
        ca_key,
        "system:kube-controller-manager",
        "system:kube-controller-manager",
        vec![],
    )?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let ca_b64 = b64.encode(ca_cert.as_bytes());
    let cert_b64 = b64.encode(client_cert.as_bytes());
    let key_b64 = b64.encode(client_key.as_bytes());

    let kubeconfig = format!(
        r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: {ca_b64}
    server: {server_url}
  name: default
contexts:
- context:
    cluster: default
    user: system:kube-controller-manager
  name: default
current-context: default
users:
- name: system:kube-controller-manager
  user:
    client-certificate-data: {cert_b64}
    client-key-data: {key_b64}
"#
    );

    debug!("Generated KCM kubeconfig");
    Ok(kubeconfig)
}

// ---------------------------------------------------------------------------
// Kubernetes Secret creation
// ---------------------------------------------------------------------------

/// Generate full PKI + KCM kubeconfig and store in a Kubernetes Secret.
///
/// Creates (or replaces) a Secret named `{name}-certs` in the given namespace
/// containing:
/// - All PKI material from [`VirtualClusterPki::to_secret_data()`]
/// - A `controller-manager.conf` key with the KCM kubeconfig
///
/// This must be called **before** creating the Deployment that references
/// the Secret as a volume, otherwise the pod will deadlock in
/// `ContainerCreating`.
pub async fn create_pki_secret(
    client: &kube::Client,
    name: &str,
    namespace: &str,
    pki: &VirtualClusterPki,
    kcm_kubeconfig: &str,
) -> Result<()> {
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::ByteString;
    use kube::api::{Api, PostParams};

    let secret_name = format!("{name}-certs");
    let api: Api<Secret> = Api::namespaced(client.clone(), namespace);

    // Build the data map: PKI material + KCM kubeconfig
    let mut data = BTreeMap::new();
    for (k, v) in pki.to_secret_data() {
        data.insert(k, ByteString(v.as_bytes().to_vec()));
    }
    data.insert(
        "controller-manager.conf".to_string(),
        ByteString(kcm_kubeconfig.as_bytes().to_vec()),
    );

    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "kunobi-pool-operator".to_string(),
    );
    labels.insert(
        "kunobi.ninja/cluster".to_string(),
        name.to_string(),
    );

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
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
                "Created PKI secret"
            );
        }
        Err(kube::Error::Api(ref api_err)) if api_err.code == 409 => {
            // Secret already exists, replace it.
            api.replace(&secret_name, &PostParams::default(), &secret)
                .await
                .with_context(|| format!("Failed to update PKI secret {secret_name}"))?;
            info!(
                secret = %secret_name,
                namespace = %namespace,
                "Updated existing PKI secret"
            );
        }
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to create PKI secret {secret_name}"));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Generate a self-signed CA with a specific CN and org.
fn generate_named_ca(san: &str, cn: &str, org: &str) -> Result<(String, String)> {
    let mut params = CertificateParams::new(vec![san.to_string()])?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, cn);
    params
        .distinguished_name
        .push(DnType::OrganizationName, org);

    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;

    debug!(cn = %cn, "Generated named CA certificate");
    Ok((cert.pem(), key.serialize_pem()))
}

/// Generate a certificate signed by a CA with the given CN, org, and optional SANs.
///
/// If `sans` is empty, the cert will have no Subject Alternative Names
/// (appropriate for client certificates).
fn generate_signed_cert(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    cn: &str,
    org: &str,
    sans: Vec<String>,
) -> Result<(String, String)> {
    let ca_key = KeyPair::from_pem(ca_key_pem).context("Failed to parse CA private key")?;
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
        .context("Failed to parse CA certificate PEM")?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("Failed to reconstruct CA certificate for signing")?;

    let mut params = if sans.is_empty() {
        let mut p = CertificateParams::default();
        // Empty SANs for client certs -- rcgen requires at least setting the DN.
        p.subject_alt_names = vec![];
        p
    } else {
        CertificateParams::new(sans)?
    };

    params.distinguished_name.push(DnType::CommonName, cn);
    params
        .distinguished_name
        .push(DnType::OrganizationName, org);

    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, &ca_cert, &ca_key)?;

    debug!(cn = %cn, "Generated signed certificate");
    Ok((cert.pem(), key.serialize_pem()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_full_pki() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = VirtualClusterPki::generate(
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
    }

    #[test]
    fn test_generate_kcm_kubeconfig() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (ca_cert, ca_key) = generate_named_ca("test-ca", "test CA", "test").unwrap();
        let kubeconfig =
            generate_kcm_kubeconfig(&ca_cert, &ca_key, "https://10.0.0.1:6443").unwrap();

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
    }

    #[test]
    fn test_pki_secrets_map() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = VirtualClusterPki::generate("test-cluster", &["kubernetes", "localhost"]).unwrap();

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
    fn test_front_proxy_separate_chain() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki =
            VirtualClusterPki::generate("test-cluster", &["kubernetes", "localhost"]).unwrap();

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

        let pki = VirtualClusterPki::generate("test-cluster", &expected_sans).unwrap();

        let (_, pem_block) = parse_x509_pem(pki.apiserver_cert.as_bytes())
            .expect("Failed to parse apiserver cert PEM");
        let cert = pem_block
            .parse_x509()
            .expect("Failed to parse apiserver cert X.509");

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
}
