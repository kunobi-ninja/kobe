//! Vkobe backend — manages vkobe virtual clusters.
//!
//! This backend creates lightweight virtual clusters using the vkobe
//! runtime. Each virtual cluster runs as a 3-container Deployment
//! (kube-apiserver + kube-controller-manager + vkobe) in its own
//! namespace, backed by an external etcd KobeStore.
//!
//! Unlike the k3s/k0s backends, vkobe doesn't run a full
//! Kubernetes distribution — it runs a minimal kube-apiserver + KCM and
//! uses vkobe to synchronise resources to the host cluster.

use anyhow::{Context, Result};
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, ContainerPort, EnvVar, HTTPGetAction, PodSpec, PodTemplateSpec, Probe,
    ResourceRequirements, Secret, SecretVolumeSource, Service, ServiceAccount, ServicePort,
    ServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::api::rbac::v1::{
    ClusterRole, ClusterRoleBinding, PolicyRule, Role, RoleBinding, RoleRef, Subject,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::Client;
use kube::api::{Api, DeleteParams, ObjectMeta, PostParams};
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

use crate::crd::{Addon, ClusterConfig, KobeStore, KobeStoreRef, ReadinessGate, VkobeConfig};
use crate::pki;

use super::{
    ClusterBackend, apply_addon_impl, check_readiness_gate_impl, check_virtual_health,
    read_kubeconfig_secret, virtual_client_from_kubeconfig,
};

/// Labels applied to all resources managed by this backend.
const MANAGED_BY: &str = "kobe-operator";

/// Default vkobe container image.
const DEFAULT_IMAGE: &str = "zondax/vkobe:latest";

/// Vkobe backend — manages vkobe virtual clusters.
#[derive(Clone)]
pub struct VkobeBackend {
    client: Client,
    vkobe_config: Option<VkobeConfig>,
}

impl VkobeBackend {
    pub fn new(client: Client, vkobe_config: Option<VkobeConfig>) -> Self {
        Self {
            client,
            vkobe_config,
        }
    }

    fn effective_config(&self, config: &ClusterConfig) -> VkobeConfig {
        self.vkobe_config
            .clone()
            .or_else(|| parse_kobe_sync_args(&config.server_args))
            .unwrap_or(VkobeConfig {
                data_store_ref: KobeStoreRef {
                    name: "default".into(),
                },
                version: crate::crd::default_k8s_version(),
                kcm: None,
                syncers: vec![
                    "pods".into(),
                    "services".into(),
                    "configmaps".into(),
                    "secrets".into(),
                    "endpoints".into(),
                    "ingresses".into(),
                ],
                proxy_port: 8443,
                metrics_port: 9090,
            })
    }

    async fn resolve_store_endpoints(
        &self,
        namespace: &str,
        config: &VkobeConfig,
    ) -> Result<String> {
        let stores: Api<KobeStore> = Api::namespaced(self.client.clone(), namespace);
        let store = stores
            .get(&config.data_store_ref.name)
            .await
            .with_context(|| format!("Failed to get KobeStore {}", config.data_store_ref.name))?;

        if store.spec.endpoints.is_empty() {
            anyhow::bail!(
                "KobeStore {} has no endpoints configured",
                config.data_store_ref.name
            );
        }

        Ok(store.spec.endpoints.join(","))
    }

    async fn ensure_pki_secret(
        &self,
        name: &str,
        namespace: &str,
        pki_material: &pki::VirtualClusterPki,
        kcm_kubeconfig: &str,
        owner_ref: Option<&OwnerReference>,
    ) -> Result<()> {
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let secret_name = format!("{name}-certs");

        match secrets.get(&secret_name).await {
            Ok(_) => {
                debug!(
                    cluster = name,
                    secret = %secret_name,
                    "Reusing existing vkobe PKI secret"
                );
                Ok(())
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => pki::create_pki_secret(
                &self.client,
                name,
                namespace,
                pki_material,
                kcm_kubeconfig,
                owner_ref,
            )
            .await
            .context("Failed to create PKI secret"),
            Err(e) => Err(e).context("Failed to check vkobe PKI secret"),
        }
    }

    /// Build a kube Client targeting the virtual cluster's API server.
    async fn virtual_client(&self, name: &str, namespace: &str) -> Result<Client> {
        let kubeconfig_yaml = read_kubeconfig_secret(&self.client, name, namespace).await?;
        virtual_client_from_kubeconfig(&kubeconfig_yaml).await
    }

    /// Wait until the virtual cluster API is actually usable for discovery.
    async fn wait_ready(&self, name: &str, namespace: &str) -> Result<()> {
        info!(cluster = name, "Waiting for vkobe cluster API readiness");

        for attempt in 0..120 {
            match check_virtual_health(&self.client, name, namespace).await {
                Ok(true) => {
                    info!(
                        cluster = name,
                        attempts = attempt + 1,
                        "vkobe cluster API is ready"
                    );
                    return Ok(());
                }
                Ok(false) => {
                    if attempt % 6 == 0 {
                        info!(
                            cluster = name,
                            attempt = attempt + 1,
                            elapsed_seconds = attempt * 5,
                            "Waiting for vkobe cluster API readiness"
                        );
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                Err(e) => {
                    if attempt % 6 == 0 {
                        warn!(
                            cluster = name,
                            attempt = attempt + 1,
                            error = %format!("{e:#}"),
                            "vkobe readiness probe failed"
                        );
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }

        anyhow::bail!("vkobe cluster {name} not ready after 10 minutes");
    }

    /// Standard labels for resources belonging to a cluster.
    fn cluster_labels(name: &str) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        labels.insert("kobe.kunobi.ninja/cluster".to_string(), name.to_string());
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            MANAGED_BY.to_string(),
        );
        labels.insert(
            "app.kubernetes.io/component".to_string(),
            "vkobe".to_string(),
        );
        labels
    }

    /// Build the API Service for the vkobe proxy.
    ///
    /// `owner_ref` (when `Some`) is stamped on `metadata.owner_references`
    /// so the Service is reaped by k8s GC if the parent ClusterInstance
    /// CR is deleted out-of-band — defense-in-depth on top of the
    /// explicit `delete()` cleanup path.
    fn build_service(
        name: &str,
        namespace: &str,
        kobe_sync_config: Option<&VkobeConfig>,
        owner_ref: Option<&OwnerReference>,
    ) -> Service {
        let proxy_port = kobe_sync_config.map(|c| c.proxy_port).unwrap_or(8443);

        Service {
            metadata: ObjectMeta {
                name: Some(format!("{name}-api")),
                namespace: Some(namespace.to_string()),
                labels: Some(Self::cluster_labels(name)),
                owner_references: owner_ref.cloned().map(|o| vec![o]),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                selector: Some(Self::cluster_labels(name)),
                ports: Some(vec![ServicePort {
                    name: Some("api".to_string()),
                    port: 443,
                    target_port: Some(IntOrString::Int(proxy_port.into())),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                }]),
                type_: Some("ClusterIP".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Build a kubeconfig YAML for connecting to the vkobe virtual cluster.
    async fn build_kubeconfig(&self, name: &str, namespace: &str) -> Result<String> {
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let secret_name = format!("{name}-certs");
        let certs_secret = secrets
            .get(&secret_name)
            .await
            .context("Certs Secret not found")?;

        let data = certs_secret
            .data
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Certs Secret has no data"))?;

        let ca_cert = data
            .get("ca.crt")
            .ok_or_else(|| anyhow::anyhow!("Certs Secret missing ca.crt"))?;

        let ca_pem = String::from_utf8(ca_cert.0.clone())?;
        let ca_b64 = base64_encode(&ca_cert.0);

        // Generate a client certificate signed by the CA for the kubeconfig
        let client_cert_b64;
        let client_key_b64;

        // For the kubeconfig, we generate a client cert signed by the CA.
        // The CA key is stored in the certs Secret.
        if let Some(ca_key_data) = data.get("ca.key") {
            let ca_key_pem = String::from_utf8(ca_key_data.0.clone())?;
            let (cert_pem, key_pem) = generate_client_cert(&ca_pem, &ca_key_pem, name)?;
            client_cert_b64 = base64_encode(cert_pem.as_bytes());
            client_key_b64 = base64_encode(key_pem.as_bytes());
        } else {
            anyhow::bail!("Certs Secret missing ca.key — cannot generate client certificate");
        }

        let server_url = format!("https://{name}-api.{namespace}.svc:443");

        let kubeconfig = format!(
            r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: {ca_b64}
    server: {server_url}
  name: {name}
contexts:
- context:
    cluster: {name}
    user: {name}-admin
  name: {name}
current-context: {name}
users:
- name: {name}-admin
  user:
    client-certificate-data: {client_cert_b64}
    client-key-data: {client_key_b64}
"#
        );

        Ok(kubeconfig)
    }

    /// Store the kubeconfig as a Secret.
    async fn store_kubeconfig(
        &self,
        name: &str,
        namespace: &str,
        kubeconfig: &str,
        owner_ref: Option<&OwnerReference>,
    ) -> Result<()> {
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let secret_name = format!("{name}-kubeconfig");

        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(secret_name.clone()),
                namespace: Some(namespace.to_string()),
                labels: Some(Self::cluster_labels(name)),
                owner_references: owner_ref.cloned().map(|o| vec![o]),
                ..Default::default()
            },
            data: Some({
                let mut data = BTreeMap::new();
                data.insert(
                    "kubeconfig".to_string(),
                    k8s_openapi::ByteString(kubeconfig.as_bytes().to_vec()),
                );
                data
            }),
            ..Default::default()
        };

        match secrets.create(&PostParams::default(), &secret).await {
            Ok(_) => info!(cluster = name, "Kubeconfig Secret created"),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                debug!(cluster = name, "Kubeconfig Secret already exists, updating");
                let patch = serde_json::json!({
                    "data": {
                        "kubeconfig": base64_encode(kubeconfig.as_bytes()),
                    }
                });
                secrets
                    .patch(
                        &secret_name,
                        &kube::api::PatchParams::apply(MANAGED_BY),
                        &kube::api::Patch::Merge(&patch),
                    )
                    .await?;
            }
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }
}

impl ClusterBackend for VkobeBackend {
    async fn create(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        addons: &[Addon],
        // Stamped on every namespaced child resource (ConfigMap,
        // Service, Secrets, ServiceAccount, Role, RoleBinding,
        // host-namespace auth-reader RoleBinding, Deployment) so
        // k8s GC reaps them when the parent ClusterInstance CR is
        // deleted out-of-band — defense in depth on top of the
        // explicit `delete()` path. The two cluster-scoped children
        // (ClusterRole, ClusterRoleBinding) cannot reference a
        // namespaced parent (the apiserver rejects cross-scope
        // OwnerRefs) and rely on the explicit cleanup path; the
        // matching `delete()` change makes that path fail loudly so
        // a partial cleanup retries.
        owner_ref: Option<&OwnerReference>,
    ) -> Result<()> {
        info!(cluster = name, namespace, "Creating vkobe virtual cluster");

        // The namespace should already exist (Kobe creates it).
        // We need to find the kobe_sync config from server_args or default.
        let kobe_sync_config = self.effective_config(config);

        let kobe_sync_image =
            std::env::var("KOBE_SYNC_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string());

        let etcd_endpoints = self
            .resolve_store_endpoints(namespace, &kobe_sync_config)
            .await?;
        info!(
            cluster = name,
            store = %kobe_sync_config.data_store_ref.name,
            etcd_endpoints = %etcd_endpoints,
            "Resolved vkobe store endpoints"
        );

        // 1. Create ConfigMap (v2 — includes etcd connection info)
        let config_maps: Api<ConfigMap> = Api::namespaced(self.client.clone(), namespace);
        let cm = build_config_map_v2(
            name,
            namespace,
            &kobe_sync_config,
            &etcd_endpoints,
            owner_ref,
        );
        match config_maps.create(&PostParams::default(), &cm).await {
            Ok(_) => debug!(cluster = name, "ConfigMap created"),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                debug!(cluster = name, "ConfigMap already exists");
            }
            Err(e) => return Err(e).context("Failed to create ConfigMap"),
        }

        // 2. Create Service
        let services: Api<Service> = Api::namespaced(self.client.clone(), namespace);
        let svc = Self::build_service(name, namespace, Some(&kobe_sync_config), owner_ref);
        match services.create(&PostParams::default(), &svc).await {
            Ok(_) => debug!(cluster = name, "Service created"),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                debug!(cluster = name, "Service already exists");
            }
            Err(e) => return Err(e).context("Failed to create Service"),
        }

        // 3. Generate PKI and store in Secret BEFORE creating the Deployment.
        //    The Deployment volumes reference {name}-certs, so it must exist
        //    or the pod will deadlock in ContainerCreating.
        let service_name = format!("{name}-api");
        let apiserver_sans: Vec<&str> = vec![
            "kubernetes",
            "kubernetes.default",
            "kubernetes.default.svc",
            "kubernetes.default.svc.cluster.local",
            "localhost",
            "127.0.0.1",
        ];
        // Include Service DNS names so the apiserver cert is valid for
        // in-cluster connections.
        let svc_dns_short = service_name.to_string();
        let svc_dns_ns = format!("{service_name}.{namespace}");
        let svc_dns_svc = format!("{service_name}.{namespace}.svc");
        let svc_dns_full = format!("{service_name}.{namespace}.svc.cluster.local");
        let mut all_sans = apiserver_sans;
        all_sans.push(&svc_dns_short);
        all_sans.push(&svc_dns_ns);
        all_sans.push(&svc_dns_svc);
        all_sans.push(&svc_dns_full);

        let pki_material = pki::VirtualClusterPki::generate(name, &all_sans)
            .context("Failed to generate PKI for virtual cluster")?;

        // Generate the KCM kubeconfig that points to the local apiserver.
        let kcm_kubeconfig = pki::generate_kcm_kubeconfig(
            &pki_material.ca_cert,
            &pki_material.ca_key,
            "https://localhost:6443",
        )
        .context("Failed to generate KCM kubeconfig")?;

        // Create the PKI Secret containing all certs + KCM kubeconfig.
        self.ensure_pki_secret(name, namespace, &pki_material, &kcm_kubeconfig, owner_ref)
            .await?;

        info!(cluster = name, "PKI secret created before Deployment");

        // 4. Create RBAC resources for vkobe sidecar
        let (sa, role, rb, cr, crb) = build_rbac(name, namespace, owner_ref);
        let host_auth_reader_binding =
            build_host_auth_reader_role_binding(name, namespace, owner_ref);

        // ServiceAccount
        let sa_api: Api<ServiceAccount> = Api::namespaced(self.client.clone(), namespace);
        match sa_api.create(&PostParams::default(), &sa).await {
            Ok(_) => debug!(cluster = name, "ServiceAccount created"),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                debug!(cluster = name, "ServiceAccount already exists");
            }
            Err(e) => return Err(e).context("Failed to create ServiceAccount"),
        }

        // Role (namespaced)
        let role_api: Api<Role> = Api::namespaced(self.client.clone(), namespace);
        match role_api.create(&PostParams::default(), &role).await {
            Ok(_) => debug!(cluster = name, "Role created"),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                debug!(cluster = name, "Role already exists");
            }
            Err(e) => return Err(e).context("Failed to create Role"),
        }

        // RoleBinding (namespaced)
        let rb_api: Api<RoleBinding> = Api::namespaced(self.client.clone(), namespace);
        match rb_api.create(&PostParams::default(), &rb).await {
            Ok(_) => debug!(cluster = name, "RoleBinding created"),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                debug!(cluster = name, "RoleBinding already exists");
            }
            Err(e) => return Err(e).context("Failed to create RoleBinding"),
        }

        // Host kube-system RoleBinding for extension-apiserver-authentication
        let host_rb_api: Api<RoleBinding> = Api::namespaced(self.client.clone(), "kube-system");
        match host_rb_api
            .create(&PostParams::default(), &host_auth_reader_binding)
            .await
        {
            Ok(_) => debug!(cluster = name, "Host auth RoleBinding created"),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                debug!(cluster = name, "Host auth RoleBinding already exists");
            }
            Err(e) => return Err(e).context("Failed to create host auth RoleBinding"),
        }

        // ClusterRole (cluster-scoped)
        let cr_api: Api<ClusterRole> = Api::all(self.client.clone());
        match cr_api.create(&PostParams::default(), &cr).await {
            Ok(_) => debug!(cluster = name, "ClusterRole created"),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                debug!(cluster = name, "ClusterRole already exists");
            }
            Err(e) => return Err(e).context("Failed to create ClusterRole"),
        }

        // ClusterRoleBinding (cluster-scoped)
        let crb_api: Api<ClusterRoleBinding> = Api::all(self.client.clone());
        match crb_api.create(&PostParams::default(), &crb).await {
            Ok(_) => debug!(cluster = name, "ClusterRoleBinding created"),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                debug!(cluster = name, "ClusterRoleBinding already exists");
            }
            Err(e) => return Err(e).context("Failed to create ClusterRoleBinding"),
        }

        info!(cluster = name, "RBAC resources created for vkobe");

        // 5. Create Deployment (v2 -- 3-container pod: apiserver + KCM + vkobe)
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        let dep = build_deployment(
            name,
            namespace,
            &kobe_sync_config,
            &etcd_endpoints,
            &kobe_sync_image,
            owner_ref,
        );
        match deployments.create(&PostParams::default(), &dep).await {
            Ok(_) => debug!(cluster = name, "Deployment created"),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                debug!(cluster = name, "Deployment already exists");
            }
            Err(e) => return Err(e).context("Failed to create Deployment"),
        }

        // 6. Build and store kubeconfig
        let kubeconfig = self.build_kubeconfig(name, namespace).await?;
        self.store_kubeconfig(name, namespace, &kubeconfig, owner_ref)
            .await?;

        // 7. Wait until the virtual API is actually serving discovery.
        self.wait_ready(name, namespace).await?;

        // 8. Apply addons
        if !addons.is_empty() {
            let vc_client = self.virtual_client(name, namespace).await?;
            for addon in addons {
                apply_addon_impl(&vc_client, addon).await.with_context(|| {
                    format!(
                        "Failed to apply vkobe addon {} for cluster {name}",
                        addon.name
                    )
                })?;
            }
        }

        info!(cluster = name, "vkobe virtual cluster ready");
        Ok(())
    }

    /// Delete every resource produced by [`Self::create`] for this
    /// cluster.
    ///
    /// **Fail-loud semantics.** Each child delete is attempted
    /// independently — we do *not* short-circuit on the first
    /// failure, so a flaky apiserver doesn't strand resources whose
    /// turn comes after the flake. Successes and "already-gone" 404s
    /// are logged at debug. Real errors are accumulated and a single
    /// `Err` is returned at the end summarizing what failed.
    ///
    /// The instance controller treats any `Err` from this function as
    /// "retry the recycle" (see
    /// [`crate::controllers::instance`] — the `Recycling` arm only
    /// removes the parent ClusterInstance CR when this returns Ok),
    /// so a partial cleanup correctly *blocks* CR removal and
    /// re-attempts on the next reconcile. Without this, the previous
    /// `warn!`-and-continue behavior could leak the resources whose
    /// individual deletes failed: the warning fired, the function
    /// returned Ok, the CR was deleted, and (since the OwnerRef on
    /// cluster-scoped resources cannot reference a namespaced parent)
    /// k8s GC had no anchor to reap the rest.
    async fn delete(&self, name: &str, namespace: &str) -> Result<()> {
        info!(cluster = name, namespace, "Deleting vkobe virtual cluster");

        // Tracks (kind, name) pairs whose delete failed with a real
        // error (not 404). The function returns Err if non-empty.
        let mut failures: Vec<String> = Vec::new();

        // Helper to record one delete attempt's outcome. `kind` and
        // `resource_name` are descriptive labels used in logs and the
        // aggregated error.
        async fn try_delete<K>(
            api: &Api<K>,
            cluster: &str,
            kind: &str,
            resource_name: &str,
            failures: &mut Vec<String>,
        ) where
            K: kube::Resource<DynamicType = ()>
                + Clone
                + serde::de::DeserializeOwned
                + std::fmt::Debug,
        {
            match api.delete(resource_name, &DeleteParams::default()).await {
                Ok(_) => debug!(cluster, kind, resource_name, "deleted"),
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    debug!(cluster, kind, resource_name, "already gone");
                }
                Err(e) => {
                    warn!(cluster, kind, resource_name, error = %e, "delete failed");
                    failures.push(format!("{kind}/{resource_name}: {e}"));
                }
            }
        }

        let rbac_name = format!("{name}-vkobe");
        let cluster_role_name = format!("{name}-vkobe-nodes");
        let host_rb_name = format!("{name}-vkobe-auth-reader");

        // Order roughly matches reverse-create so dependents go before
        // their dependencies (Deployment before its mounted Secret /
        // SA, etc.). Each step is idempotent and order-tolerant in
        // practice, but matching reverse-create is friendlier to
        // observers reading kubectl events.

        let dep_api: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        try_delete(
            &dep_api,
            name,
            "Deployment",
            &format!("{name}-vkobe"),
            &mut failures,
        )
        .await;

        let svc_api: Api<Service> = Api::namespaced(self.client.clone(), namespace);
        try_delete(
            &svc_api,
            name,
            "Service",
            &format!("{name}-api"),
            &mut failures,
        )
        .await;

        let cm_api: Api<ConfigMap> = Api::namespaced(self.client.clone(), namespace);
        try_delete(
            &cm_api,
            name,
            "ConfigMap",
            &format!("{name}-config"),
            &mut failures,
        )
        .await;

        let secret_api: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        for suffix in &["certs", "kubeconfig"] {
            try_delete(
                &secret_api,
                name,
                "Secret",
                &format!("{name}-{suffix}"),
                &mut failures,
            )
            .await;
        }

        // RBAC — cluster-scoped first (no OwnerRef anchor, must be
        // explicitly deleted), then namespaced (which would survive
        // via OwnerRef-GC even if this delete fails).
        let crb_api: Api<ClusterRoleBinding> = Api::all(self.client.clone());
        try_delete(
            &crb_api,
            name,
            "ClusterRoleBinding",
            &cluster_role_name,
            &mut failures,
        )
        .await;

        let cr_api: Api<ClusterRole> = Api::all(self.client.clone());
        try_delete(
            &cr_api,
            name,
            "ClusterRole",
            &cluster_role_name,
            &mut failures,
        )
        .await;

        let rb_api: Api<RoleBinding> = Api::namespaced(self.client.clone(), namespace);
        try_delete(&rb_api, name, "RoleBinding", &rbac_name, &mut failures).await;

        let host_rb_api: Api<RoleBinding> = Api::namespaced(self.client.clone(), "kube-system");
        try_delete(
            &host_rb_api,
            name,
            "RoleBinding (kube-system auth-reader)",
            &host_rb_name,
            &mut failures,
        )
        .await;

        let role_api: Api<Role> = Api::namespaced(self.client.clone(), namespace);
        try_delete(&role_api, name, "Role", &rbac_name, &mut failures).await;

        let sa_api: Api<ServiceAccount> = Api::namespaced(self.client.clone(), namespace);
        try_delete(&sa_api, name, "ServiceAccount", &rbac_name, &mut failures).await;

        if failures.is_empty() {
            info!(cluster = name, "vkobe virtual cluster deleted");
            Ok(())
        } else {
            // Aggregated error → controller retries the recycle.
            // Each failure entry is `"<kind>/<name>: <error>"`.
            let summary = failures.join("; ");
            warn!(
                cluster = name,
                count = failures.len(),
                summary = %summary,
                "vkobe delete partial; controller will retry"
            );
            anyhow::bail!(
                "partial vkobe delete for cluster {name}: {} failure(s): {summary}",
                failures.len()
            )
        }
    }

    async fn check_health(&self, name: &str, namespace: &str) -> Result<bool> {
        check_virtual_health(&self.client, name, namespace).await
    }

    async fn extract_kubeconfig(&self, name: &str, namespace: &str) -> Result<String> {
        read_kubeconfig_secret(&self.client, name, namespace).await
    }

    async fn check_readiness_gate(
        &self,
        name: &str,
        namespace: &str,
        gate: &ReadinessGate,
    ) -> Result<bool> {
        let vc_client = self.virtual_client(name, namespace).await?;
        check_readiness_gate_impl(&vc_client, gate).await
    }

    async fn apply_addon(&self, name: &str, namespace: &str, addon: &Addon) -> Result<()> {
        let vc_client = self.virtual_client(name, namespace).await?;
        apply_addon_impl(&vc_client, addon).await
    }
}

/// Parse vkobe specific config from server_args.
///
/// server_args may contain `--syncers=pods,services,...` which we parse
/// into a VkobeConfig.
fn parse_kobe_sync_args(server_args: &[String]) -> Option<VkobeConfig> {
    let mut syncers = None;

    for arg in server_args {
        if let Some(value) = arg.strip_prefix("--syncers=") {
            syncers = Some(value.split(',').map(|s| s.trim().to_string()).collect());
        }
    }

    // parse_kobe_sync_args is a legacy helper for v1 server_args.
    // In v2, VkobeConfig comes from the pool's backend.vkobe field
    // which includes data_store_ref. This path is only used as a fallback
    // and the data_store_ref will be overridden by the profile config.
    syncers.map(|s| VkobeConfig {
        data_store_ref: crate::crd::KobeStoreRef {
            name: "unset".into(),
        },
        version: crate::crd::default_k8s_version(),
        kcm: None,
        syncers: s,
        proxy_port: 8443,
        metrics_port: 9090,
    })
}

/// Generate a client certificate signed by the CA.
fn generate_client_cert(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    name: &str,
) -> Result<(String, String)> {
    use rcgen::{CertificateParams, DnType, KeyPair};

    let ca_key = KeyPair::from_pem(ca_key_pem).context("Failed to parse CA key")?;
    let ca_params =
        CertificateParams::from_ca_cert_pem(ca_cert_pem).context("Failed to parse CA cert")?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("Failed to reconstruct CA cert")?;

    let mut params = CertificateParams::new(vec![format!("{name}-admin")])?;
    params
        .distinguished_name
        .push(DnType::CommonName, format!("{name}-admin"));
    params
        .distinguished_name
        .push(DnType::OrganizationName, "system:masters");

    let client_key = KeyPair::generate()?;
    let client_cert = params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .context("Failed to sign client cert")?;

    Ok((client_cert.pem(), client_key.serialize_pem()))
}

/// Base64-encode bytes using the standard base64 crate.
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn normalize_kube_component_version(version: &str) -> String {
    let trimmed = version.trim().trim_start_matches('v');
    let parts: Vec<_> = trimmed.split('.').collect();
    if parts.len() == 2 {
        format!("v{trimmed}.0")
    } else {
        format!("v{trimmed}")
    }
}

// ── RBAC for vkobe sidecar ─────────────────────────────────────────

/// Build RBAC resources for the vkobe sidecar.
///
/// Returns (ServiceAccount, Role, RoleBinding, ClusterRole, ClusterRoleBinding).
///
/// The Role grants namespace-scoped CRUD on the resources the syncer manages
/// (pods, services, configmaps, secrets, endpoints, PVCs, ingresses,
/// networkpolicies, plus the pods/status subresource). The ClusterRole grants
/// cluster-scoped read/watch on Nodes for the fake-node syncer.
/// Build the five RBAC resources for a vkobe sidecar.
///
/// Namespaced ones (ServiceAccount, Role, RoleBinding) get
/// `owner_ref` stamped on them so k8s GC reaps them with the parent
/// ClusterInstance CR. Cluster-scoped ones (ClusterRole,
/// ClusterRoleBinding) **cannot** reference a namespaced owner
/// (k8s rejects the OwnerRef as invalid), so they fall back to the
/// explicit cleanup path in [`VkobeBackend::delete`]. Pair this
/// with the fail-loud delete change so a partial cleanup propagates
/// to the controller's retry loop.
fn build_rbac(
    name: &str,
    namespace: &str,
    owner_ref: Option<&OwnerReference>,
) -> (
    ServiceAccount,
    Role,
    RoleBinding,
    ClusterRole,
    ClusterRoleBinding,
) {
    let sa_name = format!("{name}-vkobe");
    let labels = VkobeBackend::cluster_labels(name);
    let namespaced_owner = owner_ref.cloned().map(|o| vec![o]);

    // ServiceAccount
    let sa = ServiceAccount {
        metadata: ObjectMeta {
            name: Some(sa_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            owner_references: namespaced_owner.clone(),
            ..Default::default()
        },
        ..Default::default()
    };

    // Role — namespaced CRUD for synced resources in the host namespace
    let role = Role {
        metadata: ObjectMeta {
            name: Some(sa_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            owner_references: namespaced_owner.clone(),
            ..Default::default()
        },
        rules: Some(vec![
            PolicyRule {
                api_groups: Some(vec!["".to_string()]),
                resources: Some(vec![
                    "pods".into(),
                    "services".into(),
                    "configmaps".into(),
                    "secrets".into(),
                    "endpoints".into(),
                    "persistentvolumeclaims".into(),
                ]),
                verbs: vec![
                    "get".into(),
                    "list".into(),
                    "watch".into(),
                    "create".into(),
                    "update".into(),
                    "patch".into(),
                    "delete".into(),
                ],
                ..Default::default()
            },
            PolicyRule {
                api_groups: Some(vec!["networking.k8s.io".to_string()]),
                resources: Some(vec!["ingresses".into(), "networkpolicies".into()]),
                verbs: vec![
                    "get".into(),
                    "list".into(),
                    "watch".into(),
                    "create".into(),
                    "update".into(),
                    "patch".into(),
                    "delete".into(),
                ],
                ..Default::default()
            },
            // Pod status subresource
            PolicyRule {
                api_groups: Some(vec!["".to_string()]),
                resources: Some(vec!["pods/status".into()]),
                verbs: vec!["get".into(), "patch".into()],
                ..Default::default()
            },
        ]),
    };

    // RoleBinding
    let role_binding = RoleBinding {
        metadata: ObjectMeta {
            name: Some(sa_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            owner_references: namespaced_owner.clone(),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".into(),
            kind: "Role".into(),
            name: sa_name.clone(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".into(),
            name: sa_name.clone(),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        }]),
    };

    // ClusterRole — cluster-scoped: cannot reference a namespaced
    // ClusterInstance as owner (k8s would reject the OwnerRef).
    // Cleanup falls back to the explicit `delete()` path.
    let cluster_role_name = format!("{name}-vkobe-nodes");
    let cluster_role = ClusterRole {
        metadata: ObjectMeta {
            name: Some(cluster_role_name.clone()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        rules: Some(vec![PolicyRule {
            api_groups: Some(vec!["".to_string()]),
            resources: Some(vec!["nodes".into()]),
            verbs: vec!["get".into(), "list".into(), "watch".into()],
            ..Default::default()
        }]),
        ..Default::default()
    };

    // ClusterRoleBinding
    let cluster_role_binding = ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some(cluster_role_name.clone()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".into(),
            kind: "ClusterRole".into(),
            name: cluster_role_name,
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".into(),
            name: sa_name,
            namespace: Some(namespace.to_string()),
            ..Default::default()
        }]),
    };

    (sa, role, role_binding, cluster_role, cluster_role_binding)
}

/// Build the host kube-system RoleBinding that grants the vkobe
/// sidecar read access to `extension-apiserver-authentication`.
///
/// **Cannot carry an OwnerReference.** The previous version of this
/// builder stamped the parent ClusterInstance's OwnerRef on the
/// binding's metadata under the (incorrect) assumption that k8s GC
/// resolves cross-namespace owners by UID. It does not — k8s
/// explicitly disallows cross-namespace OwnerRefs from a namespaced
/// child to a namespaced parent. The apiserver accepts the create
/// (the validation isn't immediate), then within seconds the GC
/// scans the binding's namespace (`kube-system`) for the named
/// parent UID, finds nothing, and **deletes the binding as
/// orphaned**.
///
/// This was the regression in PR #69 / v0.22.0 that caused KCM in
/// every newly-created vkobe pod to crashloop with
/// `configmaps "extension-apiserver-authentication" is forbidden`:
/// the operator created the binding, GC reaped it 1-2s later, KCM
/// woke up, found no permission, exited 1, repeat.
///
/// The `owner_ref` parameter is accepted for signature parity with
/// the other builders but **deliberately ignored** here. Cleanup of
/// this specific binding falls back to the explicit `delete()`
/// path, same as the cluster-scoped `ClusterRole` and
/// `ClusterRoleBinding`.
///
/// `namespace` is the namespace where the SA lives (the pool
/// namespace), used to populate the binding's subject. The binding
/// itself is always in `kube-system`.
fn build_host_auth_reader_role_binding(
    name: &str,
    namespace: &str,
    _owner_ref: Option<&OwnerReference>,
) -> RoleBinding {
    let binding_name = format!("{name}-vkobe-auth-reader");
    let sa_name = format!("{name}-vkobe");

    RoleBinding {
        metadata: ObjectMeta {
            name: Some(binding_name),
            namespace: Some("kube-system".to_string()),
            labels: Some(VkobeBackend::cluster_labels(name)),
            // owner_references intentionally None — see fn doc.
            // Cross-namespace OwnerRef = silent GC of this binding =
            // KCM crashloop on every new vkobe pod.
            owner_references: None,
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".into(),
            kind: "Role".into(),
            name: "extension-apiserver-authentication-reader".into(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".into(),
            name: sa_name,
            namespace: Some(namespace.to_string()),
            ..Default::default()
        }]),
    }
}

// ── v2: 3-container Deployment (kube-apiserver + KCM + vkobe) ──────

/// Build the ConfigMap with etcd connection info for the virtual cluster.
///
/// Includes the KobeStore endpoints so the kube-apiserver can connect to
/// the external etcd.
pub fn build_config_map_v2(
    name: &str,
    namespace: &str,
    kobe_sync_config: &VkobeConfig,
    etcd_endpoints: &str,
    owner_ref: Option<&OwnerReference>,
) -> ConfigMap {
    let config_data = serde_json::json!({
        "host_namespace": namespace,
        "cluster_name": name,
        "etcd_endpoints": etcd_endpoints,
        "etcd_prefix": format!("/kobe/{name}/"),
        "enabled_syncers": kobe_sync_config.syncers,
        "proxy_port": kobe_sync_config.proxy_port,
        "metrics_port": kobe_sync_config.metrics_port,
        "version": kobe_sync_config.version,
    });

    let mut labels = BTreeMap::new();
    labels.insert("kobe.kunobi.ninja/cluster".to_string(), name.to_string());
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        MANAGED_BY.to_string(),
    );
    labels.insert(
        "app.kubernetes.io/component".to_string(),
        "vkobe".to_string(),
    );

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(format!("{name}-config")),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            owner_references: owner_ref.cloned().map(|o| vec![o]),
            ..Default::default()
        },
        data: Some({
            let mut data = BTreeMap::new();
            data.insert("config.json".to_string(), config_data.to_string());
            data
        }),
        ..Default::default()
    }
}

// ─────────────────────────────────────────────────────────────────────
// Default resources for the 3 control-plane containers
// ─────────────────────────────────────────────────────────────────────
//
// Why baked-in defaults instead of `Option<ResourceRequirements>` from
// the spec? Because `BestEffort` QoS is fundamentally unsafe for these
// workloads. Recap of the failure mode that motivated this:
//
//   1. Pod has no resource requests/limits → kernel throttles CPU
//      aggressively under contention (BestEffort is the lowest-priority
//      class, evicted/throttled before Burstable or Guaranteed).
//   2. Under `flux install` load (200+ concurrent applies, watch
//      streams, JSON encode/decode), the apiserver inside the pod
//      can't keep up. Lease writes from KCM at `localhost:6443`
//      time out (5s deadline).
//   3. KCM loses the leader lease → exits 1 → kubelet back-off
//      restart loop.
//   4. Without KCM, `flux install` blocks indefinitely on
//      ServiceAccount token generation → bootstrap Job hits its
//      `BackoffLimit` → kobe recycles the ClusterInstance →
//      next instance hits the same wall.
//
// The only sustainable answer is "always Burstable" — i.e., always
// emit non-empty `requests`. The numbers below are the smallest set
// that survived the 2026-04-29 vkobe-flux incident in staging:
// apiserver gets the lion's share because it's the bottleneck during
// bootstrap fanout; KCM is light but lease-renewal-sensitive;
// kobe-sync sidecar is comparable to KCM in cost.
//
// These can later become opt-in overrides from `VkobeConfig` if a
// pool needs different sizing, but the FALLBACK must always produce
// a Burstable pod — never `resources: null`. A unit test
// (`vkobe_pod_never_creates_besteffort_containers`) below enforces
// this invariant.

fn quantity(s: &str) -> Quantity {
    Quantity(s.to_string())
}

fn default_apiserver_resources() -> ResourceRequirements {
    ResourceRequirements {
        requests: Some(BTreeMap::from([
            ("cpu".to_string(), quantity("200m")),
            ("memory".to_string(), quantity("256Mi")),
        ])),
        limits: Some(BTreeMap::from([
            ("cpu".to_string(), quantity("1")),
            ("memory".to_string(), quantity("1Gi")),
        ])),
        ..Default::default()
    }
}

fn default_controller_manager_resources() -> ResourceRequirements {
    ResourceRequirements {
        requests: Some(BTreeMap::from([
            ("cpu".to_string(), quantity("100m")),
            ("memory".to_string(), quantity("128Mi")),
        ])),
        limits: Some(BTreeMap::from([
            ("cpu".to_string(), quantity("500m")),
            ("memory".to_string(), quantity("512Mi")),
        ])),
        ..Default::default()
    }
}

fn default_kobe_sync_resources() -> ResourceRequirements {
    ResourceRequirements {
        requests: Some(BTreeMap::from([
            ("cpu".to_string(), quantity("100m")),
            ("memory".to_string(), quantity("128Mi")),
        ])),
        limits: Some(BTreeMap::from([
            ("cpu".to_string(), quantity("500m")),
            ("memory".to_string(), quantity("256Mi")),
        ])),
        ..Default::default()
    }
}

/// Build the Deployment with 3 containers: kube-apiserver, kube-controller-manager, and vkobe.
///
/// The Deployment is stateless — all
/// persistent state lives in the external KobeStore (etcd). PKI material is
/// mounted from Kubernetes Secrets.
///
/// # Arguments
///
/// * `name` — Virtual cluster name (used for etcd prefix, labels, Secret references).
/// * `namespace` — Namespace to deploy into.
/// * `kobe_sync_config` — Configuration from the pool's `backend.vkobe` field.
/// * `kobe_sync_image` — Container image for the vkobe sidecar.
pub fn build_deployment(
    name: &str,
    namespace: &str,
    kobe_sync_config: &VkobeConfig,
    etcd_endpoints: &str,
    kobe_sync_image: &str,
    owner_ref: Option<&OwnerReference>,
) -> Deployment {
    let version = normalize_kube_component_version(&kobe_sync_config.version);
    let proxy_port = kobe_sync_config.proxy_port;
    let metrics_port = kobe_sync_config.metrics_port;

    let mut labels = BTreeMap::new();
    labels.insert("kobe.kunobi.ninja/cluster".to_string(), name.to_string());
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        MANAGED_BY.to_string(),
    );
    labels.insert(
        "app.kubernetes.io/component".to_string(),
        "vkobe".to_string(),
    );

    // ── Container 1: kube-apiserver ──────────────────────────────────
    let apiserver = Container {
        name: "kube-apiserver".to_string(),
        image: Some(format!("registry.k8s.io/kube-apiserver:{version}")),
        command: Some(vec!["kube-apiserver".to_string()]),
        args: Some(vec![
            format!("--etcd-servers={etcd_endpoints}"),
            format!("--etcd-prefix=/kobe/{name}/"),
            // Bind only to the pod loopback. The apiserver is a sidecar
            // consumed exclusively by KCM and kobe-sync inside the same
            // pod (both connect via https://localhost:6443). Binding to
            // 0.0.0.0 (the default) would expose it on the pod IP,
            // letting any pod in the cluster network reach it directly
            // — and anyone with the front-proxy-client cert (or the
            // {name}-certs Secret) could then impersonate arbitrary
            // identities via X-Remote-User headers, completely
            // bypassing the kobe-sync front-proxy gateway.
            "--bind-address=127.0.0.1".to_string(),
            "--service-cluster-ip-range=10.96.0.0/12".to_string(),
            "--service-account-key-file=/pki/sa.pub".to_string(),
            "--service-account-signing-key-file=/pki/sa.key".to_string(),
            "--service-account-issuer=https://kubernetes.default.svc".to_string(),
            "--tls-cert-file=/pki/apiserver.crt".to_string(),
            "--tls-private-key-file=/pki/apiserver.key".to_string(),
            "--client-ca-file=/pki/ca.crt".to_string(),
            // Front-proxy authentication: the kobe-sync sidecar terminates
            // client TLS, validates the caller's cert against ca.crt, then
            // re-establishes a separate mTLS connection to this apiserver
            // using a client cert signed by front-proxy-ca. The apiserver
            // trusts callers identified via X-Remote-User/X-Remote-Group
            // headers ONLY when those connections present the front-proxy
            // client cert (CN=front-proxy-client). This is the same pattern
            // the kube-aggregator uses for extension API servers.
            "--requestheader-client-ca-file=/pki/front-proxy-ca.crt".to_string(),
            "--requestheader-allowed-names=front-proxy-client".to_string(),
            "--requestheader-username-headers=X-Remote-User".to_string(),
            "--requestheader-group-headers=X-Remote-Group".to_string(),
            "--requestheader-extra-headers-prefix=X-Remote-Extra-".to_string(),
            "--enable-admission-plugins=NodeRestriction".to_string(),
            "--authorization-mode=Node,RBAC".to_string(),
        ]),
        ports: Some(vec![ContainerPort {
            name: Some("https".to_string()),
            container_port: 6443,
            protocol: Some("TCP".to_string()),
            ..Default::default()
        }]),
        volume_mounts: Some(vec![VolumeMount {
            name: "pki-volume".to_string(),
            mount_path: "/pki".to_string(),
            read_only: Some(true),
            ..Default::default()
        }]),
        // No readiness probe on the apiserver: with --bind-address=127.0.0.1
        // the kubelet (host netns) cannot reach :6443 on the pod IP. The
        // pod's readiness signal lives on the kobe-sync container instead
        // (see below), which only serves traffic after `wait_for_apiserver`
        // confirms the local apiserver is up — so kobe-sync ready ⇒
        // apiserver ready.
        resources: Some(default_apiserver_resources()),
        ..Default::default()
    };

    // ── Container 2: kube-controller-manager ─────────────────────────
    let kcm = Container {
        name: "kube-controller-manager".to_string(),
        image: Some(format!("registry.k8s.io/kube-controller-manager:{version}")),
        command: Some(vec!["kube-controller-manager".to_string()]),
        args: Some(vec![
            "--kubeconfig=/etc/kubernetes/controller-manager.conf".to_string(),
            "--controllers=*,-nodelifecycle,-persistentvolume-binder,-attachdetach,-ttl"
                .to_string(),
            "--service-account-private-key-file=/pki/sa.key".to_string(),
            "--root-ca-file=/pki/ca.crt".to_string(),
            "--use-service-account-credentials=true".to_string(),
        ]),
        volume_mounts: Some(vec![
            VolumeMount {
                name: "pki-volume".to_string(),
                mount_path: "/pki".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "kcm-kubeconfig".to_string(),
                mount_path: "/etc/kubernetes".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
        ]),
        resources: Some(default_controller_manager_resources()),
        ..Default::default()
    };

    // ── Container 3: vkobe ──────────────────────────────────────
    let kobe_sync = Container {
        name: "vkobe".to_string(),
        image: Some(kobe_sync_image.to_string()),
        env: Some(vec![
            EnvVar {
                name: "KOBE_SYNC_HOST_NAMESPACE".to_string(),
                value: Some(namespace.to_string()),
                ..Default::default()
            },
            EnvVar {
                name: "KOBE_SYNC_CLUSTER_NAME".to_string(),
                value: Some(name.to_string()),
                ..Default::default()
            },
            EnvVar {
                name: "KOBE_SYNC_VIRTUAL_API_URL".to_string(),
                value: Some("https://localhost:6443".to_string()),
                ..Default::default()
            },
            EnvVar {
                name: "KOBE_SYNC_SYNCERS".to_string(),
                value: Some(kobe_sync_config.syncers.join(",")),
                ..Default::default()
            },
        ]),
        ports: Some(vec![
            ContainerPort {
                name: Some("proxy".to_string()),
                container_port: proxy_port.into(),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            },
            ContainerPort {
                name: Some("metrics".to_string()),
                container_port: metrics_port.into(),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            },
        ]),
        volume_mounts: Some(vec![VolumeMount {
            name: "pki-volume".to_string(),
            mount_path: "/pki".to_string(),
            read_only: Some(true),
            ..Default::default()
        }]),
        // The pod's readiness signal: kobe-sync only starts serving its
        // metrics/health endpoint after `wait_for_apiserver` succeeds, so
        // kubelet seeing /readyz=200 implies the local apiserver is up
        // and the proxy is accepting traffic. The metrics server listens
        // on plain HTTP on `metrics_port` and is reachable from the
        // kubelet via the pod IP (apiserver itself is loopback-bound).
        readiness_probe: Some(Probe {
            http_get: Some(HTTPGetAction {
                path: Some("/readyz".to_string()),
                port: IntOrString::Int(metrics_port.into()),
                scheme: Some("HTTP".to_string()),
                ..Default::default()
            }),
            initial_delay_seconds: Some(2),
            period_seconds: Some(5),
            ..Default::default()
        }),
        resources: Some(default_kobe_sync_resources()),
        ..Default::default()
    };

    // ── Shared Volumes ───────────────────────────────────────────────
    // The PKI Secret ({name}-certs) is created by ClusterBackend::create()
    // before launching this Deployment. It contains all PKI material
    // (CA cert/key, apiserver cert/key, front-proxy certs, SA signing keys)
    // plus the KCM kubeconfig (controller-manager.conf).
    let volumes = vec![
        Volume {
            name: "pki-volume".to_string(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(format!("{name}-certs")),
                ..Default::default()
            }),
            ..Default::default()
        },
        Volume {
            name: "kcm-kubeconfig".to_string(),
            secret: Some(SecretVolumeSource {
                // The {name}-certs Secret contains both PKI material and
                // the KCM kubeconfig (controller-manager.conf key), created
                // by ClusterBackend::create() before this Deployment.
                secret_name: Some(format!("{name}-certs")),
                ..Default::default()
            }),
            ..Default::default()
        },
    ];

    // ── Assemble the Deployment ──────────────────────────────────────
    Deployment {
        metadata: ObjectMeta {
            name: Some(format!("{name}-vkobe")),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            owner_references: owner_ref.cloned().map(|o| vec![o]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    annotations: Some({
                        let mut ann = BTreeMap::new();
                        ann.insert("prometheus.io/scrape".to_string(), "true".to_string());
                        ann.insert("prometheus.io/port".to_string(), metrics_port.to_string());
                        ann.insert("prometheus.io/path".to_string(), "/metrics".to_string());
                        ann
                    }),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: Some(format!("{name}-vkobe")),
                    containers: vec![apiserver, kcm, kobe_sync],
                    volumes: Some(volumes),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_labels() {
        let labels = VkobeBackend::cluster_labels("my-cluster");
        assert_eq!(
            labels.get("kobe.kunobi.ninja/cluster"),
            Some(&"my-cluster".to_string())
        );
        assert_eq!(
            labels.get("app.kubernetes.io/managed-by"),
            Some(&MANAGED_BY.to_string())
        );
        assert_eq!(
            labels.get("app.kubernetes.io/component"),
            Some(&"vkobe".to_string())
        );
    }

    #[test]
    fn test_parse_kobe_sync_args_with_syncers() {
        let args = vec!["--syncers=pods,services,configmaps".to_string()];
        let config = parse_kobe_sync_args(&args).unwrap();
        assert_eq!(config.syncers, vec!["pods", "services", "configmaps"]);
    }

    #[test]
    fn test_parse_kobe_sync_args_empty() {
        let args: Vec<String> = vec![];
        assert!(parse_kobe_sync_args(&args).is_none());
    }

    #[test]
    fn test_parse_kobe_sync_args_no_syncers() {
        let args = vec!["--other-arg=value".to_string()];
        assert!(parse_kobe_sync_args(&args).is_none());
    }

    #[test]
    fn test_normalize_kube_component_version_adds_patch() {
        assert_eq!(normalize_kube_component_version("1.35"), "v1.35.0");
        assert_eq!(normalize_kube_component_version("v1.35"), "v1.35.0");
        assert_eq!(normalize_kube_component_version("1.35.1"), "v1.35.1");
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }

    #[test]
    fn test_build_service() {
        let svc = VkobeBackend::build_service("test-cluster", "test-ns", None, None);
        assert_eq!(svc.metadata.name.as_deref(), Some("test-cluster-api"));
        let ports = svc.spec.unwrap().ports.unwrap();
        assert_eq!(ports[0].port, 443);
    }

    /// Helper: a synthetic OwnerReference for testing the OwnerRef
    /// stamping. The real value comes from
    /// `instance.controller_owner_ref(&())` at the call site; tests
    /// just need a value distinguishable from `None`.
    fn test_owner_ref() -> OwnerReference {
        OwnerReference {
            api_version: "kobe.kunobi.ninja/v1alpha1".to_string(),
            kind: "ClusterInstance".to_string(),
            name: "pool-test-cluster".to_string(),
            uid: "fake-uid-1234".to_string(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }
    }

    /// Every namespaced child resource produced by the vkobe
    /// builders must carry the parent ClusterInstance's
    /// OwnerReference so k8s GC reaps it when the parent is deleted.
    /// This test covers all 6 namespaced builders in one place to
    /// catch a future regression where someone adds a builder and
    /// forgets to plumb owner_ref.
    #[test]
    fn build_namespaced_resources_carry_owner_reference() {
        let owner = test_owner_ref();
        let cfg = test_kobe_sync_config();

        let svc = VkobeBackend::build_service("c", "ns", None, Some(&owner));
        assert_eq!(
            svc.metadata.owner_references.as_deref(),
            Some(std::slice::from_ref(&owner)),
            "Service missing OwnerRef"
        );

        let cm = build_config_map_v2("c", "ns", &cfg, "http://etcd:2379", Some(&owner));
        assert_eq!(
            cm.metadata.owner_references.as_deref(),
            Some(std::slice::from_ref(&owner)),
            "ConfigMap missing OwnerRef"
        );

        let dep = build_deployment("c", "ns", &cfg, "http://etcd:2379", "img", Some(&owner));
        assert_eq!(
            dep.metadata.owner_references.as_deref(),
            Some(std::slice::from_ref(&owner)),
            "Deployment missing OwnerRef"
        );

        let (sa, role, rb, _cr, _crb) = build_rbac("c", "ns", Some(&owner));
        assert_eq!(
            sa.metadata.owner_references.as_deref(),
            Some(std::slice::from_ref(&owner)),
            "ServiceAccount missing OwnerRef"
        );
        assert_eq!(
            role.metadata.owner_references.as_deref(),
            Some(std::slice::from_ref(&owner)),
            "Role missing OwnerRef"
        );
        assert_eq!(
            rb.metadata.owner_references.as_deref(),
            Some(std::slice::from_ref(&owner)),
            "RoleBinding missing OwnerRef"
        );

        // host_rb is intentionally NOT in this assertion set — it
        // crosses namespaces (binding lives in kube-system, parent
        // CR lives in the pool namespace). See the dedicated
        // regression test
        // `build_host_auth_reader_role_binding_omits_cross_namespace_owner_reference`
        // for why and what happens when this rule is broken.
    }

    /// The host kube-system auth-reader RoleBinding **must not**
    /// carry the parent ClusterInstance's OwnerRef, even though it
    /// is itself a namespaced resource and the call site supplies
    /// `Some(owner_ref)` for parity with other builders.
    ///
    /// Cross-namespace OwnerRefs from a namespaced child to a
    /// namespaced parent are accepted by the apiserver at create
    /// time (validation is async), then silently reaped by the GC
    /// loop within seconds when it scans the child's namespace
    /// looking for the named parent UID and finds nothing.
    ///
    /// This is the regression that shipped in PR #69 / v0.22.0 and
    /// caused KCM in every newly-created vkobe pod to crashloop
    /// with `configmaps "extension-apiserver-authentication" is
    /// forbidden` — the binding got created, GC reaped it 1-2s
    /// later, KCM started, hit the missing permission, exited 1,
    /// repeat. Manual `kubectl get rolebinding ...-auth-reader -n
    /// kube-system` returned `NotFound` despite the operator
    /// reporting successful create.
    ///
    /// Pinned here so a future "let's stamp OwnerRefs everywhere"
    /// refactor can't reintroduce the same bug.
    #[test]
    fn build_host_auth_reader_role_binding_omits_cross_namespace_owner_reference() {
        let owner = test_owner_ref();
        let host_rb = build_host_auth_reader_role_binding("c", "ns", Some(&owner));
        assert!(
            host_rb.metadata.owner_references.is_none(),
            "host kube-system auth-reader RoleBinding must NOT carry \
             a cross-namespace OwnerRef. The k8s GC reaps it within \
             seconds, leaving KCM unable to read \
             `extension-apiserver-authentication` and crashlooping. \
             See fn doc on `build_host_auth_reader_role_binding`."
        );
    }

    /// Cluster-scoped resources cannot reference a namespaced
    /// `ClusterInstance` parent (the apiserver rejects the OwnerRef
    /// as `cross-namespace owner references are disallowed`). The
    /// builders explicitly drop `owner_ref` for those two resources
    /// — the explicit `delete()` cleanup path handles them, and the
    /// fail-loud delete change ensures partial cleanup propagates
    /// to the controller's retry loop.
    #[test]
    fn build_cluster_scoped_rbac_omits_owner_reference() {
        let owner = test_owner_ref();
        let (_sa, _role, _rb, cr, crb) = build_rbac("c", "ns", Some(&owner));
        assert!(
            cr.metadata.owner_references.is_none(),
            "ClusterRole must NOT carry the OwnerRef (cross-scope rejection)"
        );
        assert!(
            crb.metadata.owner_references.is_none(),
            "ClusterRoleBinding must NOT carry the OwnerRef (cross-scope rejection)"
        );
    }

    /// When `owner_ref` is `None`, builders produce resources without
    /// an OwnerReference — preserves the legacy behavior for callers
    /// that don't have a parent CR (e.g. velero's golden-image
    /// coordinator, ad-hoc tools, tests).
    #[test]
    fn build_namespaced_resources_with_no_owner_ref_omit_field() {
        let cfg = test_kobe_sync_config();
        let svc = VkobeBackend::build_service("c", "ns", None, None);
        let cm = build_config_map_v2("c", "ns", &cfg, "http://etcd:2379", None);
        let dep = build_deployment("c", "ns", &cfg, "http://etcd:2379", "img", None);
        let (sa, role, rb, _, _) = build_rbac("c", "ns", None);
        let host_rb = build_host_auth_reader_role_binding("c", "ns", None);

        for (label, refs) in [
            ("Service", svc.metadata.owner_references),
            ("ConfigMap", cm.metadata.owner_references),
            ("Deployment", dep.metadata.owner_references),
            ("ServiceAccount", sa.metadata.owner_references),
            ("Role", role.metadata.owner_references),
            ("RoleBinding", rb.metadata.owner_references),
            (
                "host auth-reader RoleBinding",
                host_rb.metadata.owner_references,
            ),
        ] {
            assert!(
                refs.is_none(),
                "{label} must have no OwnerRef when owner_ref=None"
            );
        }
    }

    // ── v2 Deployment tests ─────────────────────────────────────────

    /// Helper: build a VkobeConfig for v2 tests.
    fn test_kobe_sync_config() -> VkobeConfig {
        VkobeConfig {
            data_store_ref: KobeStoreRef {
                name: "dev-store".into(),
            },
            version: "1.32".into(),
            kcm: None,
            syncers: vec!["pods".into(), "services".into(), "configmaps".into()],
            proxy_port: 8443,
            metrics_port: 9090,
        }
    }

    #[test]
    fn test_build_deployment_has_three_containers() {
        let config = test_kobe_sync_config();
        let dep = build_deployment(
            "cluster-1",
            "pool-prod",
            &config,
            "http://etcd.pool-prod.svc:2379",
            "test-image:latest",
            None,
        );
        let containers = &dep
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers;
        assert_eq!(containers.len(), 3);
        let names: Vec<&str> = containers.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"kube-apiserver"));
        assert!(names.contains(&"kube-controller-manager"));
        assert!(names.contains(&"vkobe"));
    }

    /// Invariant: every container the operator launches in a vkobe pod
    /// MUST carry both `requests` and `limits`. Any container without
    /// resources lands in QoS=BestEffort, and on a busy node the
    /// kernel will throttle CPU aggressively — under flux install
    /// fanout the apiserver becomes unresponsive, KCM lease writes
    /// time out (`Put .../leases/kube-controller-manager?timeout=5s:
    /// context deadline exceeded`), KCM exits with `leaderelection
    /// lost`, ServiceAccount tokens stop being generated, flux install
    /// hangs at "verifying installation", the bootstrap Job hits
    /// `BackoffLimitExceeded`, the ClusterInstance recycles, and the
    /// next instance hits the same wall — the bug observed in
    /// production on 2026-04-29.
    ///
    /// This test fails if anyone removes a container's resources or
    /// adds a new container without setting them. The defaults live
    /// in this file (`default_*_resources`); tune them by editing
    /// those, never by removing them.
    #[test]
    fn vkobe_pod_containers_must_not_be_besteffort() {
        let config = test_kobe_sync_config();
        let dep = build_deployment(
            "cluster-1",
            "pool-prod",
            &config,
            "http://etcd.pool-prod.svc:2379",
            "test-image:latest",
            None,
        );
        let containers = &dep
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers;
        assert!(
            !containers.is_empty(),
            "Deployment must have at least one container"
        );
        for c in containers {
            let resources = c.resources.as_ref().unwrap_or_else(|| {
                panic!(
                    "Container `{}` has no resources — that's QoS=BestEffort and \
                     will deadlock under flux install load. See \
                     `default_{}_resources` for the expected defaults.",
                    c.name,
                    match c.name.as_str() {
                        "kube-apiserver" => "apiserver",
                        "kube-controller-manager" => "controller_manager",
                        "vkobe" => "kobe_sync",
                        other => other,
                    }
                )
            });
            assert!(
                resources.requests.as_ref().is_some_and(|r| !r.is_empty()),
                "Container `{}` has resources but `requests` is empty — needs \
                 at least cpu+memory requests to land in QoS=Burstable.",
                c.name
            );
            assert!(
                resources.limits.as_ref().is_some_and(|l| !l.is_empty()),
                "Container `{}` has resources but `limits` is empty — without \
                 limits the kernel can't enforce a ceiling.",
                c.name
            );
        }
    }

    /// Concrete check that the apiserver gets the heaviest budget,
    /// since it's the proven bottleneck during bootstrap fanout.
    #[test]
    fn vkobe_apiserver_resources_match_documented_defaults() {
        let config = test_kobe_sync_config();
        let dep = build_deployment(
            "cluster-1",
            "pool-prod",
            &config,
            "http://etcd.pool-prod.svc:2379",
            "test-image:latest",
            None,
        );
        let containers = &dep
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers;
        let api = containers
            .iter()
            .find(|c| c.name == "kube-apiserver")
            .unwrap();
        let r = api.resources.as_ref().unwrap();
        let req = r.requests.as_ref().unwrap();
        let lim = r.limits.as_ref().unwrap();
        assert_eq!(req["cpu"], quantity("200m"));
        assert_eq!(req["memory"], quantity("256Mi"));
        assert_eq!(lim["cpu"], quantity("1"));
        assert_eq!(lim["memory"], quantity("1Gi"));
    }

    #[test]
    fn test_apiserver_container_has_etcd_flags() {
        let config = test_kobe_sync_config();
        let dep = build_deployment(
            "cluster-1",
            "pool-prod",
            &config,
            "http://etcd.pool-prod.svc:2379",
            "test-image:latest",
            None,
        );
        let containers = &dep
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers;
        let apiserver = containers
            .iter()
            .find(|c| c.name == "kube-apiserver")
            .unwrap();
        let args: Vec<&str> = apiserver
            .args
            .as_ref()
            .unwrap()
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert!(
            args.iter()
                .any(|a| *a == "--etcd-servers=http://etcd.pool-prod.svc:2379")
        );
        assert!(
            args.iter()
                .any(|a| a.starts_with("--etcd-prefix=/kobe/cluster-1/"))
        );
    }

    #[test]
    fn test_apiserver_binds_to_loopback_only() {
        // Regression: the apiserver MUST bind to 127.0.0.1 so other pods
        // in the cluster network can't reach it directly and forge
        // X-Remote-* headers using the front-proxy-client cert. See the
        // long comment in build_deployment for the threat model.
        let config = test_kobe_sync_config();
        let dep = build_deployment(
            "cluster-1",
            "pool-prod",
            &config,
            "http://etcd.pool-prod.svc:2379",
            "test-image:latest",
            None,
        );
        let containers = &dep
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers;
        let apiserver = containers
            .iter()
            .find(|c| c.name == "kube-apiserver")
            .unwrap();
        let args: Vec<&str> = apiserver
            .args
            .as_ref()
            .unwrap()
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert!(
            args.contains(&"--bind-address=127.0.0.1"),
            "apiserver must bind to 127.0.0.1 to prevent pod-network bypass; \
             args were: {args:?}"
        );
    }

    #[test]
    fn test_apiserver_has_requestheader_auth_flags() {
        // The K8s front-proxy auth pattern requires this exact set of
        // flags so the apiserver only honors X-Remote-* headers from
        // connections that present the front-proxy-client cert.
        let config = test_kobe_sync_config();
        let dep = build_deployment(
            "cluster-1",
            "pool-prod",
            &config,
            "http://etcd.pool-prod.svc:2379",
            "test-image:latest",
            None,
        );
        let apiserver = dep
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers
            .iter()
            .find(|c| c.name == "kube-apiserver")
            .unwrap()
            .clone();
        let args: Vec<String> = apiserver.args.unwrap();
        for required in [
            "--requestheader-client-ca-file=/pki/front-proxy-ca.crt",
            "--requestheader-allowed-names=front-proxy-client",
            "--requestheader-username-headers=X-Remote-User",
            "--requestheader-group-headers=X-Remote-Group",
            "--requestheader-extra-headers-prefix=X-Remote-Extra-",
        ] {
            assert!(
                args.iter().any(|a| a == required),
                "apiserver missing required front-proxy flag: {required}"
            );
        }
    }

    #[test]
    fn test_readiness_probe_lives_on_kobe_sync() {
        // With the apiserver bound to loopback, the kubelet can't reach
        // it directly. The pod's readiness signal lives on the kobe-sync
        // container's metrics port instead — kobe-sync only starts
        // serving after `wait_for_apiserver` confirms the local apiserver
        // is up, so kobe-sync ready ⇒ apiserver ready.
        let config = test_kobe_sync_config();
        let dep = build_deployment(
            "cluster-1",
            "pool-prod",
            &config,
            "http://etcd.pool-prod.svc:2379",
            "test-image:latest",
            None,
        );
        let containers = &dep
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers;

        let apiserver = containers
            .iter()
            .find(|c| c.name == "kube-apiserver")
            .unwrap();
        assert!(
            apiserver.readiness_probe.is_none(),
            "apiserver should not have a readiness probe: kubelet cannot reach 127.0.0.1:6443 from the host netns"
        );

        let kobe_sync = containers.iter().find(|c| c.name == "vkobe").unwrap();
        let probe = kobe_sync
            .readiness_probe
            .as_ref()
            .expect("kobe-sync container must carry the pod's readiness probe");
        let http = probe
            .http_get
            .as_ref()
            .expect("readiness probe should be HTTPGet on the metrics port");
        assert_eq!(http.path.as_deref(), Some("/readyz"));
        assert_eq!(http.scheme.as_deref(), Some("HTTP"));
    }

    #[test]
    fn test_kcm_container_has_disabled_controllers() {
        let config = test_kobe_sync_config();
        let dep = build_deployment(
            "cluster-1",
            "pool-prod",
            &config,
            "http://etcd.pool-prod.svc:2379",
            "test-image:latest",
            None,
        );
        let containers = &dep
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers;
        let kcm = containers
            .iter()
            .find(|c| c.name == "kube-controller-manager")
            .unwrap();
        let args: Vec<&str> = kcm
            .args
            .as_ref()
            .unwrap()
            .iter()
            .map(|s| s.as_str())
            .collect();
        // Must disable nodelifecycle, persistentvolume-binder, attachdetach, ttl
        assert!(args.iter().any(|a| a.contains("-nodelifecycle")));
    }

    #[test]
    fn test_deployment_is_stateless() {
        let config = test_kobe_sync_config();
        let dep = build_deployment(
            "cluster-1",
            "pool-prod",
            &config,
            "http://etcd.pool-prod.svc:2379",
            "test-image:latest",
            None,
        );
        let template = &dep.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
        // No PVCs — stateless pod
        assert!(
            template
                .volumes
                .as_ref()
                .is_none_or(|vols| { !vols.iter().any(|v| v.persistent_volume_claim.is_some()) })
        );
    }

    #[test]
    fn test_build_config_map_v2_has_etcd_info() {
        let config = test_kobe_sync_config();
        let cm = build_config_map_v2(
            "cluster-1",
            "pool-prod",
            &config,
            "https://etcd-0:2379",
            None,
        );
        assert_eq!(cm.metadata.name.as_deref(), Some("cluster-1-config"));
        let data = cm.data.unwrap();
        let config_json = data.get("config.json").unwrap();
        assert!(config_json.contains("etcd_endpoints"));
        assert!(config_json.contains("/kobe/cluster-1/"));
    }

    #[test]
    fn test_deployment_pki_volume_from_secret() {
        let config = test_kobe_sync_config();
        let dep = build_deployment(
            "cluster-1",
            "pool-prod",
            &config,
            "http://etcd.pool-prod.svc:2379",
            "test-image:latest",
            None,
        );
        let volumes = dep
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .volumes
            .as_ref()
            .unwrap();
        let pki_vol = volumes.iter().find(|v| v.name == "pki-volume").unwrap();
        assert_eq!(
            pki_vol.secret.as_ref().unwrap().secret_name.as_deref(),
            Some("cluster-1-certs")
        );
    }

    #[test]
    fn test_deployment_has_prometheus_annotations() {
        let config = test_kobe_sync_config();
        let dep = build_deployment(
            "cluster-1",
            "pool-prod",
            &config,
            "http://etcd.pool-prod.svc:2379",
            "test-image:latest",
            None,
        );
        let annotations = dep
            .spec
            .as_ref()
            .unwrap()
            .template
            .metadata
            .as_ref()
            .unwrap()
            .annotations
            .as_ref()
            .unwrap();
        assert_eq!(
            annotations.get("prometheus.io/scrape"),
            Some(&"true".to_string())
        );
        assert_eq!(
            annotations.get("prometheus.io/port"),
            Some(&"9090".to_string())
        );
    }

    // ── RBAC tests ────────────────────────────────────────────────────

    #[test]
    fn test_build_rbac_creates_correct_names() {
        let (sa, role, rb, cr, crb) = build_rbac("test-cluster", "test-ns", None);

        assert_eq!(sa.metadata.name.as_deref(), Some("test-cluster-vkobe"));
        assert_eq!(sa.metadata.namespace.as_deref(), Some("test-ns"));
        assert_eq!(role.metadata.name.as_deref(), Some("test-cluster-vkobe"));
        assert_eq!(rb.metadata.name.as_deref(), Some("test-cluster-vkobe"));
        assert_eq!(
            cr.metadata.name.as_deref(),
            Some("test-cluster-vkobe-nodes")
        );
        assert_eq!(
            crb.metadata.name.as_deref(),
            Some("test-cluster-vkobe-nodes")
        );
    }

    #[test]
    fn test_rbac_sa_name_matches_deployment() {
        let config = test_kobe_sync_config();
        let dep = build_deployment(
            "cluster-1",
            "pool-prod",
            &config,
            "http://etcd.pool-prod.svc:2379",
            "test-image:latest",
            None,
        );
        let (sa, ..) = build_rbac("cluster-1", "pool-prod", None);

        let sa_name_on_dep = dep
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .service_account_name
            .as_ref()
            .unwrap();
        assert_eq!(sa_name_on_dep, sa.metadata.name.as_ref().unwrap());
    }

    #[test]
    fn test_rbac_role_has_all_required_verbs() {
        let (_, role, ..) = build_rbac("test-cluster", "test-ns", None);
        let rules = role.rules.as_ref().unwrap();

        // Check core API group rule (pods, services, configmaps, etc.)
        let core_rule = rules
            .iter()
            .find(|r| {
                r.api_groups
                    .as_ref()
                    .is_some_and(|g| g.contains(&"".to_string()))
                    && r.resources
                        .as_ref()
                        .is_some_and(|res| res.contains(&"pods".to_string()))
            })
            .expect("Should have a core API group rule for pods");

        let expected_verbs = [
            "get", "list", "watch", "create", "update", "patch", "delete",
        ];
        for verb in &expected_verbs {
            assert!(
                core_rule.verbs.contains(&verb.to_string()),
                "Role should have verb '{verb}' for core resources"
            );
        }

        // Check that the required core resources are present
        let core_resources = core_rule.resources.as_ref().unwrap();
        for resource in &[
            "pods",
            "services",
            "configmaps",
            "secrets",
            "endpoints",
            "persistentvolumeclaims",
        ] {
            assert!(
                core_resources.contains(&resource.to_string()),
                "Role should manage '{resource}'"
            );
        }

        // Check networking API group rule
        let networking_rule = rules
            .iter()
            .find(|r| {
                r.api_groups
                    .as_ref()
                    .is_some_and(|g| g.contains(&"networking.k8s.io".to_string()))
            })
            .expect("Should have a networking.k8s.io rule");
        let net_resources = networking_rule.resources.as_ref().unwrap();
        assert!(net_resources.contains(&"ingresses".to_string()));
        assert!(net_resources.contains(&"networkpolicies".to_string()));

        // Check pods/status subresource
        let status_rule = rules
            .iter()
            .find(|r| {
                r.resources
                    .as_ref()
                    .is_some_and(|res| res.contains(&"pods/status".to_string()))
            })
            .expect("Should have a pods/status rule");
        assert!(status_rule.verbs.contains(&"get".to_string()));
        assert!(status_rule.verbs.contains(&"patch".to_string()));
    }

    #[test]
    fn test_rbac_cluster_role_has_node_permissions() {
        let (.., cr, _) = build_rbac("test-cluster", "test-ns", None);
        let rules = cr.rules.as_ref().unwrap();

        assert_eq!(rules.len(), 1, "ClusterRole should have exactly one rule");
        let rule = &rules[0];

        let resources = rule.resources.as_ref().unwrap();
        assert!(resources.contains(&"nodes".to_string()));

        for verb in &["get", "list", "watch"] {
            assert!(
                rule.verbs.contains(&verb.to_string()),
                "ClusterRole should have verb '{verb}' for nodes"
            );
        }
        // Should NOT have write verbs on nodes
        assert!(
            !rule.verbs.contains(&"create".to_string()),
            "ClusterRole should not have 'create' on nodes"
        );
        assert!(
            !rule.verbs.contains(&"delete".to_string()),
            "ClusterRole should not have 'delete' on nodes"
        );
    }

    #[test]
    fn test_rbac_resources_have_correct_labels() {
        let (sa, role, rb, cr, crb) = build_rbac("test-cluster", "test-ns", None);
        let expected_labels = VkobeBackend::cluster_labels("test-cluster");

        assert_eq!(sa.metadata.labels.as_ref().unwrap(), &expected_labels);
        assert_eq!(role.metadata.labels.as_ref().unwrap(), &expected_labels);
        assert_eq!(rb.metadata.labels.as_ref().unwrap(), &expected_labels);
        assert_eq!(cr.metadata.labels.as_ref().unwrap(), &expected_labels);
        assert_eq!(crb.metadata.labels.as_ref().unwrap(), &expected_labels);
    }

    #[test]
    fn test_rbac_role_binding_references_correct_role() {
        let (_, _, rb, ..) = build_rbac("test-cluster", "test-ns", None);

        assert_eq!(rb.role_ref.kind, "Role");
        assert_eq!(rb.role_ref.name, "test-cluster-vkobe");
        assert_eq!(rb.role_ref.api_group, "rbac.authorization.k8s.io");

        let subject = &rb.subjects.as_ref().unwrap()[0];
        assert_eq!(subject.kind, "ServiceAccount");
        assert_eq!(subject.name, "test-cluster-vkobe");
        assert_eq!(subject.namespace.as_deref(), Some("test-ns"));
    }

    #[test]
    fn test_rbac_cluster_role_binding_references_correct_cluster_role() {
        let (.., crb) = build_rbac("test-cluster", "test-ns", None);

        assert_eq!(crb.role_ref.kind, "ClusterRole");
        assert_eq!(crb.role_ref.name, "test-cluster-vkobe-nodes");
        assert_eq!(crb.role_ref.api_group, "rbac.authorization.k8s.io");

        let subject = &crb.subjects.as_ref().unwrap()[0];
        assert_eq!(subject.kind, "ServiceAccount");
        assert_eq!(subject.name, "test-cluster-vkobe");
        assert_eq!(subject.namespace.as_deref(), Some("test-ns"));
    }

    #[test]
    fn test_host_auth_reader_role_binding_references_builtin_role() {
        let rb = build_host_auth_reader_role_binding("test-cluster", "test-ns", None);

        assert_eq!(
            rb.metadata.name.as_deref(),
            Some("test-cluster-vkobe-auth-reader")
        );
        assert_eq!(rb.metadata.namespace.as_deref(), Some("kube-system"));
        assert_eq!(rb.role_ref.kind, "Role");
        assert_eq!(
            rb.role_ref.name,
            "extension-apiserver-authentication-reader"
        );

        let subject = &rb.subjects.as_ref().unwrap()[0];
        assert_eq!(subject.kind, "ServiceAccount");
        assert_eq!(subject.name, "test-cluster-vkobe");
        assert_eq!(subject.namespace.as_deref(), Some("test-ns"));
    }
}
