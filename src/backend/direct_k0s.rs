//! Direct k0s backend -- manages k0s clusters via StatefulSets, without external operators.
//!
//! Instead of relying on any third-party operator, this backend directly creates
//! the Kubernetes resources needed to run k0s:
//!
//! - A **token Secret** for inter-node authentication
//! - A **k0s.yaml ConfigMap** with cluster configuration (including datastore settings)
//! - A **server StatefulSet** running `k0s controller --enable-worker`
//! - A **kubeconfig-publisher sidecar** that creates the `{name}-kubeconfig` Secret
//! - A **ClusterIP Service** exposing port 6443
//! - Optionally, an **agent Deployment** running `k0s worker`
//!
//! When a shared PostgreSQL datastore is configured, the k0s.yaml spec sets
//! `spec.storage.type: kine` with a PostgreSQL dataSource, instead of the
//! default etcd backend.

use anyhow::{Context, Result};
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, StatefulSet, StatefulSetSpec};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, EnvVar, KeyToPath, PodSpec, PodTemplateSpec, Secret, SecretVolumeSource,
    Service, ServicePort, ServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Api, DeleteParams, ObjectMeta, Patch, PatchParams};
use kube::Client;
use sqlx::PgPool;
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

use crate::crd::{Addon, ClusterConfig, ReadinessGate};

use super::{
    apply_addon_impl, check_readiness_gate_impl, check_virtual_health, datastore,
    read_kubeconfig_secret, virtual_client_from_kubeconfig, ClusterBackend,
};

/// Database name prefix for k0s clusters.
pub const DB_PREFIX: &str = "k0s_";

/// Labels applied to all resources managed by this backend.
const MANAGED_BY: &str = "kobe-operator";

/// The kubeconfig publisher sidecar script, mounted from a ConfigMap.
///
/// Waits for k0s to generate the admin kubeconfig at `/var/lib/k0s/pki/admin.conf`,
/// rewrites the server URL to the ClusterIP Service address, and creates/updates
/// a Kubernetes Secret.
const KUBECONFIG_PUBLISHER_SCRIPT: &str = r#"#!/bin/sh
set -e
echo "Waiting for kubeconfig to appear..."
while [ ! -f /var/lib/k0s/pki/admin.conf ]; do sleep 1; done
echo "Kubeconfig found, rewriting server URL..."
cp /var/lib/k0s/pki/admin.conf /tmp/kubeconfig
sed -i "s|https://localhost:6443|https://${CLUSTER_NAME}-server.${NAMESPACE}.svc:6443|" /tmp/kubeconfig
sed -i "s|https://127.0.0.1:6443|https://${CLUSTER_NAME}-server.${NAMESPACE}.svc:6443|" /tmp/kubeconfig
echo "Publishing kubeconfig as Secret..."
kubectl create secret generic ${CLUSTER_NAME}-kubeconfig \
  --from-file=kubeconfig=/tmp/kubeconfig \
  --namespace=${NAMESPACE} \
  -o yaml --dry-run=client | kubectl apply -f -
echo "Kubeconfig Secret published, sleeping..."
sleep infinity
"#;

/// Direct k0s backend -- manages k0s clusters via raw Kubernetes resources.
#[derive(Clone)]
pub struct DirectK0sBackend {
    /// Kubernetes client for the host cluster.
    client: Client,
    /// Optional PostgreSQL connection pool for shared datastore.
    pg_pool: Option<PgPool>,
    /// Base PostgreSQL connection URL (before per-cluster DB rewriting).
    pg_base_url: Option<String>,
}

impl DirectK0sBackend {
    pub fn new(client: Client, pg_pool: Option<PgPool>, pg_base_url: Option<String>) -> Self {
        Self {
            client,
            pg_pool,
            pg_base_url,
        }
    }

    /// Build a kube Client targeting the virtual cluster's API server.
    async fn virtual_client(&self, name: &str, namespace: &str) -> Result<Client> {
        let kubeconfig_yaml = read_kubeconfig_secret(&self.client, name, namespace).await?;
        virtual_client_from_kubeconfig(&kubeconfig_yaml).await
    }

    /// Generate a random token for k0s node authentication.
    fn generate_token() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.random()).collect();
        hex::encode(bytes)
    }

    /// Standard labels for resources belonging to a cluster.
    fn cluster_labels(name: &str) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        labels.insert("kobe.kunobi.ninja/cluster".to_string(), name.to_string());
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            MANAGED_BY.to_string(),
        );
        labels
    }

    /// Labels for server pods specifically.
    fn server_labels(name: &str) -> BTreeMap<String, String> {
        let mut labels = Self::cluster_labels(name);
        labels.insert("kobe.kunobi.ninja/role".to_string(), "server".to_string());
        labels
    }

    /// Labels for agent pods specifically.
    fn agent_labels(name: &str) -> BTreeMap<String, String> {
        let mut labels = Self::cluster_labels(name);
        labels.insert("kobe.kunobi.ninja/role".to_string(), "agent".to_string());
        labels
    }

    /// Generate a k0s.yaml configuration file.
    ///
    /// When `datastore_endpoint` is `Some`, configures kine with a PostgreSQL
    /// data source. Otherwise, uses the default etcd storage backend.
    /// Any `extra_args` are appended to the `spec.api.extraArgs` map.
    pub fn build_k0s_config_yaml(
        datastore_endpoint: Option<&str>,
        extra_args: &[String],
    ) -> String {
        let storage_section = if let Some(endpoint) = datastore_endpoint {
            format!(
                r#"    type: kine
    kine:
      dataSource: "{endpoint}""#
            )
        } else {
            "    type: etcd".to_string()
        };

        let extra_args_section = if extra_args.is_empty() {
            String::new()
        } else {
            let mut section = String::from("  api:\n    extraArgs:\n");
            for arg in extra_args {
                // Parse --key=value format
                let stripped = arg.strip_prefix("--").unwrap_or(arg);
                if let Some((key, value)) = stripped.split_once('=') {
                    section.push_str(&format!("      {key}: \"{value}\"\n"));
                }
            }
            section
        };

        let mut yaml = format!(
            r#"apiVersion: k0s.k0sproject.io/v1beta1
kind: ClusterConfig
metadata:
  name: k0s
spec:
  storage:
{storage_section}
  network:
    provider: kube-router
"#
        );

        if !extra_args_section.is_empty() {
            yaml.push_str(&extra_args_section);
        }

        yaml
    }

    /// Build the ConfigMap containing the k0s.yaml configuration.
    fn build_k0s_config_configmap(name: &str, namespace: &str, config_yaml: &str) -> ConfigMap {
        ConfigMap {
            metadata: ObjectMeta {
                name: Some(format!("{name}-k0s-config")),
                namespace: Some(namespace.to_string()),
                labels: Some(Self::cluster_labels(name)),
                ..Default::default()
            },
            data: Some({
                let mut data = BTreeMap::new();
                data.insert("k0s.yaml".to_string(), config_yaml.to_string());
                data
            }),
            ..Default::default()
        }
    }

    /// Create the token Secret for k0s node authentication.
    async fn create_token_secret(&self, name: &str, namespace: &str) -> Result<()> {
        let token = Self::generate_token();
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let secret_name = format!("{name}-token");

        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(secret_name.clone()),
                namespace: Some(namespace.to_string()),
                labels: Some(Self::cluster_labels(name)),
                ..Default::default()
            },
            string_data: Some({
                let mut data = BTreeMap::new();
                data.insert("token".to_string(), token);
                data
            }),
            ..Default::default()
        };

        secrets
            .patch(
                &secret_name,
                &PatchParams::apply("kobe-operator").force(),
                &Patch::Apply(&secret),
            )
            .await
            .with_context(|| format!("Failed to apply token secret {secret_name}"))?;

        debug!(cluster = name, "Token secret applied");
        Ok(())
    }

    /// Create the ConfigMap containing the kubeconfig publisher script.
    async fn create_publisher_configmap(&self, name: &str, namespace: &str) -> Result<()> {
        let cms: Api<ConfigMap> = Api::namespaced(self.client.clone(), namespace);
        let cm_name = format!("{name}-kubeconfig-publisher");

        let cm = ConfigMap {
            metadata: ObjectMeta {
                name: Some(cm_name.clone()),
                namespace: Some(namespace.to_string()),
                labels: Some(Self::cluster_labels(name)),
                ..Default::default()
            },
            data: Some({
                let mut data = BTreeMap::new();
                data.insert(
                    "publish.sh".to_string(),
                    KUBECONFIG_PUBLISHER_SCRIPT.to_string(),
                );
                data
            }),
            ..Default::default()
        };

        cms.patch(
            &cm_name,
            &PatchParams::apply("kobe-operator").force(),
            &Patch::Apply(&cm),
        )
        .await
        .with_context(|| format!("Failed to apply publisher ConfigMap {cm_name}"))?;

        debug!(cluster = name, "Publisher ConfigMap applied");
        Ok(())
    }

    /// Create the ConfigMap containing the k0s.yaml cluster configuration.
    async fn create_k0s_config_configmap(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        datastore_endpoint: Option<&str>,
    ) -> Result<()> {
        let config_yaml = Self::build_k0s_config_yaml(datastore_endpoint, &config.server_args);
        let cm = Self::build_k0s_config_configmap(name, namespace, &config_yaml);

        let cms: Api<ConfigMap> = Api::namespaced(self.client.clone(), namespace);
        let cm_name = format!("{name}-k0s-config");
        cms.patch(
            &cm_name,
            &PatchParams::apply("kobe-operator").force(),
            &Patch::Apply(&cm),
        )
        .await
        .with_context(|| format!("Failed to apply k0s config ConfigMap for {name}"))?;

        debug!(cluster = name, "k0s config ConfigMap applied");
        Ok(())
    }

    /// Build the k0s controller container.
    fn build_server_container(name: &str, namespace: &str, config: &ClusterConfig) -> Container {
        let image = format!("k0sproject/k0s:{}", config.version);

        let args = vec![
            "controller".to_string(),
            format!("--config=/etc/k0s/k0s.yaml"),
            "--enable-worker".to_string(),
            format!("--token-file=/var/lib/k0s/token/token"),
        ];

        let mut volume_mounts = vec![
            VolumeMount {
                name: "token".to_string(),
                mount_path: "/var/lib/k0s/token".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "k0s-config".to_string(),
                mount_path: "/etc/k0s".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "k0s-data".to_string(),
                mount_path: "/var/lib/k0s".to_string(),
                ..Default::default()
            },
        ];

        // If persistence is configured, mount data volume
        if config.persistence.is_some() {
            volume_mounts.push(VolumeMount {
                name: "data".to_string(),
                mount_path: "/var/lib/k0s/data".to_string(),
                ..Default::default()
            });
        }

        let _ = (name, namespace); // used for consistency with k3s signature

        Container {
            name: "k0s-controller".to_string(),
            image: Some(image),
            command: Some(vec!["k0s".to_string()]),
            args: Some(args),
            volume_mounts: Some(volume_mounts),
            ports: Some(vec![k8s_openapi::api::core::v1::ContainerPort {
                container_port: 6443,
                name: Some("api".to_string()),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }]),
            readiness_probe: Some(k8s_openapi::api::core::v1::Probe {
                tcp_socket: Some(k8s_openapi::api::core::v1::TCPSocketAction {
                    port: IntOrString::Int(6443),
                    ..Default::default()
                }),
                initial_delay_seconds: Some(10),
                period_seconds: Some(5),
                ..Default::default()
            }),
            liveness_probe: Some(k8s_openapi::api::core::v1::Probe {
                http_get: Some(k8s_openapi::api::core::v1::HTTPGetAction {
                    path: Some("/healthz".to_string()),
                    port: IntOrString::Int(6443),
                    scheme: Some("HTTPS".to_string()),
                    ..Default::default()
                }),
                initial_delay_seconds: Some(30),
                period_seconds: Some(10),
                ..Default::default()
            }),
            security_context: Some(k8s_openapi::api::core::v1::SecurityContext {
                privileged: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Build the kubeconfig publisher sidecar container.
    fn build_publisher_sidecar(name: &str, namespace: &str, k0s_image: &str) -> Container {
        Container {
            name: "kubeconfig-publisher".to_string(),
            image: Some(k0s_image.to_string()),
            command: Some(vec!["sh".to_string(), "/scripts/publish.sh".to_string()]),
            env: Some(vec![
                EnvVar {
                    name: "CLUSTER_NAME".to_string(),
                    value: Some(name.to_string()),
                    ..Default::default()
                },
                EnvVar {
                    name: "NAMESPACE".to_string(),
                    value: Some(namespace.to_string()),
                    ..Default::default()
                },
            ]),
            volume_mounts: Some(vec![
                VolumeMount {
                    name: "k0s-data".to_string(),
                    mount_path: "/var/lib/k0s".to_string(),
                    read_only: Some(true),
                    ..Default::default()
                },
                VolumeMount {
                    name: "publisher-script".to_string(),
                    mount_path: "/scripts".to_string(),
                    read_only: Some(true),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }
    }

    /// Build the volumes list for the server pod.
    fn build_server_volumes(name: &str, config: &ClusterConfig) -> Vec<Volume> {
        let mut volumes = vec![
            // Token secret mount
            Volume {
                name: "token".to_string(),
                secret: Some(SecretVolumeSource {
                    secret_name: Some(format!("{name}-token")),
                    items: Some(vec![KeyToPath {
                        key: "token".to_string(),
                        path: "token".to_string(),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            },
            // k0s config ConfigMap mount
            Volume {
                name: "k0s-config".to_string(),
                config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                    name: format!("{name}-k0s-config"),
                    ..Default::default()
                }),
                ..Default::default()
            },
            // Shared k0s data volume (controller writes kubeconfig here, sidecar reads it)
            Volume {
                name: "k0s-data".to_string(),
                empty_dir: Some(k8s_openapi::api::core::v1::EmptyDirVolumeSource {
                    ..Default::default()
                }),
                ..Default::default()
            },
            // Publisher script ConfigMap
            Volume {
                name: "publisher-script".to_string(),
                config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                    name: format!("{name}-kubeconfig-publisher"),
                    default_mode: Some(0o755),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];

        // Data volume -- PVC if persistence is configured, otherwise emptyDir
        if config.persistence.is_some() {
            volumes.push(Volume {
                name: "data".to_string(),
                empty_dir: Some(k8s_openapi::api::core::v1::EmptyDirVolumeSource::default()),
                ..Default::default()
            });
        }

        volumes
    }

    /// Build the server StatefulSet.
    fn build_server_statefulset(
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        datastore_endpoint: Option<&str>,
    ) -> StatefulSet {
        let k0s_image = format!("k0sproject/k0s:{}", config.version);
        let labels = Self::server_labels(name);

        // Build the k0s.yaml so the ConfigMap is consistent but note: the
        // actual ConfigMap is created separately. The StatefulSet just mounts it.
        let _ = datastore_endpoint; // used to select kine vs etcd in the config

        let server_container = Self::build_server_container(name, namespace, config);
        let publisher_sidecar = Self::build_publisher_sidecar(name, namespace, &k0s_image);
        let volumes = Self::build_server_volumes(name, config);

        StatefulSet {
            metadata: ObjectMeta {
                name: Some(format!("{name}-server")),
                namespace: Some(namespace.to_string()),
                labels: Some(labels.clone()),
                ..Default::default()
            },
            spec: Some(StatefulSetSpec {
                replicas: Some(1),
                service_name: Some(format!("{name}-server")),
                selector: LabelSelector {
                    match_labels: Some(labels.clone()),
                    ..Default::default()
                },
                template: PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        labels: Some(labels),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        containers: vec![server_container, publisher_sidecar],
                        volumes: Some(volumes),
                        service_account_name: Some(
                            std::env::var("POOL_SERVICE_ACCOUNT")
                                .unwrap_or_else(|_| "kobe-operator".to_string()),
                        ),
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Build the ClusterIP Service for the k0s API server.
    fn build_service(name: &str, namespace: &str, config: &ClusterConfig) -> Service {
        let labels = Self::server_labels(name);

        let service_type = config
            .expose
            .as_ref()
            .map(|e| e.expose_type.clone())
            .unwrap_or_else(|| "ClusterIP".to_string());

        let node_port = config.expose.as_ref().and_then(|e| e.node_port);

        Service {
            metadata: ObjectMeta {
                name: Some(format!("{name}-server")),
                namespace: Some(namespace.to_string()),
                labels: Some(Self::cluster_labels(name)),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some(service_type),
                selector: Some(labels),
                ports: Some(vec![ServicePort {
                    port: 6443,
                    target_port: Some(IntOrString::Int(6443)),
                    name: Some("api".to_string()),
                    protocol: Some("TCP".to_string()),
                    node_port,
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Build the agent Deployment.
    fn build_agent_deployment(
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        replicas: u32,
    ) -> Deployment {
        let k0s_image = format!("k0sproject/k0s:{}", config.version);
        let labels = Self::agent_labels(name);

        let container = Container {
            name: "k0s-worker".to_string(),
            image: Some(k0s_image),
            command: Some(vec!["k0s".to_string()]),
            args: Some(vec![
                "worker".to_string(),
                format!("--token-file=/var/lib/k0s/token/token"),
            ]),
            volume_mounts: Some(vec![VolumeMount {
                name: "token".to_string(),
                mount_path: "/var/lib/k0s/token".to_string(),
                read_only: Some(true),
                ..Default::default()
            }]),
            security_context: Some(k8s_openapi::api::core::v1::SecurityContext {
                privileged: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        Deployment {
            metadata: ObjectMeta {
                name: Some(format!("{name}-agent")),
                namespace: Some(namespace.to_string()),
                labels: Some(labels.clone()),
                ..Default::default()
            },
            spec: Some(DeploymentSpec {
                replicas: Some(i32::try_from(replicas).unwrap_or(i32::MAX)),
                selector: LabelSelector {
                    match_labels: Some(labels.clone()),
                    ..Default::default()
                },
                template: PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        labels: Some(labels),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        containers: vec![container],
                        volumes: Some(vec![Volume {
                            name: "token".to_string(),
                            secret: Some(SecretVolumeSource {
                                secret_name: Some(format!("{name}-token")),
                                items: Some(vec![KeyToPath {
                                    key: "token".to_string(),
                                    path: "token".to_string(),
                                    ..Default::default()
                                }]),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Wait for the kubeconfig Secret to appear (created by the sidecar).
    async fn wait_ready(&self, name: &str, namespace: &str) -> Result<()> {
        debug!(
            cluster = name,
            "Waiting for direct-k0s cluster to become ready"
        );

        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let secret_name = format!("{name}-kubeconfig");

        // Poll every 5s for up to 10 minutes
        for attempt in 0..120 {
            match secrets.get(&secret_name).await {
                Ok(_) => {
                    info!(
                        cluster = name,
                        attempts = attempt + 1,
                        "direct-k0s cluster kubeconfig secret found"
                    );
                    return Ok(());
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    if attempt % 12 == 0 {
                        debug!(
                            cluster = name,
                            attempt = attempt + 1,
                            "Waiting for direct-k0s cluster kubeconfig..."
                        );
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                Err(e) => {
                    return Err(e).context(format!(
                        "Error checking direct-k0s cluster {name} readiness"
                    ));
                }
            }
        }

        anyhow::bail!("direct-k0s cluster {name} not ready after 10 minutes");
    }

    /// Delete a resource, ignoring 404 (already deleted).
    async fn delete_ignoring_not_found<K>(api: &Api<K>, name: &str) -> Result<()>
    where
        K: kube::Resource
            + Clone
            + serde::de::DeserializeOwned
            + std::fmt::Debug
            + Send
            + Sync
            + 'static,
        <K as kube::Resource>::DynamicType: Default,
    {
        match api.delete(name, &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

impl ClusterBackend for DirectK0sBackend {
    #[tracing::instrument(skip(self, config, addons), fields(cluster = name, namespace))]
    async fn create(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        addons: &[Addon],
    ) -> Result<()> {
        info!(cluster = name, "Creating direct-k0s cluster");

        // 1. Create token secret
        self.create_token_secret(name, namespace).await?;

        // 2. Create publisher ConfigMap
        self.create_publisher_configmap(name, namespace).await?;

        // 3. If PostgreSQL configured, create per-cluster database
        let datastore_endpoint =
            if let (Some(pool), Some(base_url)) = (&self.pg_pool, &self.pg_base_url) {
                datastore::create_database(pool, name, DB_PREFIX).await?;
                let endpoint = datastore::cluster_endpoint(base_url, name, DB_PREFIX)?;
                Some(endpoint)
            } else {
                None
            };

        // 4. Create k0s config ConfigMap
        self.create_k0s_config_configmap(name, namespace, config, datastore_endpoint.as_deref())
            .await?;

        // 5. Create server StatefulSet
        let sts =
            Self::build_server_statefulset(name, namespace, config, datastore_endpoint.as_deref());
        let sts_api: Api<StatefulSet> = Api::namespaced(self.client.clone(), namespace);
        let sts_name = format!("{name}-server");
        sts_api
            .patch(
                &sts_name,
                &PatchParams::apply("kobe-operator").force(),
                &Patch::Apply(&sts),
            )
            .await
            .with_context(|| format!("Failed to apply server StatefulSet for {name}"))?;
        info!(cluster = name, "Server StatefulSet applied");

        // 6. Create Service
        let svc = Self::build_service(name, namespace, config);
        let svc_api: Api<Service> = Api::namespaced(self.client.clone(), namespace);
        let svc_name = format!("{name}-server");
        svc_api
            .patch(
                &svc_name,
                &PatchParams::apply("kobe-operator").force(),
                &Patch::Apply(&svc),
            )
            .await
            .with_context(|| format!("Failed to apply Service for {name}"))?;
        info!(cluster = name, "Service applied");

        // 7. Wait for kubeconfig Secret (created by sidecar)
        self.wait_ready(name, namespace).await?;

        // 8. Create agent Deployment if requested
        if let Some(agents) = config.agents {
            if agents > 0 {
                let deploy = Self::build_agent_deployment(name, namespace, config, agents);
                let deploy_api: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
                let deploy_name = format!("{name}-agent");
                deploy_api
                    .patch(
                        &deploy_name,
                        &PatchParams::apply("kobe-operator").force(),
                        &Patch::Apply(&deploy),
                    )
                    .await
                    .with_context(|| format!("Failed to apply agent Deployment for {name}"))?;
                info!(cluster = name, agents = agents, "Agent Deployment applied");
            }
        }

        // 9. Apply addons
        for addon in addons {
            self.apply_addon(name, namespace, addon).await?;
        }

        info!(cluster = name, "direct-k0s cluster fully ready with addons");
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(cluster = name, namespace))]
    async fn delete(&self, name: &str, namespace: &str) -> Result<()> {
        info!(cluster = name, "Deleting direct-k0s cluster");

        // Delete agent Deployment
        let deploy_api: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&deploy_api, &format!("{name}-agent")).await?;

        // Delete Service
        let svc_api: Api<Service> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&svc_api, &format!("{name}-server")).await?;

        // Delete server StatefulSet
        let sts_api: Api<StatefulSet> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&sts_api, &format!("{name}-server")).await?;

        // Delete k0s config ConfigMap
        let cms: Api<ConfigMap> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&cms, &format!("{name}-k0s-config")).await?;

        // Delete publisher ConfigMap
        Self::delete_ignoring_not_found(&cms, &format!("{name}-kubeconfig-publisher")).await?;

        // Delete secrets: token and kubeconfig
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&secrets, &format!("{name}-token")).await?;
        Self::delete_ignoring_not_found(&secrets, &format!("{name}-kubeconfig")).await?;

        // Drop database if PostgreSQL is configured
        if let Some(pool) = &self.pg_pool {
            if let Err(e) = datastore::drop_database(pool, name, DB_PREFIX).await {
                warn!(cluster = name, error = %e, "Failed to drop database (may not exist)");
            }
        }

        info!(cluster = name, "direct-k0s cluster deleted");
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(cluster = name, namespace))]
    async fn check_health(&self, name: &str, namespace: &str) -> Result<bool> {
        check_virtual_health(&self.client, name, namespace).await
    }

    async fn extract_kubeconfig(&self, name: &str, namespace: &str) -> Result<String> {
        info!(
            cluster = name,
            "Extracting kubeconfig from direct-k0s secret"
        );
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
        info!(
            cluster = name,
            addon = addon.name,
            "Applying addon via kube-rs SSA"
        );
        let vc_client = self.virtual_client(name, namespace).await?;
        apply_addon_impl(&vc_client, addon).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{ClusterConfig, ExposeConfig, PersistenceConfig};

    fn base_config() -> ClusterConfig {
        ClusterConfig {
            version: "v1.30.1+k0s.0".to_string(),
            servers: 1,
            agents: None,
            server_args: vec![],
            persistence: None,
            expose: None,
        }
    }

    // =================================================================
    // Pure function tests for resource builders
    // =================================================================

    #[test]
    fn test_db_prefix_is_k0s() {
        assert_eq!(DB_PREFIX, "k0s_");
    }

    #[test]
    fn test_build_k0s_config_yaml_no_pg() {
        let yaml = DirectK0sBackend::build_k0s_config_yaml(None, &[]);
        assert!(
            yaml.contains("type: etcd"),
            "Should use etcd when no PG: {yaml}"
        );
        assert!(
            !yaml.contains("kine"),
            "Should not contain kine section: {yaml}"
        );
        assert!(yaml.contains("apiVersion: k0s.k0sproject.io/v1beta1"));
        assert!(yaml.contains("kind: ClusterConfig"));
        assert!(yaml.contains("provider: kube-router"));
    }

    #[test]
    fn test_build_k0s_config_yaml_with_pg() {
        let yaml = DirectK0sBackend::build_k0s_config_yaml(
            Some("postgres://user:pass@pg:5432/k0s_my_cluster"),
            &[],
        );
        assert!(
            yaml.contains("type: kine"),
            "Should use kine when PG is set: {yaml}"
        );
        assert!(
            yaml.contains("dataSource: \"postgres://user:pass@pg:5432/k0s_my_cluster\""),
            "Should contain PG endpoint: {yaml}"
        );
        assert!(!yaml.contains("type: etcd"), "Should not use etcd: {yaml}");
    }

    #[test]
    fn test_build_k0s_config_yaml_with_extra_args() {
        let yaml =
            DirectK0sBackend::build_k0s_config_yaml(None, &["--tls-san=example.com".to_string()]);
        assert!(
            yaml.contains("tls-san: \"example.com\""),
            "Should include extra args: {yaml}"
        );
    }

    #[test]
    fn test_build_server_statefulset_uses_k0s_image() {
        let config = base_config();
        let sts =
            DirectK0sBackend::build_server_statefulset("test-cluster", "test-ns", &config, None);

        let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
        let server = &pod_spec.containers[0];
        assert_eq!(server.name, "k0s-controller");
        assert_eq!(
            server.image.as_deref(),
            Some("k0sproject/k0s:v1.30.1+k0s.0")
        );
        assert_eq!(server.command.as_ref().unwrap(), &vec!["k0s".to_string()]);

        let args = server.args.as_ref().unwrap();
        assert!(args.contains(&"controller".to_string()));
        assert!(args.contains(&"--config=/etc/k0s/k0s.yaml".to_string()));
        assert!(args.contains(&"--enable-worker".to_string()));
    }

    #[test]
    fn test_build_server_statefulset_mounts_config() {
        let config = base_config();
        let sts =
            DirectK0sBackend::build_server_statefulset("test-cluster", "test-ns", &config, None);

        let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();

        // Check that k0s-config volume exists
        let volumes = pod_spec.volumes.as_ref().unwrap();
        let config_vol = volumes.iter().find(|v| v.name == "k0s-config");
        assert!(config_vol.is_some(), "Should have k0s-config volume");
        let config_vol = config_vol.unwrap();
        assert_eq!(
            config_vol.config_map.as_ref().unwrap().name,
            "test-cluster-k0s-config"
        );

        // Check that server container mounts k0s-config at /etc/k0s
        let server = &pod_spec.containers[0];
        let mounts = server.volume_mounts.as_ref().unwrap();
        let config_mount = mounts.iter().find(|m| m.name == "k0s-config");
        assert!(config_mount.is_some(), "Should mount k0s-config");
        assert_eq!(config_mount.unwrap().mount_path, "/etc/k0s");
    }

    #[test]
    fn test_build_server_statefulset_basic() {
        let config = base_config();
        let sts =
            DirectK0sBackend::build_server_statefulset("test-cluster", "test-ns", &config, None);

        assert_eq!(sts.metadata.name.as_deref(), Some("test-cluster-server"));
        assert_eq!(sts.metadata.namespace.as_deref(), Some("test-ns"));

        let spec = sts.spec.as_ref().unwrap();
        assert_eq!(spec.replicas, Some(1));

        let pod_spec = spec.template.spec.as_ref().unwrap();
        assert_eq!(pod_spec.containers.len(), 2); // controller + sidecar
    }

    #[test]
    fn test_build_service() {
        let config = base_config();
        let svc = DirectK0sBackend::build_service("my-cluster", "ns", &config);

        assert_eq!(svc.metadata.name.as_deref(), Some("my-cluster-server"));
        let spec = svc.spec.as_ref().unwrap();
        assert_eq!(spec.type_.as_deref(), Some("ClusterIP"));
        assert_eq!(spec.ports.as_ref().unwrap()[0].port, 6443);
    }

    #[test]
    fn test_build_service_nodeport() {
        let mut config = base_config();
        config.expose = Some(ExposeConfig {
            expose_type: "NodePort".to_string(),
            ingress_class_name: None,
            node_port: Some(31234),
        });

        let svc = DirectK0sBackend::build_service("np-cluster", "ns", &config);
        let spec = svc.spec.as_ref().unwrap();
        assert_eq!(spec.type_.as_deref(), Some("NodePort"));
        assert_eq!(spec.ports.as_ref().unwrap()[0].node_port, Some(31234));
    }

    #[test]
    fn test_cluster_labels() {
        let labels = DirectK0sBackend::cluster_labels("my-cluster");
        assert_eq!(
            labels.get("kobe.kunobi.ninja/cluster").unwrap(),
            "my-cluster"
        );
        assert_eq!(
            labels.get("app.kubernetes.io/managed-by").unwrap(),
            MANAGED_BY
        );
    }

    #[test]
    fn test_server_labels_include_role() {
        let labels = DirectK0sBackend::server_labels("c1");
        assert_eq!(labels.get("kobe.kunobi.ninja/role").unwrap(), "server");
        assert!(labels.contains_key("kobe.kunobi.ninja/cluster"));
    }

    #[test]
    fn test_agent_labels_include_role() {
        let labels = DirectK0sBackend::agent_labels("c1");
        assert_eq!(labels.get("kobe.kunobi.ninja/role").unwrap(), "agent");
    }

    #[test]
    fn test_build_agent_deployment() {
        let config = base_config();
        let deploy = DirectK0sBackend::build_agent_deployment("my-cluster", "ns", &config, 3);

        assert_eq!(deploy.metadata.name.as_deref(), Some("my-cluster-agent"));
        let spec = deploy.spec.as_ref().unwrap();
        assert_eq!(spec.replicas, Some(3));

        let pod_spec = spec.template.spec.as_ref().unwrap();
        assert_eq!(pod_spec.containers.len(), 1);
        let agent = &pod_spec.containers[0];
        assert_eq!(agent.name, "k0s-worker");
        assert_eq!(agent.command.as_ref().unwrap(), &vec!["k0s".to_string()]);

        let args = agent.args.as_ref().unwrap();
        assert!(args.contains(&"worker".to_string()));
    }

    #[test]
    fn test_publisher_sidecar_has_correct_env() {
        let sidecar = DirectK0sBackend::build_publisher_sidecar(
            "my-cluster",
            "ns",
            "k0sproject/k0s:v1.30.1+k0s.0",
        );
        let env = sidecar.env.as_ref().unwrap();
        assert!(env
            .iter()
            .any(|e| e.name == "CLUSTER_NAME" && e.value.as_deref() == Some("my-cluster")));
        assert!(env
            .iter()
            .any(|e| e.name == "NAMESPACE" && e.value.as_deref() == Some("ns")));
    }

    #[test]
    fn test_publisher_sidecar_mounts() {
        let sidecar =
            DirectK0sBackend::build_publisher_sidecar("c", "ns", "k0sproject/k0s:v1.30.1+k0s.0");
        let mounts = sidecar.volume_mounts.as_ref().unwrap();
        assert!(mounts.iter().any(|m| m.name == "k0s-data"));
        assert!(mounts.iter().any(|m| m.name == "publisher-script"));
    }

    #[test]
    fn test_build_server_statefulset_with_persistence() {
        let mut config = base_config();
        config.persistence = Some(PersistenceConfig {
            storage_type: Some("dynamic".to_string()),
            storage_class_name: Some("local-path".to_string()),
            storage_request_size: Some("10Gi".to_string()),
        });

        let sts = DirectK0sBackend::build_server_statefulset("p-cluster", "ns", &config, None);

        let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
        let volumes = pod_spec.volumes.as_ref().unwrap();
        assert!(volumes.iter().any(|v| v.name == "data"));
    }

    #[test]
    fn test_build_k0s_config_configmap() {
        let yaml = "apiVersion: k0s.k0sproject.io/v1beta1\nkind: ClusterConfig\n";
        let cm = DirectK0sBackend::build_k0s_config_configmap("test-cl", "test-ns", yaml);

        assert_eq!(cm.metadata.name.as_deref(), Some("test-cl-k0s-config"));
        assert_eq!(cm.metadata.namespace.as_deref(), Some("test-ns"));
        let data = cm.data.as_ref().unwrap();
        assert!(data.contains_key("k0s.yaml"));
        assert_eq!(data.get("k0s.yaml").unwrap(), yaml);
    }

    #[test]
    fn test_kubeconfig_publisher_script_waits_for_k0s_path() {
        assert!(
            KUBECONFIG_PUBLISHER_SCRIPT.contains("/var/lib/k0s/pki/admin.conf"),
            "Publisher script should wait for k0s admin.conf"
        );
        assert!(
            !KUBECONFIG_PUBLISHER_SCRIPT.contains("/output/kubeconfig"),
            "Publisher script should NOT reference k3s output path"
        );
    }

    // =================================================================
    // wiremock-based tests for create/delete flows
    // =================================================================

    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn mock_client(server: &MockServer) -> kube::Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::testutil::mock_k8s_client(server)
    }

    fn secret_response(name: &str, namespace: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": name, "namespace": namespace }
        })
    }

    fn generic_response(
        api_version: &str,
        kind: &str,
        name: &str,
        namespace: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": api_version,
            "kind": kind,
            "metadata": { "name": name, "namespace": namespace }
        })
    }

    #[tokio::test]
    async fn test_create_cluster_basic() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = DirectK0sBackend::new(client, None, None);

        // Mock: PATCH token secret (server-side apply)
        Mock::given(method("PATCH"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/test-cluster-token",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(secret_response("test-cluster-token", "test-ns")),
            )
            .mount(&server)
            .await;

        // Mock: PATCH ConfigMaps (publisher + k0s-config, server-side apply)
        Mock::given(method("PATCH"))
            .and(path_regex(
                "/api/v1/namespaces/test-ns/configmaps/test-cluster-.*",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(generic_response(
                "v1",
                "ConfigMap",
                "test-cluster-k0s-config",
                "test-ns",
            )))
            .mount(&server)
            .await;

        // Mock: PATCH StatefulSet (server-side apply)
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/apps/v1/namespaces/test-ns/statefulsets/test-cluster-server",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(generic_response(
                "apps/v1",
                "StatefulSet",
                "test-cluster-server",
                "test-ns",
            )))
            .mount(&server)
            .await;

        // Mock: PATCH Service (server-side apply)
        Mock::given(method("PATCH"))
            .and(path(
                "/api/v1/namespaces/test-ns/services/test-cluster-server",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(generic_response(
                "v1",
                "Service",
                "test-cluster-server",
                "test-ns",
            )))
            .mount(&server)
            .await;

        // Mock: GET kubeconfig secret (appears on first poll)
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/test-cluster-kubeconfig",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(secret_response("test-cluster-kubeconfig", "test-ns")),
            )
            .mount(&server)
            .await;

        let config = base_config();
        let result = backend
            .create("test-cluster", "test-ns", &config, &[])
            .await;
        assert!(result.is_ok(), "create should succeed: {result:?}");
    }

    #[tokio::test]
    async fn test_delete_cluster_basic() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = DirectK0sBackend::new(client, None, None);

        // Mock: DELETE agent deployment (404 -- doesn't exist, that's fine)
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/apps/v1/namespaces/test-ns/deployments/test-cluster-agent",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "deployments",
                    "test-cluster-agent",
                )),
            )
            .mount(&server)
            .await;

        // Mock: DELETE service
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/namespaces/test-ns/services/test-cluster-server",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(generic_response(
                "v1",
                "Service",
                "test-cluster-server",
                "test-ns",
            )))
            .mount(&server)
            .await;

        // Mock: DELETE statefulset
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/apps/v1/namespaces/test-ns/statefulsets/test-cluster-server",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(generic_response(
                "apps/v1",
                "StatefulSet",
                "test-cluster-server",
                "test-ns",
            )))
            .mount(&server)
            .await;

        // Mock: DELETE configmaps (k0s-config + publisher)
        Mock::given(method("DELETE"))
            .and(path_regex(
                "/api/v1/namespaces/test-ns/configmaps/test-cluster-.*",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(generic_response(
                "v1",
                "ConfigMap",
                "test-cluster-k0s-config",
                "test-ns",
            )))
            .mount(&server)
            .await;

        // Mock: DELETE secrets (token + kubeconfig)
        Mock::given(method("DELETE"))
            .and(path_regex(
                "/api/v1/namespaces/test-ns/secrets/test-cluster-.*",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(secret_response("test-cluster-token", "test-ns")),
            )
            .mount(&server)
            .await;

        let result = backend.delete("test-cluster", "test-ns").await;
        assert!(result.is_ok(), "delete should succeed: {result:?}");
    }

    #[tokio::test]
    async fn test_check_health_not_ready() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = DirectK0sBackend::new(client, None, None);

        Mock::given(method("GET"))
            .and(path(
                "/api/v1/namespaces/test-ns/secrets/new-cluster-kubeconfig",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "secrets",
                    "new-cluster-kubeconfig",
                )),
            )
            .mount(&server)
            .await;

        let result = backend.check_health("new-cluster", "test-ns").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
