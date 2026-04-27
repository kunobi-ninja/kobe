//! K3s backend — manages k3s clusters via StatefulSets.
//!
//! This backend directly creates the Kubernetes resources needed to run k3s:
//!
//! - A **token Secret** for inter-node authentication
//! - A **server StatefulSet** running `k3s server`
//! - A **kubeconfig-publisher sidecar** that creates the `{name}-kubeconfig` Secret
//! - A **ClusterIP Service** exposing port 6443
//! - Optionally, an **agent Deployment** running `k3s agent`
//!
//! When a shared PostgreSQL datastore is configured, k3s uses
//! `--datastore-endpoint=postgres://...` instead of embedded SQLite, enabling
//! golden image creation via `CREATE DATABASE ... TEMPLATE`.

use anyhow::{Context, Result};
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, StatefulSet, StatefulSetSpec};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, EnvVar, KeyToPath, PodSpec, PodTemplateSpec, Secret, SecretVolumeSource,
    Service, ServicePort, ServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::Client;
use kube::api::{Api, DeleteParams, ObjectMeta, Patch, PatchParams};
use sqlx::PgPool;
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

use crate::crd::{Addon, ClusterConfig, ReadinessGate};

use super::{
    ClusterBackend, apply_addon_impl, check_readiness_gate_impl, check_virtual_health, datastore,
    read_kubeconfig_secret, virtual_client_from_kubeconfig,
};

/// Labels applied to all resources managed by this backend.
const MANAGED_BY: &str = "kobe-operator";

/// Convert a k3s semver version to a valid Docker image reference.
///
/// k3s releases use `+` for build metadata (e.g. `v1.31.3+k3s1`), but `+` is
/// illegal in OCI image tags. Docker Hub publishes the same images with `-`
/// instead (e.g. `rancher/k3s:v1.31.3-k3s1`).
fn k3s_image(version: &str) -> String {
    format!("rancher/k3s:{}", version.replace('+', "-"))
}

/// The kubeconfig publisher sidecar script, mounted from a ConfigMap.
///
/// Waits for k3s to write the kubeconfig, rewrites the server URL to the
/// ClusterIP Service address, and creates/updates a Kubernetes Secret.
const KUBECONFIG_PUBLISHER_SCRIPT: &str = r#"#!/bin/sh
set -e
echo "Waiting for kubeconfig to appear..."
while [ ! -f /output/kubeconfig ]; do sleep 1; done
echo "Kubeconfig found, rewriting server URL..."
sed -i "s|https://127.0.0.1:6443|https://${CLUSTER_NAME}-server.${NAMESPACE}.svc:6443|" /output/kubeconfig
echo "Publishing kubeconfig as Secret..."
kubectl create secret generic ${CLUSTER_NAME}-kubeconfig \
  --from-file=kubeconfig=/output/kubeconfig \
  --namespace=${NAMESPACE} \
  -o yaml --dry-run=client | kubectl apply -f -
echo "Kubeconfig Secret published, sleeping..."
sleep infinity
"#;

/// Direct k3s backend — manages k3s clusters via raw Kubernetes resources.
#[derive(Clone)]
pub struct K3sBackend {
    /// Kubernetes client for the host cluster.
    client: Client,
    /// Optional PostgreSQL connection pool for shared datastore.
    pg_pool: Option<PgPool>,
    /// Base PostgreSQL connection URL (before per-cluster DB rewriting).
    pg_base_url: Option<String>,
}

impl K3sBackend {
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

    /// Generate a random token for k3s node authentication.
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

    /// Create the token Secret for k3s node authentication.
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

    /// Build the k3s server container.
    fn build_server_container(
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        datastore_endpoint: Option<&str>,
    ) -> Container {
        let image = k3s_image(&config.version);

        let mut args = vec![
            "server".to_string(),
            format!("--tls-san={name}-server.{namespace}.svc"),
            "--token-file=/var/lib/k3s/token/token".to_string(),
            "--write-kubeconfig=/output/kubeconfig".to_string(),
            "--write-kubeconfig-mode=644".to_string(),
        ];

        if let Some(endpoint) = datastore_endpoint {
            args.push(format!("--datastore-endpoint={endpoint}"));
        }

        // Honor `cluster.taints`. k3s does NOT add a master taint by default,
        // so we only need to act when the caller specified non-empty taints.
        // An empty list and an absent field are equivalent for k3s. Each taint
        // becomes its own `--node-taint key=value:effect` flag.
        if let Some(taints) = &config.taints
            && !taints.is_empty()
        {
            for taint in taints {
                args.push(format!("--node-taint={}", taint.to_kubelet_arg()));
            }
        }

        // Append user-specified server args
        args.extend(config.server_args.iter().cloned());

        let mut volume_mounts = vec![
            VolumeMount {
                name: "token".to_string(),
                mount_path: "/var/lib/k3s/token".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "output".to_string(),
                mount_path: "/output".to_string(),
                ..Default::default()
            },
        ];

        // If persistence is configured, mount data volume
        if config.persistence.is_some() {
            volume_mounts.push(VolumeMount {
                name: "data".to_string(),
                mount_path: "/var/lib/rancher/k3s".to_string(),
                ..Default::default()
            });
        }

        Container {
            name: "k3s-server".to_string(),
            image: Some(image),
            command: Some(vec!["k3s".to_string()]),
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
                    path: Some("/cacerts".to_string()),
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
    fn build_publisher_sidecar(name: &str, namespace: &str, k3s_image: &str) -> Container {
        Container {
            name: "kubeconfig-publisher".to_string(),
            image: Some(k3s_image.to_string()),
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
                    name: "output".to_string(),
                    mount_path: "/output".to_string(),
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
            // Shared output volume (kubeconfig exchange between server and sidecar)
            Volume {
                name: "output".to_string(),
                empty_dir: Some(k8s_openapi::api::core::v1::EmptyDirVolumeSource {
                    medium: Some("Memory".to_string()),
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

        // Data volume — PVC if persistence is configured, otherwise emptyDir
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
        let image = k3s_image(&config.version);
        let labels = Self::server_labels(name);

        let server_container =
            Self::build_server_container(name, namespace, config, datastore_endpoint);
        let publisher_sidecar = Self::build_publisher_sidecar(name, namespace, &image);
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

    /// Build the ClusterIP Service for the k3s API server.
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
        let image = k3s_image(&config.version);
        let labels = Self::agent_labels(name);

        let container = Container {
            name: "k3s-agent".to_string(),
            image: Some(image),
            command: Some(vec!["k3s".to_string()]),
            args: Some(vec![
                "agent".to_string(),
                format!("--server=https://{name}-server.{namespace}.svc:6443"),
                "--token-file=/var/lib/k3s/token/token".to_string(),
            ]),
            volume_mounts: Some(vec![VolumeMount {
                name: "token".to_string(),
                mount_path: "/var/lib/k3s/token".to_string(),
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
        debug!(cluster = name, "Waiting for k3s cluster to become ready");

        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let secret_name = format!("{name}-kubeconfig");

        // Poll every 5s for up to 10 minutes
        for attempt in 0..120 {
            match secrets.get(&secret_name).await {
                Ok(_) => {
                    info!(
                        cluster = name,
                        attempts = attempt + 1,
                        "k3s cluster kubeconfig secret found"
                    );
                    return Ok(());
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    if attempt % 12 == 0 {
                        debug!(
                            cluster = name,
                            attempt = attempt + 1,
                            "Waiting for k3s cluster kubeconfig..."
                        );
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                Err(e) => {
                    return Err(e).context(format!("Error checking k3s cluster {name} readiness"));
                }
            }
        }

        anyhow::bail!("k3s cluster {name} not ready after 10 minutes");
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

impl ClusterBackend for K3sBackend {
    #[tracing::instrument(skip(self, config, addons), fields(cluster = name, namespace))]
    async fn create(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        addons: &[Addon],
    ) -> Result<()> {
        info!(cluster = name, "Creating k3s cluster");

        // 1. Create token secret
        self.create_token_secret(name, namespace).await?;

        // 2. Create publisher ConfigMap
        self.create_publisher_configmap(name, namespace).await?;

        // 3. If PostgreSQL configured, create per-cluster database
        let datastore_endpoint =
            if let (Some(pool), Some(base_url)) = (&self.pg_pool, &self.pg_base_url) {
                datastore::create_database(pool, name, "k3s_").await?;
                let endpoint = datastore::cluster_endpoint(base_url, name, "k3s_")?;
                Some(endpoint)
            } else {
                None
            };

        // 4. Create server StatefulSet
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

        // 5. Create Service
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

        // 6. Wait for kubeconfig Secret (created by sidecar)
        self.wait_ready(name, namespace).await?;

        // 7. Create agent Deployment if requested
        if let Some(agents) = config.agents
            && agents > 0
        {
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

        // 8. Apply addons
        for addon in addons {
            self.apply_addon(name, namespace, addon).await?;
        }

        info!(cluster = name, "k3s cluster fully ready with addons");
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(cluster = name, namespace))]
    async fn delete(&self, name: &str, namespace: &str) -> Result<()> {
        info!(cluster = name, "Deleting k3s cluster");

        // Delete agent Deployment
        let deploy_api: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&deploy_api, &format!("{name}-agent")).await?;

        // Delete Service
        let svc_api: Api<Service> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&svc_api, &format!("{name}-server")).await?;

        // Delete server StatefulSet
        let sts_api: Api<StatefulSet> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&sts_api, &format!("{name}-server")).await?;

        // Delete publisher ConfigMap
        let cms: Api<ConfigMap> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&cms, &format!("{name}-kubeconfig-publisher")).await?;

        // Delete secrets: token and kubeconfig
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&secrets, &format!("{name}-token")).await?;
        Self::delete_ignoring_not_found(&secrets, &format!("{name}-kubeconfig")).await?;

        // Drop database if PostgreSQL is configured
        if let Some(pool) = &self.pg_pool
            && let Err(e) = datastore::drop_database(pool, name, "k3s_").await
        {
            warn!(cluster = name, error = %e, "Failed to drop database (may not exist)");
        }

        info!(cluster = name, "k3s cluster deleted");
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(cluster = name, namespace))]
    async fn check_health(&self, name: &str, namespace: &str) -> Result<bool> {
        check_virtual_health(&self.client, name, namespace).await
    }

    async fn extract_kubeconfig(&self, name: &str, namespace: &str) -> Result<String> {
        info!(cluster = name, "Extracting kubeconfig from k3s secret");
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
            version: "v1.31.3+k3s1".to_string(),
            servers: 1,
            agents: None,
            server_args: vec![],
            persistence: None,
            expose: None,
            taints: None,
        }
    }

    // =================================================================
    // Pure function tests for resource builders
    // =================================================================

    #[test]
    fn test_build_server_statefulset_basic() {
        let config = base_config();
        let sts = K3sBackend::build_server_statefulset("test-cluster", "test-ns", &config, None);

        assert_eq!(sts.metadata.name.as_deref(), Some("test-cluster-server"));
        assert_eq!(sts.metadata.namespace.as_deref(), Some("test-ns"));

        let spec = sts.spec.as_ref().unwrap();
        assert_eq!(spec.replicas, Some(1));

        let pod_spec = spec.template.spec.as_ref().unwrap();
        assert_eq!(pod_spec.containers.len(), 2); // server + sidecar

        let server = &pod_spec.containers[0];
        assert_eq!(server.name, "k3s-server");
        assert_eq!(server.image.as_deref(), Some("rancher/k3s:v1.31.3-k3s1"));

        // Verify no datastore-endpoint arg
        let args = server.args.as_ref().unwrap();
        assert!(!args.iter().any(|a| a.contains("datastore-endpoint")));
    }

    #[test]
    fn test_build_server_statefulset_with_pg() {
        let config = base_config();
        let sts = K3sBackend::build_server_statefulset(
            "pg-cluster",
            "ns",
            &config,
            Some("postgres://user:pass@pg:5432/k3s_pg_cluster"),
        );

        let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
        let server = &pod_spec.containers[0];
        let args = server.args.as_ref().unwrap();
        assert!(
            args.iter()
                .any(|a| a == "--datastore-endpoint=postgres://user:pass@pg:5432/k3s_pg_cluster")
        );
    }

    #[test]
    fn test_build_server_statefulset_with_persistence() {
        let mut config = base_config();
        config.persistence = Some(PersistenceConfig {
            storage_type: Some("dynamic".to_string()),
            storage_class_name: Some("local-path".to_string()),
            storage_request_size: Some("10Gi".to_string()),
        });

        let sts = K3sBackend::build_server_statefulset("p-cluster", "ns", &config, None);

        let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
        let volumes = pod_spec.volumes.as_ref().unwrap();
        assert!(volumes.iter().any(|v| v.name == "data"));

        let server = &pod_spec.containers[0];
        let mounts = server.volume_mounts.as_ref().unwrap();
        assert!(mounts.iter().any(|m| m.name == "data"));
    }

    #[test]
    fn test_build_server_statefulset_custom_args() {
        let mut config = base_config();
        config.server_args = vec![
            "--disable=traefik".to_string(),
            "--flannel-backend=none".to_string(),
        ];

        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None);

        let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
        let server = &pod_spec.containers[0];
        let args = server.args.as_ref().unwrap();
        assert!(args.contains(&"--disable=traefik".to_string()));
        assert!(args.contains(&"--flannel-backend=none".to_string()));
    }

    #[test]
    fn test_taints_field_omitted_no_node_taint_args() {
        // Default (taints: None) keeps k3s's no-taint default — must not
        // emit any --node-taint flags. Backwards-compatible.
        let config = base_config();
        let sts = K3sBackend::build_server_statefulset("test", "ns", &config, None);
        let args = sts
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers[0]
            .args
            .as_ref()
            .unwrap();
        assert!(!args.iter().any(|a| a.starts_with("--node-taint")));
    }

    #[test]
    fn test_taints_empty_list_no_node_taint_args() {
        // k3s does not apply a master taint by default, so an empty list
        // is semantically equivalent to omission — no flags emitted.
        let mut config = base_config();
        config.taints = Some(vec![]);
        let sts = K3sBackend::build_server_statefulset("test", "ns", &config, None);
        let args = sts
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers[0]
            .args
            .as_ref()
            .unwrap();
        assert!(!args.iter().any(|a| a.starts_with("--node-taint")));
    }

    #[test]
    fn test_taints_populated_list_renders_node_taint_args() {
        use crate::crd::{NodeTaint, TaintEffect};
        let mut config = base_config();
        config.taints = Some(vec![
            NodeTaint {
                key: "dedicated".to_string(),
                value: Some("gpu".to_string()),
                effect: TaintEffect::NoSchedule,
            },
            NodeTaint {
                key: "drain-pending".to_string(),
                value: None,
                effect: TaintEffect::NoExecute,
            },
        ]);
        let sts = K3sBackend::build_server_statefulset("test", "ns", &config, None);
        let args = sts
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers[0]
            .args
            .as_ref()
            .unwrap();
        let taint_args: Vec<&String> = args
            .iter()
            .filter(|a| a.starts_with("--node-taint="))
            .collect();
        assert_eq!(
            taint_args.len(),
            2,
            "expected one --node-taint flag per entry, got {taint_args:?}"
        );
        assert!(
            taint_args
                .iter()
                .any(|a| *a == "--node-taint=dedicated=gpu:NoSchedule")
        );
        // Value-less taint must render as `key:effect` (no `=`).
        assert!(
            taint_args
                .iter()
                .any(|a| *a == "--node-taint=drain-pending:NoExecute")
        );
    }

    #[test]
    fn test_build_service_clusterip() {
        let config = base_config();
        let svc = K3sBackend::build_service("my-cluster", "ns", &config);

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

        let svc = K3sBackend::build_service("np-cluster", "ns", &config);
        let spec = svc.spec.as_ref().unwrap();
        assert_eq!(spec.type_.as_deref(), Some("NodePort"));
        assert_eq!(spec.ports.as_ref().unwrap()[0].node_port, Some(31234));
    }

    #[test]
    fn test_build_agent_deployment() {
        let config = base_config();
        let deploy = K3sBackend::build_agent_deployment("my-cluster", "ns", &config, 3);

        assert_eq!(deploy.metadata.name.as_deref(), Some("my-cluster-agent"));
        let spec = deploy.spec.as_ref().unwrap();
        assert_eq!(spec.replicas, Some(3));

        let pod_spec = spec.template.spec.as_ref().unwrap();
        assert_eq!(pod_spec.containers.len(), 1);
        let agent = &pod_spec.containers[0];
        assert_eq!(agent.name, "k3s-agent");

        let args = agent.args.as_ref().unwrap();
        assert!(
            args.iter()
                .any(|a| a == "--server=https://my-cluster-server.ns.svc:6443")
        );
    }

    #[test]
    fn test_cluster_labels() {
        let labels = K3sBackend::cluster_labels("my-cluster");
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
        let labels = K3sBackend::server_labels("c1");
        assert_eq!(labels.get("kobe.kunobi.ninja/role").unwrap(), "server");
        assert!(labels.contains_key("kobe.kunobi.ninja/cluster"));
    }

    #[test]
    fn test_agent_labels_include_role() {
        let labels = K3sBackend::agent_labels("c1");
        assert_eq!(labels.get("kobe.kunobi.ninja/role").unwrap(), "agent");
    }

    #[test]
    fn test_publisher_sidecar_has_correct_env() {
        let sidecar =
            K3sBackend::build_publisher_sidecar("my-cluster", "ns", "rancher/k3s:v1.31.3+k3s1");
        let env = sidecar.env.as_ref().unwrap();
        assert!(
            env.iter()
                .any(|e| e.name == "CLUSTER_NAME" && e.value.as_deref() == Some("my-cluster"))
        );
        assert!(
            env.iter()
                .any(|e| e.name == "NAMESPACE" && e.value.as_deref() == Some("ns"))
        );
    }

    #[test]
    fn test_publisher_sidecar_mounts() {
        let sidecar = K3sBackend::build_publisher_sidecar("c", "ns", "rancher/k3s:v1.31.3+k3s1");
        let mounts = sidecar.volume_mounts.as_ref().unwrap();
        assert!(mounts.iter().any(|m| m.name == "output"));
        assert!(mounts.iter().any(|m| m.name == "publisher-script"));
    }

    #[test]
    fn test_k3s_image_replaces_plus_with_hyphen() {
        assert_eq!(k3s_image("v1.31.3+k3s1"), "rancher/k3s:v1.31.3-k3s1");
    }

    #[test]
    fn test_k3s_image_preserves_hyphen_tags() {
        assert_eq!(k3s_image("v1.31.3-k3s1"), "rancher/k3s:v1.31.3-k3s1");
    }

    #[test]
    fn test_liveness_probe_uses_cacerts() {
        let config = base_config();
        let container = K3sBackend::build_server_container("test", "ns", &config, None);
        let probe = container.liveness_probe.as_ref().unwrap();
        let http = probe.http_get.as_ref().unwrap();
        assert_eq!(http.path.as_deref(), Some("/cacerts"));
        assert_eq!(http.scheme.as_deref(), Some("HTTPS"));
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
        let backend = K3sBackend::new(client, None, None);

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

        // Mock: PATCH publisher ConfigMap
        Mock::given(method("PATCH"))
            .and(path(
                "/api/v1/namespaces/test-ns/configmaps/test-cluster-kubeconfig-publisher",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(generic_response(
                "v1",
                "ConfigMap",
                "test-cluster-kubeconfig-publisher",
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
        let backend = K3sBackend::new(client, None, None);

        // Mock: DELETE agent deployment (404 — doesn't exist, that's fine)
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

        // Mock: DELETE configmap
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v1/namespaces/test-ns/configmaps/test-cluster-kubeconfig-publisher",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(generic_response(
                "v1",
                "ConfigMap",
                "test-cluster-kubeconfig-publisher",
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
        let backend = K3sBackend::new(client, None, None);

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
