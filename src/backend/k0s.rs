//! K0s backend — manages k0s clusters via StatefulSets, without external operators.
//!
//! Instead of relying on any third-party operator, this backend directly creates
//! the Kubernetes resources needed to run k0s:
//!
//! - A **token Secret** for inter-node authentication
//! - A **k0s.yaml ConfigMap** with cluster configuration (including datastore settings)
//! - A **server StatefulSet** running `k0s controller --enable-worker`
//! - A **kubeconfig-publisher sidecar** that reads the generated admin
//!   kubeconfig and publishes the `{name}-kubeconfig` Secret via `kube-rs`
//! - A **ClusterIP Service** exposing port 6443
//! - Optionally, an **agent Deployment** running `k0s worker`
//!
//! When a shared PostgreSQL datastore is configured, the k0s.yaml spec sets
//! `spec.storage.type: kine` with a PostgreSQL dataSource, instead of the
//! default etcd backend.

use anyhow::{Context, Result};
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, StatefulSet, StatefulSetSpec};
use k8s_openapi::api::core::v1::{
    Affinity, ConfigMap, Container, EnvVar, Event as K8sEvent, KeyToPath, Pod, PodAffinity,
    PodAffinityTerm, PodSpec, PodTemplateSpec, Secret, SecretVolumeSource, Service, ServicePort,
    ServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::Client;
use kube::api::{Api, DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PropagationPolicy};
use sqlx::PgPool;
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

use crate::crd::{Addon, ClusterConfig, NodePlacement, NodePlacementMode, ReadinessGate};

use super::{
    ClusterBackend, apply_addon_impl, check_readiness_gate_impl, check_virtual_health, datastore,
    read_kubeconfig_secret, virtual_client_from_kubeconfig,
};

/// Database name prefix for k0s clusters.
pub const DB_PREFIX: &str = "k0s_";

/// Labels applied to all resources managed by this backend.
const MANAGED_BY: &str = "kobe-operator";
const DEFAULT_K0S_POD_CIDR: &str = "10.248.0.0/16";
const DEFAULT_K0S_SERVICE_CIDR: &str = "10.128.0.0/16";

/// Default kubelet `--cluster-domain` value used by every mainstream
/// distro. Mirrors the k3s backend's constant.
const DEFAULT_CLUSTER_DOMAIN: &str = "cluster.local";

/// Convert a k0s semver version to a valid Docker image reference.
///
/// k0s releases use `+` for build metadata (e.g. `v1.30.1+k0s.0`), but `+` is
/// illegal in OCI image tags. Published images use `-` instead
/// (e.g. `k0sproject/k0s:v1.30.1-k0s.0`).
fn k0s_image(version: &str) -> String {
    format!("k0sproject/k0s:{}", version.replace('+', "-"))
}

/// Direct k0s backend -- manages k0s clusters via raw Kubernetes resources.
#[derive(Clone)]
pub struct K0sBackend {
    /// Kubernetes client for the host cluster.
    client: Client,
    /// Optional PostgreSQL connection pool for shared datastore.
    pg_pool: Option<PgPool>,
    /// Base PostgreSQL connection URL (before per-cluster DB rewriting).
    pg_base_url: Option<String>,
}

impl K0sBackend {
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
    ///
    /// `sans` populates `spec.api.sans` — the additional DNS names / IPs
    /// embedded as Subject Alternative Names on the apiserver TLS cert.
    /// Production paths MUST include the host-cluster Service DNS
    /// (`<name>-server.<namespace>.svc`) here, otherwise any client
    /// dialing the cluster via that hostname (e.g. the chart-shipped
    /// flux bootstrap Job) gets `x509: certificate is valid for ... not
    /// <service-dns>` and the bootstrap fails before it can install
    /// anything. The k3s backend solves the same problem inline via
    /// `--tls-san=...`; k0s reads its SAN list from the YAML config
    /// instead, which is why this is a separate parameter rather than
    /// being smuggled into `extra_args` (a `tls-san` key under
    /// `extraArgs` would be passed to kube-apiserver as a flag, where
    /// it does not exist — the k0s wrapper only honours
    /// `spec.api.sans`).
    ///
    /// `network` carries the operator-allocated service + cluster
    /// CIDRs from `pool::cidr_alloc`. `None` falls back to the
    /// standalone defaults below — covers test paths and CLI builds
    /// that bypass the reconciler. Production paths always pass an
    /// allocated network so two leased k0s pool members never share
    /// service CIDRs (see the same regression note in the k3s backend
    /// for the CoreDNS-vs-host-iptables collision rationale).
    pub fn build_k0s_config_yaml(
        datastore_endpoint: Option<&str>,
        extra_args: &[String],
        sans: &[String],
        network: Option<&crate::crd::ClusterInstanceNetwork>,
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

        // `spec.api` holds both `sans` (Subject Alternative Names on the
        // apiserver TLS cert) and `extraArgs` (kube-apiserver flags).
        // Emit a single `api:` block when either is non-empty so the
        // YAML stays valid k0s ClusterConfig.
        let api_section = if sans.is_empty() && extra_args.is_empty() {
            String::new()
        } else {
            let mut section = String::from("  api:\n");
            if !sans.is_empty() {
                section.push_str("    sans:\n");
                for san in sans {
                    section.push_str(&format!("      - {san}\n"));
                }
            }
            if !extra_args.is_empty() {
                section.push_str("    extraArgs:\n");
                for arg in extra_args {
                    // Parse --key=value format
                    let stripped = arg.strip_prefix("--").unwrap_or(arg);
                    if let Some((key, value)) = stripped.split_once('=') {
                        section.push_str(&format!("      {key}: \"{value}\"\n"));
                    }
                }
            }
            section
        };

        let (pod_cidr, service_cidr) = match network {
            Some(n) => (n.cluster_cidr.clone(), n.service_cidr.clone()),
            None => (
                DEFAULT_K0S_POD_CIDR.to_string(),
                DEFAULT_K0S_SERVICE_CIDR.to_string(),
            ),
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
    podCIDR: {pod_cidr}
    serviceCIDR: {service_cidr}
    provider: kuberouter
"#
        );

        if !api_section.is_empty() {
            yaml.push_str(&api_section);
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

    /// Create the ConfigMap containing the k0s.yaml cluster configuration.
    /// Build the apiserver TLS SAN list emitted into `spec.api.sans`.
    /// Includes both the short Service form and the FQDN so existing
    /// clients dialing either form keep working.
    fn build_api_sans(name: &str, namespace: &str, cluster_domain: &str) -> Vec<String> {
        vec![
            format!("{name}-server.{namespace}.svc"),
            format!("{name}-server.{namespace}.svc.{cluster_domain}"),
        ]
    }

    async fn create_k0s_config_configmap(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        datastore_endpoint: Option<&str>,
    ) -> Result<()> {
        // The chart-shipped flux bootstrap Job (and any in-cluster
        // client that dials the host-side Service for this k0s pool
        // member) connects to `<name>-server.<namespace>.svc:6443` or
        // its FQDN. The apiserver TLS cert MUST list both forms — k0s
        // only emits the generic kubernetes.* + localhost names by
        // default, so the bootstrap pod's TLS verify fails with
        // `x509: certificate is valid for kubernetes, ...
        // kubernetes.svc.cluster.local, localhost, not
        // <name>-server.<namespace>.svc`. The k3s backend solves this
        // inline (see `--tls-san=` in `build_server_container`); for
        // k0s the equivalent is `spec.api.sans` in the ClusterConfig
        // YAML.
        //
        // The FQDN form is what the published kubeconfig uses (avoids
        // the musl `search`-domain bug — see
        // `ClusterConfig::cluster_domain`).
        let api_sans = Self::build_api_sans(
            name,
            namespace,
            config
                .cluster_domain
                .as_deref()
                .unwrap_or(DEFAULT_CLUSTER_DOMAIN),
        );
        let config_yaml = Self::build_k0s_config_yaml(
            datastore_endpoint,
            &config.server_args,
            &api_sans,
            config.allocated_network.as_ref(),
        );
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
        let image = k0s_image(&config.version);

        let mut args = vec![
            "controller".to_string(),
            format!("--config=/etc/k0s/k0s.yaml"),
            "--enable-worker".to_string(),
        ];
        if config.servers > 1 {
            args.push("--token-file=/var/lib/k0s/token/token".to_string());
        }

        // Honor `cluster.taints`. When the field is set we take full control:
        // pass `--no-taints` to suppress the default master taint, then add
        // one `--taints=<key:effect>` per entry. Per-flag form mirrors k3s'
        // `--node-taint` shape and is forward-safe against any future
        // pflag StringSliceVar → StringArrayVar migration in upstream k0s
        // (StringSlice splits on commas; StringArray does not). When the
        // field is None we leave the default behaviour (master taint
        // applied) untouched so existing pools are unaffected.
        if let Some(taints) = &config.taints {
            args.push("--no-taints".to_string());
            for taint in taints {
                args.push(format!("--taints={}", taint.to_kubelet_arg()));
            }
        }

        let mut volume_mounts = vec![
            VolumeMount {
                name: "k0s-config".to_string(),
                mount_path: "/etc/k0s/k0s.yaml".to_string(),
                read_only: Some(true),
                sub_path: Some("k0s.yaml".to_string()),
                ..Default::default()
            },
            VolumeMount {
                name: "k0s-data".to_string(),
                mount_path: "/var/lib/k0s".to_string(),
                ..Default::default()
            },
        ];

        if config.servers > 1 {
            volume_mounts.insert(
                0,
                VolumeMount {
                    name: "token".to_string(),
                    mount_path: "/var/lib/k0s/token".to_string(),
                    read_only: Some(true),
                    ..Default::default()
                },
            );
        }

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
                tcp_socket: Some(k8s_openapi::api::core::v1::TCPSocketAction {
                    port: IntOrString::Int(6443),
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
    fn build_publisher_sidecar(name: &str, namespace: &str, cluster_domain: &str) -> Container {
        let image = std::env::var("KUBECONFIG_PUBLISHER_IMAGE")
            .unwrap_or_else(|_| "zondax/kobe-operator:latest".to_string());

        Container {
            name: "kubeconfig-publisher".to_string(),
            image: Some(image),
            command: Some(vec!["/kubeconfig-publisher".to_string()]),
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
                EnvVar {
                    name: "CLUSTER_DOMAIN".to_string(),
                    value: Some(cluster_domain.to_string()),
                    ..Default::default()
                },
                EnvVar {
                    name: "KUBECONFIG_PATH".to_string(),
                    value: Some("/var/lib/k0s/pki/admin.conf".to_string()),
                    ..Default::default()
                },
                EnvVar {
                    name: "RUST_LOG".to_string(),
                    value: Some(
                        std::env::var("RUST_LOG")
                            .unwrap_or_else(|_| "kubeconfig_publisher=info".to_string()),
                    ),
                    ..Default::default()
                },
            ]),
            volume_mounts: Some(vec![VolumeMount {
                name: "k0s-data".to_string(),
                mount_path: "/var/lib/k0s".to_string(),
                read_only: Some(true),
                ..Default::default()
            }]),
            ..Default::default()
        }
    }

    /// Build the volumes list for the server pod.
    fn build_server_volumes(name: &str, config: &ClusterConfig) -> Vec<Volume> {
        let mut volumes = vec![
            // k0s config ConfigMap mount
            Volume {
                name: "k0s-config".to_string(),
                config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                    name: format!("{name}-k0s-config"),
                    ..Default::default()
                }),
                ..Default::default()
            },
            // Shared k0s data volume
            Volume {
                name: "k0s-data".to_string(),
                empty_dir: Some(k8s_openapi::api::core::v1::EmptyDirVolumeSource {
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];

        if config.servers > 1 {
            volumes.insert(
                0,
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
            );
        }

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
        let labels = Self::server_labels(name);

        // Build the k0s.yaml so the ConfigMap is consistent but note: the
        // actual ConfigMap is created separately. The StatefulSet just mounts it.
        let _ = datastore_endpoint; // used to select kine vs etcd in the config

        let server_container = Self::build_server_container(name, namespace, config);
        let publisher_sidecar = Self::build_publisher_sidecar(
            name,
            namespace,
            config
                .cluster_domain
                .as_deref()
                .unwrap_or(DEFAULT_CLUSTER_DOMAIN),
        );
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
                            std::env::var("POOL_PUBLISHER_SERVICE_ACCOUNT")
                                .or_else(|_| std::env::var("POOL_SERVICE_ACCOUNT"))
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

    /// Build the agent pod affinity based on the configured placement.
    /// Returns `None` for `Any` (default) so the rendered Deployment stays
    /// byte-identical to clusters predating this field.
    fn agent_affinity(name: &str, placement: Option<&NodePlacement>) -> Option<Affinity> {
        let mode = placement.map(|p| p.mode).unwrap_or_default();
        match mode {
            NodePlacementMode::Any => None,
            NodePlacementMode::SameHost => Some(Affinity {
                pod_affinity: Some(PodAffinity {
                    required_during_scheduling_ignored_during_execution: Some(vec![
                        PodAffinityTerm {
                            label_selector: Some(LabelSelector {
                                match_labels: Some(Self::server_labels(name)),
                                ..Default::default()
                            }),
                            topology_key: "kubernetes.io/hostname".to_string(),
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }
    }

    /// Build the agent Deployment.
    fn build_agent_deployment(
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        replicas: u32,
    ) -> Deployment {
        let k0s_image = k0s_image(&config.version);
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
                        affinity: Self::agent_affinity(name, config.node_placement.as_ref()),
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

    /// Wait for the kubeconfig Secret to appear (created by the publisher sidecar).
    async fn wait_ready(&self, name: &str, namespace: &str) -> Result<()> {
        info!(cluster = name, "Waiting for k0s cluster kubeconfig");

        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let secret_name = format!("{name}-kubeconfig");

        // Poll every 5s for up to 10 minutes
        for attempt in 0..120 {
            match secrets.get(&secret_name).await {
                Ok(_) => {
                    info!(
                        cluster = name,
                        attempts = attempt + 1,
                        "k0s cluster kubeconfig secret found"
                    );
                    return Ok(());
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    if attempt % 6 == 0 {
                        info!(
                            cluster = name,
                            attempt = attempt + 1,
                            elapsed_seconds = attempt * 5,
                            "Waiting for k0s cluster kubeconfig"
                        );
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                Err(e) => {
                    return Err(e).context(format!("Error checking k0s cluster {name} readiness"));
                }
            }
        }

        let pod_summary = self
            .summarize_server_pod(name, namespace)
            .await
            .unwrap_or_else(|e| format!("unavailable ({e})"));
        let event_summary = self
            .summarize_server_pod_events(name, namespace)
            .await
            .unwrap_or_else(|e| format!("unavailable ({e})"));

        warn!(
            cluster = name,
            pod = %pod_summary,
            events = %event_summary,
            "k0s cluster readiness timed out"
        );

        anyhow::bail!(
            "k0s cluster {name} not ready after 10 minutes; pod: {pod_summary}; events: {event_summary}"
        );
    }

    async fn summarize_server_pod(&self, name: &str, namespace: &str) -> Result<String> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let pod_name = format!("{name}-server-0");
        let pod = pods
            .get(&pod_name)
            .await
            .with_context(|| format!("Failed to get server pod {pod_name}"))?;

        let phase = pod
            .status
            .as_ref()
            .and_then(|s| s.phase.as_deref())
            .unwrap_or("Unknown");

        let mut container_states = Vec::new();
        if let Some(statuses) = pod
            .status
            .as_ref()
            .and_then(|s| s.container_statuses.as_ref())
        {
            for status in statuses {
                let state = status
                    .state
                    .as_ref()
                    .and_then(|state| {
                        state
                            .waiting
                            .as_ref()
                            .map(|waiting| {
                                format!("waiting:{}", waiting.reason.as_deref().unwrap_or("-"))
                            })
                            .or_else(|| state.running.as_ref().map(|_| "running".to_string()))
                            .or_else(|| {
                                state.terminated.as_ref().map(|terminated| {
                                    format!(
                                        "terminated:{}",
                                        terminated.reason.as_deref().unwrap_or("-")
                                    )
                                })
                            })
                    })
                    .unwrap_or_else(|| "unknown".to_string());
                container_states.push(format!("{}={} image={}", status.name, state, status.image));
            }
        }

        Ok(format!(
            "{} phase={} {}",
            pod_name,
            phase,
            container_states.join(", ")
        ))
    }

    async fn summarize_server_pod_events(&self, name: &str, namespace: &str) -> Result<String> {
        let events: Api<K8sEvent> = Api::namespaced(self.client.clone(), namespace);
        let pod_name = format!("{name}-server-0");
        let items = events
            .list(&ListParams::default())
            .await
            .context("Failed to list pod events")?;

        let mut matches: Vec<String> = items
            .into_iter()
            .filter(|event| {
                event
                    .involved_object
                    .name
                    .as_deref()
                    .map(|involved| involved == pod_name)
                    .unwrap_or(false)
            })
            .map(|event| {
                format!(
                    "{}:{}",
                    event.reason.unwrap_or_else(|| "-".to_string()),
                    event.message.unwrap_or_else(|| "-".to_string())
                )
            })
            .collect();

        if matches.is_empty() {
            return Ok("no matching pod events".to_string());
        }

        matches.truncate(3);
        Ok(matches.join(" | "))
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
        let dp = DeleteParams {
            propagation_policy: Some(PropagationPolicy::Foreground),
            ..DeleteParams::default()
        };
        match api.delete(name, &dp).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn wait_deleted<K>(api: &Api<K>, name: &str) -> Result<()>
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
        for _ in 0..60 {
            match api.get_opt(name).await {
                Ok(None) => return Ok(()),
                Ok(Some(_)) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
                Err(kube::Error::Api(ae)) if ae.code == 404 => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        }

        anyhow::bail!("resource {name} was not deleted within 60 seconds")
    }
}

impl ClusterBackend for K0sBackend {
    #[tracing::instrument(skip(self, config, addons), fields(cluster = name, namespace))]
    async fn create(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        addons: &[Addon],
    ) -> Result<()> {
        info!(
            cluster = name,
            version = %config.version,
            image = %k0s_image(&config.version),
            "Creating k0s cluster"
        );

        // 1. Create token secret
        self.create_token_secret(name, namespace).await?;

        // 2. If PostgreSQL configured, create per-cluster database
        let datastore_endpoint =
            if let (Some(pool), Some(base_url)) = (&self.pg_pool, &self.pg_base_url) {
                datastore::create_database(pool, name, DB_PREFIX).await?;
                let endpoint = datastore::cluster_endpoint(base_url, name, DB_PREFIX)?;
                Some(endpoint)
            } else {
                None
            };

        // 3. Create k0s config ConfigMap
        self.create_k0s_config_configmap(name, namespace, config, datastore_endpoint.as_deref())
            .await?;

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

        // 6. Read kubeconfig from the server pod and publish Secret from the operator
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

        info!(cluster = name, "k0s cluster fully ready with addons");
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(cluster = name, namespace))]
    async fn delete(&self, name: &str, namespace: &str) -> Result<()> {
        info!(cluster = name, "Deleting k0s cluster");

        // Delete agent Deployment
        let deploy_api: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&deploy_api, &format!("{name}-agent")).await?;

        // Delete Service
        let svc_api: Api<Service> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&svc_api, &format!("{name}-server")).await?;

        // Delete server StatefulSet
        let sts_api: Api<StatefulSet> = Api::namespaced(self.client.clone(), namespace);
        let sts_name = format!("{name}-server");
        Self::delete_ignoring_not_found(&sts_api, &sts_name).await?;
        Self::wait_deleted(&sts_api, &sts_name).await?;

        // Delete k0s config ConfigMap
        let cms: Api<ConfigMap> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&cms, &format!("{name}-k0s-config")).await?;

        // Delete secrets: token and kubeconfig
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&secrets, &format!("{name}-token")).await?;
        Self::delete_ignoring_not_found(&secrets, &format!("{name}-kubeconfig")).await?;

        // Drop database if PostgreSQL is configured
        if let Some(pool) = &self.pg_pool
            && let Err(e) = datastore::drop_database(pool, name, DB_PREFIX).await
        {
            warn!(cluster = name, error = %e, "Failed to drop database (may not exist)");
        }

        info!(cluster = name, "k0s cluster deleted");
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(cluster = name, namespace))]
    async fn check_health(&self, name: &str, namespace: &str) -> Result<bool> {
        check_virtual_health(&self.client, name, namespace).await
    }

    async fn extract_kubeconfig(&self, name: &str, namespace: &str) -> Result<String> {
        info!(cluster = name, "Extracting kubeconfig from k0s secret");
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
            taints: None,
            ..Default::default()
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
    fn test_k0s_image_replaces_plus_with_hyphen() {
        assert_eq!(k0s_image("v1.30.1+k0s.0"), "k0sproject/k0s:v1.30.1-k0s.0");
    }

    #[test]
    fn test_k0s_image_preserves_hyphen_tags() {
        assert_eq!(k0s_image("v1.30.1-k0s.0"), "k0sproject/k0s:v1.30.1-k0s.0");
    }

    #[test]
    fn test_build_k0s_config_yaml_no_pg() {
        let yaml = K0sBackend::build_k0s_config_yaml(None, &[], &[], None);
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
        assert!(yaml.contains("podCIDR: 10.248.0.0/16"));
        assert!(yaml.contains("serviceCIDR: 10.128.0.0/16"));
        assert!(yaml.contains("provider: kuberouter"));
    }

    #[test]
    fn test_build_k0s_config_yaml_with_pg() {
        let yaml = K0sBackend::build_k0s_config_yaml(
            Some("postgres://user:pass@pg:5432/k0s_my_cluster"),
            &[],
            &[],
            None,
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
        let yaml = K0sBackend::build_k0s_config_yaml(
            None,
            &["--tls-san=example.com".to_string()],
            &[],
            None,
        );
        assert!(
            yaml.contains("tls-san: \"example.com\""),
            "Should include extra args: {yaml}"
        );
    }

    /// Regression: when `sans` is non-empty, the YAML must contain
    /// `spec.api.sans` listing each entry. Without this, the chart-
    /// shipped flux bootstrap Job (and any other in-cluster client
    /// dialing the host-side Service for the pool member) gets
    /// `x509: certificate is valid for kubernetes, ... not
    /// <name>-server.<namespace>.svc` and the bootstrap fails before
    /// any flux component is installed.
    #[test]
    fn test_build_k0s_config_yaml_emits_sans() {
        let yaml = K0sBackend::build_k0s_config_yaml(
            None,
            &[],
            &["pool-foo-server.kobe-system.svc".to_string()],
            None,
        );
        assert!(
            yaml.contains("api:"),
            "yaml must include spec.api block when sans is non-empty: {yaml}"
        );
        assert!(
            yaml.contains("    sans:"),
            "yaml must include spec.api.sans key: {yaml}"
        );
        assert!(
            yaml.contains("- pool-foo-server.kobe-system.svc"),
            "yaml must list the service DNS as a SAN entry: {yaml}"
        );
    }

    /// Regression: `sans` and `extra_args` must coexist under a single
    /// `spec.api:` block. A naive implementation that emits two
    /// separate `api:` keys produces invalid YAML where the second
    /// silently overrides the first, dropping the SANs.
    #[test]
    fn test_build_k0s_config_yaml_sans_and_extra_args_coexist() {
        let yaml = K0sBackend::build_k0s_config_yaml(
            None,
            &["--service-node-port-range=30000-32767".to_string()],
            &["pool-bar-server.kobe-system.svc".to_string()],
            None,
        );
        let api_count = yaml.matches("\n  api:\n").count();
        assert_eq!(
            api_count, 1,
            "spec.api: block must appear exactly once even when both sans and extraArgs are set; got {api_count} occurrences in: {yaml}"
        );
        assert!(
            yaml.contains("    sans:"),
            "sans must appear under api: {yaml}"
        );
        assert!(
            yaml.contains("- pool-bar-server.kobe-system.svc"),
            "service DNS must appear in sans list: {yaml}"
        );
        assert!(
            yaml.contains("    extraArgs:"),
            "extraArgs must appear under api: {yaml}"
        );
        assert!(
            yaml.contains("service-node-port-range: \"30000-32767\""),
            "extra arg must be parsed into extraArgs map: {yaml}"
        );
    }

    /// Invariant: the production path that builds the k0s ConfigMap
    /// (the one applied to the host cluster for every pool member)
    /// MUST always include both the short and FQDN forms of the host-
    /// side Service DNS in `spec.api.sans`. Mirrors how the k3s backend
    /// hard-codes both `--tls-san=...svc` and `--tls-san=...svc.{domain}`
    /// inline; the test exists so a refactor that drops either entry
    /// never re-introduces the silent flux-bootstrap failure mode
    /// (issue surfaced via `ci-k0s-flux` triage pool, April 2026).
    #[test]
    fn test_k0s_configmap_always_includes_service_dns_san() {
        let cluster_name = "pool-ci-k0s-flux-42";
        let namespace = "kobe-system";
        let expected_short = format!("{cluster_name}-server.{namespace}.svc");
        let expected_fqdn = format!("{expected_short}.cluster.local");

        // Mirror exactly what `create_k0s_config_configmap` builds.
        let api_sans = K0sBackend::build_api_sans(cluster_name, namespace, "cluster.local");
        let yaml = K0sBackend::build_k0s_config_yaml(None, &[], &api_sans, None);
        let cm = K0sBackend::build_k0s_config_configmap(cluster_name, namespace, &yaml);

        let stored = cm
            .data
            .as_ref()
            .and_then(|d| d.get("k0s.yaml"))
            .expect("ConfigMap must contain k0s.yaml key");
        assert!(
            stored.contains(&format!("- {expected_short}")),
            "k0s ConfigMap MUST embed `{expected_short}` as a SAN; otherwise flux bootstrap fails TLS verify. Got:\n{stored}"
        );
        assert!(
            stored.contains(&format!("- {expected_fqdn}")),
            "k0s ConfigMap MUST embed FQDN `{expected_fqdn}` as a SAN — needed by the published kubeconfig (which uses the FQDN to dodge the musl `search`-domain bug). Got:\n{stored}"
        );
    }

    /// Custom `clusterDomain` flows through to the SAN list, so an
    /// operator running on a non-default cluster (e.g.
    /// `--cluster-domain=internal.example`) still gets a cert valid
    /// for the kubeconfig's FQDN.
    #[test]
    fn test_build_api_sans_honors_custom_cluster_domain() {
        let sans = K0sBackend::build_api_sans("c", "ns", "internal.example");
        assert_eq!(sans.len(), 2);
        assert!(sans.contains(&"c-server.ns.svc".to_string()));
        assert!(sans.contains(&"c-server.ns.svc.internal.example".to_string()));
    }

    /// Regression: when the operator allocates a network slot, the
    /// k0s.yaml template MUST emit those CIDRs verbatim instead of
    /// falling back to the standalone defaults. Same rationale as the
    /// k3s backend's analogous test (see comments there).
    #[test]
    fn test_build_k0s_config_yaml_honors_allocated_network() {
        use crate::crd::ClusterInstanceNetwork;
        let net = ClusterInstanceNetwork {
            service_cidr: "10.245.32.0/20".to_string(),
            cluster_cidr: "10.253.32.0/20".to_string(),
        };
        let yaml = K0sBackend::build_k0s_config_yaml(None, &[], &[], Some(&net));
        assert!(
            yaml.contains("podCIDR: 10.253.32.0/20"),
            "must use allocated cluster_cidr; got: {yaml}"
        );
        assert!(
            yaml.contains("serviceCIDR: 10.245.32.0/20"),
            "must use allocated service_cidr; got: {yaml}"
        );
        assert!(
            !yaml.contains("10.248.0.0/16") && !yaml.contains("10.128.0.0/16"),
            "default CIDRs must NOT appear when allocator provided values; got: {yaml}"
        );
    }

    #[test]
    fn test_taints_field_omitted_keeps_default_master_taint() {
        // Default (taints: None) must not pass --no-taints / --taints, so the
        // k0s default master taint stays applied. Backwards-compatible.
        let config = base_config();
        let sts = K0sBackend::build_server_statefulset("test-cluster", "test-ns", &config, None);
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
        assert!(!args.iter().any(|a| a == "--no-taints"));
        assert!(!args.iter().any(|a| a.starts_with("--taints=")));
    }

    #[test]
    fn test_taints_empty_list_suppresses_default_master_taint() {
        let mut config = base_config();
        config.taints = Some(vec![]);
        let sts = K0sBackend::build_server_statefulset("test-cluster", "test-ns", &config, None);
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
        assert!(args.iter().any(|a| a == "--no-taints"));
        assert!(!args.iter().any(|a| a.starts_with("--taints=")));
    }

    #[test]
    fn test_taints_populated_list_renders_kubelet_args() {
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
        let sts = K0sBackend::build_server_statefulset("test-cluster", "test-ns", &config, None);
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
        assert!(args.iter().any(|a| a == "--no-taints"));
        // One --taints flag per entry (per-flag form, not comma-list).
        let taints_args: Vec<&String> =
            args.iter().filter(|a| a.starts_with("--taints=")).collect();
        assert_eq!(
            taints_args.len(),
            2,
            "expected one --taints flag per entry, got {taints_args:?}"
        );
        assert!(
            taints_args
                .iter()
                .any(|a| *a == "--taints=dedicated=gpu:NoSchedule")
        );
        // Value-less taint must render as `key:effect` (no `=`); the
        // `key=:effect` form is invalid kubelet syntax.
        assert!(
            taints_args
                .iter()
                .any(|a| *a == "--taints=drain-pending:NoExecute")
        );
    }

    #[test]
    fn test_build_server_statefulset_uses_k0s_image() {
        let config = base_config();
        let sts = K0sBackend::build_server_statefulset("test-cluster", "test-ns", &config, None);

        let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
        let server = &pod_spec.containers[0];
        assert_eq!(server.name, "k0s-controller");
        assert_eq!(
            server.image.as_deref(),
            Some("k0sproject/k0s:v1.30.1-k0s.0")
        );
        assert_eq!(server.command.as_ref().unwrap(), &vec!["k0s".to_string()]);

        let args = server.args.as_ref().unwrap();
        assert!(args.contains(&"controller".to_string()));
        assert!(args.contains(&"--config=/etc/k0s/k0s.yaml".to_string()));
        assert!(args.contains(&"--enable-worker".to_string()));
        assert!(!args.iter().any(|arg| arg.contains("--token-file=")));
    }

    #[test]
    fn test_multi_server_statefulset_enables_worker_and_token() {
        let mut config = base_config();
        config.servers = 3;
        let sts = K0sBackend::build_server_statefulset("test-cluster", "test-ns", &config, None);

        let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
        let server = &pod_spec.containers[0];
        let args = server.args.as_ref().unwrap();
        let mounts = server.volume_mounts.as_ref().unwrap();
        let volumes = pod_spec.volumes.as_ref().unwrap();

        assert!(args.contains(&"--enable-worker".to_string()));
        assert!(
            args.iter()
                .any(|arg| arg == "--token-file=/var/lib/k0s/token/token")
        );
        assert!(mounts.iter().any(|mount| mount.name == "token"));
        assert!(volumes.iter().any(|volume| volume.name == "token"));
    }

    #[test]
    fn test_build_server_statefulset_mounts_config() {
        let config = base_config();
        let sts = K0sBackend::build_server_statefulset("test-cluster", "test-ns", &config, None);

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

        // Check that server container mounts only the config file so /etc/k0s stays writable.
        let server = &pod_spec.containers[0];
        let mounts = server.volume_mounts.as_ref().unwrap();
        let config_mount = mounts.iter().find(|m| m.name == "k0s-config");
        assert!(config_mount.is_some(), "Should mount k0s-config");
        let config_mount = config_mount.unwrap();
        assert_eq!(config_mount.mount_path, "/etc/k0s/k0s.yaml");
        assert_eq!(config_mount.sub_path.as_deref(), Some("k0s.yaml"));
        assert!(config_mount.read_only.unwrap_or(false));
    }

    #[test]
    fn test_build_server_statefulset_basic() {
        let config = base_config();
        let sts = K0sBackend::build_server_statefulset("test-cluster", "test-ns", &config, None);

        assert_eq!(sts.metadata.name.as_deref(), Some("test-cluster-server"));
        assert_eq!(sts.metadata.namespace.as_deref(), Some("test-ns"));

        let spec = sts.spec.as_ref().unwrap();
        assert_eq!(spec.replicas, Some(1));

        let pod_spec = spec.template.spec.as_ref().unwrap();
        assert_eq!(pod_spec.containers.len(), 2);
    }

    #[test]
    fn test_build_service() {
        let config = base_config();
        let svc = K0sBackend::build_service("my-cluster", "ns", &config);

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

        let svc = K0sBackend::build_service("np-cluster", "ns", &config);
        let spec = svc.spec.as_ref().unwrap();
        assert_eq!(spec.type_.as_deref(), Some("NodePort"));
        assert_eq!(spec.ports.as_ref().unwrap()[0].node_port, Some(31234));
    }

    #[test]
    fn test_cluster_labels() {
        let labels = K0sBackend::cluster_labels("my-cluster");
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
        let labels = K0sBackend::server_labels("c1");
        assert_eq!(labels.get("kobe.kunobi.ninja/role").unwrap(), "server");
        assert!(labels.contains_key("kobe.kunobi.ninja/cluster"));
    }

    #[test]
    fn test_agent_labels_include_role() {
        let labels = K0sBackend::agent_labels("c1");
        assert_eq!(labels.get("kobe.kunobi.ninja/role").unwrap(), "agent");
    }

    #[test]
    fn test_build_agent_deployment() {
        let config = base_config();
        let deploy = K0sBackend::build_agent_deployment("my-cluster", "ns", &config, 3);

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

        // Default placement is Any → no affinity rendered, so the manifest
        // stays byte-identical for clusters that predate this field.
        assert!(pod_spec.affinity.is_none());
    }

    #[test]
    fn test_build_agent_deployment_same_host_placement() {
        let config = ClusterConfig {
            node_placement: Some(NodePlacement {
                mode: NodePlacementMode::SameHost,
            }),
            ..base_config()
        };
        let deploy = K0sBackend::build_agent_deployment("my-cluster", "ns", &config, 1);

        let pod_spec = deploy
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap();
        let affinity = pod_spec.affinity.as_ref().expect("affinity present");
        let pod_aff = affinity
            .pod_affinity
            .as_ref()
            .expect("pod_affinity present");
        let terms = pod_aff
            .required_during_scheduling_ignored_during_execution
            .as_ref()
            .expect("required terms present");
        assert_eq!(terms.len(), 1);

        let term = &terms[0];
        assert_eq!(term.topology_key, "kubernetes.io/hostname");
        let match_labels = term
            .label_selector
            .as_ref()
            .unwrap()
            .match_labels
            .as_ref()
            .unwrap();
        assert_eq!(
            match_labels.get("kobe.kunobi.ninja/cluster"),
            Some(&"my-cluster".to_string())
        );
        assert_eq!(
            match_labels.get("kobe.kunobi.ninja/role"),
            Some(&"server".to_string())
        );

        // Pod-anti-affinity stays unset — we only constrain co-location, not separation.
        assert!(affinity.pod_anti_affinity.is_none());
        assert!(affinity.node_affinity.is_none());
    }

    #[test]
    fn test_build_agent_deployment_explicit_any_placement_renders_no_affinity() {
        // Explicit `Any` should be indistinguishable from omitting the field.
        let config = ClusterConfig {
            node_placement: Some(NodePlacement {
                mode: NodePlacementMode::Any,
            }),
            ..base_config()
        };
        let deploy = K0sBackend::build_agent_deployment("c", "ns", &config, 1);
        let pod_spec = deploy.spec.unwrap().template.spec.unwrap();
        assert!(pod_spec.affinity.is_none());
    }

    #[test]
    fn test_publisher_sidecar_has_correct_env_and_mounts() {
        let sidecar = K0sBackend::build_publisher_sidecar("my-cluster", "ns", "cluster.local");
        let env = sidecar.env.as_ref().unwrap();
        let mounts = sidecar.volume_mounts.as_ref().unwrap();

        assert_eq!(sidecar.name, "kubeconfig-publisher");
        assert_eq!(
            sidecar.command.as_ref().unwrap(),
            &vec!["/kubeconfig-publisher".to_string()]
        );
        assert!(
            env.iter()
                .any(|e| e.name == "CLUSTER_NAME" && e.value.as_deref() == Some("my-cluster"))
        );
        assert!(
            env.iter()
                .any(|e| e.name == "NAMESPACE" && e.value.as_deref() == Some("ns"))
        );
        assert!(
            env.iter()
                .any(|e| e.name == "CLUSTER_DOMAIN" && e.value.as_deref() == Some("cluster.local"))
        );
        assert!(env.iter().any(|e| {
            e.name == "KUBECONFIG_PATH" && e.value.as_deref() == Some("/var/lib/k0s/pki/admin.conf")
        }));
        assert!(mounts.iter().any(|m| m.name == "k0s-data"));
    }

    #[test]
    fn test_build_server_statefulset_with_persistence() {
        let mut config = base_config();
        config.persistence = Some(PersistenceConfig {
            storage_type: Some("dynamic".to_string()),
            storage_class_name: Some("local-path".to_string()),
            storage_request_size: Some("10Gi".to_string()),
        });

        let sts = K0sBackend::build_server_statefulset("p-cluster", "ns", &config, None);

        let pod_spec = sts.spec.as_ref().unwrap().template.spec.as_ref().unwrap();
        let volumes = pod_spec.volumes.as_ref().unwrap();
        assert!(volumes.iter().any(|v| v.name == "data"));
    }

    #[test]
    fn test_build_k0s_config_configmap() {
        let yaml = "apiVersion: k0s.k0sproject.io/v1beta1\nkind: ClusterConfig\n";
        let cm = K0sBackend::build_k0s_config_configmap("test-cl", "test-ns", yaml);

        assert_eq!(cm.metadata.name.as_deref(), Some("test-cl-k0s-config"));
        assert_eq!(cm.metadata.namespace.as_deref(), Some("test-ns"));
        let data = cm.data.as_ref().unwrap();
        assert!(data.contains_key("k0s.yaml"));
        assert_eq!(data.get("k0s.yaml").unwrap(), yaml);
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
        let backend = K0sBackend::new(client, None, None);

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
        let backend = K0sBackend::new(client, None, None);

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
        let backend = K0sBackend::new(client, None, None);

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
