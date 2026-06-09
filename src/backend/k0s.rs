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
    ServiceSpec, Toleration, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::Client;
use kube::api::{Api, DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PropagationPolicy};
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

use crate::crd::{Addon, ClusterConfig, IntraPlacementMode, Placement, ReadinessGate};

use super::{
    ClusterBackend, apply_addon_impl, check_readiness_gate_impl, check_virtual_health,
    data_volume_claim_template, datastore, node_affinity_from_selector, read_kubeconfig_secret,
    server_anti_affinity_terms, virtual_client_from_kubeconfig,
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
    /// Optional shared PostgreSQL datastore (pool + base URL), hot-reloadable
    /// when the credential rotates.
    datastore: crate::backend::datastore::SharedDatastore,
}

impl K0sBackend {
    pub fn new(client: Client, datastore: crate::backend::datastore::SharedDatastore) -> Self {
        Self { client, datastore }
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
    ///
    /// When `pool_name` is `Some`, also stamps
    /// `kobe.kunobi.ninja/pool=<name>` so the inter-instance spread
    /// anti-affinity selector can scope to siblings of the same pool.
    /// Standalone instances pass `None`.
    fn cluster_labels(name: &str, pool_name: Option<&str>) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        labels.insert("kobe.kunobi.ninja/cluster".to_string(), name.to_string());
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            MANAGED_BY.to_string(),
        );
        if let Some(p) = pool_name {
            labels.insert("kobe.kunobi.ninja/pool".to_string(), p.to_string());
        }
        labels
    }

    /// Labels for server pods specifically.
    fn server_labels(name: &str, pool_name: Option<&str>) -> BTreeMap<String, String> {
        let mut labels = Self::cluster_labels(name, pool_name);
        labels.insert("kobe.kunobi.ninja/role".to_string(), "server".to_string());
        labels
    }

    /// Labels for agent pods specifically.
    fn agent_labels(name: &str, pool_name: Option<&str>) -> BTreeMap<String, String> {
        let mut labels = Self::cluster_labels(name, pool_name);
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
                labels: Some(Self::cluster_labels(name, None)),
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
                labels: Some(Self::cluster_labels(name, None)),
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

        // Persistence is handled by backing the existing `k0s-data` volume
        // (mounted above at k0s's real data dir `/var/lib/k0s`) with a PVC via
        // the StatefulSet's volumeClaimTemplates — see `build_server_volumes`
        // and `build_server_statefulset`. The previous code mounted a separate
        // `data` volume at `/var/lib/k0s/data`, a subdir k0s never writes to, so
        // persistence was a no-op. No extra mount is needed here.

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
            // Honors `ClusterPool.spec.resources`, matching the k3s backend.
            // Without this the field was silently dropped on k0s server pods,
            // leaving them with no requests/limits — the scheduler over-packs
            // the node and the controller flaps under bootstrap load (#92).
            resources: config.resources.as_ref().and_then(|r| r.to_k8s()),
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
    ///
    /// The `k0s-data` volume (mounted at k0s's real data dir `/var/lib/k0s`) is
    /// an `emptyDir` only when persistence is NOT configured. When persistence
    /// IS configured it is omitted here and provided instead as a per-replica
    /// PVC via the StatefulSet's `volumeClaimTemplates` (a pod-level volume of
    /// the same name would shadow the claim template).
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
        ];

        // Shared k0s data volume. Without persistence it's an emptyDir (legacy
        // behavior, unchanged); with persistence it's backed by a PVC declared
        // in volumeClaimTemplates and therefore not listed as a pod volume.
        if config.persistence.is_none() {
            volumes.push(Volume {
                name: "k0s-data".to_string(),
                empty_dir: Some(k8s_openapi::api::core::v1::EmptyDirVolumeSource {
                    ..Default::default()
                }),
                ..Default::default()
            });
        }

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

        volumes
    }

    /// Build the server StatefulSet.
    fn build_server_statefulset(
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        datastore_endpoint: Option<&str>,
    ) -> StatefulSet {
        let pool = config.pool_name.as_deref();
        let labels = Self::server_labels(name, pool);

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

        // When persistence is configured, back the `k0s-data` volume (mounted at
        // k0s's real data dir `/var/lib/k0s`) with a per-replica PVC via
        // `volumeClaimTemplates` instead of an emptyDir, so control-plane state
        // survives reschedules. `None` ⇒ no template (`k0s-data` stays emptyDir).
        let volume_claim_templates = config
            .persistence
            .as_ref()
            .map(|p| vec![data_volume_claim_template("k0s-data", p)]);

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
                        affinity: Self::server_affinity(config.placement.as_ref(), pool),
                        tolerations: Self::pod_tolerations(config.placement.as_ref()),
                        volumes: Some(volumes),
                        service_account_name: Some(
                            std::env::var("POOL_PUBLISHER_SERVICE_ACCOUNT")
                                .or_else(|_| std::env::var("POOL_SERVICE_ACCOUNT"))
                                .unwrap_or_else(|_| "kobe-operator".to_string()),
                        ),
                        ..Default::default()
                    }),
                },
                volume_claim_templates,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Build the ClusterIP Service for the k0s API server.
    fn build_service(name: &str, namespace: &str, config: &ClusterConfig) -> Service {
        let pool = config.pool_name.as_deref();
        let labels = Self::server_labels(name, pool);

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
                labels: Some(Self::cluster_labels(name, pool)),
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

    /// Build the server pod affinity block from [`Placement`]:
    /// `nodeAffinity` + `podAntiAffinity` for inter-instance spread.
    fn server_affinity(placement: Option<&Placement>, pool_name: Option<&str>) -> Option<Affinity> {
        let p = placement?;
        let node_affinity =
            node_affinity_from_selector(p.node.as_ref().and_then(|n| n.selector.as_ref()));
        let pod_anti_affinity = server_anti_affinity_terms(
            p.inter_instance.as_ref().and_then(|i| i.spread.as_ref()),
            pool_name,
        );
        if node_affinity.is_none() && pod_anti_affinity.is_none() {
            return None;
        }
        Some(Affinity {
            node_affinity,
            pod_anti_affinity,
            ..Default::default()
        })
    }

    /// Build the agent pod affinity block from [`Placement`]:
    /// `nodeAffinity` + intra-instance `podAffinity` when mode is
    /// `SameHost`.
    fn agent_affinity(
        name: &str,
        placement: Option<&Placement>,
        pool_name: Option<&str>,
    ) -> Option<Affinity> {
        let p = placement?;
        let node_affinity =
            node_affinity_from_selector(p.node.as_ref().and_then(|n| n.selector.as_ref()));
        let intra_mode = p
            .intra_instance
            .as_ref()
            .map(|i| i.mode)
            .unwrap_or_default();
        let pod_affinity = match intra_mode {
            IntraPlacementMode::Any => None,
            IntraPlacementMode::SameHost => Some(PodAffinity {
                required_during_scheduling_ignored_during_execution: Some(vec![PodAffinityTerm {
                    label_selector: Some(LabelSelector {
                        match_labels: Some(Self::server_labels(name, pool_name)),
                        ..Default::default()
                    }),
                    topology_key: "kubernetes.io/hostname".to_string(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        };
        if node_affinity.is_none() && pod_affinity.is_none() {
            return None;
        }
        Some(Affinity {
            node_affinity,
            pod_affinity,
            ..Default::default()
        })
    }

    /// Tolerations to stamp on every pod the backend creates. See the
    /// mirror in k3s.rs for the rationale on `None` vs empty.
    fn pod_tolerations(placement: Option<&Placement>) -> Option<Vec<Toleration>> {
        let tols = placement?.node.as_ref().map(|n| &n.tolerations)?;
        if tols.is_empty() {
            None
        } else {
            Some(tols.clone())
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
        let pool = config.pool_name.as_deref();
        let labels = Self::agent_labels(name, pool);

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
                        affinity: Self::agent_affinity(name, config.placement.as_ref(), pool),
                        tolerations: Self::pod_tolerations(config.placement.as_ref()),
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

    /// Opportunistic force-delete of pods carrying
    /// `kobe.kunobi.ninja/cluster=<cluster_name>`.
    ///
    /// Called at the end of [`K0sBackend::delete`] after all controller
    /// objects (STS / Deployment / Service / Secret / ConfigMap) have been
    /// removed.  This covers the normal recycle path where a pod's kubelet
    /// would eventually finalize the delete on its own but hasn't had the
    /// chance yet.  For pods that are *stuck* because the inner kubelet left
    /// Bidirectional bind-mounts on the host, force-delete is a no-op at the
    /// apiserver; the `kobe-host-reaper` DaemonSet handles that case by
    /// unmounting the host paths first.
    ///
    /// All errors are non-fatal:
    /// - 404 on an individual pod → `debug!` + continue (inherent race: a
    ///   concurrent kubelet or operator may delete a pod between our `list()`
    ///   and the per-pod `delete()`).
    /// - Other per-pod errors → `warn!` + continue.
    /// - `list()` itself fails → `warn!` + return early.
    ///
    /// Note: pods created after our `list()` (e.g. mid-teardown of the
    /// StatefulSet) will be missed; this is acceptable because all controller
    /// objects are already deleted by this point.
    async fn force_delete_instance_pods(pods: &Api<Pod>, cluster_name: &str) {
        let lp = ListParams::default().labels(&format!("kobe.kunobi.ninja/cluster={cluster_name}"));
        let pod_list = match pods.list(&lp).await {
            Ok(list) => list,
            Err(e) => {
                warn!(
                    cluster = cluster_name,
                    error = %e,
                    "failed to list pods for force-delete (non-fatal)"
                );
                return;
            }
        };

        let dp = DeleteParams {
            grace_period_seconds: Some(0),
            propagation_policy: Some(PropagationPolicy::Background),
            ..DeleteParams::default()
        };

        for pod in pod_list.items {
            let name = pod.metadata.name.as_deref().unwrap_or("<unnamed>");
            match pods.delete(name, &dp).await {
                Ok(_) => {
                    debug!(cluster = cluster_name, pod = name, "force-deleted pod");
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => {
                    debug!(
                        cluster = cluster_name,
                        pod = name,
                        "pod already gone (404), skipping"
                    );
                }
                Err(e) => {
                    warn!(
                        cluster = cluster_name,
                        pod = name,
                        error = %e,
                        "failed to force-delete pod (non-fatal)"
                    );
                }
            }
        }
    }
}

impl ClusterBackend for K0sBackend {
    #[tracing::instrument(skip(self, config, addons, _owner_ref), fields(cluster = name, namespace))]
    async fn create(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        addons: &[Addon],
        // k0s pool members are owned via labels + explicit cleanup;
        // see VkobeBackend::create for where the OwnerRef is consumed.
        _owner_ref: Option<&k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference>,
    ) -> Result<()> {
        info!(
            cluster = name,
            version = %config.version,
            image = %k0s_image(&config.version),
            "Creating k0s cluster"
        );

        // Multi-server HA is not actually implemented: the StatefulSet is
        // hardcoded to a single replica and no real k0s join token is
        // generated, so `servers > 1` would only make the sole controller
        // pass `--token-file` and try to join a nonexistent cluster — it
        // never goes Ready and create() times out after 10 minutes. Reject
        // it up front with a clear error instead of silently hanging.
        if config.servers > 1 {
            anyhow::bail!(
                "k0s HA (servers>1) is not yet implemented in this backend: the control-plane StatefulSet is single-replica and the generated join token does not satisfy k0s per-controller join. HA requires a shared external datastore (kine/PostgreSQL) AND per-controller join tokens; use the k3s backend for HA today. Got servers={}.",
                config.servers
            );
        }

        // 1. Create token secret
        self.create_token_secret(name, namespace).await?;

        // 2. If PostgreSQL configured, create per-cluster database. Read the
        // current connection each time so a rotated credential is picked up.
        let datastore_endpoint = if let Some((pool, base_url)) = self.datastore.current() {
            datastore::create_database(&pool, name, DB_PREFIX).await?;
            let endpoint = datastore::cluster_endpoint(&base_url, name, DB_PREFIX)?;
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
        if let Some((pool, _)) = self.datastore.current()
            && let Err(e) = datastore::drop_database(&pool, name, DB_PREFIX).await
        {
            warn!(cluster = name, error = %e, "Failed to drop database (may not exist)");
        }

        // Force-delete any leftover pods carrying our cluster label.
        // See doc-comment on force_delete_instance_pods for rationale.
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        Self::force_delete_instance_pods(&pods, name).await;

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
        check_readiness_gate_impl(&vc_client, gate, name).await
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
        let labels = K0sBackend::cluster_labels("my-cluster", None);
        assert_eq!(
            labels.get("kobe.kunobi.ninja/cluster").unwrap(),
            "my-cluster"
        );
        assert_eq!(
            labels.get("app.kubernetes.io/managed-by").unwrap(),
            MANAGED_BY
        );
        assert!(
            !labels.contains_key("kobe.kunobi.ninja/pool"),
            "pool label must be absent when pool_name is None (standalone case)"
        );
    }

    /// Regression: same pool-scoping rationale as `k3s::test_cluster_labels_stamps_pool_when_set`.
    #[test]
    fn test_cluster_labels_stamps_pool_when_set() {
        let labels = K0sBackend::cluster_labels("pool-ci-k0s-flux-7", Some("ci-k0s-flux"));
        assert_eq!(labels.get("kobe.kunobi.ninja/pool").unwrap(), "ci-k0s-flux");
    }

    #[test]
    fn test_server_labels_include_role() {
        let labels = K0sBackend::server_labels("c1", None);
        assert_eq!(labels.get("kobe.kunobi.ninja/role").unwrap(), "server");
        assert!(labels.contains_key("kobe.kunobi.ninja/cluster"));
    }

    #[test]
    fn test_agent_labels_include_role() {
        let labels = K0sBackend::agent_labels("c1", None);
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

    /// `intraInstance.mode: SameHost` renders a required agent
    /// podAffinity onto the server pod's host (k0s).
    #[test]
    fn test_build_agent_deployment_same_host_placement() {
        use crate::crd::{IntraInstancePlacement, IntraPlacementMode, Placement};
        let placement = Placement {
            intra_instance: Some(IntraInstancePlacement {
                mode: IntraPlacementMode::SameHost,
            }),
            ..Default::default()
        };
        let config = ClusterConfig {
            placement: Some(placement),
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

    /// Explicit `intraInstance.mode: Any` (the default) stays
    /// indistinguishable from omitting the field — no affinity rendered.
    #[test]
    fn test_build_agent_deployment_explicit_any_placement_renders_no_affinity() {
        use crate::crd::{IntraInstancePlacement, IntraPlacementMode, Placement};
        let placement = Placement {
            intra_instance: Some(IntraInstancePlacement {
                mode: IntraPlacementMode::Any,
            }),
            ..Default::default()
        };
        let config = ClusterConfig {
            placement: Some(placement),
            ..base_config()
        };
        let deploy = K0sBackend::build_agent_deployment("c", "ns", &config, 1);
        let pod_spec = deploy.spec.unwrap().template.spec.unwrap();
        assert!(pod_spec.affinity.is_none());
    }

    // ─────────────────────────────────────────────────────────────────
    // Placement API — additional coverage (selector, tolerations,
    // inter-instance spread on k0s server)
    // ─────────────────────────────────────────────────────────────────

    fn config_with_placement(placement: crate::crd::Placement) -> ClusterConfig {
        ClusterConfig {
            placement: Some(placement),
            ..base_config()
        }
    }

    // #92: a k0s pool that sets `spec.resources` must stamp requests/limits onto
    // the controller container. The field was previously dropped, leaving server
    // pods unbounded and prone to flapping when the node is over-packed under
    // bootstrap load — matching the k3s backend, which already propagates it.
    #[test]
    fn test_build_server_container_propagates_resources_k0s() {
        use crate::crd::ResourceRequirements;
        use k8s_openapi::apimachinery::pkg::api::resource::Quantity;

        let mut config = base_config();
        config.resources = Some(ResourceRequirements {
            limits: [("cpu".to_string(), "1".to_string())].into(),
            requests: [("memory".to_string(), "512Mi".to_string())].into(),
        });

        let container = K0sBackend::build_server_container("c", "ns", &config);
        let r = container
            .resources
            .as_ref()
            .expect("k0s controller container must carry resources when the pool sets them");
        assert_eq!(
            r.limits.as_ref().unwrap().get("cpu"),
            Some(&Quantity("1".to_string())),
        );
        assert_eq!(
            r.requests.as_ref().unwrap().get("memory"),
            Some(&Quantity("512Mi".to_string())),
        );
    }

    #[test]
    fn test_placement_node_selector_renders_node_affinity_on_server_and_agent_k0s() {
        use crate::crd::{NodePlacement as NewNodePlacement, Placement};
        let mut labels = BTreeMap::new();
        labels.insert(
            "topology.kubernetes.io/zone".to_string(),
            "eu-west-1b".to_string(),
        );
        let placement = Placement {
            node: Some(NewNodePlacement {
                selector: Some(LabelSelector {
                    match_labels: Some(labels),
                    ..Default::default()
                }),
                tolerations: Vec::new(),
            }),
            ..Default::default()
        };
        let config = config_with_placement(placement);

        let sts = K0sBackend::build_server_statefulset("c", "ns", &config, None);
        let pod = sts.spec.unwrap().template.spec.unwrap();
        let na = pod
            .affinity
            .expect("affinity present")
            .node_affinity
            .expect("node_affinity present");
        let term = &na
            .required_during_scheduling_ignored_during_execution
            .unwrap()
            .node_selector_terms[0];
        let reqs = term.match_expressions.as_ref().unwrap();
        assert_eq!(reqs[0].key, "topology.kubernetes.io/zone");

        let deploy = K0sBackend::build_agent_deployment("c", "ns", &config, 1);
        let pod = deploy.spec.unwrap().template.spec.unwrap();
        assert!(pod.affinity.unwrap().node_affinity.is_some());
    }

    #[test]
    fn test_placement_node_tolerations_propagate_to_server_and_agent_k0s() {
        use crate::crd::{NodePlacement as NewNodePlacement, Placement};
        let tol = Toleration {
            key: Some("spot".to_string()),
            operator: Some("Exists".to_string()),
            effect: Some("NoSchedule".to_string()),
            ..Default::default()
        };
        let placement = Placement {
            node: Some(NewNodePlacement {
                selector: None,
                tolerations: vec![tol],
            }),
            ..Default::default()
        };
        let config = config_with_placement(placement);

        let sts = K0sBackend::build_server_statefulset("c", "ns", &config, None);
        let pod = sts.spec.unwrap().template.spec.unwrap();
        assert_eq!(pod.tolerations.unwrap().len(), 1);

        let deploy = K0sBackend::build_agent_deployment("c", "ns", &config, 1);
        let pod = deploy.spec.unwrap().template.spec.unwrap();
        assert_eq!(pod.tolerations.unwrap().len(), 1);
    }

    #[test]
    fn test_placement_inter_instance_spread_on_k0s_server() {
        use crate::crd::{InterInstancePlacement, InterInstanceSpread, Placement, SpreadStrength};
        let placement = Placement {
            inter_instance: Some(InterInstancePlacement {
                spread: Some(InterInstanceSpread {
                    strength: SpreadStrength::Required,
                    topology_key: "kubernetes.io/hostname".to_string(),
                }),
            }),
            ..Default::default()
        };
        let config = config_with_placement(placement);
        let sts = K0sBackend::build_server_statefulset("c", "ns", &config, None);
        let pod = sts.spec.unwrap().template.spec.unwrap();
        let anti = pod.affinity.unwrap().pod_anti_affinity.unwrap();
        assert_eq!(
            anti.required_during_scheduling_ignored_during_execution
                .unwrap()
                .len(),
            1,
        );
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
            storage_request_size: Some("25Gi".to_string()),
        });

        let sts = K0sBackend::build_server_statefulset("p-cluster", "ns", &config, None);
        let sts_spec = sts.spec.as_ref().unwrap();
        let pod_spec = sts_spec.template.spec.as_ref().unwrap();

        // No bogus `data` pod volume, and `k0s-data` is NOT an emptyDir — it is
        // backed by the PVC declared in volumeClaimTemplates.
        if let Some(volumes) = pod_spec.volumes.as_ref() {
            assert!(
                !volumes.iter().any(|v| v.name == "data"),
                "the unused `data` volume must be gone"
            );
            assert!(
                !volumes.iter().any(|v| v.name == "k0s-data"),
                "k0s-data must come from volumeClaimTemplates, not a pod volume"
            );
        }

        // The controller container mounts `k0s-data` at k0s's REAL data dir,
        // and there must be NO mount at the unused `/var/lib/k0s/data` subdir.
        let server = &pod_spec.containers[0];
        let mounts = server.volume_mounts.as_ref().unwrap();
        let data_mount = mounts
            .iter()
            .find(|m| m.name == "k0s-data")
            .expect("k0s-data mount must exist");
        assert_eq!(data_mount.mount_path, "/var/lib/k0s");
        assert!(
            !mounts.iter().any(|m| m.mount_path == "/var/lib/k0s/data"),
            "must not mount the unused /var/lib/k0s/data subdir"
        );

        // A volumeClaimTemplate must back the `k0s-data` volume, honoring the
        // PersistenceConfig storageClassName + size request.
        let templates = sts_spec
            .volume_claim_templates
            .as_ref()
            .expect("volumeClaimTemplates must be present when persistence is set");
        let data_pvc = templates
            .iter()
            .find(|t| t.metadata.name.as_deref() == Some("k0s-data"))
            .expect("a `k0s-data` volumeClaimTemplate must exist");
        let pvc_spec = data_pvc.spec.as_ref().unwrap();
        assert_eq!(pvc_spec.storage_class_name.as_deref(), Some("local-path"));
        assert_eq!(
            pvc_spec
                .resources
                .as_ref()
                .unwrap()
                .requests
                .as_ref()
                .unwrap()
                .get("storage")
                .unwrap()
                .0,
            "25Gi"
        );
        assert_eq!(
            pvc_spec.access_modes.as_deref(),
            Some(&["ReadWriteOnce".to_string()][..])
        );
    }

    /// persistence=None must keep `k0s-data` as an emptyDir pod volume and
    /// declare NO volumeClaimTemplate (unchanged legacy behavior).
    #[test]
    fn test_build_server_statefulset_no_persistence_keeps_emptydir() {
        let config = base_config();
        assert!(config.persistence.is_none());
        let sts = K0sBackend::build_server_statefulset("c", "ns", &config, None);
        let sts_spec = sts.spec.as_ref().unwrap();
        assert!(
            sts_spec.volume_claim_templates.is_none(),
            "no persistence ⇒ no volumeClaimTemplates"
        );
        let volumes = sts_spec
            .template
            .spec
            .as_ref()
            .unwrap()
            .volumes
            .as_ref()
            .unwrap();
        let k0s_data = volumes
            .iter()
            .find(|v| v.name == "k0s-data")
            .expect("k0s-data emptyDir volume must exist when persistence is None");
        assert!(
            k0s_data.empty_dir.is_some(),
            "k0s-data must be emptyDir when persistence is None"
        );
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
        let backend = K0sBackend::new(client, Default::default());

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
            .create("test-cluster", "test-ns", &config, &[], None)
            .await;
        assert!(result.is_ok(), "create should succeed: {result:?}");
    }

    /// FIX 5: `servers > 1` is not implemented for the k0s backend (the
    /// StatefulSet is hardcoded to 1 replica and no real join token is
    /// generated). `create()` must reject it up front with a clear error
    /// rather than provisioning a controller that tries to join a
    /// nonexistent cluster and times out after 10 minutes.
    #[tokio::test]
    async fn test_create_rejects_multi_server() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K0sBackend::new(client, Default::default());

        let mut config = base_config();
        config.servers = 3;
        let result = backend
            .create("ha-cluster", "test-ns", &config, &[], None)
            .await;
        let err = result.expect_err("create must reject servers > 1");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("servers>1") && msg.contains("not yet implemented"),
            "error must explain the unsupported HA config: {msg}"
        );
    }

    #[tokio::test]
    async fn test_delete_cluster_basic() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K0sBackend::new(client, Default::default());

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

    /// Regression test for #95: `K0sBackend::delete()` MUST issue a DELETE
    /// for every resource `create()` could have produced. Same shape as the
    /// k3s version in `src/backend/k3s.rs::test_delete_cluster_issues_every_expected_delete`
    /// — keep these in lockstep so a regression in one backend doesn't
    /// hide a regression in the other.
    #[tokio::test]
    async fn test_delete_cluster_issues_every_expected_delete() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K0sBackend::new(client, Default::default());

        let expected_paths: &[(&str, &str)] = &[
            (
                "/apis/apps/v1/namespaces/test-ns/deployments/test-cluster-agent",
                "Deployment",
            ),
            (
                "/api/v1/namespaces/test-ns/services/test-cluster-server",
                "Service",
            ),
            (
                "/apis/apps/v1/namespaces/test-ns/statefulsets/test-cluster-server",
                "StatefulSet",
            ),
            (
                "/api/v1/namespaces/test-ns/configmaps/test-cluster-k0s-config",
                "ConfigMap",
            ),
            (
                "/api/v1/namespaces/test-ns/secrets/test-cluster-token",
                "Secret",
            ),
            (
                "/api/v1/namespaces/test-ns/secrets/test-cluster-kubeconfig",
                "Secret",
            ),
        ];

        for (path_str, kind) in expected_paths {
            let api_version = match *kind {
                "Deployment" | "StatefulSet" => "apps/v1",
                _ => "v1",
            };
            let name = path_str.rsplit('/').next().unwrap().to_string();
            Mock::given(method("DELETE"))
                .and(path(*path_str))
                .respond_with(ResponseTemplate::new(200).set_body_json(generic_response(
                    api_version,
                    kind,
                    &name,
                    "test-ns",
                )))
                .expect(1)
                .mount(&server)
                .await;
        }

        // wait_deleted on the StatefulSet will GET it after delete. Return
        // 404 so the poll exits immediately.
        Mock::given(method("GET"))
            .and(path(
                "/apis/apps/v1/namespaces/test-ns/statefulsets/test-cluster-server",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "statefulsets",
                    "test-cluster-server",
                )),
            )
            .mount(&server)
            .await;

        let result = backend.delete("test-cluster", "test-ns").await;
        assert!(result.is_ok(), "delete should succeed: {result:?}");
    }

    /// Idempotency: re-running `delete()` when nothing exists must succeed.
    #[tokio::test]
    async fn test_delete_is_idempotent_when_all_resources_missing() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K0sBackend::new(client, Default::default());

        Mock::given(method("DELETE"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(crate::testutil::k8s_not_found("resources", "test-cluster")),
            )
            .mount(&server)
            .await;

        // wait_deleted GET — already-gone resource returns 404.
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(crate::testutil::k8s_not_found("resources", "test-cluster")),
            )
            .mount(&server)
            .await;

        let result = backend.delete("test-cluster", "test-ns").await;
        assert!(
            result.is_ok(),
            "delete on already-deleted resources should be a no-op: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_check_health_not_ready() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K0sBackend::new(client, Default::default());

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

    // =================================================================
    // force_delete_instance_pods tests
    // =================================================================

    /// Helper: build a minimal Pod JSON object with the cluster label set.
    fn pod_json(name: &str, namespace: &str, cluster: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {
                    "kobe.kunobi.ninja/cluster": cluster,
                    "kobe.kunobi.ninja/role": "server"
                }
            },
            "spec": {
                "containers": [{ "name": "k0s", "image": "k0sproject/k0s:v1.30.1-k0s.0" }]
            },
            "status": {}
        })
    }

    /// Helper: build a Pod JSON object with a foreign finalizer.
    fn pod_json_with_finalizer(name: &str, namespace: &str, cluster: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {
                    "kobe.kunobi.ninja/cluster": cluster,
                    "kobe.kunobi.ninja/role": "server"
                },
                "finalizers": ["external/foo"]
            },
            "spec": {
                "containers": [{ "name": "k0s", "image": "k0sproject/k0s:v1.30.1-k0s.0" }]
            },
            "status": {}
        })
    }

    /// Helper: build a PodList JSON with the given pod values.
    fn pod_list_json(pods: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "PodList",
            "metadata": { "resourceVersion": "1" },
            "items": pods
        })
    }

    /// Happy path: LIST returns 3 pods, each DELETE succeeds.
    /// Asserts that:
    ///   - LIST request contains `labelSelector=kobe.kunobi.ninja/cluster=pool-test-1`
    ///   - DELETE body carries `gracePeriodSeconds: 0` and `propagationPolicy: "Background"`
    #[tokio::test]
    async fn force_delete_instance_pods_issues_label_scoped_force_deletes() {
        use wiremock::matchers::{body_partial_json, query_param};

        let server = MockServer::start().await;
        let client = mock_client(&server);

        let ns = "test-ns";
        let cluster = "pool-test-1";
        let pod_names = ["server-0", "agent-rs-pod", "bootstrap-job-pod"];

        // Mock: GET (LIST) pods with labelSelector
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/namespaces/{ns}/pods")))
            .and(query_param(
                "labelSelector",
                format!("kobe.kunobi.ninja/cluster={cluster}"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pod_list_json(
                pod_names.iter().map(|n| pod_json(n, ns, cluster)).collect(),
            )))
            .expect(1)
            .mount(&server)
            .await;

        // Mock: DELETE each pod — assert the body carries gracePeriodSeconds=0 and
        // propagationPolicy=Background.
        for name in &pod_names {
            Mock::given(method("DELETE"))
                .and(path(format!("/api/v1/namespaces/{ns}/pods/{name}")))
                .and(body_partial_json(serde_json::json!({
                    "gracePeriodSeconds": 0,
                    "propagationPolicy": "Background"
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(pod_json(name, ns, cluster)))
                .expect(1)
                .mount(&server)
                .await;
        }

        let pods: Api<k8s_openapi::api::core::v1::Pod> = Api::namespaced(client, ns);
        K0sBackend::force_delete_instance_pods(&pods, cluster).await;
        // MockServer Drop validates .expect(1) for every mounted mock.
    }

    /// LIST returns empty 200 (no pods).  Zero DELETE requests must be
    /// issued and the helper must return Ok.
    #[tokio::test]
    async fn force_delete_instance_pods_tolerates_empty_list() {
        use wiremock::matchers::query_param;

        let server = MockServer::start().await;
        let client = mock_client(&server);

        let ns = "test-ns";
        let cluster = "pool-test-1";

        // LIST returns empty
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/namespaces/{ns}/pods")))
            .and(query_param(
                "labelSelector",
                format!("kobe.kunobi.ninja/cluster={cluster}"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pod_list_json(vec![])))
            .expect(1)
            .mount(&server)
            .await;

        // No DELETE mocks — any DELETE would be an unexpected request.

        let pods: Api<k8s_openapi::api::core::v1::Pod> = Api::namespaced(client, ns);
        K0sBackend::force_delete_instance_pods(&pods, cluster).await;
    }

    /// 3 pods listed; the 2nd DELETE returns 500.  Helper returns Ok and
    /// all 3 DELETE requests are still issued (partial failure does not
    /// abort the loop).
    #[tokio::test]
    async fn force_delete_instance_pods_continues_on_partial_failure() {
        use wiremock::matchers::query_param;

        let server = MockServer::start().await;
        let client = mock_client(&server);

        let ns = "test-ns";
        let cluster = "pool-test-1";
        let pod_names = ["server-0", "agent-rs-pod", "bootstrap-job-pod"];

        // LIST returns 3 pods
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/namespaces/{ns}/pods")))
            .and(query_param(
                "labelSelector",
                format!("kobe.kunobi.ninja/cluster={cluster}"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pod_list_json(
                pod_names.iter().map(|n| pod_json(n, ns, cluster)).collect(),
            )))
            .expect(1)
            .mount(&server)
            .await;

        // 1st DELETE: success
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/namespaces/{ns}/pods/server-0")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(pod_json("server-0", ns, cluster)),
            )
            .expect(1)
            .mount(&server)
            .await;

        // 2nd DELETE: 500 — non-fatal, loop continues
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/namespaces/{ns}/pods/agent-rs-pod")))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "message": "Internal Server Error",
                "code": 500
            })))
            .expect(1)
            .mount(&server)
            .await;

        // 3rd DELETE: success — must still be issued
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/api/v1/namespaces/{ns}/pods/bootstrap-job-pod"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(pod_json(
                "bootstrap-job-pod",
                ns,
                cluster,
            )))
            .expect(1)
            .mount(&server)
            .await;

        let pods: Api<k8s_openapi::api::core::v1::Pod> = Api::namespaced(client, ns);
        K0sBackend::force_delete_instance_pods(&pods, cluster).await;
        // MockServer Drop validates all three .expect(1) assertions.
    }

    /// A pod that has a foreign finalizer must receive a DELETE request
    /// (force-delete sets deletionTimestamp) but no PATCH request (we must
    /// NOT strip the finalizer ourselves).
    #[tokio::test]
    async fn force_delete_instance_pods_does_not_strip_foreign_finalizers() {
        use wiremock::matchers::query_param;

        let server = MockServer::start().await;
        let client = mock_client(&server);

        let ns = "test-ns";
        let cluster = "pool-test-1";

        // LIST returns 1 pod with a foreign finalizer
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/namespaces/{ns}/pods")))
            .and(query_param(
                "labelSelector",
                format!("kobe.kunobi.ninja/cluster={cluster}"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pod_list_json(vec![
                pod_json_with_finalizer("server-0", ns, cluster),
            ])))
            .expect(1)
            .mount(&server)
            .await;

        // DELETE must be issued — foreign finalizer does not prevent the call
        Mock::given(method("DELETE"))
            .and(path(format!("/api/v1/namespaces/{ns}/pods/server-0")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(pod_json_with_finalizer("server-0", ns, cluster)),
            )
            .expect(1)
            .mount(&server)
            .await;

        // PATCH must NOT be issued — we do not strip foreign finalizers.
        // (wiremock returns 404 for unexpected requests; if a PATCH were sent
        //  the DELETE mock would not consume it and the test would still pass
        //  for the wrong reason — so we mount a PATCH mock with expect(0) to
        //  make it an explicit failure if a PATCH is ever issued.)
        Mock::given(method("PATCH"))
            .and(path(format!("/api/v1/namespaces/{ns}/pods/server-0")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(pod_json("server-0", ns, cluster)),
            )
            .expect(0)
            .mount(&server)
            .await;

        let pods: Api<k8s_openapi::api::core::v1::Pod> = Api::namespaced(client, ns);
        K0sBackend::force_delete_instance_pods(&pods, cluster).await;
        // MockServer Drop: DELETE expect(1) + PATCH expect(0) are both verified.
    }

    /// LIST request carries `labelSelector=kobe.kunobi.ninja/cluster=pool-test-1`.
    /// Wiremock's `query_param` matcher does the URL-encoded comparison.
    #[tokio::test]
    async fn force_delete_instance_pods_scopes_to_label() {
        use wiremock::matchers::query_param;

        let server = MockServer::start().await;
        let client = mock_client(&server);

        let ns = "test-ns";
        let cluster = "pool-test-1";

        // Only respond if the labelSelector is exactly scoped to our cluster.
        Mock::given(method("GET"))
            .and(path(format!("/api/v1/namespaces/{ns}/pods")))
            .and(query_param(
                "labelSelector",
                format!("kobe.kunobi.ninja/cluster={cluster}"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pod_list_json(vec![])))
            .expect(1)
            .mount(&server)
            .await;

        let pods: Api<k8s_openapi::api::core::v1::Pod> = Api::namespaced(client, ns);
        K0sBackend::force_delete_instance_pods(&pods, cluster).await;
        // MockServer Drop validates that the mock with the exact labelSelector
        // was called exactly once — any different labelSelector would not match
        // and the .expect(1) would fail.
    }
}
