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
    Affinity, ConfigMap, Container, EnvVar, EnvVarSource, HostPathVolumeSource, KeyToPath,
    ObjectFieldSelector, Pod, PodAffinity, PodAffinityTerm, PodSpec, PodTemplateSpec, Secret,
    SecretVolumeSource, Service, ServicePort, ServiceSpec, Toleration, Volume, VolumeMount,
};
use k8s_openapi::api::policy::v1::{PodDisruptionBudget, PodDisruptionBudgetSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::Client;
use kube::api::{Api, DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PropagationPolicy};
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

use crate::crd::{
    Addon, ClusterConfig, IntraPlacementMode, KubeletSharedMountConfig, Placement, ReadinessGate,
};

use super::{
    ClusterBackend, apply_addon_impl, check_readiness_gate_impl, check_virtual_health,
    data_volume_claim_template, datastore, node_affinity_from_selector, read_kubeconfig_secret,
    server_anti_affinity_terms, virtual_client_from_kubeconfig,
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

/// Default kubelet `--cluster-domain` value used by every mainstream
/// distro (kubeadm, kind, k3s, RKE2, EKS/GKE/AKS).
const DEFAULT_CLUSTER_DOMAIN: &str = "cluster.local";

/// Resolve the effective cluster DNS domain, falling back to the
/// upstream default when the operator hasn't pinned a custom one.
fn cluster_domain(config: &ClusterConfig) -> &str {
    config
        .cluster_domain
        .as_deref()
        .unwrap_or(DEFAULT_CLUSTER_DOMAIN)
}

/// The kubeconfig publisher sidecar script, mounted from a ConfigMap.
///
/// Waits for k3s to write the kubeconfig, then ONLY the ordinal-0 pod
/// rewrites the server URL to the FQDN of the ClusterIP Service and
/// creates/updates the `{name}-kubeconfig` Secret. Non-zero ordinals just
/// idle. The FQDN form (4 dots) skips the musl-libc `search`-domain
/// fallback issue that breaks the short `.svc` form on Alpine images.
///
/// Single-writer election (ordinal-0) removes the N-way concurrent `apply`
/// race once `servers > 1`: the kubeconfig content is byte-identical across
/// replicas (the CA comes from the shared datastore), so there's no value in
/// every replica racing to write it — and OrderedReady makes pod-0 the
/// bootstrapper anyway. The publish is an idempotent upsert wrapped in a
/// bounded retry loop so a transient apiserver/RBAC hiccup retries instead of
/// CrashLooping, and a recreated pod-0 re-applying is a no-op.
const KUBECONFIG_PUBLISHER_SCRIPT: &str = r#"#!/bin/sh
echo "Waiting for kubeconfig to appear..."
while [ ! -f /output/kubeconfig ]; do sleep 1; done
echo "Kubeconfig found."
case "${POD_NAME}" in
  *-0)
    set -e
    echo "Ordinal-0: rewriting server URL..."
    sed -i "s|https://127.0.0.1:6443|https://${CLUSTER_NAME}-server.${NAMESPACE}.svc.${CLUSTER_DOMAIN}:6443|" /output/kubeconfig
    echo "Ordinal-0: publishing kubeconfig as Secret..."
    until kubectl create secret generic ${CLUSTER_NAME}-kubeconfig \
      --from-file=kubeconfig=/output/kubeconfig \
      --namespace=${NAMESPACE} \
      -o yaml --dry-run=client | kubectl apply -f -; do
      echo "publish failed, retrying..."
      sleep 2
    done
    echo "Kubeconfig Secret published, sleeping..."
    ;;
  *)
    echo "Non-zero ordinal (${POD_NAME}): not publishing kubeconfig, idling..."
    ;;
esac
sleep infinity
"#;

/// Path k3s reads its container-runtime registry config from on every node.
/// (https://docs.k3s.io/installation/private-registry)
const REGISTRIES_YAML_PATH: &str = "/etc/rancher/k3s/registries.yaml";

/// True iff the ClusterConfig declares a non-empty registry_mirrors map.
fn has_registry_mirrors(config: &ClusterConfig) -> bool {
    config
        .registry_mirrors
        .as_ref()
        .is_some_and(|m| !m.is_empty())
}

/// Pure readiness predicate for the server StatefulSet.
///
/// `replicas` is the StatefulSet's `status.replicas` (the CLAMPED spec value
/// reflected back by the controller), `ready_replicas` is its
/// `status.readyReplicas`. Ready iff there is at least one desired replica and
/// all of them are ready (`want > 0 && have >= want`). Keying off the clamped
/// `status.replicas` — not the raw `config.servers` — means `servers == 0`
/// collapses to the single-server path. Extracted as a pure fn so it is
/// unit-testable without a live apiserver.
fn server_sts_ready(replicas: Option<i32>, ready_replicas: Option<i32>) -> bool {
    let want = replicas.unwrap_or(0);
    let have = ready_replicas.unwrap_or(0);
    want > 0 && have >= want
}

/// HA gate: `servers > 1` requires an external (shared) datastore.
///
/// Reads the RAW `servers` count. Returns `Err` (with a message mentioning
/// "external datastore") when `servers > 1` and no shared datastore is
/// configured, because without it each replica would run its own embedded
/// SQLite → split-brain. Extracted as a pure fn so the gate is unit-testable
/// independent of the mock-heavy `create()`.
///
/// B5: `servers > 1` inherits the datastore's availability SLO — there is no
/// embedded-etcd quorum fallback in this backend; require an HA/managed
/// PostgreSQL.
fn ha_requires_datastore(servers: u32, has_datastore: bool) -> Result<()> {
    if servers > 1 && !has_datastore {
        anyhow::bail!(
            "k3s HA (servers={servers}) requires an external datastore (shared PostgreSQL); none configured. Without it each replica runs its own embedded SQLite -> split-brain. Configure a shared datastore or set servers=1."
        );
    }
    Ok(())
}

/// Render the contents of `registries.yaml` from a mirrors map.
///
/// The map is `source registry → list of mirror endpoints` (e.g.
/// `"docker.io" → ["https://registry.example.com"]`). k3s reads
/// only `mirrors` here — `configs` (auth, TLS) is left for a future
/// extension. Returns `None` for an empty map so callers can short-
/// circuit ConfigMap creation and volume mounting.
fn render_registries_yaml(mirrors: &BTreeMap<String, Vec<String>>) -> Option<String> {
    if mirrors.is_empty() {
        return None;
    }
    let mut out = String::from("mirrors:\n");
    for (source, endpoints) in mirrors {
        out.push_str(&format!("  {source}:\n"));
        out.push_str("    endpoint:\n");
        for ep in endpoints {
            out.push_str(&format!("      - {ep:?}\n"));
        }
    }
    Some(out)
}

/// Direct k3s backend — manages k3s clusters via raw Kubernetes resources.
#[derive(Clone)]
pub struct K3sBackend {
    /// Kubernetes client for the host cluster.
    client: Client,
    /// Optional shared PostgreSQL datastore (pool + base URL), hot-reloadable
    /// when the credential rotates.
    datastore: crate::backend::datastore::SharedDatastore,
}

/// Build the (VolumeMount, EnvVar) pair for the shared kubelet mount.
/// Returns None when the config is absent or the flag is off for this container.
fn kubelet_shared_mount_attachments(
    ksm: Option<&KubeletSharedMountConfig>,
    enabled_for_container: impl FnOnce(&KubeletSharedMountConfig) -> bool,
) -> Option<(VolumeMount, EnvVar)> {
    let ksm = ksm?;
    if !enabled_for_container(ksm) {
        return None;
    }
    let mount = VolumeMount {
        name: "kubelet-root".to_string(),
        mount_path: "/var/lib/kubelet".to_string(),
        mount_propagation: Some("Bidirectional".to_string()),
        sub_path_expr: Some("$(POD_NAME)".to_string()),
        ..Default::default()
    };
    let env = EnvVar {
        name: "POD_NAME".to_string(),
        value_from: Some(EnvVarSource {
            field_ref: Some(ObjectFieldSelector {
                field_path: "metadata.name".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    Some((mount, env))
}

/// Build the hostPath Volume for the shared kubelet mount.
/// Returns None when the config is absent or the flag is off for this container.
fn kubelet_shared_mount_volume(
    name: &str,
    ksm: Option<&KubeletSharedMountConfig>,
    enabled_for_container: impl FnOnce(&KubeletSharedMountConfig) -> bool,
) -> Option<Volume> {
    let ksm = ksm?;
    if !enabled_for_container(ksm) {
        return None;
    }
    Some(Volume {
        name: "kubelet-root".to_string(),
        host_path: Some(HostPathVolumeSource {
            path: format!("{}/{name}/kubelets", ksm.host_path_root),
            type_: Some("DirectoryOrCreate".to_string()),
        }),
        ..Default::default()
    })
}

impl K3sBackend {
    pub fn new(client: Client, datastore: crate::backend::datastore::SharedDatastore) -> Self {
        Self { client, datastore }
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
    ///
    /// When `pool_name` is `Some`, also stamps
    /// `kobe.kunobi.ninja/pool=<name>` so the inter-instance spread
    /// anti-affinity selector can scope to siblings of the same pool
    /// (`server_anti_affinity_terms` in [`crate::backend`]). Standalone
    /// instances pass `None`.
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

    /// Create the token Secret for k3s node authentication.
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

    /// Create the ConfigMap containing the kubeconfig publisher script.
    async fn create_publisher_configmap(&self, name: &str, namespace: &str) -> Result<()> {
        let cms: Api<ConfigMap> = Api::namespaced(self.client.clone(), namespace);
        let cm_name = format!("{name}-kubeconfig-publisher");

        let cm = ConfigMap {
            metadata: ObjectMeta {
                name: Some(cm_name.clone()),
                namespace: Some(namespace.to_string()),
                labels: Some(Self::cluster_labels(name, None)),
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

    /// Create the ConfigMap holding `registries.yaml` for the leased
    /// cluster's container runtime, when registry_mirrors is set.
    /// Returns `Ok(true)` when a ConfigMap was created (so callers can
    /// decide whether to mount it), `Ok(false)` when there's nothing
    /// to do.
    async fn create_registries_configmap(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
    ) -> Result<bool> {
        let Some(mirrors) = &config.registry_mirrors else {
            return Ok(false);
        };
        let Some(yaml) = render_registries_yaml(mirrors) else {
            return Ok(false);
        };

        let cms: Api<ConfigMap> = Api::namespaced(self.client.clone(), namespace);
        let cm_name = format!("{name}-registries");

        let cm = ConfigMap {
            metadata: ObjectMeta {
                name: Some(cm_name.clone()),
                namespace: Some(namespace.to_string()),
                labels: Some(Self::cluster_labels(name, config.pool_name.as_deref())),
                ..Default::default()
            },
            data: Some({
                let mut data = BTreeMap::new();
                data.insert("registries.yaml".to_string(), yaml);
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
        .with_context(|| format!("Failed to apply registries ConfigMap {cm_name}"))?;

        debug!(cluster = name, "Registries ConfigMap applied");
        Ok(true)
    }

    /// Build the k3s server container.
    fn build_server_container(
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        datastore_endpoint: Option<&str>,
    ) -> Container {
        let image = k3s_image(&config.version);

        // Service & pod CIDRs MUST differ from the host cluster's — k3s,
        // rke2, and kubeadm all default to 10.43.0.0/16 for services and
        // 10.42.0.0/16 for pods. When a leased k3s pool member runs as a
        // pod inside a host RKE2/k3s cluster, in-pod kube-proxy iptables
        // for 10.43.0.1 collide with the host cluster's identical rule:
        // pods inside the leased k3s reach for their own apiserver via
        // 10.43.0.1 but get routed to the HOST's apiserver, which serves
        // a cert signed by a different CA than the SA token bundle they
        // mounted. CoreDNS fails its readiness probe with
        //   `x509: certificate signed by unknown authority`
        // and every other in-cluster controller breaks the same way.
        //
        // The instance reconciler allocates a unique pair of /20 ranges
        // per ClusterInstance (see `pool::cidr_alloc`) and stuffs them
        // into `config.allocated_network` before this backend runs. We
        // honor those allocations directly. The fallback below applies
        // only to standalone test paths and CLI-built configs that
        // bypass the operator — production reconciliation always sets
        // `allocated_network`.
        let (service_cidr, cluster_cidr) = match &config.allocated_network {
            Some(net) => (net.service_cidr.clone(), net.cluster_cidr.clone()),
            None => ("10.243.0.0/20".to_string(), "10.248.0.0/20".to_string()),
        };

        let domain = cluster_domain(config);
        // Cert valid for both the short and FQDN forms — clients that
        // already dial via the short name keep working while the agent
        // and published kubeconfig switch over to the FQDN.
        let mut args = vec![
            "server".to_string(),
            format!("--tls-san={name}-server.{namespace}.svc"),
            format!("--tls-san={name}-server.{namespace}.svc.{domain}"),
            "--token-file=/var/lib/k3s/token/token".to_string(),
            "--write-kubeconfig=/output/kubeconfig".to_string(),
            "--write-kubeconfig-mode=644".to_string(),
            format!("--service-cidr={service_cidr}"),
            format!("--cluster-cidr={cluster_cidr}"),
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

        // Optional registries.yaml mount — points at the file k3s
        // reads at startup to configure containerd mirrors.
        if has_registry_mirrors(config) {
            volume_mounts.push(VolumeMount {
                name: "registries-config".to_string(),
                mount_path: REGISTRIES_YAML_PATH.to_string(),
                sub_path: Some("registries.yaml".to_string()),
                read_only: Some(true),
                ..Default::default()
            });
        }

        // Kubelet shared mount (CSI passthrough). See issue #98 and
        // docs/superpowers/specs/2026-05-21-k3s-csi-kubelet-mount-propagation-design.md.
        let mut env: Vec<EnvVar> = vec![];
        if let Some((mount, env_var)) =
            kubelet_shared_mount_attachments(config.kubelet_shared_mount.as_ref(), |c| c.server)
        {
            volume_mounts.push(mount);
            env.push(env_var);
        }

        Container {
            name: "k3s-server".to_string(),
            image: Some(image),
            command: Some(vec!["k3s".to_string()]),
            args: Some(args),
            env: if env.is_empty() { None } else { Some(env) },
            volume_mounts: Some(volume_mounts),
            // Honors `ClusterPool.spec.resources`. Without requests/limits
            // the pod is `BestEffort` and the kubelet evicts it first under
            // host memory pressure — which is what made `ci-k3s-kunobi`
            // members stack on whichever host had the most slack and then
            // CrashLoopBackOff together.
            resources: config.resources.as_ref().and_then(|r| r.to_k8s()),
            ports: Some(vec![k8s_openapi::api::core::v1::ContainerPort {
                container_port: 6443,
                name: Some("api".to_string()),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }]),
            // HTTPS /readyz (not a bare TCP connect) so a replica only counts
            // Ready — and only joins the Service Endpoints / the
            // readyReplicas>=servers gate — once its apiserver genuinely serves
            // with the shared cluster cert. This closes the transient-x509
            // window where the port is open but the cert isn't the shared one
            // yet. Mirrors the liveness probe's /cacerts HTTPS shape below.
            readiness_probe: Some(k8s_openapi::api::core::v1::Probe {
                http_get: Some(k8s_openapi::api::core::v1::HTTPGetAction {
                    path: Some("/readyz".to_string()),
                    port: IntOrString::Int(6443),
                    scheme: Some("HTTPS".to_string()),
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
    fn build_publisher_sidecar(
        name: &str,
        namespace: &str,
        k3s_image: &str,
        cluster_domain: &str,
    ) -> Container {
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
                EnvVar {
                    name: "CLUSTER_DOMAIN".to_string(),
                    value: Some(cluster_domain.to_string()),
                    ..Default::default()
                },
                // Downward-API pod name so the publisher script can elect
                // ordinal-0 as the SOLE writer of the kubeconfig Secret (see
                // KUBECONFIG_PUBLISHER_SCRIPT). Under OrderedReady pod-0 is the
                // bootstrapper, so it is the natural single publisher.
                EnvVar {
                    name: "POD_NAME".to_string(),
                    value_from: Some(EnvVarSource {
                        field_ref: Some(ObjectFieldSelector {
                            field_path: "metadata.name".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
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

        // Data volume. When persistence is configured the `data` volume is
        // backed by a per-replica PVC declared in the StatefulSet's
        // `volumeClaimTemplates` (see `build_server_statefulset`), so it is NOT
        // listed here — adding a pod-level volume of the same name would shadow
        // the claim template. Without persistence, no `data` volume is needed
        // (the container mount is only added when persistence is set).

        // Optional registries.yaml ConfigMap — only mounted when
        // registry_mirrors was set on the ClusterConfig.
        if has_registry_mirrors(config) {
            volumes.push(Volume {
                name: "registries-config".to_string(),
                config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                    name: format!("{name}-registries"),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }

        // Kubelet shared mount (CSI passthrough) — host directory bound
        // into the server container for shared-propagation kubelet workloads.
        if let Some(vol) =
            kubelet_shared_mount_volume(name, config.kubelet_shared_mount.as_ref(), |c| c.server)
        {
            volumes.push(vol);
        }

        volumes
    }

    /// Build the server StatefulSet.
    ///
    /// `replicas` is the already-clamped control-plane count (callers pass
    /// `config.servers.max(1)`). The builder deliberately does NOT read
    /// `config.servers` itself — mirroring `build_agent_deployment` — so the
    /// HA gate (which reads the RAW `config.servers`) and the replica count
    /// stay decoupled and independently testable.
    fn build_server_statefulset(
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        datastore_endpoint: Option<&str>,
        replicas: u32,
    ) -> StatefulSet {
        let image = k3s_image(&config.version);
        let pool = config.pool_name.as_deref();
        let labels = Self::server_labels(name, pool);

        let server_container =
            Self::build_server_container(name, namespace, config, datastore_endpoint);
        let publisher_sidecar =
            Self::build_publisher_sidecar(name, namespace, &image, cluster_domain(config));
        let volumes = Self::build_server_volumes(name, config);

        // When persistence is configured, back the `data` volume (mounted at
        // k3s's real data dir `/var/lib/rancher/k3s`) with a per-replica PVC via
        // `volumeClaimTemplates` instead of an emptyDir, so control-plane state
        // survives reschedules. `None` ⇒ no template (no `data` mount either).
        let volume_claim_templates = config
            .persistence
            .as_ref()
            .map(|p| vec![data_volume_claim_template("data", p)]);

        StatefulSet {
            metadata: ObjectMeta {
                name: Some(format!("{name}-server")),
                namespace: Some(namespace.to_string()),
                labels: Some(labels.clone()),
                ..Default::default()
            },
            spec: Some(StatefulSetSpec {
                replicas: Some(i32::try_from(replicas).unwrap_or(i32::MAX)),
                service_name: Some(format!("{name}-server")),
                // LOAD-BEARING for HA: OrderedReady serializes pod-0 to
                // bootstrap the shared-datastore cluster CA before peers join;
                // Parallel would race N servers on a fresh DB and diverge CAs
                // (split-brain). Do not change to Parallel.
                pod_management_policy: Some("OrderedReady".to_string()),
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
                            std::env::var("POOL_SERVICE_ACCOUNT")
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

    /// Build the ClusterIP Service for the k3s API server.
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

    /// Build the PodDisruptionBudget for HA (servers>1) control planes.
    ///
    /// Selects the same server pod labels as `build_service` / the
    /// StatefulSet. `minAvailable`: `servers>=3 → servers-1` (tolerate one
    /// voluntary disruption while keeping a working majority of replicas);
    /// `servers==2 → 1` (keep at least one control plane up). Only ever called
    /// for `servers > 1`.
    ///
    /// NOTE: a PDB protects ONLY voluntary disruptions (node drains/evictions);
    /// it does NOT gate the StatefulSet's own RollingUpdate (which already does
    /// one-pod-at-a-time + readiness).
    fn build_pod_disruption_budget(
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
    ) -> PodDisruptionBudget {
        let pool = config.pool_name.as_deref();
        let labels = Self::server_labels(name, pool);

        let min_available = if config.servers >= 3 {
            config.servers - 1
        } else {
            1
        };

        PodDisruptionBudget {
            metadata: ObjectMeta {
                name: Some(format!("{name}-server")),
                namespace: Some(namespace.to_string()),
                labels: Some(Self::cluster_labels(name, pool)),
                ..Default::default()
            },
            spec: Some(PodDisruptionBudgetSpec {
                // Saturate consistently with the StatefulSet replica conversion
                // (k8s int32); an absurd >i32::MAX server count is unreachable in
                // practice but must not silently collapse minAvailable to 1.
                min_available: Some(IntOrString::Int(
                    i32::try_from(min_available).unwrap_or(i32::MAX),
                )),
                selector: Some(LabelSelector {
                    match_labels: Some(labels),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Build the server pod affinity block from [`Placement`].
    /// Combines, in one `Affinity`:
    ///
    /// - `nodeAffinity` from `placement.node.selector`
    /// - `podAntiAffinity` from `placement.interInstance.spread`
    ///
    /// Returns `None` when neither would render anything, so the
    /// StatefulSet stays byte-identical to clusters where placement was
    /// untouched. The intra-instance `SameHost` mode is irrelevant for
    /// the server (it's already the anchor pod the agents co-locate to).
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

    /// Build the agent pod affinity block from [`Placement`]. Combines:
    ///
    /// - `nodeAffinity` from `placement.node.selector`
    /// - `podAffinity` (intra-instance co-location) when
    ///   `placement.intraInstance.mode == SameHost`
    ///
    /// Returns `None` when none of the above renders anything, so the
    /// Deployment stays byte-identical to clusters where placement was
    /// untouched.
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

    /// Tolerations to stamp on every pod the backend creates. Returns
    /// `None` when `placement.node.tolerations` is absent or empty so
    /// no `tolerations:` block is emitted (byte-identical with old
    /// manifests).
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
        let image = k3s_image(&config.version);
        let pool = config.pool_name.as_deref();
        let labels = Self::agent_labels(name, pool);
        let domain = cluster_domain(config);

        let mut volume_mounts = vec![VolumeMount {
            name: "token".to_string(),
            mount_path: "/var/lib/k3s/token".to_string(),
            read_only: Some(true),
            ..Default::default()
        }];
        if has_registry_mirrors(config) {
            volume_mounts.push(VolumeMount {
                name: "registries-config".to_string(),
                mount_path: REGISTRIES_YAML_PATH.to_string(),
                sub_path: Some("registries.yaml".to_string()),
                read_only: Some(true),
                ..Default::default()
            });
        }
        let mut env: Vec<EnvVar> = vec![];
        if let Some((mount, env_var)) =
            kubelet_shared_mount_attachments(config.kubelet_shared_mount.as_ref(), |c| c.agents)
        {
            volume_mounts.push(mount);
            env.push(env_var);
        }

        let container = Container {
            name: "k3s-agent".to_string(),
            image: Some(image),
            command: Some(vec!["k3s".to_string()]),
            // FQDN avoids musl's broken `search`-domain fallback after
            // an absolute NXDOMAIN — see `ClusterConfig::cluster_domain`.
            args: Some(vec![
                "agent".to_string(),
                format!("--server=https://{name}-server.{namespace}.svc.{domain}:6443"),
                "--token-file=/var/lib/k3s/token/token".to_string(),
            ]),
            env: if env.is_empty() { None } else { Some(env) },
            volume_mounts: Some(volume_mounts),
            // Mirror the server container's resource block so server and
            // agent share the same QoS class — otherwise the agent could
            // be evicted while the server keeps running and the cluster
            // ends up only-control-plane.
            resources: config.resources.as_ref().and_then(|r| r.to_k8s()),
            security_context: Some(k8s_openapi::api::core::v1::SecurityContext {
                privileged: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        let mut volumes = vec![Volume {
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
        }];
        if has_registry_mirrors(config) {
            volumes.push(Volume {
                name: "registries-config".to_string(),
                config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                    name: format!("{name}-registries"),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        if let Some(vol) =
            kubelet_shared_mount_volume(name, config.kubelet_shared_mount.as_ref(), |c| c.agents)
        {
            volumes.push(vol);
        }

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
                        volumes: Some(volumes),
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Wait for the k3s cluster to become ready.
    ///
    /// Polls BOTH conditions in the SAME loop and only returns `Ok` when:
    ///   (a) the `{name}-kubeconfig` Secret exists (published by pod-0), AND
    ///   (b) the server StatefulSet reports enough ready replicas
    ///       (`server_sts_ready` against its CLAMPED `status.replicas`).
    ///
    /// `servers` is the RAW `config.servers`; it only sizes the timeout budget
    /// (see below). The readiness predicate keys off the StatefulSet's own
    /// `status.replicas` (the clamped spec value), so `servers == 0` collapses
    /// cleanly to the single-server path.
    ///
    /// Single-server behavior note: the historical wait returned the instant
    /// the kubeconfig Secret appeared. Additionally gating on `readyReplicas`
    /// means a single-server cluster is now declared Ready a few seconds later
    /// — once its apiserver actually passes the HTTPS `/readyz` probe and joins
    /// the Service Endpoints — instead of the moment k3s wrote its kubeconfig.
    /// This is a deliberate, strictly-safer change (never advertise Ready
    /// before the API genuinely serves), not a regression.
    ///
    /// Transient (non-404) API errors while polling are NOT fatal: they are
    /// logged and treated as "not ready yet", so a blip does not fail an
    /// otherwise-healthy provision. Only exhausting the budget fails — and an
    /// idempotent `create_database` makes the ensuing reconcile retry safe.
    ///
    /// B3 (pod-0 SPOF): pod-0 is a hard bootstrap dependency under OrderedReady
    /// (it seeds the CA and is the sole kubeconfig publisher); if pod-0 cannot
    /// reach Ready, the instance burns the wait_ready budget and recycles —
    /// mitigated by idempotent `create_database` (step 1) and the in-sidecar
    /// retry (step 7). No operator-side fallback in this version.
    async fn wait_ready(&self, name: &str, namespace: &str, servers: u32) -> Result<()> {
        debug!(cluster = name, "Waiting for k3s cluster to become ready");

        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        let secret_name = format!("{name}-kubeconfig");
        let sts_api: Api<StatefulSet> = Api::namespaced(self.client.clone(), namespace);
        let sts_name = format!("{name}-server");

        // B2 (timeout budget): OrderedReady serializes bring-up, so N servers
        // take proportionally longer than one. Scale the attempt budget with
        // the count: 120 attempts (×5s = 600s) for the first server, +36
        // attempts (+180s) per additional server. servers=1 → 600s (unchanged
        // from the historical single-server budget); servers=3 → 192×5s = 960s.
        let max_attempts = 120 + 36 * (servers.saturating_sub(1)) as usize;

        for attempt in 0..max_attempts {
            // (a) kubeconfig Secret present?
            let secret_ready = match secrets.get(&secret_name).await {
                Ok(_) => true,
                Err(kube::Error::Api(ae)) if ae.code == 404 => false,
                // Transient (non-404) errors are not fatal: log and keep
                // polling within the budget rather than failing the whole
                // provision on a blip.
                Err(e) => {
                    warn!(cluster = name, error = %e, "transient error polling kubeconfig Secret; retrying");
                    false
                }
            };

            // (b) StatefulSet readyReplicas >= clamped spec replicas?
            let sts_ready = match sts_api.get(&sts_name).await {
                Ok(sts) => {
                    let status = sts.status.as_ref();
                    server_sts_ready(
                        status.map(|s| s.replicas),
                        status.and_then(|s| s.ready_replicas),
                    )
                }
                Err(kube::Error::Api(ae)) if ae.code == 404 => false,
                // Transient (non-404) errors are not fatal: log and keep polling.
                Err(e) => {
                    warn!(cluster = name, error = %e, "transient error polling server StatefulSet; retrying");
                    false
                }
            };

            if secret_ready && sts_ready {
                info!(
                    cluster = name,
                    attempts = attempt + 1,
                    "k3s cluster ready (kubeconfig secret present and server StatefulSet ready)"
                );
                return Ok(());
            }

            if attempt % 12 == 0 {
                debug!(
                    cluster = name,
                    attempt = attempt + 1,
                    secret_ready,
                    sts_ready,
                    "Waiting for k3s cluster readiness..."
                );
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }

        anyhow::bail!(
            "k3s cluster {name} not ready after {} attempts ({}s)",
            max_attempts,
            max_attempts * 5
        );
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

    /// Opportunistic force-delete of pods carrying
    /// `kobe.kunobi.ninja/cluster=<cluster_name>`.
    ///
    /// Called at the end of [`K3sBackend::delete`] after all controller
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

impl ClusterBackend for K3sBackend {
    #[tracing::instrument(skip(self, config, addons, _owner_ref), fields(cluster = name, namespace))]
    async fn create(
        &self,
        name: &str,
        namespace: &str,
        config: &ClusterConfig,
        addons: &[Addon],
        // k3s pool members are themselves k8s resources owned via labels +
        // explicit cleanup; the OwnerRef plumbing is for vkobe's child
        // resources where defense-in-depth GC matters more.
        _owner_ref: Option<&k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference>,
    ) -> Result<()> {
        info!(cluster = name, "Creating k3s cluster");

        // 1. Create token secret
        self.create_token_secret(name, namespace).await?;

        // 2. Create publisher ConfigMap
        self.create_publisher_configmap(name, namespace).await?;

        // 2b. Optionally create registries.yaml ConfigMap (k3s containerd mirrors)
        self.create_registries_configmap(name, namespace, config)
            .await?;

        // 3. If PostgreSQL configured, create per-cluster database. Read the
        // current connection each time so a rotated credential is picked up.
        //
        // `servers` is IMMUTABLE in practice: it is folded into the pool's
        // `profile_spec_hash` (see `pool::manager::profile_spec_hash`), so any
        // change to it is a full recycle — the old instance (with its DB and
        // PVCs) is torn down and a fresh-named one created. We never mutate the
        // replica count of a live StatefulSet in place.
        let datastore_endpoint = if let Some((pool, base_url)) = self.datastore.current() {
            datastore::create_database(&pool, name, "k3s_").await?;
            let endpoint = datastore::cluster_endpoint(&base_url, name, "k3s_")?;
            Some(endpoint)
        } else {
            None
        };

        // 3b. HA gate (B5): servers>1 requires a shared external datastore. The
        // gate reads the RAW config.servers and MUST fire before ANY
        // StatefulSet/Service/PDB is patched — otherwise we'd provision N
        // embedded-SQLite replicas that diverge into split-brain. servers>1
        // inherits the datastore's availability SLO; there is no embedded-etcd
        // quorum fallback here, so an HA/managed PostgreSQL is required.
        ha_requires_datastore(config.servers, datastore_endpoint.is_some())?;

        // 4. Create server StatefulSet. The replica count is the clamped
        // `config.servers.max(1)` (the builder never reads config.servers).
        let sts = Self::build_server_statefulset(
            name,
            namespace,
            config,
            datastore_endpoint.as_deref(),
            config.servers.max(1),
        );
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

        // 5b. For HA (servers>1) ONLY, additively create a PodDisruptionBudget.
        //
        // The PDB protects ONLY voluntary disruptions (node drains/evictions);
        // it does NOT gate the StatefulSet's own RollingUpdate (which already
        // does one-pod-at-a-time + readiness). Single-server stays
        // byte-for-byte unchanged (no PDB created).
        if config.servers > 1 {
            let pdb = Self::build_pod_disruption_budget(name, namespace, config);
            let pdb_api: Api<PodDisruptionBudget> = Api::namespaced(self.client.clone(), namespace);
            let pdb_name = format!("{name}-server");
            pdb_api
                .patch(
                    &pdb_name,
                    &PatchParams::apply("kobe-operator").force(),
                    &Patch::Apply(&pdb),
                )
                .await
                .with_context(|| format!("Failed to apply PodDisruptionBudget for {name}"))?;
            info!(
                cluster = name,
                servers = config.servers,
                "PodDisruptionBudget applied"
            );
        }

        // 6. Wait for readiness: kubeconfig Secret published by pod-0 AND the
        // server StatefulSet reporting readyReplicas >= clamped replicas.
        self.wait_ready(name, namespace, config.servers).await?;

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

        // B4 (known PVC leak): the per-replica PVCs created from the
        // StatefulSet's `volumeClaimTemplates` (named
        // `data-{name}-server-{ordinal}`) are NOT deleted here and are
        // orphaned on recycle. This is tolerable today because `servers` is
        // folded into `spec_hash`, so any `servers` change is a full recycle
        // with a NEW instance name — the orphans are scoped to the old name,
        // not reused. Tracked as a follow-up (PVC GC + immutability handling),
        // intentionally out of scope for the HA change to keep it focused.

        // Delete agent Deployment
        let deploy_api: Api<Deployment> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&deploy_api, &format!("{name}-agent")).await?;

        // Delete Service
        let svc_api: Api<Service> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&svc_api, &format!("{name}-server")).await?;

        // Delete server StatefulSet
        let sts_api: Api<StatefulSet> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&sts_api, &format!("{name}-server")).await?;

        // Delete the HA PodDisruptionBudget (created only for servers>1;
        // harmless 404 for single-server). delete() has no ClusterConfig here,
        // so we attempt the delete unconditionally and swallow 404.
        let pdb_api: Api<PodDisruptionBudget> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&pdb_api, &format!("{name}-server")).await?;

        // Delete publisher ConfigMap
        let cms: Api<ConfigMap> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&cms, &format!("{name}-kubeconfig-publisher")).await?;

        // Delete registries ConfigMap. Created conditionally in step 2b of
        // create() when ClusterConfig::registry_mirrors is set; harmless 404
        // when not. Without this, every recycled k3s instance leaks one
        // `{name}-registries` CM — observed as ~230 stale CMs on an internal cluster.
        Self::delete_ignoring_not_found(&cms, &format!("{name}-registries")).await?;

        // Delete secrets: token and kubeconfig
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), namespace);
        Self::delete_ignoring_not_found(&secrets, &format!("{name}-token")).await?;
        Self::delete_ignoring_not_found(&secrets, &format!("{name}-kubeconfig")).await?;

        // Drop database if PostgreSQL is configured
        if let Some((pool, _)) = self.datastore.current()
            && let Err(e) = datastore::drop_database(&pool, name, "k3s_").await
        {
            warn!(cluster = name, error = %e, "Failed to drop database (may not exist)");
        }

        // Force-delete any leftover pods carrying our cluster label.
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        Self::force_delete_instance_pods(&pods, name).await;

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
    use crate::crd::{ClusterConfig, ExposeConfig, KubeletSharedMountConfig, PersistenceConfig};

    fn base_config() -> ClusterConfig {
        ClusterConfig {
            version: "v1.31.3+k3s1".to_string(),
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
    fn test_build_server_statefulset_basic() {
        let config = base_config();
        let sts = K3sBackend::build_server_statefulset("test-cluster", "test-ns", &config, None, 1);

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

    /// Regression: the leased k3s pool member MUST advertise service +
    /// cluster CIDRs that don't collide with the host cluster's. K3s,
    /// RKE2, and kubeadm all default to 10.43.0.0/16 (services) and
    /// 10.42.0.0/16 (pods); leaving k3s on its own defaults caused
    /// CoreDNS to fail TLS verification against the host's apiserver
    /// (in-pod 10.43.0.1 routes via host iptables → host apiserver →
    /// `x509: certificate signed by unknown authority`).
    ///
    /// The fallback path below covers standalone-test / CLI builds that
    /// bypass the reconciler. Production reconciliation always passes
    /// an `allocated_network` (see `pool::cidr_alloc`); a separate test
    /// covers that path.
    #[test]
    fn test_server_args_fallback_cidrs_avoid_host_defaults() {
        let config = base_config();
        assert!(
            config.allocated_network.is_none(),
            "base_config must leave allocation to the reconciler; got {:?}",
            config.allocated_network
        );
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let args = sts.spec.unwrap().template.spec.unwrap().containers[0]
            .args
            .clone()
            .unwrap();
        let svc = args
            .iter()
            .find(|a| a.starts_with("--service-cidr="))
            .expect("service-cidr arg must be present");
        let pod = args
            .iter()
            .find(|a| a.starts_with("--cluster-cidr="))
            .expect("cluster-cidr arg must be present");
        assert!(
            !svc.contains("10.43.") && !svc.contains("10.96."),
            "service CIDR must avoid k3s/rke2/kubeadm defaults; got {svc}"
        );
        assert!(
            !pod.contains("10.42."),
            "cluster CIDR must avoid k3s/rke2 default 10.42.0.0/16; got {pod}"
        );
    }

    /// Regression: when the operator allocates a network slot, the
    /// backend MUST emit those CIDRs verbatim instead of falling back
    /// to the standalone defaults.
    #[test]
    fn test_server_args_honor_allocated_network() {
        use crate::crd::ClusterInstanceNetwork;
        let mut config = base_config();
        config.allocated_network = Some(ClusterInstanceNetwork {
            service_cidr: "10.245.32.0/20".to_string(),
            cluster_cidr: "10.253.32.0/20".to_string(),
        });
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let args = sts.spec.unwrap().template.spec.unwrap().containers[0]
            .args
            .clone()
            .unwrap();
        assert!(
            args.contains(&"--service-cidr=10.245.32.0/20".to_string()),
            "must use allocated service CIDR; got {args:?}"
        );
        assert!(
            args.contains(&"--cluster-cidr=10.253.32.0/20".to_string()),
            "must use allocated cluster CIDR; got {args:?}"
        );
    }

    #[test]
    fn test_build_server_statefulset_with_pg() {
        let config = base_config();
        let sts = K3sBackend::build_server_statefulset(
            "pg-cluster",
            "ns",
            &config,
            Some("postgres://user:pass@pg:5432/k3s_pg_cluster"),
            1,
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
            storage_request_size: Some("20Gi".to_string()),
        });

        let sts = K3sBackend::build_server_statefulset("p-cluster", "ns", &config, None, 1);
        let sts_spec = sts.spec.as_ref().unwrap();
        let pod_spec = sts_spec.template.spec.as_ref().unwrap();

        // The `data` volume must NOT appear as a pod-level (emptyDir) volume —
        // it is provisioned via volumeClaimTemplates instead.
        if let Some(volumes) = pod_spec.volumes.as_ref() {
            assert!(
                !volumes.iter().any(|v| v.name == "data"),
                "data must come from volumeClaimTemplates, not a pod volume"
            );
        }

        // The container still mounts `data` at k3s's real data dir.
        let server = &pod_spec.containers[0];
        let mounts = server.volume_mounts.as_ref().unwrap();
        let data_mount = mounts
            .iter()
            .find(|m| m.name == "data")
            .expect("data mount must exist");
        assert_eq!(data_mount.mount_path, "/var/lib/rancher/k3s");

        // A volumeClaimTemplate must back the `data` volume, honoring the
        // PersistenceConfig storageClassName + size request.
        let templates = sts_spec
            .volume_claim_templates
            .as_ref()
            .expect("volumeClaimTemplates must be present when persistence is set");
        let data_pvc = templates
            .iter()
            .find(|t| t.metadata.name.as_deref() == Some("data"))
            .expect("a `data` volumeClaimTemplate must exist");
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
            "20Gi"
        );
        assert_eq!(
            pvc_spec.access_modes.as_deref(),
            Some(&["ReadWriteOnce".to_string()][..])
        );
    }

    /// persistence=None must NOT create a volumeClaimTemplate (k3s falls back
    /// to its container filesystem, the unchanged legacy behavior).
    #[test]
    fn test_build_server_statefulset_no_persistence_has_no_pvc_template() {
        let config = base_config();
        assert!(config.persistence.is_none());
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        assert!(
            sts.spec.unwrap().volume_claim_templates.is_none(),
            "no persistence ⇒ no volumeClaimTemplates"
        );
    }

    /// When persistence is set without an explicit size, the PVC request falls
    /// back to the default.
    #[test]
    fn test_persistence_default_size_when_unset() {
        let mut config = base_config();
        config.persistence = Some(PersistenceConfig {
            storage_type: Some("dynamic".to_string()),
            storage_class_name: None,
            storage_request_size: None,
        });
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let templates = sts.spec.unwrap().volume_claim_templates.unwrap();
        let pvc_spec = templates[0].spec.as_ref().unwrap();
        assert!(pvc_spec.storage_class_name.is_none());
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
            "10Gi"
        );
    }

    #[test]
    fn test_build_server_statefulset_custom_args() {
        let mut config = base_config();
        config.server_args = vec![
            "--disable=traefik".to_string(),
            "--flannel-backend=none".to_string(),
        ];

        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);

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
        let sts = K3sBackend::build_server_statefulset("test", "ns", &config, None, 1);
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
        let sts = K3sBackend::build_server_statefulset("test", "ns", &config, None, 1);
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
        let sts = K3sBackend::build_server_statefulset("test", "ns", &config, None, 1);
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
        // Default cluster domain is `cluster.local`, so the agent dials
        // the server via the FQDN rather than the short `.svc` form.
        assert!(
            args.iter()
                .any(|a| a == "--server=https://my-cluster-server.ns.svc.cluster.local:6443")
        );

        // Default placement is Any → no affinity rendered, so the manifest
        // stays byte-identical for clusters that predate this field.
        assert!(pod_spec.affinity.is_none());

        // Without registry_mirrors, no registries volume/mount is emitted.
        let mounts = agent.volume_mounts.as_ref().unwrap();
        assert!(mounts.iter().all(|m| m.name != "registries-config"));
        let vols = pod_spec.volumes.as_ref().unwrap();
        assert!(vols.iter().all(|v| v.name != "registries-config"));
    }

    // =================================================================
    // Registry mirrors (registries.yaml ConfigMap + volume mount)
    // =================================================================

    #[test]
    fn test_render_registries_yaml_empty_returns_none() {
        let mirrors = std::collections::BTreeMap::<String, Vec<String>>::new();
        assert!(render_registries_yaml(&mirrors).is_none());
    }

    #[test]
    fn test_render_registries_yaml_single_source_single_endpoint() {
        let mut mirrors = std::collections::BTreeMap::new();
        mirrors.insert(
            "docker.io".to_string(),
            vec!["https://registry.example.com".to_string()],
        );
        let yaml = render_registries_yaml(&mirrors).unwrap();
        // Lex-stable ordering (BTreeMap) makes the rendered output predictable.
        assert_eq!(
            yaml,
            "mirrors:\n  docker.io:\n    endpoint:\n      - \"https://registry.example.com\"\n"
        );
    }

    #[test]
    fn test_render_registries_yaml_multiple_sources_and_endpoints() {
        let mut mirrors = std::collections::BTreeMap::new();
        mirrors.insert(
            "docker.io".to_string(),
            vec![
                "https://primary.example.com".to_string(),
                "https://fallback.example.com".to_string(),
            ],
        );
        mirrors.insert(
            "quay.io".to_string(),
            vec!["https://quay-mirror.example.com".to_string()],
        );
        let yaml = render_registries_yaml(&mirrors).unwrap();
        // BTreeMap iterates lexicographically: docker.io before quay.io.
        // Endpoint list preserves insertion order.
        let expected = concat!(
            "mirrors:\n",
            "  docker.io:\n",
            "    endpoint:\n",
            "      - \"https://primary.example.com\"\n",
            "      - \"https://fallback.example.com\"\n",
            "  quay.io:\n",
            "    endpoint:\n",
            "      - \"https://quay-mirror.example.com\"\n",
        );
        assert_eq!(yaml, expected);
    }

    /// When registry_mirrors is set, the agent Deployment gets the
    /// extra ConfigMap volume + a /etc/rancher/k3s/registries.yaml
    /// subPath mount on the k3s-agent container.
    #[test]
    fn test_build_agent_deployment_mounts_registries_when_configured() {
        let mut mirrors = std::collections::BTreeMap::new();
        mirrors.insert(
            "docker.io".to_string(),
            vec!["https://registry.example.com".to_string()],
        );
        let config = ClusterConfig {
            registry_mirrors: Some(mirrors),
            ..base_config()
        };

        let deploy = K3sBackend::build_agent_deployment("my-cluster", "ns", &config, 1);
        let pod_spec = deploy.spec.unwrap().template.spec.unwrap();

        let agent = &pod_spec.containers[0];
        let mount = agent
            .volume_mounts
            .as_ref()
            .unwrap()
            .iter()
            .find(|m| m.name == "registries-config")
            .expect("registries-config volume mount missing");
        assert_eq!(mount.mount_path, REGISTRIES_YAML_PATH);
        assert_eq!(mount.sub_path.as_deref(), Some("registries.yaml"));
        assert_eq!(mount.read_only, Some(true));

        let vol = pod_spec
            .volumes
            .as_ref()
            .unwrap()
            .iter()
            .find(|v| v.name == "registries-config")
            .expect("registries-config volume missing");
        let cm = vol.config_map.as_ref().expect("config_map source missing");
        assert_eq!(cm.name, "my-cluster-registries");
    }

    /// Same coverage on the server StatefulSet pod template — the
    /// k3s-server container reads registries.yaml at startup, so the
    /// mount has to be there too (not just on the agent).
    #[test]
    fn test_build_server_statefulset_mounts_registries_when_configured() {
        let mut mirrors = std::collections::BTreeMap::new();
        mirrors.insert(
            "docker.io".to_string(),
            vec!["https://registry.example.com".to_string()],
        );
        let config = ClusterConfig {
            registry_mirrors: Some(mirrors),
            ..base_config()
        };

        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let pod_spec = sts.spec.unwrap().template.spec.unwrap();

        let server = pod_spec
            .containers
            .iter()
            .find(|c| c.name == "k3s-server")
            .unwrap();
        let mount = server
            .volume_mounts
            .as_ref()
            .unwrap()
            .iter()
            .find(|m| m.name == "registries-config")
            .expect("registries-config volume mount missing on server container");
        assert_eq!(mount.mount_path, REGISTRIES_YAML_PATH);
        assert_eq!(mount.sub_path.as_deref(), Some("registries.yaml"));

        let vol = pod_spec
            .volumes
            .as_ref()
            .unwrap()
            .iter()
            .find(|v| v.name == "registries-config")
            .expect("registries-config volume missing on server pod template");
        assert_eq!(vol.config_map.as_ref().unwrap().name, "c-registries");
    }

    #[test]
    fn test_build_agent_deployment_honors_custom_cluster_domain() {
        let config = ClusterConfig {
            cluster_domain: Some("my.k8s.example".to_string()),
            ..base_config()
        };
        let deploy = K3sBackend::build_agent_deployment("c", "ns", &config, 1);
        let args = deploy.spec.unwrap().template.spec.unwrap().containers[0]
            .args
            .clone()
            .unwrap();
        assert!(
            args.iter()
                .any(|a| a == "--server=https://c-server.ns.svc.my.k8s.example:6443"),
            "args were: {args:?}"
        );
    }

    #[test]
    fn test_server_args_include_both_short_and_fqdn_tls_sans() {
        // Cert must remain valid for both Service forms — the kubeconfig
        // and clients that already dial the short name keep working
        // while the agent + published kubeconfig switch to the FQDN.
        let config = base_config();
        let container = K3sBackend::build_server_container("my-cluster", "ns", &config, None);
        let args = container.args.as_ref().unwrap();
        assert!(args.contains(&"--tls-san=my-cluster-server.ns.svc".to_string()));
        assert!(args.contains(&"--tls-san=my-cluster-server.ns.svc.cluster.local".to_string()));
    }

    /// `intraInstance.mode: SameHost` renders a required agent
    /// podAffinity onto the server pod's host. Anchored to the
    /// historical "same_host_placement" behavior name.
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
        let deploy = K3sBackend::build_agent_deployment("my-cluster", "ns", &config, 1);

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
        let selector = term.label_selector.as_ref().unwrap();
        let match_labels = selector.match_labels.as_ref().unwrap();
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
        let deploy = K3sBackend::build_agent_deployment("c", "ns", &config, 1);
        let pod_spec = deploy.spec.unwrap().template.spec.unwrap();
        assert!(pod_spec.affinity.is_none());
    }

    #[test]
    fn test_cluster_labels() {
        let labels = K3sBackend::cluster_labels("my-cluster", None);
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

    /// Regression: setting `pool_name` stamps the pool label so the
    /// inter-instance spread anti-affinity selector can scope to
    /// siblings of the same pool. Without this, cross-pool anti-affinity
    /// can deadlock multi-pool clusters running `spread.strength: Required`.
    #[test]
    fn test_cluster_labels_stamps_pool_when_set() {
        let labels = K3sBackend::cluster_labels("pool-ci-k3s-kunobi-42", Some("ci-k3s-kunobi"));
        assert_eq!(
            labels.get("kobe.kunobi.ninja/pool").unwrap(),
            "ci-k3s-kunobi"
        );
    }

    #[test]
    fn test_server_labels_include_role() {
        let labels = K3sBackend::server_labels("c1", None);
        assert_eq!(labels.get("kobe.kunobi.ninja/role").unwrap(), "server");
        assert!(labels.contains_key("kobe.kunobi.ninja/cluster"));
    }

    #[test]
    fn test_agent_labels_include_role() {
        let labels = K3sBackend::agent_labels("c1", None);
        assert_eq!(labels.get("kobe.kunobi.ninja/role").unwrap(), "agent");
    }

    #[test]
    fn test_publisher_sidecar_has_correct_env() {
        let sidecar = K3sBackend::build_publisher_sidecar(
            "my-cluster",
            "ns",
            "rancher/k3s:v1.31.3+k3s1",
            "cluster.local",
        );
        let env = sidecar.env.as_ref().unwrap();
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
    }

    #[test]
    fn test_publisher_sidecar_mounts() {
        let sidecar = K3sBackend::build_publisher_sidecar(
            "c",
            "ns",
            "rancher/k3s:v1.31.3+k3s1",
            "cluster.local",
        );
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

    /// A StatefulSet GET response whose status reports `replicas` desired and
    /// `replicas` ready — i.e. the cluster is fully Ready. Used by create-flow
    /// tests so `wait_ready`'s readiness predicate is satisfied immediately.
    fn ready_statefulset_response(name: &str, namespace: &str, replicas: i32) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": name, "namespace": namespace },
            "status": { "replicas": replicas, "readyReplicas": replicas }
        })
    }

    #[tokio::test]
    async fn test_create_cluster_basic() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K3sBackend::new(client, Default::default());

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

        // Mock: GET StatefulSet (wait_ready now polls readyReplicas too).
        // Report 1 desired / 1 ready so the readiness predicate passes.
        Mock::given(method("GET"))
            .and(path(
                "/apis/apps/v1/namespaces/test-ns/statefulsets/test-cluster-server",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(ready_statefulset_response(
                    "test-cluster-server",
                    "test-ns",
                    1,
                )),
            )
            .mount(&server)
            .await;

        let config = base_config();
        let result = backend
            .create("test-cluster", "test-ns", &config, &[], None)
            .await;
        assert!(result.is_ok(), "create should succeed: {result:?}");
    }

    #[tokio::test]
    async fn test_delete_cluster_basic() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K3sBackend::new(client, Default::default());

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

    /// Regression test for #95: `K3sBackend::delete()` MUST issue a DELETE
    /// for every resource `create()` could have produced — including the
    /// agent Deployment, server Service, server StatefulSet, both ConfigMaps
    /// (publisher + registries), and both Secrets (token + kubeconfig).
    ///
    /// Uses `.expect(1)` on each mock so a regression that silently drops
    /// any one DELETE — like the registries CM gap fixed in #87 or the
    /// pre-#95 abnormal-path leaks — fails the test instead of silently
    /// passing on wiremock's default 404.
    #[tokio::test]
    async fn test_delete_cluster_issues_every_expected_delete() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K3sBackend::new(client, Default::default());

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
                "/apis/policy/v1/namespaces/test-ns/poddisruptionbudgets/test-cluster-server",
                "PodDisruptionBudget",
            ),
            (
                "/api/v1/namespaces/test-ns/configmaps/test-cluster-kubeconfig-publisher",
                "ConfigMap",
            ),
            (
                "/api/v1/namespaces/test-ns/configmaps/test-cluster-registries",
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
                "PodDisruptionBudget" => "policy/v1",
                _ => "v1",
            };
            // Derive the resource name from the trailing path segment so the
            // returned body looks plausibly real to the kube client.
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

        let result = backend.delete("test-cluster", "test-ns").await;
        assert!(result.is_ok(), "delete should succeed: {result:?}");
        // MockServer's Drop verifies the `.expect(1)` assertions — any
        // missing DELETE call panics here.
    }

    /// Idempotency: re-running `delete()` on an instance whose resources
    /// were already deleted (every backend resource returns 404) MUST
    /// succeed. This is the operational case where the finalizer-driven
    /// delete path retries after a partial failure.
    #[tokio::test]
    async fn test_delete_is_idempotent_when_all_resources_missing() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let backend = K3sBackend::new(client, Default::default());

        // Catch-all 404 for every DELETE the backend will issue.
        Mock::given(method("DELETE"))
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
        let backend = K3sBackend::new(client, Default::default());

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

    /// Regression: `ClusterPool.spec.resources` must reach the k3s-server
    /// container. Before this fix, the field was declared in the CRD but
    /// silently dropped by the reconciler/backend, leaving pods as
    /// BestEffort and first-to-evict under host pressure — see
    /// `kunobi-ninja/kobe#NN` (ci-k3s-kunobi pool stuck Failing 2026-05-20).
    #[test]
    fn test_build_server_container_propagates_resources() {
        use crate::crd::ResourceRequirements;
        use k8s_openapi::apimachinery::pkg::api::resource::Quantity;

        let mut config = base_config();
        config.resources = Some(ResourceRequirements {
            limits: [("cpu".to_string(), "1".to_string())].into(),
            requests: [("memory".to_string(), "512Mi".to_string())].into(),
        });

        let container = K3sBackend::build_server_container("c", "ns", &config, None);
        let r = container
            .resources
            .as_ref()
            .expect("k3s-server container must carry resources when pool sets them");
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
    fn test_build_agent_deployment_propagates_resources() {
        use crate::crd::ResourceRequirements;

        let mut config = base_config();
        config.resources = Some(ResourceRequirements {
            limits: [("memory".to_string(), "1Gi".to_string())].into(),
            requests: BTreeMap::new(),
        });

        let deploy = K3sBackend::build_agent_deployment("c", "ns", &config, 1);
        let pod = deploy.spec.unwrap().template.spec.unwrap();
        let agent = &pod.containers[0];
        let r = agent
            .resources
            .as_ref()
            .expect("k3s-agent container must carry resources when pool sets them");
        assert!(
            r.limits.as_ref().unwrap().contains_key("memory"),
            "memory limit must propagate to agent; got {r:?}"
        );
    }

    /// Regression: when no resources are set on the pool, the backend
    /// must NOT emit an empty `resources: {}` block — that would still
    /// land the pod as BestEffort but with a noisier manifest. Behavior
    /// must stay byte-identical to clusters created before the
    /// propagation fix.
    #[test]
    fn test_build_server_container_no_resources_stays_none() {
        let config = base_config();
        assert!(config.resources.is_none());
        let container = K3sBackend::build_server_container("c", "ns", &config, None);
        assert!(
            container.resources.is_none(),
            "absent pool.spec.resources must yield no resources block; got {:?}",
            container.resources
        );
    }

    /// Regression: without any placement set, the server StatefulSet
    /// renders no `affinity` block — manifests stay byte-identical to
    /// clusters created before placement existed.
    #[test]
    fn test_build_server_statefulset_no_spread_renders_no_affinity() {
        let config = base_config();
        assert!(config.placement.is_none());
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let pod_spec = sts.spec.unwrap().template.spec.unwrap();
        assert!(pod_spec.affinity.is_none());
    }

    /// `intraInstance.mode: SameHost` alone must NOT cause the server
    /// StatefulSet to grow an `affinity` block — intra-instance is an
    /// agent-deployment concern, the server is the anchor pod.
    #[test]
    fn test_build_server_statefulset_samehost_alone_renders_no_affinity() {
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
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let pod_spec = sts.spec.unwrap().template.spec.unwrap();
        assert!(pod_spec.affinity.is_none());
    }

    /// `interInstance.spread.strength: Preferred` emits a soft
    /// `podAntiAffinity` selecting all kobe-operator-managed k3s server
    /// pods on the topology key.
    #[test]
    fn test_build_server_statefulset_spread_preferred_emits_anti_affinity() {
        use crate::crd::{InterInstancePlacement, InterInstanceSpread, Placement, SpreadStrength};
        let placement = Placement {
            inter_instance: Some(InterInstancePlacement {
                spread: Some(InterInstanceSpread {
                    strength: SpreadStrength::Preferred,
                    topology_key: "kubernetes.io/hostname".to_string(),
                }),
            }),
            ..Default::default()
        };
        let config = ClusterConfig {
            placement: Some(placement),
            ..base_config()
        };
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let pod_spec = sts.spec.unwrap().template.spec.unwrap();
        let affinity = pod_spec.affinity.expect("affinity present");
        let anti = affinity
            .pod_anti_affinity
            .expect("pod_anti_affinity present");
        assert!(
            anti.required_during_scheduling_ignored_during_execution
                .is_none(),
            "Preferred must not emit required terms",
        );
        let terms = anti
            .preferred_during_scheduling_ignored_during_execution
            .expect("preferred terms present");
        assert_eq!(terms.len(), 1);
        let weighted = &terms[0];
        assert_eq!(weighted.weight, 100);
        assert_eq!(
            weighted.pod_affinity_term.topology_key,
            "kubernetes.io/hostname"
        );
        let match_labels = weighted
            .pod_affinity_term
            .label_selector
            .as_ref()
            .unwrap()
            .match_labels
            .as_ref()
            .unwrap();
        assert_eq!(
            match_labels.get("app.kubernetes.io/managed-by"),
            Some(&MANAGED_BY.to_string()),
        );
        assert_eq!(
            match_labels.get("kobe.kunobi.ninja/role"),
            Some(&"server".to_string()),
        );
        // Must NOT carry the per-cluster label — that would match only
        // the pod's own siblings (replicas=1) and never spread anything.
        assert!(
            !match_labels.contains_key("kobe.kunobi.ninja/cluster"),
            "selector must match across pool members, not self only",
        );
        // Standalone case (pool_name=None) — selector is host-wide.
        assert!(
            !match_labels.contains_key("kobe.kunobi.ninja/pool"),
            "pool label must be absent on the selector when pool_name is None",
        );
    }

    /// Regression: when `pool_name` is set on `ClusterConfig` (the
    /// pool-managed case), the inter-instance anti-affinity selector
    /// scopes to siblings of the SAME pool. Without this, a multi-pool
    /// host cluster running `Required` spread on two pools deadlocks
    /// scheduling (cross-pool anti-affinity collapses placement).
    #[test]
    fn test_spread_selector_is_pool_scoped_when_pool_name_set() {
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
        let config = ClusterConfig {
            placement: Some(placement),
            pool_name: Some("ci-k3s-kunobi".to_string()),
            ..base_config()
        };
        let sts =
            K3sBackend::build_server_statefulset("pool-ci-k3s-kunobi-7", "ns", &config, None, 1);
        let pod_spec = sts.spec.unwrap().template.spec.unwrap();
        let anti = pod_spec.affinity.unwrap().pod_anti_affinity.unwrap();
        let term = &anti
            .required_during_scheduling_ignored_during_execution
            .expect("required term present")[0];
        let match_labels = term
            .label_selector
            .as_ref()
            .unwrap()
            .match_labels
            .as_ref()
            .unwrap();
        assert_eq!(
            match_labels.get("kobe.kunobi.ninja/pool"),
            Some(&"ci-k3s-kunobi".to_string()),
            "spread selector must include pool label to scope to same-pool siblings",
        );
        assert_eq!(
            match_labels.get("kobe.kunobi.ninja/role"),
            Some(&"server".to_string()),
        );

        // The pod template itself must also carry the pool label so the
        // selector can find it (selector → label match on the target pods).
        let pod_labels = sts
            .metadata
            .labels
            .as_ref()
            .expect("pod template labels present");
        assert_eq!(
            pod_labels.get("kobe.kunobi.ninja/pool"),
            Some(&"ci-k3s-kunobi".to_string()),
        );
    }

    /// `interInstance.spread.strength: Required` emits a hard
    /// `podAntiAffinity` term.
    #[test]
    fn test_build_server_statefulset_spread_required_emits_required_term() {
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
        let config = ClusterConfig {
            placement: Some(placement),
            ..base_config()
        };
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let pod_spec = sts.spec.unwrap().template.spec.unwrap();
        let anti = pod_spec.affinity.unwrap().pod_anti_affinity.unwrap();
        assert!(
            anti.preferred_during_scheduling_ignored_during_execution
                .is_none(),
            "Required must not emit preferred terms",
        );
        let terms = anti
            .required_during_scheduling_ignored_during_execution
            .expect("required terms present");
        assert_eq!(terms.len(), 1);
        assert_eq!(terms[0].topology_key, "kubernetes.io/hostname");
    }

    #[test]
    fn test_kubelet_shared_mount_server_emits_mount_volume_and_env() {
        let config = ClusterConfig {
            kubelet_shared_mount: Some(KubeletSharedMountConfig::default()),
            ..base_config()
        };
        let sts = K3sBackend::build_server_statefulset("my-cluster", "ns", &config, None, 1);
        let pod_spec = sts.spec.unwrap().template.spec.unwrap();

        let server = pod_spec
            .containers
            .iter()
            .find(|c| c.name == "k3s-server")
            .expect("k3s-server container present");

        // 1. VolumeMount: /var/lib/kubelet, Bidirectional, subPathExpr $(POD_NAME)
        let mount = server
            .volume_mounts
            .as_ref()
            .expect("server has volume_mounts")
            .iter()
            .find(|m| m.name == "kubelet-root")
            .expect("kubelet-root mount missing on server");
        assert_eq!(mount.mount_path, "/var/lib/kubelet");
        assert_eq!(mount.mount_propagation.as_deref(), Some("Bidirectional"));
        assert_eq!(mount.sub_path_expr.as_deref(), Some("$(POD_NAME)"));

        // 2. POD_NAME env wired via downward API from metadata.name
        let env = server.env.as_ref().expect("server has env");
        let pod_name = env
            .iter()
            .find(|e| e.name == "POD_NAME")
            .expect("POD_NAME env missing on server");
        let field_ref = pod_name
            .value_from
            .as_ref()
            .and_then(|s| s.field_ref.as_ref())
            .expect("POD_NAME must use fieldRef");
        assert_eq!(field_ref.field_path, "metadata.name");

        // 3. hostPath volume at the expected per-cluster path
        let vol = pod_spec
            .volumes
            .as_ref()
            .expect("pod has volumes")
            .iter()
            .find(|v| v.name == "kubelet-root")
            .expect("kubelet-root volume missing on pod spec");
        let hp = vol.host_path.as_ref().expect("must be hostPath");
        assert_eq!(hp.path, "/var/lib/kobe/leases/my-cluster/kubelets");
        assert_eq!(hp.type_.as_deref(), Some("DirectoryOrCreate"));
    }

    #[test]
    fn test_kubelet_shared_mount_agent_emits_mount_volume_and_env() {
        let config = ClusterConfig {
            kubelet_shared_mount: Some(KubeletSharedMountConfig::default()),
            ..base_config()
        };
        let deploy = K3sBackend::build_agent_deployment("my-cluster", "ns", &config, 2);
        let pod_spec = deploy.spec.unwrap().template.spec.unwrap();

        let agent = pod_spec
            .containers
            .iter()
            .find(|c| c.name == "k3s-agent")
            .expect("k3s-agent container present");

        // 1. VolumeMount
        let mount = agent
            .volume_mounts
            .as_ref()
            .expect("agent has volume_mounts")
            .iter()
            .find(|m| m.name == "kubelet-root")
            .expect("kubelet-root mount missing on agent");
        assert_eq!(mount.mount_path, "/var/lib/kubelet");
        assert_eq!(mount.mount_propagation.as_deref(), Some("Bidirectional"));
        assert_eq!(mount.sub_path_expr.as_deref(), Some("$(POD_NAME)"));

        // 2. POD_NAME env via downward API
        let env = agent.env.as_ref().expect("agent has env");
        let field_ref = env
            .iter()
            .find(|e| e.name == "POD_NAME")
            .and_then(|e| e.value_from.as_ref())
            .and_then(|s| s.field_ref.as_ref())
            .expect("POD_NAME via fieldRef missing on agent");
        assert_eq!(field_ref.field_path, "metadata.name");

        // 3. hostPath volume
        let vol = pod_spec
            .volumes
            .as_ref()
            .expect("pod has volumes")
            .iter()
            .find(|v| v.name == "kubelet-root")
            .expect("kubelet-root volume missing on agent pod spec");
        let hp = vol.host_path.as_ref().expect("hostPath");
        assert_eq!(hp.path, "/var/lib/kobe/leases/my-cluster/kubelets");
        assert_eq!(hp.type_.as_deref(), Some("DirectoryOrCreate"));
    }

    #[test]
    fn test_kubelet_shared_mount_disabled_by_default() {
        let config = base_config();
        assert!(
            config.kubelet_shared_mount.is_none(),
            "guard for the rest of the test"
        );

        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let server_spec = sts.spec.unwrap().template.spec.unwrap();
        let server = server_spec
            .containers
            .iter()
            .find(|c| c.name == "k3s-server")
            .unwrap();
        assert!(
            server
                .volume_mounts
                .as_ref()
                .map(|v| v.iter().all(|m| m.name != "kubelet-root"))
                .unwrap_or(true),
            "server must NOT have kubelet-root mount by default"
        );
        assert!(
            server_spec
                .volumes
                .as_ref()
                .map(|v| v.iter().all(|m| m.name != "kubelet-root"))
                .unwrap_or(true),
            "server pod must NOT have kubelet-root volume by default"
        );
        assert!(
            server.env.is_none()
                || server
                    .env
                    .as_ref()
                    .unwrap()
                    .iter()
                    .all(|e| e.name != "POD_NAME"),
            "server must NOT have POD_NAME env by default"
        );

        let deploy = K3sBackend::build_agent_deployment("c", "ns", &config, 1);
        let agent_spec = deploy.spec.unwrap().template.spec.unwrap();
        let agent = agent_spec
            .containers
            .iter()
            .find(|c| c.name == "k3s-agent")
            .unwrap();
        assert!(
            agent
                .volume_mounts
                .as_ref()
                .map(|v| v.iter().all(|m| m.name != "kubelet-root"))
                .unwrap_or(true),
            "agent must NOT have kubelet-root mount by default"
        );
        assert!(
            agent_spec
                .volumes
                .as_ref()
                .map(|v| v.iter().all(|m| m.name != "kubelet-root"))
                .unwrap_or(true),
            "agent pod must NOT have kubelet-root volume by default"
        );
        assert!(
            agent.env.is_none()
                || agent
                    .env
                    .as_ref()
                    .unwrap()
                    .iter()
                    .all(|e| e.name != "POD_NAME"),
            "agent must NOT have POD_NAME env by default"
        );
    }

    #[test]
    fn test_kubelet_shared_mount_server_only() {
        let config = ClusterConfig {
            kubelet_shared_mount: Some(KubeletSharedMountConfig {
                server: true,
                agents: false,
                ..KubeletSharedMountConfig::default()
            }),
            ..base_config()
        };

        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let server = sts.spec.unwrap().template.spec.unwrap();
        let server_c = server
            .containers
            .iter()
            .find(|c| c.name == "k3s-server")
            .unwrap();
        assert!(
            server_c
                .volume_mounts
                .as_ref()
                .unwrap()
                .iter()
                .any(|m| m.name == "kubelet-root"),
            "server mount expected"
        );

        let deploy = K3sBackend::build_agent_deployment("c", "ns", &config, 1);
        let agent_spec = deploy.spec.unwrap().template.spec.unwrap();
        let agent = agent_spec
            .containers
            .iter()
            .find(|c| c.name == "k3s-agent")
            .unwrap();
        assert!(
            agent
                .volume_mounts
                .as_ref()
                .map(|v| v.iter().all(|m| m.name != "kubelet-root"))
                .unwrap_or(true),
            "agent mount must NOT be present when agents=false"
        );
    }

    #[test]
    fn test_kubelet_shared_mount_agents_only() {
        let config = ClusterConfig {
            kubelet_shared_mount: Some(KubeletSharedMountConfig {
                server: false,
                agents: true,
                ..KubeletSharedMountConfig::default()
            }),
            ..base_config()
        };

        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let server_spec = sts.spec.unwrap().template.spec.unwrap();
        let server_c = server_spec
            .containers
            .iter()
            .find(|c| c.name == "k3s-server")
            .unwrap();
        assert!(
            server_c
                .volume_mounts
                .as_ref()
                .map(|v| v.iter().all(|m| m.name != "kubelet-root"))
                .unwrap_or(true),
            "server mount must NOT be present when server=false"
        );

        let deploy = K3sBackend::build_agent_deployment("c", "ns", &config, 1);
        let agent_spec = deploy.spec.unwrap().template.spec.unwrap();
        let agent = agent_spec
            .containers
            .iter()
            .find(|c| c.name == "k3s-agent")
            .unwrap();
        assert!(
            agent
                .volume_mounts
                .as_ref()
                .unwrap()
                .iter()
                .any(|m| m.name == "kubelet-root"),
            "agent mount expected"
        );
    }

    #[test]
    fn test_kubelet_shared_mount_honors_host_path_root_override() {
        let config = ClusterConfig {
            kubelet_shared_mount: Some(KubeletSharedMountConfig {
                host_path_root: "/data/kobe/leases".to_string(),
                ..KubeletSharedMountConfig::default()
            }),
            ..base_config()
        };
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let pod = sts.spec.unwrap().template.spec.unwrap();
        let vol = pod
            .volumes
            .as_ref()
            .unwrap()
            .iter()
            .find(|v| v.name == "kubelet-root")
            .unwrap();
        assert_eq!(
            vol.host_path.as_ref().unwrap().path,
            "/data/kobe/leases/c/kubelets"
        );

        let deploy = K3sBackend::build_agent_deployment("c", "ns", &config, 1);
        let apod = deploy.spec.unwrap().template.spec.unwrap();
        let avol = apod
            .volumes
            .as_ref()
            .unwrap()
            .iter()
            .find(|v| v.name == "kubelet-root")
            .unwrap();
        assert_eq!(
            avol.host_path.as_ref().unwrap().path,
            "/data/kobe/leases/c/kubelets"
        );
    }

    #[test]
    fn test_kubelet_shared_mount_path_includes_cluster_name() {
        let config = ClusterConfig {
            kubelet_shared_mount: Some(KubeletSharedMountConfig::default()),
            ..base_config()
        };
        let sts1 = K3sBackend::build_server_statefulset("cluster-a", "ns", &config, None, 1);
        let sts2 = K3sBackend::build_server_statefulset("cluster-b", "ns", &config, None, 1);

        let p1 = sts1
            .spec
            .unwrap()
            .template
            .spec
            .unwrap()
            .volumes
            .unwrap()
            .into_iter()
            .find(|v| v.name == "kubelet-root")
            .unwrap()
            .host_path
            .unwrap()
            .path;
        let p2 = sts2
            .spec
            .unwrap()
            .template
            .spec
            .unwrap()
            .volumes
            .unwrap()
            .into_iter()
            .find(|v| v.name == "kubelet-root")
            .unwrap()
            .host_path
            .unwrap()
            .path;

        assert_ne!(p1, p2);
        assert!(p1.contains("cluster-a"));
        assert!(p2.contains("cluster-b"));
    }

    #[test]
    fn test_kubelet_shared_mount_coexists_with_persistence() {
        let config = ClusterConfig {
            persistence: Some(PersistenceConfig {
                storage_type: Some("dynamic".to_string()),
                storage_class_name: None,
                storage_request_size: Some("5Gi".to_string()),
            }),
            kubelet_shared_mount: Some(KubeletSharedMountConfig::default()),
            ..base_config()
        };
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let sts_spec = sts.spec.unwrap();
        let pod = sts_spec.template.spec.unwrap();

        let server = pod
            .containers
            .iter()
            .find(|c| c.name == "k3s-server")
            .unwrap();
        let mounts = server.volume_mounts.as_ref().unwrap();
        assert!(mounts.iter().any(|m| m.name == "data"), "data mount kept");
        assert!(
            mounts.iter().any(|m| m.name == "kubelet-root"),
            "kubelet-root mount added"
        );
        // The `data` volume is now backed by a volumeClaimTemplate (PVC), not a
        // pod-level emptyDir; only `kubelet-root` remains a pod volume.
        let volumes = pod.volumes.as_ref().unwrap();
        assert!(
            !volumes.iter().any(|v| v.name == "data"),
            "data must be a PVC (volumeClaimTemplate), not a pod volume"
        );
        assert!(
            volumes.iter().any(|v| v.name == "kubelet-root"),
            "kubelet-root volume added"
        );
        assert!(
            sts_spec
                .volume_claim_templates
                .as_ref()
                .is_some_and(|t| t.iter().any(|p| p.metadata.name.as_deref() == Some("data"))),
            "a `data` volumeClaimTemplate must back the persistence mount"
        );
    }

    #[test]
    fn test_kubelet_shared_mount_coexists_with_registry_mirrors() {
        let mut mirrors = std::collections::BTreeMap::new();
        mirrors.insert(
            "docker.io".to_string(),
            vec!["https://registry.example.com".to_string()],
        );
        let config = ClusterConfig {
            registry_mirrors: Some(mirrors),
            kubelet_shared_mount: Some(KubeletSharedMountConfig::default()),
            ..base_config()
        };
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let pod = sts.spec.unwrap().template.spec.unwrap();
        let server = pod
            .containers
            .iter()
            .find(|c| c.name == "k3s-server")
            .unwrap();
        let mounts = server.volume_mounts.as_ref().unwrap();
        assert!(
            mounts.iter().any(|m| m.name == "registries-config"),
            "registries mount kept"
        );
        assert!(
            mounts.iter().any(|m| m.name == "kubelet-root"),
            "kubelet-root mount added"
        );
        let volumes = pod.volumes.as_ref().unwrap();
        assert!(
            volumes.iter().any(|v| v.name == "registries-config"),
            "registries-config volume kept"
        );
        assert!(
            volumes.iter().any(|v| v.name == "kubelet-root"),
            "kubelet-root volume added"
        );
    }

    // ─────────────────────────────────────────────────────────────────
    // Placement API tests — additional coverage (selector + tolerations
    // + custom topology key)
    // ─────────────────────────────────────────────────────────────────

    fn config_with_placement(placement: crate::crd::Placement) -> ClusterConfig {
        ClusterConfig {
            placement: Some(placement),
            ..base_config()
        }
    }

    #[test]
    fn test_placement_node_selector_renders_node_affinity_on_server_and_agent() {
        use crate::crd::{NodePlacement as NewNodePlacement, Placement};
        let mut labels = BTreeMap::new();
        labels.insert(
            "topology.kubernetes.io/zone".to_string(),
            "us-east-1a".to_string(),
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

        // Server StatefulSet
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
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
        assert_eq!(reqs[0].operator, "In");
        assert_eq!(reqs[0].values.as_ref().unwrap()[0], "us-east-1a");

        // Agent Deployment
        let deploy = K3sBackend::build_agent_deployment("c", "ns", &config, 1);
        let pod = deploy.spec.unwrap().template.spec.unwrap();
        let na = pod
            .affinity
            .expect("affinity present")
            .node_affinity
            .expect("agent node_affinity present");
        assert!(
            na.required_during_scheduling_ignored_during_execution
                .is_some()
        );
    }

    #[test]
    fn test_placement_node_tolerations_propagate_to_server_and_agent() {
        use crate::crd::{NodePlacement as NewNodePlacement, Placement};
        let tol = Toleration {
            key: Some("dedicated".to_string()),
            operator: Some("Equal".to_string()),
            value: Some("gpu".to_string()),
            effect: Some("NoSchedule".to_string()),
            ..Default::default()
        };
        let placement = Placement {
            node: Some(NewNodePlacement {
                selector: None,
                tolerations: vec![tol.clone()],
            }),
            ..Default::default()
        };
        let config = config_with_placement(placement);

        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let pod = sts.spec.unwrap().template.spec.unwrap();
        let tols = pod.tolerations.expect("server tolerations present");
        assert_eq!(tols.len(), 1);
        assert_eq!(tols[0].key.as_deref(), Some("dedicated"));

        let deploy = K3sBackend::build_agent_deployment("c", "ns", &config, 1);
        let pod = deploy.spec.unwrap().template.spec.unwrap();
        let tols = pod.tolerations.expect("agent tolerations present");
        assert_eq!(tols.len(), 1);
        assert_eq!(tols[0].effect.as_deref(), Some("NoSchedule"));
    }

    #[test]
    fn test_placement_inter_instance_spread_custom_topology_key_is_honored() {
        use crate::crd::{InterInstancePlacement, InterInstanceSpread, Placement, SpreadStrength};
        let placement = Placement {
            inter_instance: Some(InterInstancePlacement {
                spread: Some(InterInstanceSpread {
                    strength: SpreadStrength::Preferred,
                    topology_key: "topology.kubernetes.io/zone".to_string(),
                }),
            }),
            ..Default::default()
        };
        let config = config_with_placement(placement);
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        let pod = sts.spec.unwrap().template.spec.unwrap();
        let anti = pod.affinity.unwrap().pod_anti_affinity.unwrap();
        let term = &anti
            .preferred_during_scheduling_ignored_during_execution
            .unwrap()[0];
        assert_eq!(
            term.pod_affinity_term.topology_key,
            "topology.kubernetes.io/zone"
        );
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
                "containers": [{ "name": "k3s", "image": "rancher/k3s:v1.31.3-k3s1" }]
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
                "containers": [{ "name": "k3s", "image": "rancher/k3s:v1.31.3-k3s1" }]
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
        K3sBackend::force_delete_instance_pods(&pods, cluster).await;
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
        K3sBackend::force_delete_instance_pods(&pods, cluster).await;
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
        K3sBackend::force_delete_instance_pods(&pods, cluster).await;
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
        K3sBackend::force_delete_instance_pods(&pods, cluster).await;
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
        K3sBackend::force_delete_instance_pods(&pods, cluster).await;
        // MockServer Drop validates that the mock with the exact labelSelector
        // was called exactly once — any different labelSelector would not match
        // and the .expect(1) would fail.
    }

    // =================================================================
    // HA (servers>1) control-plane tests (#148)
    // =================================================================

    /// (1) The StatefulSet replica count tracks the `replicas` arg the builder
    /// is given (callers pass `config.servers.max(1)`), NOT a hardcoded 1.
    #[test]
    fn test_build_server_statefulset_replicas_scale() {
        let config = base_config();
        let sts3 = K3sBackend::build_server_statefulset("c", "ns", &config, None, 3);
        assert_eq!(sts3.spec.as_ref().unwrap().replicas, Some(3));

        let sts1 = K3sBackend::build_server_statefulset("c", "ns", &config, None, 1);
        assert_eq!(sts1.spec.as_ref().unwrap().replicas, Some(1));
    }

    /// (2) Clamp: a `0` replica count (servers=0 → `.max(1)` at the call site,
    /// but the builder still renders whatever it's handed) — verify the
    /// single-server callers' `.max(1)` clamp produces `Some(1)`.
    #[test]
    fn test_build_server_statefulset_clamp_zero() {
        // Mirror the create() call site: servers=0 → config.servers.max(1) == 1.
        let servers: u32 = 0;
        let config = base_config();
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, servers.max(1));
        assert_eq!(sts.spec.as_ref().unwrap().replicas, Some(1));
    }

    /// (3) podManagementPolicy MUST be OrderedReady (load-bearing for HA
    /// bootstrap; Parallel would race N servers and diverge CAs).
    #[test]
    fn test_build_server_statefulset_pod_management_policy_ordered_ready() {
        let config = base_config();
        let sts = K3sBackend::build_server_statefulset("c", "ns", &config, None, 3);
        assert_eq!(
            sts.spec.as_ref().unwrap().pod_management_policy.as_deref(),
            Some("OrderedReady")
        );
        // And the default updateStrategy is left untouched (not pinned).
        assert!(sts.spec.as_ref().unwrap().update_strategy.is_none());
    }

    /// (4) The publisher sidecar carries a downward-API POD_NAME env var bound
    /// to `metadata.name`, used to elect ordinal-0 as the sole writer.
    #[test]
    fn test_publisher_sidecar_has_pod_name_field_ref() {
        let sidecar = K3sBackend::build_publisher_sidecar(
            "c",
            "ns",
            "rancher/k3s:v1.31.3-k3s1",
            "cluster.local",
        );
        let env = sidecar.env.as_ref().expect("sidecar must have env");
        let pod_name = env
            .iter()
            .find(|e| e.name == "POD_NAME")
            .expect("sidecar must have POD_NAME env");
        let field_ref = pod_name
            .value_from
            .as_ref()
            .and_then(|s| s.field_ref.as_ref())
            .expect("POD_NAME must be a downward-API field_ref");
        assert_eq!(field_ref.field_path, "metadata.name");
        assert!(pod_name.value.is_none());
    }

    /// (5) The publisher script gates the rewrite+publish behind the `*-0)`
    /// case so only ordinal-0 ever touches the Secret.
    #[test]
    fn test_publisher_script_elects_ordinal_zero() {
        let script = KUBECONFIG_PUBLISHER_SCRIPT;
        assert!(
            script.contains("*-0)"),
            "script must branch on the -0 ordinal: {script}"
        );
        // The publish (kubectl apply via create secret) must live INSIDE the
        // *-0) branch — i.e. it appears after the case guard.
        let zero_idx = script.find("*-0)").expect("must contain *-0)");
        let publish_idx = script
            .find("kubectl create secret generic")
            .expect("must publish a secret");
        assert!(
            publish_idx > zero_idx,
            "publish must be inside the *-0) branch"
        );
        // Idempotent upsert (dry-run | apply) and a bounded retry loop.
        assert!(script.contains("--dry-run=client"));
        assert!(script.contains("kubectl apply -f -"));
        assert!(script.contains("until kubectl create secret"));
    }

    /// (6) The HA gate rejects servers>1 without a datastore, and allows the
    /// safe combinations.
    #[test]
    fn test_ha_requires_datastore_gate() {
        let err = ha_requires_datastore(3, false).expect_err("servers>1 + no datastore must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("external datastore"),
            "gate error must mention external datastore: {msg}"
        );

        assert!(ha_requires_datastore(3, true).is_ok());
        assert!(ha_requires_datastore(1, false).is_ok());
        assert!(ha_requires_datastore(2, true).is_ok());
        // servers==2 without datastore is also HA → rejected.
        assert!(ha_requires_datastore(2, false).is_err());
    }

    /// (7) The Service selector is independent of the replica count — it
    /// selects all server pods regardless of how many there are.
    #[test]
    fn test_service_selector_independent_of_replica_count() {
        let mut config = base_config();
        config.servers = 1;
        let svc1 = K3sBackend::build_service("c", "ns", &config);
        config.servers = 5;
        let svc5 = K3sBackend::build_service("c", "ns", &config);
        assert_eq!(
            svc1.spec.as_ref().unwrap().selector,
            svc5.spec.as_ref().unwrap().selector,
            "service selector must not depend on the replica count"
        );
        // And it is the role=server label set, not a per-pod identity.
        let sel = svc1.spec.as_ref().unwrap().selector.as_ref().unwrap();
        assert_eq!(
            sel.get("kobe.kunobi.ninja/role").map(String::as_str),
            Some("server")
        );
    }

    /// (8) TLS SANs include both the short and FQDN service names and NO
    /// per-pod SAN — the cert is shared across all replicas.
    #[test]
    fn test_server_tls_sans_short_and_fqdn_no_per_pod() {
        let config = base_config();
        let container = K3sBackend::build_server_container("my-cluster", "ns", &config, None);
        let args = container.args.as_ref().unwrap();
        assert!(args.contains(&"--tls-san=my-cluster-server.ns.svc".to_string()));
        assert!(args.contains(&"--tls-san=my-cluster-server.ns.svc.cluster.local".to_string()));
        // No SAN references a StatefulSet pod ordinal (e.g. *-server-0).
        assert!(
            !args
                .iter()
                .any(|a| a.starts_with("--tls-san=") && a.contains("-server-")),
            "TLS SANs must not pin per-pod identities: {args:?}"
        );
    }

    /// (9) The pure readiness predicate: false when have<want, true when
    /// have>=want, and the single-server case (1 ready of 1) is Ready.
    #[test]
    fn test_server_sts_ready_predicate() {
        // have < want
        assert!(!server_sts_ready(Some(3), Some(2)));
        assert!(!server_sts_ready(Some(3), None));
        // have == want
        assert!(server_sts_ready(Some(3), Some(3)));
        // have > want (scale-down transient)
        assert!(server_sts_ready(Some(2), Some(3)));
        // single-server: 1 ready of 1
        assert!(server_sts_ready(Some(1), Some(1)));
        assert!(!server_sts_ready(Some(1), Some(0)));
        // no desired replicas (status not yet populated) → not ready
        assert!(!server_sts_ready(Some(0), Some(0)));
        assert!(!server_sts_ready(None, None));
    }

    /// (10) The readiness probe is an HTTPS GET on /readyz:6443 (not a bare TCP
    /// connect), so a replica only counts Ready once its apiserver serves with
    /// the shared cluster cert.
    #[test]
    fn test_server_readiness_probe_is_readyz_https() {
        let config = base_config();
        let container = K3sBackend::build_server_container("c", "ns", &config, None);
        let probe = container.readiness_probe.as_ref().expect("readiness probe");
        assert!(
            probe.tcp_socket.is_none(),
            "readiness probe must no longer be a bare TCP connect"
        );
        let http = probe
            .http_get
            .as_ref()
            .expect("readiness probe must be http_get");
        assert_eq!(http.path.as_deref(), Some("/readyz"));
        assert_eq!(http.scheme.as_deref(), Some("HTTPS"));
        assert_eq!(http.port, IntOrString::Int(6443));
    }

    /// PDB minAvailable: servers>=3 → servers-1; servers==2 → 1. Selector is
    /// the server pod labels.
    #[test]
    fn test_build_pod_disruption_budget_min_available() {
        let mut config = base_config();

        config.servers = 3;
        let pdb3 = K3sBackend::build_pod_disruption_budget("c", "ns", &config);
        assert_eq!(
            pdb3.spec.as_ref().unwrap().min_available,
            Some(IntOrString::Int(2))
        );

        config.servers = 5;
        let pdb5 = K3sBackend::build_pod_disruption_budget("c", "ns", &config);
        assert_eq!(
            pdb5.spec.as_ref().unwrap().min_available,
            Some(IntOrString::Int(4))
        );

        config.servers = 2;
        let pdb2 = K3sBackend::build_pod_disruption_budget("c", "ns", &config);
        assert_eq!(
            pdb2.spec.as_ref().unwrap().min_available,
            Some(IntOrString::Int(1))
        );

        // Selector is the role=server label set.
        let sel = pdb2
            .spec
            .as_ref()
            .unwrap()
            .selector
            .as_ref()
            .unwrap()
            .match_labels
            .as_ref()
            .unwrap();
        assert_eq!(
            sel.get("kobe.kunobi.ninja/role").map(String::as_str),
            Some("server")
        );
    }
}
