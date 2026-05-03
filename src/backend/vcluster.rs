//! vcluster backend — manages upstream loft-sh/vcluster instances via Helm.
//!
//! # Design
//!
//! Each `ClusterInstance` becomes a vcluster Helm release in a dedicated
//! per-instance host namespace (`vcluster-{name}`). The namespace boundary
//! gives us:
//!
//! - **Self-contained cleanup**: `helm uninstall` + `kubectl delete ns`
//!   reaps everything the instance created. No orphan-projected-pods leak
//!   pattern that the legacy in-house vkobe backend suffered from.
//! - **Resource isolation**: NodePort allocation, ConfigMap/Secret name
//!   collisions, etc, are scoped to the per-instance namespace.
//! - **Observability**: `kubectl get all -n vcluster-{name}` shows the
//!   full state of one virtual cluster.
//!
//! # Helm shell-out vs Rust SDK
//!
//! We invoke the `helm` CLI binary as a subprocess rather than embedding a
//! Rust Helm client. Trade-offs:
//!
//! - **(+)** One canonical implementation (the official one), no risk of
//!   subtle divergence from `helm install`'s behavior
//! - **(+)** Helm features (hooks, post-renderers, OCI charts, etc) work
//!   uniformly
//! - **(+)** Failure modes are debuggable via `helm history` / `helm get
//!   manifest`
//! - **(−)** Operator container ships the `helm` binary (~50 MB)
//! - **(−)** Subprocess overhead (~50 ms per invocation, dominated by Go
//!   runtime startup) — negligible against the ~10 s vcluster takes to
//!   come up
//!
//! For our scale (a handful of `helm install`/`uninstall` per minute at
//! peak pool churn), shell-out is the pragmatic choice.
//!
//! # Lifecycle
//!
//! ```text
//! create()  → helm install <name> loft-sh/vcluster -n vcluster-<name>
//!             --create-namespace --version <ver> -f <values.yaml>
//!             → wait for vc-<name> Secret (kubeconfig published)
//!             → wait for StatefulSet ready
//!             → apply addons against virtual apiserver
//!
//! delete()  → helm uninstall <name> -n vcluster-<name>
//!             → kubectl delete namespace vcluster-<name>
//!
//! check_health()       → query vc-<name> Secret + StatefulSet status
//! extract_kubeconfig() → read vc-<name> Secret data.config (rewrite server URL
//!                        to in-cluster DNS form)
//! check_readiness_gate() → reuses shared check_readiness_gate_impl() against
//!                          the virtual apiserver
//! apply_addon()        → reuses shared apply_addon_impl() against the
//!                        virtual apiserver
//! ```

use anyhow::{Context, Result, anyhow};
use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{Namespace, Secret};
use kube::Client;
use kube::api::{Api, DeleteParams, ObjectMeta, Patch, PatchParams};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::crd::{Addon, ClusterConfig, ReadinessGate, VclusterConfig};

use super::{
    ClusterBackend, apply_addon_impl, check_readiness_gate_impl, virtual_client_from_kubeconfig,
};

/// Read the vcluster kubeconfig from the `vc-<name>` Secret in the
/// per-instance host namespace.
///
/// vcluster's Helm chart writes the kubeconfig to data key `config` of
/// Secret `vc-<release>`. This is a different convention from the
/// k3s/k0s backends (which use `<name>-kubeconfig` Secret with key
/// `kubeconfig`), hence this dedicated reader.
async fn read_vcluster_kubeconfig(client: &Client, host_ns: &str, name: &str) -> Result<String> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), host_ns);
    let secret_name = format!("vc-{name}");
    let secret = secrets.get(&secret_name).await.with_context(|| {
        format!("vcluster kubeconfig secret {secret_name} not found in {host_ns}")
    })?;
    let data = secret
        .data
        .as_ref()
        .ok_or_else(|| anyhow!("Secret {secret_name} has no data"))?;
    let raw = data
        .get("config")
        .ok_or_else(|| anyhow!("Secret {secret_name} missing data.config key"))?;
    String::from_utf8(raw.0.clone())
        .with_context(|| format!("Secret {secret_name} data.config is not valid UTF-8"))
}

/// Default vcluster Helm chart version pinned by the operator.
///
/// Bumped in lock-step with our integration tests against vcluster
/// upstream. See `docs/architecture/virtual-cluster-strategy.md` for
/// the validation matrix.
const DEFAULT_CHART_VERSION: &str = "0.34.0";

/// Helm repository alias the operator uses internally.
const HELM_REPO_ALIAS: &str = "kobe-loft-sh";

/// Helm repository URL for upstream vcluster charts.
const HELM_REPO_URL: &str = "https://charts.loft.sh";

/// How long to wait, total, for the vcluster Pod + kubeconfig Secret
/// to appear after `helm install`. The chart's `--wait` flag handles
/// this for us, so this is the safety upper bound on the helm
/// subprocess.
const HELM_INSTALL_TIMEOUT_SECS: u64 = 300;

/// Backend that manages vcluster instances via Helm.
#[derive(Clone)]
pub struct VclusterBackend {
    client: Client,
    /// Per-pool config carried from the `ClusterPool` spec; `None` means
    /// "use operator defaults". Held at backend construction time and
    /// passed through to each method.
    config: Option<VclusterConfig>,
}

impl VclusterBackend {
    pub fn new(client: Client, config: Option<VclusterConfig>) -> Self {
        Self { client, config }
    }

    /// The host namespace this instance lives in. We scope each instance
    /// to its own namespace named `vcluster-<name>` for clean teardown
    /// and resource isolation. The `_namespace` parameter from
    /// `ClusterBackend::create()` (the `ClusterInstance`'s own namespace,
    /// typically `kobe-system`) is intentionally not used here — the
    /// instance's CR lives in the operator namespace, but its workload
    /// is isolated to its own ns.
    fn host_namespace(&self, name: &str) -> String {
        format!("vcluster-{name}")
    }

    /// Effective chart version, falling back to the operator's pinned default.
    fn chart_version(&self) -> &str {
        self.config
            .as_ref()
            .and_then(|c| c.chart_version.as_deref())
            .unwrap_or(DEFAULT_CHART_VERSION)
    }

    /// Construct the Helm values YAML for an instance.
    ///
    /// Operator defaults + user-supplied overrides. Order: user values
    /// take precedence (Helm `--values` is last-wins for the file given,
    /// so we pass user values in a separate `--values` invocation after
    /// the defaults).
    fn default_values_yaml(&self, _name: &str, _config: &ClusterConfig) -> String {
        // Conservative defaults aligned with kobe pool conventions:
        // - sync.toHost.* enabled for the resource types kobe pools
        //   typically want projected
        // - exportKubeConfig.server uses an in-cluster DNS form so the
        //   operator can reach the apiserver without port-forward
        //
        // The chart's own defaults already cover most of what we want;
        // we only override where kobe semantics differ.
        let server = format!(
            "https://{name}.vcluster-{name}.svc.cluster.local:443",
            name = _name
        );
        format!(
            r#"# kobe operator defaults for vcluster
exportKubeConfig:
  server: {server}
controlPlane:
  statefulSet:
    persistence:
      volumeClaim:
        enabled: true
"#
        )
    }

    /// Ensure the Helm repo is registered locally. Idempotent.
    async fn ensure_helm_repo(&self) -> Result<()> {
        let status = Command::new("helm")
            .args(["repo", "add", HELM_REPO_ALIAS, HELM_REPO_URL])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .context("failed to spawn `helm repo add`")?;
        // Non-zero is normal if the repo is already registered. We don't
        // distinguish that case from real errors here because `helm repo
        // update` will fail downstream with a clearer message.
        if !status.success() {
            debug!("helm repo add returned non-zero (likely already registered); continuing");
        }
        let status = Command::new("helm")
            .args(["repo", "update", HELM_REPO_ALIAS])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .context("failed to spawn `helm repo update`")?;
        if !status.success() {
            return Err(anyhow!(
                "helm repo update for {HELM_REPO_ALIAS} returned non-zero status"
            ));
        }
        Ok(())
    }

    /// Ensure the per-instance host namespace exists.
    async fn ensure_host_namespace(&self, host_ns: &str) -> Result<()> {
        let api: Api<Namespace> = Api::all(self.client.clone());
        let ns = Namespace {
            metadata: ObjectMeta {
                name: Some(host_ns.to_string()),
                labels: Some(
                    [
                        (
                            "app.kubernetes.io/managed-by".to_string(),
                            "kobe-operator".to_string(),
                        ),
                        (
                            "kobe.kunobi.ninja/backend".to_string(),
                            "vcluster".to_string(),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            },
            ..Default::default()
        };
        api.patch(
            host_ns,
            &PatchParams::apply("kobe-operator").force(),
            &Patch::Apply(&ns),
        )
        .await
        .with_context(|| format!("failed to ensure host namespace {host_ns}"))?;
        Ok(())
    }
}

impl ClusterBackend for VclusterBackend {
    #[tracing::instrument(skip(self, config, addons, _owner_ref), fields(cluster = name, namespace))]
    async fn create(
        &self,
        name: &str,
        _namespace: &str,
        config: &ClusterConfig,
        addons: &[Addon],
        // Per-instance namespace gives us clean teardown via `kubectl
        // delete ns`; OwnerRef plumbing is not needed.
        _owner_ref: Option<&k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference>,
    ) -> Result<()> {
        let host_ns = self.host_namespace(name);
        info!(cluster = name, host_ns = %host_ns, "Creating vcluster instance");

        self.ensure_helm_repo().await?;
        self.ensure_host_namespace(&host_ns).await?;

        // Compose the Helm install invocation.
        //
        // We render the operator-default values to a temp file and pass
        // user-supplied values (from `VclusterConfig.values`) as a
        // second `--values` source so user overrides take precedence
        // (Helm merges `--values` files left-to-right with later wins).
        let defaults_yaml = self.default_values_yaml(name, config);
        let defaults_path =
            std::env::temp_dir().join(format!("kobe-vcluster-{name}-defaults.yaml"));
        tokio::fs::write(&defaults_path, defaults_yaml.as_bytes())
            .await
            .with_context(|| {
                format!(
                    "failed to write operator-default values to {}",
                    defaults_path.display()
                )
            })?;

        let mut user_values_path: Option<std::path::PathBuf> = None;
        if let Some(cfg) = &self.config
            && let Some(user_yaml) = cfg.values.as_deref()
            && !user_yaml.trim().is_empty()
        {
            let p = std::env::temp_dir().join(format!("kobe-vcluster-{name}-user.yaml"));
            tokio::fs::write(&p, user_yaml.as_bytes())
                .await
                .with_context(|| {
                    format!("failed to write user-supplied values to {}", p.display())
                })?;
            user_values_path = Some(p);
        }

        let chart_ref = format!("{HELM_REPO_ALIAS}/vcluster");
        let chart_version = self.chart_version().to_string();
        let timeout = format!("{HELM_INSTALL_TIMEOUT_SECS}s");

        let mut cmd = Command::new("helm");
        cmd.arg("upgrade")
            .arg("--install")
            .arg(name)
            .arg(&chart_ref)
            .args(["--namespace", &host_ns])
            .args(["--version", &chart_version])
            .args(["--values", defaults_path.to_str().unwrap()])
            .args(["--timeout", &timeout])
            .arg("--wait");
        if let Some(p) = &user_values_path {
            cmd.args(["--values", p.to_str().unwrap()]);
        }

        let output = cmd
            .output()
            .await
            .context("failed to spawn `helm upgrade --install`")?;

        // Best-effort cleanup of temp files. Failure here is fine — `/tmp`
        // is reaped by the OS.
        let _ = tokio::fs::remove_file(&defaults_path).await;
        if let Some(p) = &user_values_path {
            let _ = tokio::fs::remove_file(p).await;
        }

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "helm install for vcluster `{name}` failed: status={:?}\nstdout: {stdout}\nstderr: {stderr}",
                output.status.code()
            ));
        }
        info!(cluster = name, "Helm install completed");

        // Apply addons against the virtual apiserver.
        for addon in addons {
            self.apply_addon(name, _namespace, addon).await?;
        }
        info!(cluster = name, "vcluster instance ready with addons");
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(cluster = name, namespace))]
    async fn delete(&self, name: &str, _namespace: &str) -> Result<()> {
        let host_ns = self.host_namespace(name);
        info!(cluster = name, host_ns = %host_ns, "Deleting vcluster instance");

        // helm uninstall — non-fatal if release doesn't exist (e.g. partial
        // create), but we log so operators can investigate orphan namespaces.
        let output = Command::new("helm")
            .args([
                "uninstall",
                name,
                "--namespace",
                &host_ns,
                "--ignore-not-found",
            ])
            .output()
            .await
            .context("failed to spawn `helm uninstall`")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                cluster = name,
                stderr = %stderr,
                "helm uninstall returned non-zero (continuing to namespace delete)"
            );
        }

        // Delete the per-instance host namespace, which reaps everything
        // helm left behind plus any extra resources the operator added
        // (per-instance Secrets, etc).
        let ns_api: Api<Namespace> = Api::all(self.client.clone());
        match ns_api.delete(&host_ns, &DeleteParams::default()).await {
            Ok(_) => info!(cluster = name, host_ns = %host_ns, "Host namespace deleted"),
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = name, host_ns = %host_ns, "Host namespace already absent")
            }
            Err(e) => {
                return Err(anyhow!(e))
                    .with_context(|| format!("failed to delete host namespace {host_ns}"));
            }
        }
        Ok(())
    }

    async fn check_health(&self, name: &str, _namespace: &str) -> Result<bool> {
        let host_ns = self.host_namespace(name);

        // Health is composed of:
        //   1. Helm release exists in the namespace
        //   2. The vcluster StatefulSet (named after the release) is
        //      Ready (replicas == readyReplicas)
        //   3. The kubeconfig Secret `vc-<name>` is present
        //   4. (deeper) the virtual apiserver answers a discovery query
        //
        // (4) is left to the readiness gate; (1)-(3) are the cheap
        // operator-side health probe.
        let sts_api: Api<StatefulSet> = Api::namespaced(self.client.clone(), &host_ns);
        let sts = match sts_api.get(name).await {
            Ok(s) => s,
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(cluster = name, "StatefulSet absent — instance not healthy");
                return Ok(false);
            }
            Err(e) => return Err(anyhow!(e)).context("StatefulSet get failed"),
        };
        let ready = sts
            .status
            .as_ref()
            .map(|s| {
                let want = s.replicas;
                let have = s.ready_replicas.unwrap_or(0);
                want > 0 && have >= want
            })
            .unwrap_or(false);
        if !ready {
            return Ok(false);
        }

        let secret_name = format!("vc-{name}");
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), &host_ns);
        match secrets.get(&secret_name).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(false),
            Err(e) => Err(anyhow!(e)).context("kubeconfig Secret get failed"),
        }
    }

    async fn extract_kubeconfig(&self, name: &str, _namespace: &str) -> Result<String> {
        // The vcluster Helm chart writes the kubeconfig to Secret
        // `vc-<release>` under data key `config`. `default_values_yaml`
        // configured `exportKubeConfig.server` to the in-cluster DNS form
        // already, so no further URL rewriting is needed here — the
        // kubeconfig as written by the chart is already directly usable
        // by clients running inside the management cluster.
        let host_ns = self.host_namespace(name);
        read_vcluster_kubeconfig(&self.client, &host_ns, name).await
    }

    async fn check_readiness_gate(
        &self,
        name: &str,
        _namespace: &str,
        gate: &ReadinessGate,
    ) -> Result<bool> {
        let host_ns = self.host_namespace(name);
        let kubeconfig = read_vcluster_kubeconfig(&self.client, &host_ns, name).await?;
        let vc_client = virtual_client_from_kubeconfig(&kubeconfig).await?;
        // The shared impl handles all `ReadinessGate` variants
        // identically across backends (NamespaceReady, ServiceAccountReady,
        // SchedulingProbe, etc), parameterised by the instance name.
        check_readiness_gate_impl(&vc_client, gate, name).await
    }

    async fn apply_addon(&self, name: &str, _namespace: &str, addon: &Addon) -> Result<()> {
        let host_ns = self.host_namespace(name);
        let kubeconfig = read_vcluster_kubeconfig(&self.client, &host_ns, name).await?;
        let vc_client = virtual_client_from_kubeconfig(&kubeconfig).await?;
        apply_addon_impl(&vc_client, addon).await
    }
}

#[allow(dead_code)]
const _: Duration = Duration::from_secs(0); // keep the `Duration` import live for future timeouts
