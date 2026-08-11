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

/// Removes temporary Helm values files when dropped, so an early return (a
/// failed write or a failed `helm` spawn) does not leak them. Best-effort and
/// synchronous — these are small files under the OS temp dir.
#[derive(Default)]
struct TempValuesGuard(Vec<std::path::PathBuf>);

impl Drop for TempValuesGuard {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

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

/// Build the argument vector for the `helm upgrade --install` invocation
/// issued by [`VclusterBackend::create`].
///
/// Split out of `create()` purely so the ordering contract can be pinned by
/// a test: Helm merges repeated `--values` files left-to-right with later
/// wins, so the operator defaults MUST be passed first and the
/// user-supplied `VclusterConfig.values` file second. Swapping them would
/// silently make pool overrides a no-op.
///
/// `upgrade --install` (rather than plain `install`) keeps reconciliation
/// idempotent: re-running `create()` on an existing release converges
/// instead of failing with "cannot re-use a name that is still in use".
fn helm_install_args(
    name: &str,
    chart_ref: &str,
    host_ns: &str,
    chart_version: &str,
    timeout: &str,
    defaults_path: &std::path::Path,
    user_values_path: Option<&std::path::Path>,
) -> Vec<String> {
    let mut args = vec![
        "upgrade".to_string(),
        "--install".to_string(),
        name.to_string(),
        chart_ref.to_string(),
        "--namespace".to_string(),
        host_ns.to_string(),
        "--version".to_string(),
        chart_version.to_string(),
        "--values".to_string(),
        defaults_path.to_str().unwrap().to_string(),
        "--timeout".to_string(),
        timeout.to_string(),
        "--wait".to_string(),
    ];
    if let Some(p) = user_values_path {
        args.push("--values".to_string());
        args.push(p.to_str().unwrap().to_string());
    }
    args
}

/// Normalize a requested Kubernetes version into the form vcluster expects.
///
/// vcluster feeds `controlPlane.distro.k8s.version` straight through as the
/// image tag on `ghcr.io/loft-sh/kubernetes`, and every published tag there is
/// `v`-prefixed (`v1.32.3`, `v1.34.0`). A bare `1.32.3` therefore resolves to a
/// tag that does not exist and the guest never starts, so the prefix is added
/// when missing — the same shape of accommodation as `k3s_image()` rewriting
/// `+` to `-` because OCI tags forbid it.
///
/// This normalizes the PREFIX only, and deliberately nothing else. It cannot
/// make an arbitrary string a real tag: `1.34` becomes `v1.34`, which is still
/// not published (the tags carry a full patch version).
///
/// In particular a k3s/k0s-style `v1.31.3+k3s1` is passed through untouched,
/// even though `+` is not a legal tag character and the pull will fail. The
/// tempting rewrite — strip the build metadata and hand over upstream
/// `v1.31.3` — would be the very thing this function exists to stop: quietly
/// giving a tenant a different artifact from the one their manifest names. A
/// k3s build and the upstream release that shares its version are not the same
/// image. Failing loudly at pull, attributable to the value in the spec, is the
/// better outcome; correcting it is the operator's call, not ours.
fn normalize_distro_version(version: &str) -> String {
    let v = version.trim();
    // Canonicalize to the lowercase `v` the published tags use; preserving an
    // uppercase `V` would just name a tag that does not exist.
    let v = v.strip_prefix(['v', 'V']).unwrap_or(v);
    format!("v{v}")
}

/// Default vcluster Helm chart version pinned by the operator.
///
/// Bumped in lock-step with our integration tests against vcluster
/// upstream. See `docs/architecture/virtual-cluster-strategy.md` for
/// the validation matrix.
const DEFAULT_CHART_VERSION: &str = "0.34.0";

/// Helm repository alias the operator uses internally.
const HELM_REPO_ALIAS: &str = "kobe-loft-sh";

/// Cap on how much helm stderr is carried into an error.
///
/// The message reaches ClusterInstance status and the pool's
/// `lastFailureReason`, which is surfaced to lease clients — so an unbounded
/// helm dump would bloat those objects on every failed attempt.
const HELM_STDERR_LIMIT: usize = 800;

/// Build the error for a failed helm invocation, including what helm wrote to
/// stderr.
///
/// Previously both helm calls sent stderr to `Stdio::null()` and reported only
/// "returned non-zero status". That made provisioning failures undiagnosable
/// from the operator log: a DNS failure, a TLS error and a 404 were
/// indistinguishable, which is exactly what happened in #92.
fn helm_command_error(what: &str, output: &std::process::Output) -> anyhow::Error {
    let code = output
        .status
        .code()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "signal".to_string());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    if stderr.is_empty() {
        return anyhow!("{what} returned non-zero status (exit {code}), with no stderr");
    }
    if stderr.len() > HELM_STDERR_LIMIT {
        // Cut on a char boundary — helm output can carry non-ASCII.
        let mut end = HELM_STDERR_LIMIT;
        while end > 0 && !stderr.is_char_boundary(end) {
            end -= 1;
        }
        return anyhow!(
            "{what} returned non-zero status (exit {code}): {} […truncated]",
            &stderr[..end]
        );
    }
    anyhow!("{what} returned non-zero status (exit {code}): {stderr}")
}

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
    fn default_values_yaml(&self, _name: &str, config: &ClusterConfig) -> String {
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
        // Built as a structured document and serialized, rather than
        // interpolated into a string. `version` is user-controlled, and a
        // value carrying YAML syntax (`1.2.3: bad`, a trailing `# comment`,
        // an embedded newline) would otherwise restructure the document the
        // chart receives instead of merely naming a tag that fails to pull.
        use serde_yaml_ng::{Mapping, Value};

        let mut control_plane = Mapping::new();

        // Only set the distro when a version was actually requested: an empty
        // string here would set the image tag to "" and break the guest,
        // whereas saying nothing leaves the chart's own pinned default.
        if !config.version.trim().is_empty() {
            let mut k8s = Mapping::new();
            k8s.insert(
                Value::from("version"),
                Value::from(normalize_distro_version(&config.version)),
            );
            let mut distro = Mapping::new();
            distro.insert(Value::from("k8s"), Value::Mapping(k8s));
            control_plane.insert(Value::from("distro"), Value::Mapping(distro));
        }

        let mut volume_claim = Mapping::new();
        volume_claim.insert(Value::from("enabled"), Value::from(true));
        let mut persistence = Mapping::new();
        persistence.insert(Value::from("volumeClaim"), Value::Mapping(volume_claim));
        let mut stateful_set = Mapping::new();
        stateful_set.insert(Value::from("persistence"), Value::Mapping(persistence));
        control_plane.insert(Value::from("statefulSet"), Value::Mapping(stateful_set));

        let mut export_kubeconfig = Mapping::new();
        export_kubeconfig.insert(Value::from("server"), Value::from(server));

        let mut root = Mapping::new();
        root.insert(
            Value::from("exportKubeConfig"),
            Value::Mapping(export_kubeconfig),
        );
        root.insert(Value::from("controlPlane"), Value::Mapping(control_plane));

        let body = serde_yaml_ng::to_string(&Value::Mapping(root))
            // Serializing a mapping of plain scalars cannot fail; fall back to
            // an empty document rather than panicking in a reconcile.
            .unwrap_or_default();
        format!("# kobe operator defaults for vcluster\n{body}")
    }

    /// Ensure the Helm repo is registered locally. Idempotent.
    async fn ensure_helm_repo(&self) -> Result<()> {
        let output = Command::new("helm")
            .args(["repo", "add", HELM_REPO_ALIAS, HELM_REPO_URL])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("failed to spawn `helm repo add`")?;
        // Non-zero is normal if the repo is already registered, so this is not
        // fatal — but log what helm said rather than discarding it, since a
        // genuine failure here is otherwise invisible until `update` fails.
        if !output.status.success() {
            debug!(
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "helm repo add returned non-zero (likely already registered); continuing"
            );
        }
        let output = Command::new("helm")
            .args(["repo", "update", HELM_REPO_ALIAS])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("failed to spawn `helm repo update`")?;
        if !output.status.success() {
            return Err(helm_command_error(
                &format!("helm repo update for {HELM_REPO_ALIAS}"),
                &output,
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
        // A drop guard removes these temp files on every exit path — including an
        // early `?` on a failed user-values write or helm spawn, which previously
        // skipped the explicit cleanup below and leaked the defaults file (and,
        // on a helm-spawn failure, the user file, which may hold secrets).
        let mut temp_files = TempValuesGuard::default();

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
        temp_files.0.push(defaults_path.clone());

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
            temp_files.0.push(p.clone());
            user_values_path = Some(p);
        }

        let chart_ref = format!("{HELM_REPO_ALIAS}/vcluster");
        let chart_version = self.chart_version().to_string();
        let timeout = format!("{HELM_INSTALL_TIMEOUT_SECS}s");

        let helm_args = helm_install_args(
            name,
            &chart_ref,
            &host_ns,
            &chart_version,
            &timeout,
            &defaults_path,
            user_values_path.as_deref(),
        );

        let output = Command::new("helm")
            .args(&helm_args)
            .output()
            .await
            .context("failed to spawn `helm upgrade --install`")?;

        // Temp files are removed by `temp_files`' Drop on return (all paths).

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

        // Defense-in-depth guard. The host namespace name is computed
        // deterministically by `host_namespace()` as `vcluster-{name}`,
        // so under correct operation `host_ns` always carries the
        // `vcluster-` prefix. This explicit assertion prevents an
        // accidental code-path bug (empty `name`, malformed override
        // from a future config change, etc.) from issuing a delete
        // against `default`, `kube-system`, or any other non-vcluster
        // namespace via the operator's broad `namespaces:delete` RBAC.
        //
        // The chart's optional ValidatingAdmissionPolicy adds a
        // cluster-side check on top of this — see
        // `charts/kobe/templates/vap-namespace-protection.yaml`.
        if !host_ns.starts_with("vcluster-") {
            return Err(anyhow!(
                "refusing to delete namespace {host_ns} — \
                 vcluster backend only manages namespaces with the \
                 `vcluster-` prefix; aborting before issuing a \
                 destructive request that could affect cluster-wide \
                 namespaces (cluster instance: {name})"
            ));
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use std::path::Path;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn mock_client(server: &MockServer) -> Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::testutil::mock_k8s_client(server)
    }

    fn backend(server: &MockServer, config: Option<VclusterConfig>) -> VclusterBackend {
        VclusterBackend::new(mock_client(server), config)
    }

    /// A backend whose `Client` points at a dead address. Only safe for the
    /// pure helpers (`host_namespace`, `chart_version`, `default_values_yaml`)
    /// which never touch the API server.
    fn offline_backend(config: Option<VclusterConfig>) -> VclusterBackend {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let kube_config = kube::Config::new("http://127.0.0.1:1/".parse().unwrap());
        VclusterBackend::new(Client::try_from(kube_config).unwrap(), config)
    }

    fn base_config() -> ClusterConfig {
        ClusterConfig {
            version: "v1.32.0".to_string(),
            servers: 1,
            ..Default::default()
        }
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn secret_response(name: &str, host_ns: &str, data: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": name, "namespace": host_ns },
            "data": data,
        })
    }

    fn statefulset_response(
        name: &str,
        host_ns: &str,
        replicas: i32,
        ready_replicas: i32,
    ) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": name, "namespace": host_ns },
            "spec": {
                "selector": { "matchLabels": { "app": name } },
                "serviceName": name,
                "template": { "metadata": {}, "spec": { "containers": [] } },
            },
            "status": {
                "replicas": replicas,
                "readyReplicas": ready_replicas,
                "availableReplicas": ready_replicas,
            },
        })
    }

    // =================================================================
    // Naming / host-namespace invariants
    // =================================================================

    /// Every instance is scoped to `vcluster-<name>`, never to the
    /// `ClusterInstance`'s own namespace. This is the single fact the
    /// whole backend is built on: the values file, health probe,
    /// kubeconfig read and teardown all derive from it.
    #[tokio::test]
    async fn host_namespace_is_derived_from_the_instance_name_only() {
        let b = offline_backend(None);
        assert_eq!(b.host_namespace("foo"), "vcluster-foo");
        assert_eq!(
            b.host_namespace("pool-ci-abc123"),
            "vcluster-pool-ci-abc123"
        );
    }

    /// `delete()` refuses to issue a namespace delete unless the target
    /// carries the `vcluster-` prefix. That guard is only sound because
    /// `host_namespace()` unconditionally emits the prefix — if a future
    /// refactor changed the scheme (a configurable prefix, a hash, an
    /// empty-name shortcut) every delete would start erroring out. Pin
    /// the producer side of the contract the guard consumes.
    #[tokio::test]
    async fn host_namespace_always_carries_the_prefix_the_delete_guard_requires() {
        let b = offline_backend(None);
        for name in [
            "a",
            "",
            "vcluster",
            "kube-system",
            "default",
            "x".repeat(60).as_str(),
        ] {
            let ns = b.host_namespace(name);
            assert!(
                ns.starts_with("vcluster-"),
                "host_namespace({name:?}) = {ns:?} would trip delete()'s safety guard"
            );
        }
    }

    // =================================================================
    // Chart version resolution
    // =================================================================

    /// No pool config, or a pool config that simply omits `chartVersion`,
    /// both fall back to the operator's pinned default. The second case is
    /// the easy one to regress by testing `self.config.is_some()` instead
    /// of the inner `Option`.
    #[tokio::test]
    async fn chart_version_falls_back_to_the_pinned_default() {
        assert_eq!(offline_backend(None).chart_version(), DEFAULT_CHART_VERSION);
        assert_eq!(
            offline_backend(Some(VclusterConfig::default())).chart_version(),
            DEFAULT_CHART_VERSION
        );
        assert_eq!(
            offline_backend(Some(VclusterConfig {
                chart_version: None,
                values: Some("controlPlane: {}".to_string()),
            }))
            .chart_version(),
            DEFAULT_CHART_VERSION
        );
    }

    /// A pool-level `chartVersion` wins over the operator default.
    #[tokio::test]
    async fn chart_version_honours_the_pool_override() {
        let b = offline_backend(Some(VclusterConfig {
            chart_version: Some("0.29.1".to_string()),
            values: None,
        }));
        assert_eq!(b.chart_version(), "0.29.1");
        assert_ne!(b.chart_version(), DEFAULT_CHART_VERSION);
    }

    // =================================================================
    // Operator-default Helm values
    // =================================================================

    /// The defaults file is handed to `helm --values`, so it has to be
    /// well-formed YAML with the keys the chart expects at the right
    /// depth. A stray indent in the `format!` literal is invisible until
    /// helm rejects it at install time.
    /// A pool that asks for a Kubernetes version must get it.
    ///
    /// vcluster takes this at `controlPlane.distro.k8s.version` and uses
    /// it VERBATIM as the image tag on `ghcr.io/loft-sh/kubernetes`.
    /// Dropping it silently hands the tenant whatever the pinned chart
    /// defaults to (v1.35.0 for chart 0.34.0) while the manifest says
    /// otherwise — the failure mode is a cluster that looks right and is
    /// not.
    #[tokio::test]
    async fn default_values_yaml_sets_the_requested_kubernetes_version() {
        let b = offline_backend(None);
        let cfg = ClusterConfig {
            version: "v1.32.3".to_string(),
            servers: 1,
            ..Default::default()
        };
        let yaml = b.default_values_yaml("foo", &cfg);
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(
            v["controlPlane"]["distro"]["k8s"]["version"].as_str(),
            Some("v1.32.3"),
            "the requested version must reach the chart, got: {yaml}"
        );
    }

    /// The tag is used verbatim, and every published tag is v-prefixed —
    /// a bare `1.32.3` resolves to a nonexistent image and the guest
    /// never starts. Accept the un-prefixed spelling rather than turning
    /// it into an ImagePullBackOff. (This normalizes the prefix only; it
    /// does not make the value a valid tag — `1.34` is still not one.)
    #[tokio::test]
    async fn requested_version_is_v_prefixed_for_the_image_tag() {
        let b = offline_backend(None);
        let cfg = ClusterConfig {
            version: "1.32.3".to_string(),
            servers: 1,
            ..Default::default()
        };
        let yaml = b.default_values_yaml("foo", &cfg);
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
        assert_eq!(
            v["controlPlane"]["distro"]["k8s"]["version"].as_str(),
            Some("v1.32.3"),
            "a missing `v` must be added, got: {yaml}"
        );
    }

    /// The version is interpolated into a YAML document, so it must be
    /// emitted as a SCALAR — not spliced in as raw text. Otherwise a value
    /// containing YAML syntax rewrites the document: `1.2.3: bad` adds a
    /// mapping key, `1.2.3 # x` silently truncates at the comment, and a
    /// newline injects arbitrary structure. Any of those change what the
    /// chart receives rather than merely naming a tag that fails to pull.
    #[tokio::test]
    async fn a_yaml_hostile_version_cannot_restructure_the_values_document() {
        let b = offline_backend(None);
        for hostile in [
            "1.2.3: bad",
            "1.2.3 # note",
            "1.2.3\n  enabled: false",
            "1.2.3\nexportKubeConfig:\n  server: https://evil",
            "*anchor",
            "\"quoted\"",
        ] {
            let cfg = ClusterConfig {
                version: hostile.to_string(),
                servers: 1,
                ..Default::default()
            };
            let yaml = b.default_values_yaml("foo", &cfg);
            let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml)
                .unwrap_or_else(|e| panic!("input {hostile:?} produced invalid YAML: {e}\n{yaml}"));

            // The document shape must be untouched by the input.
            assert_eq!(
                v["exportKubeConfig"]["server"].as_str(),
                Some("https://foo.vcluster-foo.svc.cluster.local:443"),
                "input {hostile:?} rewrote exportKubeConfig: {yaml}"
            );
            assert!(
                v["controlPlane"]["statefulSet"]["persistence"]["volumeClaim"]["enabled"]
                    .as_bool()
                    .unwrap_or(false),
                "input {hostile:?} disturbed the persistence block: {yaml}"
            );
            // And the version must round-trip as one scalar string.
            assert!(
                v["controlPlane"]["distro"]["k8s"]["version"]
                    .as_str()
                    .is_some(),
                "input {hostile:?} did not yield a scalar version: {yaml}"
            );
        }
    }

    /// Published tags are lowercase-`v`, so an uppercase `V` must be
    /// canonicalized rather than preserved — preserving it just names a tag
    /// that does not exist.
    #[test]
    fn version_prefix_is_canonicalized_to_lowercase() {
        assert_eq!(normalize_distro_version("V1.32.3"), "v1.32.3");
    }

    /// A k3s/k0s-style build suffix is NOT rewritten away.
    ///
    /// Stripping `+k3s1` to reach upstream `v1.31.3` would substitute a
    /// different artifact for the one the manifest names — the same class of
    /// silent mismatch this whole change exists to remove. It is passed
    /// through so the pull fails loudly and points back at the spec value.
    #[test]
    fn version_does_not_rewrite_a_build_suffix_into_a_different_release() {
        assert_eq!(normalize_distro_version("v1.31.3+k3s1"), "v1.31.3+k3s1");
        assert_eq!(normalize_distro_version("1.31.3+k0s.0"), "v1.31.3+k0s.0");
    }

    /// Normalization must not corrupt an input that is already prefixed.
    /// Values it cannot interpret still pass through for the registry to
    /// reject — that is the intended failure mode — but a value that was
    /// already fine must never be made worse.
    #[test]
    fn version_normalization_is_idempotent_and_case_insensitive() {
        assert_eq!(normalize_distro_version("v1.32.3"), "v1.32.3");
        assert_eq!(normalize_distro_version("1.32.3"), "v1.32.3");
        // Canonicalized, not merely accepted: published tags are lowercase-v,
        // so preserving `V` would name a tag that does not exist.
        assert_eq!(normalize_distro_version("V1.32.3"), "v1.32.3");
        // Idempotent: normalizing twice must not stack prefixes.
        let once = normalize_distro_version("1.32.3");
        assert_eq!(normalize_distro_version(&once), once);
        // Surrounding whitespace is trimmed, not preserved into the tag.
        assert_eq!(normalize_distro_version("  1.32.3  "), "v1.32.3");
    }

    /// No version requested: say nothing, so the chart's own pinned
    /// default applies. Emitting an empty string would set the image tag
    /// to "" and break the guest.
    #[tokio::test]
    async fn an_unset_version_leaves_the_chart_default_alone() {
        let b = offline_backend(None);
        let cfg = ClusterConfig {
            version: String::new(),
            servers: 1,
            ..Default::default()
        };
        let yaml = b.default_values_yaml("foo", &cfg);
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
        assert!(
            v["controlPlane"]["distro"].is_null(),
            "an unset version must not emit a distro block, got: {yaml}"
        );
    }

    #[tokio::test]
    async fn default_values_yaml_parses_as_yaml_with_the_expected_shape() {
        let b = offline_backend(None);
        let yaml = b.default_values_yaml("foo", &base_config());
        let v: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&yaml).expect("operator default values must be valid YAML");

        assert!(
            v["exportKubeConfig"]["server"].as_str().is_some(),
            "exportKubeConfig.server must be a scalar string: {yaml}"
        );
        assert_eq!(
            v["controlPlane"]["statefulSet"]["persistence"]["volumeClaim"]["enabled"].as_bool(),
            Some(true),
            "the control-plane PVC must stay enabled so etcd survives a pod restart: {yaml}"
        );
    }

    /// `extract_kubeconfig()` deliberately does *no* URL rewriting — it
    /// relies on the chart having written an in-cluster-resolvable server
    /// URL, which comes from this values file. The URL must therefore
    /// address the vcluster Service (named after the Helm release) inside
    /// the very namespace `host_namespace()` computes. Deriving the
    /// expectation from `host_namespace()` keeps the two in lock-step.
    #[tokio::test]
    async fn default_values_yaml_points_the_kubeconfig_server_at_the_host_namespace_service() {
        let b = offline_backend(None);
        let name = "pool-ci-7f3a";
        let yaml = b.default_values_yaml(name, &base_config());
        let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
        let server = v["exportKubeConfig"]["server"].as_str().unwrap();

        assert_eq!(
            server,
            format!(
                "https://{name}.{ns}.svc.cluster.local:443",
                ns = b.host_namespace(name)
            ),
            "kubeconfig server URL drifted from host_namespace()/release name"
        );
    }

    // =================================================================
    // Helm argument assembly
    // =================================================================

    /// Helm merges repeated `--values` left-to-right with later wins, so
    /// the user file must come *after* the operator defaults. Reversing
    /// them turns every pool-level override into a silent no-op.
    #[test]
    fn helm_install_args_passes_user_values_after_operator_defaults() {
        let args = helm_install_args(
            "foo",
            "kobe-loft-sh/vcluster",
            "vcluster-foo",
            "0.34.0",
            "300s",
            Path::new("/tmp/defaults.yaml"),
            Some(Path::new("/tmp/user.yaml")),
        );

        let values_files: Vec<&String> = args
            .iter()
            .enumerate()
            .filter(|(i, a)| a.as_str() == "--values" && *i + 1 < args.len())
            .map(|(i, _)| &args[i + 1])
            .collect();
        assert_eq!(
            values_files,
            vec!["/tmp/defaults.yaml", "/tmp/user.yaml"],
            "user values must be the last --values so helm's last-wins merge applies them on top"
        );
    }

    /// With no pool-level `values`, exactly one `--values` is passed and
    /// no dangling flag is left behind.
    #[test]
    fn helm_install_args_omits_user_values_when_the_pool_supplies_none() {
        let args = helm_install_args(
            "foo",
            "kobe-loft-sh/vcluster",
            "vcluster-foo",
            "0.34.0",
            "300s",
            Path::new("/tmp/defaults.yaml"),
            None,
        );
        assert_eq!(args.iter().filter(|a| a.as_str() == "--values").count(), 1);
        assert_eq!(args.last().map(String::as_str), Some("--wait"));
    }

    /// The release is scoped to the per-instance host namespace, pinned to
    /// an explicit chart version, and waited on. Losing `--wait` would make
    /// `create()` return before the vcluster exists, so the addon loop that
    /// immediately follows would fail against a missing apiserver.
    #[test]
    fn helm_install_args_scope_the_release_and_wait_for_readiness() {
        let args = helm_install_args(
            "foo",
            "kobe-loft-sh/vcluster",
            "vcluster-foo",
            "0.34.0",
            "300s",
            Path::new("/tmp/defaults.yaml"),
            None,
        );

        // `upgrade --install`, not `install`: reconciliation must be
        // idempotent over an existing release.
        assert_eq!(args[0], "upgrade");
        assert_eq!(args[1], "--install");
        assert_eq!(args[2], "foo", "release name is the instance name");
        assert_eq!(args[3], "kobe-loft-sh/vcluster");

        let flag_value = |flag: &str| -> Option<&str> {
            args.iter()
                .position(|a| a == flag)
                .and_then(|i| args.get(i + 1))
                .map(String::as_str)
        };
        assert_eq!(flag_value("--namespace"), Some("vcluster-foo"));
        assert_eq!(flag_value("--version"), Some("0.34.0"));
        assert_eq!(flag_value("--timeout"), Some("300s"));
        assert!(args.iter().any(|a| a == "--wait"));
    }

    /// The helm subprocess timeout string must be derived from
    /// [`HELM_INSTALL_TIMEOUT_SECS`] in helm's duration syntax. A bare
    /// number (no unit) is rejected by helm at parse time.
    #[test]
    fn helm_install_timeout_is_expressed_in_helm_duration_syntax() {
        let timeout = format!("{HELM_INSTALL_TIMEOUT_SECS}s");
        assert_eq!(timeout, "300s");
        assert!(timeout.ends_with('s') && timeout[..timeout.len() - 1].parse::<u64>().is_ok());
    }

    // =================================================================
    // Host namespace bootstrap
    // =================================================================

    /// The host namespace is server-side-applied with the labels the
    /// chart's namespace-protection policy and operator-side reaping keys
    /// off. Losing `kobe.kunobi.ninja/backend=vcluster` makes an orphaned
    /// namespace indistinguishable from a user's own.
    #[tokio::test]
    async fn ensure_host_namespace_applies_kobe_ownership_labels() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/namespaces/vcluster-foo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "vcluster-foo" },
            })))
            .expect(1)
            .mount(&server)
            .await;

        backend(&server, None)
            .ensure_host_namespace("vcluster-foo")
            .await
            .expect("ensure_host_namespace should succeed");

        let requests = server.received_requests().await.unwrap();
        let req = requests.first().expect("a PATCH must have been issued");
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["metadata"]["name"], "vcluster-foo");
        assert_eq!(
            body["metadata"]["labels"]["app.kubernetes.io/managed-by"],
            "kobe-operator"
        );
        assert_eq!(
            body["metadata"]["labels"]["kobe.kunobi.ninja/backend"],
            "vcluster"
        );
        // Server-side apply under a stable field manager, forced, so a
        // re-reconcile converges instead of conflicting.
        let query = req.url.query().unwrap_or_default();
        assert!(
            query.contains("fieldManager=kobe-operator"),
            "expected a server-side apply field manager, got query {query:?}"
        );
        assert!(
            query.contains("force=true"),
            "apply must be forced to resolve field-manager conflicts, got query {query:?}"
        );
    }

    // =================================================================
    // Kubeconfig extraction
    // =================================================================

    /// vcluster's chart publishes the kubeconfig to Secret `vc-<release>`
    /// under data key `config` — a different convention from the k3s/k0s
    /// backends (`<name>-kubeconfig` / key `kubeconfig`). Reading the wrong
    /// name or key yields a permanently un-leasable instance.
    #[tokio::test]
    async fn extract_kubeconfig_reads_the_vc_prefixed_secret_config_key() {
        let server = MockServer::start().await;
        let kubeconfig = "apiVersion: v1\nkind: Config\nclusters: []\n";
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/vcluster-foo/secrets/vc-foo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(secret_response(
                "vc-foo",
                "vcluster-foo",
                serde_json::json!({
                    "config": b64(kubeconfig.as_bytes()),
                    // A decoy under the k3s/k0s convention: picking this up
                    // would mean the backend read the wrong key.
                    "kubeconfig": b64(b"wrong-key"),
                }),
            )))
            .expect(1)
            .mount(&server)
            .await;

        let got = backend(&server, None)
            .extract_kubeconfig("foo", "kobe-system")
            .await
            .expect("extract_kubeconfig should succeed");
        assert_eq!(got, kubeconfig);
    }

    /// The `namespace` argument is the `ClusterInstance`'s own namespace
    /// (usually `kobe-system`); the workload lives in `vcluster-<name>`.
    /// The mock only answers under the host namespace, so a backend that
    /// used the passed namespace would 404. Mirrors the `_namespace`
    /// doc-comment on [`VclusterBackend::host_namespace`].
    #[tokio::test]
    async fn extract_kubeconfig_ignores_the_instance_namespace() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/vcluster-foo/secrets/vc-foo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(secret_response(
                "vc-foo",
                "vcluster-foo",
                serde_json::json!({ "config": b64(b"kc") }),
            )))
            .mount(&server)
            .await;

        for instance_ns in ["kobe-system", "some-other-ns", ""] {
            let got = backend(&server, None)
                .extract_kubeconfig("foo", instance_ns)
                .await;
            assert!(
                got.is_ok(),
                "instance namespace {instance_ns:?} must not affect the lookup: {got:?}"
            );
        }
    }

    /// A missing Secret is an error, not an empty kubeconfig — the caller
    /// must be able to distinguish "not published yet" from "published as
    /// empty", and the message must name the Secret and namespace so an
    /// operator can go look.
    #[tokio::test]
    async fn extract_kubeconfig_errors_when_the_secret_is_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/vcluster-foo/secrets/vc-foo"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(crate::testutil::k8s_not_found("secrets", "vc-foo")),
            )
            .mount(&server)
            .await;

        let err = backend(&server, None)
            .extract_kubeconfig("foo", "kobe-system")
            .await
            .expect_err("absent Secret must be an error");
        let msg = format!("{err:#}");
        assert!(msg.contains("vc-foo"), "error must name the Secret: {msg}");
        assert!(
            msg.contains("vcluster-foo"),
            "error must name the host namespace: {msg}"
        );
    }

    /// A Secret that exists but has no `config` key means the chart wrote
    /// something unexpected. That must surface as a distinct, greppable
    /// error rather than an empty string.
    #[tokio::test]
    async fn extract_kubeconfig_errors_when_the_config_key_is_missing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/vcluster-foo/secrets/vc-foo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(secret_response(
                "vc-foo",
                "vcluster-foo",
                serde_json::json!({ "kubeconfig": b64(b"wrong-key") }),
            )))
            .mount(&server)
            .await;

        let err = backend(&server, None)
            .extract_kubeconfig("foo", "kobe-system")
            .await
            .expect_err("Secret without data.config must be an error");
        assert!(
            format!("{err:#}").contains("missing data.config"),
            "unexpected error: {err:#}"
        );
    }

    /// Secret payloads are opaque bytes. Non-UTF-8 content must be
    /// reported, never lossily coerced into a kubeconfig that then fails
    /// far away from the cause.
    #[tokio::test]
    async fn extract_kubeconfig_errors_when_config_is_not_utf8() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/vcluster-foo/secrets/vc-foo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(secret_response(
                "vc-foo",
                "vcluster-foo",
                serde_json::json!({ "config": b64(&[0xff, 0xfe, 0x00]) }),
            )))
            .mount(&server)
            .await;

        let err = backend(&server, None)
            .extract_kubeconfig("foo", "kobe-system")
            .await
            .expect_err("non-UTF-8 data.config must be an error");
        assert!(
            format!("{err:#}").contains("not valid UTF-8"),
            "unexpected error: {err:#}"
        );
    }

    // =================================================================
    // Health probe
    // =================================================================

    /// Before helm has created anything there is no StatefulSet. That is
    /// "not healthy yet", not a reconcile failure — returning `Err` here
    /// would put every freshly-created instance into a failed state.
    #[tokio::test]
    async fn check_health_is_false_when_the_statefulset_is_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/apps/v1/namespaces/vcluster-foo/statefulsets/foo",
            ))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(crate::testutil::k8s_not_found("statefulsets", "foo")),
            )
            .expect(1)
            .mount(&server)
            .await;

        let healthy = backend(&server, None)
            .check_health("foo", "kobe-system")
            .await
            .expect("absent StatefulSet must not be an error");
        assert!(!healthy);
    }

    /// A StatefulSet that exists but has fewer ready replicas than created
    /// ones is still coming up. The kubeconfig Secret must not even be
    /// consulted — asserting on the un-mounted Secret route proves the
    /// short-circuit.
    #[tokio::test]
    async fn check_health_is_false_while_replicas_are_not_ready() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/apps/v1/namespaces/vcluster-foo/statefulsets/foo",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(statefulset_response(
                    "foo",
                    "vcluster-foo",
                    1,
                    0,
                )),
            )
            .expect(1)
            .mount(&server)
            .await;

        let healthy = backend(&server, None)
            .check_health("foo", "kobe-system")
            .await
            .unwrap();
        assert!(!healthy);
        // No Secret GET was mounted; if the probe had continued, wiremock
        // would have recorded a second request.
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// A StatefulSet reporting zero replicas (scaled to zero, or status
    /// not yet populated) is not healthy, even though `readyReplicas >=
    /// replicas` holds vacuously at 0 >= 0. This is what the `want > 0`
    /// guard exists for.
    #[tokio::test]
    async fn check_health_is_false_when_the_statefulset_reports_zero_replicas() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/apps/v1/namespaces/vcluster-foo/statefulsets/foo",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(statefulset_response(
                    "foo",
                    "vcluster-foo",
                    0,
                    0,
                )),
            )
            .mount(&server)
            .await;
        // Mounted as *present* on purpose: the replica guard must be the
        // only thing that can produce `false` in this scenario.
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/vcluster-foo/secrets/vc-foo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(secret_response(
                "vc-foo",
                "vcluster-foo",
                serde_json::json!({ "config": b64(b"kc") }),
            )))
            .mount(&server)
            .await;

        let healthy = backend(&server, None)
            .check_health("foo", "kobe-system")
            .await
            .unwrap();
        assert!(!healthy, "a zero-replica StatefulSet must not read healthy");
    }

    /// A ready StatefulSet is not enough: without the `vc-<name>` Secret
    /// nobody can reach the virtual cluster, so the instance must not be
    /// advertised as healthy (and handed out on a lease).
    #[tokio::test]
    async fn check_health_is_false_when_the_kubeconfig_secret_is_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/apps/v1/namespaces/vcluster-foo/statefulsets/foo",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(statefulset_response(
                    "foo",
                    "vcluster-foo",
                    1,
                    1,
                )),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/vcluster-foo/secrets/vc-foo"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(crate::testutil::k8s_not_found("secrets", "vc-foo")),
            )
            .expect(1)
            .mount(&server)
            .await;

        let healthy = backend(&server, None)
            .check_health("foo", "kobe-system")
            .await
            .expect("absent Secret must not be an error");
        assert!(!healthy);
    }

    /// Ready StatefulSet plus published kubeconfig Secret — both probed in
    /// the per-instance host namespace, never the instance's own.
    #[tokio::test]
    async fn check_health_is_true_when_the_statefulset_is_ready_and_the_secret_exists() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/apps/v1/namespaces/vcluster-foo/statefulsets/foo",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(statefulset_response(
                    "foo",
                    "vcluster-foo",
                    1,
                    1,
                )),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/vcluster-foo/secrets/vc-foo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(secret_response(
                "vc-foo",
                "vcluster-foo",
                serde_json::json!({ "config": b64(b"kc") }),
            )))
            .expect(1)
            .mount(&server)
            .await;

        assert!(
            backend(&server, None)
                .check_health("foo", "kobe-system")
                .await
                .unwrap()
        );
    }

    /// Only 404 means "not there yet". Any other API failure (RBAC denial,
    /// apiserver outage) must propagate as an error — silently reporting
    /// `false` would let the pool controller tear down and recreate healthy
    /// instances during an unrelated control-plane blip.
    #[tokio::test]
    async fn check_health_propagates_non_404_api_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/apps/v1/namespaces/vcluster-foo/statefulsets/foo",
            ))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "message": "statefulsets.apps \"foo\" is forbidden",
                "reason": "Forbidden",
                "code": 403,
            })))
            .mount(&server)
            .await;

        let err = backend(&server, None)
            .check_health("foo", "kobe-system")
            .await
            .expect_err("a 403 must not be swallowed as `unhealthy`");
        assert!(
            format!("{err:#}").contains("StatefulSet get failed"),
            "unexpected error: {err:#}"
        );
    }

    /// Same rule on the Secret leg of the probe.
    #[tokio::test]
    async fn check_health_propagates_non_404_secret_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/apps/v1/namespaces/vcluster-foo/statefulsets/foo",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(statefulset_response(
                    "foo",
                    "vcluster-foo",
                    1,
                    1,
                )),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/vcluster-foo/secrets/vc-foo"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "message": "etcd is unavailable",
                "reason": "InternalError",
                "code": 500,
            })))
            .mount(&server)
            .await;

        let err = backend(&server, None)
            .check_health("foo", "kobe-system")
            .await
            .expect_err("a 500 must not be swallowed as `unhealthy`");
        assert!(
            format!("{err:#}").contains("kubeconfig Secret get failed"),
            "unexpected error: {err:#}"
        );
    }

    // --- helm stderr capture -------------------------------------------

    fn output_with(stderr: &[u8], code: i32) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn helm_error_includes_what_helm_actually_said() {
        let err = helm_command_error(
            "helm repo update for kobe-loft-sh",
            &output_with(
                b"Error: looks like \"https://charts.loft.sh\" is not a valid chart repository",
                1,
            ),
        );
        let msg = err.to_string();
        assert!(msg.contains("helm repo update for kobe-loft-sh"), "{msg}");
        assert!(msg.contains("not a valid chart repository"), "{msg}");
    }

    #[test]
    fn helm_error_trims_surrounding_whitespace() {
        let err = helm_command_error("helm repo add", &output_with(b"\n\n  boom  \n\n", 1));
        assert!(err.to_string().ends_with("boom"), "{err}");
    }

    /// The message lands in ClusterInstance status and in the pool's
    /// lastFailureReason, which is surfaced to lease clients. An unbounded
    /// helm dump there bloats the object on every failed attempt.
    #[test]
    fn helm_error_truncates_a_very_long_stderr() {
        let long = vec![b'x'; 10_000];
        let msg = helm_command_error("helm repo update", &output_with(&long, 1)).to_string();
        assert!(msg.len() < 1_200, "message was {} bytes", msg.len());
        assert!(msg.contains("truncated"), "{msg}");
    }

    #[test]
    fn helm_error_without_stderr_still_reports_the_exit_code() {
        let msg = helm_command_error("helm repo update", &output_with(b"", 3)).to_string();
        assert!(msg.contains("helm repo update"), "{msg}");
        assert!(msg.contains('3'), "expected the exit code in: {msg}");
    }

    #[test]
    fn helm_error_survives_non_utf8_stderr() {
        let msg = helm_command_error("helm repo add", &output_with(&[0xff, 0xfe, b'h', b'i'], 1))
            .to_string();
        assert!(msg.contains("hi"), "{msg}");
    }
}
