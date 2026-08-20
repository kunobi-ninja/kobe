//! Installation and certification of the upstream Agent Sandbox runtime.
//!
//! Kobe consumes `SandboxTemplate`, `SandboxWarmPool` and `SandboxClaim` from
//! the upstream [Agent Sandbox] project. In `managed` mode the chart installs
//! the official v0.5.4 core/extensions bundle with an immutable image digest,
//! retains its four CRDs across uninstall, and publishes the same bundle as a
//! child-cluster [`crate::crd::BootstrapConfig`]. In `external` mode the
//! operator owns that installation. Both modes run the same certification.
//!
//! # Why validate at all
//!
//! Without a check, a missing or mismatched runtime surfaces as an obscure
//! failure deep in placement — a `SandboxClaim` create that 404s, or worse, one
//! that succeeds against an incompatible schema and leaves an object no
//! controller reconciles. Refusing up front, with the version actually found,
//! turns that into one legible error.
//!
//! # What this deliberately does NOT do
//!
//! Certification is deliberately stronger than API discovery: Kobe verifies
//! the controller generation, exact running image, conversion webhook and TLS,
//! then creates a restricted real Claim and proves its cleanup. Startup and
//! child composition fail closed when any part cannot be proven.
//!
//! [Agent Sandbox]: https://github.com/kubernetes-sigs/agent-sandbox

use serde::{Deserialize, Serialize};

/// How the upstream Agent Sandbox runtime reaches a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AgentSandboxMode {
    /// New Sandbox admission and placement are off. No Sandbox API is served,
    /// but lifecycle/reaper loops stay active to drain leases and tombstones
    /// created while External was enabled. The default, so a fresh install
    /// never starts depending on a runtime the operator has not installed.
    #[default]
    Disabled,
    /// Kobe installs the pinned release and the identical child bootstrap.
    Managed,
    /// The operator installs and owns the runtime; Kobe only creates temporary
    /// certification objects and ordinary Sandbox placement objects.
    External,
}

impl AgentSandboxMode {
    /// Whether Sandbox HTTP routes and lifecycle controllers may run.
    pub const fn enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// Upstream release pinned by the management and child installation assets.
pub const AGENT_SANDBOX_RELEASE: &str = "v0.5.4";

/// SHA-256 reported by GitHub for the official v0.5.4
/// `sandbox-with-extensions.yaml` release asset.
#[cfg(test)]
pub const AGENT_SANDBOX_RELEASE_MANIFEST_SHA256: &str =
    "7ada631db5d5a2cc043f48ca05cec94db54bc0afa4756b3b610c920b188fe2c4";

/// Immutable multi-platform controller image used by Kobe-managed assets.
pub const AGENT_SANDBOX_CONTROLLER_IMAGE: &str = "registry.k8s.io/agent-sandbox/agent-sandbox-controller@sha256:be477ba317d84a13a38d7605e925e7b4aa82de5b313a4274358920310a931b7f";

/// Platform manifests accepted when validating a running external controller.
pub const AGENT_SANDBOX_CONTROLLER_IMAGE_DIGESTS: &[&str] = &[
    "sha256:be477ba317d84a13a38d7605e925e7b4aa82de5b313a4274358920310a931b7f",
    "sha256:f7192ebdb18dbcfa26f242b7108f370ecb6e8d99352b427de4697d51853309d8",
    "sha256:46e2bcca361a6394ec118982c77d4644942c57467ecf6649558724a4aa5e532c",
];

/// BootstrapConfig installed by the chart for the managed child path.
pub const AGENT_SANDBOX_BOOTSTRAP_NAME: &str = "agent-sandbox-v0-5-4";

/// SHA-256 of the bootstrap file after replacing the mutable upstream image
/// tag with [`AGENT_SANDBOX_CONTROLLER_IMAGE`].
pub const AGENT_SANDBOX_BOOTSTRAP_SHA256: &str =
    "f5f6cd88a52ad76e2f18eac0a7a4ee620a77c3e02186abe48e8aa6f29155d8fa";

/// Namespace used by the pinned upstream controller and conversion webhook.
pub const AGENT_SANDBOX_SYSTEM_NAMESPACE: &str = "agent-sandbox-system";

/// The upstream API version this build is written against.
///
/// Pinned rather than "whatever is installed": Kobe projects pool and lease
/// configuration onto a specific upstream schema, and a different version can
/// accept the same object while meaning something else by it.
pub const REQUIRED_AGENT_SANDBOX_API_VERSION: &str = "extensions.agents.x-k8s.io/v1beta1";

/// The upstream CRDs Kobe consumes. All three are required: a runtime with
/// claims but no warm pools would pass a laxer check and then fail to serve.
/// The core Agent Sandbox group. The `Sandbox` object itself lives here, not
/// in the `extensions.` group its templates, warm pools and claims are in.
pub const CORE_AGENT_SANDBOX_API_VERSION: &str = "agents.x-k8s.io/v1beta1";

/// The upstream CRDs Kobe consumes, each with the API version it is consumed
/// at. All are required: a runtime missing any one of them passes a laxer
/// check and then fails to serve — and `sandboxes` in particular fails
/// *silently*, because it is read to find the Pod behind a claim, so its
/// absence surfaces as leases that never pass readiness rather than as an
/// error anyone can act on.
pub const REQUIRED_AGENT_SANDBOX_CRDS: &[(&str, &str)] = &[
    (
        "sandboxtemplates.extensions.agents.x-k8s.io",
        REQUIRED_AGENT_SANDBOX_API_VERSION,
    ),
    (
        "sandboxwarmpools.extensions.agents.x-k8s.io",
        REQUIRED_AGENT_SANDBOX_API_VERSION,
    ),
    (
        "sandboxclaims.extensions.agents.x-k8s.io",
        REQUIRED_AGENT_SANDBOX_API_VERSION,
    ),
    ("sandboxes.agents.x-k8s.io", CORE_AGENT_SANDBOX_API_VERSION),
];

/// Why an operator-installed runtime cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AgentSandboxUnusable {
    #[error(
        "Agent Sandbox is disabled; set agentSandbox.mode=managed or external to use Sandbox features"
    )]
    Disabled,
    #[error("Agent Sandbox CRD {crd} is not installed or not established")]
    CrdMissing { crd: String },
    #[error("Agent Sandbox CRD {crd} does not serve {expected} (found: {found})")]
    VersionMismatch {
        crd: String,
        expected: String,
        found: String,
    },
    #[error("Agent Sandbox runtime component {component} is unhealthy: {reason}")]
    ComponentUnhealthy {
        component: &'static str,
        reason: String,
    },
    #[error("Agent Sandbox runtime canary failed: {reason}")]
    CanaryFailed { reason: String },
    #[error("managed child runtime bootstrap is not the pinned {release} bundle: {reason}")]
    BootstrapMismatch {
        release: &'static str,
        reason: String,
    },
}

impl AgentSandboxUnusable {
    /// Bounded reason code for status, events and metrics.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::CrdMissing { .. } => "crd_missing",
            Self::VersionMismatch { .. } => "version_mismatch",
            Self::ComponentUnhealthy { .. } => "component_unhealthy",
            Self::CanaryFailed { .. } => "canary_failed",
            Self::BootstrapMismatch { .. } => "bootstrap_mismatch",
        }
    }
}

/// Parse the configured runtime ownership mode.
///
/// An unrecognised value is refused rather than defaulted: silently treating a
/// typo as `disabled` would leave an operator who asked for Sandbox features
/// wondering why nothing works, and treating it as `external` would be worse.
pub fn parse_mode(configured: &str) -> Result<AgentSandboxMode, AgentSandboxUnusable> {
    match configured.trim().to_ascii_lowercase().as_str() {
        "disabled" | "" => Ok(AgentSandboxMode::Disabled),
        "managed" => Ok(AgentSandboxMode::Managed),
        "external" => Ok(AgentSandboxMode::External),
        _ => Err(AgentSandboxUnusable::Disabled),
    }
}

/// Read the configured mode from the environment.
///
/// Absent means [`AgentSandboxMode::Disabled`] — a deployment that predates
/// this setting, or one that never opted in, must not start depending on a
/// runtime nobody installed.
pub fn mode_from_env() -> Result<AgentSandboxMode, AgentSandboxUnusable> {
    parse_mode(&std::env::var("AGENT_SANDBOX_MODE").unwrap_or_default())
}

/// Whether one CRD, as observed, is established and serves the pinned version.
///
/// Pure so the compatibility rule is testable without a cluster: the caller
/// supplies what the API server reported.
pub fn crd_is_compatible(
    crd: &str,
    expected_api_version: &str,
    established: bool,
    served_versions: &[String],
) -> Result<(), AgentSandboxUnusable> {
    if !established {
        return Err(AgentSandboxUnusable::CrdMissing {
            crd: crd.to_string(),
        });
    }
    // The pinned constant is `group/version`; a CRD reports versions alone.
    let expected_version = expected_api_version.rsplit('/').next().unwrap_or_default();
    if served_versions
        .iter()
        .any(|version| version == expected_version)
    {
        return Ok(());
    }
    Err(AgentSandboxUnusable::VersionMismatch {
        crd: crd.to_string(),
        expected: expected_api_version.to_string(),
        found: if served_versions.is_empty() {
            "none".to_string()
        } else {
            served_versions.join(",")
        },
    })
}

/// Validate that a compatible operator-installed runtime is present.
///
/// Every required CRD must be established and serve the pinned version. The
/// first failure is returned rather than a collected list: an operator fixes
/// these one at a time, and the first one usually explains the rest.
pub async fn validate_external_runtime(client: &kube::Client) -> Result<(), AgentSandboxUnusable> {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::api::Api;

    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    for (name, expected_api_version) in REQUIRED_AGENT_SANDBOX_CRDS {
        let observed = crds.get(name).await.ok();
        let established = observed.as_ref().is_some_and(|crd| {
            crd.status
                .as_ref()
                .and_then(|status| status.conditions.as_ref())
                .is_some_and(|conditions| {
                    conditions
                        .iter()
                        .any(|c| c.type_ == "Established" && c.status == "True")
                })
        });
        let served: Vec<String> = observed
            .as_ref()
            .map(|crd| {
                crd.spec
                    .versions
                    .iter()
                    .filter(|version| version.served)
                    .map(|version| version.name.clone())
                    .collect()
            })
            .unwrap_or_default();
        crd_is_compatible(name, expected_api_version, established, &served)?;
    }
    Ok(())
}

/// Whether a controller image reference is the pinned release Kobe supports.
///
/// Managed installs use the immutable OCI index. External installs may keep
/// the official release tag in their Deployment, but their running Pod still
/// has to report one of the exact platform digests below.
fn controller_image_reference_is_compatible(image: &str) -> bool {
    image == AGENT_SANDBOX_CONTROLLER_IMAGE
        || image
            == format!(
                "registry.k8s.io/agent-sandbox/agent-sandbox-controller:{AGENT_SANDBOX_RELEASE}"
            )
}

fn observed_controller_image_is_pinned(image_id: &str) -> bool {
    AGENT_SANDBOX_CONTROLLER_IMAGE_DIGESTS
        .iter()
        .any(|digest| image_id.ends_with(digest))
}

fn component_unhealthy(component: &'static str, reason: impl Into<String>) -> AgentSandboxUnusable {
    AgentSandboxUnusable::ComponentUnhealthy {
        component,
        reason: reason.into(),
    }
}

/// Validate the pinned controller, conversion webhook and running image.
///
/// CRD presence alone is not a runtime signal. This additionally requires the
/// v0.5.4 controller Deployment to have observed its current generation, an
/// available Ready Pod whose runtime image ID matches the pinned release, the
/// webhook TLS Secret, and a ready webhook endpoint.
pub async fn validate_runtime_components(
    client: &kube::Client,
) -> Result<(), AgentSandboxUnusable> {
    use k8s_openapi::api::apps::v1::Deployment;
    use k8s_openapi::api::core::v1::{Endpoints, Pod, Secret};
    use kube::api::{Api, ListParams};
    use kube::runtime::reflector::ObjectRef;

    validate_external_runtime(client).await?;

    let deployments: Api<Deployment> =
        Api::namespaced(client.clone(), AGENT_SANDBOX_SYSTEM_NAMESPACE);
    let deployment = deployments
        .get("agent-sandbox-controller")
        .await
        .map_err(|error| component_unhealthy("controller_deployment", error.to_string()))?;
    let desired_generation = deployment.metadata.generation.unwrap_or_default();
    let status = deployment.status.as_ref().ok_or_else(|| {
        component_unhealthy("controller_deployment", "status has not been published")
    })?;
    if status.observed_generation.unwrap_or_default() != desired_generation {
        return Err(component_unhealthy(
            "controller_deployment",
            format!(
                "observedGeneration {} does not match generation {desired_generation}",
                status.observed_generation.unwrap_or_default()
            ),
        ));
    }
    let desired_replicas = deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.replicas)
        .unwrap_or(1)
        .max(1);
    if status.available_replicas.unwrap_or_default() < desired_replicas {
        return Err(component_unhealthy(
            "controller_deployment",
            format!(
                "only {} of {desired_replicas} replicas are available",
                status.available_replicas.unwrap_or_default()
            ),
        ));
    }
    let controller = deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.template.spec.as_ref())
        .and_then(|spec| {
            spec.containers
                .iter()
                .find(|container| container.name == "agent-sandbox-controller")
        })
        .ok_or_else(|| {
            component_unhealthy(
                "controller_deployment",
                "agent-sandbox-controller container is missing",
            )
        })?;
    let image = controller.image.as_deref().unwrap_or_default();
    if !controller_image_reference_is_compatible(image) {
        return Err(component_unhealthy(
            "controller_image",
            format!("expected {AGENT_SANDBOX_RELEASE}, found {image}"),
        ));
    }
    if !controller
        .args
        .as_ref()
        .is_some_and(|args| args.iter().any(|arg| arg == "--extensions"))
    {
        return Err(component_unhealthy(
            "controller_deployment",
            "extensions controller is not enabled",
        ));
    }

    let pods: Api<Pod> = Api::namespaced(client.clone(), AGENT_SANDBOX_SYSTEM_NAMESPACE);
    let pods = pods
        .list(&ListParams::default().labels("app=agent-sandbox-controller"))
        .await
        .map_err(|error| component_unhealthy("controller_pod", error.to_string()))?;
    let pinned_ready_pod = pods.iter().any(|pod| {
        let ready = pod
            .status
            .as_ref()
            .and_then(|status| status.conditions.as_ref())
            .is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|condition| condition.type_ == "Ready" && condition.status == "True")
            });
        let pinned = pod
            .status
            .as_ref()
            .and_then(|status| status.container_statuses.as_ref())
            .and_then(|statuses| {
                statuses
                    .iter()
                    .find(|status| status.name == "agent-sandbox-controller")
            })
            .is_some_and(|status| {
                status.ready && observed_controller_image_is_pinned(&status.image_id)
            });
        ready && pinned
    });
    if !pinned_ready_pod {
        let observed = pods
            .iter()
            .map(|pod| ObjectRef::from_obj(pod).name)
            .collect::<Vec<_>>()
            .join(",");
        return Err(component_unhealthy(
            "controller_pod",
            format!("no Ready Pod runs a pinned image (observed: {observed})"),
        ));
    }

    let secrets: Api<Secret> = Api::namespaced(client.clone(), AGENT_SANDBOX_SYSTEM_NAMESPACE);
    let certs = secrets
        .get("agent-sandbox-webhook-certs")
        .await
        .map_err(|error| component_unhealthy("webhook_tls", error.to_string()))?;
    let cert_data = certs
        .data
        .as_ref()
        .ok_or_else(|| component_unhealthy("webhook_tls", "Secret data is empty"))?;
    for key in ["ca.crt", "tls.crt", "tls.key"] {
        if cert_data.get(key).is_none_or(|value| value.0.is_empty()) {
            return Err(component_unhealthy(
                "webhook_tls",
                format!("Secret key {key} is missing or empty"),
            ));
        }
    }

    let endpoints: Api<Endpoints> = Api::namespaced(client.clone(), AGENT_SANDBOX_SYSTEM_NAMESPACE);
    let webhook = endpoints
        .get("agent-sandbox-webhook-service")
        .await
        .map_err(|error| component_unhealthy("webhook_endpoint", error.to_string()))?;
    let ready = webhook.subsets.as_ref().is_some_and(|subsets| {
        subsets.iter().any(|subset| {
            subset
                .addresses
                .as_ref()
                .is_some_and(|addresses| !addresses.is_empty())
                && subset.ports.as_ref().is_some_and(|ports| {
                    ports
                        .iter()
                        .any(|port| port.port == 9443 || port.name.as_deref() == Some("webhook"))
                })
        })
    });
    if !ready {
        return Err(component_unhealthy(
            "webhook_endpoint",
            "no ready endpoint serves the webhook port",
        ));
    }

    Ok(())
}

/// Verify that a BootstrapConfig contains exactly Kobe's immutable child
/// runtime bundle.
pub fn validate_managed_bootstrap(
    bootstrap: &crate::crd::BootstrapConfig,
) -> Result<(), AgentSandboxUnusable> {
    use sha2::{Digest, Sha256};

    if bootstrap.metadata.name.as_deref() != Some(AGENT_SANDBOX_BOOTSTRAP_NAME) {
        return Err(AgentSandboxUnusable::BootstrapMismatch {
            release: AGENT_SANDBOX_RELEASE,
            reason: "unexpected BootstrapConfig name".to_string(),
        });
    }
    if bootstrap.spec.job.is_some() || bootstrap.spec.files.len() != 1 {
        return Err(AgentSandboxUnusable::BootstrapMismatch {
            release: AGENT_SANDBOX_RELEASE,
            reason: "expected one manifest file and no bootstrap job".to_string(),
        });
    }
    let manifest = bootstrap
        .spec
        .files
        .get("agent-sandbox-v0.5.4.yaml")
        .ok_or_else(|| AgentSandboxUnusable::BootstrapMismatch {
            release: AGENT_SANDBOX_RELEASE,
            reason: "pinned manifest file is missing".to_string(),
        })?;
    let digest = hex::encode(Sha256::digest(manifest.as_bytes()));
    if digest != AGENT_SANDBOX_BOOTSTRAP_SHA256 {
        return Err(AgentSandboxUnusable::BootstrapMismatch {
            release: AGENT_SANDBOX_RELEASE,
            reason: format!("manifest digest is {digest}"),
        });
    }
    Ok(())
}

/// Require a child ClusterPool to consume the built-in pinned runtime bundle.
///
/// Merely finding the expected reference name is insufficient: a mutable
/// BootstrapConfig with that name could install a different controller after
/// the pool passed review. The referenced object is re-read and content-hashed
/// before Kobe allocates child capacity.
pub async fn validate_managed_child_pool(
    client: &kube::Client,
    namespace: &str,
    pool: &crate::crd::ClusterPool,
) -> Result<(), AgentSandboxUnusable> {
    use kube::api::Api;

    let references = pool
        .spec
        .bootstraps
        .iter()
        .filter(|reference| reference.name == AGENT_SANDBOX_BOOTSTRAP_NAME)
        .collect::<Vec<_>>();
    if references.len() != 1 || !references[0].params.is_empty() {
        return Err(AgentSandboxUnusable::BootstrapMismatch {
            release: AGENT_SANDBOX_RELEASE,
            reason: format!(
                "ClusterPool {} must reference {AGENT_SANDBOX_BOOTSTRAP_NAME} exactly once without parameters",
                pool.metadata.name.as_deref().unwrap_or("<unnamed>")
            ),
        });
    }
    let bootstraps: Api<crate::crd::BootstrapConfig> = Api::namespaced(client.clone(), namespace);
    let bootstrap = bootstraps
        .get(AGENT_SANDBOX_BOOTSTRAP_NAME)
        .await
        .map_err(|error| AgentSandboxUnusable::BootstrapMismatch {
            release: AGENT_SANDBOX_RELEASE,
            reason: format!("cannot read BootstrapConfig: {error}"),
        })?;
    validate_managed_bootstrap(&bootstrap)
}

const RUNTIME_CANARY_IMAGE: &str =
    "registry.k8s.io/pause@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c";

fn runtime_resource(kind: &str, plural: &str) -> kube::api::ApiResource {
    kube::api::ApiResource {
        group: "extensions.agents.x-k8s.io".to_string(),
        version: "v1beta1".to_string(),
        api_version: REQUIRED_AGENT_SANDBOX_API_VERSION.to_string(),
        kind: kind.to_string(),
        plural: plural.to_string(),
    }
}

fn canary_name(pod_uid: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(pod_uid.as_bytes()));
    format!("kobe-runtime-canary-{}", &digest[..16])
}

fn canary_object(
    kind: &str,
    name: &str,
    namespace: &str,
    owner: &k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference,
    data: serde_json::Value,
) -> kube::api::DynamicObject {
    kube::api::DynamicObject {
        types: Some(kube::api::TypeMeta {
            api_version: REQUIRED_AGENT_SANDBOX_API_VERSION.to_string(),
            kind: kind.to_string(),
        }),
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner.clone()]),
            labels: Some(
                [
                    (
                        "app.kubernetes.io/managed-by".to_string(),
                        "kobe-operator".to_string(),
                    ),
                    (
                        "kobe.kunobi.ninja/runtime-canary".to_string(),
                        owner.uid.clone(),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        },
        data,
    }
}

fn build_runtime_canary(
    name: &str,
    namespace: &str,
    owner: &k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference,
) -> [kube::api::DynamicObject; 3] {
    let template = canary_object(
        "SandboxTemplate",
        name,
        namespace,
        owner,
        serde_json::json!({
            "spec": {
                "service": false,
                "networkPolicyManagement": "Managed",
                "envVarsInjectionPolicy": "Disallowed",
                "volumeClaimTemplatesPolicy": "Disallowed",
                "podTemplate": {
                    "spec": {
                        "automountServiceAccountToken": false,
                        "restartPolicy": "Never",
                        "terminationGracePeriodSeconds": 1,
                        "securityContext": {
                            "runAsNonRoot": true,
                            "runAsUser": 65532,
                            "seccompProfile": { "type": "RuntimeDefault" }
                        },
                        "containers": [{
                            "name": "canary",
                            "image": RUNTIME_CANARY_IMAGE,
                            "imagePullPolicy": "IfNotPresent",
                            "securityContext": {
                                "allowPrivilegeEscalation": false,
                                "readOnlyRootFilesystem": true,
                                "capabilities": { "drop": ["ALL"] }
                            },
                            "resources": {
                                "requests": { "cpu": "1m", "memory": "4Mi" },
                                "limits": { "cpu": "10m", "memory": "16Mi" }
                            }
                        }]
                    }
                }
            }
        }),
    );
    let warm_pool = canary_object(
        "SandboxWarmPool",
        name,
        namespace,
        owner,
        serde_json::json!({
            "spec": {
                "replicas": 0,
                "sandboxTemplateRef": { "name": name },
                "updateStrategy": { "type": "Recreate" }
            }
        }),
    );
    let shutdown_time = (chrono::Utc::now() + chrono::Duration::minutes(5))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let claim = canary_object(
        "SandboxClaim",
        name,
        namespace,
        owner,
        serde_json::json!({
            "spec": {
                "warmPoolRef": { "name": name },
                "lifecycle": {
                    "shutdownTime": shutdown_time,
                    "shutdownPolicy": "DeleteForeground"
                }
            }
        }),
    );
    [template, warm_pool, claim]
}

fn controlled_by_uid(object: &kube::api::DynamicObject, owner_uid: &str) -> bool {
    object
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| {
            owners.len() == 1 && owners[0].controller == Some(true) && owners[0].uid == owner_uid
        })
}

async fn delete_canary_object(
    client: &kube::Client,
    namespace: &str,
    resource: &kube::api::ApiResource,
    name: &str,
    owner_uid: &str,
) -> Result<(), AgentSandboxUnusable> {
    use kube::api::{Api, DeleteParams, Preconditions, PropagationPolicy};
    use kube::{Resource, ResourceExt};

    let api: Api<kube::api::DynamicObject> =
        Api::namespaced_with(client.clone(), namespace, resource);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let object = match api.get(name).await {
            Ok(object) => object,
            Err(kube::Error::Api(error)) if error.code == 404 => return Ok(()),
            Err(error) => {
                return Err(AgentSandboxUnusable::CanaryFailed {
                    reason: format!("failed to read {} during cleanup: {error}", resource.kind),
                });
            }
        };
        if !controlled_by_uid(&object, owner_uid) {
            return Err(AgentSandboxUnusable::CanaryFailed {
                reason: format!(
                    "refusing to delete foreign {} {namespace}/{name}",
                    resource.kind
                ),
            });
        }
        if object.meta().deletion_timestamp.is_none() {
            let uid = object
                .uid()
                .ok_or_else(|| AgentSandboxUnusable::CanaryFailed {
                    reason: format!("{} {namespace}/{name} has no UID", resource.kind),
                })?;
            let params = DeleteParams {
                propagation_policy: Some(PropagationPolicy::Foreground),
                preconditions: Some(Preconditions {
                    uid: Some(uid),
                    resource_version: object.resource_version(),
                }),
                ..DeleteParams::default()
            };
            match api.delete(name, &params).await {
                Ok(_) => {}
                Err(kube::Error::Api(error)) if error.code == 404 || error.code == 409 => {}
                Err(error) => {
                    return Err(AgentSandboxUnusable::CanaryFailed {
                        reason: format!("failed to delete {}: {error}", resource.kind),
                    });
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(AgentSandboxUnusable::CanaryFailed {
                reason: format!("timed out deleting {} {namespace}/{name}", resource.kind),
            });
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

async fn cleanup_runtime_canary(
    client: &kube::Client,
    namespace: &str,
    name: &str,
    owner_uid: &str,
) -> Result<(), AgentSandboxUnusable> {
    for (kind, plural) in [
        ("SandboxClaim", "sandboxclaims"),
        ("SandboxWarmPool", "sandboxwarmpools"),
        ("SandboxTemplate", "sandboxtemplates"),
    ] {
        delete_canary_object(
            client,
            namespace,
            &runtime_resource(kind, plural),
            name,
            owner_uid,
        )
        .await?;
    }
    Ok(())
}

/// Execute one real create/Ready/delete runtime canary under an exact owner.
///
/// Management startup uses the Kobe Pod; child certification uses the exact
/// lease-owned child Namespace. The deterministic owner-UID name makes a crash
/// recoverable in either cluster. Clean completion requires foreground
/// deletion and a subsequent 404 for Claim, WarmPool and Template.
pub async fn run_runtime_canary_owned(
    client: &kube::Client,
    namespace: &str,
    owner: &k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference,
) -> Result<(), AgentSandboxUnusable> {
    use kube::api::{Api, PostParams};
    let name = canary_name(&owner.uid);

    cleanup_runtime_canary(client, namespace, &name, &owner.uid).await?;
    let resources = [
        runtime_resource("SandboxTemplate", "sandboxtemplates"),
        runtime_resource("SandboxWarmPool", "sandboxwarmpools"),
        runtime_resource("SandboxClaim", "sandboxclaims"),
    ];
    let objects = build_runtime_canary(&name, namespace, owner);
    let create_result = async {
        for (resource, object) in resources.iter().zip(objects.iter()) {
            let api: Api<kube::api::DynamicObject> =
                Api::namespaced_with(client.clone(), namespace, resource);
            let created = api
                .create(&PostParams::default(), object)
                .await
                .map_err(|error| AgentSandboxUnusable::CanaryFailed {
                    reason: format!("failed to create {}: {error}", resource.kind),
                })?;
            if !controlled_by_uid(&created, &owner.uid) {
                return Err(AgentSandboxUnusable::CanaryFailed {
                    reason: format!("created {} without the exact canary owner", resource.kind),
                });
            }
        }

        let claims: Api<kube::api::DynamicObject> = Api::namespaced_with(
            client.clone(),
            namespace,
            &runtime_resource("SandboxClaim", "sandboxclaims"),
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
        loop {
            let claim =
                claims
                    .get(&name)
                    .await
                    .map_err(|error| AgentSandboxUnusable::CanaryFailed {
                        reason: format!("failed to observe SandboxClaim: {error}"),
                    })?;
            let ready = claim
                .data
                .get("status")
                .and_then(|status| status.get("conditions"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|conditions| {
                    conditions.iter().any(|condition| {
                        condition.get("type").and_then(serde_json::Value::as_str) == Some("Ready")
                            && condition.get("status").and_then(serde_json::Value::as_str)
                                == Some("True")
                    })
                });
            let sandbox_recorded = claim
                .data
                .get("status")
                .and_then(|status| status.get("sandbox"))
                .and_then(|sandbox| sandbox.get("name"))
                .and_then(serde_json::Value::as_str)
                .is_some_and(|name| !name.is_empty());
            if ready && sandbox_recorded {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(AgentSandboxUnusable::CanaryFailed {
                    reason: "SandboxClaim did not become Ready within 180s".to_string(),
                });
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    .await;

    let cleanup_result = cleanup_runtime_canary(client, namespace, &name, &owner.uid).await;
    match (create_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(AgentSandboxUnusable::CanaryFailed {
            reason: format!("{primary}; cleanup also failed: {cleanup}"),
        }),
    }
}

/// Execute the management-cluster canary under this Kobe Pod.
pub async fn run_runtime_canary(
    client: &kube::Client,
    pod_namespace: &str,
    pod_name: &str,
) -> Result<(), AgentSandboxUnusable> {
    use k8s_openapi::api::core::v1::Pod;
    use kube::Resource;
    use kube::api::Api;

    let pods: Api<Pod> = Api::namespaced(client.clone(), pod_namespace);
    let pod = pods
        .get(pod_name)
        .await
        .map_err(|error| AgentSandboxUnusable::CanaryFailed {
            reason: format!("cannot read owner Pod {pod_namespace}/{pod_name}: {error}"),
        })?;
    let owner =
        pod.controller_owner_ref(&())
            .ok_or_else(|| AgentSandboxUnusable::CanaryFailed {
                reason: format!("owner Pod {pod_namespace}/{pod_name} has no UID"),
            })?;
    run_runtime_canary_owned(client, pod_namespace, &owner).await
}

/// Wait for a complete runtime certification before serving Sandbox traffic.
///
/// Fresh Helm installs start Kobe and Agent Sandbox concurrently, so a single
/// missing-Deployment observation is not a terminal configuration error. The
/// whole install/health/canary sequence is nevertheless bounded to five
/// minutes; each observation has its own short timeout so an unresponsive API
/// request cannot consume that budget invisibly.
pub async fn wait_for_runtime(
    client: &kube::Client,
    pod_namespace: &str,
    pod_name: &str,
) -> Result<(), AgentSandboxUnusable> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(300);
    loop {
        let last_error = match tokio::time::timeout(
            std::time::Duration::from_secs(15),
            validate_runtime_components(client),
        )
        .await
        {
            Ok(Ok(())) => break,
            Ok(Err(error)) => error,
            Err(_) => component_unhealthy("kubernetes_api", "health read exceeded 15s"),
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(last_error);
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    tokio::time::timeout_at(
        deadline,
        run_runtime_canary(client, pod_namespace, pod_name),
    )
    .await
    .map_err(|_| AgentSandboxUnusable::CanaryFailed {
        reason: "runtime certification exceeded the 300s startup budget".to_string(),
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_runtime_modes_are_explicit_and_case_insensitive() {
        assert_eq!(parse_mode("managed").unwrap(), AgentSandboxMode::Managed);
        assert_eq!(
            parse_mode("  MANAGED  ").unwrap(),
            AgentSandboxMode::Managed
        );
        assert_eq!(AgentSandboxMode::default(), AgentSandboxMode::Disabled);
        assert_eq!(parse_mode("").unwrap(), AgentSandboxMode::Disabled);
        assert_eq!(parse_mode("disabled").unwrap(), AgentSandboxMode::Disabled);
        assert_eq!(parse_mode("external").unwrap(), AgentSandboxMode::External);
        assert_eq!(
            parse_mode("  EXTERNAL  ").unwrap(),
            AgentSandboxMode::External
        );
    }

    #[test]
    fn vendored_release_and_child_bootstrap_are_the_pinned_artifacts() {
        use sha2::{Digest, Sha256};

        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/charts/kobe/files/agent-sandbox-v0.5.4.yaml"
        ))
        .expect("vendored release asset");
        assert_eq!(
            hex::encode(Sha256::digest(source.as_bytes())),
            AGENT_SANDBOX_RELEASE_MANIFEST_SHA256
        );

        let pinned = source.replace(
            "registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.5.4",
            AGENT_SANDBOX_CONTROLLER_IMAGE,
        );
        assert_eq!(
            hex::encode(Sha256::digest(pinned.as_bytes())),
            AGENT_SANDBOX_BOOTSTRAP_SHA256
        );
        assert!(!pinned.contains("agent-sandbox-controller:v0.5.4"));
        assert!(!pinned.to_ascii_lowercase().contains("sandbox-router"));

        let bootstrap = crate::crd::BootstrapConfig::new(
            AGENT_SANDBOX_BOOTSTRAP_NAME,
            crate::crd::BootstrapConfigSpec {
                files: [("agent-sandbox-v0.5.4.yaml".to_string(), pinned.clone())]
                    .into_iter()
                    .collect(),
                job: None,
            },
        );
        validate_managed_bootstrap(&bootstrap).expect("exact bundle accepted");

        let mut tampered = bootstrap;
        tampered
            .spec
            .files
            .get_mut("agent-sandbox-v0.5.4.yaml")
            .expect("manifest")
            .push_str("\n# drift");
        assert!(matches!(
            validate_managed_bootstrap(&tampered),
            Err(AgentSandboxUnusable::BootstrapMismatch { .. })
        ));
    }

    #[test]
    fn runtime_canary_is_exact_owner_restricted_and_bounded() {
        let owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            api_version: "v1".to_string(),
            kind: "Pod".to_string(),
            name: "kobe-operator-0".to_string(),
            uid: "pod-uid".to_string(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        };
        let [template, warm_pool, claim] = build_runtime_canary("canary", "kobe-system", &owner);

        for object in [&template, &warm_pool, &claim] {
            assert!(controlled_by_uid(object, "pod-uid"));
            assert_eq!(object.metadata.namespace.as_deref(), Some("kobe-system"));
        }
        assert_eq!(
            template.data["spec"]["podTemplate"]["spec"]["containers"][0]["image"],
            RUNTIME_CANARY_IMAGE
        );
        assert_eq!(
            template.data["spec"]["podTemplate"]["spec"]["automountServiceAccountToken"],
            false
        );
        assert_eq!(warm_pool.data["spec"]["replicas"], 0);
        assert_eq!(
            claim.data["spec"]["lifecycle"]["shutdownPolicy"],
            "DeleteForeground"
        );
        assert!(claim.data["spec"]["lifecycle"]["shutdownTime"].is_string());

        let namespace_owner = k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
            kind: "Namespace".to_string(),
            name: "kobe-sandbox".to_string(),
            uid: "child-namespace-uid".to_string(),
            ..owner
        };
        for object in build_runtime_canary("child-canary", "kobe-sandbox", &namespace_owner) {
            assert!(controlled_by_uid(&object, "child-namespace-uid"));
            assert_eq!(object.metadata.namespace.as_deref(), Some("kobe-sandbox"));
        }
    }

    #[test]
    fn only_the_pinned_controller_release_is_compatible() {
        assert!(controller_image_reference_is_compatible(
            AGENT_SANDBOX_CONTROLLER_IMAGE
        ));
        assert!(controller_image_reference_is_compatible(
            "registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.5.4"
        ));
        assert!(!controller_image_reference_is_compatible(
            "registry.k8s.io/agent-sandbox/agent-sandbox-controller:latest"
        ));
        assert!(observed_controller_image_is_pinned(
            "registry.k8s.io/agent-sandbox/agent-sandbox-controller@sha256:f7192ebdb18dbcfa26f242b7108f370ecb6e8d99352b427de4697d51853309d8"
        ));
        assert!(!observed_controller_image_is_pinned("sha256:foreign"));
    }

    /// A runtime serving a different version must be refused, not accepted
    /// because the CRD name matched.
    ///
    /// Kobe projects pool and lease configuration onto a specific upstream
    /// schema. A different version can accept the same object and mean
    /// something else by it, which surfaces as a claim no controller
    /// reconciles rather than as an error.
    #[test]
    fn a_different_upstream_version_is_refused() {
        let crd = "sandboxclaims.extensions.agents.x-k8s.io";

        let expected = REQUIRED_AGENT_SANDBOX_API_VERSION;
        assert!(crd_is_compatible(crd, expected, true, &["v1beta1".into()]).is_ok());
        // Serving several versions is fine as long as ours is among them.
        assert!(
            crd_is_compatible(crd, expected, true, &["v1alpha1".into(), "v1beta1".into()]).is_ok()
        );

        let err = crd_is_compatible(crd, expected, true, &["v1alpha1".into()]).unwrap_err();
        assert!(matches!(err, AgentSandboxUnusable::VersionMismatch { .. }));
        assert_eq!(err.reason_code(), "version_mismatch");
        // The found version belongs in the message: "incompatible" without it
        // sends an operator digging for what is actually installed.
        assert!(format!("{err}").contains("v1alpha1"));
    }

    /// A CRD that exists but is not established is not usable — during install
    /// or a failed upgrade it can be present and not yet serving.
    #[test]
    fn an_unestablished_crd_is_not_usable() {
        let err = crd_is_compatible(
            "sandboxclaims.extensions.agents.x-k8s.io",
            REQUIRED_AGENT_SANDBOX_API_VERSION,
            false,
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, AgentSandboxUnusable::CrdMissing { .. }));
        assert_eq!(err.reason_code(), "crd_missing");
    }

    /// All three CRDs are required. A runtime with claims but no warm pools
    /// would pass a laxer check and then fail to serve.
    #[test]
    fn every_consumed_crd_is_required_at_the_version_it_is_consumed_at() {
        assert_eq!(REQUIRED_AGENT_SANDBOX_CRDS.len(), 4);
        for (crd, expected) in REQUIRED_AGENT_SANDBOX_CRDS {
            // The name must sit under the group it is validated against;
            // otherwise a CRD could pass a version check that never applied
            // to it.
            let group = expected.rsplit_once('/').unwrap().0;
            assert!(crd.ends_with(&format!(".{group}")), "{crd} vs {expected}");
        }

        // `sandboxes` lives in the CORE group, and is the one whose absence
        // fails silently: it is read to find the Pod behind a claim, so a
        // runtime without it yields leases that never pass readiness rather
        // than an error.
        assert!(
            REQUIRED_AGENT_SANDBOX_CRDS
                .contains(&("sandboxes.agents.x-k8s.io", CORE_AGENT_SANDBOX_API_VERSION)),
            "the canary reads Sandbox objects, so the runtime must serve them"
        );
    }
}
