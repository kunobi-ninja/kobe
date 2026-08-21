//! Installation and certification of the upstream Agent Sandbox runtime.
//!
//! Kobe consumes `SandboxTemplate`, `SandboxWarmPool` and `SandboxClaim` from
//! the upstream [Agent Sandbox] project. In `managed` mode the chart installs
//! the official v0.5.6 core/extensions bundle with an immutable image digest,
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
use std::collections::{BTreeMap, BTreeSet};

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
pub const AGENT_SANDBOX_RELEASE: &str = "v0.5.6";

/// SHA-256 reported by GitHub for the official v0.5.6
/// `sandbox-with-extensions.yaml` release asset.
#[cfg(test)]
pub const AGENT_SANDBOX_RELEASE_MANIFEST_SHA256: &str =
    "1696dbb6faded503149b3994badb599df5dcf24d5985466881784f442dd9c3e5";

/// Immutable multi-platform controller image used by Kobe-managed assets.
pub const AGENT_SANDBOX_CONTROLLER_IMAGE: &str = "registry.k8s.io/agent-sandbox/agent-sandbox-controller@sha256:dc23fb0d5624c306ca2f8ef0d41848dba670ebaf62beb500f870175aec529ffd";

/// Platform manifests accepted when validating a running external controller.
pub const AGENT_SANDBOX_CONTROLLER_IMAGE_DIGESTS: &[&str] = &[
    "sha256:dc23fb0d5624c306ca2f8ef0d41848dba670ebaf62beb500f870175aec529ffd",
    "sha256:a502cfdbcf550e77509cc56097978458a1ac3d5b59972f21b7ce0e0a84a5c12e",
    "sha256:db3d5a89473701ff0859eb81c98a0f8fcbce70915f2af052f599eba094284061",
];

/// BootstrapConfig installed by the chart for the managed child path.
pub const AGENT_SANDBOX_BOOTSTRAP_NAME: &str = "agent-sandbox-v0-5-6";

/// SHA-256 of the bootstrap file after replacing the mutable upstream image
/// tag with [`AGENT_SANDBOX_CONTROLLER_IMAGE`].
pub const AGENT_SANDBOX_BOOTSTRAP_SHA256: &str =
    "f38255d5aa7761dec45507683127066a1750fbedb1e3b6a56573901033d0110f";

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

fn crd_conversion_is_compatible(
    crd: &k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition,
) -> bool {
    let Some(conversion) = crd.spec.conversion.as_ref() else {
        return false;
    };
    let Some(webhook) = conversion.webhook.as_ref() else {
        return false;
    };
    let Some(config) = webhook.client_config.as_ref() else {
        return false;
    };
    let Some(service) = config.service.as_ref() else {
        return false;
    };
    conversion.strategy == "Webhook"
        && config.url.is_none()
        && config
            .ca_bundle
            .as_ref()
            .is_some_and(|bundle| !bundle.0.is_empty())
        && service.name == "agent-sandbox-webhook-service"
        && service.namespace == AGENT_SANDBOX_SYSTEM_NAMESPACE
        && service.path.as_deref() == Some("/convert")
        && service.port.is_none_or(|port| port == 443)
        && webhook.conversion_review_versions == ["v1".to_string(), "v1beta1".to_string()]
}

/// Whether the served WarmPool schema exposes the v0.5.6 reconciliation
/// checkpoint Kobe relies on before trusting replica counts.
///
/// Serving `v1beta1` is not sufficient: v0.5.4 serves the same API version but
/// has no `status.observedGeneration`, so a client cannot distinguish current
/// replica counts from a status write produced for an older spec generation.
fn warm_pool_crd_supports_observed_generation(
    crd: &k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition,
) -> bool {
    let expected_version = REQUIRED_AGENT_SANDBOX_API_VERSION
        .rsplit('/')
        .next()
        .unwrap_or_default();
    let Some(root) = crd
        .spec
        .versions
        .iter()
        .find(|version| version.name == expected_version && version.served)
        .and_then(|version| version.schema.as_ref())
        .and_then(|schema| schema.open_api_v3_schema.as_ref())
    else {
        return false;
    };
    let Some(observed_generation) = root
        .properties
        .as_ref()
        .and_then(|properties| properties.get("status"))
        .and_then(|status| status.properties.as_ref())
        .and_then(|properties| properties.get("observedGeneration"))
    else {
        return false;
    };

    observed_generation.type_.as_deref() == Some("integer")
        && observed_generation.format.as_deref() == Some("int64")
        && observed_generation.minimum == Some(0.0)
}

/// Validate that a compatible operator-installed runtime is present.
///
/// Every required CRD must be established, serve the pinned version, and use
/// the exact TLS-backed conversion webhook installed by the pinned release.
/// The WarmPool CRD must additionally expose the v0.5.6
/// `status.observedGeneration` checkpoint. The first failure is returned
/// rather than a collected list: an operator fixes these one at a time, and
/// the first one usually explains the rest.
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
        if observed
            .as_ref()
            .is_none_or(|crd| !crd_conversion_is_compatible(crd))
        {
            return Err(component_unhealthy(
                "crd_conversion",
                format!("CRD {name} does not use the exact trusted conversion webhook"),
            ));
        }
        if *name == "sandboxwarmpools.extensions.agents.x-k8s.io"
            && observed
                .as_ref()
                .is_none_or(|crd| !warm_pool_crd_supports_observed_generation(crd))
        {
            return Err(component_unhealthy(
                "crd_schema",
                format!("CRD {name} does not expose v0.5.6 status.observedGeneration"),
            ));
        }
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

/// Require one sole controller owner with the exact immutable identity.
///
/// Kubernetes permits several non-controller owners, but at most one owner is
/// authoritative for reconciliation. Ambiguous or name-reused controller
/// ownership therefore fails closed.
fn exact_controller_uid(
    metadata: &kube::api::ObjectMeta,
    api_version: &str,
    kind: &str,
    name: &str,
    uid: &str,
) -> bool {
    let mut controllers = metadata
        .owner_references
        .as_ref()
        .into_iter()
        .flatten()
        .filter(|owner| owner.controller == Some(true));
    let Some(owner) = controllers.next() else {
        return false;
    };
    controllers.next().is_none()
        && owner.api_version == api_version
        && owner.kind == kind
        && owner.name == name
        && owner.uid == uid
}

fn deployment_rollout_is_converged(
    status: &k8s_openapi::api::apps::v1::DeploymentStatus,
    desired_replicas: i32,
) -> bool {
    status.replicas.unwrap_or_default() == desired_replicas
        && status.updated_replicas.unwrap_or_default() == desired_replicas
        && status.ready_replicas.unwrap_or_default() == desired_replicas
        && status.available_replicas.unwrap_or_default() == desired_replicas
        && status.unavailable_replicas.unwrap_or_default() == 0
}

fn exact_webhook_service_uid(
    service: &k8s_openapi::api::core::v1::Service,
    selector_labels: &BTreeMap<String, String>,
) -> Result<String, AgentSandboxUnusable> {
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

    if service.metadata.deletion_timestamp.is_some() {
        return Err(component_unhealthy(
            "webhook_service",
            "Service is deleting",
        ));
    }
    let uid = service
        .metadata
        .uid
        .as_deref()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| component_unhealthy("webhook_service", "UID is missing"))?;
    let spec = service
        .spec
        .as_ref()
        .ok_or_else(|| component_unhealthy("webhook_service", "spec is missing"))?;
    if spec.selector.as_ref() != Some(selector_labels) {
        return Err(component_unhealthy(
            "webhook_service",
            "selector does not exactly match the controller Deployment",
        ));
    }
    let ports = spec
        .ports
        .as_ref()
        .filter(|ports| ports.len() == 1)
        .ok_or_else(|| {
            component_unhealthy(
                "webhook_service",
                "expected exactly one webhook Service port",
            )
        })?;
    let port = &ports[0];
    if port.name.as_deref() != Some("webhook")
        || port.port != 443
        || port.protocol.as_deref() != Some("TCP")
        || port.target_port != Some(IntOrString::Int(9443))
    {
        return Err(component_unhealthy(
            "webhook_service",
            "webhook port must be TCP 443 targeting 9443",
        ));
    }
    Ok(uid.to_string())
}

fn endpoint_slices_cover_exact_pods(
    slices: &[k8s_openapi::api::discovery::v1::EndpointSlice],
    service_uid: &str,
    pinned_pod_uids: &BTreeSet<String>,
) -> bool {
    if slices.is_empty() || pinned_pod_uids.is_empty() {
        return false;
    }

    let mut endpoint_pod_uids = BTreeSet::new();
    for slice in slices {
        if slice.metadata.deletion_timestamp.is_some()
            || !exact_controller_uid(
                &slice.metadata,
                "v1",
                "Service",
                "agent-sandbox-webhook-service",
                service_uid,
            )
        {
            return false;
        }
        let Some(ports) = slice.ports.as_ref().filter(|ports| ports.len() == 1) else {
            return false;
        };
        let port = &ports[0];
        if port.name.as_deref() != Some("webhook")
            || port.port != Some(9443)
            || port.protocol.as_deref() != Some("TCP")
        {
            return false;
        }
        if slice.endpoints.is_empty() {
            return false;
        }
        for endpoint in &slice.endpoints {
            let Some(target) = endpoint.target_ref.as_ref() else {
                return false;
            };
            let Some(uid) = target
                .uid
                .as_ref()
                .filter(|uid| pinned_pod_uids.contains(*uid))
            else {
                return false;
            };
            if endpoint.conditions.as_ref().is_none_or(|conditions| {
                conditions.ready != Some(true) || conditions.terminating == Some(true)
            }) || target.api_version.as_deref() != Some("v1")
                || target.kind.as_deref() != Some("Pod")
                || target.namespace.as_deref() != Some(AGENT_SANDBOX_SYSTEM_NAMESPACE)
                || target.name.as_deref().is_none_or(str::is_empty)
                || !endpoint_pod_uids.insert(uid.clone())
            {
                return false;
            }
        }
    }
    endpoint_pod_uids == *pinned_pod_uids
}

/// Validate the pinned controller, conversion webhook and running image.
///
/// CRD presence alone is not a runtime signal. This additionally requires the
/// v0.5.6 Deployment and its single current ReplicaSet to have converged, every
/// selected Pod to be exact-owned, Ready, and running the pinned image, and the
/// exact webhook Service to route only to those Pod UIDs through owned
/// EndpointSlices. The webhook TLS Secret must also contain all required keys.
pub async fn validate_runtime_components(
    client: &kube::Client,
) -> Result<(), AgentSandboxUnusable> {
    use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet};
    use k8s_openapi::api::core::v1::{Pod, Secret, Service};
    use k8s_openapi::api::discovery::v1::EndpointSlice;
    use kube::api::{Api, ListParams};
    use kube::runtime::reflector::ObjectRef;

    validate_external_runtime(client).await?;

    let deployments: Api<Deployment> =
        Api::namespaced(client.clone(), AGENT_SANDBOX_SYSTEM_NAMESPACE);
    let deployment = deployments
        .get("agent-sandbox-controller")
        .await
        .map_err(|error| component_unhealthy("controller_deployment", error.to_string()))?;
    let deployment_uid = deployment
        .metadata
        .uid
        .as_deref()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| component_unhealthy("controller_deployment", "UID is missing"))?;
    if deployment.metadata.deletion_timestamp.is_some() {
        return Err(component_unhealthy(
            "controller_deployment",
            "Deployment is deleting",
        ));
    }
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
    if !deployment_rollout_is_converged(status, desired_replicas) {
        return Err(component_unhealthy(
            "controller_deployment",
            format!(
                "rollout has replicas={}/updated={}/ready={}/available={}/unavailable={}, expected {desired_replicas} fully converged replicas",
                status.replicas.unwrap_or_default(),
                status.updated_replicas.unwrap_or_default(),
                status.ready_replicas.unwrap_or_default(),
                status.available_replicas.unwrap_or_default(),
                status.unavailable_replicas.unwrap_or_default(),
            ),
        ));
    }
    let deployment_spec = deployment.spec.as_ref().ok_or_else(|| {
        component_unhealthy("controller_deployment", "Deployment spec is missing")
    })?;
    let selector_labels = deployment_spec
        .selector
        .match_labels
        .as_ref()
        .filter(|labels| !labels.is_empty())
        .ok_or_else(|| {
            component_unhealthy(
                "controller_deployment",
                "Deployment selector has no exact matchLabels",
            )
        })?;
    if deployment_spec
        .selector
        .match_expressions
        .as_ref()
        .is_some_and(|expressions| !expressions.is_empty())
    {
        return Err(component_unhealthy(
            "controller_deployment",
            "Deployment selector uses unsupported matchExpressions",
        ));
    }
    let deployment_pod_spec = deployment_spec
        .template
        .spec
        .as_ref()
        .ok_or_else(|| component_unhealthy("controller_deployment", "Pod spec is missing"))?;
    let controller = deployment_pod_spec
        .containers
        .iter()
        .find(|container| container.name == "agent-sandbox-controller")
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

    let selector = selector_labels
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",");
    let replica_sets: Api<ReplicaSet> =
        Api::namespaced(client.clone(), AGENT_SANDBOX_SYSTEM_NAMESPACE);
    let replica_sets = replica_sets
        .list(&ListParams::default().labels(&selector))
        .await
        .map_err(|error| component_unhealthy("controller_replicaset", error.to_string()))?;
    let mut current_replica_sets = replica_sets.iter().filter(|replica_set| {
        let spec = replica_set.spec.as_ref();
        let status = replica_set.status.as_ref();
        replica_set.metadata.deletion_timestamp.is_none()
            && exact_controller_uid(
                &replica_set.metadata,
                "apps/v1",
                "Deployment",
                "agent-sandbox-controller",
                deployment_uid,
            )
            && spec.and_then(|spec| spec.replicas) == Some(desired_replicas)
            && spec
                .and_then(|spec| spec.template.as_ref())
                .and_then(|template| template.spec.as_ref())
                == Some(deployment_pod_spec)
            && selector_labels.iter().all(|(key, value)| {
                spec.and_then(|spec| spec.template.as_ref())
                    .and_then(|template| template.metadata.as_ref())
                    .and_then(|metadata| metadata.labels.as_ref())
                    .and_then(|labels| labels.get(key))
                    == Some(value)
            })
            && status.is_some_and(|status| {
                status.observed_generation == replica_set.metadata.generation
                    && status.replicas == desired_replicas
                    && status.fully_labeled_replicas.unwrap_or_default() == desired_replicas
                    && status.ready_replicas.unwrap_or_default() == desired_replicas
                    && status.available_replicas.unwrap_or_default() == desired_replicas
            })
    });
    let Some(current_replica_set) = current_replica_sets.next() else {
        return Err(component_unhealthy(
            "controller_replicaset",
            "no exact Deployment-owned ReplicaSet has fully converged",
        ));
    };
    if current_replica_sets.next().is_some() {
        return Err(component_unhealthy(
            "controller_replicaset",
            "more than one active ReplicaSet matches the current Deployment template",
        ));
    }
    let current_replica_set_uid = current_replica_set
        .metadata
        .uid
        .as_deref()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| component_unhealthy("controller_replicaset", "UID is missing"))?;

    let pods: Api<Pod> = Api::namespaced(client.clone(), AGENT_SANDBOX_SYSTEM_NAMESPACE);
    let pods = pods
        .list(&ListParams::default().labels(&selector))
        .await
        .map_err(|error| component_unhealthy("controller_pod", error.to_string()))?;
    if pods.items.len() != usize::try_from(desired_replicas).unwrap_or(usize::MAX) {
        return Err(component_unhealthy(
            "controller_pod",
            format!(
                "observed {} matching Pods, expected exactly {desired_replicas}",
                pods.items.len()
            ),
        ));
    }
    let mut pinned_pod_uids = BTreeSet::new();
    let all_pods_pinned_and_ready = pods.iter().all(|pod| {
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
        let owned = exact_controller_uid(
            &pod.metadata,
            "apps/v1",
            "ReplicaSet",
            &current_replica_set
                .metadata
                .name
                .clone()
                .unwrap_or_default(),
            current_replica_set_uid,
        );
        let uid = pod
            .metadata
            .uid
            .as_ref()
            .filter(|uid| !uid.is_empty())
            .cloned();
        if ready
            && pinned
            && owned
            && pod.metadata.deletion_timestamp.is_none()
            && let Some(uid) = uid
        {
            pinned_pod_uids.insert(uid);
            return true;
        }
        false
    });
    if !all_pods_pinned_and_ready
        || pinned_pod_uids.len() != usize::try_from(desired_replicas).unwrap_or(usize::MAX)
    {
        let observed = pods
            .iter()
            .map(|pod| ObjectRef::from_obj(pod).name)
            .collect::<Vec<_>>()
            .join(",");
        return Err(component_unhealthy(
            "controller_pod",
            format!(
                "not every current ReplicaSet Pod is Ready, exact-owned and pinned (observed: {observed})"
            ),
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

    let services: Api<Service> = Api::namespaced(client.clone(), AGENT_SANDBOX_SYSTEM_NAMESPACE);
    let webhook_service = services
        .get("agent-sandbox-webhook-service")
        .await
        .map_err(|error| component_unhealthy("webhook_service", error.to_string()))?;
    let webhook_service_uid = exact_webhook_service_uid(&webhook_service, selector_labels)?;

    let endpoint_slices: Api<EndpointSlice> =
        Api::namespaced(client.clone(), AGENT_SANDBOX_SYSTEM_NAMESPACE);
    let webhook_slices = endpoint_slices
        .list(
            &ListParams::default()
                .labels("kubernetes.io/service-name=agent-sandbox-webhook-service"),
        )
        .await
        .map_err(|error| component_unhealthy("webhook_endpoint", error.to_string()))?;
    let ready = endpoint_slices_cover_exact_pods(
        &webhook_slices.items,
        &webhook_service_uid,
        &pinned_pod_uids,
    );
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
        .get("agent-sandbox-v0.5.6.yaml")
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
            "/charts/kobe/files/agent-sandbox-v0.5.6.yaml"
        ))
        .expect("vendored release asset");
        assert_eq!(
            hex::encode(Sha256::digest(source.as_bytes())),
            AGENT_SANDBOX_RELEASE_MANIFEST_SHA256
        );

        let warm_pool_crd = source
            .split("\n---\n")
            .filter_map(|document| {
                serde_yaml_ng::from_str::<
                    k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition,
                >(document)
                .ok()
            })
            .find(|crd| {
                crd.metadata.name.as_deref()
                    == Some("sandboxwarmpools.extensions.agents.x-k8s.io")
            })
            .expect("vendored WarmPool CRD");
        assert!(warm_pool_crd_supports_observed_generation(&warm_pool_crd));

        let pinned = source.replace(
            "registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.5.6",
            AGENT_SANDBOX_CONTROLLER_IMAGE,
        );
        assert_eq!(
            hex::encode(Sha256::digest(pinned.as_bytes())),
            AGENT_SANDBOX_BOOTSTRAP_SHA256
        );
        assert!(!pinned.contains("agent-sandbox-controller:v0.5.6"));
        assert!(!pinned.to_ascii_lowercase().contains("sandbox-router"));

        let bootstrap = crate::crd::BootstrapConfig::new(
            AGENT_SANDBOX_BOOTSTRAP_NAME,
            crate::crd::BootstrapConfigSpec {
                files: [("agent-sandbox-v0.5.6.yaml".to_string(), pinned.clone())]
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
            .get_mut("agent-sandbox-v0.5.6.yaml")
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
            "registry.k8s.io/agent-sandbox/agent-sandbox-controller:v0.5.6"
        ));
        assert!(!controller_image_reference_is_compatible(
            "registry.k8s.io/agent-sandbox/agent-sandbox-controller:latest"
        ));
        assert!(observed_controller_image_is_pinned(
            "registry.k8s.io/agent-sandbox/agent-sandbox-controller@sha256:a502cfdbcf550e77509cc56097978458a1ac3d5b59972f21b7ce0e0a84a5c12e"
        ));
        assert!(!observed_controller_image_is_pinned("sha256:foreign"));
    }

    #[test]
    fn controller_rollout_requires_every_replica_to_be_current_and_ready() {
        let mut status: k8s_openapi::api::apps::v1::DeploymentStatus =
            serde_json::from_value(serde_json::json!({
                "replicas": 2,
                "updatedReplicas": 2,
                "readyReplicas": 2,
                "availableReplicas": 2,
                "unavailableReplicas": 0
            }))
            .expect("DeploymentStatus");
        assert!(deployment_rollout_is_converged(&status, 2));

        status.updated_replicas = Some(1);
        assert!(!deployment_rollout_is_converged(&status, 2));
        status.updated_replicas = Some(2);
        status.unavailable_replicas = Some(1);
        assert!(!deployment_rollout_is_converged(&status, 2));
    }

    #[test]
    fn crd_conversion_requires_the_exact_tls_webhook() {
        let exact: k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition =
            serde_json::from_value(serde_json::json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "sandboxclaims.extensions.agents.x-k8s.io" },
                "spec": {
                    "group": "extensions.agents.x-k8s.io",
                    "scope": "Namespaced",
                    "names": {
                        "plural": "sandboxclaims",
                        "singular": "sandboxclaim",
                        "kind": "SandboxClaim",
                        "listKind": "SandboxClaimList"
                    },
                    "versions": [{ "name": "v1beta1", "served": true, "storage": true }],
                    "conversion": {
                        "strategy": "Webhook",
                        "webhook": {
                            "clientConfig": {
                                "caBundle": "Y2E=",
                                "service": {
                                    "name": "agent-sandbox-webhook-service",
                                    "namespace": AGENT_SANDBOX_SYSTEM_NAMESPACE,
                                    "path": "/convert",
                                    "port": 443
                                }
                            },
                            "conversionReviewVersions": ["v1", "v1beta1"]
                        }
                    }
                }
            }))
            .expect("CRD");
        assert!(crd_conversion_is_compatible(&exact));

        let mut replaced_service = exact.clone();
        replaced_service
            .spec
            .conversion
            .as_mut()
            .unwrap()
            .webhook
            .as_mut()
            .unwrap()
            .client_config
            .as_mut()
            .unwrap()
            .service
            .as_mut()
            .unwrap()
            .name = "replacement-webhook".to_string();
        assert!(!crd_conversion_is_compatible(&replaced_service));

        let mut untrusted = exact;
        untrusted
            .spec
            .conversion
            .as_mut()
            .unwrap()
            .webhook
            .as_mut()
            .unwrap()
            .client_config
            .as_mut()
            .unwrap()
            .ca_bundle = None;
        assert!(!crd_conversion_is_compatible(&untrusted));
    }

    #[test]
    fn warm_pool_schema_requires_the_current_generation_checkpoint() {
        let exact = serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {
                "name": "sandboxwarmpools.extensions.agents.x-k8s.io"
            },
            "spec": {
                "group": "extensions.agents.x-k8s.io",
                "scope": "Namespaced",
                "names": {
                    "plural": "sandboxwarmpools",
                    "singular": "sandboxwarmpool",
                    "kind": "SandboxWarmPool",
                    "listKind": "SandboxWarmPoolList"
                },
                "versions": [{
                    "name": "v1beta1",
                    "served": true,
                    "storage": true,
                    "schema": {
                        "openAPIV3Schema": {
                            "type": "object",
                            "properties": {
                                "status": {
                                    "type": "object",
                                    "properties": {
                                        "observedGeneration": {
                                            "type": "integer",
                                            "format": "int64",
                                            "minimum": 0
                                        }
                                    }
                                }
                            }
                        }
                    }
                }]
            }
        });
        let crd = serde_json::from_value(exact.clone()).expect("WarmPool CRD");
        assert!(warm_pool_crd_supports_observed_generation(&crd));

        let mut legacy = exact.clone();
        legacy["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]
            ["status"]["properties"]
            .as_object_mut()
            .expect("status properties")
            .remove("observedGeneration");
        let crd = serde_json::from_value(legacy).expect("legacy WarmPool CRD");
        assert!(!warm_pool_crd_supports_observed_generation(&crd));

        let mut drifted = exact;
        drifted["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["status"]["properties"]
            ["observedGeneration"]["format"] = serde_json::json!("int32");
        let crd = serde_json::from_value(drifted).expect("drifted WarmPool CRD");
        assert!(!warm_pool_crd_supports_observed_generation(&crd));
    }

    #[test]
    fn webhook_endpoints_require_exact_service_and_pod_uids() {
        let selector = [("app".to_string(), "agent-sandbox-controller".to_string())]
            .into_iter()
            .collect();
        let service: k8s_openapi::api::core::v1::Service =
            serde_json::from_value(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "name": "agent-sandbox-webhook-service",
                    "namespace": AGENT_SANDBOX_SYSTEM_NAMESPACE,
                    "uid": "service-uid"
                },
                "spec": {
                    "selector": { "app": "agent-sandbox-controller" },
                    "ports": [{
                        "name": "webhook",
                        "port": 443,
                        "protocol": "TCP",
                        "targetPort": 9443
                    }]
                }
            }))
            .expect("Service");
        let service_uid =
            exact_webhook_service_uid(&service, &selector).expect("exact webhook Service");
        let exact_slice: k8s_openapi::api::discovery::v1::EndpointSlice =
            serde_json::from_value(serde_json::json!({
                "apiVersion": "discovery.k8s.io/v1",
                "kind": "EndpointSlice",
                "metadata": {
                    "name": "agent-sandbox-webhook-service-a",
                    "namespace": AGENT_SANDBOX_SYSTEM_NAMESPACE,
                    "ownerReferences": [{
                        "apiVersion": "v1",
                        "kind": "Service",
                        "name": "agent-sandbox-webhook-service",
                        "uid": "service-uid",
                        "controller": true
                    }]
                },
                "addressType": "IPv4",
                "ports": [{ "name": "webhook", "port": 9443, "protocol": "TCP" }],
                "endpoints": [{
                    "addresses": ["10.0.0.2"],
                    "conditions": { "ready": true, "terminating": false },
                    "targetRef": {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "name": "agent-sandbox-controller-current",
                        "namespace": AGENT_SANDBOX_SYSTEM_NAMESPACE,
                        "uid": "pod-uid"
                    }
                }]
            }))
            .expect("EndpointSlice");
        let pod_uids = ["pod-uid".to_string()].into_iter().collect();
        assert!(endpoint_slices_cover_exact_pods(
            std::slice::from_ref(&exact_slice),
            &service_uid,
            &pod_uids
        ));

        let mut ambiguous_owner = exact_slice.clone();
        ambiguous_owner
            .metadata
            .owner_references
            .as_mut()
            .unwrap()
            .push(
                k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                    api_version: "v1".to_string(),
                    kind: "Service".to_string(),
                    name: "other-service".to_string(),
                    uid: "other-service-uid".to_string(),
                    controller: Some(true),
                    block_owner_deletion: Some(true),
                },
            );
        assert!(!endpoint_slices_cover_exact_pods(
            &[ambiguous_owner],
            &service_uid,
            &pod_uids
        ));

        let mut replaced_service = exact_slice.clone();
        replaced_service.metadata.owner_references.as_mut().unwrap()[0].uid =
            "replacement-service".to_string();
        assert!(!endpoint_slices_cover_exact_pods(
            &[replaced_service],
            &service_uid,
            &pod_uids
        ));

        let mut replaced_pod = exact_slice;
        replaced_pod.endpoints[0].target_ref.as_mut().unwrap().uid =
            Some("replacement-pod".to_string());
        assert!(!endpoint_slices_cover_exact_pods(
            &[replaced_pod],
            &service_uid,
            &pod_uids
        ));
    }

    #[test]
    fn runtime_rollout_observation_is_read_only_in_the_chart() {
        let chart = include_str!("../charts/kobe/templates/rbac.yaml");
        assert!(
            chart.contains(
                "resources: [\"replicasets\"]\n    verbs: [\"get\", \"list\", \"watch\"]"
            )
        );
        assert!(chart.contains(
            "resources: [\"endpointslices\"]\n    verbs: [\"get\", \"list\", \"watch\"]"
        ));
        assert!(!chart.contains(
            "resources: [\"replicasets\"]\n    verbs: [\"get\", \"list\", \"watch\", \"patch\"]"
        ));
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

    /// All four CRDs are required. A runtime with claims but no warm pools
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
