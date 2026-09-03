//! Kobe-native API contracts for leasing upstream Agent Sandbox capacity.
//!
//! These types deliberately expose a much smaller surface than an upstream
//! `PodSpec` or `SandboxClaim`. Administrators define a bounded [`SandboxPool`];
//! callers can request only a pool, TTL, alias, and requester identity through a
//! [`SandboxLease`]. Placement controllers translate that intent into upstream
//! resources without accepting caller-provided namespaces, credentials, mounts,
//! environment variables, PVCs, or runtime classes.

use std::collections::BTreeSet;

use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::TeardownEvidenceReference;

/// Administrator-owned class of Agent Sandbox capacity.
///
/// Root CRD CEL can couple the status generation markers to one another, but
/// Kubernetes does not expose `metadata.generation` to CRD validation rules.
/// The API and controllers therefore revalidate those markers against the
/// live object's generation before they admit work or trust readiness.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, KubeSchema, PartialEq, Eq)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "SandboxPool",
    plural = "sandboxpools",
    shortname = "sp",
    status = "SandboxPoolStatus",
    namespaced,
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.conditions) || !self.status.conditions.exists(c, c.type == 'Ready' && c.status == 'True') || (has(self.status.observedGeneration) && self.status.conditions.exists(c, c.type == 'Ready' && c.status == 'True' && has(c.observedGeneration) && c.observedGeneration == self.status.observedGeneration) && has(self.status.certification) && self.status.certification.phase == 'certified' && self.status.certification.observedGeneration == self.status.observedGeneration && has(self.status.certification.certifiedAt))")
        .message("Ready=True requires a coherent observed-generation durable Certified receipt"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.certification) || (has(self.status) && self.status != null && has(self.status.certification) && (oldSelf.status.certification.fingerprint != self.status.certification.fingerprint || (oldSelf.status.certification.sandboxTemplate == self.status.certification.sandboxTemplate && oldSelf.status.certification.sandboxWarmPool == self.status.certification.sandboxWarmPool && (!has(oldSelf.status.certification.sandboxClaim) || (has(self.status.certification.sandboxClaim) && oldSelf.status.certification.sandboxClaim == self.status.certification.sandboxClaim)) && (!has(oldSelf.status.certification.sandbox) || (has(self.status.certification.sandbox) && oldSelf.status.certification.sandbox == self.status.certification.sandbox)) && (!has(oldSelf.status.certification.pod) || (has(self.status.certification.pod) && oldSelf.status.certification.pod == self.status.certification.pod)) && (!has(oldSelf.status.certification.service) || (has(self.status.certification.service) && oldSelf.status.certification.service == self.status.certification.service)) && (!has(oldSelf.status.certification.persistentVolumeClaims) || (has(self.status.certification.persistentVolumeClaims) && oldSelf.status.certification.persistentVolumeClaims == self.status.certification.persistentVolumeClaims)) && (!has(oldSelf.status.certification.persistentVolumes) || (has(self.status.certification.persistentVolumes) && oldSelf.status.certification.persistentVolumes == self.status.certification.persistentVolumes)) && (!has(oldSelf.status.certification.baselineIdleSandboxUids) || (has(self.status.certification.baselineIdleSandboxUids) && oldSelf.status.certification.baselineIdleSandboxUids == self.status.certification.baselineIdleSandboxUids)) && (!has(oldSelf.status.certification.teardownFence) || (has(self.status.certification.teardownFence) && oldSelf.status.certification.teardownFence == self.status.certification.teardownFence)) && (!has(oldSelf.status.certification.drainGeneration) || (has(self.status.certification.drainGeneration) && oldSelf.status.certification.drainGeneration == self.status.certification.drainGeneration)) && (!has(oldSelf.status.certification.replenishGeneration) || (has(self.status.certification.replenishGeneration) && oldSelf.status.certification.replenishGeneration == self.status.certification.replenishGeneration)) && (!has(oldSelf.status.certification.canaryPassedAt) || (has(self.status.certification.canaryPassedAt) && oldSelf.status.certification.canaryPassedAt == self.status.certification.canaryPassedAt)) && (!has(oldSelf.status.certification.certifiedAt) || (has(self.status.certification.certifiedAt) && oldSelf.status.certification.certifiedAt == self.status.certification.certifiedAt)))))")
        .message("exact certification references are immutable within one fingerprint"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.certification) || (has(self.status) && self.status != null && has(self.status.certification) && (oldSelf.status.certification.fingerprint == self.status.certification.fingerprint || oldSelf.status.certification.phase == 'certified' || (oldSelf.status.certification.phase in ['initialized', 'cleanupBlocked'] && !has(oldSelf.status.certification.sandboxClaim) && !has(oldSelf.status.certification.sandbox) && !has(oldSelf.status.certification.teardownFence))))")
        .message("an active certification fingerprint cannot be abandoned before exact cleanup"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.placementAuthority) || !has(self.status.placement) || (self.status.placement.type == 'childCluster' && self.status.placementAuthority.apiVersion == 'kobe.kunobi.ninja/v1alpha1' && self.status.placementAuthority.kind == 'ClusterPool' && self.status.placementAuthority.name == self.status.placement.clusterPoolRef)")
        .message("placementAuthority must identify the exact child ClusterPool"),
    validation = Rule::new("!has(self.status) || self.status == null || (has(self.status.placementAuthority) == (has(self.status.placement) && self.status.placement.type == 'childCluster' && has(self.status.observedGeneration) && has(self.status.conditions) && self.status.conditions.exists(c, c.type == 'Ready' && c.status == 'False' && c.reason == 'CompositionEligible' && has(c.observedGeneration) && c.observedGeneration == self.status.observedGeneration)))")
        .message("placementAuthority is published only with coherent CompositionEligible status"),
    printcolumn = r#"{"name":"Ready","type":"integer","jsonPath":".status.ready"}"#,
    printcolumn = r#"{"name":"Allocated","type":"integer","jsonPath":".status.allocated"}"#,
    printcolumn = r#"{"name":"Quarantined","type":"integer","jsonPath":".status.quarantined"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxPoolSpec {
    /// Desired number of unclaimed upstream Sandboxes kept warm.
    #[schemars(range(max = 2147483647))]
    pub warm_capacity: u32,

    /// TTL used when a lease request omits one.
    #[schemars(length(min = 1))]
    pub default_ttl: String,

    /// Maximum runtime TTL this pool will accept, independent of caller policy.
    #[schemars(length(min = 1))]
    pub max_ttl: String,

    /// Maximum time allowed for placement and Sandbox provisioning. Runtime TTL
    /// starts only after readiness and is therefore separate from this deadline.
    #[schemars(length(min = 1))]
    pub provisioning_timeout: String,

    /// Exactly one target class. The tagged enum makes management and child
    /// placement mutually exclusive in both JSON and generated OpenAPI.
    pub placement: SandboxPlacement,

    /// Restricted template translated into the controller-owned upstream
    /// `SandboxTemplate`; this is intentionally not a `PodSpec` escape hatch.
    pub template: SandboxTemplateSpec,

    /// Claimed workload-isolation mechanism. Hardened tiers carry the exact
    /// administrator-selected RuntimeClass; leases cannot override it.
    pub isolation: SandboxIsolation,

    /// Pool-specific execution canary used in addition to fixed controller
    /// checks such as upstream readiness and runtime verification.
    pub readiness: SandboxReadinessRequirements,
}

impl SandboxPoolSpec {
    /// Validate relationships that cannot be expressed by the Rust type shape.
    ///
    /// Controllers and administrative admission paths must call this before
    /// rendering upstream objects. Structural exclusivity for placement and
    /// isolation is already enforced by tagged enums.
    // `crdgen` imports this module for schemas without calling runtime helpers.
    #[allow(dead_code)]
    pub fn validate(&self) -> Result<(), SandboxPoolValidationError> {
        for (field, value) in [
            ("defaultTtl", self.default_ttl.as_str()),
            ("maxTtl", self.max_ttl.as_str()),
            ("provisioningTimeout", self.provisioning_timeout.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(SandboxPoolValidationError::EmptyDuration(field));
            }
        }

        if self.warm_capacity > i32::MAX as u32 {
            return Err(SandboxPoolValidationError::WarmCapacityTooLarge);
        }
        if let SandboxPlacement::ChildCluster { cluster_pool_ref } = &self.placement
            && cluster_pool_ref.trim().is_empty()
        {
            return Err(SandboxPoolValidationError::EmptyClusterPoolRef);
        }

        if self.template.containers.is_empty() {
            return Err(SandboxPoolValidationError::NoContainers);
        }

        let mut container_names = BTreeSet::new();
        for container in &self.template.containers {
            if container.name.trim().is_empty() {
                return Err(SandboxPoolValidationError::EmptyContainerName);
            }
            if !container_names.insert(container.name.as_str()) {
                return Err(SandboxPoolValidationError::DuplicateContainer(
                    container.name.clone(),
                ));
            }
            if container.image.trim().is_empty() {
                return Err(SandboxPoolValidationError::EmptyContainerImage(
                    container.name.clone(),
                ));
            }
            for (field, value) in [
                ("requests.cpu", container.resources.requests.cpu.as_str()),
                (
                    "requests.memory",
                    container.resources.requests.memory.as_str(),
                ),
                (
                    "requests.ephemeralStorage",
                    container.resources.requests.ephemeral_storage.as_str(),
                ),
                ("limits.cpu", container.resources.limits.cpu.as_str()),
                ("limits.memory", container.resources.limits.memory.as_str()),
                (
                    "limits.ephemeralStorage",
                    container.resources.limits.ephemeral_storage.as_str(),
                ),
            ] {
                if value.trim().is_empty() {
                    return Err(SandboxPoolValidationError::EmptyResource {
                        container: container.name.clone(),
                        field,
                    });
                }
            }
        }

        if !container_names.contains(self.template.default_container.as_str()) {
            return Err(SandboxPoolValidationError::UnknownDefaultContainer(
                self.template.default_container.clone(),
            ));
        }

        let mut port_names = BTreeSet::new();
        let mut target_ports = BTreeSet::new();
        for port in &self.template.exposed_ports {
            if port.name.trim().is_empty() {
                return Err(SandboxPoolValidationError::EmptyPortName);
            }
            if !port_names.insert(port.name.as_str()) {
                return Err(SandboxPoolValidationError::DuplicatePortName(
                    port.name.clone(),
                ));
            }
            if port.port == 0 {
                return Err(SandboxPoolValidationError::ZeroPort(port.name.clone()));
            }
            if !container_names.contains(port.container.as_str()) {
                return Err(SandboxPoolValidationError::UnknownPortContainer {
                    port: port.name.clone(),
                    container: port.container.clone(),
                });
            }
            if !target_ports.insert((port.container.as_str(), port.port)) {
                return Err(SandboxPoolValidationError::DuplicateContainerPort {
                    container: port.container.clone(),
                    port: port.port,
                });
            }
        }

        if let Some(runtime_class) = self.isolation.runtime_class_name()
            && runtime_class.trim().is_empty()
        {
            return Err(SandboxPoolValidationError::EmptyRuntimeClass);
        }

        if self.readiness.canary.argv.is_empty()
            || self
                .readiness
                .canary
                .argv
                .iter()
                .any(|part| part.is_empty())
        {
            return Err(SandboxPoolValidationError::EmptyCanaryArgv);
        }
        if self.readiness.canary.timeout.trim().is_empty() {
            return Err(SandboxPoolValidationError::EmptyCanaryTimeout);
        }

        Ok(())
    }
}

/// Exactly one place in which a SandboxPool may be reconciled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum SandboxPlacement {
    /// Reconcile upstream objects in Kobe's management cluster.
    Management {},
    /// Acquire a child cluster from this same-namespace ClusterPool.
    ChildCluster {
        /// Name of the administrator-owned `ClusterPool` used for composition.
        #[serde(rename = "clusterPoolRef")]
        cluster_pool_ref: String,
    },
}

// Internally tagged enums normally become `oneOf` schemas whose discriminator
// property has a different enum value in each branch. Kubernetes structural
// CRDs reject that shape, so keep the wire representation while publishing one
// flat object plus CEL for the branch invariant.
impl JsonSchema for SandboxPlacement {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SandboxPlacement".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        serde_json::from_value(serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["type"],
            "properties": {
                "type": { "type": "string", "enum": ["management", "childCluster"] },
                "clusterPoolRef": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 63,
                    "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"
                }
            },
            "x-kubernetes-validations": [{
                "rule": "(self.type == 'management' && !has(self.clusterPoolRef)) || (self.type == 'childCluster' && has(self.clusterPoolRef))",
                "message": "management must not set clusterPoolRef; childCluster must set it"
            }]
        }))
        .expect("static SandboxPlacement schema is valid")
    }
}

/// Restricted administrator-authored template for one Sandbox Pod.
#[derive(Debug, Clone, Serialize, Deserialize, KubeSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[x_kube(
    validation = Rule::new("self.containers.exists(c, c.name == self.defaultContainer)")
        .message("defaultContainer must name one declared container")
)]
#[x_kube(
    validation = Rule::new("self.containers.all(c, self.containers.filter(other, other.name == c.name).size() == 1)")
        .message("container names must be unique")
)]
#[x_kube(
    validation = Rule::new("!has(self.exposedPorts) || self.exposedPorts.all(p, self.containers.exists(c, c.name == p.container))")
        .message("every exposed port must name one declared container")
)]
#[x_kube(
    validation = Rule::new("!has(self.exposedPorts) || self.exposedPorts.all(p, self.exposedPorts.filter(other, other.name == p.name).size() == 1)")
        .message("exposed port names must be unique")
)]
#[x_kube(
    validation = Rule::new("!has(self.exposedPorts) || self.exposedPorts.all(p, self.exposedPorts.filter(other, other.container == p.container && other.port == p.port).size() == 1)")
        .message("a container port may be declared only once")
)]
#[x_kube(
    validation = Rule::new("!has(self.exposedPorts) || self.exposedPorts.all(p, p.name.matches('.*[a-z].*') && !p.name.contains('--'))")
        .message("exposed port names must contain a letter and cannot contain consecutive hyphens")
)]
pub struct SandboxTemplateSpec {
    /// Container selected by default for execution operations.
    #[schemars(length(min = 1, max = 63), pattern("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"))]
    pub default_container: String,
    /// Complete bounded set of containers. Environment, mounts, security
    /// context, service accounts, and arbitrary Pod fields are not exposed.
    #[schemars(length(min = 1, max = 16))]
    pub containers: Vec<SandboxContainerSpec>,
    /// Ports that later access brokers may expose. Any undeclared port remains
    /// unauthorized.
    #[serde(default)]
    #[schemars(length(max = 64))]
    pub exposed_ports: Vec<SandboxPortSpec>,
    /// Absolute path to `kobe-runner` inside `defaultContainer`, when the
    /// administrator's image ships one.
    ///
    /// Absent means this pool does not offer detached execution, and the API
    /// says so rather than approximating it. A detached execution that actually
    /// dies with its connection is worse than none, because the caller has
    /// already built on the guarantee it appeared to offer.
    ///
    /// A constrained path rather than free text: it becomes `argv[0]` of an
    /// exec, so anything that could carry an argument, a shell metacharacter or
    /// a nul is refused by the schema before it can reach one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 255), pattern(r"^/[A-Za-z0-9._/-]*$"))]
    pub runner_path: Option<String>,
}

/// One administrator-controlled container in a Sandbox template.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxContainerSpec {
    #[schemars(length(min = 1, max = 63), pattern("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"))]
    pub name: String,
    #[schemars(length(min = 1, max = 2048))]
    pub image: String,
    /// Executable and arguments, passed directly without an implicit shell.
    #[serde(default)]
    #[schemars(with = "Vec<NonEmptySandboxArgSchema>", length(max = 64))]
    pub command: Vec<String>,
    #[serde(default)]
    #[schemars(with = "Vec<BoundedSandboxArgSchema>", length(max = 256))]
    pub args: Vec<String>,
    pub resources: SandboxContainerResources,
}

/// Explicit requests and limits. CPU and memory are the only resource
/// dimensions admitted by the first Sandbox API, keeping quota comparison
/// deterministic and avoiding arbitrary extended-resource keys.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxContainerResources {
    pub requests: SandboxResourceQuantity,
    pub limits: SandboxResourceQuantity,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxResourceQuantity {
    /// Kubernetes CPU quantity such as `500m` or `2`.
    #[schemars(length(min = 1))]
    pub cpu: String,
    /// Kubernetes memory quantity such as `512Mi` or `2Gi`.
    #[schemars(length(min = 1))]
    pub memory: String,
    /// Kubernetes ephemeral-storage quantity such as `1Gi`.
    #[schemars(length(min = 1))]
    pub ephemeral_storage: String,
}

/// Aggregate per-Sandbox resource ceiling carried by an access grant.
///
/// The values use Kubernetes quantities so administrators can express the
/// ceiling in the same units as pool container limits. Admission compares
/// parsed values through [`crate::sandbox::resource_ceiling_allows`].
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxResourceCeiling {
    #[schemars(length(min = 1))]
    pub max_cpu: String,
    #[schemars(length(min = 1))]
    pub max_memory: String,
}

/// One TCP port declared safe for later lease-scoped forwarding.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxPortSpec {
    #[schemars(length(min = 1, max = 15), pattern("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"))]
    pub name: String,
    #[schemars(length(min = 1, max = 63), pattern("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"))]
    pub container: String,
    #[schemars(range(min = 1))]
    pub port: u16,
}

/// Isolation is a tagged enum so a hardened claim cannot omit its exact
/// RuntimeClass and trusted-runc cannot smuggle one through another field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "tier", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SandboxIsolation {
    TrustedRunc {},
    Gvisor {
        #[serde(rename = "runtimeClassName")]
        runtime_class_name: String,
    },
    Kata {
        #[serde(rename = "runtimeClassName")]
        runtime_class_name: String,
    },
}

impl JsonSchema for SandboxIsolation {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SandboxIsolation".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        serde_json::from_value(serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["tier"],
            "properties": {
                "tier": { "type": "string", "enum": ["trusted-runc", "gvisor", "kata"] },
                "runtimeClassName": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 253,
                    "pattern": "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$"
                }
            },
            "x-kubernetes-validations": [{
                "rule": "(self.tier == 'trusted-runc' && !has(self.runtimeClassName)) || (self.tier in ['gvisor', 'kata'] && has(self.runtimeClassName))",
                "message": "trusted-runc must not set runtimeClassName; hardened tiers must set it"
            }]
        }))
        .expect("static SandboxIsolation schema is valid")
    }
}

impl SandboxIsolation {
    // `crdgen` imports this module for schemas without rendering Pods.
    #[allow(dead_code)]
    pub fn runtime_class_name(&self) -> Option<&str> {
        match self {
            Self::TrustedRunc {} => None,
            Self::Gvisor { runtime_class_name } | Self::Kata { runtime_class_name } => {
                Some(runtime_class_name)
            }
        }
    }
}

/// Variable part of readiness validation. Runtime, admission, network, and
/// upstream-controller checks remain mandatory controller invariants.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxReadinessRequirements {
    pub canary: SandboxExecutionCanary,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxExecutionCanary {
    /// Direct argv vector; no implicit shell expansion. Certification may
    /// execute this more than once after a controller crash or lost status
    /// response, so the command must be idempotent and safe to retry.
    #[schemars(with = "Vec<NonEmptySandboxArgSchema>", length(min = 1, max = 64))]
    pub argv: Vec<String>,
    #[schemars(length(min = 1))]
    pub timeout: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
struct NonEmptySandboxArgSchema(#[schemars(length(min = 1, max = 4096))] String);

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
struct BoundedSandboxArgSchema(#[schemars(length(max = 4096))] String);

/// Caller-safe intent for one disposable Sandbox.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, KubeSchema, PartialEq, Eq)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "SandboxLease",
    plural = "sandboxleases",
    shortname = "sl",
    status = "SandboxLeaseStatus",
    namespaced,
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.releaseCause) || (has(self.status) && self.status != null && has(self.status.releaseCause) && self.status.releaseCause == oldSelf.status.releaseCause)")
        .message("status.releaseCause is immutable once recorded"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.conditions) || !oldSelf.status.conditions.exists(c, c.type == 'FootprintAbsent' && c.status == 'True') || (has(self.status) && self.status != null && has(self.status.conditions) && self.status.conditions.exists(c, c.type == 'FootprintAbsent' && c.status == 'True'))")
        .message("status FootprintAbsent proof is immutable once recorded"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.childTeardownReceiptAcknowledgement) || (has(self.status) && self.status != null && has(self.status.childTeardownReceiptAcknowledgement) && self.status.childTeardownReceiptAcknowledgement == oldSelf.status.childTeardownReceiptAcknowledgement)")
        .message("status.childTeardownReceiptAcknowledgement is immutable once recorded"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.childTeardownEvidence) || (has(self.status) && self.status != null && has(self.status.childTeardownEvidence) && self.status.childTeardownEvidence == oldSelf.status.childTeardownEvidence)")
        .message("status.childTeardownEvidence is immutable once recorded"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.childUnboundReleaseProof) || (has(self.status) && self.status != null && has(self.status.childUnboundReleaseProof) && self.status.childUnboundReleaseProof == oldSelf.status.childUnboundReleaseProof)")
        .message("status.childUnboundReleaseProof is immutable once recorded"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.conditions) || self.status.conditions.all(c, c.type != 'FootprintAbsent' || (c.status == 'True' && has(self.status.releaseCause) && self.status.phase in ['Releasing', 'Released', 'Expired']))")
        .message("FootprintAbsent must be True and requires a releasing or clean terminal status with releaseCause"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.target) || !has(oldSelf.status.target.childClusterKubeconfigSecret) || (has(self.status) && self.status != null && has(self.status.target) && has(self.status.target.childClusterKubeconfigSecret) && self.status.target.childClusterKubeconfigSecret == oldSelf.status.target.childClusterKubeconfigSecret)")
        .message("status.target.childClusterKubeconfigSecret is immutable once recorded"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.target) || !has(oldSelf.status.target.childClusterKubeconfigSha256) || (has(self.status) && self.status != null && has(self.status.target) && has(self.status.target.childClusterKubeconfigSha256) && self.status.target.childClusterKubeconfigSha256 == oldSelf.status.target.childClusterKubeconfigSha256)")
        .message("status.target.childClusterKubeconfigSha256 is immutable once recorded"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.target) || (has(self.status.target.childClusterKubeconfigSecret) == has(self.status.target.childClusterKubeconfigSha256))")
        .message("child kubeconfig Secret identity and payload digest must be checkpointed together"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.target) || !has(self.status.target.childClusterKubeconfigSecret) || (has(self.status.placement) && self.status.placement.type == 'childCluster' && has(self.status.target.childClusterInstance) && self.status.target.childClusterKubeconfigSecret.apiVersion == 'v1' && self.status.target.childClusterKubeconfigSecret.kind == 'Secret' && has(self.status.target.childClusterKubeconfigSecret.__namespace__) && has(self.status.target.childClusterInstance.__namespace__) && self.status.target.childClusterKubeconfigSecret.__namespace__ == self.status.target.childClusterInstance.__namespace__ && !has(self.status.target.childClusterKubeconfigSecret.generation) && self.status.target.childClusterKubeconfigSecret.name == self.status.target.childClusterInstance.name + '-kubeconfig' && self.status.target.childClusterKubeconfigSha256.matches('^[0-9a-f]{64}$'))")
        .message("childClusterKubeconfigSecret must be the exact deterministic Secret for the recorded child instance"),
    validation = Rule::new("!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.childTeardownMode) || (has(self.status) && self.status != null && has(self.status.childTeardownMode) && self.status.childTeardownMode == oldSelf.status.childTeardownMode)")
        .message("status.childTeardownMode is immutable once recorded"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.childTeardownMode) || (has(self.status.placement) && self.status.placement.type == 'childCluster' && has(self.status.target) && has(self.status.target.childClusterKubeconfigSecret))")
        .message("childTeardownMode requires exact child placement and kubeconfig Secret provenance"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.childTeardownReceiptAcknowledgement) || (has(self.status.placement) && self.status.placement.type == 'childCluster')")
        .message("a child teardown receipt acknowledgement requires child placement"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.childTeardownReceiptAcknowledgement) || (has(self.status.conditions) && self.status.conditions.exists(c, c.type == 'FootprintAbsent' && c.status == 'True'))")
        .message("a child teardown receipt acknowledgement requires FootprintAbsent=True in the same checkpoint"),
    validation = Rule::new("!has(oldSelf.spec.placementAuthority) ? !has(self.spec.placementAuthority) : (has(self.spec.placementAuthority) && self.spec.placementAuthority == oldSelf.spec.placementAuthority)")
        .message("spec.placementAuthority is immutable"),
    validation = Rule::new("!has(self.spec.placementAuthority) || (self.spec.placementAuthority.apiVersion == 'kobe.kunobi.ninja/v1alpha1' && self.spec.placementAuthority.kind == 'ClusterPool')")
        .message("spec.placementAuthority must identify a ClusterPool"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.placement) || ((self.status.placement.type == 'management' && !has(self.spec.placementAuthority)) || (self.status.placement.type == 'childCluster' && (!has(self.spec.placementAuthority) || (self.status.placement.clusterPool.apiVersion == self.spec.placementAuthority.apiVersion && self.status.placement.clusterPool.kind == self.spec.placementAuthority.kind && self.status.placement.clusterPool.__namespace__ == self.spec.placementAuthority.__namespace__ && self.status.placement.clusterPool.name == self.spec.placementAuthority.name && self.status.placement.clusterPool.uid == self.spec.placementAuthority.uid && has(self.status.placement.clusterPool.generation) && self.status.placement.clusterPool.generation == self.spec.placementAuthority.generation))))")
        .message("resolved placement must match the immutable admission placementAuthority"),
    validation = Rule::new("!(has(self.status) && self.status != null && has(self.status.placement) && self.status.placement.type == 'childCluster' && !has(self.spec.placementAuthority)) || (has(oldSelf.status) && oldSelf.status != null && has(oldSelf.status.placement) && oldSelf.status.placement.type == 'childCluster' && !has(oldSelf.spec.placementAuthority) && self.status.placement == oldSelf.status.placement)")
        .message("child placement without placementAuthority may only preserve an exact legacy placement"),
    validation = Rule::new("!(has(oldSelf.status) && oldSelf.status != null && has(oldSelf.status.placement) && oldSelf.status.placement.type == 'childCluster' && !has(oldSelf.spec.placementAuthority)) || (has(self.status) && self.status != null && has(self.status.placement) && self.status.placement.type == 'childCluster' && !has(self.spec.placementAuthority) && self.status.placement == oldSelf.status.placement)")
        .message("legacy child placement without placementAuthority may not be removed or changed"),
    validation = Rule::new("!has(self.status) || self.status == null || (has(self.status.childTeardownReceiptAcknowledgement) == has(self.status.childTeardownEvidence))")
        .message("child receipt token and immutable evidence must be checkpointed together"),
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.childUnboundReleaseProof) || (!has(self.status.childTeardownReceiptAcknowledgement) && !has(self.status.childTeardownEvidence) && has(self.status.placement) && self.status.placement.type == 'childCluster')")
        .message("NeverBound and receipt checkpoints are mutually exclusive and require child placement"),
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Expires","type":"date","jsonPath":".status.expiresAt"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxLeaseSpec {
    /// Exact SandboxPool admitted by Kobe. UID and generation fence pool
    /// recreation or mutation between HTTP admission and placement.
    pub pool_ref: SandboxPoolReference,
    /// Server-owned exact child `ClusterPool` identity copied from the admitted
    /// [`SandboxPoolStatus`]. It is absent for management placement and may not
    /// be added, removed, or changed after the `SandboxLease` CREATE. During a
    /// rolling controller upgrade, replicas built before this field fail to
    /// deserialize such leases and therefore fail closed; deploy the new reader
    /// before any child admission is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_authority: Option<SandboxPlacementAuthority>,
    #[schemars(length(min = 1))]
    pub ttl: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1))]
    pub alias: Option<String>,
    /// Set by Kobe from the authenticated principal, never trusted from an HTTP
    /// request body. Ownership uses the complete tuple, not the display
    /// identity alone.
    pub requester: SandboxPrincipal,
}

/// Same-namespace, immutable reference to the exact SandboxPool admitted by
/// Kobe. GVK and namespace are implicit in the typed field.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxPoolReference {
    #[schemars(length(min = 1, max = 63), pattern("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"))]
    pub name: String,
    #[schemars(length(min = 1, max = 128))]
    pub uid: String,
    #[schemars(range(min = 1))]
    pub generation: i64,
}

/// Exact child `ClusterPool` identity authorized by pool reconciliation.
///
/// Every identity component is required because a same-named replacement is
/// different capacity. Admission copies this value into a lease before any
/// placement controller is allowed to create an internal `ClusterLease`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxPlacementAuthority {
    #[schemars(length(min = 1, max = 253))]
    pub api_version: String,
    #[schemars(length(min = 1, max = 63))]
    pub kind: String,
    #[schemars(length(min = 1, max = 63), pattern("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"))]
    pub namespace: String,
    #[schemars(length(min = 1, max = 63), pattern("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"))]
    pub name: String,
    #[schemars(length(min = 1, max = 128))]
    pub uid: String,
    #[schemars(range(min = 1))]
    pub generation: i64,
}

/// Canonical authenticated owner of a SandboxLease.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxPrincipal {
    /// Stable configured authentication provider ID.
    #[schemars(length(min = 1))]
    pub provider: String,
    #[serde(rename = "type")]
    #[schemars(length(min = 1))]
    pub requester_type: String,
    #[schemars(length(min = 1))]
    pub issuer: String,
    #[schemars(length(min = 1))]
    pub identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxPoolStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 0))]
    pub observed_generation: Option<i64>,
    /// Clean, idle upstream Sandboxes reported by the exact reconciled
    /// WarmPool's `readyReplicas`; allocated and quarantined capacity is not
    /// counted as ready.
    #[serde(default)]
    pub ready: u32,
    /// Admitted leases whose immutable pool UID matches this pool and whose
    /// current phase consumes capacity.
    #[serde(default)]
    pub allocated: u32,
    /// Subset of `allocated` leases in the `Quarantined` phase. Quarantined
    /// capacity remains allocated until its complete footprint is proven absent.
    #[serde(default)]
    pub quarantined: u32,
    /// The placement this Pool generation is being reconciled under, recorded
    /// by the placement controller from `spec.placement`.
    ///
    /// Status-only on purpose: the placement CEL invariants compare authority
    /// against this recorded value, never against `spec.placement`. Kubernetes
    /// carries status over unchanged across a spec-only update, so a rule
    /// reading spec would compare the new intent against the previous
    /// generation's recorded state and reject every placement edit forever —
    /// freezing a child pool's target even though nothing inconsistent had
    /// been written. With the value mirrored here, an edit is admitted and the
    /// controller's next reconcile brings status back in line with spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<SandboxPlacement>,
    /// Exact child `ClusterPool` proven composition-eligible for this Pool
    /// generation. Management placement and ineligible child pools omit it.
    /// This is discovery authority only: child `Ready` remains `False` until an
    /// in-child certification and teardown receipt protocol exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_authority: Option<SandboxPlacementAuthority>,
    /// Restart-safe certification attempt for this exact Pool generation.
    ///
    /// The controller checkpoints object identities before crossing each
    /// external side effect. A non-terminal attempt is deliberately retained:
    /// abandoning its exact Claim or teardown fence would make a controller
    /// restart capable of leaking capacity or admitting against stale proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certification: Option<SandboxPoolCertificationStatus>,
    /// Current-generation pool certification. `Ready=True` authorizes new
    /// leases; missing, stale, `False`, or `Unknown` conditions fail closed.
    /// Replica counters alone never authorize admission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(
        length(max = 16),
        extend("x-kubernetes-list-type" = "map"),
        extend("x-kubernetes-list-map-keys" = ["type"])
    )]
    pub conditions: Vec<SandboxCondition>,
}

/// Durable phase of one management-pool certification attempt.
///
/// `Certified` is the only phase that may accompany Pool `Ready=True`.
/// `CleanupBlocked` is fail-closed and retains every exact reference needed to
/// resume or investigate cleanup. Child placement does not use this state
/// until an equivalent in-child receipt protocol exists.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SandboxPoolCertificationPhase {
    #[default]
    Initialized,
    ClaimCreated,
    WorkloadCaptured,
    CanaryPassed,
    FenceInstalled,
    DrainAcknowledged,
    ClaimDeleting,
    AbsenceProven,
    Replenished,
    FenceFinalizerRemoved,
    FenceDeleting,
    Certified,
    CleanupBlocked,
}

/// Exact, non-secret evidence retained across pool certification reconciles.
#[derive(Debug, Clone, Serialize, Deserialize, KubeSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[x_kube(
    validation = Rule::new("self.phase in ['initialized', 'claimCreated', 'cleanupBlocked'] || (has(self.sandboxClaim) && has(self.sandbox) && has(self.pod))")
        .message("workload and later certification phases require exact Claim, Sandbox and Pod references")
)]
#[x_kube(
    validation = Rule::new("!(self.phase in ['fenceInstalled', 'drainAcknowledged', 'claimDeleting', 'absenceProven', 'replenished', 'fenceFinalizerRemoved', 'fenceDeleting', 'certified']) || has(self.teardownFence)")
        .message("post-fence certification phases require the exact teardown fence reference")
)]
#[x_kube(
    validation = Rule::new("!(self.phase in ['canaryPassed', 'fenceInstalled', 'drainAcknowledged', 'claimDeleting', 'absenceProven', 'replenished', 'fenceFinalizerRemoved', 'fenceDeleting', 'certified']) || has(self.canaryPassedAt)")
        .message("post-canary certification phases require the durable canary timestamp")
)]
#[x_kube(
    validation = Rule::new("self.phase != 'certified' || has(self.certifiedAt)")
        .message("Certified requires a durable certification timestamp")
)]
#[x_kube(
    validation = Rule::new("!(self.phase in ['drainAcknowledged', 'claimDeleting', 'absenceProven', 'replenished', 'fenceFinalizerRemoved', 'fenceDeleting', 'certified']) || has(self.drainGeneration)")
        .message("drain acknowledgement and later phases require the exact WarmPool drain generation")
)]
#[x_kube(
    validation = Rule::new("!(self.phase in ['replenished', 'fenceFinalizerRemoved', 'fenceDeleting', 'certified']) || has(self.replenishGeneration)")
        .message("replenishment and terminal phases require the exact restored WarmPool generation")
)]
pub struct SandboxPoolCertificationStatus {
    /// SHA-256 over the Pool UID/generation, exact Template/WarmPool identity,
    /// pinned runtime version, and canonical canary requirements.
    #[schemars(length(min = 64, max = 64), pattern("^[0-9a-f]{64}$"))]
    pub fingerprint: String,
    #[schemars(range(min = 1))]
    pub observed_generation: i64,
    pub phase: SandboxPoolCertificationPhase,
    pub sandbox_template: SandboxObjectReference,
    pub sandbox_warm_pool: SandboxObjectReference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_claim: Option<SandboxObjectReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxObjectReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<SandboxObjectReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<SandboxObjectReference>,
    /// Exact PVC/PV identities seen before teardown. Empty means the closed
    /// Pool template proved that no durable volumes can be created.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 16))]
    pub persistent_volume_claims: Vec<SandboxObjectReference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 16))]
    pub persistent_volumes: Vec<SandboxObjectReference>,
    /// Immutable parameter object for the teardown ValidatingAdmissionPolicy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teardown_fence: Option<SandboxObjectReference>,
    /// WarmPool-owned Sandbox UIDs present before the sacrificial Claim. Clean
    /// replenishment must exclude the claimed Sandbox and preserve none of a
    /// replaced generation's identities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(with = "Vec<BoundedSandboxUidSchema>", length(max = 256))]
    pub baseline_idle_sandbox_uids: Vec<String>,
    /// WarmPool generation created by the post-fence scale-to-zero write. The
    /// WarmPool `observedGeneration` ACK is meaningful only for this exact value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub drain_generation: Option<i64>,
    /// WarmPool generation created when restoring the configured capacity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub replenish_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64), extend("format" = "date-time"))]
    pub canary_passed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64), extend("format" = "date-time"))]
    pub certified_at: Option<String>,
    /// Human-readable fail-closed reason. In `CleanupBlocked`, this is the
    /// exact causal proof that the controller could not obtain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 4096))]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
struct BoundedSandboxUidSchema(#[schemars(length(min = 1, max = 128))] String);

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxLeaseStatus {
    #[serde(default)]
    pub phase: SandboxLeasePhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 0))]
    pub observed_generation: Option<i64>,
    /// Absolute bound for setup. This is not the runtime expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "date-time"))]
    pub provisioning_deadline: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "date-time"))]
    pub ready_at: Option<String>,
    /// Set only when the upstream Sandbox becomes Ready.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: Option<String>,
    /// Runtime TTL extensions already granted to this lease.
    ///
    /// Monotonic and never reset: the budget is spent per lease, not per
    /// reconcile or per API replica. Absent on leases admitted before
    /// extension existed, which reads as zero.
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub extensions_count: u32,
    /// Total granted extension, in seconds, added to the derived expiry.
    ///
    /// Expiry has exactly ONE derivation, `readyAt + spec.ttl + this`, and the
    /// lifecycle controller recomputes it on every Ready pass. Extension
    /// therefore moves this INPUT rather than writing `expiresAt` behind the
    /// controller's back: a second writer of a derived value made the Ready
    /// transition non-idempotent, so the controller rejected every later
    /// reconcile and stopped re-asserting the upstream shutdown backstop,
    /// leaving the workload to be destroyed at its original deadline while the
    /// lease still advertised the extended one.
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub granted_extension_seconds: i64,
    /// Immutable reason the lease first entered `Releasing`. Persisted in the
    /// same status write as that phase so retries, later release requests, and
    /// controller restarts cannot change the terminal accounting outcome.
    /// `Unverifiable` means Kobe could not verify the lease's own admission
    /// gate: the lease is treated as unsafe to serve and torn down through the
    /// evidence-gated path rather than holding finalizer and quota forever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_cause: Option<SandboxReleaseCause>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<ResolvedSandboxPlacement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<SandboxTargetProvenance>,
    /// Protocol checkpoint written before any management `SandboxClaim` POST.
    /// `FinalizerV1` means every subsequently created Claim carries Kobe's
    /// cleanup finalizer from birth, so an unrecorded Claim cannot disappear
    /// before teardown either checkpoints its UID or proves the name absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_cleanup_fence: Option<SandboxClaimCleanupFence>,
    /// Exact management-cluster `SandboxClaim` retained as an inert release
    /// tombstone. This is separate from [`SandboxTargetProvenance::sandbox_claim`]:
    /// the original workload Claim may already be gone, while its same-named
    /// replacement has a different UID that must be checkpointed before it can
    /// fence delayed creates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_claim_tombstone: Option<SandboxObjectReference>,
    /// Exact management-cluster coordination `Lease` that closes allocation
    /// before teardown begins. Create paths must observe its absence inside a
    /// bounded final authorization window; release drains that window before
    /// it may checkpoint footprint absence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocation_fence: Option<SandboxObjectReference>,
    /// Restart-safe decision made before requesting destruction of a bound
    /// child cluster. `ReachableCleanupV1` means exact runner records and
    /// scoped credentials were proven clean through the checkpointed child
    /// kubeconfig Secret; `VerifiedDestroyFallbackV1` means either an
    /// authenticated child probe failed at the transport layer or a reachable
    /// runner could not prove its process group absent. In both cases the exact
    /// backend receipt must linearize target absence before records can be
    /// retired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_teardown_mode: Option<SandboxChildTeardownMode>,

    /// Durable consumer acknowledgement of the exact internal ClusterLease
    /// teardown receipt. This is the receipt's SHA-256 acknowledgement token,
    /// written atomically with `FootprintAbsent=True` before the producer is
    /// ACKed or allowed to discard its full receipt bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(equal = 71), pattern("^sha256:[0-9a-f]{64}$"))]
    pub child_teardown_receipt_acknowledgement: Option<String>,
    /// Exact immutable authority object copied in the same status checkpoint
    /// as [`Self::child_teardown_receipt_acknowledgement`]. A hash alone is not
    /// enough to release the producer's retained handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_teardown_evidence: Option<TeardownEvidenceReference>,
    /// Attempt-bound proof used when the internal ClusterLease reached a
    /// terminal phase before any reciprocal ClusterInstance binding existed.
    /// It is copied before the receipt authority acknowledges the child.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_unbound_release_proof: Option<ChildUnboundReleaseProof>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(
        length(max = 16),
        extend("x-kubernetes-list-type" = "map"),
        extend("x-kubernetes-list-map-keys" = ["type"])
    )]
    pub conditions: Vec<SandboxCondition>,
}

/// Durable management-Claim deletion fence understood by this controller.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum SandboxClaimCleanupFence {
    /// Release won while the lease still had the exact admission-only shape.
    /// The UID/resourceVersion-fenced `Releasing` checkpoint therefore proves
    /// no placement pass had authorised a Claim POST. Teardown may use an exact
    /// inert tombstone plus empty descendant scans without inventing target
    /// provenance for workload that never started.
    AdmissionOnlyV1,
    /// Release won after the controller had checkpointed provisioning but
    /// before any create was authorised: no target was ever named, so no
    /// Claim and no child `ClusterLease` POST can have been issued.
    ///
    /// Weaker than [`Self::AdmissionOnlyV1`], which requires the exact
    /// admission shape and is only reachable in the moment between admission
    /// and the controller's first status write. That interval is far too
    /// narrow to be the only pre-create proof: the first write sets
    /// `phase = Provisioning` and `observedGeneration`, and a caller who
    /// cancels immediately after it lands had, until this variant existed,
    /// nothing to prove absence with and was quarantined for it.
    ///
    /// The obligation is correspondingly stronger. Verification waits for the
    /// allocation fence to drain, then requires BOTH the inert Claim tombstone
    /// with empty descendant scans AND a verified 404 on the deterministic
    /// child handle name. The drain is what makes those 404s mean "nothing was
    /// created and nothing can be" rather than "I did not find it".
    PreCreateV1,
    /// A management Claim cleanup finalizer was durable before the first POST,
    /// or an exact non-deleting legacy Claim was atomically migrated to that
    /// ownerless/finalized shape before this checkpoint was written.
    FinalizerV1,
}

/// Durable ordering proof selected before a bound child `ClusterLease` is
/// released. The value is write-once: a restart must never reinterpret the
/// same in-flight destroy as a successful reachable cleanup.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum SandboxChildTeardownMode {
    /// The exact child API was reachable and every durable execution plus
    /// scoped credential was proven clean before cluster destruction began.
    ReachableCleanupV1,
    /// Reachable cleanup could not prove all target processes absent, either
    /// because the exact child API was unreachable at the transport layer or a
    /// runner supervisor was lost. Execution records may be retired only after
    /// the exact verified-destroy receipt proves their target cluster absent.
    VerifiedDestroyFallbackV1,
}

/// Exact attempt checkpoint copied by the outer Sandbox before the receipt
/// authority may acknowledge and retire a child handle that never bound.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChildUnboundReleaseProof {
    #[schemars(length(min = 1))]
    pub attempt_id: String,
    #[schemars(extend("format" = "date-time"))]
    pub verified_at: String,
}

/// Stable public phases. `Released` and `Expired` are clean terminal states;
/// uncertain teardown remains `Quarantined` and continues consuming capacity.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
pub enum SandboxLeasePhase {
    #[default]
    Pending,
    Provisioning,
    Ready,
    Releasing,
    Released,
    Expired,
    Quarantined,
}

/// Durable cause of Sandbox teardown. Runtime and provisioning expiry both end
/// in `Expired`, but remain distinct for operator diagnostics and billing.
/// `ModeDisabled` records an operator-wide drain rather than misreporting it as
/// a caller request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum SandboxReleaseCause {
    Requested,
    RuntimeTtl,
    ProvisioningDeadline,
    ModeDisabled,
    // Kobe could not verify the lease's own admission gate, so it cannot
    // prove which principal holds the workload or drain its operations. Such
    // a lease is treated as unsafe to serve and torn down through the
    // ordinary evidence-gated path rather than holding finalizer and quota
    // forever. Distinct from Requested so billing and support can see the
    // capacity was taken by the system, not given back by the caller.
    Unverifiable,
}

impl std::fmt::Display for SandboxLeasePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl SandboxLeasePhase {
    /// Whether the lease may still own or reserve capacity.
    // `crdgen` imports this module for schemas without lifecycle evaluation.
    #[allow(dead_code)]
    pub fn consumes_capacity(self) -> bool {
        !matches!(self, Self::Released | Self::Expired)
    }
}

/// Resolved placement recorded once by a placement controller. A child
/// placement binds the referenced pool by UID, preventing name-reuse attacks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum ResolvedSandboxPlacement {
    Management {},
    ChildCluster {
        #[serde(rename = "clusterPool")]
        cluster_pool: SandboxObjectReference,
    },
}

impl JsonSchema for ResolvedSandboxPlacement {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ResolvedSandboxPlacement".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let reference = serde_json::to_value(generator.subschema_for::<SandboxObjectReference>())
            .expect("SandboxObjectReference schema serializes");
        serde_json::from_value(serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["type"],
            "properties": {
                "type": { "type": "string", "enum": ["management", "childCluster"] },
                "clusterPool": reference
            },
            "x-kubernetes-validations": [{
                "rule": "(self.type == 'management' && !has(self.clusterPool)) || (self.type == 'childCluster' && has(self.clusterPool))",
                "message": "resolved childCluster placement requires the exact ClusterPool reference"
            }]
        }))
        .expect("static ResolvedSandboxPlacement schema is valid")
    }
}

/// Non-secret identity of one exact Kubernetes object. String fields use the
/// Kubernetes name/identity ceilings so root-level CEL comparisons have a
/// finite admission cost instead of being rejected by the API server.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxObjectReference {
    #[schemars(length(min = 1, max = 253))]
    pub api_version: String,
    #[schemars(length(min = 1, max = 63))]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 63), pattern("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"))]
    pub namespace: Option<String>,
    #[schemars(length(min = 1, max = 253))]
    pub name: String,
    #[schemars(length(min = 1, max = 128))]
    pub uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 0))]
    pub generation: Option<i64>,
}

/// Restart-safe, non-secret target provenance. Fields are filled monotonically:
/// once a reference is present its name and UID may never be cleared or changed.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxTargetProvenance {
    #[schemars(length(min = 1, max = 63), pattern("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$"))]
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_cluster_lease: Option<SandboxObjectReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_cluster_instance: Option<SandboxObjectReference>,
    /// Exact management-cluster Secret whose bytes authenticate the child
    /// client. The Secret is checkpointed before its contents are first used,
    /// then re-read by UID and payload digest on every later pass. Only
    /// non-secret identity is persisted; kubeconfig bytes never enter status,
    /// logs, or API responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_cluster_kubeconfig_secret: Option<SandboxObjectReference>,
    /// SHA-256 of the exact, sole `data.kubeconfig` payload read from
    /// [`Self::child_cluster_kubeconfig_secret`]. It is checkpointed in the
    /// same status write as the Secret UID and never changes. ResourceVersion
    /// may move on an idempotent publisher apply; payload identity may not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 64, max = 64), pattern("^[0-9a-f]{64}$"))]
    pub child_cluster_kubeconfig_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_template: Option<SandboxObjectReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_warm_pool: Option<SandboxObjectReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_claim: Option<SandboxObjectReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxObjectReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<SandboxObjectReference>,
    /// Exact headless Service created by Agent Sandbox when the pool exposes
    /// ports. Teardown uses this UID rather than assuming Claim disappearance
    /// proves every nested dependent is gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<SandboxObjectReference>,
}

/// Kubernetes-style condition with the generation from which it was derived.
/// Status lists are capped because CEL lifecycle proofs scan them on every
/// status write.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxCondition {
    #[serde(rename = "type")]
    #[schemars(length(min = 1, max = 63))]
    pub condition_type: String,
    pub status: SandboxConditionStatus,
    #[schemars(length(max = 128))]
    pub reason: String,
    #[schemars(length(max = 32768))]
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 0))]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "date-time"))]
    pub last_transition_time: Option<String>,
}

/// Kubernetes Condition status values.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
pub enum SandboxConditionStatus {
    True,
    False,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[allow(dead_code)] // Used by runtime admission/mapping, not the `crdgen` binary.
pub enum SandboxPoolValidationError {
    #[error("{0} must not be empty")]
    EmptyDuration(&'static str),
    #[error("warmCapacity exceeds upstream int32 replicas")]
    WarmCapacityTooLarge,
    #[error("childCluster placement requires a non-empty clusterPoolRef")]
    EmptyClusterPoolRef,
    #[error("template must contain at least one container")]
    NoContainers,
    #[error("container name must not be empty")]
    EmptyContainerName,
    #[error("duplicate container name {0}")]
    DuplicateContainer(String),
    #[error("container {0} has an empty image")]
    EmptyContainerImage(String),
    #[error("container {container} has an empty {field} resource quantity")]
    EmptyResource {
        container: String,
        field: &'static str,
    },
    #[error("default container {0} is not declared")]
    UnknownDefaultContainer(String),
    #[error("port name must not be empty")]
    EmptyPortName,
    #[error("duplicate port name {0}")]
    DuplicatePortName(String),
    #[error("port {0} must be in the range 1-65535")]
    ZeroPort(String),
    #[error("port {port} references undeclared container {container}")]
    UnknownPortContainer { port: String, container: String },
    #[error("container {container} exposes port {port} more than once")]
    DuplicateContainerPort { container: String, port: u16 },
    #[error("hardened isolation requires a non-empty runtimeClassName")]
    EmptyRuntimeClass,
    #[error("readiness canary argv must contain non-empty arguments")]
    EmptyCanaryArgv,
    #[error("readiness canary timeout must not be empty")]
    EmptyCanaryTimeout,
}

#[cfg(test)]
mod tests {
    use kube::CustomResourceExt;

    use super::*;

    fn valid_pool_spec() -> SandboxPoolSpec {
        SandboxPoolSpec {
            warm_capacity: 2,
            default_ttl: "1h".into(),
            max_ttl: "8h".into(),
            provisioning_timeout: "10m".into(),
            placement: SandboxPlacement::Management {},
            template: SandboxTemplateSpec {
                default_container: "agent".into(),
                containers: vec![SandboxContainerSpec {
                    name: "agent".into(),
                    image: "example.invalid/agent@sha256:abc".into(),
                    command: vec!["/agent".into()],
                    args: vec![],
                    resources: SandboxContainerResources {
                        requests: SandboxResourceQuantity {
                            cpu: "500m".into(),
                            memory: "512Mi".into(),
                            ephemeral_storage: "512Mi".into(),
                        },
                        limits: SandboxResourceQuantity {
                            cpu: "1".into(),
                            memory: "1Gi".into(),
                            ephemeral_storage: "1Gi".into(),
                        },
                    },
                }],
                exposed_ports: vec![SandboxPortSpec {
                    name: "http".into(),
                    container: "agent".into(),
                    port: 3000,
                }],
                runner_path: None,
            },
            isolation: SandboxIsolation::TrustedRunc {},
            readiness: SandboxReadinessRequirements {
                canary: SandboxExecutionCanary {
                    argv: vec!["/agent".into(), "health".into()],
                    timeout: "30s".into(),
                },
            },
        }
    }

    #[test]
    fn sandbox_lease_defaults_to_pending() {
        assert_eq!(
            SandboxLeaseStatus::default().phase,
            SandboxLeasePhase::Pending
        );
    }

    #[test]
    fn sandbox_pool_status_wire_contract_is_camel_case_and_zero_defaulted() {
        let status: SandboxPoolStatus = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(status, SandboxPoolStatus::default());
        assert_eq!(status.ready, 0);
        assert_eq!(status.allocated, 0);
        assert_eq!(status.quarantined, 0);

        let encoded = serde_json::to_value(SandboxPoolStatus {
            observed_generation: Some(7),
            ready: 3,
            allocated: 2,
            quarantined: 1,
            placement: None,
            placement_authority: None,
            certification: None,
            conditions: vec![],
        })
        .unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({
                "observedGeneration": 7,
                "ready": 3,
                "allocated": 2,
                "quarantined": 1
            })
        );
        assert!(encoded.get("observed_generation").is_none());
    }

    #[test]
    fn pool_certification_wire_shape_is_crash_restart_safe() {
        let reference = SandboxObjectReference {
            api_version: "extensions.agents.x-k8s.io/v1beta1".into(),
            kind: "SandboxTemplate".into(),
            namespace: Some("kobe-system".into()),
            name: "kobe-agents".into(),
            uid: "template-uid".into(),
            generation: Some(4),
        };
        let status = SandboxPoolCertificationStatus {
            fingerprint: "a".repeat(64),
            observed_generation: 7,
            phase: SandboxPoolCertificationPhase::WorkloadCaptured,
            sandbox_template: reference.clone(),
            sandbox_warm_pool: SandboxObjectReference {
                kind: "SandboxWarmPool".into(),
                ..reference.clone()
            },
            sandbox_claim: Some(SandboxObjectReference {
                kind: "SandboxClaim".into(),
                uid: "claim-uid".into(),
                ..reference.clone()
            }),
            sandbox: Some(SandboxObjectReference {
                api_version: "agents.x-k8s.io/v1beta1".into(),
                kind: "Sandbox".into(),
                uid: "sandbox-uid".into(),
                ..reference.clone()
            }),
            pod: Some(SandboxObjectReference {
                api_version: "v1".into(),
                kind: "Pod".into(),
                uid: "pod-uid".into(),
                generation: None,
                ..reference.clone()
            }),
            service: None,
            persistent_volume_claims: vec![],
            persistent_volumes: vec![],
            teardown_fence: None,
            baseline_idle_sandbox_uids: vec!["idle-uid".into()],
            drain_generation: None,
            replenish_generation: None,
            canary_passed_at: None,
            certified_at: None,
            message: None,
        };
        let encoded = serde_json::to_value(&status).unwrap();
        assert_eq!(encoded["phase"], "workloadCaptured");
        assert_eq!(
            serde_json::from_value::<SandboxPoolCertificationStatus>(encoded).unwrap(),
            status
        );
    }

    #[test]
    fn placement_rejects_both_or_neither_shapes() {
        assert_eq!(
            serde_json::from_value::<SandboxPlacement>(serde_json::json!({
                "type": "management"
            }))
            .unwrap(),
            SandboxPlacement::Management {}
        );
        assert_eq!(
            serde_json::from_value::<SandboxPlacement>(serde_json::json!({
                "type": "childCluster",
                "clusterPoolRef": "ci"
            }))
            .unwrap(),
            SandboxPlacement::ChildCluster {
                cluster_pool_ref: "ci".into()
            }
        );
        assert!(serde_json::from_value::<SandboxPlacement>(serde_json::json!({})).is_err());
        assert!(
            serde_json::from_value::<SandboxPlacement>(serde_json::json!({
                "management": {},
                "childCluster": { "clusterPoolRef": "ci" }
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<SandboxPlacement>(serde_json::json!({
                "type": "management",
                "clusterPoolRef": "smuggled"
            }))
            .is_err()
        );
    }

    #[test]
    fn hardened_isolation_requires_runtime_class_by_shape() {
        assert!(
            serde_json::from_value::<SandboxIsolation>(serde_json::json!({ "tier": "gvisor" }))
                .is_err()
        );
        assert!(
            serde_json::from_value::<SandboxIsolation>(serde_json::json!({
                "tier": "trusted-runc",
                "runtimeClassName": "runsc"
            }))
            .is_err()
        );
    }

    #[test]
    fn pool_validation_rejects_invalid_container_and_port_links() {
        let mut spec = valid_pool_spec();
        spec.placement = SandboxPlacement::ChildCluster {
            cluster_pool_ref: " ".into(),
        };
        assert_eq!(
            spec.validate(),
            Err(SandboxPoolValidationError::EmptyClusterPoolRef)
        );

        let mut spec = valid_pool_spec();
        spec.template.default_container = "missing".into();
        assert_eq!(
            spec.validate(),
            Err(SandboxPoolValidationError::UnknownDefaultContainer(
                "missing".into()
            ))
        );

        let mut spec = valid_pool_spec();
        spec.template.exposed_ports[0].container = "missing".into();
        assert_eq!(
            spec.validate(),
            Err(SandboxPoolValidationError::UnknownPortContainer {
                port: "http".into(),
                container: "missing".into(),
            })
        );
    }

    #[test]
    fn lease_spec_rejects_unsafe_fields() {
        let valid_spec = serde_json::json!({
            "poolRef": {
                "name": "agents",
                "uid": "pool-uid",
                "generation": 1
            },
            "ttl": "1h",
            "requester": {
                "provider": "developer-oidc",
                "type": "oidc:user",
                "issuer": "https://issuer.example",
                "identity": "alice"
            }
        });
        assert!(serde_json::from_value::<SandboxLeaseSpec>(valid_spec.clone()).is_ok());
        for (field, value) in [
            ("namespace", serde_json::json!("kube-system")),
            ("runtimeClassName", serde_json::json!("runc")),
            (
                "env",
                serde_json::json!([{ "name": "TOKEN", "value": "secret" }]),
            ),
        ] {
            let mut unsafe_spec = valid_spec.clone();
            unsafe_spec[field] = value;
            assert!(
                serde_json::from_value::<SandboxLeaseSpec>(unsafe_spec).is_err(),
                "field {field} must be rejected"
            );
        }
    }

    #[test]
    fn lease_phase_capacity_contract_keeps_quarantine_active() {
        for phase in [
            SandboxLeasePhase::Pending,
            SandboxLeasePhase::Provisioning,
            SandboxLeasePhase::Ready,
            SandboxLeasePhase::Releasing,
            SandboxLeasePhase::Quarantined,
        ] {
            assert!(phase.consumes_capacity(), "{phase} must consume capacity");
        }
        assert!(!SandboxLeasePhase::Released.consumes_capacity());
        assert!(!SandboxLeasePhase::Expired.consumes_capacity());
    }

    #[test]
    fn generated_crds_are_concrete_and_status_enabled() {
        let pool = serde_json::to_value(SandboxPool::crd()).unwrap();
        let lease = serde_json::to_value(SandboxLease::crd()).unwrap();
        assert_eq!(pool["metadata"]["name"], "sandboxpools.kobe.kunobi.ninja");
        assert_eq!(lease["metadata"]["name"], "sandboxleases.kobe.kunobi.ninja");
        assert_eq!(pool["spec"]["scope"], "Namespaced");
        assert_eq!(lease["spec"]["scope"], "Namespaced");
        let placement = &pool["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
            ["properties"]["placement"];
        let isolation = &pool["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
            ["properties"]["isolation"];
        let schema_json = serde_json::to_string(&pool).unwrap();
        assert!(
            !schema_json.contains("x-kubernetes-preserve-unknown-fields"),
            "SandboxPool must not contain a free-form schema escape hatch"
        );
        assert_eq!(placement["type"], "object");
        assert_eq!(isolation["type"], "object");
        assert!(placement["x-kubernetes-validations"].is_array());
        assert!(isolation["x-kubernetes-validations"].is_array());
        assert_eq!(
            pool["spec"]["versions"][0]["subresources"]["status"],
            serde_json::json!({})
        );
        assert_eq!(
            lease["spec"]["versions"][0]["subresources"]["status"],
            serde_json::json!({})
        );
    }

    #[test]
    fn sandbox_pool_status_schema_and_print_columns_are_exact() {
        let pool = serde_json::to_value(SandboxPool::crd()).unwrap();
        let version = &pool["spec"]["versions"][0];
        let status = &version["schema"]["openAPIV3Schema"]["properties"]["status"]["properties"];

        for field in ["ready", "allocated", "quarantined"] {
            assert_eq!(status[field]["type"], "integer");
            assert_eq!(status[field]["format"], "uint32");
            assert_eq!(status[field]["default"], 0);
            assert_eq!(status[field]["minimum"], 0.0);
        }
        assert!(status.get("observedGeneration").is_some());
        assert!(status.get("observed_generation").is_none());
        let certification = &status["certification"];
        assert_eq!(certification["type"], "object");
        assert_eq!(
            certification["properties"]["fingerprint"]["pattern"],
            "^[0-9a-f]{64}$"
        );
        assert_eq!(
            certification["properties"]["phase"]["enum"],
            serde_json::json!([
                "initialized",
                "claimCreated",
                "workloadCaptured",
                "canaryPassed",
                "fenceInstalled",
                "drainAcknowledged",
                "claimDeleting",
                "absenceProven",
                "replenished",
                "fenceFinalizerRemoved",
                "fenceDeleting",
                "certified",
                "cleanupBlocked"
            ])
        );
        assert_eq!(
            certification["x-kubernetes-validations"]
                .as_array()
                .map(Vec::len),
            Some(6)
        );
        assert_eq!(
            certification["properties"]["persistentVolumeClaims"]["maxItems"],
            16
        );
        assert_eq!(
            certification["properties"]["persistentVolumes"]["maxItems"],
            16
        );
        assert_eq!(
            certification["properties"]["baselineIdleSandboxUids"]["maxItems"],
            256
        );
        assert_eq!(
            certification["properties"]["baselineIdleSandboxUids"]["items"]["maxLength"],
            128
        );
        let pool_validations =
            pool["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["x-kubernetes-validations"]
                .as_array()
                .expect("SandboxPool root CEL validations");
        assert!(pool_validations.iter().any(|validation| {
            validation["message"]
                == "Ready=True requires a coherent observed-generation durable Certified receipt"
        }));
        let ready_rule = pool_validations
            .iter()
            .find(|validation| {
                validation["message"]
                    == "Ready=True requires a coherent observed-generation durable Certified receipt"
            })
            .expect("Ready receipt CEL")["rule"]
            .as_str()
            .expect("CEL rule string");
        assert!(ready_rule.contains("c.observedGeneration == self.status.observedGeneration"));
        assert!(ready_rule.contains(
            "self.status.certification.observedGeneration == self.status.observedGeneration"
        ));
        assert!(!ready_rule.contains("metadata.generation"));
        assert!(
            !pool_validations.iter().any(|validation| {
                validation["message"]
                    == "a Certified receipt requires the same-write current-generation Ready=True condition"
            }),
            "revoking Ready must remain writable while retaining the terminal receipt"
        );
        let immutable_references = pool_validations
            .iter()
            .find(|validation| {
                validation["message"]
                    == "exact certification references are immutable within one fingerprint"
            })
            .expect("exact-reference immutability CEL")["rule"]
            .as_str()
            .expect("CEL rule string");
        for field in [
            "sandboxClaim",
            "sandbox",
            "pod",
            "service",
            "persistentVolumeClaims",
            "persistentVolumes",
            "baselineIdleSandboxUids",
            "teardownFence",
            "drainGeneration",
            "replenishGeneration",
            "canaryPassedAt",
            "certifiedAt",
        ] {
            assert!(
                immutable_references.contains(field),
                "exact-reference CEL omitted {field}"
            );
        }
        let workload_reference_rule = certification["x-kubernetes-validations"]
            .as_array()
            .expect("certification CEL validations")
            .iter()
            .find(|validation| {
                validation["message"]
                    == "workload and later certification phases require exact Claim, Sandbox and Pod references"
            })
            .expect("workload-reference phase CEL")["rule"]
            .as_str()
            .expect("CEL rule string");
        assert!(
            workload_reference_rule.contains("'cleanupBlocked'"),
            "an early durable CleanupBlocked checkpoint must not require workload refs"
        );
        let active_fingerprint_rule = pool_validations
            .iter()
            .find(|validation| {
                validation["message"]
                    == "an active certification fingerprint cannot be abandoned before exact cleanup"
            })
            .expect("active-fingerprint CEL")["rule"]
            .as_str()
            .expect("CEL rule string");
        assert!(
            active_fingerprint_rule.contains("['initialized', 'cleanupBlocked']"),
            "a ref-less early blocker must be restartable after an administrator edit"
        );

        assert_eq!(
            version["additionalPrinterColumns"],
            serde_json::json!([
                {"jsonPath": ".status.ready", "name": "Ready", "type": "integer"},
                {"jsonPath": ".status.allocated", "name": "Allocated", "type": "integer"},
                {"jsonPath": ".status.quarantined", "name": "Quarantined", "type": "integer"},
                {"jsonPath": ".metadata.creationTimestamp", "name": "Age", "type": "date"}
            ])
        );
    }

    /// The first teardown cause is a durable accounting fact. Its wire values
    /// are public, and Kubernetes must reject both changing and removing it.
    #[test]
    fn release_cause_schema_is_exact_and_write_once() {
        let mut status = SandboxLeaseStatus::default();
        let absent = serde_json::to_value(&status).unwrap();
        assert!(absent.get("releaseCause").is_none());

        status.release_cause = Some(SandboxReleaseCause::RuntimeTtl);
        assert_eq!(
            serde_json::to_value(&status).unwrap()["releaseCause"],
            "RuntimeTtl"
        );

        let lease = serde_json::to_value(SandboxLease::crd()).unwrap();
        let root_schema = &lease["spec"]["versions"][0]["schema"]["openAPIV3Schema"];
        let status_schema = &root_schema["properties"]["status"];
        assert_eq!(
            status_schema["properties"]["releaseCause"]["enum"],
            serde_json::json!([
                "Requested",
                "RuntimeTtl",
                "ProvisioningDeadline",
                "ModeDisabled",
                "Unverifiable",
                null
            ])
        );
        assert!(status_schema.get("x-kubernetes-validations").is_none());
        let validations = root_schema["x-kubernetes-validations"].as_array().unwrap();
        for rule in [
            "!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.releaseCause) || (has(self.status) && self.status != null && has(self.status.releaseCause) && self.status.releaseCause == oldSelf.status.releaseCause)",
            "!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.conditions) || !oldSelf.status.conditions.exists(c, c.type == 'FootprintAbsent' && c.status == 'True') || (has(self.status) && self.status != null && has(self.status.conditions) && self.status.conditions.exists(c, c.type == 'FootprintAbsent' && c.status == 'True'))",
            "!has(self.status) || self.status == null || !has(self.status.conditions) || self.status.conditions.all(c, c.type != 'FootprintAbsent' || (c.status == 'True' && has(self.status.releaseCause) && self.status.phase in ['Releasing', 'Released', 'Expired']))",
            "!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.childTeardownReceiptAcknowledgement) || (has(self.status) && self.status != null && has(self.status.childTeardownReceiptAcknowledgement) && self.status.childTeardownReceiptAcknowledgement == oldSelf.status.childTeardownReceiptAcknowledgement)",
            "!has(self.status) || self.status == null || !has(self.status.childTeardownReceiptAcknowledgement) || (has(self.status.placement) && self.status.placement.type == 'childCluster')",
            "!has(self.status) || self.status == null || !has(self.status.childTeardownReceiptAcknowledgement) || (has(self.status.conditions) && self.status.conditions.exists(c, c.type == 'FootprintAbsent' && c.status == 'True'))",
        ] {
            assert!(
                validations
                    .iter()
                    .any(|validation| validation["rule"] == rule),
                "missing root validation: {rule}"
            );
        }
        let acknowledgement = &status_schema["properties"]["childTeardownReceiptAcknowledgement"];
        assert_eq!(acknowledgement["type"], "string");
        assert_eq!(acknowledgement["pattern"], "^sha256:[0-9a-f]{64}$");
    }

    /// Child authentication and teardown interpretation are restart authority,
    /// so the CRD rejects partial, changed, or non-canonical checkpoints even
    /// if a buggy status writer attempts them.
    #[test]
    fn child_kubeconfig_and_teardown_mode_schema_are_exact_and_write_once() {
        let lease = serde_json::to_value(SandboxLease::crd()).unwrap();
        let root_schema = &lease["spec"]["versions"][0]["schema"]["openAPIV3Schema"];
        let status = &root_schema["properties"]["status"]["properties"];
        assert_eq!(
            status["childTeardownMode"]["enum"],
            serde_json::json!(["ReachableCleanupV1", "VerifiedDestroyFallbackV1"])
        );
        let digest = &status["target"]["properties"]["childClusterKubeconfigSha256"];
        assert_eq!(digest["minLength"], 64);
        assert_eq!(digest["maxLength"], 64);
        assert_eq!(digest["pattern"], "^[0-9a-f]{64}$");

        let validations = root_schema["x-kubernetes-validations"].as_array().unwrap();
        for message in [
            "status.target.childClusterKubeconfigSecret is immutable once recorded",
            "status.target.childClusterKubeconfigSha256 is immutable once recorded",
            "child kubeconfig Secret identity and payload digest must be checkpointed together",
            "childClusterKubeconfigSecret must be the exact deterministic Secret for the recorded child instance",
            "status.childTeardownMode is immutable once recorded",
            "childTeardownMode requires exact child placement and kubeconfig Secret provenance",
        ] {
            assert!(
                validations
                    .iter()
                    .any(|validation| validation["message"] == message),
                "missing root validation: {message}"
            );
        }
        let secret_rule = validations
            .iter()
            .find(|validation| {
                validation["message"]
                    == "childClusterKubeconfigSecret must be the exact deterministic Secret for the recorded child instance"
            })
            .and_then(|validation| validation["rule"].as_str())
            .expect("child kubeconfig Secret CEL");
        assert!(secret_rule.contains(".__namespace__"));
        assert!(!secret_rule.contains(".namespace"));
    }

    /// Every string or list traversed by a root CEL rule has a finite schema
    /// bound. Kubernetes rejects an otherwise-valid CRD when the static CEL
    /// estimator must assume unbounded identities or condition lists.
    #[test]
    fn sandbox_lease_root_cel_inputs_are_bounded() {
        let lease = serde_json::to_value(SandboxLease::crd()).unwrap();
        let root = &lease["spec"]["versions"][0]["schema"]["openAPIV3Schema"];
        let status = &root["properties"]["status"]["properties"];
        let conditions = &status["conditions"];
        assert_eq!(conditions["maxItems"], 16);
        assert_eq!(conditions["items"]["properties"]["type"]["maxLength"], 63);

        let reference = &status["target"]["properties"]["childClusterKubeconfigSecret"];
        assert_eq!(reference["properties"]["apiVersion"]["maxLength"], 253);
        assert_eq!(reference["properties"]["kind"]["maxLength"], 63);
        assert_eq!(reference["properties"]["namespace"]["maxLength"], 63);
        assert_eq!(reference["properties"]["name"]["maxLength"], 253);
        assert_eq!(reference["properties"]["uid"]["maxLength"], 128);
    }

    #[test]
    fn placement_authority_schema_is_exact_child_only_and_immutable() {
        let pool = serde_json::to_value(SandboxPool::crd()).unwrap();
        let lease = serde_json::to_value(SandboxLease::crd()).unwrap();
        let pool_root = &pool["spec"]["versions"][0]["schema"]["openAPIV3Schema"];
        let lease_root = &lease["spec"]["versions"][0]["schema"]["openAPIV3Schema"];
        let pool_authority = &pool_root["properties"]["status"]["properties"]["placementAuthority"];
        let lease_authority = &lease_root["properties"]["spec"]["properties"]["placementAuthority"];

        for authority in [pool_authority, lease_authority] {
            let required = authority["required"].as_array().unwrap();
            for field in [
                "apiVersion",
                "kind",
                "namespace",
                "name",
                "uid",
                "generation",
            ] {
                assert!(required.iter().any(|required| required == field));
            }
            assert_eq!(authority["properties"]["generation"]["minimum"], 1.0);
            assert_eq!(authority["properties"]["apiVersion"]["maxLength"], 253);
            assert_eq!(authority["properties"]["kind"]["maxLength"], 63);
            assert_eq!(authority["properties"]["namespace"]["maxLength"], 63);
            assert_eq!(authority["properties"]["name"]["maxLength"], 63);
            assert_eq!(authority["properties"]["uid"]["maxLength"], 128);
        }

        let pool_validations = pool_root["x-kubernetes-validations"].as_array().unwrap();
        for message in [
            "placementAuthority must identify the exact child ClusterPool",
            "placementAuthority is published only with coherent CompositionEligible status",
        ] {
            assert!(
                pool_validations
                    .iter()
                    .any(|validation| validation["message"] == message)
            );
        }
        let lease_validations = lease_root["x-kubernetes-validations"].as_array().unwrap();
        for message in [
            "spec.placementAuthority is immutable",
            "spec.placementAuthority must identify a ClusterPool",
            "resolved placement must match the immutable admission placementAuthority",
            "child placement without placementAuthority may only preserve an exact legacy placement",
            "legacy child placement without placementAuthority may not be removed or changed",
        ] {
            assert!(
                lease_validations
                    .iter()
                    .any(|validation| validation["message"] == message)
            );
        }
        let resolved_rule = lease_validations
            .iter()
            .find(|validation| {
                validation["message"]
                    == "resolved placement must match the immutable admission placementAuthority"
            })
            .and_then(|validation| validation["rule"].as_str())
            .expect("resolved placement CEL");
        assert!(resolved_rule.contains(".__namespace__"));
        assert!(!resolved_rule.contains(".namespace"));
        for message in [
            "child placement without placementAuthority may only preserve an exact legacy placement",
            "legacy child placement without placementAuthority may not be removed or changed",
        ] {
            let rule = lease_validations
                .iter()
                .find(|validation| validation["message"] == message)
                .and_then(|validation| validation["rule"].as_str())
                .expect("legacy transition rule");
            assert!(rule.contains("self.status.placement == oldSelf.status.placement"));
            assert!(rule.contains("!has(oldSelf.spec.placementAuthority)"));
        }
        for validation in pool_validations.iter().chain(lease_validations) {
            assert!(
                !validation["rule"]
                    .as_str()
                    .expect("CEL validation rule")
                    .contains("metadata.namespace"),
                "CRD CEL cannot address metadata.namespace"
            );
        }
    }

    /// The SandboxPool placement invariants are status-only.
    ///
    /// A rule that constrains `status.placementAuthority` against
    /// `self.spec.placement` rejected every placement edit on a child pool,
    /// permanently: PrepareForUpdate carries status over unchanged across a
    /// spec-only edit, so the new spec was judged against the previous
    /// generation's recorded authority and could never agree with it. These
    /// pins keep the rules reading `status.placement` — the controller-recorded
    /// mirror of what is being reconciled — so an edit is admitted and the next
    /// reconcile brings status back in line with spec.
    #[test]
    fn sandbox_pool_placement_rules_are_status_only() {
        let pool = serde_json::to_value(SandboxPool::crd()).unwrap();
        let root = &pool["spec"]["versions"][0]["schema"]["openAPIV3Schema"];
        let validations = root["x-kubernetes-validations"].as_array().unwrap();
        for message in [
            "placementAuthority must identify the exact child ClusterPool",
            "placementAuthority is published only with coherent CompositionEligible status",
        ] {
            let rule = validations
                .iter()
                .find(|validation| validation["message"] == message)
                .and_then(|validation| validation["rule"].as_str())
                .expect("pool placement CEL");
            assert!(
                !rule.contains("self.spec"),
                "'{message}' must not read spec: a spec/status comparison freezes placement"
            );
            assert!(
                rule.contains("self.status.placement"),
                "'{message}' must compare against the status-recorded placement"
            );
        }
    }

    #[test]
    fn pre_authority_replica_rejects_new_lease_field_during_rolling_upgrade() {
        #[allow(dead_code)]
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct PreAuthoritySandboxLeaseSpec {
            pool_ref: SandboxPoolReference,
            ttl: String,
            #[serde(default)]
            alias: Option<String>,
            requester: SandboxPrincipal,
        }

        let current = SandboxLeaseSpec {
            pool_ref: SandboxPoolReference {
                name: "sandbox-pool".into(),
                uid: "sandbox-pool-uid".into(),
                generation: 1,
            },
            placement_authority: Some(SandboxPlacementAuthority {
                api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                kind: "ClusterPool".into(),
                namespace: "kobe-system".into(),
                name: "child-pool".into(),
                uid: "child-pool-uid".into(),
                generation: 3,
            }),
            ttl: "1h".into(),
            alias: None,
            requester: SandboxPrincipal {
                provider: "oidc".into(),
                requester_type: "user".into(),
                issuer: "https://issuer.invalid".into(),
                identity: "alice".into(),
            },
        };
        let result = serde_json::from_value::<PreAuthoritySandboxLeaseSpec>(
            serde_json::to_value(current).unwrap(),
        );
        let error = result
            .err()
            .expect("older strict replica must reject the field");
        assert!(error.to_string().contains("placementAuthority"));
    }
}
