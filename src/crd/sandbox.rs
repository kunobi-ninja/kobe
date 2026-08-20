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

/// Administrator-owned class of Agent Sandbox capacity.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, KubeSchema, PartialEq, Eq)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "SandboxPool",
    plural = "sandboxpools",
    shortname = "sp",
    status = "SandboxPoolStatus",
    namespaced,
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
    /// Direct argv vector; no implicit shell expansion.
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
    validation = Rule::new("!has(self.status) || self.status == null || !has(self.status.conditions) || self.status.conditions.all(c, c.type != 'FootprintAbsent' || (c.status == 'True' && has(self.status.releaseCause) && self.status.phase in ['Releasing', 'Released', 'Expired']))")
        .message("FootprintAbsent must be True and requires a releasing or clean terminal status with releaseCause"),
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Expires","type":"date","jsonPath":".status.expiresAt"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxLeaseSpec {
    /// Exact SandboxPool admitted by Kobe. UID and generation fence pool
    /// recreation or mutation between HTTP admission and placement.
    pub pool_ref: SandboxPoolReference,
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
    #[schemars(length(min = 1))]
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
    /// Current-generation pool certification. `Ready=True` authorizes new
    /// leases; missing, stale, `False`, or `Unknown` conditions fail closed.
    /// Replica counters alone never authorize admission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(
        extend("x-kubernetes-list-type" = "map"),
        extend("x-kubernetes-list-map-keys" = ["type"])
    )]
    pub conditions: Vec<SandboxCondition>,
}

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
    /// Immutable reason the lease first entered `Releasing`. Persisted in the
    /// same status write as that phase so retries, later release requests, and
    /// controller restarts cannot change the terminal accounting outcome.
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(
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
    /// A management Claim cleanup finalizer was durable before the first POST,
    /// or an exact non-deleting legacy Claim was atomically migrated to that
    /// ownerless/finalized shape before this checkpoint was written.
    FinalizerV1,
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

/// Non-secret identity of one exact Kubernetes object.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxObjectReference {
    #[schemars(length(min = 1))]
    pub api_version: String,
    #[schemars(length(min = 1))]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1))]
    pub namespace: Option<String>,
    #[schemars(length(min = 1))]
    pub name: String,
    #[schemars(length(min = 1))]
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
    #[schemars(length(min = 1))]
    pub namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_cluster_lease: Option<SandboxObjectReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_cluster_instance: Option<SandboxObjectReference>,
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxCondition {
    #[serde(rename = "type")]
    pub condition_type: String,
    pub status: SandboxConditionStatus,
    pub reason: String,
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
                null
            ])
        );
        assert!(status_schema.get("x-kubernetes-validations").is_none());
        let validations = root_schema["x-kubernetes-validations"].as_array().unwrap();
        for rule in [
            "!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.releaseCause) || (has(self.status) && self.status != null && has(self.status.releaseCause) && self.status.releaseCause == oldSelf.status.releaseCause)",
            "!has(oldSelf.status) || oldSelf.status == null || !has(oldSelf.status.conditions) || !oldSelf.status.conditions.exists(c, c.type == 'FootprintAbsent' && c.status == 'True') || (has(self.status) && self.status != null && has(self.status.conditions) && self.status.conditions.exists(c, c.type == 'FootprintAbsent' && c.status == 'True'))",
            "!has(self.status) || self.status == null || !has(self.status.conditions) || self.status.conditions.all(c, c.type != 'FootprintAbsent' || (c.status == 'True' && has(self.status.releaseCause) && self.status.phase in ['Releasing', 'Released', 'Expired']))",
        ] {
            assert!(
                validations
                    .iter()
                    .any(|validation| validation["rule"] == rule),
                "missing root validation: {rule}"
            );
        }
    }
}
