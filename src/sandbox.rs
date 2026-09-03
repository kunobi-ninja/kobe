//! Pure Agent Sandbox v1.0.0 `v1beta1` projections and lease invariants.
//!
//! This module has no Kubernetes client or reconciliation side effects. Pool
//! controllers can render the restricted Kobe contract into upstream objects,
//! and placement/teardown controllers can reuse the monotonic provenance
//! checks before touching a target cluster.

// #71 intentionally lands these pure contracts before #73/#74 wire them into
// reconcilers. Keep non-test builds warning-clean during that staged rollout.
#![allow(dead_code)]

use std::collections::BTreeMap;

use chrono::{DateTime, SecondsFormat, Utc};
use k8s_openapi::api::core::v1::{
    Capabilities, Container, ContainerPort, PodSecurityContext, PodSpec, ResourceRequirements,
    SeccompProfile, SecurityContext,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::ResourceExt;
use kube::api::{DynamicObject, ObjectMeta, TypeMeta};
use thiserror::Error;

use crate::crd::{
    ResolvedSandboxPlacement, SandboxConditionStatus, SandboxLeasePhase, SandboxLeaseStatus,
    SandboxObjectReference, SandboxPool, SandboxPoolSpec, SandboxPoolValidationError,
    SandboxResourceCeiling, SandboxTargetProvenance, SandboxTemplateSpec,
};

pub const AGENT_SANDBOX_API_VERSION: &str = "extensions.agents.x-k8s.io/v1beta1";
pub const SANDBOX_TEMPLATE_KIND: &str = "SandboxTemplate";
pub const SANDBOX_WARM_POOL_KIND: &str = "SandboxWarmPool";
pub const SANDBOX_CLAIM_KIND: &str = "SandboxClaim";
pub const KOBE_MANAGED_BY: &str = "kobe-operator";
pub const SANDBOX_LEASE_UID_LABEL: &str = "kobe.kunobi.ninja/sandbox-lease-uid";
/// Namespace inside an exclusive child cluster that holds Sandbox objects.
///
/// This is shared by placement and provenance validation: accepting a
/// different namespace during recovery would let a damaged parent select a
/// teardown path the controller never created.
pub const CHILD_SANDBOX_NAMESPACE: &str = "kobe-sandbox";
/// Holds a management `SandboxClaim` through the create-response/status-write
/// gap. Release removes it only while atomically converting a live Claim into
/// an inert tombstone, or the retained tombstone reaper removes it later.
pub const SANDBOX_CLAIM_CLEANUP_FINALIZER: &str = "kobe.kunobi.ninja/sandbox-claim-cleanup";
/// Keeps a [`SandboxLease`](crate::crd::SandboxLease) present until Kobe has
/// durably proved its complete footprint absent and released its reservations.
///
/// Admission stamps this on the initial CREATE, eliminating the controller
/// race where a direct Kubernetes DELETE could otherwise bypass cleanup.
pub const SANDBOX_LEASE_FINALIZER: &str = "kobe.kunobi.ninja/sandbox-cleanup";
const KOBE_API_VERSION: &str = "kobe.kunobi.ninja/v1alpha1";
const SANDBOX_API_VERSION: &str = "agents.x-k8s.io/v1beta1";
const CORE_API_VERSION: &str = "v1";

/// Require the durable, current-generation readiness certificate used by both
/// HTTP admission and the final pre-Claim placement check.
///
/// Capacity counters and an upstream WarmPool's `readyReplicas` are
/// observations, not a safety certificate. A pool is admissible only when one
/// `Ready=True` condition and the enclosing status were both derived from the
/// pool's current generation and backed by the terminal durable certification
/// receipt. Missing, stale, duplicate, false, unknown, or receipt-less status
/// all fail closed.
pub fn require_current_sandbox_pool_ready(
    pool: &SandboxPool,
) -> Result<(), SandboxPoolReadinessError> {
    let generation = pool
        .metadata
        .generation
        .ok_or(SandboxPoolReadinessError::MissingGeneration)?;
    let status = pool
        .status
        .as_ref()
        .ok_or(SandboxPoolReadinessError::MissingStatus)?;
    if status.observed_generation != Some(generation) {
        return Err(SandboxPoolReadinessError::StaleStatus {
            expected: generation,
            observed: status.observed_generation,
        });
    }

    let mut ready_conditions = status
        .conditions
        .iter()
        .filter(|condition| condition.condition_type == "Ready");
    let ready = ready_conditions
        .next()
        .ok_or(SandboxPoolReadinessError::MissingReadyCondition)?;
    if ready_conditions.next().is_some() {
        return Err(SandboxPoolReadinessError::DuplicateReadyCondition);
    }
    if ready.observed_generation != Some(generation) {
        return Err(SandboxPoolReadinessError::StaleReadyCondition {
            expected: generation,
            observed: ready.observed_generation,
        });
    }
    if ready.status != SandboxConditionStatus::True {
        return Err(SandboxPoolReadinessError::NotReady {
            status: ready.status,
            reason: ready.reason.clone(),
        });
    }
    let certification = status
        .certification
        .as_ref()
        .ok_or(SandboxPoolReadinessError::MissingCertification)?;
    if certification.observed_generation != generation {
        return Err(SandboxPoolReadinessError::StaleCertification {
            expected: generation,
            observed: certification.observed_generation,
        });
    }
    if certification.phase != crate::crd::SandboxPoolCertificationPhase::Certified
        || certification.certified_at.is_none()
    {
        return Err(SandboxPoolReadinessError::IncompleteCertification {
            phase: certification.phase,
        });
    }
    Ok(())
}

/// Return the exact child ClusterPool authority currently certified for
/// allocation, without claiming the remote runtime is ready yet.
///
/// This certificate may allocate only the internal exclusive ClusterLease.
/// The composition reconciler still must authenticate and canary that exact
/// child before creating the caller's upstream Claim.
pub fn current_child_pool_allocation_authority(
    pool: &SandboxPool,
) -> Option<&crate::crd::SandboxPlacementAuthority> {
    let generation = pool.metadata.generation?;
    if pool.metadata.deletion_timestamp.is_some() {
        return None;
    }
    let crate::crd::SandboxPlacement::ChildCluster { cluster_pool_ref } = &pool.spec.placement
    else {
        return None;
    };
    let status = pool.status.as_ref()?;
    if status.observed_generation != Some(generation) {
        return None;
    }
    let ready = status
        .conditions
        .iter()
        .filter(|condition| condition.condition_type == "Ready")
        .collect::<Vec<_>>();
    if ready.len() != 1
        || ready[0].status != SandboxConditionStatus::False
        || ready[0].reason != "CompositionEligible"
        || ready[0].observed_generation != Some(generation)
    {
        return None;
    }
    let authority = status.placement_authority.as_ref()?;
    let namespace = pool.namespace()?;
    (authority.api_version == KOBE_API_VERSION
        && authority.kind == "ClusterPool"
        && authority.namespace == namespace
        && authority.name == *cluster_pool_ref
        && !authority.uid.is_empty()
        && authority.generation > 0)
        .then_some(authority)
}

/// Why a SandboxPool cannot currently authorize new workload placement.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SandboxPoolReadinessError {
    #[error("SandboxPool has no metadata.generation")]
    MissingGeneration,
    #[error("SandboxPool has no status")]
    MissingStatus,
    #[error(
        "SandboxPool status observed generation {observed:?}, expected current generation {expected}"
    )]
    StaleStatus {
        expected: i64,
        observed: Option<i64>,
    },
    #[error("SandboxPool status has no Ready condition")]
    MissingReadyCondition,
    #[error("SandboxPool status has duplicate Ready conditions")]
    DuplicateReadyCondition,
    #[error(
        "SandboxPool Ready condition observed generation {observed:?}, expected current generation {expected}"
    )]
    StaleReadyCondition {
        expected: i64,
        observed: Option<i64>,
    },
    #[error("SandboxPool Ready condition is {status:?}: {reason}")]
    NotReady {
        status: SandboxConditionStatus,
        reason: String,
    },
    #[error("SandboxPool status has no durable certification receipt")]
    MissingCertification,
    #[error(
        "SandboxPool certification observed generation {observed}, expected current generation {expected}"
    )]
    StaleCertification { expected: i64, observed: i64 },
    #[error("SandboxPool certification phase is {phase:?}, expected Certified")]
    IncompleteCertification {
        phase: crate::crd::SandboxPoolCertificationPhase,
    },
}

/// Render one administrator-owned Kobe pool template into the pinned upstream
/// Agent Sandbox contract.
///
/// The projection is intentionally closed: it emits only declared containers,
/// CPU/memory/ephemeral-storage resources, TCP ports, the administrator's
/// RuntimeClass, and fixed Restricted-profile-compatible Pod/container
/// security contexts. Every workload runs as Kobe's non-root UID/GID 65532,
/// drops all capabilities, disables privilege escalation and service-account
/// token/service-link injection, and uses RuntimeDefault seccomp. It cannot
/// emit PVC templates, environment values, service accounts, arbitrary
/// volumes, or caller metadata.
pub fn build_sandbox_template(
    name: &str,
    namespace: &str,
    pool: &SandboxPoolSpec,
    owner_ref: Option<&OwnerReference>,
) -> Result<DynamicObject, SandboxMappingError> {
    pool.validate()?;
    aggregate_resource_limits(&pool.template)?;

    let containers = pool
        .template
        .containers
        .iter()
        .map(|container| {
            let ports: Vec<ContainerPort> = pool
                .template
                .exposed_ports
                .iter()
                .filter(|port| port.container == container.name)
                .map(|port| ContainerPort {
                    container_port: i32::from(port.port),
                    name: Some(port.name.clone()),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                })
                .collect();

            Container {
                name: container.name.clone(),
                image: Some(container.image.clone()),
                command: (!container.command.is_empty()).then(|| container.command.clone()),
                args: (!container.args.is_empty()).then(|| container.args.clone()),
                ports: (!ports.is_empty()).then_some(ports),
                resources: Some(to_k8s_resources(&container.resources)),
                security_context: Some(SecurityContext {
                    allow_privilege_escalation: Some(false),
                    capabilities: Some(Capabilities {
                        drop: Some(vec!["ALL".to_string()]),
                        ..Capabilities::default()
                    }),
                    privileged: Some(false),
                    run_as_non_root: Some(true),
                    ..SecurityContext::default()
                }),
                ..Default::default()
            }
        })
        .collect();

    let pod_spec = PodSpec {
        automount_service_account_token: Some(false),
        containers,
        enable_service_links: Some(false),
        restart_policy: Some("Never".to_string()),
        runtime_class_name: pool.isolation.runtime_class_name().map(ToString::to_string),
        security_context: Some(PodSecurityContext {
            run_as_group: Some(65_532),
            run_as_non_root: Some(true),
            run_as_user: Some(65_532),
            seccomp_profile: Some(SeccompProfile {
                type_: "RuntimeDefault".to_string(),
                ..SeccompProfile::default()
            }),
            ..PodSecurityContext::default()
        }),
        ..Default::default()
    };
    let pod_spec = serde_json::to_value(pod_spec)?;

    Ok(managed_object(
        SANDBOX_TEMPLATE_KIND,
        name,
        namespace,
        owner_ref,
        serde_json::json!({
            "spec": {
                "podTemplate": {
                    "metadata": {
                        "labels": {
                            "app.kubernetes.io/managed-by": KOBE_MANAGED_BY
                        },
                        "annotations": {
                            "kubectl.kubernetes.io/default-container": pool.template.default_container
                        }
                    },
                    "spec": pod_spec
                },
                "service": !pool.template.exposed_ports.is_empty(),
                "networkPolicyManagement": "Managed",
                "envVarsInjectionPolicy": "Disallowed",
                "volumeClaimTemplatesPolicy": "Disallowed"
            }
        }),
    ))
}

/// Render the upstream warm pool using the exact v1beta1
/// `sandboxTemplateRef.name` field and an immediate drift replacement policy.
pub fn build_sandbox_warm_pool(
    name: &str,
    namespace: &str,
    template_name: &str,
    warm_capacity: u32,
    owner_ref: Option<&OwnerReference>,
) -> Result<DynamicObject, SandboxMappingError> {
    let replicas = i32::try_from(warm_capacity)
        .map_err(|_| SandboxMappingError::WarmCapacityTooLarge(warm_capacity))?;
    Ok(managed_object(
        SANDBOX_WARM_POOL_KIND,
        name,
        namespace,
        owner_ref,
        serde_json::json!({
            "spec": {
                "replicas": replicas,
                "sandboxTemplateRef": { "name": template_name },
                "updateStrategy": { "type": "Recreate" }
            }
        }),
    ))
}

/// Render one lease as a v1beta1 SandboxClaim.
///
/// The initial claim carries the already-persisted provisioning deadline as a
/// shutdown backstop. Runtime TTL still starts only after the upstream Sandbox
/// becomes Ready: [`build_sandbox_claim_lifecycle_patch`] then replaces this
/// provisional bound with `readyAt + ttl` under a resourceVersion fence.
///
/// Putting the first bound in the POST body matters for cancellation safety. A
/// request whose apiserver commit is delayed past outer-lease retention is
/// already expired when it finally lands; it cannot create an unbounded orphan.
///
/// Every claim also carries the exact outer lease UID. Management placement
/// deliberately has no owner reference: garbage collection must not remove the
/// claim before the outer lease finalizer has verified teardown. Child claims
/// may be owned by their same-cluster target Namespace, so deleting that
/// exclusive Namespace still collects its upstream footprint.
pub fn build_sandbox_claim(
    name: &str,
    namespace: &str,
    warm_pool_name: &str,
    lease_uid: &str,
    provisioning_deadline: DateTime<Utc>,
    hold_for_explicit_cleanup: bool,
    owner_ref: Option<&OwnerReference>,
) -> DynamicObject {
    let mut claim = managed_object(
        SANDBOX_CLAIM_KIND,
        name,
        namespace,
        owner_ref,
        serde_json::json!({
            "spec": {
                "warmPoolRef": { "name": warm_pool_name },
                "lifecycle": {
                    "shutdownTime": provisioning_deadline
                        .to_rfc3339_opts(SecondsFormat::AutoSi, true),
                    "shutdownPolicy": "DeleteForeground"
                }
            }
        }),
    );
    let labels = claim.metadata.labels.get_or_insert_default();
    labels.insert(SANDBOX_LEASE_UID_LABEL.to_string(), lease_uid.to_string());
    if hold_for_explicit_cleanup {
        claim.metadata.finalizers = Some(vec![SANDBOX_CLAIM_CLEANUP_FINALIZER.to_string()]);
    }
    claim
}

/// Build the post-Ready merge patch that starts upstream expiry. Callers must
/// derive `expires_at` from the persisted `readyAt + ttl` invariant and use the
/// current exact Claim resourceVersion.
pub fn build_sandbox_claim_lifecycle_patch(
    resource_version: &str,
    expires_at: DateTime<Utc>,
) -> Result<serde_json::Value, SandboxMappingError> {
    if resource_version.trim().is_empty() {
        return Err(SandboxMappingError::MissingResourceVersion);
    }
    Ok(serde_json::json!({
        "metadata": { "resourceVersion": resource_version },
        "spec": {
            "lifecycle": {
                "shutdownTime": expires_at.to_rfc3339_opts(SecondsFormat::AutoSi, true),
                "shutdownPolicy": "DeleteForeground"
            }
        }
    }))
}

fn managed_object(
    kind: &str,
    name: &str,
    namespace: &str,
    owner_ref: Option<&OwnerReference>,
    data: serde_json::Value,
) -> DynamicObject {
    DynamicObject {
        types: Some(TypeMeta {
            api_version: AGENT_SANDBOX_API_VERSION.to_string(),
            kind: kind.to_string(),
        }),
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(
                [(
                    "app.kubernetes.io/managed-by".to_string(),
                    KOBE_MANAGED_BY.to_string(),
                )]
                .into_iter()
                .collect(),
            ),
            owner_references: owner_ref.cloned().map(|owner| vec![owner]),
            ..Default::default()
        },
        data,
    }
}

fn to_k8s_resources(resources: &crate::crd::SandboxContainerResources) -> ResourceRequirements {
    let quantities = |quantity: &crate::crd::SandboxResourceQuantity| {
        BTreeMap::from([
            ("cpu".to_string(), Quantity(quantity.cpu.clone())),
            ("memory".to_string(), Quantity(quantity.memory.clone())),
            (
                "ephemeral-storage".to_string(),
                Quantity(quantity.ephemeral_storage.clone()),
            ),
        ])
    };
    ResourceRequirements {
        limits: Some(quantities(&resources.limits)),
        requests: Some(quantities(&resources.requests)),
        ..Default::default()
    }
}

#[derive(Debug, Error)]
pub enum SandboxMappingError {
    #[error(transparent)]
    InvalidPool(#[from] SandboxPoolValidationError),
    #[error(transparent)]
    InvalidResources(#[from] SandboxResourceError),
    #[error("warm capacity {0} exceeds upstream int32 replicas")]
    WarmCapacityTooLarge(u32),
    #[error("failed to serialize the restricted PodSpec: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("SandboxClaim resourceVersion is required for the lifecycle patch")]
    MissingResourceVersion,
}

/// Canonical aggregate values used for exact, unit-independent admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxResourceTotals {
    pub cpu_millicores: u128,
    pub memory_bytes: u128,
    cpu_nanocores: u128,
    memory_nanobytes: u128,
}

/// Sum declared per-container limits and validate every resource pair.
///
/// Requests may not exceed limits. Quantities are rounded upward to the target
/// unit following Kubernetes Quantity semantics, avoiding an undercount at an
/// authorization boundary.
pub fn aggregate_resource_limits(
    template: &SandboxTemplateSpec,
) -> Result<SandboxResourceTotals, SandboxResourceError> {
    let mut total_cpu_nanos = 0u128;
    let mut total_memory_nanos = 0u128;

    for container in &template.containers {
        // Compare exact nanounits before rounding into policy units. Independent
        // ceiling-rounding would incorrectly accept 900m > 100m memory because
        // both values become one whole byte.
        let request_cpu = parse_positive_quantity_nanos(
            &container.resources.requests.cpu,
            QuantityDimension::Cpu,
            "requests.cpu",
        )?;
        let limit_cpu = parse_positive_quantity_nanos(
            &container.resources.limits.cpu,
            QuantityDimension::Cpu,
            "limits.cpu",
        )?;
        let request_memory = parse_positive_quantity_nanos(
            &container.resources.requests.memory,
            QuantityDimension::Bytes,
            "requests.memory",
        )?;
        let limit_memory = parse_positive_quantity_nanos(
            &container.resources.limits.memory,
            QuantityDimension::Bytes,
            "limits.memory",
        )?;
        let request_ephemeral = parse_positive_quantity_nanos(
            &container.resources.requests.ephemeral_storage,
            QuantityDimension::Bytes,
            "requests.ephemeralStorage",
        )?;
        let limit_ephemeral = parse_positive_quantity_nanos(
            &container.resources.limits.ephemeral_storage,
            QuantityDimension::Bytes,
            "limits.ephemeralStorage",
        )?;

        for (resource, request, limit) in [
            ("cpu", request_cpu, limit_cpu),
            ("memory", request_memory, limit_memory),
            ("ephemeral-storage", request_ephemeral, limit_ephemeral),
        ] {
            if request > limit {
                return Err(SandboxResourceError::RequestExceedsLimit {
                    container: container.name.clone(),
                    resource,
                });
            }
        }

        total_cpu_nanos = total_cpu_nanos
            .checked_add(limit_cpu)
            .ok_or(SandboxResourceError::AggregateOverflow("cpu"))?;
        total_memory_nanos = total_memory_nanos
            .checked_add(limit_memory)
            .ok_or(SandboxResourceError::AggregateOverflow("memory"))?;
    }

    Ok(SandboxResourceTotals {
        cpu_millicores: ceil_div(total_cpu_nanos, 1_000_000)
            .ok_or(SandboxResourceError::AggregateOverflow("cpu"))?,
        memory_bytes: ceil_div(total_memory_nanos, 1_000_000_000)
            .ok_or(SandboxResourceError::AggregateOverflow("memory"))?,
        cpu_nanocores: total_cpu_nanos,
        memory_nanobytes: total_memory_nanos,
    })
}

/// Parse a policy ceiling into the canonical units used by admission.
pub fn parse_resource_ceiling(
    ceiling: &SandboxResourceCeiling,
) -> Result<SandboxResourceTotals, SandboxResourceError> {
    let cpu_nanocores = parse_positive_quantity_nanos(
        &ceiling.max_cpu,
        QuantityDimension::Cpu,
        "resourceCeiling.maxCpu",
    )?;
    let memory_nanobytes = parse_positive_quantity_nanos(
        &ceiling.max_memory,
        QuantityDimension::Bytes,
        "resourceCeiling.maxMemory",
    )?;
    Ok(SandboxResourceTotals {
        cpu_millicores: ceil_div(cpu_nanocores, 1_000_000)
            .ok_or(SandboxResourceError::AggregateOverflow("cpu"))?,
        memory_bytes: ceil_div(memory_nanobytes, 1_000_000_000)
            .ok_or(SandboxResourceError::AggregateOverflow("memory"))?,
        cpu_nanocores,
        memory_nanobytes,
    })
}

/// Compare a pool's aggregate limits with a caller's typed policy ceiling.
/// Invalid policy quantities return an error so admission can fail closed.
pub fn resource_ceiling_allows(
    ceiling: &SandboxResourceCeiling,
    requested: &SandboxResourceTotals,
) -> Result<bool, SandboxResourceError> {
    let ceiling = parse_resource_ceiling(ceiling)?;
    Ok(requested.cpu_nanocores <= ceiling.cpu_nanocores
        && requested.memory_nanobytes <= ceiling.memory_nanobytes)
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SandboxResourceError {
    #[error("invalid or non-positive Kubernetes quantity for {field}: {value}")]
    InvalidQuantity { field: &'static str, value: String },
    #[error("container {container} {resource} request exceeds its limit")]
    RequestExceedsLimit {
        container: String,
        resource: &'static str,
    },
    #[error("aggregate {0} limit overflow")]
    AggregateOverflow(&'static str),
}

#[derive(Debug, Clone, Copy)]
enum QuantityDimension {
    Cpu,
    Bytes,
}

fn parse_positive_quantity(
    value: &str,
    dimension: QuantityDimension,
    field: &'static str,
) -> Result<u128, SandboxResourceError> {
    let parsed = parse_quantity_nanos(value)
        .filter(|value| *value > 0)
        .filter(|value| {
            !matches!(dimension, QuantityDimension::Cpu)
                || (*value >= 1_000_000 && *value % 1_000_000 == 0)
        })
        .and_then(|nanos| match dimension {
            QuantityDimension::Cpu => ceil_div(nanos, 1_000_000),
            QuantityDimension::Bytes => ceil_div(nanos, 1_000_000_000),
        });
    parsed.ok_or_else(|| SandboxResourceError::InvalidQuantity {
        field,
        value: value.to_string(),
    })
}

fn parse_positive_quantity_nanos(
    value: &str,
    dimension: QuantityDimension,
    field: &'static str,
) -> Result<u128, SandboxResourceError> {
    parse_quantity_nanos(value)
        .filter(|value| *value > 0)
        .filter(|value| {
            !matches!(dimension, QuantityDimension::Cpu)
                || (*value >= 1_000_000 && *value % 1_000_000 == 0)
        })
        .ok_or_else(|| SandboxResourceError::InvalidQuantity {
            field,
            value: value.to_string(),
        })
}

fn parse_quantity(value: &str, dimension: QuantityDimension) -> Option<u128> {
    let nanos = parse_quantity_nanos(value)?;
    match dimension {
        QuantityDimension::Cpu if nanos >= 1_000_000 && nanos % 1_000_000 == 0 => {
            ceil_div(nanos, 1_000_000)
        }
        QuantityDimension::Cpu => None,
        QuantityDimension::Bytes => ceil_div(nanos, 1_000_000_000),
    }
}

/// Parse the full positive Kubernetes Quantity suffix grammar into nanounits.
/// Nanounits retain exact request/limit ordering; conversion to mCPU or bytes
/// happens only after comparisons and aggregation. Kubernetes quantities cap
/// at signed 64-bit base units, which also bounds admission arithmetic.
fn parse_quantity_nanos(value: &str) -> Option<u128> {
    if value != value.trim() {
        return None;
    }
    let value = value.strip_prefix('+').unwrap_or(value);
    if value.is_empty() || value.starts_with('-') {
        return None;
    }

    let bytes = value.as_bytes();
    let mut index = 0;
    let mut mantissa = 0u128;
    let mut fractional_digits = 0u32;
    let mut saw_digit = false;
    let mut saw_decimal = false;
    while index < bytes.len() {
        match bytes[index] {
            b'0'..=b'9' => {
                saw_digit = true;
                mantissa = mantissa
                    .checked_mul(10)?
                    .checked_add(u128::from(bytes[index] - b'0'))?;
                if saw_decimal {
                    fractional_digits = fractional_digits.checked_add(1)?;
                }
                index += 1;
            }
            b'.' if !saw_decimal => {
                saw_decimal = true;
                index += 1;
            }
            _ => break,
        }
    }
    if !saw_digit {
        return None;
    }

    let suffix = &value[index..];
    let nanos = if let Some(binary_power) = match suffix {
        "Ki" => Some(1),
        "Mi" => Some(2),
        "Gi" => Some(3),
        "Ti" => Some(4),
        "Pi" => Some(5),
        "Ei" => Some(6),
        _ => None,
    } {
        let numerator = mantissa
            .checked_mul(1024u128.checked_pow(binary_power)?)?
            .checked_mul(1_000_000_000)?;
        ceil_div(numerator, 10u128.checked_pow(fractional_digits)?)?
    } else {
        let suffix_exponent = match suffix {
            "" => 0,
            "n" => -9,
            "u" => -6,
            "m" => -3,
            "k" => 3,
            "M" => 6,
            "G" => 9,
            "T" => 12,
            "P" => 15,
            "E" => 18,
            _ if suffix.starts_with('e') || (suffix.starts_with('E') && suffix.len() > 1) => {
                suffix[1..].parse::<i32>().ok()?
            }
            _ => return None,
        };
        let scale = suffix_exponent
            .checked_add(9)?
            .checked_sub(i32::try_from(fractional_digits).ok()?)?;
        if scale >= 0 {
            mantissa.checked_mul(10u128.checked_pow(scale as u32)?)?
        } else {
            ceil_div(mantissa, 10u128.checked_pow(scale.unsigned_abs())?)?
        }
    };

    const KUBERNETES_MAX_NANOUNITS: u128 = (i64::MAX as u128) * 1_000_000_000;
    (nanos <= KUBERNETES_MAX_NANOUNITS).then_some(nanos)
}

fn ceil_div(numerator: u128, denominator: u128) -> Option<u128> {
    let quotient = numerator.checked_div(denominator)?;
    let remainder = numerator.checked_rem(denominator)?;
    quotient.checked_add(u128::from(remainder != 0))
}

/// Record resolved placement once. Retries may repeat the same value, but no
/// controller may silently retarget a lease or invent a management fallback.
pub fn record_placement_once(
    existing: Option<&ResolvedSandboxPlacement>,
    proposed: ResolvedSandboxPlacement,
    management_namespace: &str,
) -> Result<ResolvedSandboxPlacement, SandboxProvenanceError> {
    validate_resolved_placement(&proposed, management_namespace)?;
    match existing {
        None => Ok(proposed),
        Some(current) if current == &proposed => {
            validate_resolved_placement(current, management_namespace)?;
            Ok(current.clone())
        }
        Some(_) => Err(SandboxProvenanceError::PlacementChanged),
    }
}

/// Require an explicitly persisted placement before target operations.
pub fn require_resolved_placement<'a>(
    status: &'a SandboxLeaseStatus,
    management_namespace: &str,
) -> Result<&'a ResolvedSandboxPlacement, SandboxProvenanceError> {
    let placement = status
        .placement
        .as_ref()
        .ok_or(SandboxProvenanceError::UnresolvedPlacement)?;
    validate_resolved_placement(placement, management_namespace)?;
    Ok(placement)
}

/// Require placement/target provenance that can safely select a teardown path.
///
/// Progressive placement may record a partial target while it discovers
/// objects. Admission repair is stricter: management placement must use the
/// operator namespace and carry no child identities, while child placement
/// must carry both the exact internal lease and bound instance. Every present
/// reference is also checked for its canonical GVK, namespace, non-empty UID,
/// and required generation. Without this proof, choosing either teardown path
/// could release quota while the footprint belonging to the other path
/// survives.
pub fn require_release_safe_target_provenance<'a>(
    status: &'a SandboxLeaseStatus,
    management_namespace: &str,
) -> Result<&'a SandboxTargetProvenance, SandboxProvenanceError> {
    let placement = require_resolved_placement(status, management_namespace)?;
    let target = status
        .target
        .as_ref()
        .ok_or(SandboxProvenanceError::MissingTargetProvenance)?;
    validate_target_provenance(target, placement, management_namespace)?;
    match placement {
        ResolvedSandboxPlacement::Management {} if target.namespace != management_namespace => {
            return Err(SandboxProvenanceError::InvalidReference {
                field: "namespace",
                reason: "management target namespace does not match the operator namespace",
            });
        }
        ResolvedSandboxPlacement::ChildCluster { .. }
            if target.child_cluster_lease.is_none() || target.child_cluster_instance.is_none() =>
        {
            return Err(SandboxProvenanceError::IncompleteChildProvenance);
        }
        ResolvedSandboxPlacement::Management {} | ResolvedSandboxPlacement::ChildCluster { .. } => {
        }
    }
    Ok(target)
}

/// Merge progressively discovered target references without permitting any
/// existing identity to be changed or cleared. Equality covers API version,
/// kind, namespace, name, UID, and generation, so delete/recreate name reuse is
/// rejected even when the object name is unchanged.
pub fn merge_target_provenance(
    existing: Option<&SandboxTargetProvenance>,
    proposed: SandboxTargetProvenance,
    placement: &ResolvedSandboxPlacement,
    management_namespace: &str,
) -> Result<SandboxTargetProvenance, SandboxProvenanceError> {
    validate_resolved_placement(placement, management_namespace)?;
    validate_target_provenance(&proposed, placement, management_namespace)?;
    let Some(existing) = existing else {
        return Ok(proposed);
    };
    validate_target_provenance(existing, placement, management_namespace)?;
    if existing.namespace != proposed.namespace {
        return Err(SandboxProvenanceError::NamespaceChanged);
    }

    Ok(SandboxTargetProvenance {
        namespace: existing.namespace.clone(),
        child_cluster_lease: merge_reference(
            "childClusterLease",
            &existing.child_cluster_lease,
            proposed.child_cluster_lease,
        )?,
        child_cluster_instance: merge_reference(
            "childClusterInstance",
            &existing.child_cluster_instance,
            proposed.child_cluster_instance,
        )?,
        child_cluster_kubeconfig_secret: merge_reference(
            "childClusterKubeconfigSecret",
            &existing.child_cluster_kubeconfig_secret,
            proposed.child_cluster_kubeconfig_secret,
        )?,
        child_cluster_kubeconfig_sha256: merge_string(
            "childClusterKubeconfigSha256",
            &existing.child_cluster_kubeconfig_sha256,
            proposed.child_cluster_kubeconfig_sha256,
        )?,
        sandbox_template: merge_reference(
            "sandboxTemplate",
            &existing.sandbox_template,
            proposed.sandbox_template,
        )?,
        sandbox_warm_pool: merge_reference(
            "sandboxWarmPool",
            &existing.sandbox_warm_pool,
            proposed.sandbox_warm_pool,
        )?,
        sandbox_claim: merge_reference(
            "sandboxClaim",
            &existing.sandbox_claim,
            proposed.sandbox_claim,
        )?,
        sandbox: merge_reference("sandbox", &existing.sandbox, proposed.sandbox)?,
        pod: merge_reference("pod", &existing.pod, proposed.pod)?,
        service: merge_reference("service", &existing.service, proposed.service)?,
    })
}

fn validate_resolved_placement(
    placement: &ResolvedSandboxPlacement,
    management_namespace: &str,
) -> Result<(), SandboxProvenanceError> {
    if let ResolvedSandboxPlacement::ChildCluster { cluster_pool } = placement {
        validate_reference(
            "clusterPool",
            cluster_pool,
            KOBE_API_VERSION,
            "ClusterPool",
            Some(management_namespace),
            true,
        )?;
    }
    Ok(())
}

fn validate_target_provenance(
    provenance: &SandboxTargetProvenance,
    placement: &ResolvedSandboxPlacement,
    management_namespace: &str,
) -> Result<(), SandboxProvenanceError> {
    if provenance.namespace.trim().is_empty() {
        return Err(SandboxProvenanceError::InvalidReference {
            field: "namespace",
            reason: "target namespace is empty",
        });
    }

    match placement {
        ResolvedSandboxPlacement::Management {}
            if provenance.child_cluster_lease.is_some()
                || provenance.child_cluster_instance.is_some()
                || provenance.child_cluster_kubeconfig_secret.is_some()
                || provenance.child_cluster_kubeconfig_sha256.is_some() =>
        {
            return Err(SandboxProvenanceError::UnexpectedChildReference);
        }
        ResolvedSandboxPlacement::ChildCluster { .. }
            if provenance.namespace != CHILD_SANDBOX_NAMESPACE =>
        {
            return Err(SandboxProvenanceError::InvalidReference {
                field: "namespace",
                reason: "child target namespace does not match Kobe's fixed child namespace",
            });
        }
        ResolvedSandboxPlacement::Management {} | ResolvedSandboxPlacement::ChildCluster { .. } => {
        }
    }

    for (field, reference, api_version, kind, target_namespace, generation_required) in [
        (
            "childClusterLease",
            &provenance.child_cluster_lease,
            KOBE_API_VERSION,
            "ClusterLease",
            Some(management_namespace),
            true,
        ),
        (
            "childClusterInstance",
            &provenance.child_cluster_instance,
            KOBE_API_VERSION,
            "ClusterInstance",
            Some(management_namespace),
            true,
        ),
        (
            "childClusterKubeconfigSecret",
            &provenance.child_cluster_kubeconfig_secret,
            CORE_API_VERSION,
            "Secret",
            Some(management_namespace),
            false,
        ),
        (
            "sandboxTemplate",
            &provenance.sandbox_template,
            AGENT_SANDBOX_API_VERSION,
            SANDBOX_TEMPLATE_KIND,
            Some(provenance.namespace.as_str()),
            false,
        ),
        (
            "sandboxWarmPool",
            &provenance.sandbox_warm_pool,
            AGENT_SANDBOX_API_VERSION,
            SANDBOX_WARM_POOL_KIND,
            Some(provenance.namespace.as_str()),
            false,
        ),
        (
            "sandboxClaim",
            &provenance.sandbox_claim,
            AGENT_SANDBOX_API_VERSION,
            SANDBOX_CLAIM_KIND,
            Some(provenance.namespace.as_str()),
            false,
        ),
        (
            "sandbox",
            &provenance.sandbox,
            SANDBOX_API_VERSION,
            "Sandbox",
            Some(provenance.namespace.as_str()),
            false,
        ),
        (
            "pod",
            &provenance.pod,
            CORE_API_VERSION,
            "Pod",
            Some(provenance.namespace.as_str()),
            false,
        ),
        (
            "service",
            &provenance.service,
            CORE_API_VERSION,
            "Service",
            Some(provenance.namespace.as_str()),
            false,
        ),
    ] {
        if let Some(reference) = reference {
            validate_reference(
                field,
                reference,
                api_version,
                kind,
                target_namespace,
                generation_required,
            )?;
        }
    }
    match (
        provenance.child_cluster_kubeconfig_secret.as_ref(),
        provenance.child_cluster_kubeconfig_sha256.as_deref(),
    ) {
        (Some(secret), Some(digest)) => {
            let Some(instance) = provenance.child_cluster_instance.as_ref() else {
                return Err(SandboxProvenanceError::InvalidReference {
                    field: "childClusterKubeconfigSecret",
                    reason: "credential Secret requires a recorded child instance",
                });
            };
            if secret.name != format!("{}-kubeconfig", instance.name)
                || secret.namespace != instance.namespace
                || secret.generation.is_some()
            {
                return Err(SandboxProvenanceError::InvalidReference {
                    field: "childClusterKubeconfigSecret",
                    reason: "credential Secret does not match the recorded child instance",
                });
            }
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(SandboxProvenanceError::InvalidReference {
                    field: "childClusterKubeconfigSha256",
                    reason: "credential payload digest is not lowercase SHA-256",
                });
            }
        }
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            return Err(SandboxProvenanceError::InvalidReference {
                field: "childClusterKubeconfigSecret",
                reason: "credential Secret identity and payload digest must be recorded together",
            });
        }
    }
    Ok(())
}

fn validate_reference(
    field: &'static str,
    reference: &SandboxObjectReference,
    expected_api_version: &str,
    expected_kind: &str,
    expected_namespace: Option<&str>,
    generation_required: bool,
) -> Result<(), SandboxProvenanceError> {
    if reference.api_version != expected_api_version || reference.kind != expected_kind {
        return Err(SandboxProvenanceError::InvalidReference {
            field,
            reason: "unexpected API version or kind",
        });
    }
    if reference.name.trim().is_empty() || reference.uid.trim().is_empty() {
        return Err(SandboxProvenanceError::InvalidReference {
            field,
            reason: "name and UID are required",
        });
    }
    let namespace = reference
        .namespace
        .as_deref()
        .filter(|value| !value.is_empty());
    if namespace.is_none() {
        return Err(SandboxProvenanceError::InvalidReference {
            field,
            reason: "namespace is required",
        });
    }
    if expected_namespace.is_some_and(|expected| namespace != Some(expected)) {
        return Err(SandboxProvenanceError::InvalidReference {
            field,
            reason: "namespace does not match the target namespace",
        });
    }
    if generation_required
        && reference
            .generation
            .is_none_or(|generation| generation <= 0)
    {
        return Err(SandboxProvenanceError::InvalidReference {
            field,
            reason: "positive generation is required",
        });
    }
    Ok(())
}

fn merge_reference(
    field: &'static str,
    existing: &Option<SandboxObjectReference>,
    proposed: Option<SandboxObjectReference>,
) -> Result<Option<SandboxObjectReference>, SandboxProvenanceError> {
    match (existing, proposed) {
        (None, proposed) => Ok(proposed),
        (Some(_), None) => Err(SandboxProvenanceError::ReferenceCleared(field)),
        (Some(current), Some(proposed)) if current == &proposed => Ok(Some(current.clone())),
        (Some(_), Some(_)) => Err(SandboxProvenanceError::ReferenceChanged(field)),
    }
}

fn merge_string(
    field: &'static str,
    existing: &Option<String>,
    proposed: Option<String>,
) -> Result<Option<String>, SandboxProvenanceError> {
    match (existing, proposed) {
        (None, proposed) => Ok(proposed),
        (Some(_), None) => Err(SandboxProvenanceError::ReferenceCleared(field)),
        (Some(current), Some(proposed)) if current == &proposed => Ok(Some(current.clone())),
        (Some(_), Some(_)) => Err(SandboxProvenanceError::ReferenceChanged(field)),
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SandboxProvenanceError {
    #[error("Sandbox placement has not been resolved; no backend fallback is permitted")]
    UnresolvedPlacement,
    #[error("resolved Sandbox placement cannot change")]
    PlacementChanged,
    #[error("target namespace cannot change")]
    NamespaceChanged,
    #[error("target provenance field {0} cannot be cleared")]
    ReferenceCleared(&'static str),
    #[error("target provenance field {0} cannot change")]
    ReferenceChanged(&'static str),
    #[error("invalid target provenance field {field}: {reason}")]
    InvalidReference {
        field: &'static str,
        reason: &'static str,
    },
    #[error("management placement cannot record child-cluster references")]
    UnexpectedChildReference,
    #[error("resolved Sandbox placement has no target provenance")]
    MissingTargetProvenance,
    #[error("childCluster placement requires exact lease and instance provenance")]
    IncompleteChildProvenance,
}

/// Compute the absolute setup bound from the API-server creation timestamp.
///
/// Admission and reconciliation share this helper so neither can reset the
/// clock after queueing, controller downtime, or a missing pool.
pub fn sandbox_provisioning_deadline(
    accepted_at: DateTime<Utc>,
    provisioning_timeout: chrono::Duration,
) -> Result<String, SandboxLifecycleError> {
    if provisioning_timeout <= chrono::Duration::zero() {
        return Err(SandboxLifecycleError::InvalidDuration(
            "provisioning timeout",
        ));
    }
    let deadline = accepted_at
        .checked_add_signed(provisioning_timeout)
        .ok_or(SandboxLifecycleError::TimestampOverflow)?;
    Ok(deadline.to_rfc3339_opts(SecondsFormat::AutoSi, true))
}

/// Start bounded provisioning from the lease creation timestamp. Retrying with
/// the same inputs is idempotent; changing an already-persisted deadline fails.
pub fn begin_sandbox_provisioning(
    status: &SandboxLeaseStatus,
    observed_generation: i64,
    accepted_at: DateTime<Utc>,
    provisioning_timeout: chrono::Duration,
) -> Result<SandboxLeaseStatus, SandboxLifecycleError> {
    let deadline = sandbox_provisioning_deadline(accepted_at, provisioning_timeout)?;

    if status
        .provisioning_deadline
        .as_deref()
        .is_some_and(|persisted| persisted != deadline)
    {
        return Err(SandboxLifecycleError::PersistedTimestampChanged(
            "provisioningDeadline",
        ));
    }

    if status.phase == SandboxLeasePhase::Provisioning {
        if status.provisioning_deadline.as_deref() == Some(deadline.as_str())
            && status.observed_generation == Some(observed_generation)
        {
            return Ok(status.clone());
        }
        return Err(SandboxLifecycleError::PersistedTimestampChanged(
            "provisioningDeadline",
        ));
    }
    transition_sandbox_phase(status.phase, SandboxLeasePhase::Provisioning, false)?;

    let mut next = status.clone();
    next.phase = SandboxLeasePhase::Provisioning;
    next.observed_generation = Some(observed_generation);
    next.provisioning_deadline = Some(deadline);
    Ok(next)
}

/// Mark an upstream Sandbox Ready and start runtime TTL from that exact instant.
/// Readiness after the persisted provisioning deadline fails closed.
pub fn mark_sandbox_ready(
    status: &SandboxLeaseStatus,
    observed_generation: i64,
    ready_at: DateTime<Utc>,
    runtime_ttl: chrono::Duration,
) -> Result<SandboxLeaseStatus, SandboxLifecycleError> {
    if runtime_ttl <= chrono::Duration::zero() {
        return Err(SandboxLifecycleError::InvalidDuration("runtime TTL"));
    }
    let deadline = status
        .provisioning_deadline
        .as_deref()
        .ok_or(SandboxLifecycleError::MissingProvisioningDeadline)
        .and_then(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|_| SandboxLifecycleError::MalformedProvisioningDeadline)
        })?;
    if ready_at > deadline {
        return Err(SandboxLifecycleError::ProvisioningDeadlineElapsed);
    }
    let ready_at_string = ready_at.to_rfc3339_opts(SecondsFormat::AutoSi, true);
    // One derivation, one writer. Granted extensions are an INPUT here rather
    // than a competing write of `expiresAt`, so this stays idempotent across
    // requeues and the caller's extension reaches the upstream backstop the
    // controller stamps from the value returned below.
    let granted = chrono::Duration::try_seconds(status.granted_extension_seconds)
        .ok_or(SandboxLifecycleError::TimestampOverflow)?;
    if granted < chrono::Duration::zero() {
        return Err(SandboxLifecycleError::InvalidDuration("granted extension"));
    }
    let expires_at = ready_at
        .checked_add_signed(runtime_ttl)
        .and_then(|value| value.checked_add_signed(granted))
        .ok_or(SandboxLifecycleError::TimestampOverflow)?
        .to_rfc3339_opts(SecondsFormat::AutoSi, true);

    if status.phase == SandboxLeasePhase::Ready {
        if status.ready_at.as_deref() == Some(ready_at_string.as_str())
            && status.expires_at.as_deref() == Some(expires_at.as_str())
            && status.observed_generation == Some(observed_generation)
        {
            return Ok(status.clone());
        }
        return Err(SandboxLifecycleError::PersistedTimestampChanged(
            "readyAt/expiresAt",
        ));
    }
    transition_sandbox_phase(status.phase, SandboxLeasePhase::Ready, false)?;

    let mut next = status.clone();
    next.phase = SandboxLeasePhase::Ready;
    next.observed_generation = Some(observed_generation);
    next.ready_at = Some(ready_at_string);
    next.expires_at = Some(expires_at);
    Ok(next)
}

/// Validate a lifecycle phase transition. Clean terminal states always require
/// verified cleanup; in particular, Quarantined can never look clean merely
/// because a controller retried or restarted.
pub fn transition_sandbox_phase(
    current: SandboxLeasePhase,
    next: SandboxLeasePhase,
    cleanup_verified: bool,
) -> Result<SandboxLeasePhase, SandboxLifecycleError> {
    if current == next {
        return Ok(current);
    }
    if matches!(
        next,
        SandboxLeasePhase::Released | SandboxLeasePhase::Expired
    ) && !cleanup_verified
    {
        return Err(SandboxLifecycleError::CleanupProofRequired);
    }

    let allowed = matches!(
        (current, next),
        (SandboxLeasePhase::Pending, SandboxLeasePhase::Provisioning)
            | (SandboxLeasePhase::Pending, SandboxLeasePhase::Releasing)
            | (SandboxLeasePhase::Pending, SandboxLeasePhase::Quarantined)
            | (SandboxLeasePhase::Provisioning, SandboxLeasePhase::Ready)
            | (
                SandboxLeasePhase::Provisioning,
                SandboxLeasePhase::Releasing
            )
            | (
                SandboxLeasePhase::Provisioning,
                SandboxLeasePhase::Quarantined
            )
            | (SandboxLeasePhase::Ready, SandboxLeasePhase::Releasing)
            | (SandboxLeasePhase::Ready, SandboxLeasePhase::Quarantined)
            | (SandboxLeasePhase::Releasing, SandboxLeasePhase::Released)
            | (SandboxLeasePhase::Releasing, SandboxLeasePhase::Expired)
            | (SandboxLeasePhase::Releasing, SandboxLeasePhase::Quarantined)
            // Quarantine is a retryable evidence hold, not an operator-only
            // tomb. A retry may resume teardown, but quota still cannot move
            // until the ordinary cleanup proof gate succeeds.
            | (SandboxLeasePhase::Quarantined, SandboxLeasePhase::Releasing)
    );
    if allowed {
        Ok(next)
    } else {
        Err(SandboxLifecycleError::InvalidTransition { current, next })
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SandboxLifecycleError {
    #[error("{0} must be positive")]
    InvalidDuration(&'static str),
    #[error("timestamp overflow")]
    TimestampOverflow,
    #[error("provisioningDeadline is required before readiness")]
    MissingProvisioningDeadline,
    #[error("provisioningDeadline is malformed")]
    MalformedProvisioningDeadline,
    #[error("Sandbox became Ready after its provisioning deadline")]
    ProvisioningDeadlineElapsed,
    #[error("persisted {0} cannot change")]
    PersistedTimestampChanged(&'static str),
    #[error("cleanup proof is required for a clean terminal phase")]
    CleanupProofRequired,
    #[error("invalid Sandbox lifecycle transition {current} -> {next}")]
    InvalidTransition {
        current: SandboxLeasePhase,
        next: SandboxLeasePhase,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        SandboxCondition, SandboxContainerResources, SandboxContainerSpec, SandboxExecutionCanary,
        SandboxIsolation, SandboxPlacement, SandboxPoolStatus, SandboxPortSpec,
        SandboxReadinessRequirements, SandboxResourceQuantity,
    };

    fn quantity(cpu: &str, memory: &str, ephemeral_storage: &str) -> SandboxResourceQuantity {
        SandboxResourceQuantity {
            cpu: cpu.into(),
            memory: memory.into(),
            ephemeral_storage: ephemeral_storage.into(),
        }
    }

    fn pool() -> SandboxPoolSpec {
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
                    args: vec!["serve".into()],
                    resources: SandboxContainerResources {
                        requests: quantity("500m", "512Mi", "256Mi"),
                        limits: quantity("1", "1Gi", "2Gi"),
                    },
                }],
                exposed_ports: vec![SandboxPortSpec {
                    name: "http".into(),
                    container: "agent".into(),
                    port: 3000,
                }],
                runner_path: None,
                attach_command: None,
            },
            isolation: SandboxIsolation::Gvisor {
                runtime_class_name: "runsc".into(),
            },
            readiness: SandboxReadinessRequirements {
                canary: SandboxExecutionCanary {
                    argv: vec!["/agent".into(), "health".into()],
                    timeout: "30s".into(),
                },
            },
        }
    }

    fn owner() -> OwnerReference {
        OwnerReference {
            api_version: "kobe.kunobi.ninja/v1alpha1".into(),
            kind: "SandboxPool".into(),
            name: "agents".into(),
            uid: "pool-uid".into(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }
    }

    fn pool_resource(status: Option<SandboxPoolStatus>) -> SandboxPool {
        SandboxPool {
            metadata: ObjectMeta {
                name: Some("agents".into()),
                namespace: Some("kobe".into()),
                uid: Some("pool-uid".into()),
                generation: Some(3),
                ..Default::default()
            },
            spec: pool(),
            status,
        }
    }

    fn ready_condition(
        status: SandboxConditionStatus,
        observed_generation: Option<i64>,
    ) -> SandboxCondition {
        SandboxCondition {
            condition_type: "Ready".into(),
            status,
            reason: "Certified".into(),
            message: "all required certification gates passed".into(),
            observed_generation,
            last_transition_time: Some("2026-08-20T00:00:00Z".into()),
        }
    }

    fn pool_certification(generation: i64) -> crate::crd::SandboxPoolCertificationStatus {
        let object = |kind: &str, uid: &str| SandboxObjectReference {
            api_version: if matches!(kind, "Pod" | "ConfigMap") {
                "v1".into()
            } else if kind == "Sandbox" {
                "agents.x-k8s.io/v1beta1".into()
            } else {
                AGENT_SANDBOX_API_VERSION.into()
            },
            kind: kind.into(),
            namespace: Some("targets".into()),
            name: format!("cert-{}", kind.to_ascii_lowercase()),
            uid: uid.into(),
            generation: Some(1),
        };
        crate::crd::SandboxPoolCertificationStatus {
            fingerprint: "a".repeat(64),
            observed_generation: generation,
            phase: crate::crd::SandboxPoolCertificationPhase::Certified,
            sandbox_template: object("SandboxTemplate", "template-uid"),
            sandbox_warm_pool: object("SandboxWarmPool", "warm-pool-uid"),
            sandbox_claim: Some(object("SandboxClaim", "claim-uid")),
            sandbox: Some(object("Sandbox", "sandbox-uid")),
            pod: Some(object("Pod", "pod-uid")),
            service: None,
            persistent_volume_claims: vec![],
            persistent_volumes: vec![],
            teardown_fence: Some(object("ConfigMap", "fence-uid")),
            baseline_idle_sandbox_uids: vec![],
            drain_generation: Some(2),
            replenish_generation: Some(3),
            canary_passed_at: Some("2026-08-20T00:00:00Z".into()),
            certified_at: Some("2026-08-20T00:01:00Z".into()),
            message: None,
        }
    }

    /// Admission authority comes only from a current-generation Ready=True
    /// certificate; capacity counts and stale conditions cannot substitute.
    #[test]
    fn sandbox_pool_readiness_certificate_fails_closed() {
        let certified = pool_resource(Some(SandboxPoolStatus {
            observed_generation: Some(3),
            ready: 2,
            allocated: 1,
            quarantined: 0,
            placement: None,
            placement_authority: None,
            certification: Some(pool_certification(3)),
            conditions: vec![ready_condition(SandboxConditionStatus::True, Some(3))],
        }));
        assert_eq!(require_current_sandbox_pool_ready(&certified), Ok(()));

        let mut receiptless = certified.clone();
        receiptless.status.as_mut().unwrap().certification = None;
        assert_eq!(
            require_current_sandbox_pool_ready(&receiptless),
            Err(SandboxPoolReadinessError::MissingCertification)
        );

        let mut stale_receipt = certified.clone();
        stale_receipt
            .status
            .as_mut()
            .unwrap()
            .certification
            .as_mut()
            .unwrap()
            .observed_generation = 2;
        assert!(matches!(
            require_current_sandbox_pool_ready(&stale_receipt),
            Err(SandboxPoolReadinessError::StaleCertification { .. })
        ));

        let missing_status = pool_resource(None);
        assert_eq!(
            require_current_sandbox_pool_ready(&missing_status),
            Err(SandboxPoolReadinessError::MissingStatus)
        );

        let mut stale_status = certified.clone();
        stale_status.status.as_mut().unwrap().observed_generation = Some(2);
        assert!(matches!(
            require_current_sandbox_pool_ready(&stale_status),
            Err(SandboxPoolReadinessError::StaleStatus { .. })
        ));

        let mut missing_condition = certified.clone();
        missing_condition
            .status
            .as_mut()
            .unwrap()
            .conditions
            .clear();
        assert_eq!(
            require_current_sandbox_pool_ready(&missing_condition),
            Err(SandboxPoolReadinessError::MissingReadyCondition)
        );

        for status in [
            SandboxConditionStatus::False,
            SandboxConditionStatus::Unknown,
        ] {
            let mut not_ready = certified.clone();
            not_ready.status.as_mut().unwrap().conditions = vec![ready_condition(status, Some(3))];
            assert!(matches!(
                require_current_sandbox_pool_ready(&not_ready),
                Err(SandboxPoolReadinessError::NotReady { .. })
            ));
        }

        let mut stale_condition = certified.clone();
        stale_condition.status.as_mut().unwrap().conditions =
            vec![ready_condition(SandboxConditionStatus::True, Some(2))];
        assert!(matches!(
            require_current_sandbox_pool_ready(&stale_condition),
            Err(SandboxPoolReadinessError::StaleReadyCondition { .. })
        ));

        let mut duplicate = certified;
        duplicate
            .status
            .as_mut()
            .unwrap()
            .conditions
            .push(ready_condition(SandboxConditionStatus::True, Some(3)));
        assert_eq!(
            require_current_sandbox_pool_ready(&duplicate),
            Err(SandboxPoolReadinessError::DuplicateReadyCondition)
        );
    }

    #[test]
    fn child_allocation_certificate_is_exact_current_and_not_runtime_readiness() {
        let mut child = pool_resource(Some(SandboxPoolStatus {
            observed_generation: Some(3),
            ready: 0,
            allocated: 0,
            quarantined: 0,
            placement: Some(SandboxPlacement::ChildCluster {
                cluster_pool_ref: "children".into(),
            }),
            placement_authority: Some(crate::crd::SandboxPlacementAuthority {
                api_version: KOBE_API_VERSION.into(),
                kind: "ClusterPool".into(),
                namespace: "kobe".into(),
                name: "children".into(),
                uid: "children-uid".into(),
                generation: 7,
            }),
            certification: None,
            conditions: vec![SandboxCondition {
                condition_type: "Ready".into(),
                status: SandboxConditionStatus::False,
                reason: "CompositionEligible".into(),
                message: "runtime canary still required".into(),
                observed_generation: Some(3),
                last_transition_time: None,
            }],
        }));
        child.spec.placement = SandboxPlacement::ChildCluster {
            cluster_pool_ref: "children".into(),
        };

        let authority = current_child_pool_allocation_authority(&child)
            .expect("current child allocation authority");
        assert_eq!(authority.uid, "children-uid");
        assert!(require_current_sandbox_pool_ready(&child).is_err());

        let mut stale = child.clone();
        stale.status.as_mut().unwrap().observed_generation = Some(2);
        assert!(current_child_pool_allocation_authority(&stale).is_none());

        let mut duplicate = child;
        let condition = duplicate.status.as_ref().unwrap().conditions[0].clone();
        duplicate
            .status
            .as_mut()
            .unwrap()
            .conditions
            .push(condition);
        assert!(current_child_pool_allocation_authority(&duplicate).is_none());
    }

    fn reference(kind: &str, name: &str, uid: &str) -> SandboxObjectReference {
        SandboxObjectReference {
            api_version: AGENT_SANDBOX_API_VERSION.into(),
            kind: kind.into(),
            namespace: Some("targets".into()),
            name: name.into(),
            uid: uid.into(),
            generation: Some(1),
        }
    }

    fn cluster_pool_reference(namespace: &str) -> SandboxObjectReference {
        SandboxObjectReference {
            api_version: KOBE_API_VERSION.into(),
            kind: "ClusterPool".into(),
            namespace: Some(namespace.into()),
            name: "ci".into(),
            uid: "pool-uid".into(),
            generation: Some(1),
        }
    }

    fn provenance(claim: Option<SandboxObjectReference>) -> SandboxTargetProvenance {
        SandboxTargetProvenance {
            namespace: "targets".into(),
            child_cluster_lease: None,
            child_cluster_instance: None,
            child_cluster_kubeconfig_secret: None,
            child_cluster_kubeconfig_sha256: None,
            sandbox_template: Some(reference("SandboxTemplate", "agents", "template-uid")),
            sandbox_warm_pool: None,
            sandbox_claim: claim,
            sandbox: None,
            pod: None,
            service: None,
        }
    }

    #[test]
    fn template_projection_is_v1beta1_and_closed() {
        let object = build_sandbox_template("agents", "targets", &pool(), Some(&owner())).unwrap();
        let value = serde_json::to_value(object).unwrap();

        assert_eq!(value["apiVersion"], AGENT_SANDBOX_API_VERSION);
        assert_eq!(value["kind"], SANDBOX_TEMPLATE_KIND);
        assert_eq!(value["metadata"]["ownerReferences"][0]["uid"], "pool-uid");
        assert_eq!(
            value["spec"]["podTemplate"]["spec"]["runtimeClassName"],
            "runsc"
        );
        assert_eq!(
            value["spec"]["podTemplate"]["spec"]["automountServiceAccountToken"],
            false
        );
        assert_eq!(
            value["spec"]["podTemplate"]["spec"]["enableServiceLinks"],
            false
        );
        assert_eq!(
            value["spec"]["podTemplate"]["spec"]["securityContext"]["runAsUser"],
            65_532
        );
        assert_eq!(
            value["spec"]["podTemplate"]["spec"]["securityContext"]["runAsGroup"],
            65_532
        );
        assert_eq!(
            value["spec"]["podTemplate"]["spec"]["securityContext"]["runAsNonRoot"],
            true
        );
        assert_eq!(
            value["spec"]["podTemplate"]["spec"]["securityContext"]["seccompProfile"]["type"],
            "RuntimeDefault"
        );
        assert_eq!(
            value["spec"]["podTemplate"]["spec"]["containers"][0]["securityContext"]["allowPrivilegeEscalation"],
            false
        );
        assert_eq!(
            value["spec"]["podTemplate"]["spec"]["containers"][0]["securityContext"]["capabilities"]
                ["drop"],
            serde_json::json!(["ALL"])
        );
        assert_eq!(value["spec"]["envVarsInjectionPolicy"], "Disallowed");
        assert_eq!(value["spec"]["volumeClaimTemplatesPolicy"], "Disallowed");
        assert_eq!(
            value["spec"]["podTemplate"]["spec"]["containers"][0]["resources"]["limits"]["ephemeral-storage"],
            "2Gi"
        );
        assert!(value["spec"].get("volumeClaimTemplates").is_none());
        assert!(
            value["spec"]["podTemplate"]["spec"]["containers"][0]
                .get("env")
                .is_none()
        );
        assert!(
            value["spec"]["podTemplate"]["spec"]
                .get("volumes")
                .is_none()
        );
    }

    #[test]
    fn warm_pool_projection_uses_exact_template_reference() {
        let value = serde_json::to_value(
            build_sandbox_warm_pool("agents", "targets", "agents-template", 3, None).unwrap(),
        )
        .unwrap();
        assert_eq!(value["apiVersion"], AGENT_SANDBOX_API_VERSION);
        assert_eq!(value["kind"], SANDBOX_WARM_POOL_KIND);
        assert_eq!(value["spec"]["replicas"], 3);
        assert_eq!(
            value["spec"]["sandboxTemplateRef"]["name"],
            "agents-template"
        );
    }

    #[test]
    fn claim_projection_bounds_provisioning_then_starts_runtime_ttl_at_ready() {
        let provisioning_deadline = DateTime::parse_from_rfc3339("2026-08-10T10:10:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let expires_at = DateTime::parse_from_rfc3339("2026-08-10T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        let value = serde_json::to_value(build_sandbox_claim(
            "claim-a",
            "targets",
            "agents",
            "lease-uid-a",
            provisioning_deadline,
            true,
            None,
        ))
        .unwrap();

        assert_eq!(value["apiVersion"], AGENT_SANDBOX_API_VERSION);
        assert_eq!(value["kind"], SANDBOX_CLAIM_KIND);
        assert_eq!(value["spec"]["warmPoolRef"]["name"], "agents");
        assert_eq!(
            value["metadata"]["labels"][SANDBOX_LEASE_UID_LABEL],
            "lease-uid-a"
        );
        assert!(
            value["metadata"].get("ownerReferences").is_none(),
            "a management claim must survive outer-lease GC until explicit proof"
        );
        assert_eq!(
            value["metadata"]["finalizers"],
            serde_json::json!([SANDBOX_CLAIM_CLEANUP_FINALIZER]),
            "a management claim must not disappear before its UID checkpoint"
        );
        assert_eq!(
            value["spec"]["lifecycle"]["shutdownTime"],
            "2026-08-10T10:10:00Z"
        );
        assert_eq!(
            value["spec"]["lifecycle"]["shutdownPolicy"],
            "DeleteForeground"
        );

        let patch = build_sandbox_claim_lifecycle_patch("claim-rv", expires_at).unwrap();
        assert_eq!(patch["metadata"]["resourceVersion"], "claim-rv");
        assert_eq!(
            patch["spec"]["lifecycle"]["shutdownTime"],
            "2026-08-10T12:34:56Z"
        );
        assert_eq!(
            patch["spec"]["lifecycle"]["shutdownPolicy"],
            "DeleteForeground"
        );
        assert!(build_sandbox_claim_lifecycle_patch(" ", expires_at).is_err());
        for forbidden in [
            "env",
            "volumeClaimTemplates",
            "additionalPodMetadata",
            "namespace",
            "credentials",
        ] {
            assert!(value["spec"].get(forbidden).is_none(), "found {forbidden}");
        }
    }

    /// A child claim may remain owned by its same-cluster Namespace. That
    /// owner cannot race deletion of the outer management-cluster lease.
    #[test]
    fn child_claim_can_be_owned_by_its_remote_namespace() {
        let owner = OwnerReference {
            api_version: "v1".into(),
            kind: "Namespace".into(),
            name: "kobe-sandbox".into(),
            uid: "namespace-uid".into(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        };
        let value = serde_json::to_value(build_sandbox_claim(
            "claim-a",
            "targets",
            "agents",
            "lease-uid-a",
            DateTime::parse_from_rfc3339("2026-08-10T10:10:00Z")
                .unwrap()
                .with_timezone(&Utc),
            false,
            Some(&owner),
        ))
        .unwrap();

        assert_eq!(value["metadata"]["ownerReferences"][0]["kind"], "Namespace");
        assert_eq!(
            value["metadata"]["ownerReferences"][0]["uid"],
            "namespace-uid"
        );
        assert!(
            value["metadata"].get("finalizers").is_none(),
            "the remote Namespace already owns child-Claim cleanup"
        );
    }

    #[test]
    fn aggregate_resources_are_unit_independent_and_ceiling_bounded() {
        let totals = aggregate_resource_limits(&pool().template).unwrap();
        assert_eq!(totals.cpu_millicores, 1000);
        assert_eq!(totals.memory_bytes, 1024 * 1024 * 1024);
        assert!(
            resource_ceiling_allows(
                &SandboxResourceCeiling {
                    max_cpu: "1000m".into(),
                    max_memory: "1024Mi".into(),
                },
                &totals,
            )
            .unwrap()
        );
        assert!(
            !resource_ceiling_allows(
                &SandboxResourceCeiling {
                    max_cpu: "999m".into(),
                    max_memory: "2Gi".into(),
                },
                &totals,
            )
            .unwrap()
        );
    }

    #[test]
    fn quantity_parser_rejects_sub_millicore_cpu_and_whitespace() {
        assert_eq!(parse_quantity("100u", QuantityDimension::Cpu), None);
        assert_eq!(parse_quantity("1m", QuantityDimension::Cpu), Some(1));
        assert_eq!(
            parse_quantity("1n", QuantityDimension::Bytes),
            Some(1),
            "positive sub-byte quantities round up to one byte"
        );
        assert_eq!(parse_quantity(" 1", QuantityDimension::Bytes), None);
        assert_eq!(parse_quantity("1 ", QuantityDimension::Bytes), None);
    }

    #[test]
    fn invalid_or_inverted_resource_quantities_fail_closed() {
        let mut template = pool().template;
        template.containers[0].resources.requests.cpu = "2".into();
        assert!(matches!(
            aggregate_resource_limits(&template),
            Err(SandboxResourceError::RequestExceedsLimit {
                resource: "cpu",
                ..
            })
        ));

        assert!(
            parse_resource_ceiling(&SandboxResourceCeiling {
                max_cpu: "NaN".into(),
                max_memory: "4Gi".into(),
            })
            .is_err()
        );

        let mut inverted_memory = pool().template;
        inverted_memory.containers[0].resources.requests.memory = "900m".into();
        inverted_memory.containers[0].resources.limits.memory = "100m".into();
        assert!(matches!(
            aggregate_resource_limits(&inverted_memory),
            Err(SandboxResourceError::RequestExceedsLimit {
                resource: "memory",
                ..
            })
        ));

        let mut fine_cpu = pool().template;
        fine_cpu.containers[0].resources.requests.cpu = "100u".into();
        assert!(matches!(
            aggregate_resource_limits(&fine_cpu),
            Err(SandboxResourceError::InvalidQuantity {
                field: "requests.cpu",
                ..
            })
        ));
    }

    #[test]
    fn fractional_memory_is_compared_exactly_across_containers_and_policy() {
        let mut template = pool().template;
        let mut first = template.containers[0].clone();
        first.name = "first".into();
        first.resources.requests.cpu = "1m".into();
        first.resources.limits.cpu = "1m".into();
        first.resources.requests.memory = "100m".into();
        first.resources.limits.memory = "450m".into();
        let mut second = first.clone();
        second.name = "second".into();
        template.containers = vec![first, second];

        let totals = aggregate_resource_limits(&template).unwrap();
        assert_eq!(
            totals.memory_bytes, 1,
            "reporting rounds only after summing"
        );
        assert!(
            !resource_ceiling_allows(
                &SandboxResourceCeiling {
                    max_cpu: "2m".into(),
                    max_memory: "100m".into(),
                },
                &totals,
            )
            .unwrap(),
            "900m bytes must not fit beneath a 100m-byte ceiling"
        );
        assert!(
            resource_ceiling_allows(
                &SandboxResourceCeiling {
                    max_cpu: "2m".into(),
                    max_memory: "900m".into(),
                },
                &totals,
            )
            .unwrap()
        );
    }

    #[test]
    fn placement_has_no_default_and_cannot_change() {
        let status = SandboxLeaseStatus::default();
        assert_eq!(
            require_resolved_placement(&status, "kobe"),
            Err(SandboxProvenanceError::UnresolvedPlacement)
        );

        let placement = ResolvedSandboxPlacement::Management {};
        assert_eq!(
            record_placement_once(None, placement.clone(), "kobe"),
            Ok(placement.clone())
        );
        assert_eq!(
            record_placement_once(Some(&placement), placement.clone(), "kobe"),
            Ok(placement)
        );
        assert_eq!(
            record_placement_once(
                Some(&ResolvedSandboxPlacement::Management {}),
                ResolvedSandboxPlacement::ChildCluster {
                    cluster_pool: cluster_pool_reference("kobe"),
                },
                "kobe",
            ),
            Err(SandboxProvenanceError::PlacementChanged)
        );

        let wrong_namespace = ResolvedSandboxPlacement::ChildCluster {
            cluster_pool: cluster_pool_reference("other"),
        };
        assert!(matches!(
            record_placement_once(None, wrong_namespace, "kobe"),
            Err(SandboxProvenanceError::InvalidReference {
                field: "clusterPool",
                ..
            })
        ));
    }

    #[test]
    fn provenance_only_allows_monotonic_exact_enrichment() {
        let existing = provenance(None);
        let enriched = provenance(Some(reference("SandboxClaim", "lease-a", "claim-uid")));
        let placement = ResolvedSandboxPlacement::Management {};
        assert_eq!(
            merge_target_provenance(Some(&existing), enriched.clone(), &placement, "kobe"),
            Ok(enriched.clone())
        );

        let mut name_reused = enriched.clone();
        name_reused.sandbox_claim.as_mut().unwrap().uid = "replacement-uid".into();
        assert_eq!(
            merge_target_provenance(Some(&enriched), name_reused, &placement, "kobe"),
            Err(SandboxProvenanceError::ReferenceChanged("sandboxClaim"))
        );

        let mut cleared = enriched.clone();
        cleared.sandbox_claim = None;
        assert_eq!(
            merge_target_provenance(Some(&enriched), cleared, &placement, "kobe"),
            Err(SandboxProvenanceError::ReferenceCleared("sandboxClaim"))
        );

        let mut with_service = enriched.clone();
        with_service.service = Some(SandboxObjectReference {
            api_version: CORE_API_VERSION.into(),
            kind: "Service".into(),
            namespace: Some("targets".into()),
            name: "sandbox-service".into(),
            uid: "service-uid".into(),
            generation: None,
        });
        assert_eq!(
            merge_target_provenance(Some(&enriched), with_service.clone(), &placement, "kobe"),
            Ok(with_service.clone())
        );
        let mut reused_service = with_service.clone();
        reused_service.service.as_mut().unwrap().uid = "replacement-service-uid".into();
        assert_eq!(
            merge_target_provenance(Some(&with_service), reused_service, &placement, "kobe"),
            Err(SandboxProvenanceError::ReferenceChanged("service"))
        );

        let mut moved = enriched.clone();
        moved.namespace = "other".into();
        assert_eq!(
            merge_target_provenance(Some(&enriched), moved, &placement, "kobe"),
            Err(SandboxProvenanceError::InvalidReference {
                field: "sandboxTemplate",
                reason: "namespace does not match the target namespace",
            })
        );

        let mut wrong_gvk = enriched.clone();
        wrong_gvk.sandbox_claim.as_mut().unwrap().kind = "Secret".into();
        assert!(matches!(
            merge_target_provenance(None, wrong_gvk, &placement, "kobe"),
            Err(SandboxProvenanceError::InvalidReference {
                field: "sandboxClaim",
                ..
            })
        ));
    }

    #[test]
    fn child_kubeconfig_uid_and_payload_digest_are_one_monotonic_checkpoint() {
        let placement = ResolvedSandboxPlacement::ChildCluster {
            cluster_pool: cluster_pool_reference("kobe"),
        };
        let instance = SandboxObjectReference {
            api_version: KOBE_API_VERSION.into(),
            kind: "ClusterInstance".into(),
            namespace: Some("kobe".into()),
            name: "kobe-child".into(),
            uid: "instance-uid".into(),
            generation: Some(1),
        };
        let mut target = SandboxTargetProvenance {
            namespace: CHILD_SANDBOX_NAMESPACE.into(),
            child_cluster_lease: None,
            child_cluster_instance: Some(instance),
            child_cluster_kubeconfig_secret: Some(SandboxObjectReference {
                api_version: CORE_API_VERSION.into(),
                kind: "Secret".into(),
                namespace: Some("kobe".into()),
                name: "kobe-child-kubeconfig".into(),
                uid: "secret-uid".into(),
                generation: None,
            }),
            child_cluster_kubeconfig_sha256: Some("a".repeat(64)),
            sandbox_template: None,
            sandbox_warm_pool: None,
            sandbox_claim: None,
            sandbox: None,
            pod: None,
            service: None,
        };
        assert_eq!(
            merge_target_provenance(Some(&target), target.clone(), &placement, "kobe"),
            Ok(target.clone())
        );

        let mut changed = target.clone();
        changed.child_cluster_kubeconfig_sha256 = Some("b".repeat(64));
        assert_eq!(
            merge_target_provenance(Some(&target), changed, &placement, "kobe"),
            Err(SandboxProvenanceError::ReferenceChanged(
                "childClusterKubeconfigSha256"
            ))
        );

        let mut noncanonical = target.clone();
        noncanonical
            .child_cluster_kubeconfig_secret
            .as_mut()
            .unwrap()
            .generation = Some(1);
        assert!(matches!(
            merge_target_provenance(None, noncanonical, &placement, "kobe"),
            Err(SandboxProvenanceError::InvalidReference {
                field: "childClusterKubeconfigSecret",
                ..
            })
        ));

        target.child_cluster_kubeconfig_sha256 = None;
        assert!(matches!(
            merge_target_provenance(None, target, &placement, "kobe"),
            Err(SandboxProvenanceError::InvalidReference {
                field: "childClusterKubeconfigSecret",
                ..
            })
        ));
    }

    #[test]
    fn lifecycle_starts_ttl_at_ready_and_requires_cleanup_proof() {
        let accepted_at = DateTime::parse_from_rfc3339("2026-08-10T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let ready_at = DateTime::parse_from_rfc3339("2026-08-10T10:03:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let provisioning = begin_sandbox_provisioning(
            &SandboxLeaseStatus::default(),
            2,
            accepted_at,
            chrono::Duration::minutes(10),
        )
        .unwrap();
        assert_eq!(
            provisioning.provisioning_deadline.as_deref(),
            Some("2026-08-10T10:10:00Z")
        );
        assert!(provisioning.ready_at.is_none());
        assert!(provisioning.expires_at.is_none());

        let mut stamped = SandboxLeaseStatus {
            provisioning_deadline: Some("2026-08-10T10:10:00Z".into()),
            ..Default::default()
        };
        assert_eq!(
            begin_sandbox_provisioning(&stamped, 2, accepted_at, chrono::Duration::minutes(10),)
                .unwrap()
                .provisioning_deadline,
            stamped.provisioning_deadline
        );
        stamped.provisioning_deadline = Some("2026-08-10T10:11:00Z".into());
        assert_eq!(
            begin_sandbox_provisioning(&stamped, 2, accepted_at, chrono::Duration::minutes(10),),
            Err(SandboxLifecycleError::PersistedTimestampChanged(
                "provisioningDeadline"
            ))
        );

        let ready =
            mark_sandbox_ready(&provisioning, 2, ready_at, chrono::Duration::hours(1)).unwrap();
        assert_eq!(ready.ready_at.as_deref(), Some("2026-08-10T10:03:00Z"));
        assert_eq!(ready.expires_at.as_deref(), Some("2026-08-10T11:03:00Z"));

        // A granted extension is an INPUT to this derivation, so re-running the
        // Ready transition over an extended lease is idempotent. It used to be
        // a second write of `expiresAt`, which made every later pass fail as a
        // changed timestamp - so the controller requeued forever and never
        // re-stamped the upstream shutdown backstop, letting upstream destroy
        // the workload at its ORIGINAL deadline while the lease advertised the
        // extended one.
        let mut extended = ready.clone();
        extended.granted_extension_seconds = 1800;
        extended.expires_at = Some("2026-08-10T11:33:00Z".into());
        let reconciled =
            mark_sandbox_ready(&extended, 2, ready_at, chrono::Duration::hours(1)).unwrap();
        assert_eq!(
            reconciled.expires_at.as_deref(),
            Some("2026-08-10T11:33:00Z")
        );

        // And an expiry that does NOT match the derivation is still refused,
        // so the guard against an out-of-band writer is not weakened by it.
        let mut forged = extended.clone();
        forged.expires_at = Some("2026-08-10T12:33:00Z".into());
        assert_eq!(
            mark_sandbox_ready(&forged, 2, ready_at, chrono::Duration::hours(1)),
            Err(SandboxLifecycleError::PersistedTimestampChanged(
                "readyAt/expiresAt"
            ))
        );
        assert_eq!(
            transition_sandbox_phase(
                SandboxLeasePhase::Releasing,
                SandboxLeasePhase::Released,
                false,
            ),
            Err(SandboxLifecycleError::CleanupProofRequired)
        );
        assert_eq!(
            transition_sandbox_phase(
                SandboxLeasePhase::Quarantined,
                SandboxLeasePhase::Released,
                true,
            ),
            Err(SandboxLifecycleError::InvalidTransition {
                current: SandboxLeasePhase::Quarantined,
                next: SandboxLeasePhase::Released,
            })
        );
        assert_eq!(
            transition_sandbox_phase(
                SandboxLeasePhase::Quarantined,
                SandboxLeasePhase::Releasing,
                false,
            ),
            Ok(SandboxLeasePhase::Releasing)
        );
    }
}
