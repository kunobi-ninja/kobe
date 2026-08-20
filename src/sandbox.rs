//! Pure Agent Sandbox v0.5.4 `v1beta1` projections and lease invariants.
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
use k8s_openapi::api::core::v1::{Container, ContainerPort, PodSpec, ResourceRequirements};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{DynamicObject, ObjectMeta, TypeMeta};
use thiserror::Error;

use crate::crd::{
    ResolvedSandboxPlacement, SandboxLeasePhase, SandboxLeaseStatus, SandboxObjectReference,
    SandboxPoolSpec, SandboxPoolValidationError, SandboxResourceCeiling, SandboxTargetProvenance,
    SandboxTemplateSpec,
};

pub const AGENT_SANDBOX_API_VERSION: &str = "extensions.agents.x-k8s.io/v1beta1";
pub const SANDBOX_TEMPLATE_KIND: &str = "SandboxTemplate";
pub const SANDBOX_WARM_POOL_KIND: &str = "SandboxWarmPool";
pub const SANDBOX_CLAIM_KIND: &str = "SandboxClaim";
pub const KOBE_MANAGED_BY: &str = "kobe-operator";
const KOBE_API_VERSION: &str = "kobe.kunobi.ninja/v1alpha1";
const SANDBOX_API_VERSION: &str = "agents.x-k8s.io/v1beta1";
const CORE_API_VERSION: &str = "v1";

/// Render one administrator-owned Kobe pool template into the pinned upstream
/// Agent Sandbox contract.
///
/// The projection is intentionally closed: it emits only declared containers,
/// CPU/memory/ephemeral-storage resources, TCP ports, the administrator's
/// RuntimeClass, and fixed secure policies. It cannot emit PVC templates,
/// environment values, service accounts, arbitrary volumes, or caller metadata.
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
                ..Default::default()
            }
        })
        .collect();

    let pod_spec = PodSpec {
        automount_service_account_token: Some(false),
        containers,
        restart_policy: Some("Never".to_string()),
        runtime_class_name: pool.isolation.runtime_class_name().map(ToString::to_string),
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
/// The initial claim intentionally omits `shutdownTime`: runtime TTL starts
/// only after the upstream Sandbox becomes Ready. [`build_sandbox_claim_lifecycle_patch`]
/// adds the absolute expiry later with a resourceVersion fence.
pub fn build_sandbox_claim(
    name: &str,
    namespace: &str,
    warm_pool_name: &str,
    owner_ref: Option<&OwnerReference>,
) -> DynamicObject {
    managed_object(
        SANDBOX_CLAIM_KIND,
        name,
        namespace,
        owner_ref,
        serde_json::json!({
            "spec": {
                "warmPoolRef": { "name": warm_pool_name },
                "lifecycle": {
                    "shutdownPolicy": "DeleteForeground"
                }
            }
        }),
    )
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
                || provenance.child_cluster_instance.is_some() =>
        {
            return Err(SandboxProvenanceError::UnexpectedChildReference);
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
    let expires_at = ready_at
        .checked_add_signed(runtime_ttl)
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
            | (SandboxLeasePhase::Quarantined, SandboxLeasePhase::Released)
            | (SandboxLeasePhase::Quarantined, SandboxLeasePhase::Expired)
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
        SandboxContainerResources, SandboxContainerSpec, SandboxExecutionCanary, SandboxIsolation,
        SandboxPlacement, SandboxPortSpec, SandboxReadinessRequirements, SandboxResourceQuantity,
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
            sandbox_template: Some(reference("SandboxTemplate", "agents", "template-uid")),
            sandbox_warm_pool: None,
            sandbox_claim: claim,
            sandbox: None,
            pod: None,
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
    fn claim_projection_starts_ttl_only_after_ready() {
        let expires_at = DateTime::parse_from_rfc3339("2026-08-10T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        let value = serde_json::to_value(build_sandbox_claim("lease-a", "targets", "agents", None))
            .unwrap();

        assert_eq!(value["apiVersion"], AGENT_SANDBOX_API_VERSION);
        assert_eq!(value["kind"], SANDBOX_CLAIM_KIND);
        assert_eq!(value["spec"]["warmPoolRef"]["name"], "agents");
        assert!(value["spec"]["lifecycle"].get("shutdownTime").is_none());
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
            Ok(SandboxLeasePhase::Released)
        );
    }
}
