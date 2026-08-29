//! Composition of child-cluster Sandboxes through an internal `ClusterLease`
//! (#74).
//!
//! A child-placement `SandboxPool` says: do not run this pool's Sandboxes next
//! to everybody else's. Kobe acquires one exclusive cluster from an
//! administrator-named `ClusterPool`, and places the caller's `SandboxClaim`
//! inside it.
//!
//! # The internal cluster is not the caller's
//!
//! The caller asked for a Sandbox. They receive Sandbox operations and nothing
//! else. They cannot connect to the internal `ClusterLease`, extend it, release
//! it, obtain credentials for it, or learn that it exists — the composition is
//! Kobe's implementation of the pool, not a capability it hands out. Its
//! kubeconfig is read from controller-authorised storage into memory and never
//! written to status, an API response, a log line, or an event.
//!
//! The operator provides Agent Sandbox v1.0.0 through a generic, explicitly
//! referenced `BootstrapConfig` or another external provisioning mechanism.
//! Kobe performs read-only API compatibility checks before creating tenant
//! pool objects; it does not ship or inject a privileged runtime installer.

use std::time::Duration;

use kube::Resource;
use kube::api::ObjectMeta;
use kube::{Client, ResourceExt};

use crate::crd::{
    CleanupMode, ClusterLease, ClusterLeaseSpec, ClusterPool, ClusterPoolPhase, Requester,
    SandboxLease, SandboxObjectReference, SandboxPlacement, SandboxPlacementAuthority, SandboxPool,
};

pub(crate) const SANDBOX_COMPOSITION_NAME_ANNOTATION: &str =
    "kobe.kunobi.ninja/sandbox-composition-name";
pub(crate) const CONNECT_TOKEN_CREATE_FENCE_ANNOTATION: &str =
    "kobe.kunobi.ninja/connect-token-binding-before-create-v1";

/// Grace added on top of provisioning and runtime, so the internal cluster
/// cannot expire while its Sandbox is still being torn down.
///
/// Teardown is not instantaneous — a foreground claim delete waits for the
/// Sandbox to stop, and #80's verification then has to observe the footprint
/// gone. If the child lease expired inside that window, the evidence would
/// disappear along with the cluster and the composition could never report
/// clean completion.
pub const CHILD_DRAIN_GRACE: Duration = Duration::from_secs(15 * 60);

/// Keeps the deterministic internal-handle name occupied after proof is ACKed.
///
/// A controller from before the allocation-fence protocol may still have a
/// create request in flight. Deleting the handle to 404 before the outer
/// lease's retention window ends would let that stale request recreate an
/// allocation after `FootprintAbsent=True`. The Sandbox tombstone reaper is
/// the only code allowed to remove this finalizer.
pub const CHILD_HANDLE_RETENTION_FINALIZER: &str =
    "kobe.kunobi.ninja/sandbox-child-handle-retention";
pub const CHILD_HANDLE_TOMBSTONE_LABEL: &str = "kobe.kunobi.ninja/sandbox-child-handle-tombstone";
pub const CHILD_HANDLE_RETAIN_UNTIL_ANNOTATION: &str =
    "kobe.kunobi.ninja/child-handle-retain-until";
pub const CHILD_HANDLE_OUTER_NAME_ANNOTATION: &str = "kobe.kunobi.ninja/sandbox-lease-name";
pub const CHILD_HANDLE_STALE_REJECTED_ANNOTATION: &str =
    "kobe.kunobi.ninja/stale-sandbox-composition-rejected";
pub const CHILD_KUBECONFIG_PROVENANCE_ANNOTATION: &str =
    "kobe.kunobi.ninja/child-kubeconfig-provenance";
pub const CHILD_KUBECONFIG_PROVENANCE_SECRET_UID_SHA256_V1: &str = "secret-uid-sha256-v1";

/// Retain the handle at least as long as the outer audit record, plus the
/// bounded create window and scheduling margin used by the release fence.
pub fn child_handle_retention_deadline(
    now: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    let configured = std::env::var(crate::api::sandbox::ENV_SANDBOX_LEASE_RETENTION).ok();
    now + crate::api::sandbox::sandbox_lease_retention(configured.as_deref())
        + chrono::Duration::from_std(crate::controllers::sandbox::SANDBOX_CLAIM_CREATE_TIMEOUT)
            .expect("fixed create timeout fits chrono")
        + chrono::Duration::minutes(5)
}

/// Why a child composition cannot proceed.
///
/// A closed, non-secret vocabulary: these values reach status, events and
/// metrics, and none of them may carry a kubeconfig, a token, or a raw backend
/// response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChildPlacementError {
    #[error(
        "SandboxPool {pool} names ClusterPool {cluster_pool}, whose backend {backend} cannot \
         produce a teardown receipt; child placement requires backend.type=k3s"
    )]
    BackendUnsupported {
        pool: String,
        cluster_pool: String,
        backend: String,
    },
    #[error(
        "ClusterPool {cluster_pool} is not eligible for verified destroy: {reason}. A child \
         Sandbox whose capacity cannot be proven destroyed must not be placed."
    )]
    VerifiedDestroyIneligible {
        cluster_pool: String,
        reason: String,
    },
    #[error(
        "ClusterPool {cluster_pool} allows at most {pool_max}, but this Sandbox needs {required} \
         to cover provisioning, its runtime TTL and the cleanup window"
    )]
    LifetimeUnachievable {
        cluster_pool: String,
        pool_max: String,
        required: String,
    },
    #[error("{field} is not a valid duration")]
    InvalidDuration { field: &'static str },
    #[error(
        "child cluster {cluster} does not serve a compatible Agent Sandbox runtime ({reason}). \
         Configure the operator-owned ClusterPool bootstrap or image to install Agent Sandbox v1.0.0."
    )]
    ChildRuntimeUnusable { cluster: String, reason: String },
    #[error("child cluster {cluster} has an unusable checkpointed kubeconfig Secret")]
    ChildCredentialUnusable { cluster: String },
    #[error("ClusterPool {cluster_pool} cannot safely compose this SandboxPool ({reason})")]
    CapacityUnavailable {
        cluster_pool: String,
        reason: &'static str,
    },
}

impl ChildPlacementError {
    /// Bounded reason code for status, events and metrics.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::BackendUnsupported { .. } => "backend_unsupported",
            Self::VerifiedDestroyIneligible { .. } => "verified_destroy_ineligible",
            Self::LifetimeUnachievable { .. } => "lifetime_unachievable",
            Self::InvalidDuration { .. } => "invalid_duration",
            Self::ChildRuntimeUnusable { .. } => "child_runtime_unusable",
            Self::ChildCredentialUnusable { .. } => "child_credential_unusable",
            Self::CapacityUnavailable { .. } => "capacity_unavailable",
        }
    }
}

/// Prove a child pool may safely accept compositions before allocation.
///
/// This is deliberately not a capacity promise: an on-demand ClusterPool may
/// be Idle with zero Ready members and concurrent compositions race for idle
/// members. The internal [`ClusterLease`] is the only allocator. Certification
/// proves static verified-destroy eligibility, complete object identity, no
/// known unhealthy/quarantined footprint, and that the ClusterPool TTL ceiling
/// covers the SandboxPool's worst permitted lifetime.
pub fn child_pool_is_composition_eligible(
    sandbox_pool: &SandboxPool,
    cluster_pool: &ClusterPool,
) -> Result<(), ChildPlacementError> {
    child_pool_is_eligible(&sandbox_pool.name_any(), cluster_pool)?;
    sandbox_pool
        .spec
        .validate()
        .map_err(|_| ChildPlacementError::CapacityUnavailable {
            cluster_pool: cluster_pool.name_any(),
            reason: "SandboxPool spec is invalid",
        })?;
    crate::sandbox::aggregate_resource_limits(&sandbox_pool.spec.template).map_err(|_| {
        ChildPlacementError::CapacityUnavailable {
            cluster_pool: cluster_pool.name_any(),
            reason: "SandboxPool resource quantities are invalid",
        }
    })?;
    if crate::pool::parse_duration(&sandbox_pool.spec.readiness.canary.timeout)
        .and_then(|duration| duration.to_std().ok())
        .is_none_or(|duration| duration.is_zero())
    {
        return Err(ChildPlacementError::CapacityUnavailable {
            cluster_pool: cluster_pool.name_any(),
            reason: "SandboxPool canary timeout is not a positive duration",
        });
    }
    if !matches!(
        sandbox_pool.spec.isolation,
        crate::crd::SandboxIsolation::TrustedRunc {}
    ) {
        return Err(ChildPlacementError::CapacityUnavailable {
            cluster_pool: cluster_pool.name_any(),
            reason: "gVisor and Kata isolation remain unqualified until issue #14 is closed",
        });
    }
    if cluster_pool.uid().is_none_or(|uid| uid.is_empty())
        || cluster_pool.metadata.generation.is_none()
    {
        return Err(ChildPlacementError::CapacityUnavailable {
            cluster_pool: cluster_pool.name_any(),
            reason: "pool identity is incomplete",
        });
    }
    let status =
        cluster_pool
            .status
            .as_ref()
            .ok_or_else(|| ChildPlacementError::CapacityUnavailable {
                cluster_pool: cluster_pool.name_any(),
                reason: "status is missing",
            })?;
    if status.quarantined != 0 {
        return Err(ChildPlacementError::CapacityUnavailable {
            cluster_pool: cluster_pool.name_any(),
            reason: "quarantined members are present",
        });
    }
    if status.unhealthy != 0 {
        return Err(ChildPlacementError::CapacityUnavailable {
            cluster_pool: cluster_pool.name_any(),
            reason: "unhealthy members are present",
        });
    }
    if !matches!(
        status.phase,
        Some(
            ClusterPoolPhase::Healthy
                | ClusterPoolPhase::ScalingUp
                | ClusterPoolPhase::ScalingDown
                | ClusterPoolPhase::Idle
        )
    ) {
        return Err(ChildPlacementError::CapacityUnavailable {
            cluster_pool: cluster_pool.name_any(),
            reason: "pool is failing, backed off, or has no published phase",
        });
    }
    let worst_ttl = parse_std_duration(&sandbox_pool.spec.max_ttl)
        .ok_or(ChildPlacementError::InvalidDuration { field: "maxTtl" })?;
    child_lifetime_fits(cluster_pool, sandbox_pool, worst_ttl)?;
    Ok(())
}

/// Resolve the exact child `ClusterPool` identity proven eligible by this
/// observation.
///
/// A name is only a lookup key. UID and generation are the authority copied by
/// HTTP admission and later revalidated immediately before allocation.
pub fn eligible_child_placement_authority(
    sandbox_pool: &SandboxPool,
    cluster_pool: &ClusterPool,
    management_namespace: &str,
) -> Result<SandboxPlacementAuthority, ChildPlacementError> {
    let SandboxPlacement::ChildCluster { cluster_pool_ref } = &sandbox_pool.spec.placement else {
        return Err(ChildPlacementError::CapacityUnavailable {
            cluster_pool: cluster_pool.name_any(),
            reason: "SandboxPool does not request child placement",
        });
    };
    if cluster_pool.name_any() != *cluster_pool_ref
        || cluster_pool.namespace().as_deref() != Some(management_namespace)
        || cluster_pool.metadata.deletion_timestamp.is_some()
    {
        return Err(ChildPlacementError::CapacityUnavailable {
            cluster_pool: cluster_pool.name_any(),
            reason: "pool name, namespace, or deletion state does not match the requested child placement",
        });
    }
    child_pool_is_composition_eligible(sandbox_pool, cluster_pool)?;
    Ok(SandboxPlacementAuthority {
        api_version: "kobe.kunobi.ninja/v1alpha1".into(),
        kind: "ClusterPool".into(),
        namespace: management_namespace.into(),
        name: cluster_pool.name_any(),
        uid: cluster_pool
            .uid()
            .expect("eligibility requires a non-empty UID"),
        generation: cluster_pool
            .metadata
            .generation
            .expect("eligibility requires a generation"),
    })
}

/// Revalidate an admission authority against one freshly read eligible pool.
pub fn child_placement_authority_matches(
    authority: &SandboxPlacementAuthority,
    sandbox_pool: &SandboxPool,
    cluster_pool: &ClusterPool,
    management_namespace: &str,
) -> Result<bool, ChildPlacementError> {
    Ok(
        eligible_child_placement_authority(sandbox_pool, cluster_pool, management_namespace)?
            == *authority,
    )
}

/// The internal lease's name, derived from the Sandbox lease it serves.
///
/// Derived rather than generated so a restarted controller finds the same
/// object instead of allocating a second cluster, and prefixed so an internal
/// lease is never mistaken for — or adopted from — a tenant one.
pub fn internal_lease_name(sandbox_lease: &str) -> String {
    format!("kobe-sbx-{sandbox_lease}")
}

/// How long the internal cluster must live for the outer Sandbox to complete.
///
/// Provisioning, then the full runtime TTL, then the drain grace. The child
/// cannot expire first: an internal cluster that vanished mid-lease would take
/// the caller's running Sandbox with it, and one that vanished mid-teardown
/// would take the evidence that it was cleaned up.
pub fn required_child_lifetime(
    provisioning_timeout: Duration,
    runtime_ttl: Duration,
    drain_grace: Duration,
) -> Duration {
    provisioning_timeout
        .saturating_add(runtime_ttl)
        .saturating_add(drain_grace)
}

/// Whether the named `ClusterPool` may back a child Sandbox at all.
///
/// Refused *before* anything is allocated. A pool that cannot produce a
/// teardown receipt would let a Sandbox's capacity return to the pool without
/// anyone proving the previous tenant's footprint was gone — and the whole
/// point of child placement is that the tenant got a cluster to themselves.
///
/// The one condition deliberately not checked here is whether the external
/// datastore identity was recorded: that is a bind-time fact about a specific
/// instance, not something a pool spec can state. #80's release gate enforces
/// it before any teardown reports clean, so deferring it narrows nothing.
pub fn child_pool_is_eligible(
    sandbox_pool: &str,
    cluster_pool: &ClusterPool,
) -> Result<(), ChildPlacementError> {
    // The backend rule lives in `verified_destroy_eligibility`, not here.
    // Duplicating it would let the two drift into disagreeing about which
    // backends qualify — and the one that silently won would be whichever ran
    // first.
    crate::crd::verified_destroy_eligibility(
        &cluster_pool.spec.backend.backend_type,
        &cluster_pool.spec.cluster,
        cluster_pool.spec.diagnostics.as_ref(),
        // Bind-time condition; see the doc comment above.
        true,
    )
    .map_err(|reason| match reason {
        // Reported with the pool names, because an operator reading this needs
        // to know WHICH SandboxPool named WHICH ClusterPool.
        crate::crd::VerifiedDestroyIneligible::UnsupportedBackend => {
            ChildPlacementError::BackendUnsupported {
                pool: sandbox_pool.to_string(),
                cluster_pool: cluster_pool.name_any(),
                backend: format!("{:?}", cluster_pool.spec.backend.backend_type).to_lowercase(),
            }
        }
        reason => ChildPlacementError::VerifiedDestroyIneligible {
            cluster_pool: cluster_pool.name_any(),
            reason: reason.to_string(),
        },
    })
}

/// Check that the pool's own TTL ceiling can cover the whole composition.
///
/// Rejecting here, before a cluster is allocated, is the difference between an
/// error the caller sees immediately and a Sandbox that works right up until
/// its cluster disappears underneath it.
pub fn child_lifetime_fits(
    cluster_pool: &ClusterPool,
    sandbox_pool: &SandboxPool,
    runtime_ttl: Duration,
) -> Result<Duration, ChildPlacementError> {
    let provisioning = parse_std_duration(&sandbox_pool.spec.provisioning_timeout).ok_or(
        ChildPlacementError::InvalidDuration {
            field: "provisioningTimeout",
        },
    )?;
    let required = required_child_lifetime(provisioning, runtime_ttl, CHILD_DRAIN_GRACE);

    let pool_max =
        parse_std_duration(&cluster_pool.spec.ttl).ok_or(ChildPlacementError::InvalidDuration {
            field: "clusterPool.ttl",
        })?;
    if required > pool_max {
        return Err(ChildPlacementError::LifetimeUnachievable {
            cluster_pool: cluster_pool.name_any(),
            pool_max: cluster_pool.spec.ttl.clone(),
            required: format!("{}s", required.as_secs()),
        });
    }
    Ok(required)
}

fn parse_std_duration(value: &str) -> Option<Duration> {
    crate::pool::parse_duration(value)
        .and_then(|value| value.to_std().ok())
        .filter(|value| !value.is_zero())
}

/// Build the internal `ClusterLease` for one Sandbox lease.
///
/// Three properties matter and each is deliberate:
///
/// * **Not owner-referenced to the `SandboxLease`.** Kubernetes garbage
///   collection must not erase the lease or its teardown receipt before the
///   outer finalizer consumes that proof. The exact outer UID label plus the
///   deterministic name form the restart-safe pre-status recovery fence.
///   Normal deletion is covered by the outer finalizer and explicit cleanup.
///   A generic orphan reaper is intentionally not inferred from a missing
///   outer object: after manual finalizer stripping it would have no durable
///   place to retain the destroy receipt or decide quota ownership safely.
/// * **`CleanupMode::VerifiedDestroy`.** A pool that cannot honour it rejects
///   the lease at bind time rather than degrading to "we issued the deletes and
///   assumed they worked" — which for an exclusive tenant cluster is exactly
///   the assumption not worth making.
/// * **An internal requester identity.** The lease is Kobe's, not the caller's.
///   Recording the tenant as its requester would make it appear in their own
///   cluster-lease listings and, worse, look releasable by them.
pub fn build_internal_cluster_lease(
    sandbox_lease: &SandboxLease,
    cluster_pool_ref: &str,
    lifetime: Duration,
) -> Option<ClusterLease> {
    let sandbox_uid = sandbox_lease.uid().filter(|uid| !uid.is_empty())?;
    let requester = internal_requester(&sandbox_uid);
    Some(ClusterLease {
        metadata: ObjectMeta {
            name: Some(internal_lease_name(&sandbox_lease.name_any())),
            namespace: sandbox_lease.namespace(),
            labels: Some(
                [
                    (
                        "app.kubernetes.io/managed-by".to_string(),
                        crate::sandbox::KOBE_MANAGED_BY.to_string(),
                    ),
                    (
                        crate::sandbox::SANDBOX_LEASE_UID_LABEL.to_string(),
                        sandbox_uid.clone(),
                    ),
                    (CHILD_HANDLE_TOMBSTONE_LABEL.to_string(), "true".into()),
                ]
                .into_iter()
                .collect(),
            ),
            annotations: Some(
                [
                    (
                        CHILD_HANDLE_OUTER_NAME_ANNOTATION.to_string(),
                        sandbox_lease.name_any(),
                    ),
                    (
                        CHILD_HANDLE_RETAIN_UNTIL_ANNOTATION.to_string(),
                        child_handle_retention_deadline(chrono::Utc::now()).to_rfc3339(),
                    ),
                    (
                        CHILD_KUBECONFIG_PROVENANCE_ANNOTATION.to_string(),
                        CHILD_KUBECONFIG_PROVENANCE_SECRET_UID_SHA256_V1.to_string(),
                    ),
                    (
                        SANDBOX_COMPOSITION_NAME_ANNOTATION.to_string(),
                        sandbox_lease.name_any(),
                    ),
                    (
                        CONNECT_TOKEN_CREATE_FENCE_ANNOTATION.to_string(),
                        "true".into(),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
            finalizers: Some(vec![
                CHILD_HANDLE_RETENTION_FINALIZER.to_string(),
                crate::crd::TEARDOWN_RECEIPT_RETENTION_FINALIZER.to_string(),
            ]),
            ..Default::default()
        },
        spec: ClusterLeaseSpec {
            pool_ref: cluster_pool_ref.to_string(),
            ttl: format!("{}s", lifetime.as_secs()),
            requester,
            metadata: None,
            priority: default_internal_priority(),
            cleanup_mode: Some(CleanupMode::VerifiedDestroy),
        },
        status: None,
    })
}

fn internal_lease_base_identity_is_for_sandbox(
    internal: &ClusterLease,
    sandbox_lease: &SandboxLease,
) -> bool {
    if sandbox_lease.uid().is_none_or(|uid| uid.is_empty()) {
        return false;
    }
    internal.name_any() == internal_lease_name(&sandbox_lease.name_any())
        && internal.namespace() == sandbox_lease.namespace()
        && internal
            .labels()
            .get("app.kubernetes.io/managed-by")
            .is_some_and(|value| value == crate::sandbox::KOBE_MANAGED_BY)
        && internal.spec.requester.requester_type == "kobe:sandbox-composition"
        && internal.spec.cleanup_mode == Some(CleanupMode::VerifiedDestroy)
}

/// Ownership state of an otherwise exact internal composition handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InternalLeaseOwnership {
    /// Current format: durable UID labels and no GC dependency.
    Ownerless,
    /// Exact sole controller owner from a pre-migration Kobe build. It may be
    /// removed under UID/resourceVersion tests before the object is used.
    ExactLegacy,
    /// Foreign, ambiguous, deleting, or otherwise not safely migratable.
    Foreign,
}

/// Classify legacy ownership without silently treating GC dependence as safe.
pub(crate) fn internal_lease_ownership(
    internal: &ClusterLease,
    sandbox_lease: &SandboxLease,
) -> InternalLeaseOwnership {
    if !internal_lease_base_identity_is_for_sandbox(internal, sandbox_lease)
        || internal.metadata.deletion_timestamp.is_some()
    {
        return InternalLeaseOwnership::Foreign;
    }
    let Some(sandbox_uid) = sandbox_lease.uid().filter(|uid| !uid.is_empty()) else {
        return InternalLeaseOwnership::Foreign;
    };
    let uid_label = internal
        .labels()
        .get(crate::sandbox::SANDBOX_LEASE_UID_LABEL);
    let Some(owners) = internal.metadata.owner_references.as_ref() else {
        return if uid_label == Some(&sandbox_uid)
            && (internal.spec.requester.identity == sandbox_uid
                || internal.spec.requester.identity == "kobe-operator")
        {
            InternalLeaseOwnership::Ownerless
        } else {
            InternalLeaseOwnership::Foreign
        };
    };
    if owners.is_empty() {
        return if uid_label == Some(&sandbox_uid)
            && (internal.spec.requester.identity == sandbox_uid
                || internal.spec.requester.identity == "kobe-operator")
        {
            InternalLeaseOwnership::Ownerless
        } else {
            InternalLeaseOwnership::Foreign
        };
    }
    if owners.len() == 1
        && owners[0].api_version == SandboxLease::api_version(&()).as_ref()
        && owners[0].kind == SandboxLease::kind(&()).as_ref()
        && owners[0].name == sandbox_lease.name_any()
        && owners[0].uid == sandbox_uid
        && owners[0].controller == Some(true)
        // The exact v1167179 object had no lease-UID label. Accept that byte
        // shape, or a partially migrated exact label, but never a conflicting
        // label from a same-named replacement outer lease.
        && uid_label.is_none_or(|value| value == &sandbox_uid)
        && (internal.spec.requester.identity == "kobe-operator"
            || internal.spec.requester.identity == sandbox_uid)
    {
        InternalLeaseOwnership::ExactLegacy
    } else {
        InternalLeaseOwnership::Foreign
    }
}

/// Whether an internal lease carries the exact durable identity of one outer
/// Sandbox lease in the current ownerless format.
pub fn internal_lease_is_for_sandbox(
    internal: &ClusterLease,
    sandbox_lease: &SandboxLease,
) -> bool {
    internal_lease_ownership(internal, sandbox_lease) == InternalLeaseOwnership::Ownerless
}

/// Whether this handle was created under the checkpoint-before-first-use
/// kubeconfig protocol. The marker is written on CREATE; adding it to an older
/// already-bound handle would manufacture provenance for credentials that may
/// already have been consumed.
pub fn internal_lease_has_secret_uid_protocol(internal: &ClusterLease) -> bool {
    internal
        .annotations()
        .get(CHILD_KUBECONFIG_PROVENANCE_ANNOTATION)
        .is_some_and(|value| value == CHILD_KUBECONFIG_PROVENANCE_SECRET_UID_SHA256_V1)
}

/// Whether a legacy-owner migration is permitted without changing the
/// immutable composition request.
pub(crate) fn internal_lease_matches_composition_identity(
    internal: &ClusterLease,
    sandbox_lease: &SandboxLease,
    cluster_pool_ref: &str,
    lifetime: Duration,
) -> bool {
    internal_lease_ownership(internal, sandbox_lease) != InternalLeaseOwnership::Foreign
        && internal.spec.pool_ref == cluster_pool_ref
        && internal.spec.ttl == format!("{}s", lifetime.as_secs())
}

/// Placement additionally requires the immutable request shape this controller
/// intended. Identity alone authorises recovery; it does not authorise silently
/// changing pools or shortening the child lifetime after a create race.
pub fn internal_lease_matches_composition(
    internal: &ClusterLease,
    sandbox_lease: &SandboxLease,
    cluster_pool_ref: &str,
    lifetime: Duration,
) -> bool {
    internal_lease_is_for_sandbox(internal, sandbox_lease)
        && internal_lease_matches_composition_identity(
            internal,
            sandbox_lease,
            cluster_pool_ref,
            lifetime,
        )
}

/// The identity Kobe uses for its own compositions.
///
/// Deliberately not the caller's. An internal lease attributed to a tenant
/// would show up in their listings and read as theirs to release — and
/// releasing it out from under a running Sandbox is precisely the operation
/// this composition exists to prevent them performing.
fn internal_requester(outer_uid: &str) -> Requester {
    Requester {
        requester_type: "kobe:sandbox-composition".to_string(),
        // This is the outer object's UID, not the tenant identity. It lives in
        // immutable spec so the isolated authority can authenticate the exact
        // consumer without trusting mutable labels or owner references.
        identity: outer_uid.to_string(),
    }
}

/// Internal compositions outrank ordinary queued work.
///
/// A caller is already waiting on a Sandbox by the time this lease is queued —
/// they are not queuing for a cluster, they are queuing behind one.
fn default_internal_priority() -> u32 {
    100
}

/// Record what was composed, so teardown can act on exact identities.
///
/// Names alone are not identity. A same-named replacement cluster is fresh
/// capacity, not evidence that the original was destroyed, and #80's receipts
/// are checked against these UIDs rather than against a name that may have been
/// reused in between. Management objects keep their management namespace,
/// while `target.namespace` is the namespace inside the child cluster; merging
/// those two authorities would make later upstream provenance look like a
/// target substitution.
pub fn child_provenance(
    management_namespace: &str,
    target_namespace: &str,
    lease: &ClusterLease,
    instance_name: &str,
    instance_uid: &str,
    instance_generation: Option<i64>,
) -> crate::crd::SandboxTargetProvenance {
    crate::crd::SandboxTargetProvenance {
        namespace: target_namespace.to_string(),
        child_cluster_lease: Some(SandboxObjectReference {
            api_version: "kobe.kunobi.ninja/v1alpha1".to_string(),
            kind: "ClusterLease".to_string(),
            namespace: lease.namespace(),
            name: lease.name_any(),
            uid: lease.uid().unwrap_or_default(),
            generation: lease.metadata.generation,
        }),
        child_cluster_instance: Some(SandboxObjectReference {
            api_version: "kobe.kunobi.ninja/v1alpha1".to_string(),
            kind: "ClusterInstance".to_string(),
            namespace: Some(management_namespace.to_string()),
            name: instance_name.to_string(),
            uid: instance_uid.to_string(),
            generation: instance_generation,
        }),
        child_cluster_kubeconfig_secret: None,
        child_cluster_kubeconfig_sha256: None,
        // Upstream object references are filled in by placement once each
        // object exists. Provenance is monotonic: a reference is only ever
        // added, never cleared, so teardown can always name what it must prove
        // absent even after a restart.
        sandbox_template: None,
        sandbox_warm_pool: None,
        sandbox_claim: None,
        sandbox: None,
        pod: None,
        service: None,
    }
}

/// Validate the operator-installed child runtime without mutating it.
pub async fn validate_child_runtime(
    child: &Client,
    cluster: &str,
) -> Result<(), ChildPlacementError> {
    crate::sandbox_runtime::validate_external_runtime(child)
        .await
        .map_err(|reason| ChildPlacementError::ChildRuntimeUnusable {
            cluster: cluster.to_string(),
            reason: reason.reason_code().to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{BackendType, ClusterPoolSpec};

    fn cluster_pool(backend: BackendType, ttl: &str) -> ClusterPool {
        let spec: ClusterPoolSpec = serde_json::from_value(serde_json::json!({
            "ttl": ttl,
            "backend": { "type": backend_wire_name(backend) },
            "cluster": { "version": "v1.32.0" },
        }))
        .expect("cluster pool fixture deserializes");
        ClusterPool {
            metadata: ObjectMeta {
                name: Some("sandbox-children".into()),
                namespace: Some("kobe".into()),
                uid: Some("cluster-pool-uid".into()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    fn healthy_cluster_pool() -> ClusterPool {
        let mut pool = cluster_pool(BackendType::K3s, "10h");
        pool.metadata.generation = Some(4);
        pool.status = Some(crate::crd::ClusterPoolStatus {
            phase: Some(ClusterPoolPhase::Healthy),
            ready: 2,
            ..Default::default()
        });
        pool
    }

    fn backend_wire_name(backend: BackendType) -> String {
        serde_json::to_value(backend)
            .expect("backend serializes")
            .as_str()
            .expect("backend is a string")
            .to_string()
    }

    /// Only a backend that can prove teardown may back a child Sandbox.
    ///
    /// Child placement's entire promise is that the tenant had the cluster to
    /// themselves. A backend that returns capacity to the pool on the strength
    /// of an accepted delete cannot support that promise, so it is refused
    /// before anything is allocated rather than degraded silently — which is
    /// what "must return Unsupported" in #74 is protecting against.
    #[test]
    fn only_a_receipt_capable_backend_is_admitted() {
        assert!(child_pool_is_eligible("agents", &cluster_pool(BackendType::K3s, "8h")).is_ok());

        for backend in [
            BackendType::K0s,
            BackendType::Vcluster,
            BackendType::Vkobe,
            BackendType::Capi,
        ] {
            let error =
                child_pool_is_eligible("agents", &cluster_pool(backend.clone(), "8h")).unwrap_err();
            assert!(
                matches!(error, ChildPlacementError::BackendUnsupported { .. }),
                "{backend:?} must be refused, got {error}"
            );
            assert_eq!(error.reason_code(), "backend_unsupported");
        }
    }

    /// Child admission consumes only demonstrably clean idle capacity.
    ///
    /// A healthy-looking count cannot hide quarantine or unhealthy members,
    /// and static k3s eligibility cannot substitute for current status.
    #[test]
    fn child_composition_requires_clean_bounded_pool_state() {
        let sandbox_pool = SandboxPool {
            metadata: ObjectMeta {
                name: Some("agents".into()),
                uid: Some("sandbox-pool-uid".into()),
                generation: Some(3),
                ..Default::default()
            },
            spec: serde_json::from_value(serde_json::json!({
                "warmCapacity": 1,
                "defaultTtl": "1h",
                "maxTtl": "8h",
                "provisioningTimeout": "10m",
                "placement": { "type": "childCluster", "clusterPoolRef": "sandbox-children" },
                "template": {
                    "defaultContainer": "agent",
                    "containers": [{
                        "name": "agent",
                        "image": "example.invalid/agent@sha256:abc",
                        "command": ["/agent"],
                        "resources": {
                            "requests": { "cpu": "100m", "memory": "128Mi", "ephemeralStorage": "128Mi" },
                            "limits": { "cpu": "1", "memory": "1Gi", "ephemeralStorage": "1Gi" }
                        }
                    }]
                },
                "isolation": { "tier": "trusted-runc" },
                "readiness": { "canary": { "argv": ["/agent", "health"], "timeout": "30s" } }
            }))
            .unwrap(),
            status: None,
        };
        let healthy = healthy_cluster_pool();
        child_pool_is_composition_eligible(&sandbox_pool, &healthy).unwrap();

        let mut degraded = healthy.clone();
        degraded.status.as_mut().unwrap().quarantined = 1;
        assert!(matches!(
            child_pool_is_composition_eligible(&sandbox_pool, &degraded),
            Err(ChildPlacementError::CapacityUnavailable { .. })
        ));

        let mut scaling = healthy.clone();
        scaling.status.as_mut().unwrap().phase = Some(ClusterPoolPhase::ScalingUp);
        assert!(child_pool_is_composition_eligible(&sandbox_pool, &scaling).is_ok());

        let mut empty = healthy;
        empty.status.as_mut().unwrap().phase = Some(ClusterPoolPhase::Idle);
        empty.status.as_mut().unwrap().ready = 0;
        child_pool_is_composition_eligible(&sandbox_pool, &empty)
            .expect("an on-demand zero-ready pool remains composition-eligible");
    }

    /// The internal cluster must outlive the whole composition.
    ///
    /// Provisioning, then the full runtime TTL the caller paid for, then the
    /// drain grace. A cluster that expired mid-lease would take the running
    /// Sandbox with it; one that expired mid-teardown would take the evidence
    /// that it was cleaned up, which is worse — capacity would be reused with
    /// nothing able to prove it was safe.
    #[test]
    fn the_child_cluster_cannot_expire_before_the_sandbox_is_cleaned_up() {
        let provisioning = Duration::from_secs(600);
        let runtime = Duration::from_secs(3600);

        let required = required_child_lifetime(provisioning, runtime, CHILD_DRAIN_GRACE);
        assert!(
            required > provisioning + runtime,
            "the cleanup window must be part of the bound, not assumed free"
        );
        assert_eq!(required, provisioning + runtime + CHILD_DRAIN_GRACE);

        // Saturating, so an absurd TTL cannot wrap into a short lifetime — the
        // one arithmetic slip here would produce a cluster that expires almost
        // immediately under a lease that believes it has days.
        assert_eq!(
            required_child_lifetime(Duration::MAX, Duration::MAX, Duration::MAX),
            Duration::MAX
        );
    }

    /// A composition that cannot be guaranteed is refused, not attempted.
    #[test]
    fn a_pool_whose_ceiling_is_too_low_is_refused_before_allocating() {
        let sandbox_pool = sandbox_pool_with_provisioning("10m");
        let runtime = Duration::from_secs(3600);

        // 10m + 1h + 15m = 1h25m. An 8h ceiling is plenty.
        assert!(
            child_lifetime_fits(
                &cluster_pool(BackendType::K3s, "8h"),
                &sandbox_pool,
                runtime
            )
            .is_ok()
        );

        // A ceiling above the runtime TTL but below the full window is exactly
        // the case a naive check misses: the Sandbox would run fine and the
        // cluster would vanish during teardown.
        let error = child_lifetime_fits(
            &cluster_pool(BackendType::K3s, "70m"),
            &sandbox_pool,
            runtime,
        )
        .unwrap_err();
        assert!(
            matches!(error, ChildPlacementError::LifetimeUnachievable { .. }),
            "got {error}"
        );
        assert_eq!(error.reason_code(), "lifetime_unachievable");
    }

    /// A malformed duration refuses the composition rather than defaulting.
    ///
    /// Every default here is a guess about how long somebody else's cluster
    /// should live, and the failure mode of guessing low is a Sandbox that dies
    /// early with its evidence.
    #[test]
    fn a_malformed_duration_refuses_rather_than_defaults() {
        for bad in ["", "soon", "0s", "-1h"] {
            let error = child_lifetime_fits(
                &cluster_pool(BackendType::K3s, "8h"),
                &sandbox_pool_with_provisioning(bad),
                Duration::from_secs(60),
            )
            .unwrap_err();
            assert!(
                matches!(error, ChildPlacementError::InvalidDuration { .. }),
                "provisioningTimeout {bad:?} must refuse, got {error}"
            );
        }

        let error = child_lifetime_fits(
            &cluster_pool(BackendType::K3s, "not-a-ttl"),
            &sandbox_pool_with_provisioning("10m"),
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ChildPlacementError::InvalidDuration {
                field: "clusterPool.ttl"
            }
        ));
    }

    /// The internal lease is Kobe's and survives until explicit proof cleanup.
    ///
    /// It must not be a GC dependent: foreground deletion could otherwise
    /// erase the receipt before the outer finalizer consumes it. Restart-safe
    /// recovery uses the exact lease UID label and deterministic name.
    #[test]
    fn the_internal_lease_has_durable_identity_without_an_owner_reference() {
        let sandbox_lease = sandbox_lease();
        let lease =
            build_internal_cluster_lease(&sandbox_lease, "children", Duration::from_secs(5100))
                .expect("a lease with a UID composes");

        assert_eq!(lease.name_any(), "kobe-sbx-sbx-1");
        assert!(
            lease.name_any().starts_with("kobe-sbx-"),
            "an internal lease must never be mistakable for a tenant one"
        );

        assert!(lease.metadata.owner_references.is_none());
        assert_eq!(
            lease.labels().get(crate::sandbox::SANDBOX_LEASE_UID_LABEL),
            Some(&"lease-uid-1".to_string())
        );
        assert!(internal_lease_is_for_sandbox(&lease, &sandbox_lease));

        // Verified destroy is requested explicitly. A pool that cannot honour
        // it rejects at bind time instead of quietly downgrading.
        assert_eq!(lease.spec.cleanup_mode, Some(CleanupMode::VerifiedDestroy));
        assert!(
            internal_lease_has_secret_uid_protocol(&lease),
            "the from-birth marker is the proof that no child request preceded the Secret UID+digest checkpoint"
        );

        // The requester is Kobe. Attributing it to the tenant would surface the
        // internal cluster in their listings and read as theirs to release.
        assert_ne!(lease.spec.requester.identity, "alice");
        assert!(lease.spec.requester.requester_type.starts_with("kobe:"));
        assert_eq!(lease.spec.requester.identity, "lease-uid-1");

        assert_eq!(lease.spec.ttl, "5100s");
    }

    /// A Sandbox lease with no UID cannot identify anything, so nothing is composed.
    ///
    /// The exact UID label is what lets restart and release recover a handle
    /// before its status checkpoint. Without it, a derived name alone could
    /// adopt or destroy somebody else's cluster.
    #[test]
    fn a_lease_without_a_uid_composes_nothing() {
        let mut sandbox_lease = sandbox_lease();
        sandbox_lease.metadata.uid = None;
        assert!(
            build_internal_cluster_lease(&sandbox_lease, "children", Duration::from_secs(60))
                .is_none()
        );
    }

    /// A derived name never permits adoption without the exact UID label, and
    /// reintroducing an owner reference is rejected as the same GC hazard.
    #[test]
    fn same_named_or_gc_owned_internal_leases_are_foreign() {
        let sandbox_lease = sandbox_lease();
        let exact =
            build_internal_cluster_lease(&sandbox_lease, "children", Duration::from_secs(60))
                .unwrap();

        let mut wrong_uid = exact.clone();
        wrong_uid.metadata.labels.as_mut().unwrap().insert(
            crate::sandbox::SANDBOX_LEASE_UID_LABEL.into(),
            "replacement-lease-uid".into(),
        );
        assert!(!internal_lease_is_for_sandbox(&wrong_uid, &sandbox_lease));

        let mut gc_owned = exact;
        gc_owned.metadata.owner_references = sandbox_lease
            .controller_owner_ref(&())
            .map(|owner| vec![owner]);
        assert!(!internal_lease_is_for_sandbox(&gc_owned, &sandbox_lease));
    }

    /// Provenance is recorded by UID, because a name is not identity.
    ///
    /// A same-named replacement instance is fresh capacity, not proof the
    /// original was destroyed. #80's receipt is checked against these UIDs
    /// precisely so a recreated cluster cannot satisfy a teardown it never
    /// underwent.
    #[test]
    fn provenance_pins_uids_not_names() {
        let sandbox_lease = sandbox_lease();
        let lease =
            build_internal_cluster_lease(&sandbox_lease, "children", Duration::from_secs(60))
                .unwrap();
        let mut lease = lease;
        lease.metadata.uid = Some("internal-lease-uid".into());
        lease.metadata.generation = Some(1);

        let provenance = child_provenance(
            "test-ns",
            "kobe-sandbox",
            &lease,
            "kobe-abc",
            "instance-uid",
            Some(4),
        );

        assert_eq!(provenance.namespace, "kobe-sandbox");
        let placement = crate::crd::ResolvedSandboxPlacement::ChildCluster {
            cluster_pool: SandboxObjectReference {
                api_version: "kobe.kunobi.ninja/v1alpha1".into(),
                kind: "ClusterPool".into(),
                namespace: Some("test-ns".into()),
                name: "children".into(),
                uid: "pool-uid".into(),
                generation: Some(1),
            },
        };
        crate::sandbox::merge_target_provenance(None, provenance.clone(), &placement, "test-ns")
            .expect("the child target namespace must be valid for child placement");

        let recorded_lease = provenance.child_cluster_lease.unwrap();
        assert_eq!(recorded_lease.uid, "internal-lease-uid");
        assert_eq!(recorded_lease.kind, "ClusterLease");

        let instance = provenance.child_cluster_instance.unwrap();
        assert_eq!(instance.namespace.as_deref(), Some("test-ns"));
        assert_eq!(instance.uid, "instance-uid");
        assert_eq!(instance.generation, Some(4));
        assert!(
            !instance.uid.is_empty(),
            "an empty UID would make any replacement satisfy the receipt"
        );
    }

    fn sandbox_pool_with_provisioning(provisioning_timeout: &str) -> SandboxPool {
        let mut pool = crate::controllers::sandbox::tests::management_pool("uid", 1);
        pool.spec.provisioning_timeout = provisioning_timeout.to_string();
        pool
    }

    fn sandbox_lease() -> SandboxLease {
        crate::controllers::sandbox::tests::admitted_lease()
    }
}
