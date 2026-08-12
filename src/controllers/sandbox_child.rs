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
//! # What this module does NOT do
//!
//! It does not **install** the Agent Sandbox runtime into the child cluster.
//! #74 as filed proposed bootstrapping it there with cluster-admin, which is
//! one of the three effects paused pending approval on #72; #72 shipped
//! `external` mode only, where the operator installs the runtime and Kobe owns
//! nothing. Child placement follows the same rule: the child cluster must
//! already serve a compatible runtime — through the pool's own bootstraps or
//! addons — and Kobe *validates* it. A child without one is refused with a
//! legible error rather than silently granted cluster-admin install rights.
//!
//! That is a real narrowing of #74, and it is recorded here rather than papered
//! over: pools must be configured to bring their own runtime.

use std::time::Duration;

use kube::api::ObjectMeta;
use kube::{Client, Resource, ResourceExt};

use crate::crd::{
    BackendType, CleanupMode, ClusterLease, ClusterLeaseSpec, ClusterPool, Requester, SandboxLease,
    SandboxObjectReference, SandboxPool,
};

/// Grace added on top of provisioning and runtime, so the internal cluster
/// cannot expire while its Sandbox is still being torn down.
///
/// Teardown is not instantaneous — a foreground claim delete waits for the
/// Sandbox to stop, and #80's verification then has to observe the footprint
/// gone. If the child lease expired inside that window, the evidence would
/// disappear along with the cluster and the composition could never report
/// clean completion.
pub const CHILD_DRAIN_GRACE: Duration = Duration::from_secs(15 * 60);

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
         Kobe does not install it: configure the ClusterPool's bootstraps or addons to provide it."
    )]
    ChildRuntimeUnusable { cluster: String, reason: String },
    #[error("child cluster {cluster} is not reachable")]
    ChildUnreachable { cluster: String },
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
            Self::ChildUnreachable { .. } => "child_unreachable",
        }
    }
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
    let name = cluster_pool.name_any();
    if cluster_pool.spec.backend.backend_type != BackendType::K3s {
        return Err(ChildPlacementError::BackendUnsupported {
            pool: sandbox_pool.to_string(),
            cluster_pool: name,
            backend: format!("{:?}", cluster_pool.spec.backend.backend_type).to_lowercase(),
        });
    }
    crate::crd::verified_destroy_eligibility(
        &cluster_pool.spec.cluster,
        cluster_pool.spec.diagnostics.as_ref(),
        // Bind-time condition; see the doc comment above.
        true,
    )
    .map_err(|reason| ChildPlacementError::VerifiedDestroyIneligible {
        cluster_pool: cluster_pool.name_any(),
        reason: reason.to_string(),
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
/// * **Owner-referenced to the `SandboxLease`.** Cancelling or deleting the
///   outer lease garbage-collects the internal one, so a composition abandoned
///   halfway cannot strand a whole cluster.
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
    let owner = sandbox_lease.controller_owner_ref(&())?;
    Some(ClusterLease {
        metadata: ObjectMeta {
            name: Some(internal_lease_name(&sandbox_lease.name_any())),
            namespace: sandbox_lease.namespace(),
            owner_references: Some(vec![owner]),
            labels: Some(
                [(
                    "app.kubernetes.io/managed-by".to_string(),
                    crate::sandbox::KOBE_MANAGED_BY.to_string(),
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        },
        spec: ClusterLeaseSpec {
            pool_ref: cluster_pool_ref.to_string(),
            ttl: format!("{}s", lifetime.as_secs()),
            requester: internal_requester(),
            priority: default_internal_priority(),
            cleanup_mode: Some(CleanupMode::VerifiedDestroy),
        },
        status: None,
    })
}

/// The identity Kobe uses for its own compositions.
///
/// Deliberately not the caller's. An internal lease attributed to a tenant
/// would show up in their listings and read as theirs to release — and
/// releasing it out from under a running Sandbox is precisely the operation
/// this composition exists to prevent them performing.
fn internal_requester() -> Requester {
    Requester {
        requester_type: "kobe:sandbox-composition".to_string(),
        identity: "kobe-operator".to_string(),
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
/// reused in between.
pub fn child_provenance(
    namespace: &str,
    lease: &ClusterLease,
    instance_name: &str,
    instance_uid: &str,
    instance_generation: Option<i64>,
) -> crate::crd::SandboxTargetProvenance {
    crate::crd::SandboxTargetProvenance {
        namespace: namespace.to_string(),
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
            namespace: Some(namespace.to_string()),
            name: instance_name.to_string(),
            uid: instance_uid.to_string(),
            generation: instance_generation,
        }),
        // Upstream object references are filled in by placement once each
        // object exists. Provenance is monotonic: a reference is only ever
        // added, never cleared, so teardown can always name what it must prove
        // absent even after a restart.
        sandbox_template: None,
        sandbox_warm_pool: None,
        sandbox_claim: None,
        sandbox: None,
        pod: None,
    }
}

/// Validate that the child cluster serves a compatible Agent Sandbox runtime.
///
/// The same check #72 applies to the management cluster, pointed at the child.
/// Kobe does not install it: a missing runtime is an error the operator fixes
/// in the `ClusterPool`, not something the controller silently corrects using
/// cluster-admin inside a tenant's cluster.
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
    use crate::crd::ClusterPoolSpec;

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

    /// The internal lease is Kobe's, and dies with the Sandbox lease.
    ///
    /// The owner reference is what makes "cancelling a pending outer lease
    /// releases any partial internal allocation" true without a compensating
    /// code path — and a compensating path is exactly what fails to run when
    /// the controller is the thing that crashed.
    #[test]
    fn the_internal_lease_is_owned_by_the_sandbox_lease_and_never_by_the_caller() {
        let sandbox_lease = sandbox_lease();
        let lease =
            build_internal_cluster_lease(&sandbox_lease, "children", Duration::from_secs(5100))
                .expect("a lease with a UID composes");

        assert_eq!(lease.name_any(), "kobe-sbx-sbx-1");
        assert!(
            lease.name_any().starts_with("kobe-sbx-"),
            "an internal lease must never be mistakable for a tenant one"
        );

        let owner = &lease.metadata.owner_references.as_ref().unwrap()[0];
        assert_eq!(owner.kind, "SandboxLease");
        assert_eq!(owner.uid, "lease-uid-1");
        assert_eq!(owner.controller, Some(true));

        // Verified destroy is requested explicitly. A pool that cannot honour
        // it rejects at bind time instead of quietly downgrading.
        assert_eq!(lease.spec.cleanup_mode, Some(CleanupMode::VerifiedDestroy));

        // The requester is Kobe. Attributing it to the tenant would surface the
        // internal cluster in their listings and read as theirs to release.
        assert_ne!(lease.spec.requester.identity, "alice");
        assert!(lease.spec.requester.requester_type.starts_with("kobe:"));

        assert_eq!(lease.spec.ttl, "5100s");
    }

    /// A Sandbox lease with no UID cannot own anything, so nothing is composed.
    ///
    /// Allocating a cluster with no owner reference is how an abandoned
    /// composition strands one: nothing would ever collect it.
    #[test]
    fn a_lease_without_a_uid_composes_nothing() {
        let mut sandbox_lease = sandbox_lease();
        sandbox_lease.metadata.uid = None;
        assert!(
            build_internal_cluster_lease(&sandbox_lease, "children", Duration::from_secs(60))
                .is_none()
        );
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

        let provenance = child_provenance("kobe", &lease, "kobe-abc", "instance-uid", Some(4));

        let recorded_lease = provenance.child_cluster_lease.unwrap();
        assert_eq!(recorded_lease.uid, "internal-lease-uid");
        assert_eq!(recorded_lease.kind, "ClusterLease");

        let instance = provenance.child_cluster_instance.unwrap();
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
