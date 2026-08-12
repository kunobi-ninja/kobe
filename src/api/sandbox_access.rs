//! Resolving a Sandbox operation to one exact, owned target (#81).
//!
//! Every Sandbox operation — exec, logs, attach, port-forward — starts here.
//! The caller names a lease; this module answers with **one** typed target or a
//! bounded denial, and never with a default.
//!
//! # Why "never a default" is the whole design
//!
//! A resolver that falls back — to the current namespace, the first container,
//! the only Pod it found — turns a stale or ambiguous request into a
//! *successful* one against the wrong workload. For a Sandbox that means a
//! caller's command running inside somebody else's agent. So every step
//! either produces the exact object recorded at placement time, or denies.
//!
//! # Resolution order
//!
//! ```text
//! authenticated principal
//!   -> owned, Ready, unexpired SandboxLease UID
//!   -> immutable direct/child placement provenance
//!   -> exact Claim/Sandbox/Pod UIDs
//!   -> approved container and declared ports
//! ```
//!
//! Ownership is checked before existence is revealed, and the two failures are
//! deliberately indistinguishable: a caller who can tell "not yours" from "not
//! there" can enumerate other tenants' leases.
//!
//! # What a target is not
//!
//! It is not a Kubernetes capability. Resolving succeeds only for the exact
//! Pod and container this lease owns, and only for ports its pool declared —
//! nothing here can name a Node, a Secret, another namespace, or a second Pod.

use kube::ResourceExt;
use kube::api::Api;

use crate::crd::{ResolvedSandboxPlacement, SandboxLease, SandboxLeasePhase, SandboxPool};

/// One exact, fully identified Sandbox target.
///
/// Every field is a value observed at placement time and re-verified here.
/// Nothing in it is caller-supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxTarget {
    /// The lease this target belongs to, by UID. Carried so an operation that
    /// outlives its resolution can be revoked by lease identity rather than by
    /// name.
    pub lease_uid: String,
    /// Whether the workload runs in Kobe's own cluster or a composed child.
    pub placement: TargetPlacement,
    /// Namespace in the *target* cluster.
    pub namespace: String,
    pub claim_uid: String,
    pub sandbox_name: String,
    pub sandbox_uid: String,
    pub pod_name: String,
    pub pod_uid: String,
    /// The single container operations may address.
    pub container: String,
    /// Ports the pool declared. Nothing else is forwardable.
    pub ports: Vec<DeclaredPort>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetPlacement {
    Management,
    /// Composed child cluster. The caller never learns this, and never learns
    /// which cluster — it changes how Kobe reaches the Pod, not what the caller
    /// may do with it.
    ChildCluster,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredPort {
    pub name: String,
    pub port: u16,
}

/// Why an operation cannot be resolved.
///
/// A closed vocabulary, and deliberately coarse where it faces the caller:
/// several distinct internal failures share `NotFound` precisely so that a
/// caller cannot use the difference to learn about leases that are not theirs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxAccessDenied {
    /// The lease does not exist, or is not this principal's. One reason, on
    /// purpose: distinguishing them lets a caller enumerate other tenants.
    #[error("sandbox not found")]
    NotFound,
    /// It exists and is theirs, but is not currently usable.
    #[error("sandbox is not ready ({phase})")]
    NotReady { phase: String },
    #[error("sandbox lease has expired")]
    Expired,
    /// Placement never finished recording what it built, so there is no exact
    /// target to address. Never resolved by looking one up: a lookup at access
    /// time would find whatever holds the name *now*.
    #[error("sandbox target has not been resolved yet")]
    TargetUnresolved,
    /// The recorded provenance is incomplete or unusable — a reference with no
    /// UID cannot fence anything.
    #[error("sandbox target provenance is incomplete")]
    ProvenanceIncomplete,
    /// The pool that admitted this lease is gone or has changed identity, so
    /// the container and port allowlist cannot be established.
    #[error("sandbox pool is no longer resolvable")]
    PoolUnresolvable,
    /// The caller asked for a container or port the pool never declared.
    #[error("{what} is not part of this sandbox")]
    NotDeclared { what: &'static str },
    #[error("sandbox lookup failed")]
    Backend,
}

impl SandboxAccessDenied {
    /// Bounded reason code for audit records and metrics.
    ///
    /// Distinct per variant even where the caller-facing status collapses
    /// several into one: the operator has to be able to tell "expired" from
    /// "never placed" when someone reports that access stopped working.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::NotReady { .. } => "not_ready",
            Self::Expired => "expired",
            Self::TargetUnresolved => "target_unresolved",
            Self::ProvenanceIncomplete => "provenance_incomplete",
            Self::PoolUnresolvable => "pool_unresolvable",
            Self::NotDeclared { .. } => "not_declared",
            Self::Backend => "backend_error",
        }
    }

    /// The HTTP status a caller sees.
    ///
    /// Everything about *which* lease is 404. A 403 would confirm the lease
    /// exists, which is exactly the fact ownership checking is protecting.
    pub fn http_status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::NotReady { .. } | Self::TargetUnresolved => StatusCode::CONFLICT,
            Self::Expired => StatusCode::GONE,
            Self::NotDeclared { .. } => StatusCode::BAD_REQUEST,
            Self::ProvenanceIncomplete | Self::PoolUnresolvable | Self::Backend => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
    }
}

/// Whether a lease is in a phase that may serve traffic at all.
///
/// `Releasing` is refused even though the Pod may still be up: teardown has
/// started, and letting a new operation attach to a workload that is being
/// destroyed produces a stream that dies mid-flight at best, and interferes
/// with cleanup at worst.
fn phase_permits_access(phase: SandboxLeasePhase) -> Result<(), SandboxAccessDenied> {
    match phase {
        SandboxLeasePhase::Ready => Ok(()),
        SandboxLeasePhase::Expired => Err(SandboxAccessDenied::Expired),
        other => Err(SandboxAccessDenied::NotReady {
            phase: other.to_string(),
        }),
    }
}

/// Whether the lease's own expiry has passed.
///
/// A malformed expiry denies. The alternative — treating an unparseable
/// timestamp as "not expired" — grants access on the strength of a value
/// nobody can read, and the whole point of the expiry is that it bounds what
/// the caller may keep doing.
fn expiry_permits_access(
    expires_at: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), SandboxAccessDenied> {
    let Some(expires_at) = expires_at else {
        // Ready without an expiry should be impossible — placement writes them
        // together — so this is a corrupted state, not an unlimited lease.
        return Err(SandboxAccessDenied::Expired);
    };
    let Ok(expires_at) = chrono::DateTime::parse_from_rfc3339(expires_at) else {
        return Err(SandboxAccessDenied::Expired);
    };
    if now >= expires_at {
        return Err(SandboxAccessDenied::Expired);
    }
    Ok(())
}

/// Resolve the recorded provenance into an addressable target.
///
/// Pure, so the fencing rules are testable without a cluster, and separated
/// from the lookup so that no code path can construct a target from anything
/// other than what placement recorded.
pub fn target_from_provenance(
    lease: &SandboxLease,
    pool: &SandboxPool,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<SandboxTarget, SandboxAccessDenied> {
    let status = lease
        .status
        .as_ref()
        .ok_or(SandboxAccessDenied::TargetUnresolved)?;
    phase_permits_access(status.phase)?;
    expiry_permits_access(status.expires_at.as_deref(), now)?;

    let lease_uid = lease
        .uid()
        .ok_or(SandboxAccessDenied::ProvenanceIncomplete)?;

    // The pool must still be the exact one that admitted this lease. If it was
    // deleted and recreated, its template — and therefore the container and
    // ports a caller may address — is a different administrator's decision.
    if pool.uid().as_deref() != Some(lease.spec.pool_ref.uid.as_str()) {
        return Err(SandboxAccessDenied::PoolUnresolvable);
    }

    let placement = match status.placement {
        Some(ResolvedSandboxPlacement::Management {}) => TargetPlacement::Management,
        Some(ResolvedSandboxPlacement::ChildCluster { .. }) => TargetPlacement::ChildCluster,
        None => return Err(SandboxAccessDenied::TargetUnresolved),
    };

    let target = status
        .target
        .as_ref()
        .ok_or(SandboxAccessDenied::TargetUnresolved)?;
    let claim = target
        .sandbox_claim
        .as_ref()
        .ok_or(SandboxAccessDenied::TargetUnresolved)?;
    let sandbox = target
        .sandbox
        .as_ref()
        .ok_or(SandboxAccessDenied::TargetUnresolved)?;
    let pod = target
        .pod
        .as_ref()
        .ok_or(SandboxAccessDenied::TargetUnresolved)?;

    // A reference with no UID fences nothing: two empty UIDs compare equal, so
    // a later same-named Pod would satisfy the check meant to exclude it.
    if claim.uid.is_empty()
        || sandbox.uid.is_empty()
        || pod.uid.is_empty()
        || pod.name.is_empty()
        || target.namespace.is_empty()
    {
        return Err(SandboxAccessDenied::ProvenanceIncomplete);
    }

    Ok(SandboxTarget {
        lease_uid,
        placement,
        namespace: target.namespace.clone(),
        claim_uid: claim.uid.clone(),
        sandbox_name: sandbox.name.clone(),
        sandbox_uid: sandbox.uid.clone(),
        pod_name: pod.name.clone(),
        pod_uid: pod.uid.clone(),
        // The pool names one default container. A caller cannot choose another:
        // the others, if any, are the administrator's sidecars, not the
        // caller's workload.
        container: pool.spec.template.default_container.clone(),
        ports: pool
            .spec
            .template
            .exposed_ports
            .iter()
            .filter(|port| port.container == pool.spec.template.default_container)
            .map(|port| DeclaredPort {
                name: port.name.clone(),
                port: port.port,
            })
            .collect(),
    })
}

impl SandboxTarget {
    /// Resolve a caller-named container against the allowlist.
    ///
    /// `None` means "the default", which is the only container a caller may
    /// address. Naming any other — including a real sidecar that exists in the
    /// Pod — is refused rather than honoured.
    pub fn resolve_container(&self, requested: Option<&str>) -> Result<&str, SandboxAccessDenied> {
        match requested {
            None => Ok(&self.container),
            Some(name) if name == self.container => Ok(&self.container),
            Some(_) => Err(SandboxAccessDenied::NotDeclared { what: "container" }),
        }
    }
}

/// Resolve one operation, from an authenticated principal to an exact target.
///
/// Ownership is established before anything else is read, and a lease that is
/// absent and a lease that belongs to somebody else produce the identical
/// answer.
pub async fn resolve_sandbox_target(
    client: &kube::Client,
    namespace: &str,
    lease_name: &str,
    identity: &crate::api::auth::AuthIdentity,
) -> Result<(SandboxLease, SandboxTarget), SandboxAccessDenied> {
    let leases: Api<SandboxLease> = Api::namespaced(client.clone(), namespace);
    let lease = match leases.get(lease_name).await {
        Ok(lease) => lease,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return Err(SandboxAccessDenied::NotFound);
        }
        Err(_) => return Err(SandboxAccessDenied::Backend),
    };
    if !crate::api::sandbox::principal_owns_lease(&lease, identity) {
        // Same answer as absent. A caller who can tell these apart can
        // enumerate every lease in the namespace by name.
        return Err(SandboxAccessDenied::NotFound);
    }

    let pools: Api<SandboxPool> = Api::namespaced(client.clone(), namespace);
    let pool = match pools.get(&lease.spec.pool_ref.name).await {
        Ok(pool) => pool,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return Err(SandboxAccessDenied::PoolUnresolvable);
        }
        Err(_) => return Err(SandboxAccessDenied::Backend),
    };

    let target = target_from_provenance(&lease, &pool, chrono::Utc::now())?;
    Ok((lease, target))
}

/// How much of a Sandbox's output one request may return.
///
/// Bounded because the caller controls neither how much their agent writes nor
/// how often they ask. An unbounded read is a way to make the operator buffer
/// a workload's entire log in memory on demand.
pub const MAX_LOG_TAIL_LINES: i64 = 2_000;
const DEFAULT_LOG_TAIL_LINES: i64 = 200;

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxLogsQuery {
    /// Lines from the end. Clamped, never honoured unbounded.
    #[serde(default)]
    pub tail: Option<i64>,
    /// Container name. Only the pool's own container resolves; the field
    /// exists so a wrong value is refused explicitly rather than ignored.
    #[serde(default)]
    pub container: Option<String>,
}

/// Clamp a caller-supplied tail into the permitted range.
///
/// Clamped rather than rejected: a caller asking for more than the cap wants
/// as much as they can have, and failing the request teaches them to retry in
/// a loop, which is worse for everyone.
pub fn clamp_tail(requested: Option<i64>) -> i64 {
    requested
        .unwrap_or(DEFAULT_LOG_TAIL_LINES)
        .clamp(1, MAX_LOG_TAIL_LINES)
}

/// Read a bounded tail of one Sandbox's output.
///
/// The first consumer of the resolver, and deliberately the smallest one: it
/// exercises principal → lease → provenance → Pod → container end to end
/// without needing a stream protocol.
///
/// The Pod is addressed by the **recorded** name in the **recorded** namespace,
/// and its UID re-checked against provenance. A Pod that was replaced since
/// placement is a different workload wearing the same name, and returning its
/// output would show one caller another's logs.
pub async fn read_sandbox_logs(
    client: &kube::Client,
    target: &SandboxTarget,
    container: &str,
    tail_lines: i64,
) -> Result<String, SandboxAccessDenied> {
    use k8s_openapi::api::core::v1::Pod;
    use kube::api::LogParams;

    let pods: Api<Pod> = Api::namespaced(client.clone(), &target.namespace);
    let pod = match pods.get(&target.pod_name).await {
        Ok(pod) => pod,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return Err(SandboxAccessDenied::TargetUnresolved);
        }
        Err(_) => return Err(SandboxAccessDenied::Backend),
    };
    // The name resolved; the identity must too.
    if pod.uid().as_deref() != Some(target.pod_uid.as_str()) {
        return Err(SandboxAccessDenied::TargetUnresolved);
    }

    let params = LogParams {
        container: Some(container.to_string()),
        tail_lines: Some(tail_lines),
        // Never `follow`: this endpoint returns a bounded body, and a followed
        // stream here would hold a connection open with no revocation path.
        follow: false,
        ..Default::default()
    };
    pods.logs(&target.pod_name, &params)
        .await
        .map_err(|_| SandboxAccessDenied::Backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(kind: &str, name: &str, uid: &str) -> crate::crd::SandboxObjectReference {
        crate::crd::SandboxObjectReference {
            api_version: "v1".into(),
            kind: kind.into(),
            namespace: Some("kobe".into()),
            name: name.into(),
            uid: uid.into(),
            generation: None,
        }
    }

    fn ready_lease() -> SandboxLease {
        let mut lease = crate::controllers::sandbox::tests::admitted_lease();
        let status = lease.status.as_mut().unwrap();
        status.phase = SandboxLeasePhase::Ready;
        status.expires_at = Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        status.placement = Some(ResolvedSandboxPlacement::Management {});
        status.target = Some(crate::crd::SandboxTargetProvenance {
            namespace: "kobe".into(),
            child_cluster_lease: None,
            child_cluster_instance: None,
            sandbox_template: None,
            sandbox_warm_pool: None,
            sandbox_claim: Some(reference("SandboxClaim", "kobe-sbx-1", "claim-uid")),
            sandbox: Some(reference("Sandbox", "sbx", "sandbox-uid")),
            pod: Some(reference("Pod", "sbx-0", "pod-uid")),
        });
        lease
    }

    fn pool() -> SandboxPool {
        crate::controllers::sandbox::tests::management_pool("pool-uid-1", 3)
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }

    #[test]
    fn a_ready_lease_resolves_to_its_exact_recorded_objects() {
        let target = target_from_provenance(&ready_lease(), &pool(), now()).unwrap();
        assert_eq!(target.pod_name, "sbx-0");
        assert_eq!(target.pod_uid, "pod-uid");
        assert_eq!(target.claim_uid, "claim-uid");
        assert_eq!(target.sandbox_uid, "sandbox-uid");
        assert_eq!(target.namespace, "kobe");
        assert_eq!(target.placement, TargetPlacement::Management);
        assert_eq!(target.container, "agent");
    }

    /// Every phase short of Ready denies before anything is minted.
    ///
    /// `Releasing` matters most and is the least obvious: the Pod may still be
    /// up, so a laxer check would let a new stream attach to a workload that is
    /// being destroyed — a stream that dies mid-flight at best, and interferes
    /// with cleanup at worst.
    #[test]
    fn only_a_ready_lease_resolves() {
        for phase in [
            SandboxLeasePhase::Pending,
            SandboxLeasePhase::Provisioning,
            SandboxLeasePhase::Releasing,
            SandboxLeasePhase::Released,
            SandboxLeasePhase::Quarantined,
        ] {
            let mut lease = ready_lease();
            lease.status.as_mut().unwrap().phase = phase;
            let error = target_from_provenance(&lease, &pool(), now()).unwrap_err();
            assert!(
                matches!(error, SandboxAccessDenied::NotReady { .. }),
                "{phase} must deny, got {error}"
            );
        }

        let mut expired = ready_lease();
        expired.status.as_mut().unwrap().phase = SandboxLeasePhase::Expired;
        assert_eq!(
            target_from_provenance(&expired, &pool(), now()).unwrap_err(),
            SandboxAccessDenied::Expired
        );
    }

    /// An expiry that cannot be read denies.
    ///
    /// Treating an unparseable or absent timestamp as "not expired" grants
    /// access on the strength of a value nobody can read — and bounding what
    /// the caller may keep doing is the entire job of the expiry.
    #[test]
    fn an_unreadable_expiry_denies_rather_than_grants() {
        for expiry in [None, Some(""), Some("soon"), Some("0")] {
            let mut lease = ready_lease();
            lease.status.as_mut().unwrap().expires_at = expiry.map(str::to_string);
            assert_eq!(
                target_from_provenance(&lease, &pool(), now()).unwrap_err(),
                SandboxAccessDenied::Expired,
                "expiry {expiry:?} must deny"
            );
        }

        // A lease that expired one second ago is expired.
        let mut lease = ready_lease();
        lease.status.as_mut().unwrap().expires_at =
            Some((chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339());
        assert_eq!(
            target_from_provenance(&lease, &pool(), now()).unwrap_err(),
            SandboxAccessDenied::Expired
        );
    }

    /// A target is only ever the objects placement recorded.
    ///
    /// Missing provenance denies rather than triggering a lookup. Looking the
    /// Pod up at access time would find whatever holds the name *now*, which
    /// after a recycle is a different tenant's workload — the exact
    /// substitution the recorded UIDs exist to prevent.
    #[test]
    fn incomplete_provenance_denies_rather_than_falling_back() {
        for what in ["claim", "sandbox", "pod", "namespace"] {
            let mut lease = ready_lease();
            let target = lease.status.as_mut().unwrap().target.as_mut().unwrap();
            match what {
                "claim" => target.sandbox_claim = None,
                "sandbox" => target.sandbox = None,
                "pod" => target.pod = None,
                _ => target.namespace = String::new(),
            }
            let error = target_from_provenance(&lease, &pool(), now()).unwrap_err();
            assert!(
                matches!(
                    error,
                    SandboxAccessDenied::TargetUnresolved
                        | SandboxAccessDenied::ProvenanceIncomplete
                ),
                "missing {what} must deny, got {error}"
            );
        }

        // A reference with an empty UID fences nothing.
        let mut lease = ready_lease();
        lease
            .status
            .as_mut()
            .unwrap()
            .target
            .as_mut()
            .unwrap()
            .pod
            .as_mut()
            .unwrap()
            .uid = String::new();
        assert_eq!(
            target_from_provenance(&lease, &pool(), now()).unwrap_err(),
            SandboxAccessDenied::ProvenanceIncomplete
        );

        // No recorded placement at all.
        let mut lease = ready_lease();
        lease.status.as_mut().unwrap().placement = None;
        assert_eq!(
            target_from_provenance(&lease, &pool(), now()).unwrap_err(),
            SandboxAccessDenied::TargetUnresolved
        );
    }

    /// A pool recreated under the same name cannot supply the allowlist.
    ///
    /// The container and ports a caller may address come from the pool's
    /// template. A replacement pool is a different administrator's decision
    /// about what should be reachable, and applying it to a lease admitted
    /// against the old one silently changes what that caller can do.
    #[test]
    fn a_replaced_pool_denies_rather_than_supplying_a_new_allowlist() {
        let replaced = crate::controllers::sandbox::tests::management_pool("a-different-uid", 3);
        assert_eq!(
            target_from_provenance(&ready_lease(), &replaced, now()).unwrap_err(),
            SandboxAccessDenied::PoolUnresolvable
        );
    }

    /// Only the pool's own container is addressable.
    ///
    /// Anything else in the Pod is the administrator's — a sidecar, an
    /// injected proxy — and executing in one would run the caller's command
    /// with that component's identity and mounts rather than their own.
    #[test]
    fn only_the_declared_container_is_addressable() {
        let target = target_from_provenance(&ready_lease(), &pool(), now()).unwrap();

        assert_eq!(target.resolve_container(None).unwrap(), "agent");
        assert_eq!(target.resolve_container(Some("agent")).unwrap(), "agent");

        for other in ["istio-proxy", "linkerd-proxy", "AGENT", "agent ", ""] {
            assert_eq!(
                target.resolve_container(Some(other)).unwrap_err(),
                SandboxAccessDenied::NotDeclared { what: "container" },
                "container {other:?} must be refused"
            );
        }
    }

    /// The forwardable set is exactly what the pool declared.
    ///
    /// Carried on the target so #83's port-forward cannot improvise one:
    /// without a fixed allowlist it becomes a general tunnel into the Pod's
    /// network namespace, reaching a debug listener or a metrics endpoint the
    /// administrator never meant to publish.
    #[test]
    fn the_target_carries_only_pool_declared_ports() {
        let target = target_from_provenance(&ready_lease(), &pool(), now()).unwrap();
        assert_eq!(
            target.ports,
            vec![DeclaredPort {
                name: "http".into(),
                port: 3000
            }]
        );
    }

    /// Absent and unowned are the same answer to a caller.
    ///
    /// A 403 would confirm the lease exists. That difference is enough to
    /// enumerate every lease in the namespace by guessing names, which is
    /// precisely what ownership checking is supposed to prevent.
    #[test]
    fn not_found_and_not_yours_are_indistinguishable() {
        assert_eq!(
            SandboxAccessDenied::NotFound.http_status(),
            axum::http::StatusCode::NOT_FOUND
        );
        // No variant may map to 403: that status is itself the disclosure.
        for denial in [
            SandboxAccessDenied::NotFound,
            SandboxAccessDenied::NotReady {
                phase: "Pending".into(),
            },
            SandboxAccessDenied::Expired,
            SandboxAccessDenied::TargetUnresolved,
            SandboxAccessDenied::ProvenanceIncomplete,
            SandboxAccessDenied::PoolUnresolvable,
            SandboxAccessDenied::NotDeclared { what: "port" },
            SandboxAccessDenied::Backend,
        ] {
            assert_ne!(
                denial.http_status(),
                axum::http::StatusCode::FORBIDDEN,
                "{denial} must not confirm a lease exists"
            );
            assert!(!denial.reason_code().is_empty());
        }
    }

    /// Child placement resolves through the same path, and says so only
    /// internally.
    ///
    /// #76 asks that both placements behave equivalently; sharing one resolver
    /// is what makes that true rather than asserted. The placement is recorded
    /// on the target because Kobe needs it to pick a client — not because the
    /// caller may know it.
    #[test]
    fn child_placement_resolves_through_the_same_interface() {
        let mut lease = ready_lease();
        lease.status.as_mut().unwrap().placement = Some(ResolvedSandboxPlacement::ChildCluster {
            cluster_pool: reference("ClusterPool", "children", "cluster-pool-uid"),
        });

        let target = target_from_provenance(&lease, &pool(), now()).unwrap();
        assert_eq!(target.placement, TargetPlacement::ChildCluster);
        // Everything else a caller can do is identical.
        assert_eq!(target.container, "agent");
        assert_eq!(target.ports.len(), 1);
        assert_eq!(target.pod_uid, "pod-uid");
    }
}
