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
    /// Where `kobe-runner` lives inside the container, if the pool's image
    /// ships one. `None` means this Sandbox cannot provide the durable
    /// execution contract — including exact exit status and `cwd` — and that
    /// API refuses one rather than approximating it with a raw exec stream.
    pub runner_path: Option<String>,
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
    /// More than one live lease carries the alias.
    #[error("more than one sandbox uses this alias")]
    AmbiguousAlias,
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
            Self::AmbiguousAlias => "ambiguous_alias",
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
            // 409 rather than 400: the request is well-formed, and the caller
            // fixes it by changing their leases rather than their command.
            Self::AmbiguousAlias => StatusCode::CONFLICT,
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
    // A direct Kubernetes DELETE sets deletionTimestamp before the lifecycle
    // controller can checkpoint Releasing. Deny immediately: otherwise a
    // caller can open a fresh exec/attach stream in that gap and race cleanup.
    if lease.metadata.deletion_timestamp.is_some() {
        return Err(SandboxAccessDenied::NotReady {
            phase: "Deleting".into(),
        });
    }
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
        // Taken from the pool that admitted this lease, never from the caller.
        // It becomes `argv[0]` of an exec, so a caller who could name it could
        // run anything in the container under Kobe's own credential.
        runner_path: pool.spec.template.runner_path.clone(),
    })
}

impl SandboxTarget {
    /// Resolve a caller-named port against the pool's declaration.
    ///
    /// Accepts a declared name or a declared number, and nothing else. Without
    /// this, port-forward is a general tunnel into the Pod's network namespace
    /// — reaching a debug listener, a metrics endpoint, or anything else bound
    /// on localhost that the administrator never meant to publish.
    pub fn resolve_port(&self, requested: &str) -> Result<u16, SandboxAccessDenied> {
        if let Some(port) = self.ports.iter().find(|port| port.name == requested) {
            return Ok(port.port);
        }
        if let Ok(number) = requested.parse::<u16>()
            && let Some(port) = self.ports.iter().find(|port| port.port == number)
        {
            return Ok(port.port);
        }
        Err(SandboxAccessDenied::NotDeclared { what: "port" })
    }

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

/// Whether a string is a lease id rather than an alias.
///
/// Lease ids are server-generated and always carry the [`LEASE_ID_PREFIX`], so
/// anything else is an alias. Decided by shape rather than by trying one and
/// falling back to the other: a fallback would let a caller who names a lease
/// that has just expired silently reach a *different* lease that happens to
/// use that name as an alias, and find out from its side effects.
///
/// The prefix is shared with the minting site rather than written twice. It
/// was written twice, they disagreed — ids are minted `sandbox-…` while this
/// tested for `sbx-` — and every operation addressed by id fell through to
/// alias resolution and 404'd. Worse than dead: a caller's second lease could
/// take the first lease's id as its ALIAS and silently capture operations
/// aimed at the first, which is exactly the substitution this check exists to
/// prevent.
pub fn looks_like_lease_id(value: &str) -> bool {
    value.starts_with(crate::api::sandbox::LEASE_ID_PREFIX)
}

/// Resolve a caller's alias to exactly one lease id.
///
/// Scoped to the caller, so one tenant's alias can never resolve to another's
/// lease — aliases are chosen by callers, and two tenants picking `dev` is the
/// expected case rather than a collision to break arbitrarily.
///
/// Ambiguity is **refused**, never resolved by picking the newest. A caller
/// with two live leases under one alias has a state they need to see; silently
/// choosing one means their next command lands somewhere they did not expect.
pub async fn resolve_alias(
    client: &kube::Client,
    namespace: &str,
    alias: &str,
    identity: &crate::api::auth::AuthIdentity,
) -> Result<String, SandboxAccessDenied> {
    let candidates = crate::api::sandbox::leases_with_alias(client, namespace, alias, identity)
        .await
        .map_err(|_| SandboxAccessDenied::Backend)?;

    match candidates.len() {
        1 => Ok(candidates.into_iter().next().expect("length checked")),
        // Indistinguishable from a lease that does not exist, for the same
        // reason ownership failures are: the difference is enumerable.
        0 => Err(SandboxAccessDenied::NotFound),
        _ => Err(SandboxAccessDenied::AmbiguousAlias),
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
    // An alias is turned into exactly one id before anything else happens, so
    // every check below is against a real lease rather than a name that might
    // mean several things.
    let resolved = if looks_like_lease_id(lease_name) {
        lease_name.to_string()
    } else {
        resolve_alias(client, namespace, lease_name, identity).await?
    };
    let lease_name = resolved.as_str();

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

/// The cluster a resolved target's operations run against.
///
/// Both variants carry a `Config` rather than only a `Client` because #81
/// re-authenticates: it mints a per-lease token and needs the endpoint and
/// trust anchors *without* the identity that came with them.
pub struct TargetCluster {
    /// Admin-capable client for the cluster the Pod is in. Used only to mint
    /// the scoped credential, never to touch the Pod.
    pub admin: kube::Client,
    /// The configuration a scoped client is rebuilt from.
    pub config: kube::Config,
}

/// Resolve the cluster one target's operations run against.
///
/// Management placement is the operator's own cluster. Child placement follows
/// the provenance recorded at composition — and re-verifies it, because the
/// composition may have been recycled since: the internal `ClusterLease` must
/// still exist with the recorded UID, and its binding must still name the
/// recorded instance.
///
/// A child cluster is never resolved by *name*. The recorded UIDs are what
/// stop a recycled cluster, or a later Sandbox's composition reusing the name,
/// from receiving this caller's exec.
///
/// Constructed per request rather than cached. A cache here would have to be
/// invalidated on lease expiry, revocation, and any UID or provenance change —
/// #83 requires exactly that — and a cache that outlives one of those is worse
/// than no cache at all, because it hands a caller access their lease no longer
/// grants.
pub async fn resolve_target_cluster(
    client: &kube::Client,
    namespace: &str,
    lease: &SandboxLease,
    target: &SandboxTarget,
) -> Result<TargetCluster, SandboxAccessDenied> {
    if target.placement == TargetPlacement::Management {
        let config = crate::api::sandbox_credentials::operator_config()
            .await
            .map_err(|_| SandboxAccessDenied::Backend)?
            .clone();
        return Ok(TargetCluster {
            admin: client.clone(),
            config,
        });
    }

    let provenance = lease
        .status
        .as_ref()
        .and_then(|status| status.target.as_ref())
        .ok_or(SandboxAccessDenied::TargetUnresolved)?;
    let recorded_lease = provenance
        .child_cluster_lease
        .as_ref()
        .ok_or(SandboxAccessDenied::ProvenanceIncomplete)?;
    let recorded_instance = provenance
        .child_cluster_instance
        .as_ref()
        .ok_or(SandboxAccessDenied::ProvenanceIncomplete)?;
    if recorded_lease.uid.is_empty() || recorded_instance.uid.is_empty() {
        return Err(SandboxAccessDenied::ProvenanceIncomplete);
    }

    // The internal lease must still be the exact one this Sandbox was composed
    // onto. A same-named lease belonging to a later composition is somebody
    // else's cluster.
    let internal: Api<crate::crd::ClusterLease> = Api::namespaced(client.clone(), namespace);
    let current = match internal.get(&recorded_lease.name).await {
        Ok(current) => current,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return Err(SandboxAccessDenied::TargetUnresolved);
        }
        Err(_) => return Err(SandboxAccessDenied::Backend),
    };
    if current.uid().as_deref() != Some(recorded_lease.uid.as_str()) {
        return Err(SandboxAccessDenied::TargetUnresolved);
    }

    // And it must still be bound to the recorded instance. A recycled cluster
    // keeps the lease name and changes the instance underneath it, which is
    // precisely the substitution the recorded UID exists to catch.
    let binding = current
        .status
        .as_ref()
        .and_then(|status| status.binding.as_ref())
        .ok_or(SandboxAccessDenied::TargetUnresolved)?;
    if binding.instance.uid != recorded_instance.uid
        || binding.instance.name != recorded_instance.name
    {
        return Err(SandboxAccessDenied::TargetUnresolved);
    }

    // The kubeconfig is read into memory and never leaves it. The error is
    // swallowed rather than propagated: its context can carry the Secret's own
    // contents, and this value reaches a caller-facing status.
    let kubeconfig =
        crate::backend::read_kubeconfig_secret(client, &recorded_instance.name, namespace)
            .await
            .map_err(|_| SandboxAccessDenied::Backend)?;
    let config = crate::backend::virtual_config_from_kubeconfig(&kubeconfig)
        .await
        .map_err(|_| SandboxAccessDenied::Backend)?;
    let admin = kube::Client::try_from(config.clone()).map_err(|_| SandboxAccessDenied::Backend)?;

    Ok(TargetCluster { admin, config })
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

/// The largest command output one exec response may carry.
///
/// The caller controls what they run, so they control how much it prints.
/// Without a cap, `cat /dev/urandom` is a way to make the operator buffer
/// unbounded memory on request — from inside a sandbox that exists precisely
/// because its occupant is not trusted.
pub const MAX_EXEC_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxExecRequest {
    /// argv. Executed directly — never through a shell, which would make
    /// quoting the security boundary.
    pub command: Vec<String>,
    #[serde(default)]
    pub container: Option<String>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxExecResponse {
    pub stdout: String,
    pub stderr: String,
    /// Whether the command exited zero. A numeric exit code is not always
    /// available over this protocol, and inventing one would be worse than
    /// reporting what is actually known.
    pub success: bool,
    /// Exact remote exit status when Kubernetes reported one. `None` means the
    /// transport did not establish an outcome; it is never synthesised.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Whether output was cut off at the cap. Reported rather than silently
    /// truncated: a caller parsing partial output as complete is how a
    /// truncation becomes a wrong answer instead of an obvious one.
    pub truncated: bool,
}

/// Run one command inside the Sandbox and return its bounded output.
///
/// No stdin and no TTY: this is the request/response surface, and both of those
/// need a stream protocol with its own revocation story (#83). No shell either
/// — argv is executed directly, so quoting is never the security boundary.
pub async fn exec_in_sandbox(
    client: &kube::Client,
    target: &SandboxTarget,
    container: &str,
    command: &[String],
    timeout: std::time::Duration,
) -> Result<SandboxExecResponse, SandboxAccessDenied> {
    let raw = exec_capped(
        client,
        target,
        container,
        command,
        None,
        timeout,
        MAX_EXEC_OUTPUT_BYTES,
    )
    .await?;

    Ok(SandboxExecResponse {
        // Lossy on purpose: a sandboxed command's output is arbitrary bytes,
        // and refusing to return anything because byte 900k was not UTF-8
        // would lose the 899k that were.
        stdout: String::from_utf8_lossy(&raw.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&raw.stderr).into_owned(),
        success: raw.success,
        exit_code: raw.exit_code,
        truncated: raw.truncated,
    })
}

/// One exec's raw result, before anything decides what it means.
#[derive(Debug)]
pub struct RawExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub truncated: bool,
}

/// Run one command in the Sandbox, optionally writing to its stdin.
///
/// The stdin half exists for the runner contract (#82) and for nothing else: a
/// tenant's argv is a URL when it travels as exec arguments, and the target
/// apiserver's audit log records that URL verbatim. Sending the command over
/// stdin instead keeps it out of a log Kobe does not own and cannot redact.
///
/// The input is written and the connection's write half is closed immediately.
/// The runner reads a single line precisely so it never has to wait for an EOF
/// that the exec transport may not deliver.
pub async fn exec_capped(
    client: &kube::Client,
    target: &SandboxTarget,
    container: &str,
    command: &[String],
    stdin: Option<&[u8]>,
    timeout: std::time::Duration,
    output_cap: usize,
) -> Result<RawExecOutput, SandboxAccessDenied> {
    use k8s_openapi::api::core::v1::Pod;
    use kube::api::AttachParams;
    if command.is_empty() || command.iter().any(|argument| argument.is_empty()) {
        return Err(SandboxAccessDenied::NotDeclared { what: "command" });
    }

    let pods: Api<Pod> = Api::namespaced(client.clone(), &target.namespace);
    // The name resolved at placement; the identity must still match, or this is
    // a different workload wearing the same name.
    let pod = pods
        .get(&target.pod_name)
        .await
        .map_err(|_| SandboxAccessDenied::TargetUnresolved)?;
    if pod.uid().as_deref() != Some(target.pod_uid.as_str()) {
        return Err(SandboxAccessDenied::TargetUnresolved);
    }

    let params = AttachParams::default()
        .container(container)
        .stdin(stdin.is_some())
        .stdout(true)
        .stderr(true)
        .tty(false);

    let mut attached = tokio::time::timeout(timeout, pods.exec(&target.pod_name, command, &params))
        .await
        .map_err(|_| SandboxAccessDenied::Backend)?
        .map_err(|_| SandboxAccessDenied::Backend)?;

    if let Some(input) = stdin {
        use tokio::io::AsyncWriteExt;
        let Some(mut writer) = attached.stdin() else {
            return Err(SandboxAccessDenied::Backend);
        };
        // A failed write is not swallowed: the command on the other end is
        // waiting for a request it will now never get, and reporting success
        // here would attribute its silence to the workload.
        tokio::time::timeout(timeout, async {
            writer.write_all(input).await?;
            writer.shutdown().await
        })
        .await
        .map_err(|_| SandboxAccessDenied::Backend)?
        .map_err(|_| SandboxAccessDenied::Backend)?;
    }

    let stdout_stream = attached.stdout();
    let stderr_stream = attached.stderr();
    let status = attached.take_status().ok_or(SandboxAccessDenied::Backend)?;

    // Drain both bounded pipes while waiting for status. Reading stdout to EOF
    // before touching stderr deadlocks when the command fills stderr's pipe
    // while Kobe is blocked on stdout (and vice versa).
    let ((stdout, stderr, stdout_truncated, stderr_truncated), status) = tokio::join!(
        drain_capped_pair(stdout_stream, stderr_stream, output_cap, timeout),
        tokio::time::timeout(timeout, status),
    );
    let status = match status {
        Ok(status) => status,
        Err(_) => {
            attached.abort();
            None
        }
    };
    let exit_code = exact_exec_exit_code(status.as_ref());
    let success = exit_code == Some(0);

    Ok(RawExecOutput {
        stdout,
        stderr,
        success,
        exit_code,
        truncated: stdout_truncated || stderr_truncated,
    })
}

/// Drain stdout and stderr concurrently under independent per-stream caps.
///
/// The remote process can block while writing either pipe. Progress on one
/// must therefore never depend on the other reaching EOF first.
async fn drain_capped_pair<Stdout, Stderr>(
    stdout: Option<Stdout>,
    stderr: Option<Stderr>,
    cap: usize,
    timeout: std::time::Duration,
) -> (Vec<u8>, Vec<u8>, bool, bool)
where
    Stdout: tokio::io::AsyncRead + Unpin,
    Stderr: tokio::io::AsyncRead + Unpin,
{
    let stdout_read = async {
        let mut output = Vec::new();
        let truncated = match stdout {
            Some(mut stream) => read_capped(&mut stream, &mut output, cap, timeout).await,
            None => false,
        };
        (output, truncated)
    };
    let stderr_read = async {
        let mut output = Vec::new();
        let truncated = match stderr {
            Some(mut stream) => read_capped(&mut stream, &mut output, cap, timeout).await,
            None => false,
        };
        (output, truncated)
    };
    let ((stdout, stdout_truncated), (stderr, stderr_truncated)) =
        tokio::join!(stdout_read, stderr_read);
    (stdout, stderr, stdout_truncated, stderr_truncated)
}

/// Extract only an exit status Kubernetes actually observed.
///
/// Success is exactly zero. A non-zero remote exit is encoded as an
/// `ExitCode` status cause. Any malformed, missing, or unfamiliar status stays
/// `None`; mapping it to `1` would turn a transport uncertainty into a claim
/// about what the process returned.
fn exact_exec_exit_code(
    status: Option<&k8s_openapi::apimachinery::pkg::apis::meta::v1::Status>,
) -> Option<i32> {
    let status = status?;
    if status.status.as_deref() == Some("Success") {
        return Some(0);
    }
    if status.status.as_deref() != Some("Failure")
        || status.reason.as_deref() != Some("NonZeroExitCode")
    {
        return None;
    }
    status
        .details
        .as_ref()?
        .causes
        .as_ref()?
        .iter()
        .find(|cause| cause.reason.as_deref() == Some("ExitCode"))?
        .message
        .as_deref()?
        .parse::<i32>()
        .ok()
        .filter(|code| (1..=255).contains(code))
}

/// Read at most `cap` bytes, reporting whether more was waiting.
///
/// Stops reading at the cap rather than reading everything and truncating
/// afterwards — the memory is spent either way if you read first.
async fn read_capped<R>(
    stream: &mut R,
    into: &mut Vec<u8>,
    cap: usize,
    timeout: std::time::Duration,
) -> bool
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut limited = stream.take((cap + 1) as u64);
    if tokio::time::timeout(timeout, limited.read_to_end(into))
        .await
        .is_err()
    {
        return true;
    }
    if into.len() > cap {
        into.truncate(cap);
        return true;
    }
    false
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
            service: None,
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

    /// Kubernetes deletion intent revokes before the controller phase catches
    /// up, so no new stream can open while finalizer cleanup is starting.
    #[test]
    fn a_deleting_ready_lease_denies_access_immediately() {
        let mut lease = ready_lease();
        lease.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::from_millisecond(
                    chrono::Utc::now().timestamp_millis(),
                )
                .unwrap(),
            ));

        assert_eq!(
            target_from_provenance(&lease, &pool(), now()).unwrap_err(),
            SandboxAccessDenied::NotReady {
                phase: "Deleting".into()
            }
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

    /// Only pool-declared ports are forwardable.
    ///
    /// Without this, port-forward is a general tunnel into the Pod's network
    /// namespace — reaching a debug listener, a metrics endpoint, or anything
    /// else bound on localhost that the administrator never meant to publish.
    #[test]
    fn only_declared_ports_are_forwardable() {
        let target = target_from_provenance(&ready_lease(), &pool(), now()).unwrap();

        assert_eq!(target.resolve_port("http").unwrap(), 3000);
        assert_eq!(target.resolve_port("3000").unwrap(), 3000);

        for undeclared in ["9090", "22", "ssh", "", "3000 ", "0"] {
            assert_eq!(
                target.resolve_port(undeclared).unwrap_err(),
                SandboxAccessDenied::NotDeclared { what: "port" },
                "port {undeclared:?} must be refused"
            );
        }

        // Alternate spellings of a DECLARED port are fine, and deliberately
        // so: the allowlist is checked against the resolved number, not the
        // string. Refusing `03000` would reject a request for a port the pool
        // published, which is a usability bug rather than a boundary.
        assert_eq!(target.resolve_port("03000").unwrap(), 3000);
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

    /// A caller cannot ask the operator to buffer an unbounded log.
    ///
    /// They control neither how much their agent writes nor how often they
    /// ask. Clamping rather than rejecting is deliberate: refusing an
    /// over-large request teaches callers to retry in a loop, which costs more
    /// than serving the cap once.
    #[test]
    fn a_log_tail_is_always_bounded() {
        assert_eq!(clamp_tail(None), 200);
        assert_eq!(clamp_tail(Some(50)), 50);
        assert_eq!(clamp_tail(Some(MAX_LOG_TAIL_LINES)), MAX_LOG_TAIL_LINES);

        for requested in [MAX_LOG_TAIL_LINES + 1, i64::MAX, 0, -1, i64::MIN] {
            let clamped = clamp_tail(Some(requested));
            assert!(
                (1..=MAX_LOG_TAIL_LINES).contains(&clamped),
                "tail {requested} clamped to {clamped}, outside the permitted range"
            );
        }
    }

    /// Unknown log options are refused, not ignored.
    ///
    /// `follow`, `previous`, `sinceSeconds` and `limitBytes` are all real
    /// `LogParams` options. Silently dropping one a caller sent means they
    /// believe they set a bound that was never applied.
    #[test]
    fn unknown_log_options_are_refused_rather_than_ignored() {
        assert!(
            serde_json::from_value::<SandboxLogsQuery>(
                serde_json::json!({ "tail": 10, "container": "agent" })
            )
            .is_ok()
        );

        for smuggled in [
            "follow",
            "previous",
            "sinceSeconds",
            "limitBytes",
            "podName",
        ] {
            assert!(
                serde_json::from_value::<SandboxLogsQuery>(serde_json::json!({ smuggled: "true" }))
                    .is_err(),
                "{smuggled} must be refused, not ignored"
            );
        }
    }

    /// A command must be argv, and must not be empty.
    ///
    /// An empty argv, or one with an empty element, is a request whose meaning
    /// is decided by the container runtime rather than by the caller — and
    /// there is no reading of "run nothing" that should reach a tenant's
    /// workload.
    #[tokio::test]
    async fn an_empty_command_is_refused_before_the_pod_is_touched() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let target = target_from_provenance(&ready_lease(), &pool(), now()).unwrap();

        for command in [
            vec![],
            vec![String::new()],
            vec!["sh".into(), String::new()],
        ] {
            let error = exec_in_sandbox(
                &client,
                &target,
                "agent",
                &command,
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap_err();
            assert_eq!(
                error,
                SandboxAccessDenied::NotDeclared { what: "command" },
                "command {command:?} must be refused"
            );
        }

        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "a malformed command is refused before the Pod is touched"
        );
    }

    /// Exec requests carry argv and nothing else.
    ///
    /// `tty`, `stdin`, `pod` and `namespace` are all things a caller might try
    /// to send. Silently ignoring one means they believe they set something
    /// that was never applied; accepting one would be worse.
    #[test]
    fn exec_requests_cannot_smuggle_execution_settings() {
        assert!(
            serde_json::from_value::<SandboxExecRequest>(
                serde_json::json!({ "command": ["/agent", "status"] })
            )
            .is_ok()
        );

        for smuggled in [
            "tty",
            "stdin",
            "pod",
            "namespace",
            "container_name",
            "shell",
        ] {
            assert!(
                serde_json::from_value::<SandboxExecRequest>(
                    serde_json::json!({ "command": ["true"], smuggled: "x" })
                )
                .is_err(),
                "{smuggled} must be refused, not ignored"
            );
        }

        // `command` is not optional: there is no default command.
        assert!(serde_json::from_value::<SandboxExecRequest>(serde_json::json!({})).is_err());
    }

    /// Output is capped, and the cap is reported.
    ///
    /// The caller chooses what runs, so they choose how much it prints —
    /// `cat /dev/urandom` from inside a sandbox is otherwise a way to make the
    /// operator buffer unbounded memory on request. Reporting the truncation
    /// matters as much as applying it: a caller parsing partial output as
    /// complete turns a cap into a wrong answer.
    #[tokio::test]
    async fn command_output_is_capped_and_the_truncation_is_reported() {
        let mut into = Vec::new();
        let mut source = std::io::Cursor::new(vec![b'x'; MAX_EXEC_OUTPUT_BYTES * 2]);
        let truncated = read_capped(
            &mut source,
            &mut into,
            MAX_EXEC_OUTPUT_BYTES,
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(truncated, "the caller must be told output was cut off");
        assert_eq!(into.len(), MAX_EXEC_OUTPUT_BYTES);

        // Output that fits is returned whole, and not flagged.
        let mut into = Vec::new();
        let mut source = std::io::Cursor::new(b"hello".to_vec());
        let truncated = read_capped(
            &mut source,
            &mut into,
            MAX_EXEC_OUTPUT_BYTES,
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(!truncated);
        assert_eq!(into, b"hello");

        // Exactly at the cap is not truncation.
        let mut into = Vec::new();
        let mut source = std::io::Cursor::new(vec![b'x'; MAX_EXEC_OUTPUT_BYTES]);
        assert!(
            !read_capped(
                &mut source,
                &mut into,
                MAX_EXEC_OUTPUT_BYTES,
                std::time::Duration::from_secs(5)
            )
            .await
        );
        assert_eq!(into.len(), MAX_EXEC_OUTPUT_BYTES);
    }

    /// Neither output pipe may wait for the other one to close first.
    ///
    /// The writer deliberately fills stderr before touching stdout. A serial
    /// stdout-first reader deadlocks here; the production concurrent drain
    /// lets stderr make room and eventually receives both streams exactly.
    #[tokio::test]
    async fn stdout_and_stderr_are_drained_without_cross_stream_deadlock() {
        use tokio::io::AsyncWriteExt;

        let (mut stdout_writer, stdout_reader) = tokio::io::duplex(8);
        let (mut stderr_writer, stderr_reader) = tokio::io::duplex(8);
        let writer = tokio::spawn(async move {
            stderr_writer.write_all(&[b'e'; 32]).await.unwrap();
            drop(stderr_writer);
            stdout_writer.write_all(&[b'o'; 32]).await.unwrap();
        });

        let (stdout, stderr, stdout_truncated, stderr_truncated) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            drain_capped_pair(
                Some(stdout_reader),
                Some(stderr_reader),
                64,
                std::time::Duration::from_secs(1),
            ),
        )
        .await
        .expect("a concurrent drain must not deadlock");
        writer.await.unwrap();

        assert_eq!(stdout, [b'o'; 32]);
        assert_eq!(stderr, [b'e'; 32]);
        assert!(!stdout_truncated);
        assert!(!stderr_truncated);
    }

    /// Kubernetes reports the exact non-zero code in a structured cause.
    /// Missing or malformed causes remain unknown instead of becoming a
    /// synthesised `1` that the process may never have returned.
    #[test]
    fn an_exec_exit_code_is_exact_or_absent() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Status, StatusCause, StatusDetails};

        let success = Status {
            status: Some("Success".into()),
            ..Default::default()
        };
        assert_eq!(exact_exec_exit_code(Some(&success)), Some(0));

        let failed = Status {
            status: Some("Failure".into()),
            reason: Some("NonZeroExitCode".into()),
            details: Some(StatusDetails {
                causes: Some(vec![StatusCause {
                    reason: Some("ExitCode".into()),
                    message: Some("42".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(exact_exec_exit_code(Some(&failed)), Some(42));

        let mut impossible = failed.clone();
        impossible
            .details
            .as_mut()
            .unwrap()
            .causes
            .as_mut()
            .unwrap()[0]
            .message = Some("-1".into());
        assert_eq!(exact_exec_exit_code(Some(&impossible)), None);
        impossible
            .details
            .as_mut()
            .unwrap()
            .causes
            .as_mut()
            .unwrap()[0]
            .message = Some("256".into());
        assert_eq!(exact_exec_exit_code(Some(&impossible)), None);

        for unknown in [
            None,
            Some(&Status {
                status: Some("Failure".into()),
                reason: Some("NonZeroExitCode".into()),
                ..Default::default()
            }),
            Some(&Status {
                status: Some("Failure".into()),
                reason: Some("TransportError".into()),
                ..Default::default()
            }),
        ] {
            assert_eq!(exact_exec_exit_code(unknown), None);
        }
    }

    fn child_lease_with(cluster_lease_uid: &str, instance_uid: &str) -> SandboxLease {
        let mut lease = ready_lease();
        let status = lease.status.as_mut().unwrap();
        status.placement = Some(ResolvedSandboxPlacement::ChildCluster {
            cluster_pool: reference("ClusterPool", "children", "cluster-pool-uid"),
        });
        let target = status.target.as_mut().unwrap();
        target.child_cluster_lease = Some(reference(
            "ClusterLease",
            "kobe-sbx-sbx-1",
            cluster_lease_uid,
        ));
        target.child_cluster_instance =
            Some(reference("ClusterInstance", "kobe-abc123", instance_uid));
        lease
    }

    fn cluster_lease_json(uid: &str, instance_name: &str, instance_uid: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterLease",
            "metadata": { "name": "kobe-sbx-sbx-1", "namespace": "kobe", "uid": uid },
            "spec": {
                "poolRef": "children",
                "ttl": "2h",
                "requester": { "type": "kobe:sandbox-composition", "identity": "kobe-operator" },
            },
            "status": {
                "phase": "Bound",
                "binding": {
                    "bindingId": "binding-1",
                    "lease": { "name": "kobe-sbx-sbx-1", "uid": uid },
                    "instance": {
                        "name": instance_name,
                        "uid": instance_uid,
                        "observedGeneration": 2,
                    },
                    "pool": { "name": "children", "uid": "cluster-pool-uid" },
                    "backend": { "type": "k3s", "configDigest": "digest" },
                    "instanceSpecDigest": "spec-digest",
                },
            },
        })
    }

    const CLUSTER_LEASE_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/kobe/clusterleases/kobe-sbx-sbx-1";

    /// A recycled child cluster must not receive this lease's operations.
    ///
    /// The internal `ClusterLease` name survives a recycle; the instance
    /// underneath it does not. Resolving by name would send a caller's exec
    /// into whatever cluster now answers to it — a different tenant's, or a
    /// fresh one their lease was never placed on.
    #[tokio::test]
    async fn a_recycled_child_cluster_is_refused() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        // The lease is still there under the recorded UID, but it is now bound
        // to a different instance.
        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(cluster_lease_json(
                "child-lease-uid",
                "kobe-recycled",
                "a-different-instance-uid",
            )))
            .mount(&server)
            .await;

        let lease = child_lease_with("child-lease-uid", "child-instance-uid");
        let target = target_from_provenance(&lease, &pool(), now()).unwrap();
        let error = resolve_target_cluster(&client, "kobe", &lease, &target)
            .await
            .err()
            .expect("a recycled instance must not resolve");
        assert_eq!(error, SandboxAccessDenied::TargetUnresolved);

        // Nothing was read from the child: no kubeconfig Secret was fetched,
        // so no credential could have been minted against the wrong cluster.
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|request| request.url.path().contains("/secrets/"))
                .count(),
            0
        );
    }

    /// A composition whose lease was replaced under the same name is refused.
    #[tokio::test]
    async fn a_name_reused_by_a_later_composition_is_refused() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        Mock::given(method("GET"))
            .and(path(CLUSTER_LEASE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(cluster_lease_json(
                "somebody-elses-lease-uid",
                "kobe-abc123",
                "child-instance-uid",
            )))
            .mount(&server)
            .await;

        let lease = child_lease_with("child-lease-uid", "child-instance-uid");
        let target = target_from_provenance(&lease, &pool(), now()).unwrap();
        assert_eq!(
            resolve_target_cluster(&client, "kobe", &lease, &target)
                .await
                .err()
                .expect("a reused name must not resolve"),
            SandboxAccessDenied::TargetUnresolved
        );
    }

    /// Provenance without UIDs cannot fence a child cluster at all.
    ///
    /// Two absent UIDs compare equal, so a check written against them would
    /// accept any cluster — which is the whole failure this resolution exists
    /// to prevent.
    #[tokio::test]
    async fn child_provenance_without_uids_is_refused() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        for (lease_uid, instance_uid) in [("", "instance"), ("lease", ""), ("", "")] {
            let lease = child_lease_with(lease_uid, instance_uid);
            // `target_from_provenance` is unaffected — the Pod refs are intact —
            // so the refusal has to come from cluster resolution itself.
            let target = target_from_provenance(&lease, &pool(), now()).unwrap();
            assert_eq!(
                resolve_target_cluster(&client, "kobe", &lease, &target)
                    .await
                    .err()
                    .expect("an unfenced child must not resolve"),
                SandboxAccessDenied::ProvenanceIncomplete
            );
        }

        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "unfenced provenance is refused before anything is looked up"
        );
    }

    fn alice() -> crate::api::auth::AuthIdentity {
        crate::api::auth::AuthIdentity {
            provider: "oidc".into(),
            requester_type: "oidc:developer".into(),
            issuer: "https://issuer.invalid".into(),
            identity: "alice".into(),
            policy: crate::api::policy::Policy {
                allowed_pools: vec![],
                max_ttl: chrono::Duration::hours(1),
                max_concurrent_leases: 1,
                default_priority: 50,
                max_extensions: 0,
                sandbox: None,
            },
        }
    }

    fn lease_item(name: &str, identity: &str, alias: &str, phase: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "SandboxLease",
            "metadata": { "name": name, "namespace": "kobe", "uid": name },
            "spec": {
                "poolRef": { "name": "agents", "uid": "p", "generation": 1 },
                "ttl": "1h",
                "alias": alias,
                "requester": {
                    "provider": "oidc",
                    "type": "oidc:developer",
                    "issuer": "https://issuer.invalid",
                    "identity": identity,
                },
            },
            "status": { "phase": phase },
        })
    }

    async fn alias_server(items: Vec<serde_json::Value>) -> (kube::Client, wiremock::MockServer) {
        use wiremock::matchers::method;
        use wiremock::{Mock, ResponseTemplate};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "SandboxLeaseList",
                "metadata": { "resourceVersion": "1" },
                "items": items,
            })))
            .mount(&server)
            .await;
        (client, server)
    }

    /// A minted id must resolve as an id.
    ///
    /// These were written at two sites and silently disagreed: ids were minted
    /// `sandbox-…` while the shape check tested for `sbx-`, so every operation
    /// addressed by id fell through to alias resolution and 404'd. The check
    /// now shares the prefix constant, and this asserts the agreement holds
    /// against a REAL minted id rather than a literal.
    #[test]
    fn an_id_the_server_mints_resolves_as_an_id() {
        let minted = format!("{}1ad3aa5d03bf", crate::api::sandbox::LEASE_ID_PREFIX);
        assert!(
            looks_like_lease_id(&minted),
            "{minted} is a server-minted lease id and must not be treated as an alias"
        );
    }

    /// An alias is never tried as an id, or an id as an alias.
    ///
    /// A fallback between the two is the dangerous shape: a caller naming a
    /// lease that has just expired would silently reach a DIFFERENT lease that
    /// happens to use that name as an alias.
    #[test]
    fn a_lease_id_and_an_alias_are_told_apart_by_shape() {
        assert!(looks_like_lease_id("sandbox-7f3a"));
        for alias in [
            "dev",
            "my-sandbox",
            "sandbox",
            "SANDBOX-1",
            "x-sandbox-1",
            "",
        ] {
            assert!(
                !looks_like_lease_id(alias),
                "{alias:?} must be treated as an alias"
            );
        }
    }

    /// Exactly one live lease resolves.
    #[tokio::test]
    async fn an_unambiguous_alias_resolves_to_its_lease() {
        let (client, _server) =
            alias_server(vec![lease_item("sbx-mine", "alice", "dev", "Ready")]).await;
        assert_eq!(
            resolve_alias(&client, "kobe", "dev", &alice())
                .await
                .unwrap(),
            "sbx-mine"
        );
    }

    /// Two live leases under one alias are refused, never guessed.
    ///
    /// Picking the newest would land a caller's next command somewhere they
    /// did not expect, and they would find out from its side effects. 409
    /// rather than 400: the request is well-formed, and the fix is to their
    /// leases rather than to their command.
    #[tokio::test]
    async fn an_ambiguous_alias_is_refused_rather_than_guessed() {
        let (client, _server) = alias_server(vec![
            lease_item("sbx-one", "alice", "dev", "Ready"),
            lease_item("sbx-two", "alice", "dev", "Provisioning"),
        ])
        .await;

        let error = resolve_alias(&client, "kobe", "dev", &alice())
            .await
            .unwrap_err();
        assert_eq!(error, SandboxAccessDenied::AmbiguousAlias);
        assert_eq!(error.http_status(), axum::http::StatusCode::CONFLICT);
        assert_eq!(error.reason_code(), "ambiguous_alias");
    }

    /// A released lease does not shadow the live one that replaced it.
    ///
    /// Reusing an alias after releasing is the ordinary workflow. If terminal
    /// leases counted, every second use of an alias would be "ambiguous" — and
    /// the feature would be unusable exactly when it is most wanted.
    #[tokio::test]
    async fn terminal_leases_do_not_shadow_a_live_alias() {
        for terminal in ["Released", "Expired", "Quarantined"] {
            let (client, _server) = alias_server(vec![
                lease_item("sbx-old", "alice", "dev", terminal),
                lease_item("sbx-new", "alice", "dev", "Ready"),
            ])
            .await;
            assert_eq!(
                resolve_alias(&client, "kobe", "dev", &alice())
                    .await
                    .unwrap(),
                "sbx-new",
                "a {terminal} lease must not shadow the live one"
            );
        }
    }

    /// The label prefilter is not the authorisation.
    ///
    /// The requester hash narrows the list; each candidate is then re-checked
    /// against the complete principal tuple. The hash is over caller-
    /// influenced values, so a collision would otherwise be enough to reach
    /// another tenant's lease by aliasing it — and the answer is `NotFound`,
    /// not a conflict, because a conflict would confirm it exists.
    #[tokio::test]
    async fn a_lease_that_survives_the_label_filter_is_still_checked() {
        let (client, _server) =
            alias_server(vec![lease_item("sbx-theirs", "mallory", "dev", "Ready")]).await;
        assert_eq!(
            resolve_alias(&client, "kobe", "dev", &alice())
                .await
                .unwrap_err(),
            SandboxAccessDenied::NotFound,
            "another principal's lease must not resolve, however it was labelled"
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
