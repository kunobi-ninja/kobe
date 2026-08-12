//! Management-cluster placement for Sandbox pools and leases (#73).
//!
//! #71 supplied the projection — [`build_sandbox_template`],
//! [`build_sandbox_warm_pool`], [`build_sandbox_claim`] — and the pure
//! lifecycle transitions. This module is the loop that drives them: it
//! reconciles each `SandboxPool` into controller-owned upstream objects, and
//! each admitted `SandboxLease` into exactly one `SandboxClaim`.
//!
//! # What a caller cannot reach
//!
//! Callers select a `SandboxPool` and nothing else. Every upstream object here
//! is built from the administrator-owned pool spec, named by the controller,
//! and owner-referenced to its Kobe parent. There is no path from lease intent
//! to a Pod spec, a RuntimeClass, a namespace, or a host mount.
//!
//! # Admission is a precondition, not a formality
//!
//! Only leases annotated `admitted` are placed. A `pending` lease may exist
//! before its quota reservation committed, so acting on one would place work
//! that admission never authorised — the reason that annotation exists.

use std::sync::Arc;

use futures::StreamExt;
use kube::api::{Api, ApiResource, DynamicObject, Patch, PatchParams, PostParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, Resource, ResourceExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::api::sandbox::{SANDBOX_ADMISSION_ADMITTED, SANDBOX_ADMISSION_ANNOTATION};
use crate::crd::{SandboxLease, SandboxPlacement, SandboxPool};
use crate::sandbox::{
    AGENT_SANDBOX_API_VERSION, SANDBOX_CLAIM_KIND, SANDBOX_TEMPLATE_KIND, SANDBOX_WARM_POOL_KIND,
    build_sandbox_claim, build_sandbox_template, build_sandbox_warm_pool,
};

/// Shared state for the Sandbox placement controllers.
pub struct SandboxContext {
    pub client: Client,
    /// Operator-owned namespace the upstream objects live in. Never
    /// caller-selectable: a lease that could choose its namespace could place
    /// work next to somebody else's.
    pub namespace: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxPlacementError {
    #[error(transparent)]
    Kubernetes(#[from] kube::Error),
    #[error(transparent)]
    Mapping(#[from] crate::sandbox::SandboxMappingError),
    #[error("{0}")]
    Invalid(String),
}

/// Names are derived, never taken from caller input, so one pool's objects can
/// never collide with or impersonate another's.
fn template_name(pool: &str) -> String {
    format!("kobe-{pool}")
}
fn warm_pool_name(pool: &str) -> String {
    format!("kobe-{pool}")
}
fn claim_name(lease: &str) -> String {
    format!("kobe-{lease}")
}

/// The upstream API resources this controller writes.
///
/// Built by hand rather than discovered: the version is pinned so an
/// incompatible runtime is refused at startup (#72) rather than silently
/// written to here.
fn upstream_resource(kind: &str, plural: &str) -> ApiResource {
    ApiResource {
        group: "extensions.agents.x-k8s.io".into(),
        version: "v1beta1".into(),
        api_version: AGENT_SANDBOX_API_VERSION.into(),
        kind: kind.into(),
        plural: plural.into(),
    }
}

/// Server-side apply, so a drifted upstream object is corrected rather than
/// duplicated, and two replicas reconciling the same pool converge instead of
/// fighting.
async fn apply_upstream(
    client: &Client,
    namespace: &str,
    resource: &ApiResource,
    object: &DynamicObject,
) -> Result<DynamicObject, kube::Error> {
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, resource);
    api.patch(
        &object.name_any(),
        &PatchParams::apply(crate::sandbox::KOBE_MANAGED_BY).force(),
        &Patch::Apply(object),
    )
    .await
}

/// Reconcile one `SandboxPool` into its controller-owned upstream objects.
///
/// Child-placement pools are skipped entirely: composing a child cluster is
/// #74's job, and reconciling their template here would create management-
/// cluster capacity for a pool that must never serve from the management
/// cluster.
pub async fn reconcile_pool(
    pool: Arc<SandboxPool>,
    ctx: Arc<SandboxContext>,
) -> Result<Action, SandboxPlacementError> {
    let name = pool.name_any();
    if !matches!(pool.spec.placement, SandboxPlacement::Management {}) {
        debug!(pool = %name, "not a management-placement pool; skipping");
        return Ok(Action::await_change());
    }

    let owner = pool.controller_owner_ref(&()).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!("SandboxPool {name} has no UID to own its objects"))
    })?;

    let template = build_sandbox_template(
        &template_name(&name),
        &ctx.namespace,
        &pool.spec,
        Some(&owner),
    )?;
    apply_upstream(
        &ctx.client,
        &ctx.namespace,
        &upstream_resource(SANDBOX_TEMPLATE_KIND, "sandboxtemplates"),
        &template,
    )
    .await?;

    let warm_pool = build_sandbox_warm_pool(
        &warm_pool_name(&name),
        &ctx.namespace,
        &template_name(&name),
        pool.spec.warm_capacity,
        Some(&owner),
    )?;
    apply_upstream(
        &ctx.client,
        &ctx.namespace,
        &upstream_resource(SANDBOX_WARM_POOL_KIND, "sandboxwarmpools"),
        &warm_pool,
    )
    .await?;

    debug!(pool = %name, "reconciled upstream template and warm pool");
    Ok(Action::requeue(std::time::Duration::from_secs(120)))
}

/// Reconcile one admitted `SandboxLease` into exactly one `SandboxClaim`.
///
/// Creation is `create`-then-tolerate-409 rather than apply: exactly one claim
/// per lease is the invariant, and a create that loses the race has already
/// been satisfied by whoever won it.
pub async fn reconcile_lease(
    lease: Arc<SandboxLease>,
    ctx: Arc<SandboxContext>,
) -> Result<Action, SandboxPlacementError> {
    let name = lease.name_any();

    // Placement acts only on admitted leases. A `pending` lease may exist
    // before its quota reservation committed; placing one would create work
    // admission never authorised.
    if lease
        .annotations()
        .get(SANDBOX_ADMISSION_ANNOTATION)
        .map(String::as_str)
        != Some(SANDBOX_ADMISSION_ADMITTED)
    {
        debug!(lease = %name, "not admitted; placement declines");
        return Ok(Action::await_change());
    }

    let pools: Api<SandboxPool> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let pool = pools.get(&lease.spec.pool_ref.name).await?;

    // The reference carries UID and generation precisely because a name is not
    // an identity. Between admission and here the pool can be deleted and
    // recreated, or edited — and admission decided quota, placement and image
    // against the spec it actually saw. Placing against anything else runs the
    // caller's workload under configuration nobody admitted them to.
    if pool.uid().as_deref() != Some(lease.spec.pool_ref.uid.as_str()) {
        return Err(SandboxPlacementError::Invalid(format!(
            "lease {name} was admitted against SandboxPool uid {} but {} now has uid {}",
            lease.spec.pool_ref.uid,
            lease.spec.pool_ref.name,
            pool.uid().unwrap_or_else(|| "<none>".into())
        )));
    }
    if pool.metadata.generation.unwrap_or_default() != lease.spec.pool_ref.generation {
        return Err(SandboxPlacementError::Invalid(format!(
            "lease {name} was admitted against SandboxPool generation {} but {} is now generation {}",
            lease.spec.pool_ref.generation,
            lease.spec.pool_ref.name,
            pool.metadata.generation.unwrap_or_default()
        )));
    }

    if !matches!(pool.spec.placement, SandboxPlacement::Management {}) {
        debug!(lease = %name, "child placement is #74's; declining");
        return Ok(Action::await_change());
    }

    let owner = lease.controller_owner_ref(&()).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!("SandboxLease {name} has no UID to own its claim"))
    })?;
    let claim = build_sandbox_claim(
        &claim_name(&name),
        &ctx.namespace,
        &warm_pool_name(&pool.name_any()),
        Some(&owner),
    );

    let resource = upstream_resource(SANDBOX_CLAIM_KIND, "sandboxclaims");
    let claims: Api<DynamicObject> =
        Api::namespaced_with(ctx.client.clone(), &ctx.namespace, &resource);
    match claims.create(&PostParams::default(), &claim).await {
        Ok(_) => info!(lease = %name, "created upstream SandboxClaim"),
        // Already placed. One claim per lease is the invariant, and this
        // reconcile simply lost the race to satisfy it.
        Err(kube::Error::Api(error)) if error.code == 409 => {
            debug!(lease = %name, "claim already exists")
        }
        Err(error) => return Err(error.into()),
    }

    // The claim exists. Everything below turns "an object was created" into a
    // lease that is actually usable and actually bounded.
    let claim = claims.get(&claim_name(&name)).await?;
    if !upstream_claim_is_ready(&claim) {
        debug!(lease = %name, "claim not Ready yet; TTL clock has not started");
        return Ok(Action::requeue(std::time::Duration::from_secs(10)));
    }

    // Runtime TTL starts HERE, at observed readiness — not when the request
    // arrived. A caller must not be billed for however long placement and
    // provisioning took, which is the whole reason the provisioning deadline
    // is a separate bound.
    let runtime_ttl = crate::pool::parse_duration(&lease.spec.ttl).ok_or_else(|| {
        SandboxPlacementError::Invalid(format!("lease {name} has an invalid TTL"))
    })?;
    let status = lease.status.clone().unwrap_or_default();
    let observed_generation = lease.metadata.generation.unwrap_or_default();
    // An already-Ready lease reuses its PERSISTED readiness instant. Passing a
    // fresh `now()` on every requeue would make the transition non-idempotent:
    // it would be refused as a changed timestamp forever, and the backstop
    // below would stop being re-asserted.
    let ready_at = persisted_ready_at(&status).unwrap_or_else(chrono::Utc::now);
    let resource_version = claim.resource_version().unwrap_or_default();

    let next_status = match crate::sandbox::mark_sandbox_ready(
        &status,
        observed_generation,
        ready_at,
        runtime_ttl,
    ) {
        Ok(next) => next,
        // The Sandbox came up, but too late to be worth anything. Leaving
        // it running with no expiry is the unbounded-workload case this
        // whole path exists to prevent, so shut it down upstream NOW and
        // move the lease to Releasing rather than requeue forever.
        Err(crate::sandbox::SandboxLifecycleError::ProvisioningDeadlineElapsed) => {
            warn!(lease = %name, "provisioning deadline elapsed; releasing");
            stamp_upstream_shutdown(
                &claims,
                &claim_name(&name),
                &resource_version,
                chrono::Utc::now(),
            )
            .await?;
            let phase = crate::sandbox::transition_sandbox_phase(
                status.phase,
                crate::crd::SandboxLeasePhase::Releasing,
                false,
            )
            .map_err(|error| SandboxPlacementError::Invalid(error.to_string()))?;
            patch_lease_status(
                &ctx,
                &name,
                &serde_json::json!({ "phase": phase, "message": "provisioning deadline elapsed" }),
            )
            .await?;
            return Ok(Action::await_change());
        }
        Err(error) => {
            debug!(lease = %name, error = %error, "readiness transition declined");
            return Ok(Action::requeue(std::time::Duration::from_secs(30)));
        }
    };

    // Stamp the upstream absolute shutdown time as a BACKSTOP. If Kobe stops
    // reconciling — crash, upgrade, lost credentials — the upstream controller
    // still tears the Sandbox down at the deadline rather than leaving a
    // tenant workload running indefinitely. `DeleteForeground` so the
    // dependents go with it.
    //
    // A missing or unparseable expiry is a HARD failure, not a skipped step:
    // marking the lease Ready without the backstop is exactly the unbounded
    // case, and it would be invisible until someone went looking.
    let expires_at = next_status
        .expires_at
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .ok_or_else(|| {
            SandboxPlacementError::Invalid(format!(
                "lease {name} became Ready without a parseable expiry; refusing to place it unbounded"
            ))
        })?;
    stamp_upstream_shutdown(
        &claims,
        &claim_name(&name),
        &resource_version,
        expires_at.with_timezone(&chrono::Utc),
    )
    .await?;

    // Only now is the lease Ready: the Sandbox exists, and its shutdown is
    // bounded even if this controller never runs again.
    patch_lease_status(&ctx, &name, &serde_json::json!(next_status)).await?;
    info!(lease = %name, "Sandbox lease Ready; runtime TTL started");

    Ok(Action::requeue(std::time::Duration::from_secs(30)))
}

/// The readiness instant already persisted on a Ready lease, if any.
fn persisted_ready_at(
    status: &crate::crd::SandboxLeaseStatus,
) -> Option<chrono::DateTime<chrono::Utc>> {
    if status.phase != crate::crd::SandboxLeasePhase::Ready {
        return None;
    }
    status
        .ready_at
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
}

/// Write the upstream absolute shutdown time and `DeleteForeground` policy.
///
/// Fenced on `resourceVersion`: a claim that changed underneath this reconcile
/// may no longer be the one whose readiness was observed, and stamping a
/// shutdown time onto the wrong generation is how a live Sandbox gets torn
/// down early.
async fn stamp_upstream_shutdown(
    claims: &Api<DynamicObject>,
    claim: &str,
    resource_version: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<(), SandboxPlacementError> {
    let patch = crate::sandbox::build_sandbox_claim_lifecycle_patch(resource_version, at)?;
    claims
        .patch(claim, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    Ok(())
}

async fn patch_lease_status(
    ctx: &SandboxContext,
    lease: &str,
    status: &serde_json::Value,
) -> Result<(), SandboxPlacementError> {
    let leases: Api<SandboxLease> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    leases
        .patch_status(
            lease,
            &PatchParams::apply(crate::sandbox::KOBE_MANAGED_BY),
            &Patch::Merge(&serde_json::json!({ "status": status })),
        )
        .await?;
    Ok(())
}

/// Whether the upstream claim reports a Ready condition.
///
/// Pure and defensive: an unparseable or absent status is NOT ready. Treating
/// "cannot tell" as ready would start the TTL clock on a Sandbox that may never
/// serve, and hand the caller a lease that expires without ever working.
fn upstream_claim_is_ready(claim: &DynamicObject) -> bool {
    claim
        .data
        .get("status")
        .and_then(|status| status.get("conditions"))
        .and_then(|conditions| conditions.as_array())
        .is_some_and(|conditions| {
            conditions.iter().any(|condition| {
                condition.get("type").and_then(|t| t.as_str()) == Some("Ready")
                    && condition.get("status").and_then(|s| s.as_str()) == Some("True")
            })
        })
}

fn pool_error_policy(
    _pool: Arc<SandboxPool>,
    error: &SandboxPlacementError,
    _ctx: Arc<SandboxContext>,
) -> Action {
    warn!(error = %error, "SandboxPool reconcile failed");
    Action::requeue(std::time::Duration::from_secs(30))
}

fn lease_error_policy(
    _lease: Arc<SandboxLease>,
    error: &SandboxPlacementError,
    _ctx: Arc<SandboxContext>,
) -> Action {
    warn!(error = %error, "SandboxLease placement failed");
    Action::requeue(std::time::Duration::from_secs(15))
}

/// Run both placement controllers until shutdown.
pub async fn run_sandbox_controller(client: Client, namespace: &str, shutdown: CancellationToken) {
    let ctx = Arc::new(SandboxContext {
        client: client.clone(),
        namespace: namespace.to_string(),
    });

    let pools: Api<SandboxPool> = Api::namespaced(client.clone(), namespace);
    let leases: Api<SandboxLease> = Api::namespaced(client, namespace);

    info!("Starting Sandbox placement controller (management)");

    let pool_ctx = ctx.clone();
    let pool_shutdown = shutdown.clone();
    let pool_loop = async move {
        Controller::new(pools, Config::default())
            .graceful_shutdown_on(async move { pool_shutdown.cancelled().await })
            .run(reconcile_pool, pool_error_policy, pool_ctx)
            .for_each(|result| async move {
                if let Err(error) = result {
                    error!(error = %error, "SandboxPool controller error");
                }
            })
            .await;
    };

    let lease_shutdown = shutdown.clone();
    let lease_loop = async move {
        Controller::new(leases, Config::default())
            .graceful_shutdown_on(async move { lease_shutdown.cancelled().await })
            .run(reconcile_lease, lease_error_policy, ctx)
            .for_each(|result| async move {
                if let Err(error) = result {
                    error!(error = %error, "SandboxLease controller error");
                }
            })
            .await;
    };

    tokio::join!(pool_loop, lease_loop);
    info!("Sandbox placement controller shut down");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upstream object names are DERIVED, never taken from caller input.
    ///
    /// A lease supplies only a pool reference and an alias; if either reached a
    /// name here, one caller could collide with — or impersonate — another
    /// pool's template or another lease's claim.
    #[test]
    fn upstream_names_are_derived_and_namespaced_by_kind() {
        assert_eq!(template_name("agent-small"), "kobe-agent-small");
        assert_eq!(warm_pool_name("agent-small"), "kobe-agent-small");
        assert_eq!(claim_name("sandbox-abc123"), "kobe-sandbox-abc123");
        // The `kobe-` prefix marks ownership: an object without it was not
        // created by this controller and must never be adopted.
        for derived in [
            template_name("p"),
            warm_pool_name("p"),
            claim_name("sandbox-x"),
        ] {
            assert!(derived.starts_with("kobe-"), "{derived}");
        }
    }

    fn claim_with(status: serde_json::Value) -> DynamicObject {
        let mut claim = DynamicObject::new(
            "kobe-sandbox-x",
            &upstream_resource(SANDBOX_CLAIM_KIND, "sandboxclaims"),
        );
        claim.data = serde_json::json!({ "status": status });
        claim
    }

    /// "Cannot tell" must never read as ready.
    ///
    /// Readiness starts the runtime TTL. Treating an absent, malformed, or
    /// not-yet-populated status as Ready would start the clock on a Sandbox
    /// that may never serve — handing the caller a lease that expires without
    /// ever having worked, which is worse than waiting.
    #[test]
    fn only_an_explicit_ready_condition_starts_the_clock() {
        assert!(upstream_claim_is_ready(&claim_with(serde_json::json!({
            "conditions": [{ "type": "Ready", "status": "True" }]
        }))));

        // Every one of these is "not yet", not "yes".
        for not_ready in [
            serde_json::json!({}),
            serde_json::json!({ "conditions": [] }),
            serde_json::json!({ "conditions": [{ "type": "Ready", "status": "False" }] }),
            serde_json::json!({ "conditions": [{ "type": "Ready", "status": "Unknown" }] }),
            serde_json::json!({ "conditions": [{ "type": "Provisioning", "status": "True" }] }),
            // Malformed shapes must fail closed rather than panic or pass.
            serde_json::json!({ "conditions": "not-an-array" }),
            serde_json::json!({ "conditions": [{ "type": "Ready" }] }),
        ] {
            assert!(
                !upstream_claim_is_ready(&claim_with(not_ready.clone())),
                "must not read as ready: {not_ready}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Reconcile-level fixtures
    //
    // These exercise `reconcile_lease` itself rather than an extracted helper:
    // the bugs that matter here — starting a TTL that was never earned, marking
    // a lease Ready without a shutdown backstop — are bugs in the ORDER of the
    // writes, and an order bug is invisible to a test of any single step.
    // -----------------------------------------------------------------------

    use crate::crd::{
        SandboxContainerResources, SandboxContainerSpec, SandboxExecutionCanary, SandboxIsolation,
        SandboxLeaseSpec, SandboxLeaseStatus, SandboxPoolReference, SandboxPoolSpec,
        SandboxPortSpec, SandboxPrincipal, SandboxReadinessRequirements, SandboxResourceQuantity,
        SandboxTemplateSpec,
    };
    use kube::api::ObjectMeta;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const NS: &str = "test-ns";
    const POOL_UID: &str = "pool-uid-1";
    const POOL_GENERATION: i64 = 3;
    const LEASE: &str = "sbx-1";

    const POOL_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxpools/agents";
    const CLAIMS_PATH: &str =
        "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxclaims";
    const CLAIM_PATH: &str =
        "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxclaims/kobe-sbx-1";
    const LEASE_STATUS_PATH: &str =
        "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/sandboxleases/sbx-1/status";

    async fn test_context() -> (Arc<SandboxContext>, MockServer) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let ctx = Arc::new(SandboxContext {
            client: crate::testutil::mock_k8s_client(&server),
            namespace: NS.to_string(),
        });
        (ctx, server)
    }

    fn quantity(cpu: &str, memory: &str, ephemeral_storage: &str) -> SandboxResourceQuantity {
        SandboxResourceQuantity {
            cpu: cpu.into(),
            memory: memory.into(),
            ephemeral_storage: ephemeral_storage.into(),
        }
    }

    fn management_pool(uid: &str, generation: i64) -> SandboxPool {
        SandboxPool {
            metadata: ObjectMeta {
                name: Some("agents".into()),
                namespace: Some(NS.into()),
                uid: Some(uid.into()),
                generation: Some(generation),
                ..Default::default()
            },
            spec: SandboxPoolSpec {
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
            },
            status: None,
        }
    }

    fn admitted_lease() -> SandboxLease {
        SandboxLease {
            metadata: ObjectMeta {
                name: Some(LEASE.into()),
                namespace: Some(NS.into()),
                uid: Some("lease-uid-1".into()),
                generation: Some(1),
                annotations: Some(
                    [(
                        SANDBOX_ADMISSION_ANNOTATION.to_string(),
                        SANDBOX_ADMISSION_ADMITTED.to_string(),
                    )]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            },
            spec: SandboxLeaseSpec {
                pool_ref: SandboxPoolReference {
                    name: "agents".into(),
                    uid: POOL_UID.into(),
                    generation: POOL_GENERATION,
                },
                ttl: "1h".into(),
                alias: None,
                requester: SandboxPrincipal {
                    provider: "oidc".into(),
                    requester_type: "user".into(),
                    issuer: "https://issuer.invalid".into(),
                    identity: "alice".into(),
                },
            },
            status: Some(SandboxLeaseStatus {
                phase: crate::crd::SandboxLeasePhase::Provisioning,
                observed_generation: Some(1),
                provisioning_deadline: Some(
                    (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
                ),
                ..Default::default()
            }),
        }
    }

    fn claim_json(status: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": AGENT_SANDBOX_API_VERSION,
            "kind": SANDBOX_CLAIM_KIND,
            "metadata": { "name": "kobe-sbx-1", "namespace": NS, "resourceVersion": "77" },
            "status": status,
        })
    }

    async fn requests_to(server: &MockServer, method: &str, target: &str) -> usize {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| request.method.as_str() == method && request.url.path() == target)
            .count()
    }

    /// An unready claim must not start the TTL clock.
    ///
    /// If readiness were assumed, the caller's paid runtime would begin while
    /// the Sandbox was still provisioning — or never came up at all — and the
    /// lease would be handed over already part-spent. The observable proof is
    /// that neither the upstream shutdown time nor the lease status is written.
    #[tokio::test]
    async fn an_unready_claim_starts_no_clock_and_writes_no_status() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION)),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(CLAIMS_PATH))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(claim_json(serde_json::json!({}))),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(claim_json(serde_json::json!({
                    "conditions": [{ "type": "Ready", "status": "False" }]
                }))),
            )
            .mount(&server)
            .await;

        let action = reconcile_lease(Arc::new(admitted_lease()), ctx)
            .await
            .unwrap();
        assert_ne!(
            action,
            Action::await_change(),
            "must come back and re-check"
        );

        assert_eq!(
            requests_to(&server, "PATCH", CLAIM_PATH).await,
            0,
            "no shutdown time may be stamped before readiness"
        );
        assert_eq!(
            requests_to(&server, "PATCH", LEASE_STATUS_PATH).await,
            0,
            "the lease must not be marked Ready before the Sandbox is"
        );
    }

    /// A lease is Ready only once its shutdown is bounded WITHOUT Kobe.
    ///
    /// The upstream `shutdownTime` is the backstop for Kobe crashing, being
    /// upgraded, or losing credentials. If the lease were marked Ready first
    /// and the stamp failed, the caller would hold a working Sandbox whose only
    /// expiry lived in a controller that is, by assumption, not running — a
    /// tenant workload that runs forever.
    #[tokio::test]
    async fn a_failed_shutdown_stamp_leaves_the_lease_unready() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION)),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(CLAIMS_PATH))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 409, "reason": "AlreadyExists"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(CLAIM_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(claim_json(serde_json::json!({
                    "conditions": [{ "type": "Ready", "status": "True" }]
                }))),
            )
            .mount(&server)
            .await;
        // The stamp fails — a conflict, an outage, anything.
        Mock::given(method("PATCH"))
            .and(path(CLAIM_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "kind": "Status", "status": "Failure", "code": 500
            })))
            .mount(&server)
            .await;

        let result = reconcile_lease(Arc::new(admitted_lease()), ctx).await;
        assert!(result.is_err(), "a failed backstop must fail the reconcile");
        assert_eq!(
            requests_to(&server, "PATCH", LEASE_STATUS_PATH).await,
            0,
            "the lease must not be Ready while its shutdown is unbounded"
        );
    }

    /// A pool that is not the one admission saw must not be placed against.
    ///
    /// `poolRef` carries a UID because a name is not an identity: delete and
    /// recreate `agents` with a different image, RuntimeClass or placement and
    /// the name still resolves. Quota, isolation and template were all decided
    /// against the admitted spec, so placing against a new object runs the
    /// caller under configuration nobody admitted them to.
    #[tokio::test]
    async fn a_recreated_pool_is_refused_before_anything_is_placed() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool("a-different-pool-uid", POOL_GENERATION)),
            )
            .mount(&server)
            .await;

        let error = reconcile_lease(Arc::new(admitted_lease()), ctx.clone())
            .await
            .unwrap_err();
        assert!(
            matches!(error, SandboxPlacementError::Invalid(ref message) if message.contains("uid")),
            "expected a UID fence failure, got: {error}"
        );
        assert_eq!(
            requests_to(&server, "POST", CLAIMS_PATH).await,
            0,
            "nothing may be placed against a pool the lease was not admitted against"
        );
    }

    /// An edited pool is refused for the same reason a recreated one is.
    ///
    /// Generation moves on any spec change — a raised warm capacity is
    /// harmless, a swapped image or a downgraded isolation tier is not, and
    /// placement cannot tell which happened.
    #[tokio::test]
    async fn a_mutated_pool_generation_is_refused() {
        let (ctx, server) = test_context().await;
        Mock::given(method("GET"))
            .and(path(POOL_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(management_pool(POOL_UID, POOL_GENERATION + 1)),
            )
            .mount(&server)
            .await;

        let error = reconcile_lease(Arc::new(admitted_lease()), ctx)
            .await
            .unwrap_err();
        assert!(
            matches!(error, SandboxPlacementError::Invalid(ref message) if message.contains("generation")),
            "expected a generation fence failure, got: {error}"
        );
    }

    /// An unadmitted lease is not placed, and the check costs no API call.
    ///
    /// A `pending` lease exists before its quota reservation commits. Placing
    /// one creates real capacity that admission never authorised — the reason
    /// the annotation exists at all.
    #[tokio::test]
    async fn a_pending_lease_is_never_placed() {
        let (ctx, server) = test_context().await;
        let mut lease = admitted_lease();
        lease.metadata.annotations = Some(
            [(
                SANDBOX_ADMISSION_ANNOTATION.to_string(),
                "pending".to_string(),
            )]
            .into_iter()
            .collect(),
        );

        let action = reconcile_lease(Arc::new(lease), ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "placement must decline before it touches the API at all"
        );
    }

    /// The pinned upstream version must match what #72 validates at startup.
    ///
    /// If these drifted, the operator would refuse to start against a runtime
    /// it then wrote to anyway, or worse, accept one and write objects the
    /// installed controller does not understand.
    #[test]
    fn the_written_api_version_matches_the_validated_one() {
        let resource = upstream_resource(SANDBOX_CLAIM_KIND, "sandboxclaims");
        assert_eq!(resource.api_version, AGENT_SANDBOX_API_VERSION);
        assert_eq!(
            resource.api_version,
            crate::sandbox_runtime::REQUIRED_AGENT_SANDBOX_API_VERSION,
            "placement must write the version #72 validates"
        );
    }
}
