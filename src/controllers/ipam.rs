//! IPAM controller: binds `CIDRClaim` resources to slices of the
//! kobe IPAM plan (`pool::cidr_alloc::ipam_plan`).
//!
//! ## Responsibilities
//!
//! 1.  Pick a free slot from `ipam_plan()` when a claim enters
//!     `Pending`, write `(serviceCidr, clusterCidr)` back to the
//!     claim's status. The "in-use set" is computed by listing every
//!     `CIDRClaim` in the operator namespace — claims ARE the
//!     allocations, no parallel bookkeeping.
//! 2.  Honour static reservations: a claim with
//!     `spec.requestedServiceCidr` plus `spec.requestedClusterCidr` is
//!     bound to those exact CIDRs iff they are aligned to the plan's
//!     slot prefix and not already taken. Otherwise the claim moves
//!     to `Conflict` with a human-readable `message`.
//!
//! ## Why no finalizer?
//!
//! Because there's no separate bookkeeping to release. Deleting a
//! `CIDRClaim` IS releasing its allocation: next time a `Pending`
//! claim reconciles, the deleted claim's CIDRs are no longer in the
//! list. Kube GC handles owner cleanup; we don't need to interpose.
//!
//! ## Adoption of pre-IPAM allocations
//!
//! Older `ClusterInstance`s have CIDRs in `status.network` but no
//! corresponding `CIDRClaim`. The IPAM controller treats those slots
//! as taken when picking a free slot for a new claim, by unioning
//! every `ClusterInstance.status.network.serviceCidr` (within the
//! plan's parent block) into the in-use set. Migration from the
//! pre-IPAM allocator is therefore implicit: the IPAM controller
//! simply doesn't reissue a slot that's already in use.

use std::sync::Arc;

use chrono::Utc;
use futures::StreamExt;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::{Action, Config as ControllerConfig, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, ResourceExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::crd::{
    CIDRClaim, CIDRClaimPhase, CIDRClaimStatus, CIDRPool, CIDRPoolPhase, CIDRPoolStatus,
    ClusterInstance,
};
use crate::pool::cidr_alloc::{PoolPlan, ipam_plan};

/// Well-known name of the singleton `CIDRPool` the allocator reads to
/// override the built-in address plan. See [`resolve_ipam_plan`].
const CIDRPOOL_SINGLETON: &str = "default";

pub struct IpamContext {
    pub client: Client,
    pub namespace: String,
    /// Cached plan so reconciles don't reparse every time.
    pub plan: PoolPlan,
    /// True when a `CIDRPool/default` is present but INVALID. The operator
    /// explicitly asked to override the address space (almost always because
    /// the host cluster overlaps the built-in `10.240.0.0/13`), so silently
    /// falling back to that default would re-introduce the very host/guest CIDR
    /// collision the override was meant to avoid (guest CoreDNS x509, #42).
    /// Instead we fail closed: refuse to bind claims until the pool is fixed,
    /// so the misconfiguration is loud (pool members stuck) rather than silently
    /// shipping broken-DNS guests.
    pub blocked: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum IpamError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
}

/// Resolve the allocator's address plan at startup. Returns `(plan, blocked)`:
/// - no `CIDRPool/default` (or a transient read error) → built-in [`ipam_plan`],
///   not blocked (the default is correct for every deployment that didn't opt in);
/// - a present + valid pool → that plan, not blocked;
/// - a present but INVALID pool → built-in plan but **blocked = true**, so the
///   controller fails closed (see [`IpamContext::blocked`]) rather than silently
///   shipping guests on the host-colliding default.
///
/// Best-effort patches the pool's status so `kubectl get cidrpool` shows whether
/// the override took effect.
async fn resolve_ipam_plan(client: &Client, namespace: &str) -> (PoolPlan, bool) {
    let pools: Api<CIDRPool> = Api::namespaced(client.clone(), namespace);
    let pool = match pools.get_opt(CIDRPOOL_SINGLETON).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            info!(
                service_block = "10.240.0.0/13",
                cluster_block = "10.248.0.0/13",
                slot_prefix = "/20",
                "No CIDRPool/default found; using built-in IPAM plan"
            );
            return (ipam_plan(), false);
        }
        Err(err) => {
            warn!(error = %err, "Failed to read CIDRPool/default; using built-in IPAM plan");
            return (ipam_plan(), false);
        }
    };

    let spec = &pool.spec;
    match PoolPlan::new(
        &spec.service_cidr,
        spec.service_slot_prefix,
        &spec.cluster_cidr,
        spec.cluster_slot_prefix,
    ) {
        Ok(plan) => {
            info!(
                service_block = %spec.service_cidr,
                cluster_block = %spec.cluster_cidr,
                service_slot_prefix = spec.service_slot_prefix,
                cluster_slot_prefix = spec.cluster_slot_prefix,
                capacity = plan.capacity(),
                "CIDRPool/default accepted as active IPAM plan"
            );
            patch_cidrpool_status(
                &pools,
                CIDRPoolStatus {
                    phase: CIDRPoolPhase::Active,
                    capacity: Some(plan.capacity()),
                    message: None,
                },
            )
            .await;
            (plan, false)
        }
        Err(err) => {
            error!(
                error = %err,
                "CIDRPool/default is invalid; IPAM is FAILING CLOSED — no guest CIDRs will be \
                 allocated until it is fixed. (Falling back to the built-in 10.240.0.0/13 plan \
                 was deliberately avoided: the override implies the host overlaps it, so the \
                 default would re-introduce the guest CoreDNS x509 break, #42.)"
            );
            patch_cidrpool_status(
                &pools,
                CIDRPoolStatus {
                    phase: CIDRPoolPhase::Invalid,
                    capacity: None,
                    message: Some(err.to_string()),
                },
            )
            .await;
            (ipam_plan(), true)
        }
    }
}

/// Status patch on the singleton CIDRPool, retried a few times before giving up
/// (the status is the operator-visible record of which plan is live, so a single
/// transient apiserver blip shouldn't silently leave it stale). Still non-fatal —
/// the resolved plan is already in hand.
async fn patch_cidrpool_status(pools: &Api<CIDRPool>, status: CIDRPoolStatus) {
    let patch = serde_json::json!({ "status": status });
    let pp = PatchParams::default();
    let mut last_err = None;
    for attempt in 1..=3 {
        match pools
            .patch_status(CIDRPOOL_SINGLETON, &pp, &Patch::Merge(&patch))
            .await
        {
            Ok(_) => return,
            Err(err) => {
                last_err = Some(err);
                if attempt < 3 {
                    tokio::time::sleep(std::time::Duration::from_millis(200 * attempt)).await;
                }
            }
        }
    }
    if let Some(err) = last_err {
        warn!(error = %err, "Failed to patch CIDRPool/default status after retries (non-fatal); the live plan may not match CIDRPool.status");
    }
}

pub async fn run_ipam_controller(client: Client, namespace: &str, shutdown: CancellationToken) {
    let claims: Api<CIDRClaim> = Api::namespaced(client.clone(), namespace);
    let (plan, blocked) = resolve_ipam_plan(&client, namespace).await;
    let ctx = Arc::new(IpamContext {
        client,
        namespace: namespace.to_string(),
        plan,
        blocked,
    });

    if blocked {
        error!(
            "IPAM controller starting in FAIL-CLOSED mode (CIDRPool/default invalid); claims will be held in Conflict until it is fixed and the operator restarts"
        );
    } else {
        info!(
            capacity = ctx.plan.capacity(),
            service_block = %ctx.plan.service_block_cidr(),
            cluster_block = %ctx.plan.cluster_block_cidr(),
            "Starting IPAM controller"
        );
    }

    // Serialize allocation: a CIDRClaim binds the lowest free slot computed from
    // the live set of bound claims, so two claims reconciled concurrently can
    // both read the same in-use set and bind identical CIDRs. Capping the
    // controller to one in-flight reconcile makes each binding visible to the
    // next claim's `compute_used`, preventing duplicate allocation. Allocation
    // is cheap and namespace-scoped, so single concurrency is not a bottleneck.
    let controller = Controller::new(claims, Config::default())
        .with_config(ControllerConfig::default().concurrency(1))
        .run(reconcile_claim, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _action)) => {
                    debug!(claim = %obj.name, "CIDRClaim reconciled");
                }
                Err(e) => {
                    error!("CIDRClaim reconciliation error: {e:?}");
                }
            }
        });

    tokio::select! {
        _ = controller => {},
        _ = shutdown.cancelled() => {
            info!("IPAM controller shutting down");
        }
    }
}

fn error_policy(_claim: Arc<CIDRClaim>, err: &IpamError, _ctx: Arc<IpamContext>) -> Action {
    error!("IPAM reconcile error: {err}");
    Action::requeue(std::time::Duration::from_secs(30))
}

async fn reconcile_claim(
    claim: Arc<CIDRClaim>,
    ctx: Arc<IpamContext>,
) -> Result<Action, IpamError> {
    // Deletion: nothing to do — kube GC handles owner cleanup, and the
    // claim's mere absence from the next reconcile's claim list IS the
    // release. No finalizer needed.
    if claim.metadata.deletion_timestamp.is_some() {
        return Ok(Action::await_change());
    }

    let claim_name = claim.name_any();
    let claim_ns = claim.namespace().unwrap_or_else(|| ctx.namespace.clone());
    let claims_api: Api<CIDRClaim> = Api::namespaced(ctx.client.clone(), &claim_ns);

    // #42 fail-closed: an invalid CIDRPool/default means we must NOT allocate
    // from the built-in default (which the override implies the host overlaps).
    // Hold every claim in Conflict — visibly stuck — until it's fixed.
    if ctx.blocked {
        return set_conflict(
            &claims_api,
            &claim,
            "IPAM is failing closed: CIDRPool/default is invalid. No CIDRs will be \
             allocated until it is corrected and the operator restarts."
                .to_string(),
        )
        .await;
    }

    // If already Bound and the bound CIDRs round-trip cleanly through
    // the plan, nothing to do. Re-validating each reconcile catches
    // the case where the plan was changed (e.g. via a code patch) to
    // a narrower block that the existing binding now sits outside.
    if claim
        .status
        .as_ref()
        .map(|s| s.phase == CIDRClaimPhase::Bound)
        .unwrap_or(false)
    {
        let bound_cidrs = claim.status.as_ref().and_then(|s| {
            s.service_cidr
                .as_ref()
                .zip(s.cluster_cidr.as_ref())
                .map(|(svc, cls)| (svc.clone(), cls.clone()))
        });
        if let Some((svc, cls)) = bound_cidrs
            && ctx.plan.service.slot_of(&svc).is_some()
            && ctx.plan.cluster.slot_of(&cls).is_some()
        {
            return Ok(Action::await_change());
        }
        return set_conflict(
            &claims_api,
            &claim,
            "previously bound CIDRs no longer fit the IPAM plan; \
             plan may have been narrowed since binding"
                .to_string(),
        )
        .await;
    }

    // ── Allocate ──────────────────────────────────────────────────────
    let (svc_cidr, cls_cidr) = match (
        claim.spec.requested_service_cidr.as_deref(),
        claim.spec.requested_cluster_cidr.as_deref(),
    ) {
        // Static reservation: both axes pinned by the user.
        (Some(svc), Some(cls)) => {
            if let Err(msg) = validate_static(&ctx.plan, svc, cls) {
                return set_conflict(&claims_api, &claim, msg).await;
            }
            let (used_svc, used_cls) = compute_used(&ctx, &claim).await?;
            if used_svc.iter().any(|x| x == svc) || used_cls.iter().any(|x| x == cls) {
                return set_conflict(
                    &claims_api,
                    &claim,
                    format!("requested CIDR {svc}/{cls} already allocated"),
                )
                .await;
            }
            (svc.to_string(), cls.to_string())
        }
        // One side pinned but not both — currently rejected. We could
        // mix-and-match (free slot for cluster, pinned slot for
        // service) but the value is marginal and the failure modes
        // (mis-paired slots end up at different indices) are
        // surprising. Easier to require all-or-nothing.
        (Some(_), None) | (None, Some(_)) => {
            return set_conflict(
                &claims_api,
                &claim,
                "must pin both requestedServiceCidr and requestedClusterCidr together".to_string(),
            )
            .await;
        }
        // Dynamic allocation.
        (None, None) => {
            let (used_svc, used_cls) = compute_used(&ctx, &claim).await?;
            match ctx.plan.pick_first_free(used_svc, used_cls) {
                Some((_slot, svc, cls)) => (svc, cls),
                None => {
                    return set_conflict(&claims_api, &claim, "IPAM plan is full".to_string())
                        .await;
                }
            }
        }
    };

    set_bound(&claims_api, &claim, &svc_cidr, &cls_cidr).await?;
    info!(
        claim = %claim_name,
        service_cidr = %svc_cidr,
        cluster_cidr = %cls_cidr,
        "CIDRClaim bound"
    );

    Ok(Action::await_change())
}

// ─────────────────────────────────────────────────────────────────────
// In-use set computation
// ─────────────────────────────────────────────────────────────────────

/// Sum of CIDRs currently in use, drawn from two independent sources
/// of truth that must both be respected to avoid reissuing a slot:
///
/// 1. **All other `CIDRClaim`s in the operator namespace** whose
///    status carries assigned CIDRs (Bound, plus Conflict claims that
///    happen to still hold last-known CIDRs from a prior bind). Every
///    `Pending` claim contributes nothing — by definition it hasn't
///    grabbed anything yet.
/// 2. **Pre-IPAM `ClusterInstance.status.network` entries**, only when
///    the recorded CIDR falls inside the IPAM plan's parent block.
///    This makes the migration from the in-status allocator seamless:
///    existing instances aren't disturbed, but their slots are also
///    never reallocated.
///
/// We exclude the claim being reconciled from the "claims" axis so
/// re-reconciling a Bound claim doesn't see itself as a competitor.
///
/// Both lists are load-bearing for collision-freedom, so a transient
/// list error is propagated rather than swallowed: allocating from a
/// partial in-use set could re-issue a slot already held by another
/// claim/instance (a #42-class CIDR collision). The caller fails the
/// reconcile on error, leaving the claim Pending for `error_policy` to
/// retry — strictly safer than binding on an under-populated view.
async fn compute_used(
    ctx: &IpamContext,
    current: &CIDRClaim,
) -> Result<(Vec<String>, Vec<String>), IpamError> {
    let mut used_svc = Vec::new();
    let mut used_cls = Vec::new();
    let current_uid = current.metadata.uid.clone();

    let claims_api: Api<CIDRClaim> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let claim_list = claims_api.list(&ListParams::default()).await?;
    for c in claim_list.items {
        if c.metadata.uid == current_uid && current_uid.is_some() {
            continue;
        }
        let Some(status) = c.status.as_ref() else {
            continue;
        };
        if let Some(svc) = &status.service_cidr {
            used_svc.push(svc.clone());
        }
        if let Some(cls) = &status.cluster_cidr {
            used_cls.push(cls.clone());
        }
    }

    let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    let instance_list = instances_api.list(&ListParams::default()).await?;
    for inst in instance_list.items {
        let Some(net) = inst.status.and_then(|s| s.network) else {
            continue;
        };
        if ctx.plan.service.slot_of(&net.service_cidr).is_some() {
            used_svc.push(net.service_cidr);
        }
        if ctx.plan.cluster.slot_of(&net.cluster_cidr).is_some() {
            used_cls.push(net.cluster_cidr);
        }
    }

    Ok((used_svc, used_cls))
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

fn validate_static(plan: &PoolPlan, svc: &str, cls: &str) -> Result<(), String> {
    let Some(svc_slot) = plan.service.slot_of(svc) else {
        return Err(format!(
            "requestedServiceCidr {svc} is not aligned to the plan's service prefix /{} or is outside the parent block",
            plan.service.slot_prefix
        ));
    };
    let Some(cls_slot) = plan.cluster.slot_of(cls) else {
        return Err(format!(
            "requestedClusterCidr {cls} is not aligned to the plan's cluster prefix /{} or is outside the parent block",
            plan.cluster.slot_prefix
        ));
    };
    // Slot N of the service axis pairs with slot N of the cluster axis
    // (see the design comment in `reconcile_claim`'s "one side pinned"
    // arm). A two-sided reservation that pins service slot A and cluster
    // slot B (A != B) would break that invariant — every dynamic claim
    // assumes the two CIDRs of a slot move together — so reject it.
    if svc_slot != cls_slot {
        return Err(format!(
            "requestedServiceCidr and requestedClusterCidr must be at the same slot index \
             (service {svc} is slot {svc_slot}, cluster {cls} is slot {cls_slot})"
        ));
    }
    Ok(())
}

async fn set_bound(
    claims: &Api<CIDRClaim>,
    claim: &CIDRClaim,
    svc: &str,
    cls: &str,
) -> Result<(), kube::Error> {
    let status = CIDRClaimStatus {
        phase: CIDRClaimPhase::Bound,
        service_cidr: Some(svc.to_string()),
        cluster_cidr: Some(cls.to_string()),
        bound_at: Some(Utc::now().to_rfc3339()),
        message: None,
    };
    let patch = serde_json::json!({ "status": status });
    claims
        .patch_status(
            &claim.name_any(),
            &PatchParams::apply("kobe-operator"),
            &Patch::Merge(&patch),
        )
        .await?;
    // Phase 1 + 2 metric emission: bind duration histogram + outcome
    // counter. Uses `claim.metadata.creation_timestamp` as the start
    // of the Pending→Bound clock, which is precise enough for this
    // controller's reconcile cadence (sub-second to a few seconds).
    let kind = if claim.spec.requested_service_cidr.is_some() {
        crate::metrics::IpamClaimKind::Reservation
    } else {
        crate::metrics::IpamClaimKind::Dynamic
    };
    let elapsed = claim_age_seconds(claim);
    crate::metrics::IPAM_BIND_DURATION
        .with_label_values(&[crate::metrics::IpamClaimOutcome::Bound.as_str()])
        .observe(elapsed);
    crate::metrics::IPAM_CLAIMS_TOTAL
        .with_label_values(&[
            crate::metrics::IpamClaimOutcome::Bound.as_str(),
            kind.as_str(),
        ])
        .inc();
    Ok(())
}

async fn set_conflict(
    claims: &Api<CIDRClaim>,
    claim: &CIDRClaim,
    message: String,
) -> Result<Action, IpamError> {
    let status = CIDRClaimStatus {
        phase: CIDRClaimPhase::Conflict,
        service_cidr: claim.status.as_ref().and_then(|s| s.service_cidr.clone()),
        cluster_cidr: claim.status.as_ref().and_then(|s| s.cluster_cidr.clone()),
        bound_at: claim.status.as_ref().and_then(|s| s.bound_at.clone()),
        message: Some(message.clone()),
    };
    let patch = serde_json::json!({ "status": status });
    claims
        .patch_status(
            &claim.name_any(),
            &PatchParams::apply("kobe-operator"),
            &Patch::Merge(&patch),
        )
        .await?;
    warn!(claim = %claim.name_any(), reason = %message, "CIDRClaim conflict");
    // Same metric instrumentation as the Bound path. Conflict counts
    // are the most actionable IPAM signal — a sudden spike means
    // either the pool is filling up or someone's repeatedly creating
    // claims with bad pinned CIDRs.
    let kind = if claim.spec.requested_service_cidr.is_some() {
        crate::metrics::IpamClaimKind::Reservation
    } else {
        crate::metrics::IpamClaimKind::Dynamic
    };
    let elapsed = claim_age_seconds(claim);
    crate::metrics::IPAM_BIND_DURATION
        .with_label_values(&[crate::metrics::IpamClaimOutcome::Conflict.as_str()])
        .observe(elapsed);
    crate::metrics::IPAM_CLAIMS_TOTAL
        .with_label_values(&[
            crate::metrics::IpamClaimOutcome::Conflict.as_str(),
            kind.as_str(),
        ])
        .inc();
    // Slow requeue so a conflict caused by an in-flight competitor
    // (e.g. our requested CIDR was just released) eventually retries.
    Ok(Action::requeue(std::time::Duration::from_secs(60)))
}

/// Seconds elapsed since the claim was created. Mirrors
/// `instance_age_seconds` in `controllers::instance` — same chrono
/// ↔ jiff conversion pattern.
fn claim_age_seconds(claim: &CIDRClaim) -> f64 {
    claim
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| {
            let created_ms = t.0.as_millisecond();
            let now_ms = Utc::now().timestamp_millis();
            ((now_ms - created_ms).max(0) as f64) / 1000.0
        })
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::CIDRClaimSpec;
    use kube::core::ObjectMeta;

    fn plan() -> PoolPlan {
        ipam_plan()
    }

    fn claim_with_status(
        spec: CIDRClaimSpec,
        status: Option<CIDRClaimStatus>,
        uid: &str,
    ) -> CIDRClaim {
        CIDRClaim {
            metadata: ObjectMeta {
                name: Some(format!("claim-{uid}")),
                namespace: Some("kobe".to_string()),
                uid: Some(uid.to_string()),
                ..Default::default()
            },
            spec,
            status,
        }
    }

    #[test]
    fn validate_static_accepts_aligned_cidrs_inside_plan() {
        let p = plan();
        assert!(validate_static(&p, "10.240.0.0/20", "10.248.0.0/20").is_ok());
        assert!(validate_static(&p, "10.240.80.0/20", "10.248.80.0/20").is_ok());
    }

    #[test]
    fn validate_static_rejects_outside_plan_block() {
        let p = plan();
        assert!(validate_static(&p, "10.43.0.0/20", "10.248.0.0/20").is_err());
    }

    #[test]
    fn validate_static_rejects_unaligned() {
        let p = plan();
        assert!(validate_static(&p, "10.240.8.0/20", "10.248.0.0/20").is_err());
    }

    #[test]
    fn validate_static_rejects_wrong_prefix() {
        let p = plan();
        assert!(validate_static(&p, "10.240.0.0/16", "10.248.0.0/20").is_err());
    }

    // FIX 6: a two-sided reservation must pin both axes at the SAME slot
    // index. Service slot 0 with cluster slot 1 violates the "slot N of
    // service pairs with slot N of cluster" invariant and must be rejected.
    #[test]
    fn validate_static_rejects_mismatched_slot_indices() {
        let p = plan();
        // 10.240.0.0/20 is service slot 0; 10.248.16.0/20 is cluster slot 1.
        let err = validate_static(&p, "10.240.0.0/20", "10.248.16.0/20")
            .expect_err("mismatched slot indices must be rejected");
        assert!(
            err.contains("same slot index"),
            "error should mention the slot-index requirement: {err}"
        );
    }

    // FIX 6 control: aligned, same-slot reservations on both axes still pass.
    #[test]
    fn validate_static_accepts_matching_slot_indices() {
        let p = plan();
        assert!(validate_static(&p, "10.240.16.0/20", "10.248.16.0/20").is_ok());
    }

    #[test]
    fn ipam_plan_is_well_formed() {
        let p = ipam_plan();
        assert_eq!(p.service.cidr_at(0), "10.240.0.0/20");
        assert_eq!(p.cluster.cidr_at(0), "10.248.0.0/20");
        assert_eq!(p.capacity(), 128);
    }

    #[test]
    fn claim_with_bound_status_is_recognised() {
        let c = claim_with_status(
            CIDRClaimSpec {
                requested_service_cidr: None,
                requested_cluster_cidr: None,
            },
            Some(CIDRClaimStatus {
                phase: CIDRClaimPhase::Bound,
                service_cidr: Some("10.240.0.0/20".to_string()),
                cluster_cidr: Some("10.248.0.0/20".to_string()),
                bound_at: Some("2026-04-28T20:00:00Z".to_string()),
                message: None,
            }),
            "u-1",
        );
        assert_eq!(c.status.as_ref().unwrap().phase, CIDRClaimPhase::Bound);
    }

    // #42: a missing CIDRPool/default must yield the built-in plan, so
    // every existing deployment (which has no CIDRPool) is unaffected.
    #[tokio::test]
    async fn resolve_ipam_plan_falls_back_to_default_when_absent() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/cidrpools/default",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let (plan, blocked) = resolve_ipam_plan(&client, "test-ns").await;
        assert!(!blocked, "absent pool must not block allocation");
        assert_eq!(plan.service_block_cidr(), "10.240.0.0/13");
        assert_eq!(plan.cluster_block_cidr(), "10.248.0.0/13");
    }

    // #42: a valid CIDRPool/default relocates the allocator's supernets.
    #[tokio::test]
    async fn resolve_ipam_plan_uses_valid_override() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/cidrpools/default",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "CIDRPool",
                "metadata": { "name": "default", "namespace": "test-ns" },
                "spec": {
                    "serviceCidr": "100.64.0.0/13",
                    "serviceSlotPrefix": 20,
                    "clusterCidr": "100.72.0.0/13",
                    "clusterSlotPrefix": 20
                }
            })))
            .mount(&server)
            .await;
        // Best-effort status patch (Active) — accept it so it isn't noisy.
        Mock::given(method("PATCH"))
            .and(path_regex(".*/cidrpools/default/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "CIDRPool",
                "metadata": { "name": "default", "namespace": "test-ns" },
                "spec": {
                    "serviceCidr": "100.64.0.0/13", "serviceSlotPrefix": 20,
                    "clusterCidr": "100.72.0.0/13", "clusterSlotPrefix": 20
                }
            })))
            .mount(&server)
            .await;

        let (plan, blocked) = resolve_ipam_plan(&client, "test-ns").await;
        assert!(!blocked, "valid override must not block allocation");
        assert_eq!(plan.service_block_cidr(), "100.64.0.0/13");
        assert_eq!(plan.cluster_block_cidr(), "100.72.0.0/13");
    }

    // #42 fail-closed: a present-but-invalid CIDRPool must BLOCK (not silently
    // fall back to the host-colliding built-in default).
    #[tokio::test]
    async fn resolve_ipam_plan_blocks_on_invalid_override() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/cidrpools/default",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "CIDRPool",
                "metadata": { "name": "default", "namespace": "test-ns" },
                // Unaligned service block (10.64.5.0 is not on a /13 boundary).
                "spec": {
                    "serviceCidr": "10.64.5.0/13", "serviceSlotPrefix": 20,
                    "clusterCidr": "10.72.0.0/13", "clusterSlotPrefix": 20
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path_regex(".*/cidrpools/default/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let (_plan, blocked) = resolve_ipam_plan(&client, "test-ns").await;
        assert!(
            blocked,
            "invalid override must fail closed (block allocation)"
        );
    }
}
