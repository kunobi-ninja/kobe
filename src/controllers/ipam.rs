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
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, ResourceExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::crd::{CIDRClaim, CIDRClaimPhase, CIDRClaimStatus, ClusterInstance};
use crate::pool::cidr_alloc::{PoolPlan, ipam_plan};

pub struct IpamContext {
    pub client: Client,
    pub namespace: String,
    /// Cached plan so reconciles don't reparse every time. The plan
    /// itself is a Rust constant; this is just a convenience.
    pub plan: PoolPlan,
}

#[derive(Debug, thiserror::Error)]
pub enum IpamError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
}

pub async fn run_ipam_controller(client: Client, namespace: &str, shutdown: CancellationToken) {
    let claims: Api<CIDRClaim> = Api::namespaced(client.clone(), namespace);
    let plan = ipam_plan();
    let ctx = Arc::new(IpamContext {
        client,
        namespace: namespace.to_string(),
        plan,
    });

    info!(
        capacity = ctx.plan.capacity(),
        service_block = "10.240.0.0/13",
        cluster_block = "10.248.0.0/13",
        slot_prefix = "/20",
        "Starting IPAM controller"
    );

    let controller = Controller::new(claims, Config::default())
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
            let (used_svc, used_cls) = compute_used(&ctx, &claim).await;
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
            let (used_svc, used_cls) = compute_used(&ctx, &claim).await;
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
async fn compute_used(ctx: &IpamContext, current: &CIDRClaim) -> (Vec<String>, Vec<String>) {
    let mut used_svc = Vec::new();
    let mut used_cls = Vec::new();
    let current_uid = current.metadata.uid.clone();

    let claims_api: Api<CIDRClaim> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    match claims_api.list(&ListParams::default()).await {
        Ok(list) => {
            for c in list.items {
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
        }
        Err(e) => {
            warn!(
                error = %e,
                "Failed to list CIDRClaims for in-use computation; \
                 falling back to plan-only allocation \
                 (risk: reissuing an in-use slot)"
            );
        }
    }

    let instances_api: Api<ClusterInstance> = Api::namespaced(ctx.client.clone(), &ctx.namespace);
    match instances_api.list(&ListParams::default()).await {
        Ok(list) => {
            for inst in list.items {
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
        }
        Err(e) => {
            warn!(
                error = %e,
                "Failed to list ClusterInstances for IPAM adoption sweep; \
                 pre-IPAM allocations may be reissued"
            );
        }
    }

    (used_svc, used_cls)
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

fn validate_static(plan: &PoolPlan, svc: &str, cls: &str) -> Result<(), String> {
    if plan.service.slot_of(svc).is_none() {
        return Err(format!(
            "requestedServiceCidr {svc} is not aligned to the plan's service prefix /{} or is outside the parent block",
            plan.service.slot_prefix
        ));
    }
    if plan.cluster.slot_of(cls).is_none() {
        return Err(format!(
            "requestedClusterCidr {cls} is not aligned to the plan's cluster prefix /{} or is outside the parent block",
            plan.cluster.slot_prefix
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
}
