use std::sync::Arc;

use futures::StreamExt;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher::Config;
use kube::{Client, ResourceExt};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::api::auth::JwtAuthenticator;
use crate::backend::{BackendFactory, ClusterBackend};
use crate::crd::{ClaimPhase, ClusterClaim, ClusterClaimStatus, ClusterPoolProfile};
use crate::diagnostics;
use crate::pool::{parse_duration, ClusterState, PoolState};

/// Shared state for the claim controller.
pub struct ClaimContext<B: ClusterBackend> {
    pub client: Client,
    pub backend: B,
    /// Reference to pool state shared with profile controller.
    pub pools: Arc<RwLock<std::collections::HashMap<String, PoolState>>>,
    /// Priority queue of pending claims per profile.
    pub queues: RwLock<std::collections::HashMap<String, Vec<PendingClaim>>>,
    /// Operator namespace.
    pub namespace: String,
    /// Authenticator for policy lookups by requester_type.
    pub authenticator: Arc<JwtAuthenticator>,
    /// Optional backend factory for per-profile backend dispatch.
    pub factory: Option<BackendFactory>,
}

/// A pending claim in the priority queue.
#[derive(Debug, Clone)]
pub struct PendingClaim {
    pub claim_name: String,
    pub priority: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Error type for the claim controller.
#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("Lifecycle error: {0}")]
    Lifecycle(#[from] anyhow::Error),
}

/// Start the claim reconciler controller.
pub async fn run_claim_controller<B: ClusterBackend + Clone + 'static>(
    client: Client,
    namespace: &str,
    backend: B,
    pools: Arc<RwLock<std::collections::HashMap<String, PoolState>>>,
    authenticator: Arc<JwtAuthenticator>,
    factory: Option<BackendFactory>,
    shutdown: CancellationToken,
) {
    let claims: Api<ClusterClaim> = Api::namespaced(client.clone(), namespace);

    let ctx = Arc::new(ClaimContext {
        client: client.clone(),
        backend,
        pools,
        queues: RwLock::new(std::collections::HashMap::new()),
        namespace: namespace.to_string(),
        authenticator,
        factory,
    });

    rebuild_queues(&ctx).await;

    let reaper_ctx = ctx.clone();
    let reaper_ns = namespace.to_string();
    let reaper_shutdown = shutdown.clone();
    tokio::spawn(async move {
        run_reaper(reaper_ctx, &reaper_ns, reaper_shutdown).await;
    });

    info!("Starting claim controller");

    let controller = Controller::new(claims, Config::default())
        .run(reconcile_claim, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _action)) => {
                    crate::metrics::RECONCILIATIONS_TOTAL
                        .with_label_values(&["claim", "ok"])
                        .inc();
                    debug!(claim = %obj.name, "Claim reconciled");
                }
                Err(e) => {
                    crate::metrics::RECONCILIATIONS_TOTAL
                        .with_label_values(&["claim", "error"])
                        .inc();
                    error!("Claim reconciliation error: {e:?}");
                }
            }
        });

    tokio::select! {
        _ = controller => {},
        _ = shutdown.cancelled() => {
            info!("Claim controller shutting down");
        },
    }
}

/// Rebuild priority queues from existing Pending ClusterClaim CRDs.
async fn rebuild_queues<B: ClusterBackend>(ctx: &ClaimContext<B>) {
    let claims_api: Api<ClusterClaim> = Api::namespaced(ctx.client.clone(), &ctx.namespace);

    let claims = match claims_api.list(&ListParams::default()).await {
        Ok(list) => list,
        Err(e) => {
            error!("Failed to list claims for queue rebuild: {e}");
            return;
        }
    };

    let mut queues = ctx.queues.write().await;

    for claim in &claims {
        let status = claim.status.clone().unwrap_or_default();
        if status.phase != ClaimPhase::Pending {
            continue;
        }

        let name = claim.name_any();
        let created_at = claim
            .metadata
            .creation_timestamp
            .as_ref()
            .and_then(|ts| {
                chrono::DateTime::parse_from_rfc3339(&ts.0.to_string())
                    .ok()
                    .map(|dt| dt.with_timezone(&chrono::Utc))
            })
            .unwrap_or_else(chrono::Utc::now);

        let queue = queues
            .entry(claim.spec.profile_ref.clone())
            .or_insert_with(Vec::new);

        if !queue.iter().any(|p| p.claim_name == name) {
            queue.push(PendingClaim {
                claim_name: name,
                priority: claim.spec.priority,
                created_at,
            });
        }
    }

    for queue in queues.values_mut() {
        queue.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then(a.created_at.cmp(&b.created_at))
        });
    }

    let total: usize = queues.values().map(|q| q.len()).sum();
    if total > 0 {
        info!(
            pending_claims = total,
            profiles = queues.len(),
            "Rebuilt priority queues from existing CRDs"
        );
    }
}

/// Main reconciliation logic for a ClusterClaim.
#[tracing::instrument(skip_all, fields(claim = %claim.name_any()))]
async fn reconcile_claim<B: ClusterBackend + Clone + 'static>(
    claim: Arc<ClusterClaim>,
    ctx: Arc<ClaimContext<B>>,
) -> Result<Action, ClaimError> {
    let name = claim.name_any();
    let ns = claim.namespace().unwrap_or_else(|| ctx.namespace.clone());
    let claims_api: Api<ClusterClaim> = Api::namespaced(ctx.client.clone(), &ns);

    let status = claim.status.clone().unwrap_or_default();
    let phase = &status.phase;

    match phase {
        ClaimPhase::Pending => {
            info!(claim = %name, profile = %claim.spec.profile_ref, "Reconciling pending claim");

            let created_at = claim
                .metadata
                .creation_timestamp
                .as_ref()
                .and_then(|ts| {
                    chrono::DateTime::parse_from_rfc3339(&ts.0.to_string())
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                })
                .unwrap_or_else(chrono::Utc::now);

            let (is_head, position) = {
                let mut queues = ctx.queues.write().await;
                let queue = queues
                    .entry(claim.spec.profile_ref.clone())
                    .or_insert_with(Vec::new);

                if !queue.iter().any(|p| p.claim_name == name) {
                    queue.push(PendingClaim {
                        claim_name: name.clone(),
                        priority: claim.spec.priority,
                        created_at,
                    });
                    queue.sort_by(|a, b| {
                        b.priority
                            .cmp(&a.priority)
                            .then(a.created_at.cmp(&b.created_at))
                    });
                }

                let pos = queue
                    .iter()
                    .position(|p| p.claim_name == name)
                    .map(|p| p as u32 + 1)
                    .unwrap_or(0);
                let head = queue.first().map(|h| h.claim_name == name).unwrap_or(false);
                (head, pos)
            };

            let patch = serde_json::json!({
                "status": {
                    "phase": "Pending",
                    "queuePosition": position
                }
            });
            claims_api
                .patch_status(
                    &name,
                    &PatchParams::apply("kunobi-pool-operator"),
                    &Patch::Merge(&patch),
                )
                .await?;

            if let Some(profile) = get_profile(&ctx.client, &claim.spec.profile_ref, &ns).await {
                if let Some(scaling) = &profile.spec.scaling {
                    if let Some(timeout) = parse_duration(&scaling.queue_timeout) {
                        let age = chrono::Utc::now() - created_at;
                        if age > timeout {
                            warn!(claim = %name, "Claim exceeded queue timeout, expiring");
                            remove_from_queue(&ctx.queues, &claim.spec.profile_ref, &name).await;
                            let patch = serde_json::json!({
                                "status": { "phase": "Expired" }
                            });
                            claims_api
                                .patch_status(
                                    &name,
                                    &PatchParams::apply("kunobi-pool-operator"),
                                    &Patch::Merge(&patch),
                                )
                                .await?;
                            return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                        }
                    }
                }
            }

            if !is_head {
                debug!(claim = %name, position, "Not queue head, waiting for higher-priority claims");
                return Ok(Action::requeue(std::time::Duration::from_secs(5)));
            }

            let reserved_cluster = {
                let mut pools = ctx.pools.write().await;
                let pool = pools
                    .entry(claim.spec.profile_ref.clone())
                    .or_insert_with(|| PoolState {
                        clusters: std::collections::HashMap::new(),
                    });

                let ready_cluster = pool
                    .clusters
                    .iter()
                    .find(|(_, e)| e.state == ClusterState::Ready)
                    .map(|(name, _)| name.clone());

                if let Some(ref cluster_name) = ready_cluster {
                    if let Some(entry) = pool.clusters.get_mut(cluster_name) {
                        entry.state = ClusterState::Claimed;
                        entry.idle_since = None;
                    }
                }

                ready_cluster
            };

            if let Some(cluster_name) = reserved_cluster {
                let ttl =
                    parse_duration(&claim.spec.ttl).unwrap_or_else(|| chrono::Duration::hours(1));
                let now = chrono::Utc::now();
                let expires_at = now + ttl;

                let policy = ctx
                    .authenticator
                    .policy_for_requester_type(&claim.spec.requester.requester_type)
                    .await;
                let max_extensions = policy.map(|p| p.max_extensions).unwrap_or(2);
                let new_status = ClusterClaimStatus {
                    phase: ClaimPhase::Bound,
                    cluster_name: Some(cluster_name.clone()),
                    bound_at: Some(now.to_rfc3339()),
                    expires_at: Some(expires_at.to_rfc3339()),
                    queue_position: 0,
                    diagnostics_url: None,
                    extensions_count: 0,
                    max_extensions,
                };

                let patch = serde_json::json!({ "status": new_status });
                match claims_api
                    .patch_status(
                        &name,
                        &PatchParams::apply("kunobi-pool-operator"),
                        &Patch::Merge(&patch),
                    )
                    .await
                {
                    Ok(_) => {
                        remove_from_queue(&ctx.queues, &claim.spec.profile_ref, &name).await;

                        let bind_duration =
                            (chrono::Utc::now() - created_at).num_milliseconds() as f64 / 1000.0;
                        crate::metrics::CLAIM_BIND_DURATION
                            .with_label_values(&[&claim.spec.profile_ref])
                            .observe(bind_duration);

                        crate::metrics::CLAIMS_TOTAL
                            .with_label_values(&[claim.spec.profile_ref.as_str(), "bound"])
                            .inc();

                        info!(
                            claim = %name,
                            cluster = %cluster_name,
                            expires_at = %expires_at,
                            bind_seconds = bind_duration,
                            "Claim bound to cluster"
                        );

                        Ok(Action::requeue(std::time::Duration::from_secs(60)))
                    }
                    Err(e) => {
                        warn!(claim = %name, cluster = %cluster_name, "Bind patch failed, rolling back reservation");
                        let mut pools = ctx.pools.write().await;
                        if let Some(pool) = pools.get_mut(&claim.spec.profile_ref) {
                            if let Some(entry) = pool.clusters.get_mut(&cluster_name) {
                                entry.state = ClusterState::Ready;
                                entry.idle_since = Some(chrono::Utc::now());
                            }
                        }
                        Err(ClaimError::Kube(e))
                    }
                }
            } else {
                info!(
                    claim = %name,
                    profile = %claim.spec.profile_ref,
                    priority = claim.spec.priority,
                    "No ready cluster, claim queued at position {position}"
                );

                Ok(Action::requeue(std::time::Duration::from_secs(5)))
            }
        }

        ClaimPhase::Bound => {
            if let Some(expires_at_str) = &status.expires_at {
                match chrono::DateTime::parse_from_rfc3339(expires_at_str) {
                    Ok(expires_at) => {
                        if chrono::Utc::now() > expires_at.with_timezone(&chrono::Utc) {
                            crate::metrics::CLAIMS_TOTAL
                                .with_label_values(&[claim.spec.profile_ref.as_str(), "expired"])
                                .inc();
                            info!(claim = %name, "Claim TTL expired");
                            let patch = serde_json::json!({
                                "status": { "phase": "Expired" }
                            });
                            claims_api
                                .patch_status(
                                    &name,
                                    &PatchParams::apply("kunobi-pool-operator"),
                                    &Patch::Merge(&patch),
                                )
                                .await?;
                            return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                        }
                    }
                    Err(e) => {
                        error!(
                            claim = %name,
                            expires_at = %expires_at_str,
                            "Failed to parse expires_at, force-expiring claim: {e}"
                        );
                        let patch = serde_json::json!({
                            "status": { "phase": "Expired" }
                        });
                        claims_api
                            .patch_status(
                                &name,
                                &PatchParams::apply("kunobi-pool-operator"),
                                &Patch::Merge(&patch),
                            )
                            .await?;
                        return Ok(Action::requeue(std::time::Duration::from_secs(5)));
                    }
                }
            }

            Ok(Action::requeue(std::time::Duration::from_secs(30)))
        }

        ClaimPhase::Released | ClaimPhase::Expired => {
            info!(claim = %name, phase = %phase, "Processing claim termination");

            remove_from_queue(&ctx.queues, &claim.spec.profile_ref, &name).await;

            let patch = serde_json::json!({
                "status": { "phase": "Recycling" }
            });
            claims_api
                .patch_status(
                    &name,
                    &PatchParams::apply("kunobi-pool-operator"),
                    &Patch::Merge(&patch),
                )
                .await?;

            if let Some(cluster_name) = &status.cluster_name {
                let profile = get_profile(&ctx.client, &claim.spec.profile_ref, &ns).await;
                if let Some(ref profile) = profile {
                    if let Some(ref diag_config) = profile.spec.diagnostics {
                        if diag_config.enabled {
                            info!(claim = %name, "Capturing diagnostic bundle");
                            let diag_url = match diagnostics::capture_bundle(
                                cluster_name,
                                &ns,
                                diag_config,
                                &name,
                                &ctx.backend,
                            )
                            .await
                            {
                                Ok(url) => Some(url),
                                Err(e) => {
                                    warn!(
                                        claim = %name,
                                        cluster = %cluster_name,
                                        "Failed to capture diagnostic bundle: {e:#}"
                                    );
                                    None
                                }
                            };

                            if let Some(url) = &diag_url {
                                let patch = serde_json::json!({
                                    "status": { "diagnosticsUrl": url }
                                });
                                if let Err(e) = claims_api
                                    .patch_status(
                                        &name,
                                        &PatchParams::apply("kunobi-pool-operator"),
                                        &Patch::Merge(&patch),
                                    )
                                    .await
                                {
                                    error!(
                                        claim = %name,
                                        diagnostics_url = %url,
                                        "Failed to record diagnostics URL on claim status: {e}"
                                    );
                                }
                            }
                        }
                    }
                }

                let c_name = cluster_name.clone();
                let c_ns = ns.clone();
                let profile_ref = claim.spec.profile_ref.clone();
                let pools = ctx.pools.clone();
                let factory = ctx.factory.clone();
                let profile_for_dispatch = profile.clone();
                let fallback_backend = ctx.backend.clone();
                tokio::spawn(async move {
                    // Use per-profile backend dispatch when factory is available.
                    let delete_result = if let (Some(ref factory), Some(ref p)) =
                        (&factory, &profile_for_dispatch)
                    {
                        match factory.backend_for(p) {
                            Ok(b) => b.delete(&c_name, &c_ns).await,
                            Err(e) => Err(e),
                        }
                    } else {
                        fallback_backend.delete(&c_name, &c_ns).await
                    };
                    match delete_result {
                        Ok(_) => {
                            if let Some(pool) = pools.write().await.get_mut(&profile_ref) {
                                pool.clusters.remove(&c_name);
                            }
                        }
                        Err(e) => {
                            error!(cluster = %c_name, "Failed to delete cluster during recycle: {e}");
                        }
                    }
                });
            } else {
                info!(claim = %name, "No cluster to recycle, claim will be cleaned up");
            }

            Ok(Action::requeue(std::time::Duration::from_secs(10)))
        }

        ClaimPhase::Recycling => {
            let cluster_gone = if let Some(cluster_name) = &status.cluster_name {
                let pools = ctx.pools.read().await;
                pools
                    .get(&claim.spec.profile_ref)
                    .map(|p| !p.clusters.contains_key(cluster_name))
                    .unwrap_or(true)
            } else {
                true
            };

            if cluster_gone {
                info!(claim = %name, "Recycling complete, deleting claim CRD");
                match claims_api.delete(&name, &Default::default()).await {
                    Ok(_) => {}
                    Err(kube::Error::Api(ae)) if ae.code == 404 => {
                        // Already deleted, that's fine
                    }
                    Err(e) => {
                        warn!(claim = %name, "Failed to delete recycled claim CRD: {e}");
                    }
                }
                Ok(Action::await_change())
            } else {
                debug!(claim = %name, "Claim in recycling phase, waiting for cluster cleanup");
                Ok(Action::requeue(std::time::Duration::from_secs(15)))
            }
        }
    }
}

/// Extend a claim's TTL.
pub async fn extend_claim_ttl(
    client: &Client,
    namespace: &str,
    claim_name: &str,
    extend_by: &str,
    authenticator: &JwtAuthenticator,
) -> Result<String, ClaimError> {
    let claims_api: Api<ClusterClaim> = Api::namespaced(client.clone(), namespace);
    let claim = claims_api.get(claim_name).await?;
    let status = claim.status.clone().unwrap_or_default();

    if status.phase != ClaimPhase::Bound {
        return Err(ClaimError::Lifecycle(anyhow::anyhow!(
            "Cannot extend TTL: claim is not in Bound phase (current: {})",
            status.phase
        )));
    }

    if status.extensions_count >= status.max_extensions {
        return Err(ClaimError::Lifecycle(anyhow::anyhow!(
            "Maximum extensions ({}) reached",
            status.max_extensions
        )));
    }

    let extension = parse_duration(extend_by)
        .ok_or_else(|| ClaimError::Lifecycle(anyhow::anyhow!("Invalid duration: {extend_by}")))?;

    let current_expiry = status
        .expires_at
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now);

    let new_expiry = current_expiry + extension;

    let bound_at = status
        .bound_at
        .as_ref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .ok_or_else(|| {
            ClaimError::Lifecycle(anyhow::anyhow!("Claim has no valid bound_at timestamp"))
        })?;

    let policy = authenticator
        .policy_for_requester_type(&claim.spec.requester.requester_type)
        .await;
    if let Some(policy) = &policy {
        let max_expiry = bound_at + policy.max_ttl;
        if new_expiry > max_expiry {
            return Err(ClaimError::Lifecycle(anyhow::anyhow!(
                "Extension would exceed maximum TTL ({}). Max expiry: {}",
                crate::api::policy::format_duration(&policy.max_ttl),
                max_expiry.to_rfc3339()
            )));
        }
    }

    let patch = serde_json::json!({
        "status": {
            "expiresAt": new_expiry.to_rfc3339(),
            "extensionsCount": status.extensions_count + 1
        }
    });
    claims_api
        .patch_status(
            claim_name,
            &PatchParams::apply("kunobi-pool-operator"),
            &Patch::Merge(&patch),
        )
        .await?;

    crate::metrics::CLAIMS_TOTAL
        .with_label_values(&[claim.spec.profile_ref.as_str(), "extended"])
        .inc();

    info!(
        claim = claim_name,
        new_expiry = %new_expiry,
        extension_number = status.extensions_count + 1,
        "Claim TTL extended"
    );

    Ok(new_expiry.to_rfc3339())
}

/// Background reaper that force-expires overdue Bound claims.
async fn run_reaper<B: ClusterBackend>(
    ctx: Arc<ClaimContext<B>>,
    namespace: &str,
    shutdown: CancellationToken,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.cancelled() => {
                info!("Reaper shutting down");
                return;
            },
        }

        let claims_api: Api<ClusterClaim> = Api::namespaced(ctx.client.clone(), namespace);
        let claims = match claims_api.list(&ListParams::default()).await {
            Ok(list) => list,
            Err(e) => {
                error!("Reaper: failed to list claims: {e}");
                continue;
            }
        };

        let now = chrono::Utc::now();

        for claim in claims {
            let name = claim.name_any();
            let status = claim.status.clone().unwrap_or_default();

            if status.phase != ClaimPhase::Bound {
                continue;
            }

            if let Some(expires_at_str) = &status.expires_at {
                match chrono::DateTime::parse_from_rfc3339(expires_at_str) {
                    Ok(expires_at) => {
                        if now > expires_at.with_timezone(&chrono::Utc) {
                            warn!(claim = %name, "Reaper: force-expiring overdue claim");
                            let patch = serde_json::json!({
                                "status": { "phase": "Expired" }
                            });
                            if let Err(e) = claims_api
                                .patch_status(
                                    &name,
                                    &PatchParams::apply("kunobi-pool-operator"),
                                    &Patch::Merge(&patch),
                                )
                                .await
                            {
                                error!(
                                    claim = %name,
                                    "Reaper: failed to force-expire overdue claim: {e}"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            claim = %name,
                            expires_at = %expires_at_str,
                            "Reaper: failed to parse expires_at, force-expiring claim: {e}"
                        );
                        let patch = serde_json::json!({
                            "status": { "phase": "Expired" }
                        });
                        if let Err(e) = claims_api
                            .patch_status(
                                &name,
                                &PatchParams::apply("kunobi-pool-operator"),
                                &Patch::Merge(&patch),
                            )
                            .await
                        {
                            error!(
                                claim = %name,
                                "Reaper: failed to expire claim with corrupt timestamp: {e}"
                            );
                        }
                    }
                }
            }
        }
    }
}

async fn remove_from_queue(
    queues: &RwLock<std::collections::HashMap<String, Vec<PendingClaim>>>,
    profile: &str,
    claim_name: &str,
) {
    let mut queues = queues.write().await;
    if let Some(queue) = queues.get_mut(profile) {
        queue.retain(|p| p.claim_name != claim_name);
    }
}

async fn get_profile(client: &Client, name: &str, namespace: &str) -> Option<ClusterPoolProfile> {
    let profiles_api: Api<ClusterPoolProfile> = Api::namespaced(client.clone(), namespace);
    match profiles_api.get(name).await {
        Ok(profile) => Some(profile),
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            warn!(profile = name, "Profile not found");
            None
        }
        Err(e) => {
            error!(profile = name, "Failed to fetch profile: {e}");
            None
        }
    }
}

fn error_policy<B: ClusterBackend>(
    _claim: Arc<ClusterClaim>,
    error: &ClaimError,
    _ctx: Arc<ClaimContext<B>>,
) -> Action {
    error!("Claim reconciliation error: {error}");
    Action::requeue(std::time::Duration::from_secs(30))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::MockBackend;
    use std::collections::HashMap;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a `ClaimContext<MockBackend>` wired to a local wiremock server.
    async fn test_claim_context() -> (Arc<ClaimContext<MockBackend>>, MockServer) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);
        let backend = MockBackend::new();
        let pools = Arc::new(RwLock::new(HashMap::new()));
        let authenticator = Arc::new(JwtAuthenticator::new());

        let ctx = Arc::new(ClaimContext {
            client,
            backend,
            pools,
            queues: RwLock::new(HashMap::new()),
            namespace: "test-ns".to_string(),
            authenticator,
            factory: None,
        });
        (ctx, server)
    }

    /// Build a `ClusterClaim` CRD object in the given phase.
    fn make_test_claim(name: &str, phase: &str) -> Arc<ClusterClaim> {
        let cluster_name: serde_json::Value =
            if phase == "Bound" || phase == "Released" || phase == "Recycling" {
                serde_json::json!("pool-test-1")
            } else {
                serde_json::json!(null)
            };

        let expires_at: serde_json::Value = if phase == "Bound" {
            let future = chrono::Utc::now() + chrono::Duration::hours(1);
            serde_json::json!(future.to_rfc3339())
        } else {
            serde_json::json!(null)
        };

        Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterClaim",
                "metadata": {
                    "name": name,
                    "namespace": "test-ns"
                },
                "spec": {
                    "profileRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "user@test.com" },
                    "priority": 50
                },
                "status": {
                    "phase": phase,
                    "clusterName": cluster_name,
                    "expiresAt": expires_at,
                    "queuePosition": 0,
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            }))
            .unwrap(),
        )
    }

    /// Build a minimal `ClusterPoolProfile` JSON value for K8s API responses.
    fn make_test_profile() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPoolProfile",
            "metadata": {
                "name": "test-profile",
                "namespace": "test-ns"
            },
            "spec": {
                "poolSize": 3,
                "ttl": "2h",
                "cluster": {
                    "version": "v1.31.3+k3s1"
                }
            }
        })
    }

    // -----------------------------------------------------------------------
    // error_policy
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_error_policy_returns_requeue() {
        let (ctx, _server) = test_claim_context().await;
        let claim = make_test_claim("err-claim", "Pending");
        let error = ClaimError::Lifecycle(anyhow::anyhow!("test error"));
        let action = error_policy(claim, &error, ctx);
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(30)));
    }

    // -----------------------------------------------------------------------
    // remove_from_queue
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_remove_from_queue() {
        let queues = RwLock::new(HashMap::new());
        {
            let mut q = queues.write().await;
            q.insert(
                "test-profile".to_string(),
                vec![
                    PendingClaim {
                        claim_name: "claim-a".to_string(),
                        priority: 100,
                        created_at: chrono::Utc::now(),
                    },
                    PendingClaim {
                        claim_name: "claim-b".to_string(),
                        priority: 50,
                        created_at: chrono::Utc::now(),
                    },
                ],
            );
        }

        remove_from_queue(&queues, "test-profile", "claim-a").await;

        let q = queues.read().await;
        let queue = q.get("test-profile").unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].claim_name, "claim-b");
    }

    #[tokio::test]
    async fn test_remove_from_queue_nonexistent_profile() {
        let queues = RwLock::new(HashMap::new());
        // Should not panic when profile does not exist.
        remove_from_queue(&queues, "no-such-profile", "claim-x").await;
        assert!(queues.read().await.is_empty());
    }

    // -----------------------------------------------------------------------
    // reconcile_claim: Pending — no ready clusters
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_pending_claim_no_ready_clusters() {
        let (ctx, server) = test_claim_context().await;
        let claim = make_test_claim("pending-1", "Pending");

        // Mock the status PATCH that the reconciler issues to update queue position.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterclaims/pending-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterClaim",
                "metadata": { "name": "pending-1", "namespace": "test-ns" },
                "spec": { "profileRef": "test-profile", "ttl": "1h",
                           "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": { "phase": "Pending", "queuePosition": 1 }
            })))
            .mount(&server)
            .await;

        // Mock GET for profile (return 404 — no profile, so no queue timeout logic).
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpoolprofiles/test-profile",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "clusterpoolprofiles",
                    "test-profile",
                )),
            )
            .mount(&server)
            .await;

        let action = reconcile_claim(claim, ctx).await.unwrap();
        // No ready cluster → requeue at 5s.
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(5)));
    }

    // -----------------------------------------------------------------------
    // reconcile_claim: Pending — binds to a ready cluster
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_pending_claim_binds_to_ready_cluster() {
        let (ctx, server) = test_claim_context().await;
        let claim = make_test_claim("bind-1", "Pending");

        // Pre-populate pool state with a ready cluster.
        {
            let mut pools = ctx.pools.write().await;
            let mut clusters = std::collections::HashMap::new();
            clusters.insert(
                "pool-test-1".to_string(),
                crate::pool::ClusterEntry {
                    state: ClusterState::Ready,
                    idle_since: Some(chrono::Utc::now()),
                    health_failures: 0,
                    state_since: Some(chrono::Utc::now()),
                    spec_hash: None,
                },
            );
            pools.insert("test-profile".to_string(), PoolState { clusters });
        }

        // Mock PATCH for queue-position status update.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterclaims/bind-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterClaim",
                "metadata": { "name": "bind-1", "namespace": "test-ns" },
                "spec": { "profileRef": "test-profile", "ttl": "1h",
                           "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": { "phase": "Bound", "clusterName": "pool-test-1" }
            })))
            .mount(&server)
            .await;

        // Mock GET for profile (404 — no profile, no queue timeout).
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpoolprofiles/test-profile",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "clusterpoolprofiles",
                    "test-profile",
                )),
            )
            .mount(&server)
            .await;

        let action = reconcile_claim(claim, ctx.clone()).await.unwrap();
        // Successful bind → requeue at 60s.
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(60)));

        // Verify the cluster state changed to Claimed.
        let pools = ctx.pools.read().await;
        let pool = pools.get("test-profile").unwrap();
        let entry = pool.clusters.get("pool-test-1").unwrap();
        assert_eq!(entry.state, ClusterState::Claimed);
    }

    // -----------------------------------------------------------------------
    // reconcile_claim: Bound — not expired
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_bound_claim_not_expired() {
        let (ctx, _server) = test_claim_context().await;
        let claim = make_test_claim("bound-1", "Bound");
        // The helper already sets expires_at to now + 1h.

        let action = reconcile_claim(claim, ctx).await.unwrap();
        // Not expired → requeue at 30s.
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(30)));
    }

    // -----------------------------------------------------------------------
    // reconcile_claim: Bound — expired
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_bound_claim_expired() {
        let (ctx, server) = test_claim_context().await;

        // Build a Bound claim with expires_at in the past.
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let claim: Arc<ClusterClaim> = Arc::new(
            serde_json::from_value(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterClaim",
                "metadata": { "name": "expired-1", "namespace": "test-ns" },
                "spec": {
                    "profileRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Bound",
                    "clusterName": "pool-test-1",
                    "expiresAt": past.to_rfc3339(),
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            }))
            .unwrap(),
        );

        // Mock PATCH for status update to Expired.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterclaims/expired-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterClaim",
                "metadata": { "name": "expired-1", "namespace": "test-ns" },
                "spec": { "profileRef": "test-profile", "ttl": "1h",
                           "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": { "phase": "Expired" }
            })))
            .mount(&server)
            .await;

        let action = reconcile_claim(claim, ctx).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(5)));
    }

    // -----------------------------------------------------------------------
    // reconcile_claim: Released — transitions to Recycling
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_released_claim() {
        let (ctx, server) = test_claim_context().await;
        let claim = make_test_claim("released-1", "Released");

        // Pre-populate pool state with the cluster.
        {
            let mut pools = ctx.pools.write().await;
            let mut clusters = std::collections::HashMap::new();
            clusters.insert(
                "pool-test-1".to_string(),
                crate::pool::ClusterEntry {
                    state: ClusterState::Claimed,
                    idle_since: None,
                    health_failures: 0,
                    state_since: Some(chrono::Utc::now()),
                    spec_hash: None,
                },
            );
            pools.insert("test-profile".to_string(), PoolState { clusters });
        }

        // Mock PATCH for status update to Recycling.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterclaims/released-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterClaim",
                "metadata": { "name": "released-1", "namespace": "test-ns" },
                "spec": { "profileRef": "test-profile", "ttl": "1h",
                           "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": { "phase": "Recycling", "clusterName": "pool-test-1" }
            })))
            .mount(&server)
            .await;

        // Mock GET for profile (for diagnostics check — return profile with no diagnostics).
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpoolprofiles/test-profile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(make_test_profile()))
            .mount(&server)
            .await;

        let action = reconcile_claim(claim, ctx.clone()).await.unwrap();
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(10)));

        // Give the spawned deletion task time to run.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify the backend got a delete call.
        let calls = ctx.backend.call_count();
        assert_eq!(calls.delete, 1);
    }

    // -----------------------------------------------------------------------
    // reconcile_claim: Recycling — cluster gone, claim deleted
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_recycling_claim_cluster_gone() {
        let (ctx, server) = test_claim_context().await;
        let claim = make_test_claim("recycling-1", "Recycling");

        // Pool state has NO entry for the cluster (it's gone).
        // (pools is already empty by default.)

        // Mock DELETE for the claim CRD.
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterclaims/recycling-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterClaim",
                "metadata": { "name": "recycling-1", "namespace": "test-ns" },
                "spec": { "profileRef": "test-profile", "ttl": "1h",
                           "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": { "phase": "Recycling" }
            })))
            .mount(&server)
            .await;

        let action = reconcile_claim(claim, ctx).await.unwrap();
        assert_eq!(action, Action::await_change());
    }

    // -----------------------------------------------------------------------
    // reconcile_claim: Recycling — cluster NOT gone, requeue
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_reconcile_recycling_claim_cluster_still_present() {
        let (ctx, _server) = test_claim_context().await;
        let claim = make_test_claim("recycling-2", "Recycling");

        // Pre-populate pool state so the cluster is still present.
        {
            let mut pools = ctx.pools.write().await;
            let mut clusters = std::collections::HashMap::new();
            clusters.insert(
                "pool-test-1".to_string(),
                crate::pool::ClusterEntry {
                    state: ClusterState::Claimed,
                    idle_since: None,
                    health_failures: 0,
                    state_since: Some(chrono::Utc::now()),
                    spec_hash: None,
                },
            );
            pools.insert("test-profile".to_string(), PoolState { clusters });
        }

        let action = reconcile_claim(claim, ctx).await.unwrap();
        // Cluster still present → requeue at 15s.
        assert_eq!(action, Action::requeue(std::time::Duration::from_secs(15)));
    }

    // -----------------------------------------------------------------------
    // extend_claim_ttl: success
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_extend_claim_ttl_success() {
        let (ctx, server) = test_claim_context().await;

        let future_expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        let bound_at = chrono::Utc::now() - chrono::Duration::minutes(30);

        // Mock GET for the claim.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterclaims/extend-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterClaim",
                "metadata": { "name": "extend-1", "namespace": "test-ns" },
                "spec": {
                    "profileRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Bound",
                    "clusterName": "pool-test-1",
                    "boundAt": bound_at.to_rfc3339(),
                    "expiresAt": future_expiry.to_rfc3339(),
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            })))
            .mount(&server)
            .await;

        // Mock PATCH for extending the TTL.
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterclaims/extend-1/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterClaim",
                "metadata": { "name": "extend-1", "namespace": "test-ns" },
                "spec": { "profileRef": "test-profile", "ttl": "1h",
                           "requester": {"type": "test:admin", "identity": "u"}, "priority": 50 },
                "status": {
                    "phase": "Bound",
                    "extensionsCount": 1
                }
            })))
            .mount(&server)
            .await;

        let result = extend_claim_ttl(
            &ctx.client,
            "test-ns",
            "extend-1",
            "30m",
            &ctx.authenticator,
        )
        .await;
        assert!(result.is_ok());
        // The returned string should be a valid RFC3339 timestamp.
        let new_expiry_str = result.unwrap();
        assert!(chrono::DateTime::parse_from_rfc3339(&new_expiry_str).is_ok());
    }

    // -----------------------------------------------------------------------
    // extend_claim_ttl: wrong phase
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_extend_claim_ttl_wrong_phase() {
        let (ctx, server) = test_claim_context().await;

        // Mock GET returning a claim in Pending phase.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterclaims/pending-ext",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterClaim",
                "metadata": { "name": "pending-ext", "namespace": "test-ns" },
                "spec": {
                    "profileRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Pending",
                    "extensionsCount": 0,
                    "maxExtensions": 2
                }
            })))
            .mount(&server)
            .await;

        let result = extend_claim_ttl(
            &ctx.client,
            "test-ns",
            "pending-ext",
            "30m",
            &ctx.authenticator,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not in Bound phase"),
            "Expected 'not in Bound phase' in error, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // extend_claim_ttl: max extensions reached
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_extend_claim_ttl_max_extensions_reached() {
        let (ctx, server) = test_claim_context().await;

        let future_expiry = chrono::Utc::now() + chrono::Duration::hours(1);

        // Mock GET returning a Bound claim with extensions_count == max_extensions.
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterclaims/maxext-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                "kind": "ClusterClaim",
                "metadata": { "name": "maxext-1", "namespace": "test-ns" },
                "spec": {
                    "profileRef": "test-profile",
                    "ttl": "1h",
                    "requester": { "type": "test:admin", "identity": "u" },
                    "priority": 50
                },
                "status": {
                    "phase": "Bound",
                    "clusterName": "pool-test-1",
                    "expiresAt": future_expiry.to_rfc3339(),
                    "extensionsCount": 2,
                    "maxExtensions": 2
                }
            })))
            .mount(&server)
            .await;

        let result = extend_claim_ttl(
            &ctx.client,
            "test-ns",
            "maxext-1",
            "30m",
            &ctx.authenticator,
        )
        .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Maximum extensions"),
            "Expected 'Maximum extensions' in error, got: {err}"
        );
    }
}
