//! UID-fenced `ClusterLease` to `ClusterInstance` resolution.
//!
//! This module is the single authority for crossing the lease/instance
//! boundary. Callers receive an exact reciprocal pair or a typed denial; they
//! never infer authority from names, a mutable pool, or a default backend.

use kube::api::Api;
use kube::{Client, ResourceExt};

use crate::crd::{
    BackendProvenance, ClusterInstance, ClusterInstancePhase, ClusterLease, ClusterPool,
    LeaseBinding, LeasePhase,
};

/// Policy-specific gates layered on top of the shared reciprocal validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindingResolveMode {
    /// Tenant access: lease must be live `Bound`, unexpired, and the instance
    /// must still be `Leased`.
    Access,
    /// Controller lifecycle work: the same exact reciprocal pair is required,
    /// but release/expiry/recycling phases are permitted.
    Lifecycle,
}

/// Fully validated objects for one exact binding.
#[derive(Debug)]
pub(crate) struct ResolvedLeaseBinding {
    pub lease: ClusterLease,
    /// `#[allow(dead_code)]`: callers work off the validated `binding`, but the
    /// resolved object stays part of the tuple so a caller needing live
    /// instance state does not re-fetch it unvalidated.
    #[allow(dead_code)]
    pub instance: ClusterInstance,
    pub pool: ClusterPool,
    pub binding: LeaseBinding,
}

/// Closed, non-secret failure vocabulary for binding resolution.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BindingResolutionError {
    #[error("lease not found")]
    LeaseNotFound,
    #[error("lease lookup failed")]
    LeaseLookup(#[source] kube::Error),
    #[error("lease UID does not match authenticated capability")]
    LeaseUidMismatch,
    #[error("lease is being deleted")]
    LeaseDeleting,
    #[error("lease is not Bound")]
    LeaseNotBound,
    #[error("lease expiry is missing")]
    ExpiryMissing,
    #[error("lease expiry is malformed")]
    ExpiryMalformed,
    #[error("lease has expired")]
    Expired,
    #[error("lease binding is missing")]
    BindingMissing,
    #[error("lease binding is malformed: {0}")]
    BindingMalformed(&'static str),
    #[error("lease binding does not identify the lease")]
    BindingLeaseMismatch,
    #[error("lease display cluster does not match binding")]
    ClusterNameMismatch,
    #[error("bound instance not found")]
    InstanceNotFound,
    #[error("instance lookup failed")]
    InstanceLookup(#[source] kube::Error),
    #[error("instance UID does not match binding")]
    InstanceUidMismatch,
    #[error("instance generation does not match binding")]
    InstanceGenerationMismatch,
    #[error("instance is being deleted")]
    InstanceDeleting,
    #[error("instance phase is not valid for access")]
    InstancePhaseMismatch,
    #[error("instance reciprocal binding does not match")]
    ReciprocalBindingMismatch,
    #[error("lease is still bound to this instance")]
    LeaseStillBound,
    #[error("instance lease reference does not match binding")]
    LeaseRefMismatch,
    #[error("instance pool reference does not match binding")]
    InstancePoolMismatch,
    #[error("instance owner reference does not match binding")]
    InstanceOwnerMismatch,
    #[error("instance spec digest does not match binding")]
    InstanceSpecDigestMismatch,
    #[error("instance creation provenance is missing")]
    InstanceProvenanceMissing,
    #[error("instance creation provenance does not match binding")]
    InstanceProvenanceMismatch,
    #[error("bound pool not found")]
    PoolNotFound,
    #[error("pool lookup failed")]
    PoolLookup(#[source] kube::Error),
    #[error("pool UID does not match binding")]
    PoolUidMismatch,
    #[error("pool is being deleted")]
    PoolDeleting,
    #[error("pool backend provenance drifted")]
    BackendProvenanceMismatch,
}

impl BindingResolutionError {
    /// Bounded reason code suitable for status, events, metrics, and logs.
    pub(crate) const fn reason_code(&self) -> &'static str {
        match self {
            Self::LeaseNotFound => "lease_not_found",
            Self::LeaseLookup(_) => "lease_lookup_failed",
            Self::LeaseUidMismatch => "lease_uid_mismatch",
            Self::LeaseDeleting => "lease_deleting",
            Self::LeaseNotBound => "lease_not_bound",
            Self::ExpiryMissing => "expiry_missing",
            Self::ExpiryMalformed => "expiry_malformed",
            Self::Expired => "expired",
            Self::BindingMissing => "binding_missing",
            Self::BindingMalformed(_) => "binding_malformed",
            Self::BindingLeaseMismatch => "binding_lease_mismatch",
            Self::ClusterNameMismatch => "cluster_name_mismatch",
            Self::InstanceNotFound => "instance_not_found",
            Self::InstanceLookup(_) => "instance_lookup_failed",
            Self::InstanceUidMismatch => "instance_uid_mismatch",
            Self::InstanceGenerationMismatch => "instance_generation_mismatch",
            Self::InstanceDeleting => "instance_deleting",
            Self::InstancePhaseMismatch => "instance_phase_mismatch",
            Self::ReciprocalBindingMismatch => "reciprocal_binding_mismatch",
            Self::LeaseStillBound => "lease_still_bound",
            Self::LeaseRefMismatch => "lease_ref_mismatch",
            Self::InstancePoolMismatch => "instance_pool_mismatch",
            Self::InstanceOwnerMismatch => "instance_owner_mismatch",
            Self::InstanceSpecDigestMismatch => "instance_spec_digest_mismatch",
            Self::InstanceProvenanceMissing => "instance_provenance_missing",
            Self::InstanceProvenanceMismatch => "instance_provenance_mismatch",
            Self::PoolNotFound => "pool_not_found",
            Self::PoolLookup(_) => "pool_lookup_failed",
            Self::PoolUidMismatch => "pool_uid_mismatch",
            Self::PoolDeleting => "pool_deleting",
            Self::BackendProvenanceMismatch => "backend_provenance_mismatch",
        }
    }
}

/// Resolve and validate the exact lease/instance/pool tuple.
///
/// `expected_lease_uid` comes from the authenticated capability (for connect,
/// the connect-token Secret owner UID), not from the same-name lease fetched
/// here. This is what turns a name-based request into a UID-fenced authority.
pub(crate) async fn resolve_lease_binding(
    client: &Client,
    namespace: &str,
    lease_name: &str,
    expected_lease_uid: &str,
    mode: BindingResolveMode,
) -> Result<ResolvedLeaseBinding, BindingResolutionError> {
    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    let lease = match leases.get(lease_name).await {
        Ok(lease) => lease,
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            return Err(BindingResolutionError::LeaseNotFound);
        }
        Err(err) => return Err(BindingResolutionError::LeaseLookup(err)),
    };

    let lease_uid = lease
        .metadata
        .uid
        .as_deref()
        .ok_or(BindingResolutionError::LeaseUidMismatch)?;
    if lease_uid != expected_lease_uid || lease.name_any() != lease_name {
        return Err(BindingResolutionError::LeaseUidMismatch);
    }
    if lease.metadata.deletion_timestamp.is_some() {
        return Err(BindingResolutionError::LeaseDeleting);
    }

    let lease_status = lease.status.as_ref().cloned().unwrap_or_default();
    if mode == BindingResolveMode::Access {
        if lease_status.phase != LeasePhase::Bound {
            return Err(BindingResolutionError::LeaseNotBound);
        }
        let expires_at = lease_status
            .expires_at
            .as_deref()
            .ok_or(BindingResolutionError::ExpiryMissing)?;
        let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at)
            .map_err(|_| BindingResolutionError::ExpiryMalformed)?
            .with_timezone(&chrono::Utc);
        if chrono::Utc::now() >= expires_at {
            return Err(BindingResolutionError::Expired);
        }
    }

    let binding = lease_status
        .binding
        .clone()
        .ok_or(BindingResolutionError::BindingMissing)?;
    validate_binding_shape(&binding)?;

    if binding.lease.name != lease_name || binding.lease.uid.as_deref() != Some(expected_lease_uid)
    {
        return Err(BindingResolutionError::BindingLeaseMismatch);
    }
    if lease.spec.pool_ref != binding.pool.name {
        return Err(BindingResolutionError::InstancePoolMismatch);
    }
    if mode == BindingResolveMode::Access
        && lease_status.cluster_name.as_deref() != Some(binding.instance.name.as_str())
    {
        return Err(BindingResolutionError::ClusterNameMismatch);
    }

    let instances: Api<ClusterInstance> = Api::namespaced(client.clone(), namespace);
    let instance = match instances.get(&binding.instance.name).await {
        Ok(instance) => instance,
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            return Err(BindingResolutionError::InstanceNotFound);
        }
        Err(err) => return Err(BindingResolutionError::InstanceLookup(err)),
    };
    if instance.metadata.uid.as_deref() != Some(binding.instance.uid.as_str()) {
        return Err(BindingResolutionError::InstanceUidMismatch);
    }
    if instance.metadata.generation != Some(binding.instance.observed_generation) {
        return Err(BindingResolutionError::InstanceGenerationMismatch);
    }
    if instance.metadata.deletion_timestamp.is_some() {
        return Err(BindingResolutionError::InstanceDeleting);
    }

    let instance_status = instance.status.as_ref().cloned().unwrap_or_default();
    if mode == BindingResolveMode::Access && instance_status.phase != ClusterInstancePhase::Leased {
        return Err(BindingResolutionError::InstancePhaseMismatch);
    }
    if instance_status.binding.as_ref() != Some(&binding) {
        return Err(BindingResolutionError::ReciprocalBindingMismatch);
    }
    let lease_ref_matches = instance_status.lease_ref.as_ref().is_some_and(|reference| {
        reference.name == binding.lease.name && reference.uid == binding.lease.uid
    });
    if !lease_ref_matches {
        return Err(BindingResolutionError::LeaseRefMismatch);
    }
    let pool_ref_matches = instance.spec.pool_ref.as_ref().is_some_and(|reference| {
        reference.name == binding.pool.name && reference.uid == binding.pool.uid
    });
    if !pool_ref_matches {
        return Err(BindingResolutionError::InstancePoolMismatch);
    }
    let owner_matches = instance
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| {
            owners.iter().any(|owner| {
                owner.api_version == "kobe.kunobi.ninja/v1alpha1"
                    && owner.kind == "ClusterPool"
                    && owner.name == binding.pool.name
                    && Some(owner.uid.as_str()) == binding.pool.uid.as_deref()
            })
        });
    if !owner_matches {
        return Err(BindingResolutionError::InstanceOwnerMismatch);
    }
    if instance_status.spec_hash.as_deref() != Some(binding.instance_spec_digest.as_str()) {
        return Err(BindingResolutionError::InstanceSpecDigestMismatch);
    }

    let created_with = instance_status
        .created_with
        .as_ref()
        .ok_or(BindingResolutionError::InstanceProvenanceMissing)?;
    if created_with.pool_uid.as_deref() != binding.pool.uid.as_deref()
        || created_with.backend.as_ref() != Some(&binding.backend)
        || created_with.backend_type.as_ref() != Some(&binding.backend.backend_type)
    {
        return Err(BindingResolutionError::InstanceProvenanceMismatch);
    }

    let pools: Api<ClusterPool> = Api::namespaced(client.clone(), namespace);
    let pool = match pools.get(&binding.pool.name).await {
        Ok(pool) => pool,
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            return Err(BindingResolutionError::PoolNotFound);
        }
        Err(err) => return Err(BindingResolutionError::PoolLookup(err)),
    };
    if pool.metadata.uid.as_deref() != binding.pool.uid.as_deref() {
        return Err(BindingResolutionError::PoolUidMismatch);
    }
    if pool.metadata.deletion_timestamp.is_some() {
        return Err(BindingResolutionError::PoolDeleting);
    }
    let current_backend = BackendProvenance::from_config(&pool.spec.backend)
        .map_err(|_| BindingResolutionError::BackendProvenanceMismatch)?;
    if current_backend != binding.backend {
        return Err(BindingResolutionError::BackendProvenanceMismatch);
    }

    Ok(ResolvedLeaseBinding {
        lease,
        instance,
        pool,
        binding,
    })
}

/// Verify that a bound `ClusterInstance` is safe to tear down.
///
/// # Why this is not `resolve_lease_binding(_, Lifecycle)`
///
/// Teardown runs on an instance that is already being destroyed, so the
/// resolver's live-pair invariants are unsatisfiable by construction:
///
/// * Kubernetes bumps `metadata.generation` when it stamps `deletionTimestamp`
///   on a finalizer-bearing object, so a deleting instance always reads
///   `generation == observedGeneration + 1` → `InstanceGenerationMismatch`.
/// * The resolver rejects any instance carrying a `deletionTimestamp`
///   outright → `InstanceDeleting`.
/// * The paired lease CR is deleted at the end of recycling →
///   `LeaseNotFound`.
///
/// Each denial fenced the finalizer path *permanently*: the cleanup finalizer
/// was never released, the `ClusterInstance` stayed in `Recycling` forever,
/// and the pool filled with undeletable members until every request failed
/// `pool_exhausted`. The resolver fails closed on *absence*, which is right
/// for granting tenant access and exactly wrong for reclaiming a corpse.
///
/// Teardown therefore fences only on positive evidence that this instance is
/// the wrong target — a binding describing a different object, or a lease that
/// is still live and still points here — and fails open on absence.
pub(crate) async fn verify_instance_teardown(
    client: &Client,
    namespace: &str,
    instance: &ClusterInstance,
) -> Result<(), BindingResolutionError> {
    let Some(binding) = instance
        .status
        .as_ref()
        .and_then(|status| status.binding.as_ref())
    else {
        // An unbound pool member or standalone instance has no tenant binding
        // to cross. Backend dispatch stays provenance-pinned by the caller.
        return Ok(());
    };

    // Self-consistency: the binding must describe *this* CR. A binding naming
    // another object is the copy/stale-object case the UID fence exists for.
    if instance.metadata.uid.as_deref() != Some(binding.instance.uid.as_str())
        || instance.name_any() != binding.instance.name
    {
        return Err(BindingResolutionError::InstanceUidMismatch);
    }

    let leases: Api<ClusterLease> = Api::namespaced(client.clone(), namespace);
    let lease = match leases.get(&binding.lease.name).await {
        Ok(lease) => lease,
        // The lease is gone, so no tenant can still be holding this instance.
        Err(kube::Error::Api(ae)) if ae.code == 404 => return Ok(()),
        // A lookup failure is not evidence either way; the caller requeues.
        Err(err) => return Err(BindingResolutionError::LeaseLookup(err)),
    };

    // A same-named replacement lease is somebody else's binding, not a live
    // claim on this instance.
    if lease.metadata.uid.as_deref() != binding.lease.uid.as_deref() {
        return Ok(());
    }
    if lease.metadata.deletion_timestamp.is_some() {
        return Ok(());
    }

    let lease_status = lease.status.clone().unwrap_or_default();
    if lease_status.phase != LeasePhase::Bound {
        return Ok(());
    }
    // Only an unexpired `Bound` lease can still be serving a tenant. An absent
    // or malformed expiry cannot prove liveness, and unlike the access path a
    // wrong guess here strands a cluster instead of leaking one — so
    // uncertainty releases.
    let live = lease_status
        .expires_at
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .is_some_and(|expires_at| chrono::Utc::now() < expires_at.with_timezone(&chrono::Utc));
    if !live {
        return Ok(());
    }
    // Live, and still reciprocally bound to this exact instance: a tenant is
    // using it. This fence is self-clearing — the lease expires on its TTL.
    if lease_status.binding.as_ref() == Some(binding) {
        return Err(BindingResolutionError::LeaseStillBound);
    }

    Ok(())
}

fn validate_binding_shape(binding: &LeaseBinding) -> Result<(), BindingResolutionError> {
    if binding.binding_id.is_empty() || binding.binding_id.len() > 128 {
        return Err(BindingResolutionError::BindingMalformed("binding_id"));
    }
    if binding.lease.name.is_empty()
        || binding.lease.uid.as_deref().is_none_or(str::is_empty)
        || binding.instance.name.is_empty()
        || binding.instance.uid.is_empty()
        || binding.instance.observed_generation < 1
        || binding.pool.name.is_empty()
        || binding.pool.uid.as_deref().is_none_or(str::is_empty)
    {
        return Err(BindingResolutionError::BindingMalformed("identity"));
    }
    if !valid_instance_digest(&binding.instance_spec_digest)
        || !valid_backend_digest(&binding.backend.config_digest)
    {
        return Err(BindingResolutionError::BindingMalformed("digest"));
    }
    binding
        .backend
        .dispatch_config()
        .map_err(BindingResolutionError::BindingMalformed)?;
    Ok(())
}

fn valid_backend_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_instance_digest(value: &str) -> bool {
    // `profile_spec_hash` is currently a fixed-width 64-bit hex digest. Keep
    // accepting a future SHA-256 representation without weakening either form.
    matches!(value.len(), 16 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{BackendConfig, BackendType, BoundInstanceRef, ResourceRef};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn binding() -> LeaseBinding {
        let backend = BackendProvenance::from_config(&BackendConfig {
            backend_type: BackendType::K3s,
            ..Default::default()
        })
        .unwrap();
        LeaseBinding {
            binding_id: "31ec124f-b731-4e85-8d74-b306f2da7772".into(),
            lease: ResourceRef {
                name: "lease-a".into(),
                uid: Some("lease-uid".into()),
            },
            instance: BoundInstanceRef {
                name: "pool-p-0".into(),
                uid: "instance-uid".into(),
                observed_generation: 1,
            },
            pool: ResourceRef {
                name: "p".into(),
                uid: Some("pool-uid".into()),
            },
            backend,
            instance_spec_digest:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        }
    }

    #[test]
    fn binding_shape_rejects_missing_uids_generation_and_digests() {
        let mut candidate = binding();
        assert!(validate_binding_shape(&candidate).is_ok());

        candidate.lease.uid = None;
        assert_eq!(
            validate_binding_shape(&candidate)
                .unwrap_err()
                .reason_code(),
            "binding_malformed"
        );

        candidate = binding();
        candidate.instance.observed_generation = 0;
        assert!(validate_binding_shape(&candidate).is_err());

        candidate = binding();
        candidate.backend.config_digest = "not-a-digest".into();
        assert!(validate_binding_shape(&candidate).is_err());
    }

    fn exact_objects() -> (
        LeaseBinding,
        serde_json::Value,
        serde_json::Value,
        serde_json::Value,
    ) {
        let binding = LeaseBinding {
            instance_spec_digest: "0123456789abcdef".into(),
            ..binding()
        };
        let binding_json = serde_json::to_value(&binding).unwrap();
        let lease = serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterLease",
            "metadata": {
                "name": "lease-a",
                "namespace": "test-ns",
                "uid": "lease-uid",
                "resourceVersion": "10"
            },
            "spec": {
                "poolRef": "p",
                "ttl": "1h",
                "requester": { "type": "test:admin", "identity": "owner" }
            },
            "status": {
                "phase": "Bound",
                "clusterName": "pool-p-0",
                "binding": binding_json,
                "boundAt": "2026-01-01T00:00:00Z",
                "expiresAt": "2099-01-01T00:00:00Z"
            }
        });
        let instance = serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterInstance",
            "metadata": {
                "name": "pool-p-0",
                "namespace": "test-ns",
                "uid": "instance-uid",
                "resourceVersion": "20",
                "generation": 1,
                "ownerReferences": [{
                    "apiVersion": "kobe.kunobi.ninja/v1alpha1",
                    "kind": "ClusterPool",
                    "name": "p",
                    "uid": "pool-uid",
                    "controller": true
                }]
            },
            "spec": { "poolRef": { "name": "p", "uid": "pool-uid" } },
            "status": {
                "phase": "Leased",
                "provisioned": true,
                "bootstrapped": true,
                "leaseRef": { "name": "lease-a", "uid": "lease-uid" },
                "binding": binding_json,
                "specHash": "0123456789abcdef",
                "createdWith": {
                    "operatorVersion": "v0.37.0",
                    "backendType": "k3s",
                    "poolUid": "pool-uid",
                    "backend": binding.backend
                }
            }
        });
        let pool = serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "ClusterPool",
            "metadata": {
                "name": "p",
                "namespace": "test-ns",
                "uid": "pool-uid",
                "resourceVersion": "30"
            },
            "spec": {
                "size": 1,
                "backend": { "type": "k3s" },
                "cluster": { "version": "v1.32.0" }
            }
        });
        (binding, lease, instance, pool)
    }

    async fn resolve_objects(
        lease: serde_json::Value,
        instance: serde_json::Value,
        pool: serde_json::Value,
        expected_uid: &str,
    ) -> Result<ResolvedLeaseBinding, BindingResolutionError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/lease-a",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterinstances/pool-p-0",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(instance))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterpools/p",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(pool))
            .mount(&server)
            .await;
        let client = crate::testutil::mock_k8s_client(&server);
        resolve_lease_binding(
            &client,
            "test-ns",
            "lease-a",
            expected_uid,
            BindingResolveMode::Access,
        )
        .await
    }

    #[tokio::test]
    async fn exact_reciprocal_binding_resolves() {
        let (binding, lease, instance, pool) = exact_objects();
        let resolved = resolve_objects(lease, instance, pool, "lease-uid")
            .await
            .unwrap();
        assert_eq!(resolved.binding, binding);
        assert_eq!(
            resolved.instance.metadata.uid.as_deref(),
            Some("instance-uid")
        );
        assert_eq!(resolved.pool.metadata.uid.as_deref(), Some("pool-uid"));
    }

    /// The `Access` expiry gate must deny on every non-live outcome, including
    /// the two "we cannot tell" cases.
    ///
    /// This replaces the old `routes::lease_is_expired` helper, which resolved
    /// a missing or unparseable `expiresAt` to *not expired* and leaned on the
    /// phase gate. A `Bound` lease with a corrupt timestamp therefore kept
    /// proxying indefinitely. Uncertainty now denies.
    #[tokio::test]
    async fn expiry_gate_fails_closed() {
        // Live: a future expiry resolves.
        let (_, mut lease, instance, pool) = exact_objects();
        lease["status"]["expiresAt"] =
            serde_json::json!((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        assert!(
            resolve_objects(lease, instance.clone(), pool.clone(), "lease-uid")
                .await
                .is_ok(),
            "an unexpired Bound lease must resolve"
        );

        // Past expiry.
        let (_, mut lease, _, _) = exact_objects();
        lease["status"]["expiresAt"] =
            serde_json::json!((chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339());
        assert_eq!(
            resolve_objects(lease, instance.clone(), pool.clone(), "lease-uid")
                .await
                .unwrap_err()
                .reason_code(),
            "expired"
        );

        // Absent expiry: cannot prove the lease is live.
        let (_, mut lease, _, _) = exact_objects();
        lease["status"].as_object_mut().unwrap().remove("expiresAt");
        assert_eq!(
            resolve_objects(lease, instance.clone(), pool.clone(), "lease-uid")
                .await
                .unwrap_err()
                .reason_code(),
            "expiry_missing"
        );

        // Unparseable expiry: same reasoning.
        let (_, mut lease, _, _) = exact_objects();
        lease["status"]["expiresAt"] = serde_json::json!("not-a-timestamp");
        assert_eq!(
            resolve_objects(lease, instance, pool, "lease-uid")
                .await
                .unwrap_err()
                .reason_code(),
            "expiry_malformed"
        );
    }

    #[tokio::test]
    async fn lease_instance_and_pool_name_reuse_fail_closed() {
        let (_, lease, instance, pool) = exact_objects();
        assert_eq!(
            resolve_objects(
                lease.clone(),
                instance.clone(),
                pool.clone(),
                "replacement-lease-uid"
            )
            .await
            .unwrap_err()
            .reason_code(),
            "lease_uid_mismatch"
        );

        let mut replacement_instance = instance.clone();
        replacement_instance["metadata"]["uid"] = serde_json::json!("replacement-instance-uid");
        assert_eq!(
            resolve_objects(
                lease.clone(),
                replacement_instance,
                pool.clone(),
                "lease-uid"
            )
            .await
            .unwrap_err()
            .reason_code(),
            "instance_uid_mismatch"
        );

        let mut replacement_pool = pool;
        replacement_pool["metadata"]["uid"] = serde_json::json!("replacement-pool-uid");
        assert_eq!(
            resolve_objects(lease, instance, replacement_pool, "lease-uid")
                .await
                .unwrap_err()
                .reason_code(),
            "pool_uid_mismatch"
        );
    }

    #[tokio::test]
    async fn generation_spec_and_reciprocal_substitution_fail_closed() {
        let (_, lease, instance, pool) = exact_objects();
        let mut changed_generation = instance.clone();
        changed_generation["metadata"]["generation"] = serde_json::json!(2);
        assert_eq!(
            resolve_objects(lease.clone(), changed_generation, pool.clone(), "lease-uid")
                .await
                .unwrap_err()
                .reason_code(),
            "instance_generation_mismatch"
        );

        let mut changed_spec = instance.clone();
        changed_spec["status"]["specHash"] = serde_json::json!("fedcba9876543210");
        assert_eq!(
            resolve_objects(lease.clone(), changed_spec, pool.clone(), "lease-uid")
                .await
                .unwrap_err()
                .reason_code(),
            "instance_spec_digest_mismatch"
        );

        let mut non_reciprocal = instance;
        non_reciprocal["status"]["binding"]["bindingId"] = serde_json::json!("other-binding");
        assert_eq!(
            resolve_objects(lease, non_reciprocal, pool, "lease-uid")
                .await
                .unwrap_err()
                .reason_code(),
            "reciprocal_binding_mismatch"
        );
    }

    #[tokio::test]
    async fn missing_provenance_pool_deletion_and_backend_drift_fail_closed() {
        let (_, lease, instance, pool) = exact_objects();
        let mut missing = instance.clone();
        missing["status"]
            .as_object_mut()
            .unwrap()
            .remove("createdWith");
        assert_eq!(
            resolve_objects(lease.clone(), missing, pool.clone(), "lease-uid")
                .await
                .unwrap_err()
                .reason_code(),
            "instance_provenance_missing"
        );

        let mut deleting_pool = pool.clone();
        deleting_pool["metadata"]["deletionTimestamp"] = serde_json::json!("2026-01-01T00:00:00Z");
        assert_eq!(
            resolve_objects(lease.clone(), instance.clone(), deleting_pool, "lease-uid",)
                .await
                .unwrap_err()
                .reason_code(),
            "pool_deleting"
        );

        let mut drifted_pool = pool;
        drifted_pool["spec"]["backend"] = serde_json::json!({ "type": "k0s" });
        assert_eq!(
            resolve_objects(lease, instance, drifted_pool, "lease-uid")
                .await
                .unwrap_err()
                .reason_code(),
            "backend_provenance_mismatch"
        );
    }

    #[tokio::test]
    async fn missing_or_malformed_binding_fails_before_backend_lookup() {
        let (_, mut lease, instance, pool) = exact_objects();
        lease["status"].as_object_mut().unwrap().remove("binding");
        assert_eq!(
            resolve_objects(lease, instance.clone(), pool.clone(), "lease-uid")
                .await
                .unwrap_err()
                .reason_code(),
            "binding_missing"
        );

        let (_, mut lease, _, _) = exact_objects();
        lease["status"]["binding"]["bindingId"] = serde_json::json!("");
        assert_eq!(
            resolve_objects(lease, instance, pool, "lease-uid")
                .await
                .unwrap_err()
                .reason_code(),
            "binding_malformed"
        );
    }

    /// Run `verify_instance_teardown` against a mock apiserver that serves
    /// `lease` for `lease-a` (or 404s when `lease` is `None`).
    async fn teardown_verdict(
        instance: serde_json::Value,
        lease: Option<serde_json::Value>,
    ) -> Result<(), BindingResolutionError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let response = match lease {
            Some(lease) => ResponseTemplate::new(200).set_body_json(lease),
            None => ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "message": "not found", "reason": "NotFound", "code": 404
            })),
        };
        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/clusterleases/lease-a",
            ))
            .respond_with(response)
            .mount(&server)
            .await;
        let client = crate::testutil::mock_k8s_client(&server);
        let instance: ClusterInstance = serde_json::from_value(instance).unwrap();
        verify_instance_teardown(&client, "test-ns", &instance).await
    }

    /// The production deadlock: an instance whose delete is already in flight
    /// reads one generation ahead of its binding (the apiserver bumps
    /// `metadata.generation` when it stamps `deletionTimestamp` on a
    /// finalizer-bearing object) and its lease has moved on. The live-pair
    /// resolver denied both facts, so the cleanup finalizer was never
    /// released: every bound instance became undeletable, the pool filled with
    /// them, and all leases failed `pool_exhausted`.
    #[tokio::test]
    async fn teardown_releases_a_deleting_instance_whose_lease_terminated() {
        let (_, mut lease, mut instance, _) = exact_objects();
        instance["metadata"]["deletionTimestamp"] = serde_json::json!("2026-01-01T00:00:00Z");
        instance["metadata"]["generation"] = serde_json::json!(2);
        instance["metadata"]["finalizers"] =
            serde_json::json!(["kobe.kunobi.ninja/instance-cleanup"]);
        instance["status"]["phase"] = serde_json::json!("Recycling");
        lease["status"]["phase"] = serde_json::json!("Recycling");

        assert!(
            teardown_verdict(instance.clone(), Some(lease))
                .await
                .is_ok(),
            "a deleting instance whose lease is recycling must tear down"
        );

        // The same instance once the lease CR itself is gone.
        assert!(
            teardown_verdict(instance, None).await.is_ok(),
            "a missing lease is not evidence of a live tenant"
        );
    }

    /// Absence releases, but positive evidence of the wrong target still
    /// fences: a binding that names another object must never authorise a
    /// teardown of this one.
    #[tokio::test]
    async fn teardown_fences_a_binding_that_describes_another_instance() {
        let (_, lease, instance, _) = exact_objects();
        let mut foreign_uid = instance.clone();
        foreign_uid["status"]["binding"]["instance"]["uid"] = serde_json::json!("other-uid");
        assert_eq!(
            teardown_verdict(foreign_uid, Some(lease.clone()))
                .await
                .unwrap_err()
                .reason_code(),
            "instance_uid_mismatch"
        );

        let mut foreign_name = instance;
        foreign_name["status"]["binding"]["instance"]["name"] = serde_json::json!("pool-p-9");
        assert_eq!(
            teardown_verdict(foreign_name, Some(lease))
                .await
                .unwrap_err()
                .reason_code(),
            "instance_uid_mismatch"
        );
    }

    /// A live `Bound` lease still pointing here means a tenant is using the
    /// cluster. That fence stays — it is self-clearing at the lease TTL, and
    /// only an unexpired reciprocal lease can hold it.
    #[tokio::test]
    async fn teardown_fences_only_a_live_reciprocal_lease() {
        let (_, mut lease, instance, _) = exact_objects();
        lease["status"]["expiresAt"] =
            serde_json::json!((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339());
        assert_eq!(
            teardown_verdict(instance.clone(), Some(lease.clone()))
                .await
                .unwrap_err()
                .reason_code(),
            "lease_still_bound"
        );

        // Expired, so no tenant is served even though the phase still reads Bound.
        let mut expired = lease.clone();
        expired["status"]["expiresAt"] =
            serde_json::json!((chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339());
        assert!(
            teardown_verdict(instance.clone(), Some(expired))
                .await
                .is_ok()
        );

        // Unprovable liveness releases here (the access path denies instead).
        let mut malformed = lease.clone();
        malformed["status"]["expiresAt"] = serde_json::json!("not-a-timestamp");
        assert!(
            teardown_verdict(instance.clone(), Some(malformed))
                .await
                .is_ok()
        );

        // A same-named replacement lease is somebody else's binding.
        let mut replacement = lease.clone();
        replacement["metadata"]["uid"] = serde_json::json!("replacement-lease-uid");
        assert!(
            teardown_verdict(instance.clone(), Some(replacement))
                .await
                .is_ok()
        );

        // A live lease that has moved on to another instance does not hold this one.
        let mut rebound = lease.clone();
        rebound["status"]["binding"]["bindingId"] = serde_json::json!("other-binding");
        assert!(
            teardown_verdict(instance.clone(), Some(rebound))
                .await
                .is_ok()
        );

        // A lease being deleted cannot keep serving it either.
        let mut deleting = lease;
        deleting["metadata"]["deletionTimestamp"] = serde_json::json!("2026-01-01T00:00:00Z");
        assert!(teardown_verdict(instance, Some(deleting)).await.is_ok());
    }

    /// An unbound pool member has no tenant binding to cross.
    #[tokio::test]
    async fn teardown_releases_an_unbound_instance_without_a_lease_lookup() {
        let (_, _, mut instance, _) = exact_objects();
        instance["status"]
            .as_object_mut()
            .unwrap()
            .remove("binding");
        assert!(teardown_verdict(instance, None).await.is_ok());
    }
}
