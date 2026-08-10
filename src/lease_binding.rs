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
}
