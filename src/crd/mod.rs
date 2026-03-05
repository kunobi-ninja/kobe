pub mod auth_policy;
pub mod claim;
#[allow(dead_code)]
pub mod datastore;
pub mod profile;

pub use auth_policy::*;
pub use claim::*;
#[allow(unused_imports)]
pub use datastore::*;
pub use profile::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that a profile spec with snapshot config deserializes correctly.
    #[test]
    fn test_deserialize_profile_spec_with_snapshot() {
        let json = serde_json::json!({
            "poolSize": 5,
            "ttl": "1h",
            "cluster": {
                "version": "v1.31.3+k3s1"
            },
            "snapshot": {
                "enabled": true,
                "veleroNamespace": "velero-prod",
                "storageLocation": "s3-backup",
                "goldenPrefix": "gold",
                "ttl": "168h",
                "refreshOn": "Manual"
            }
        });

        let spec: ClusterPoolProfileSpec = serde_json::from_value(json).unwrap();
        let snap = spec.snapshot.expect("snapshot should be Some");

        assert!(snap.enabled);
        assert_eq!(snap.velero_namespace, "velero-prod");
        assert_eq!(snap.storage_location, "s3-backup");
        assert_eq!(snap.golden_prefix, "gold");
        assert_eq!(snap.ttl, "168h");
        assert!(matches!(snap.refresh_on, SnapshotRefreshTrigger::Manual));
    }

    /// Backwards compatibility: a profile spec without snapshot should deserialize fine.
    #[test]
    fn test_deserialize_profile_spec_without_snapshot() {
        let json = serde_json::json!({
            "poolSize": 3,
            "ttl": "2h",
            "cluster": {
                "version": "v1.31.3+k3s1"
            }
        });

        let spec: ClusterPoolProfileSpec = serde_json::from_value(json).unwrap();
        assert!(spec.snapshot.is_none());
        assert_eq!(spec.pool_size, 3);
    }

    /// Test that SnapshotConfig defaults are applied correctly.
    #[test]
    fn test_snapshot_config_defaults() {
        let json = serde_json::json!({});

        let config: SnapshotConfig = serde_json::from_value(json).unwrap();

        assert!(!config.enabled);
        assert_eq!(config.velero_namespace, "velero");
        assert_eq!(config.storage_location, "default");
        assert_eq!(config.golden_prefix, "golden");
        assert_eq!(config.ttl, "720h");
        assert!(matches!(
            config.refresh_on,
            SnapshotRefreshTrigger::ProfileChange
        ));
    }

    /// Test that status golden tracking fields default correctly.
    #[test]
    fn test_status_golden_fields_default() {
        let status = ClusterPoolProfileStatus::default();
        assert!(status.golden_backup.is_none());
        assert!(status.golden_generation.is_none());
    }

    /// Test that status golden tracking fields deserialize when present.
    #[test]
    fn test_status_golden_fields_present() {
        let json = serde_json::json!({
            "ready": 2,
            "claimed": 1,
            "creating": 0,
            "unhealthy": 0,
            "queueDepth": 0,
            "goldenBackup": "golden-myprofile-3",
            "goldenGeneration": 7
        });

        let status: ClusterPoolProfileStatus = serde_json::from_value(json).unwrap();
        assert_eq!(status.golden_backup.as_deref(), Some("golden-myprofile-3"));
        assert_eq!(status.golden_generation, Some(7));
    }

    /// Test SnapshotRefreshTrigger default variant.
    #[test]
    fn test_snapshot_refresh_trigger_default() {
        let trigger = SnapshotRefreshTrigger::default();
        assert!(matches!(trigger, SnapshotRefreshTrigger::ProfileChange));
    }

    /// Deserialize a ClusterClaimSpec from JSON and verify all fields round-trip.
    #[test]
    fn test_claim_spec_roundtrip() {
        let json = serde_json::json!({
            "profileRef": "e2e-basic",
            "ttl": "1h",
            "requester": {
                "type": "github-actions:ci",
                "identity": "repo:org/repo:ref:refs/heads/main"
            },
            "priority": 80
        });

        let spec: ClusterClaimSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.profile_ref, "e2e-basic");
        assert_eq!(spec.ttl, "1h");
        assert_eq!(spec.requester.requester_type, "github-actions:ci");
        assert_eq!(spec.requester.identity, "repo:org/repo:ref:refs/heads/main");
        assert_eq!(spec.priority, 80);

        // Serialize back and verify round-trip
        let serialized = serde_json::to_value(&spec).unwrap();
        let deserialized: ClusterClaimSpec = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.profile_ref, spec.profile_ref);
        assert_eq!(deserialized.ttl, spec.ttl);
        assert_eq!(deserialized.priority, spec.priority);
    }

    /// ClusterClaimStatus::default() should produce Pending phase, zero counts, and None options.
    #[test]
    fn test_claim_status_defaults() {
        let status = ClusterClaimStatus::default();
        assert_eq!(status.phase, ClaimPhase::Pending);
        assert!(status.cluster_name.is_none());
        assert!(status.bound_at.is_none());
        assert!(status.expires_at.is_none());
        assert_eq!(status.queue_position, 0);
        assert!(status.diagnostics_url.is_none());
        assert_eq!(status.extensions_count, 0);
        assert_eq!(status.max_extensions, 0);
    }

    /// Display impl for ClaimPhase should produce the expected string for each variant.
    #[test]
    fn test_claim_phase_display() {
        assert_eq!(ClaimPhase::Pending.to_string(), "Pending");
        assert_eq!(ClaimPhase::Bound.to_string(), "Bound");
        assert_eq!(ClaimPhase::Released.to_string(), "Released");
        assert_eq!(ClaimPhase::Expired.to_string(), "Expired");
        assert_eq!(ClaimPhase::Recycling.to_string(), "Recycling");
    }

    /// Deserialize an AuthPolicySpec from a full JSON payload including
    /// issuer, audience, role extraction, and policies.
    #[test]
    fn test_auth_policy_spec_roundtrip() {
        let json = serde_json::json!({
            "name": "github-actions",
            "issuer": "https://token.actions.githubusercontent.com",
            "audience": ["kunobi"],
            "authorizedParties": [],
            "algorithms": ["RS256"],
            "identityTemplate": "repo:{repository}:ref:{ref}",
            "roleExtraction": {
                "method": "static",
                "role": "ci"
            },
            "policies": {
                "ci": {
                    "allowedProfiles": ["e2e-*"],
                    "maxTtl": "1h",
                    "maxConcurrentClaims": 5,
                    "defaultPriority": 50,
                    "maxExtensions": 1
                }
            }
        });

        let spec: AuthPolicySpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.name, "github-actions");
        assert_eq!(spec.issuer, "https://token.actions.githubusercontent.com");
        assert_eq!(spec.audience, vec!["kunobi"]);
        assert!(spec.authorized_parties.is_empty());
        assert_eq!(spec.algorithms, vec!["RS256"]);
        assert_eq!(spec.identity_template, "repo:{repository}:ref:{ref}");

        // Verify role extraction
        assert!(matches!(
            spec.role_extraction,
            RoleExtractionConfig::Static { ref role } if role == "ci"
        ));

        // Verify policy
        let ci_policy = spec.policies.get("ci").expect("ci policy should exist");
        assert_eq!(ci_policy.allowed_profiles, vec!["e2e-*"]);
        assert_eq!(ci_policy.max_ttl, "1h");
        assert_eq!(ci_policy.max_concurrent_claims, 5);
        assert_eq!(ci_policy.default_priority, 50);
        assert_eq!(ci_policy.max_extensions, 1);

        // Serialize back and verify round-trip
        let serialized = serde_json::to_value(&spec).unwrap();
        let deserialized: AuthPolicySpec = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.name, spec.name);
        assert_eq!(deserialized.issuer, spec.issuer);
    }

    /// Test deserialization of all four RoleExtractionConfig variants.
    #[test]
    fn test_auth_policy_role_extraction_variants() {
        // Static variant
        let json = serde_json::json!({"method": "static", "role": "ci"});
        let config: RoleExtractionConfig = serde_json::from_value(json).unwrap();
        assert!(matches!(config, RoleExtractionConfig::Static { ref role } if role == "ci"));

        // Claim variant
        let json = serde_json::json!({
            "method": "claim",
            "claim": "private_metadata.role",
            "default": "viewer"
        });
        let config: RoleExtractionConfig = serde_json::from_value(json).unwrap();
        assert!(matches!(
            config,
            RoleExtractionConfig::Claim { ref claim, ref default }
                if claim == "private_metadata.role" && default.as_deref() == Some("viewer")
        ));

        // Mapping variant
        let json = serde_json::json!({
            "method": "mapping",
            "claim": "org_role",
            "values": {"org:admin": "admin", "org:member": "user"},
            "default": "guest"
        });
        let config: RoleExtractionConfig = serde_json::from_value(json).unwrap();
        match &config {
            RoleExtractionConfig::Mapping {
                claim,
                values,
                default,
            } => {
                assert_eq!(claim, "org_role");
                assert_eq!(values.get("org:admin").unwrap(), "admin");
                assert_eq!(values.get("org:member").unwrap(), "user");
                assert_eq!(default.as_deref(), Some("guest"));
            }
            _ => panic!("Expected Mapping variant"),
        }

        // Conditional variant
        let json = serde_json::json!({
            "method": "conditional",
            "rules": [
                {"claim": "org_role", "value": "org:admin", "role": "admin"},
                {"claim": "org_role", "value": "org:member", "role": "user"}
            ],
            "default": "viewer"
        });
        let config: RoleExtractionConfig = serde_json::from_value(json).unwrap();
        match &config {
            RoleExtractionConfig::Conditional { rules, default } => {
                assert_eq!(rules.len(), 2);
                assert_eq!(rules[0].claim, "org_role");
                assert_eq!(rules[0].value, "org:admin");
                assert_eq!(rules[0].role, "admin");
                assert_eq!(rules[1].role, "user");
                assert_eq!(default.as_deref(), Some("viewer"));
            }
            _ => panic!("Expected Conditional variant"),
        }
    }

    #[test]
    fn test_backend_type_direct_k0s_deserialize() {
        let json = r#""direct-k0s""#;
        let bt: BackendType = serde_json::from_str(json).unwrap();
        assert_eq!(bt, BackendType::DirectK0s);
    }

    #[test]
    fn test_backend_type_capi_deserialize() {
        let json = r#""capi""#;
        let bt: BackendType = serde_json::from_str(json).unwrap();
        assert_eq!(bt, BackendType::Capi);
    }

    #[test]
    fn test_capi_config_deserialize() {
        let json = r#"{
            "infrastructureApiVersion": "infrastructure.cluster.x-k8s.io/v1alpha1",
            "infrastructureKind": "VCluster",
            "infrastructureSpec": {"helmRelease": {"chart": {"version": "0.24.1"}}}
        }"#;
        let cfg: CapiConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.infrastructure_kind, "VCluster");
        assert!(cfg.infrastructure_spec.is_some());
        assert!(cfg.infrastructure_plural.is_none());
    }

    #[test]
    fn test_capi_config_optional_spec() {
        let json = r#"{
            "infrastructureApiVersion": "infrastructure.cluster.x-k8s.io/v1beta1",
            "infrastructureKind": "K0smotronCluster"
        }"#;
        let cfg: CapiConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.infrastructure_spec.is_none());
        assert!(cfg.infrastructure_plural.is_none());
    }

    /// Test default functions used by AuthPolicySpec and PolicySpec.
    #[test]
    fn test_auth_policy_defaults() {
        // Minimal JSON to test defaults
        let json = serde_json::json!({
            "name": "test-provider",
            "issuer": "https://example.com",
            "roleExtraction": {
                "method": "static",
                "role": "default"
            },
            "policies": {}
        });

        let spec: AuthPolicySpec = serde_json::from_value(json).unwrap();

        // algorithms defaults to ["RS256"]
        assert_eq!(spec.algorithms, vec!["RS256"]);

        // identity_template defaults to "{sub}"
        assert_eq!(spec.identity_template, "{sub}");

        // audience defaults to empty vec
        assert!(spec.audience.is_empty());

        // Verify policy defaults via a minimal policy
        let policy_json = serde_json::json!({
            "allowedProfiles": ["*"],
            "maxTtl": "2h",
            "maxConcurrentClaims": 3
        });
        let policy: PolicySpec = serde_json::from_value(policy_json).unwrap();

        // default_priority defaults to 50
        assert_eq!(policy.default_priority, 50);

        // max_extensions defaults to 2
        assert_eq!(policy.max_extensions, 2);
    }

    // ── DataStore CRD tests ──────────────────────────────────────────

    /// Deserialize an etcd DataStore with TLS and capacity.
    #[test]
    fn test_deserialize_etcd_datastore() {
        let json = serde_json::json!({
            "driver": "etcd",
            "endpoints": [
                "https://etcd-0.etcd:2379",
                "https://etcd-1.etcd:2379",
                "https://etcd-2.etcd:2379"
            ],
            "tls": {
                "secretRef": "etcd-client-tls"
            },
            "capacity": {
                "maxClusters": 50
            },
            "replicas": 3
        });

        let spec: DataStoreSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.driver, DataStoreDriver::Etcd);
        assert_eq!(spec.endpoints.len(), 3);
        assert_eq!(spec.endpoints[0], "https://etcd-0.etcd:2379");

        let tls = spec.tls.expect("tls should be Some");
        assert_eq!(tls.secret_ref, "etcd-client-tls");

        assert_eq!(spec.capacity.max_clusters, 50);
        assert_eq!(spec.replicas, Some(3));
    }

    /// Deserialize a kine-sqlite DataStore without TLS.
    #[test]
    fn test_deserialize_kine_sqlite_datastore() {
        let json = serde_json::json!({
            "driver": "kine-sqlite",
            "endpoints": ["unix:///data/kine.sock"],
            "capacity": {
                "maxClusters": 10
            }
        });

        let spec: DataStoreSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.driver, DataStoreDriver::KineSqlite);
        assert_eq!(spec.endpoints, vec!["unix:///data/kine.sock"]);
        assert!(spec.tls.is_none());
        assert_eq!(spec.capacity.max_clusters, 10);
        assert!(spec.replicas.is_none());
    }

    /// DataStoreStatus serialization with usedBy list.
    #[test]
    fn test_datastore_status_serialization() {
        let status = DataStoreStatus {
            ready: true,
            current_clusters: 2,
            used_by: vec![
                DataStoreUser {
                    namespace: "team-a".into(),
                    name: "vc-001".into(),
                },
                DataStoreUser {
                    namespace: "team-b".into(),
                    name: "vc-042".into(),
                },
            ],
        };

        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["ready"], true);
        assert_eq!(json["currentClusters"], 2);
        assert_eq!(json["usedBy"][0]["namespace"], "team-a");
        assert_eq!(json["usedBy"][0]["name"], "vc-001");
        assert_eq!(json["usedBy"][1]["namespace"], "team-b");
        assert_eq!(json["usedBy"][1]["name"], "vc-042");

        // Round-trip
        let deserialized: DataStoreStatus = serde_json::from_value(json).unwrap();
        assert!(deserialized.ready);
        assert_eq!(deserialized.current_clusters, 2);
        assert_eq!(deserialized.used_by.len(), 2);
        assert_eq!(
            deserialized.used_by[0],
            DataStoreUser {
                namespace: "team-a".into(),
                name: "vc-001".into()
            }
        );
    }

    // ── KobeSyncConfig v2 tests ─────────────────────────────────────

    /// Deserialize a KobeSyncConfig with the new dataStoreRef, version, and kcm fields.
    #[test]
    fn test_deserialize_kobe_sync_v2_config() {
        let json = serde_json::json!({
            "dataStoreRef": {
                "name": "shared-etcd"
            },
            "version": "1.31",
            "kcm": {
                "controllers": ["deployment", "replicaset", "namespace"]
            },
            "syncers": ["pods", "services"],
            "proxyPort": 6443,
            "metricsPort": 9090
        });

        let config: KobeSyncConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.data_store_ref.name, "shared-etcd");
        assert_eq!(config.version, "1.31");

        let kcm = config.kcm.expect("kcm should be Some");
        assert_eq!(
            kcm.controllers,
            vec!["deployment", "replicaset", "namespace"]
        );

        assert_eq!(config.syncers, vec!["pods", "services"]);
        assert_eq!(config.proxy_port, 6443); // explicitly set in JSON fixture
        assert_eq!(config.metrics_port, 9090);
    }

    /// KobeSyncConfig with defaults: version defaults to "1.32", kcm is None.
    #[test]
    fn test_kobe_sync_config_defaults() {
        let json = serde_json::json!({
            "dataStoreRef": {
                "name": "my-store"
            }
        });

        let config: KobeSyncConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.data_store_ref.name, "my-store");
        assert_eq!(config.version, "1.32");
        assert!(config.kcm.is_none());
        assert_eq!(config.syncers, default_kobe_sync_syncers());
        assert_eq!(config.proxy_port, 8443);
        assert_eq!(config.metrics_port, 9090);
    }

    /// KcmConfig controller defaults include the full set.
    #[test]
    fn test_kcm_config_default_controllers() {
        let json = serde_json::json!({});
        let kcm: KcmConfig = serde_json::from_value(json).unwrap();
        assert_eq!(kcm.controllers, default_kcm_controllers());
        assert_eq!(kcm.controllers.len(), 9);
        assert!(kcm.controllers.contains(&"garbagecollector".to_string()));
    }
}
