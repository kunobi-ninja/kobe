pub mod access_policy;
pub mod bootstrap_config;
pub mod cidr;
#[allow(dead_code)]
pub mod datastore;
pub mod instance;
pub mod lease;
pub mod profile;

pub use access_policy::*;
pub use bootstrap_config::*;
pub use cidr::*;
#[allow(unused_imports)]
pub use datastore::*;
pub use instance::*;
pub use lease::*;
pub use profile::*;

/// Schema helper for `serde_json::Value` fields that need an explicit `type: object`
/// in the OpenAPI spec. Without this, schemars emits `{}` which K8s rejects.
pub fn json_object_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "x-kubernetes-preserve-unknown-fields": true
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that a profile spec with snapshot config deserializes correctly.
    #[test]
    fn test_deserialize_profile_spec_with_snapshot() {
        let json = serde_json::json!({
            "size": 5,
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

        let spec: ClusterPoolSpec = serde_json::from_value(json).unwrap();
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
            "size": 3,
            "ttl": "2h",
            "cluster": {
                "version": "v1.31.3+k3s1"
            }
        });

        let spec: ClusterPoolSpec = serde_json::from_value(json).unwrap();
        assert!(spec.snapshot.is_none());
        assert_eq!(spec.size, 3);
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
        let status = ClusterPoolStatus::default();
        assert!(status.golden_backup.is_none());
        assert!(status.golden_generation.is_none());
    }

    /// Test that status golden tracking fields deserialize when present.
    #[test]
    fn test_status_golden_fields_present() {
        let json = serde_json::json!({
            "ready": 2,
            "leased": 1,
            "creating": 0,
            "unhealthy": 0,
            "queueDepth": 0,
            "goldenBackup": "golden-myprofile-3",
            "goldenGeneration": 7
        });

        let status: ClusterPoolStatus = serde_json::from_value(json).unwrap();
        assert_eq!(status.golden_backup.as_deref(), Some("golden-myprofile-3"));
        assert_eq!(status.golden_generation, Some(7));
    }

    #[test]
    fn test_status_accepts_legacy_claimed_field() {
        let json = serde_json::json!({
            "ready": 2,
            "claimed": 1,
            "creating": 0,
            "unhealthy": 0,
            "queueDepth": 0
        });

        let status: ClusterPoolStatus = serde_json::from_value(json).unwrap();
        assert_eq!(status.ready, 2);
        assert_eq!(status.leased, 1);
        assert_eq!(status.creating, 0);
        assert_eq!(status.unhealthy, 0);
        assert_eq!(status.queue_depth, 0);
    }

    /// Test SnapshotRefreshTrigger default variant.
    #[test]
    fn test_snapshot_refresh_trigger_default() {
        let trigger = SnapshotRefreshTrigger::default();
        assert!(matches!(trigger, SnapshotRefreshTrigger::ProfileChange));
    }

    /// Deserialize a ClusterLeaseSpec from JSON and verify all fields round-trip.
    #[test]
    fn test_claim_spec_roundtrip() {
        let json = serde_json::json!({
            "poolRef": "e2e-basic",
            "ttl": "1h",
            "requester": {
                "type": "github-actions:ci",
                "identity": "repo:org/repo:ref:refs/heads/main"
            },
            "priority": 80
        });

        let spec: ClusterLeaseSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.pool_ref, "e2e-basic");
        assert_eq!(spec.ttl, "1h");
        assert_eq!(spec.requester.requester_type, "github-actions:ci");
        assert_eq!(spec.requester.identity, "repo:org/repo:ref:refs/heads/main");
        assert_eq!(spec.priority, 80);

        // Serialize back and verify round-trip
        let serialized = serde_json::to_value(&spec).unwrap();
        let deserialized: ClusterLeaseSpec = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.pool_ref, spec.pool_ref);
        assert_eq!(deserialized.ttl, spec.ttl);
        assert_eq!(deserialized.priority, spec.priority);
    }

    /// ClusterLeaseStatus::default() should produce Pending phase, zero counts, and None options.
    #[test]
    fn test_claim_status_defaults() {
        let status = ClusterLeaseStatus::default();
        assert_eq!(status.phase, LeasePhase::Pending);
        assert!(status.cluster_name.is_none());
        assert!(status.bound_at.is_none());
        assert!(status.expires_at.is_none());
        assert_eq!(status.queue_position, 0);
        assert!(status.diagnostics_url.is_none());
        assert_eq!(status.extensions_count, 0);
        assert_eq!(status.max_extensions, 0);
    }

    /// Display impl for LeasePhase should produce the expected string for each variant.
    #[test]
    fn test_claim_phase_display() {
        assert_eq!(LeasePhase::Pending.to_string(), "Pending");
        assert_eq!(LeasePhase::Bound.to_string(), "Bound");
        assert_eq!(LeasePhase::Released.to_string(), "Released");
        assert_eq!(LeasePhase::Expired.to_string(), "Expired");
        assert_eq!(LeasePhase::Recycling.to_string(), "Recycling");
    }

    #[test]
    fn test_cluster_instance_spec_optional_pool_ref() {
        let json = serde_json::json!({});
        let spec: ClusterInstanceSpec = serde_json::from_value(json).unwrap();
        assert!(spec.pool_ref.is_none());
        assert!(spec.backend.is_none());
        assert!(spec.cluster.is_none());
        assert!(spec.addons.is_empty());
        assert!(spec.bootstraps.is_empty());
        assert!(spec.health_check.is_none());
        assert!(spec.readiness_gates.is_empty());
        assert!(spec.snapshot.is_none());
    }

    #[test]
    fn test_cluster_instance_spec_supports_standalone_config() {
        let json = serde_json::json!({
            "backend": {
                "type": "k3s"
            },
            "cluster": {
                "version": "v1.31.3+k3s1"
            },
            "addons": [
                {
                    "name": "metrics-server"
                }
            ],
            "healthCheck": {
                "intervalSeconds": 15,
                "failureThreshold": 4
            }
        });

        let spec: ClusterInstanceSpec = serde_json::from_value(json).unwrap();
        assert!(spec.pool_ref.is_none());
        assert_eq!(spec.backend.unwrap().backend_type, BackendType::K3s);
        assert_eq!(spec.cluster.unwrap().version, "v1.31.3+k3s1");
        assert_eq!(spec.addons.len(), 1);
        assert!(spec.health_check.is_some());
        assert!(spec.readiness_gates.is_empty());
    }

    #[test]
    fn test_cluster_instance_status_defaults() {
        let status = ClusterInstanceStatus::default();
        assert_eq!(status.phase, ClusterInstancePhase::Creating);
        assert!(!status.provisioned);
        assert!(status.lease_ref.is_none());
        assert!(status.idle_since.is_none());
        assert!(status.state_since.is_none());
        assert_eq!(status.health_failures, 0);
        assert!(status.spec_hash.is_none());
    }

    /// Deserialize an AccessPolicySpec from a full JSON payload including
    /// auth method, identity, and rules.
    #[test]
    fn test_access_policy_spec_roundtrip() {
        let json = serde_json::json!({
            "auth": {
                "oidc": {
                    "issuer": "https://token.actions.githubusercontent.com",
                    "audience": ["kunobi"],
                    "authorizedParties": [],
                    "algorithms": ["RS256"]
                }
            },
            "identity": "repo:{repository}:ref:{ref}",
            "rules": [
                {
                    "pools": ["e2e-*"],
                    "maxTtl": "1h",
                    "maxConcurrentLeases": 5,
                    "maxExtensions": 1
                }
            ]
        });

        let spec: AccessPolicySpec = serde_json::from_value(json).unwrap();
        let oidc = spec.auth.oidc.as_ref().expect("oidc should be Some");
        assert_eq!(oidc.issuer, "https://token.actions.githubusercontent.com");
        assert_eq!(oidc.audience, vec!["kunobi"]);
        assert!(oidc.authorized_parties.is_empty());
        assert_eq!(oidc.algorithms, vec!["RS256"]);
        assert_eq!(spec.identity, "repo:{repository}:ref:{ref}");

        // Verify rule
        assert_eq!(spec.rules.len(), 1);
        let rule = &spec.rules[0];
        assert_eq!(rule.pools, vec!["e2e-*"]);
        assert_eq!(rule.max_ttl, "1h");
        assert_eq!(rule.max_concurrent_leases, 5);
        assert_eq!(rule.max_extensions, 1);

        // Serialize back and verify round-trip
        let serialized = serde_json::to_value(&spec).unwrap();
        let deserialized: AccessPolicySpec = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.identity, spec.identity);
        assert_eq!(deserialized.rules.len(), spec.rules.len());
    }

    /// Test AccessPolicy with match clauses for multi-role OIDC.
    #[test]
    fn test_access_policy_with_match_clauses() {
        let json = serde_json::json!({
            "auth": {
                "oidc": {
                    "issuer": "https://clerk.example.com",
                    "audience": ["kunobi"]
                }
            },
            "identity": "{sub}",
            "rules": [
                {
                    "match": { "claim": "org_role", "value": "org:admin" },
                    "pools": ["*"],
                    "maxTtl": "8h",
                    "maxConcurrentLeases": 10,
                    "maxExtensions": 5
                },
                {
                    "match": { "claim": "org_role", "value": "org:member" },
                    "pools": ["dev-*"],
                    "maxTtl": "2h",
                    "maxConcurrentLeases": 3,
                    "maxExtensions": 1
                }
            ]
        });

        let spec: AccessPolicySpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.rules.len(), 2);

        let admin_rule = &spec.rules[0];
        let m = admin_rule
            .match_clause
            .as_ref()
            .expect("match should exist");
        assert_eq!(m.claim, "org_role");
        assert_eq!(m.value, "org:admin");
        assert_eq!(admin_rule.pools, vec!["*"]);
        assert_eq!(admin_rule.max_concurrent_leases, 10);

        let member_rule = &spec.rules[1];
        let m = member_rule
            .match_clause
            .as_ref()
            .expect("match should exist");
        assert_eq!(m.claim, "org_role");
        assert_eq!(m.value, "org:member");
        assert_eq!(member_rule.pools, vec!["dev-*"]);
    }

    #[test]
    fn test_backend_type_k0s_deserialize() {
        let json = r#""k0s""#;
        let bt: BackendType = serde_json::from_str(json).unwrap();
        assert_eq!(bt, BackendType::K0s);
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

    /// Test default functions used by AccessPolicySpec and AccessRule.
    #[test]
    fn test_access_policy_defaults() {
        // Minimal JSON to test defaults
        let json = serde_json::json!({
            "auth": {
                "oidc": {
                    "issuer": "https://example.com"
                }
            },
            "rules": [{
                "pools": ["*"],
                "maxTtl": "2h",
                "maxConcurrentLeases": 3
            }]
        });

        let spec: AccessPolicySpec = serde_json::from_value(json).unwrap();
        let oidc = spec.auth.oidc.as_ref().expect("oidc should be Some");

        // algorithms defaults to ["RS256"]
        assert_eq!(oidc.algorithms, vec!["RS256"]);

        // identity defaults to "{sub}"
        assert_eq!(spec.identity, "{sub}");

        // audience defaults to empty vec
        assert!(oidc.audience.is_empty());

        // Verify rule defaults
        assert_eq!(spec.rules.len(), 1);
        let rule = &spec.rules[0];

        // max_extensions defaults to 2
        assert_eq!(rule.max_extensions, 2);
    }

    // ── KobeStore CRD tests ──────────────────────────────────────────

    /// Deserialize an etcd KobeStore with TLS and capacity.
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

        let spec: KobeStoreSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.driver, KobeStoreDriver::Etcd);
        assert_eq!(spec.endpoints.len(), 3);
        assert_eq!(spec.endpoints[0], "https://etcd-0.etcd:2379");

        let tls = spec.tls.expect("tls should be Some");
        assert_eq!(tls.secret_ref, "etcd-client-tls");

        assert_eq!(spec.capacity.max_clusters, 50);
        assert_eq!(spec.replicas, Some(3));
    }

    /// Deserialize a kine-sqlite KobeStore without TLS.
    #[test]
    fn test_deserialize_kine_sqlite_datastore() {
        let json = serde_json::json!({
            "driver": "kine-sqlite",
            "endpoints": ["unix:///data/kine.sock"],
            "capacity": {
                "maxClusters": 10
            }
        });

        let spec: KobeStoreSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.driver, KobeStoreDriver::KineSqlite);
        assert_eq!(spec.endpoints, vec!["unix:///data/kine.sock"]);
        assert!(spec.tls.is_none());
        assert_eq!(spec.capacity.max_clusters, 10);
        assert!(spec.replicas.is_none());
    }

    /// KobeStoreStatus serialization with usedBy list.
    #[test]
    fn test_datastore_status_serialization() {
        let status = KobeStoreStatus {
            ready: true,
            current_clusters: 2,
            used_by: vec![
                KobeStoreUser {
                    namespace: "team-a".into(),
                    name: "vc-001".into(),
                },
                KobeStoreUser {
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
        let deserialized: KobeStoreStatus = serde_json::from_value(json).unwrap();
        assert!(deserialized.ready);
        assert_eq!(deserialized.current_clusters, 2);
        assert_eq!(deserialized.used_by.len(), 2);
        assert_eq!(
            deserialized.used_by[0],
            KobeStoreUser {
                namespace: "team-a".into(),
                name: "vc-001".into()
            }
        );
    }

    // ── VkobeConfig tests ────────────────────────────────────────

    /// Deserialize a VkobeConfig with dataStoreRef, version, and kcm fields.
    #[test]
    fn test_deserialize_vkobe_config() {
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

        let config: VkobeConfig = serde_json::from_value(json).unwrap();
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

    /// VkobeConfig with defaults: version defaults to "1.32", kcm is None.
    #[test]
    fn test_vkobe_config_defaults() {
        let json = serde_json::json!({
            "dataStoreRef": {
                "name": "my-store"
            }
        });

        let config: VkobeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.data_store_ref.name, "my-store");
        assert_eq!(config.version, "1.32");
        assert!(config.kcm.is_none());
        assert_eq!(config.syncers, default_vkobe_syncers());
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
