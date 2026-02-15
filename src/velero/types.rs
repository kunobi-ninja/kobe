//! Velero Backup/Restore object builders, ApiResource helpers, and naming conventions.
//!
//! All objects are built as `serde_json::Value` using `serde_json::json!`, following
//! the same pattern as the k3k backend (`K3kBackend::build_cluster_object`).
//! Objects are consumed via `kube::api::DynamicObject` + `kube::discovery::ApiResource`.

use kube::discovery::ApiResource;

/// Velero CRD constants.
const VELERO_GROUP: &str = "velero.io";
const VELERO_VERSION: &str = "v1";
const VELERO_API_VERSION: &str = "velero.io/v1";

/// Label applied to all operator-managed resources.
const MANAGED_BY_LABEL: &str = "kunobi-pool-operator";

// ---------------------------------------------------------------------------
// ApiResource helpers
// ---------------------------------------------------------------------------

/// Returns the `ApiResource` descriptor for `velero.io/v1/Backup`.
pub fn backup_api_resource() -> ApiResource {
    ApiResource {
        group: VELERO_GROUP.into(),
        version: VELERO_VERSION.into(),
        api_version: VELERO_API_VERSION.into(),
        kind: "Backup".into(),
        plural: "backups".into(),
    }
}

/// Returns the `ApiResource` descriptor for `velero.io/v1/Restore`.
pub fn restore_api_resource() -> ApiResource {
    ApiResource {
        group: VELERO_GROUP.into(),
        version: VELERO_VERSION.into(),
        api_version: VELERO_API_VERSION.into(),
        kind: "Restore".into(),
        plural: "restores".into(),
    }
}

// ---------------------------------------------------------------------------
// Object builders
// ---------------------------------------------------------------------------

/// Build a Velero Backup JSON object.
///
/// # Arguments
/// * `name` - Name of the Backup resource
/// * `velero_namespace` - Namespace where Velero is installed (typically "velero")
/// * `included_namespaces` - Namespaces to include in the backup
/// * `storage_location` - Backup storage location name
/// * `ttl` - Time-to-live for the backup (e.g., "720h0m0s")
pub fn build_backup_object(
    name: &str,
    velero_namespace: &str,
    included_namespaces: &[String],
    storage_location: &str,
    ttl: &str,
) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": VELERO_API_VERSION,
        "kind": "Backup",
        "metadata": {
            "name": name,
            "namespace": velero_namespace,
            "labels": {
                "app.kubernetes.io/managed-by": MANAGED_BY_LABEL
            }
        },
        "spec": {
            "includedNamespaces": included_namespaces,
            "storageLocation": storage_location,
            "ttl": ttl,
            "snapshotVolumes": true
        }
    })
}

/// Build a Velero Restore JSON object.
///
/// # Arguments
/// * `name` - Name of the Restore resource
/// * `velero_namespace` - Namespace where Velero is installed (typically "velero")
/// * `backup_name` - Name of the Backup to restore from
/// * `source_namespace` - Original namespace in the backup
/// * `target_namespace` - Namespace to restore into (namespace mapping)
pub fn build_restore_object(
    name: &str,
    velero_namespace: &str,
    backup_name: &str,
    source_namespace: &str,
    target_namespace: &str,
) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": VELERO_API_VERSION,
        "kind": "Restore",
        "metadata": {
            "name": name,
            "namespace": velero_namespace,
            "labels": {
                "app.kubernetes.io/managed-by": MANAGED_BY_LABEL
            }
        },
        "spec": {
            "backupName": backup_name,
            "includedNamespaces": [source_namespace],
            "namespaceMapping": {
                source_namespace: target_namespace
            },
            "restorePVs": true
        }
    })
}

// ---------------------------------------------------------------------------
// Naming helpers
// ---------------------------------------------------------------------------

/// Generate the name for a golden backup.
///
/// Format: `{prefix}-{profile}-gen{generation}`
///
/// # Examples
/// ```text
/// golden_backup_name("e2e-full", "golden", 5) => "golden-e2e-full-gen5"
/// ```
pub fn golden_backup_name(profile: &str, prefix: &str, generation: i64) -> String {
    format!("{prefix}-{profile}-gen{generation}")
}

/// Generate the namespace used for the golden (template) cluster.
///
/// Format: `golden-{profile}-{prefix}`
///
/// # Examples
/// ```text
/// golden_namespace("e2e-full", "golden") => "golden-e2e-full"
/// ```
pub fn golden_namespace(profile: &str, prefix: &str) -> String {
    format!("{prefix}-{profile}")
}

/// Generate the name for a restore operation targeting a specific cluster.
///
/// Format: `restore-{target_cluster}`
///
/// # Examples
/// ```text
/// restore_name("pool-e2e-full-3") => "restore-pool-e2e-full-3"
/// ```
pub fn restore_name(target_cluster: &str) -> String {
    format!("restore-{target_cluster}")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ApiResource helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_api_resource_fields() {
        let ar = backup_api_resource();
        assert_eq!(ar.group, "velero.io");
        assert_eq!(ar.version, "v1");
        assert_eq!(ar.api_version, "velero.io/v1");
        assert_eq!(ar.kind, "Backup");
        assert_eq!(ar.plural, "backups");
    }

    #[test]
    fn test_restore_api_resource_fields() {
        let ar = restore_api_resource();
        assert_eq!(ar.group, "velero.io");
        assert_eq!(ar.version, "v1");
        assert_eq!(ar.api_version, "velero.io/v1");
        assert_eq!(ar.kind, "Restore");
        assert_eq!(ar.plural, "restores");
    }

    // -----------------------------------------------------------------------
    // Backup object builder tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_backup_object_basic() {
        let obj = build_backup_object(
            "golden-e2e-full-gen1",
            "velero",
            &["ns-golden-e2e".to_string()],
            "default",
            "720h0m0s",
        );

        assert_eq!(obj["apiVersion"], "velero.io/v1");
        assert_eq!(obj["kind"], "Backup");
        assert_eq!(obj["metadata"]["name"], "golden-e2e-full-gen1");
        assert_eq!(obj["metadata"]["namespace"], "velero");
        assert_eq!(
            obj["metadata"]["labels"]["app.kubernetes.io/managed-by"],
            "kunobi-pool-operator"
        );
        assert_eq!(obj["spec"]["includedNamespaces"][0], "ns-golden-e2e");
        assert_eq!(obj["spec"]["storageLocation"], "default");
        assert_eq!(obj["spec"]["ttl"], "720h0m0s");
        assert_eq!(obj["spec"]["snapshotVolumes"], true);
    }

    #[test]
    fn test_build_backup_object_multiple_namespaces() {
        let namespaces = vec!["ns-a".to_string(), "ns-b".to_string(), "ns-c".to_string()];
        let obj = build_backup_object("multi-ns-backup", "velero", &namespaces, "s3-bucket", "48h");

        let included = obj["spec"]["includedNamespaces"].as_array().unwrap();
        assert_eq!(included.len(), 3);
        assert_eq!(included[0], "ns-a");
        assert_eq!(included[1], "ns-b");
        assert_eq!(included[2], "ns-c");
    }

    #[test]
    fn test_build_backup_object_custom_namespace() {
        let obj = build_backup_object(
            "my-backup",
            "velero-system",
            &["default".to_string()],
            "minio",
            "24h",
        );

        assert_eq!(obj["metadata"]["namespace"], "velero-system");
        assert_eq!(obj["spec"]["storageLocation"], "minio");
    }

    #[test]
    fn test_build_backup_object_has_managed_by_label() {
        let obj = build_backup_object(
            "test-backup",
            "velero",
            &["ns1".to_string()],
            "default",
            "1h",
        );

        assert_eq!(
            obj["metadata"]["labels"]["app.kubernetes.io/managed-by"],
            "kunobi-pool-operator"
        );
    }

    // -----------------------------------------------------------------------
    // Restore object builder tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_restore_object_basic() {
        let obj = build_restore_object(
            "restore-pool-e2e-full-3",
            "velero",
            "golden-e2e-full-gen5",
            "golden-e2e-full",
            "pool-e2e-full-3",
        );

        assert_eq!(obj["apiVersion"], "velero.io/v1");
        assert_eq!(obj["kind"], "Restore");
        assert_eq!(obj["metadata"]["name"], "restore-pool-e2e-full-3");
        assert_eq!(obj["metadata"]["namespace"], "velero");
        assert_eq!(
            obj["metadata"]["labels"]["app.kubernetes.io/managed-by"],
            "kunobi-pool-operator"
        );
        assert_eq!(obj["spec"]["backupName"], "golden-e2e-full-gen5");
        assert_eq!(obj["spec"]["includedNamespaces"][0], "golden-e2e-full");
        assert_eq!(
            obj["spec"]["namespaceMapping"]["golden-e2e-full"],
            "pool-e2e-full-3"
        );
        assert_eq!(obj["spec"]["restorePVs"], true);
    }

    #[test]
    fn test_build_restore_object_custom_velero_namespace() {
        let obj = build_restore_object(
            "restore-cluster-1",
            "velero-prod",
            "backup-gen2",
            "source-ns",
            "target-ns",
        );

        assert_eq!(obj["metadata"]["namespace"], "velero-prod");
    }

    #[test]
    fn test_build_restore_object_namespace_mapping() {
        let obj = build_restore_object(
            "restore-x",
            "velero",
            "backup-y",
            "golden-ns",
            "pool-cluster-7",
        );

        let mapping = &obj["spec"]["namespaceMapping"];
        assert_eq!(mapping["golden-ns"], "pool-cluster-7");

        // Ensure only the source namespace is included
        let included = obj["spec"]["includedNamespaces"].as_array().unwrap();
        assert_eq!(included.len(), 1);
        assert_eq!(included[0], "golden-ns");
    }

    #[test]
    fn test_build_restore_object_has_managed_by_label() {
        let obj = build_restore_object("restore-test", "velero", "backup-test", "src-ns", "dst-ns");

        assert_eq!(
            obj["metadata"]["labels"]["app.kubernetes.io/managed-by"],
            "kunobi-pool-operator"
        );
    }

    // -----------------------------------------------------------------------
    // Naming function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_golden_backup_name() {
        assert_eq!(
            golden_backup_name("e2e-full", "golden", 5),
            "golden-e2e-full-gen5"
        );
    }

    #[test]
    fn test_golden_backup_name_gen_zero() {
        assert_eq!(
            golden_backup_name("staging", "golden", 0),
            "golden-staging-gen0"
        );
    }

    #[test]
    fn test_golden_backup_name_large_generation() {
        assert_eq!(
            golden_backup_name("perf", "golden", 999),
            "golden-perf-gen999"
        );
    }

    #[test]
    fn test_golden_backup_name_custom_prefix() {
        assert_eq!(
            golden_backup_name("e2e-full", "snapshot", 3),
            "snapshot-e2e-full-gen3"
        );
    }

    #[test]
    fn test_golden_namespace() {
        assert_eq!(golden_namespace("e2e-full", "golden"), "golden-e2e-full");
    }

    #[test]
    fn test_golden_namespace_different_profile() {
        assert_eq!(golden_namespace("staging", "golden"), "golden-staging");
    }

    #[test]
    fn test_golden_namespace_custom_prefix() {
        assert_eq!(golden_namespace("e2e-full", "snap"), "snap-e2e-full");
    }

    #[test]
    fn test_restore_name() {
        assert_eq!(restore_name("pool-e2e-full-3"), "restore-pool-e2e-full-3");
    }

    #[test]
    fn test_restore_name_simple_cluster() {
        assert_eq!(restore_name("my-cluster"), "restore-my-cluster");
    }

    #[test]
    fn test_restore_name_long_cluster() {
        assert_eq!(
            restore_name("pool-integration-tests-42"),
            "restore-pool-integration-tests-42"
        );
    }

    // -----------------------------------------------------------------------
    // Roundtrip / integration-style tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_backup_object_is_valid_json_for_dynamic_object() {
        // Verify the backup object can be deserialized into DynamicObject
        let obj = build_backup_object(
            "test-backup",
            "velero",
            &["ns1".to_string()],
            "default",
            "720h0m0s",
        );

        let result: Result<kube::api::DynamicObject, _> = serde_json::from_value(obj);
        assert!(
            result.is_ok(),
            "Backup object should deserialize into DynamicObject"
        );

        let dyn_obj = result.unwrap();
        assert_eq!(dyn_obj.metadata.name.as_deref(), Some("test-backup"));
        assert_eq!(dyn_obj.metadata.namespace.as_deref(), Some("velero"));
    }

    #[test]
    fn test_restore_object_is_valid_json_for_dynamic_object() {
        // Verify the restore object can be deserialized into DynamicObject
        let obj = build_restore_object(
            "test-restore",
            "velero",
            "test-backup",
            "source-ns",
            "target-ns",
        );

        let result: Result<kube::api::DynamicObject, _> = serde_json::from_value(obj);
        assert!(
            result.is_ok(),
            "Restore object should deserialize into DynamicObject"
        );

        let dyn_obj = result.unwrap();
        assert_eq!(dyn_obj.metadata.name.as_deref(), Some("test-restore"));
        assert_eq!(dyn_obj.metadata.namespace.as_deref(), Some("velero"));
    }

    #[test]
    fn test_naming_functions_compose_correctly() {
        // Simulate the full workflow: golden backup -> restore for a pool cluster
        let profile = "e2e-full";
        let prefix = "golden";
        let generation = 5;
        let target_cluster = "pool-e2e-full-3";

        let backup_name = golden_backup_name(profile, prefix, generation);
        let source_ns = golden_namespace(profile, prefix);
        let restore = restore_name(target_cluster);

        // Build the objects using the naming helpers
        let backup_obj = build_backup_object(
            &backup_name,
            "velero",
            std::slice::from_ref(&source_ns),
            "default",
            "720h0m0s",
        );

        let restore_obj =
            build_restore_object(&restore, "velero", &backup_name, &source_ns, target_cluster);

        // Verify the names line up
        assert_eq!(backup_obj["metadata"]["name"], "golden-e2e-full-gen5");
        assert_eq!(restore_obj["spec"]["backupName"], "golden-e2e-full-gen5");
        assert_eq!(
            restore_obj["spec"]["namespaceMapping"]["golden-e2e-full"],
            "pool-e2e-full-3"
        );
    }
}
