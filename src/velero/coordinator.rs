//! Velero backup/restore coordination logic.
//!
//! Orchestrates golden-image backup creation and restore-from-backup flows
//! for pool clusters. Uses `DynamicObject` + `ApiResource` to interact with
//! Velero CRDs.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, DeleteParams, DynamicObject, ListParams, PostParams};
use kube::{Client, ResourceExt};
use tracing::{debug, error, info, warn};

use crate::backend::ClusterBackend;
use crate::crd::{ClusterPoolSpec, SnapshotConfig};
use crate::velero::types::{
    backup_api_resource, build_backup_object, build_restore_object, golden_backup_name,
    golden_namespace, restore_api_resource, restore_name,
};

/// Coordinates Velero backup and restore operations for golden images.
///
/// Manages the lifecycle of golden backups: creating temporary clusters,
/// taking Velero backups, restoring pool members from snapshots, and
/// cleaning up stale backups.
#[derive(Clone)]
pub struct VeleroCoordinator {
    client: Client,
}

impl VeleroCoordinator {
    /// Create a new coordinator with the given Kubernetes client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Create a golden backup for a profile.
    ///
    /// This spins up a temporary cluster, waits for readiness, takes a Velero
    /// backup of it, then tears it down. On any failure the temporary cluster
    /// is cleaned up before the error is returned.
    ///
    /// Returns the backup name on success.
    #[tracing::instrument(skip_all, fields(profile))]
    pub async fn create_golden_backup<B: ClusterBackend>(
        &self,
        profile_name: &str,
        spec: &ClusterPoolSpec,
        backend: &B,
        snapshot: &SnapshotConfig,
        generation: i64,
    ) -> Result<String> {
        let backup_name = golden_backup_name(profile_name, &snapshot.golden_prefix, generation);
        let ns = golden_namespace(profile_name, &snapshot.golden_prefix);
        let cluster_name = format!("{ns}-cluster");

        info!(
            profile = profile_name,
            backup = %backup_name,
            namespace = %ns,
            "Creating golden backup"
        );

        // Ensure the namespace exists for the temporary cluster.
        self.ensure_namespace(&ns).await?;

        // Create the temporary cluster; on any subsequent failure we must clean it up.
        if let Err(e) = backend
            .create(&cluster_name, &ns, &spec.cluster, &spec.addons)
            .await
        {
            error!(
                profile = profile_name,
                error = %e,
                "Failed to create temporary golden cluster"
            );
            return Err(e.context("Failed to create temporary golden cluster"));
        }

        // Everything from here must clean up the temp cluster on failure.
        let result = self
            .do_golden_backup(
                profile_name,
                spec,
                backend,
                snapshot,
                &backup_name,
                &ns,
                &cluster_name,
            )
            .await;

        // Always clean up the temporary cluster.
        info!(
            profile = profile_name,
            cluster = %cluster_name,
            namespace = %ns,
            "Cleaning up temporary golden cluster"
        );
        if let Err(cleanup_err) = backend.delete(&cluster_name, &ns).await {
            warn!(
                profile = profile_name,
                error = %cleanup_err,
                "Failed to clean up temporary golden cluster"
            );
        }

        result
    }

    /// Inner helper for `create_golden_backup` — separated so the cleanup
    /// logic in the caller stays clean.
    #[allow(clippy::too_many_arguments)]
    async fn do_golden_backup<B: ClusterBackend>(
        &self,
        profile_name: &str,
        spec: &ClusterPoolSpec,
        backend: &B,
        snapshot: &SnapshotConfig,
        backup_name: &str,
        ns: &str,
        cluster_name: &str,
    ) -> Result<String> {
        // Poll readiness gates (up to 60 attempts, 5s apart).
        for gate in &spec.readiness_gates {
            let passed = self
                .poll_readiness_gate(backend, cluster_name, ns, gate, 60)
                .await;
            if !passed {
                bail!(
                    "Readiness gate {:?} did not pass for golden cluster {}",
                    gate,
                    cluster_name
                );
            }
        }

        // Create the Velero Backup via DynamicObject API.
        let backup_json = build_backup_object(
            backup_name,
            &snapshot.velero_namespace,
            &[ns.to_string()],
            &snapshot.storage_location,
            &snapshot.ttl,
        );

        let backup_obj: DynamicObject = serde_json::from_value(backup_json)
            .context("Failed to deserialize backup object into DynamicObject")?;

        let backups: Api<DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            &snapshot.velero_namespace,
            &backup_api_resource(),
        );

        backups
            .create(&PostParams::default(), &backup_obj)
            .await
            .with_context(|| format!("Failed to create Velero Backup {backup_name}"))?;

        info!(
            profile = profile_name,
            backup = %backup_name,
            "Velero Backup created, waiting for completion"
        );

        // Wait for backup phase == "Completed" (up to 600s).
        self.wait_velero_phase(&backups, backup_name, "Backup", 600)
            .await?;

        info!(
            profile = profile_name,
            backup = %backup_name,
            "Golden backup completed successfully"
        );

        Ok(backup_name.to_string())
    }

    /// Restore a pool cluster from a golden backup.
    ///
    /// Creates a Velero Restore with namespace remapping from the golden
    /// namespace to the target namespace. Uses a timestamp-based restore name
    /// to avoid conflicts.
    #[tracing::instrument(skip(self), fields(cluster = profile_name, backup = backup_name))]
    pub async fn restore_from_golden(
        &self,
        backup_name: &str,
        snapshot: &SnapshotConfig,
        profile_name: &str,
        target_namespace: &str,
    ) -> Result<()> {
        let source_ns = golden_namespace(profile_name, &snapshot.golden_prefix);
        let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
        let rname = format!("{}-{ts}", restore_name(target_namespace));

        info!(
            profile = profile_name,
            backup = %backup_name,
            restore = %rname,
            target_ns = %target_namespace,
            "Restoring from golden backup"
        );

        let restore_json = build_restore_object(
            &rname,
            &snapshot.velero_namespace,
            backup_name,
            &source_ns,
            target_namespace,
        );

        let restore_obj: DynamicObject = serde_json::from_value(restore_json)
            .context("Failed to deserialize restore object into DynamicObject")?;

        let restores: Api<DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            &snapshot.velero_namespace,
            &restore_api_resource(),
        );

        restores
            .create(&PostParams::default(), &restore_obj)
            .await
            .with_context(|| format!("Failed to create Velero Restore {rname}"))?;

        info!(
            restore = %rname,
            "Velero Restore created, waiting for completion"
        );

        // Wait for restore phase == "Completed" (up to 300s).
        self.wait_velero_phase(&restores, &rname, "Restore", 300)
            .await?;

        info!(
            restore = %rname,
            target_ns = %target_namespace,
            "Restore from golden backup completed successfully"
        );

        Ok(())
    }

    /// Check if a usable golden backup exists for the given profile and generation.
    ///
    /// Returns `Some(name)` if the backup exists and its phase is "Completed",
    /// `None` if not found or not yet completed.
    pub async fn get_golden_backup(
        &self,
        profile_name: &str,
        snapshot: &SnapshotConfig,
        generation: i64,
    ) -> Result<Option<String>> {
        let name = golden_backup_name(profile_name, &snapshot.golden_prefix, generation);

        let backups: Api<DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            &snapshot.velero_namespace,
            &backup_api_resource(),
        );

        match backups.get(&name).await {
            Ok(obj) => {
                let phase = extract_phase(&obj);
                if phase == "Completed" {
                    debug!(backup = %name, "Golden backup found and completed");
                    Ok(Some(name))
                } else {
                    debug!(
                        backup = %name,
                        phase = %phase,
                        "Golden backup found but not completed"
                    );
                    Ok(None)
                }
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                debug!(backup = %name, "Golden backup not found");
                Ok(None)
            }
            Err(e) => Err(e).with_context(|| format!("Failed to check golden backup {name}")),
        }
    }

    /// Delete old golden backups whose generation is less than `current_generation`.
    ///
    /// Lists backups with the `app.kubernetes.io/managed-by=kobe-operator`
    /// label and deletes any whose name indicates a generation older than current.
    #[tracing::instrument(skip_all, fields(profile))]
    pub async fn cleanup_old_backups(
        &self,
        profile_name: &str,
        snapshot: &SnapshotConfig,
        current_generation: i64,
    ) -> Result<()> {
        let backups: Api<DynamicObject> = Api::namespaced_with(
            self.client.clone(),
            &snapshot.velero_namespace,
            &backup_api_resource(),
        );

        let lp = ListParams::default().labels("app.kubernetes.io/managed-by=kobe-operator");

        let list = backups
            .list(&lp)
            .await
            .context("Failed to list Velero backups for cleanup")?;

        let prefix = format!("{}-{}-gen", snapshot.golden_prefix, profile_name);

        for obj in list.items {
            let obj_name = obj.name_any();
            if !obj_name.starts_with(&prefix) {
                continue;
            }

            // Extract the generation number from the name.
            let gen_str = &obj_name[prefix.len()..];
            let generation: i64 = match gen_str.parse() {
                Ok(g) => g,
                Err(_) => {
                    debug!(
                        backup = %obj_name,
                        "Skipping backup with unparseable generation"
                    );
                    continue;
                }
            };

            if generation < current_generation {
                info!(
                    backup = %obj_name,
                    generation = generation,
                    current = current_generation,
                    "Deleting old golden backup"
                );
                if let Err(e) = backups.delete(&obj_name, &DeleteParams::default()).await {
                    warn!(
                        backup = %obj_name,
                        error = %e,
                        "Failed to delete old golden backup"
                    );
                }
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Create a namespace if it does not already exist (idempotent).
    async fn ensure_namespace(&self, namespace: &str) -> Result<()> {
        let namespaces: Api<Namespace> = Api::all(self.client.clone());

        match namespaces.get(namespace).await {
            Ok(_) => {
                debug!(namespace = %namespace, "Namespace already exists");
                Ok(())
            }
            Err(kube::Error::Api(ae)) if ae.code == 404 => {
                info!(namespace = %namespace, "Creating namespace");
                let ns_obj: Namespace = serde_json::from_value(serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {
                        "name": namespace,
                        "labels": {
                            "app.kubernetes.io/managed-by": "kobe-operator"
                        }
                    }
                }))?;

                namespaces
                    .create(&PostParams::default(), &ns_obj)
                    .await
                    .with_context(|| format!("Failed to create namespace {namespace}"))?;

                Ok(())
            }
            Err(e) => Err(e).with_context(|| format!("Failed to check namespace {namespace}")),
        }
    }

    /// Poll a Velero resource until its phase reaches a terminal state.
    ///
    /// Returns `Ok(())` if the phase is "Completed", or an error if it reaches
    /// "Failed" / "PartiallyFailed" or times out.
    async fn wait_velero_phase(
        &self,
        api: &Api<DynamicObject>,
        name: &str,
        kind: &str,
        timeout_secs: u64,
    ) -> Result<()> {
        let poll_interval = Duration::from_secs(5);
        let max_attempts = timeout_secs / 5;

        for attempt in 0..max_attempts {
            match api.get(name).await {
                Ok(obj) => {
                    let phase = extract_phase(&obj);

                    if phase == "Completed" {
                        return Ok(());
                    }

                    if is_phase_terminal(&phase) {
                        bail!("Velero {kind} {name} reached terminal phase: {phase}",);
                    }

                    if attempt % 6 == 0 {
                        debug!(
                            kind = kind,
                            name = name,
                            phase = %phase,
                            attempt = attempt + 1,
                            "Waiting for Velero {kind} to complete..."
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        kind = kind,
                        name = name,
                        error = %e,
                        "Error polling Velero {kind}, retrying..."
                    );
                }
            }

            tokio::time::sleep(poll_interval).await;
        }

        bail!("Velero {kind} {name} did not complete within {timeout_secs}s");
    }

    /// Poll a readiness gate on a cluster, returning `true` if it passes within
    /// the allowed number of attempts.
    async fn poll_readiness_gate<B: ClusterBackend>(
        &self,
        backend: &B,
        cluster_name: &str,
        namespace: &str,
        gate: &crate::crd::ReadinessGate,
        max_attempts: u64,
    ) -> bool {
        for attempt in 0..max_attempts {
            match backend
                .check_readiness_gate(cluster_name, namespace, gate)
                .await
            {
                Ok(true) => {
                    debug!(
                        cluster = cluster_name,
                        gate = ?gate,
                        attempts = attempt + 1,
                        "Readiness gate passed"
                    );
                    return true;
                }
                Ok(false) => {
                    if attempt % 6 == 0 {
                        debug!(
                            cluster = cluster_name,
                            gate = ?gate,
                            attempt = attempt + 1,
                            "Readiness gate not yet satisfied"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        cluster = cluster_name,
                        gate = ?gate,
                        error = %e,
                        "Error checking readiness gate"
                    );
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        error!(
            cluster = cluster_name,
            gate = ?gate,
            max_attempts = max_attempts,
            "Readiness gate did not pass within allowed attempts"
        );
        false
    }
}

/// Extract the phase string from a `DynamicObject`'s status.
///
/// The phase lives at `.data["status"]["phase"]`. Returns an empty string
/// if the field is missing.
fn extract_phase(obj: &DynamicObject) -> String {
    obj.data
        .get("status")
        .and_then(|s| s.get("phase"))
        .and_then(|p| p.as_str())
        .unwrap_or("")
        .to_string()
}

/// Check whether a Velero phase string represents a terminal state.
fn is_phase_terminal(phase: &str) -> bool {
    matches!(phase, "Completed" | "Failed" | "PartiallyFailed")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // is_phase_terminal
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_phase_terminal_completed() {
        assert!(is_phase_terminal("Completed"));
    }

    #[test]
    fn test_is_phase_terminal_failed() {
        assert!(is_phase_terminal("Failed"));
    }

    #[test]
    fn test_is_phase_terminal_partially_failed() {
        assert!(is_phase_terminal("PartiallyFailed"));
    }

    #[test]
    fn test_is_phase_terminal_in_progress() {
        assert!(!is_phase_terminal("InProgress"));
    }

    #[test]
    fn test_is_phase_terminal_new() {
        assert!(!is_phase_terminal("New"));
    }

    #[test]
    fn test_is_phase_terminal_empty() {
        assert!(!is_phase_terminal(""));
    }

    #[test]
    fn test_is_phase_terminal_unknown_value() {
        assert!(!is_phase_terminal("SomethingElse"));
    }

    // -----------------------------------------------------------------------
    // extract_phase
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_phase_with_status() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "velero.io/v1",
            "kind": "Backup",
            "metadata": { "name": "test-backup" },
            "status": { "phase": "Completed" }
        }))
        .unwrap();

        assert_eq!(extract_phase(&obj), "Completed");
    }

    #[test]
    fn test_extract_phase_without_status() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "velero.io/v1",
            "kind": "Backup",
            "metadata": { "name": "test-backup" }
        }))
        .unwrap();

        assert_eq!(extract_phase(&obj), "");
    }

    #[test]
    fn test_extract_phase_empty_status() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "velero.io/v1",
            "kind": "Backup",
            "metadata": { "name": "test-backup" },
            "status": {}
        }))
        .unwrap();

        assert_eq!(extract_phase(&obj), "");
    }

    #[test]
    fn test_extract_phase_in_progress() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "velero.io/v1",
            "kind": "Backup",
            "metadata": { "name": "test-backup" },
            "status": { "phase": "InProgress" }
        }))
        .unwrap();

        assert_eq!(extract_phase(&obj), "InProgress");
    }

    #[test]
    fn test_extract_phase_failed() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "velero.io/v1",
            "kind": "Restore",
            "metadata": { "name": "test-restore" },
            "status": { "phase": "Failed" }
        }))
        .unwrap();

        assert_eq!(extract_phase(&obj), "Failed");
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    #[test]
    fn test_coordinator_new_compiles() {
        // VeleroCoordinator::new requires a real Client which needs a running
        // cluster. We verify the struct is Clone + the constructor signature
        // is correct by checking the type compiles.
        fn _assert_clone<T: Clone>() {}
        _assert_clone::<VeleroCoordinator>();
    }

    // -----------------------------------------------------------------------
    // wiremock-based integration tests
    // -----------------------------------------------------------------------

    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build a `kube::Client` backed by a wiremock `MockServer`.
    fn mock_client(server: &MockServer) -> Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::testutil::mock_k8s_client(server)
    }

    /// Build a test `SnapshotConfig` with sensible defaults.
    fn test_snapshot_config() -> SnapshotConfig {
        SnapshotConfig {
            enabled: true,
            velero_namespace: "velero".to_string(),
            storage_location: "default".to_string(),
            golden_prefix: "golden".to_string(),
            ttl: "720h".to_string(),
            refresh_on: crate::crd::SnapshotRefreshTrigger::ProfileChange,
        }
    }

    // -----------------------------------------------------------------------
    // get_golden_backup
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_get_golden_backup_completed() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let coordinator = VeleroCoordinator::new(client);
        let snapshot = test_snapshot_config();

        // GET backup returns Completed
        Mock::given(method("GET"))
            .and(path(
                "/apis/velero.io/v1/namespaces/velero/backups/golden-test-gen1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "velero.io/v1",
                "kind": "Backup",
                "metadata": { "name": "golden-test-gen1", "namespace": "velero" },
                "status": { "phase": "Completed" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = coordinator.get_golden_backup("test", &snapshot, 1).await;
        assert!(
            result.is_ok(),
            "get_golden_backup should succeed: {result:?}"
        );
        assert_eq!(
            result.unwrap(),
            Some("golden-test-gen1".to_string()),
            "should return the backup name when phase is Completed"
        );
    }

    #[tokio::test]
    async fn test_get_golden_backup_in_progress() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let coordinator = VeleroCoordinator::new(client);
        let snapshot = test_snapshot_config();

        // GET backup returns InProgress
        Mock::given(method("GET"))
            .and(path(
                "/apis/velero.io/v1/namespaces/velero/backups/golden-test-gen1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "velero.io/v1",
                "kind": "Backup",
                "metadata": { "name": "golden-test-gen1", "namespace": "velero" },
                "status": { "phase": "InProgress" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = coordinator.get_golden_backup("test", &snapshot, 1).await;
        assert!(
            result.is_ok(),
            "get_golden_backup should succeed: {result:?}"
        );
        assert_eq!(
            result.unwrap(),
            None,
            "should return None when phase is not Completed"
        );
    }

    #[tokio::test]
    async fn test_get_golden_backup_not_found() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let coordinator = VeleroCoordinator::new(client);
        let snapshot = test_snapshot_config();

        // GET backup returns 404
        Mock::given(method("GET"))
            .and(path(
                "/apis/velero.io/v1/namespaces/velero/backups/golden-test-gen1",
            ))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(crate::testutil::k8s_not_found(
                    "backups",
                    "golden-test-gen1",
                )),
            )
            .expect(1)
            .mount(&server)
            .await;

        let result = coordinator.get_golden_backup("test", &snapshot, 1).await;
        assert!(
            result.is_ok(),
            "get_golden_backup should succeed: {result:?}"
        );
        assert_eq!(
            result.unwrap(),
            None,
            "should return None when backup is not found"
        );
    }

    // -----------------------------------------------------------------------
    // cleanup_old_backups
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_cleanup_old_backups_deletes_old() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let coordinator = VeleroCoordinator::new(client);
        let snapshot = test_snapshot_config();

        // LIST returns 2 backups: gen1 (old) and gen3 (current)
        Mock::given(method("GET"))
            .and(path("/apis/velero.io/v1/namespaces/velero/backups"))
            .and(query_param(
                "labelSelector",
                "app.kubernetes.io/managed-by=kobe-operator",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![
                    serde_json::json!({
                        "apiVersion": "velero.io/v1",
                        "kind": "Backup",
                        "metadata": {
                            "name": "golden-test-gen1",
                            "namespace": "velero",
                            "labels": {
                                "app.kubernetes.io/managed-by": "kobe-operator"
                            }
                        },
                        "status": { "phase": "Completed" }
                    }),
                    serde_json::json!({
                        "apiVersion": "velero.io/v1",
                        "kind": "Backup",
                        "metadata": {
                            "name": "golden-test-gen3",
                            "namespace": "velero",
                            "labels": {
                                "app.kubernetes.io/managed-by": "kobe-operator"
                            }
                        },
                        "status": { "phase": "Completed" }
                    }),
                ]),
            ))
            .expect(1)
            .mount(&server)
            .await;

        // DELETE should only be called for gen1 (generation < 3)
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/velero.io/v1/namespaces/velero/backups/golden-test-gen1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "velero.io/v1",
                "kind": "Backup",
                "metadata": { "name": "golden-test-gen1", "namespace": "velero" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = coordinator.cleanup_old_backups("test", &snapshot, 3).await;
        assert!(
            result.is_ok(),
            "cleanup_old_backups should succeed: {result:?}"
        );
        // wiremock `.expect(1)` assertions are verified on drop
    }

    #[tokio::test]
    async fn test_cleanup_old_backups_skips_unparseable() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let coordinator = VeleroCoordinator::new(client);
        let snapshot = test_snapshot_config();

        // LIST returns a backup whose name has an unparseable generation suffix
        Mock::given(method("GET"))
            .and(path("/apis/velero.io/v1/namespaces/velero/backups"))
            .and(query_param(
                "labelSelector",
                "app.kubernetes.io/managed-by=kobe-operator",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response(vec![serde_json::json!({
                    "apiVersion": "velero.io/v1",
                    "kind": "Backup",
                    "metadata": {
                        "name": "golden-test-genabc",
                        "namespace": "velero",
                        "labels": {
                            "app.kubernetes.io/managed-by": "kobe-operator"
                        }
                    },
                    "status": { "phase": "Completed" }
                })]),
            ))
            .expect(1)
            .mount(&server)
            .await;

        // No DELETE should be called — wiremock will fail if an unexpected
        // request arrives (we mount no DELETE mock).
        let result = coordinator.cleanup_old_backups("test", &snapshot, 3).await;
        assert!(
            result.is_ok(),
            "cleanup_old_backups should succeed when names are unparseable: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // ensure_namespace
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_ensure_namespace_exists() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let coordinator = VeleroCoordinator::new(client);

        // GET namespace returns 200 — already exists
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/golden-test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "golden-test" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = coordinator.ensure_namespace("golden-test").await;
        assert!(
            result.is_ok(),
            "ensure_namespace should succeed when namespace exists: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_ensure_namespace_creates() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let coordinator = VeleroCoordinator::new(client);

        // GET namespace returns 404 — does not exist
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/golden-test"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(crate::testutil::k8s_not_found("namespaces", "golden-test")),
            )
            .expect(1)
            .mount(&server)
            .await;

        // POST to create namespace returns 201
        Mock::given(method("POST"))
            .and(path("/api/v1/namespaces"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": "golden-test",
                    "labels": {
                        "app.kubernetes.io/managed-by": "kobe-operator"
                    }
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let result = coordinator.ensure_namespace("golden-test").await;
        assert!(
            result.is_ok(),
            "ensure_namespace should succeed when creating namespace: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // restore_from_golden
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_restore_from_golden_success() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let coordinator = VeleroCoordinator::new(client);
        let snapshot = test_snapshot_config();

        // POST to create restore returns 201
        Mock::given(method("POST"))
            .and(path("/apis/velero.io/v1/namespaces/velero/restores"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "apiVersion": "velero.io/v1",
                "kind": "Restore",
                "metadata": { "name": "restore-target-ns", "namespace": "velero" },
                "status": { "phase": "" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        // GET to poll restore phase — return Completed immediately
        // Use path_regex because the restore name includes a timestamp
        Mock::given(method("GET"))
            .and(wiremock::matchers::path_regex(
                r"/apis/velero.io/v1/namespaces/velero/restores/restore-target-ns-\d{14}",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "velero.io/v1",
                "kind": "Restore",
                "metadata": { "name": "restore-target-ns", "namespace": "velero" },
                "status": { "phase": "Completed" }
            })))
            .mount(&server)
            .await;

        let result = coordinator
            .restore_from_golden("golden-test-gen1", &snapshot, "test", "target-ns")
            .await;
        assert!(
            result.is_ok(),
            "restore_from_golden should succeed: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // create_golden_backup (full flow with MockBackend + wiremock)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_create_golden_backup_success() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let coordinator = VeleroCoordinator::new(client);
        let snapshot = test_snapshot_config();
        let backend = crate::testutil::MockBackend::new();

        let spec = ClusterPoolSpec {
            size: 1,
            ttl: "2h".to_string(),
            backend: Default::default(),
            cluster: crate::crd::ClusterConfig {
                version: "v1.31.3+k3s1".to_string(),
                servers: 1,
                agents: None,
                server_args: vec![],
                persistence: None,
                expose: None,
                taints: None,
            },
            addons: vec![],
            bootstraps: vec![],
            resources: None,
            health_check: None,
            readiness_gates: vec![],
            scaling: None,
            diagnostics: None,
            snapshot: Some(snapshot.clone()),
        };

        // 1. ensure_namespace: GET returns 200 (already exists)
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/golden-test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": "golden-test" }
            })))
            .mount(&server)
            .await;

        // 2. MockBackend.create succeeds by default

        // 3. No readiness gates to poll

        // 4. POST backup returns 201
        Mock::given(method("POST"))
            .and(path("/apis/velero.io/v1/namespaces/velero/backups"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "apiVersion": "velero.io/v1",
                "kind": "Backup",
                "metadata": { "name": "golden-test-gen5", "namespace": "velero" },
                "status": { "phase": "" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        // 5. GET backup poll returns Completed on first poll
        Mock::given(method("GET"))
            .and(path(
                "/apis/velero.io/v1/namespaces/velero/backups/golden-test-gen5",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "velero.io/v1",
                "kind": "Backup",
                "metadata": { "name": "golden-test-gen5", "namespace": "velero" },
                "status": { "phase": "Completed" }
            })))
            .mount(&server)
            .await;

        // 6. MockBackend.delete (cleanup) succeeds by default

        let result = coordinator
            .create_golden_backup("test", &spec, &backend, &snapshot, 5)
            .await;
        assert!(
            result.is_ok(),
            "create_golden_backup should succeed: {result:?}"
        );
        assert_eq!(result.unwrap(), "golden-test-gen5");

        // Verify backend calls: create + delete (cleanup)
        let counts = backend.call_count();
        assert_eq!(counts.create, 1, "should have called backend.create once");
        assert_eq!(
            counts.delete, 1,
            "should have called backend.delete once (cleanup)"
        );
    }
}
