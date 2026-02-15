use anyhow::{Context, Result};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ListParams};
use kube::{Client, Config, ResourceExt};
use tracing::{debug, info, warn};

use crate::backend::ClusterBackend;
use crate::crd::DiagnosticsConfig;

/// Capture a diagnostic bundle from a cluster and upload to S3.
///
/// Uses the cluster backend to get a kubeconfig, then queries the virtual
/// cluster's API directly via kube-rs. No subprocesses needed.
pub async fn capture_bundle<B: ClusterBackend>(
    cluster_name: &str,
    namespace: &str,
    config: &DiagnosticsConfig,
    claim_id: &str,
    backend: &B,
) -> Result<String> {
    info!(
        cluster = cluster_name,
        claim = claim_id,
        include_secrets = config.include_secrets,
        "Capturing diagnostic bundle"
    );

    // Get a kube client targeting the virtual cluster
    let kubeconfig_yaml = backend.extract_kubeconfig(cluster_name, namespace).await?;
    let kube_config = Config::from_custom_kubeconfig(
        kube::config::Kubeconfig::from_yaml(&kubeconfig_yaml)?,
        &Default::default(),
    )
    .await
    .context("Failed to build config from kubeconfig for diagnostics")?;
    let vc_client =
        Client::try_from(kube_config).context("Failed to create client for diagnostics")?;

    let mut bundle = DiagnosticBundle::new(claim_id, cluster_name);

    bundle.pod_logs = capture_pod_logs(&vc_client, config.log_lines).await;
    bundle.events = capture_events(&vc_client).await;
    bundle.resource_dump = capture_resource_dump(&vc_client).await;

    if config.include_secrets {
        warn!(
            cluster = cluster_name,
            claim = claim_id,
            "Including secrets in diagnostic bundle (include_secrets=true)"
        );
        bundle.secrets_dump = Some(capture_secrets(&vc_client).await);
    }

    bundle.node_info = capture_node_info(&vc_client).await;

    let bundle_json =
        serde_json::to_string_pretty(&bundle).context("Failed to serialize diagnostic bundle")?;

    let url = upload_to_s3(&config.storage, claim_id, &bundle_json).await?;

    info!(
        claim = claim_id,
        url = %url,
        "Diagnostic bundle uploaded"
    );

    Ok(url)
}

#[derive(Debug, serde::Serialize)]
struct DiagnosticBundle {
    claim_id: String,
    cluster_name: String,
    captured_at: String,
    pod_logs: Vec<PodLog>,
    events: String,
    resource_dump: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    secrets_dump: Option<String>,
    node_info: String,
}

impl DiagnosticBundle {
    fn new(claim_id: &str, cluster_name: &str) -> Self {
        Self {
            claim_id: claim_id.to_string(),
            cluster_name: cluster_name.to_string(),
            captured_at: chrono::Utc::now().to_rfc3339(),
            pod_logs: Vec::new(),
            events: String::new(),
            resource_dump: String::new(),
            secrets_dump: None,
            node_info: String::new(),
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct PodLog {
    namespace: String,
    pod: String,
    container: String,
    logs: String,
}

/// Capture logs from all pods in all namespaces within the virtual cluster.
async fn capture_pod_logs(vc_client: &Client, log_lines: u32) -> Vec<PodLog> {
    let mut pod_logs = Vec::new();

    let pods: Api<Pod> = Api::all(vc_client.clone());
    let pod_list = match pods.list(&ListParams::default()).await {
        Ok(list) => list,
        Err(e) => {
            warn!("Failed to list pods for diagnostic bundle: {e}");
            return pod_logs;
        }
    };

    for pod in pod_list {
        let pod_name = pod.name_any();
        let pod_ns = pod.namespace().unwrap_or_default();

        let containers: Vec<String> = pod
            .spec
            .as_ref()
            .map(|s| s.containers.iter().map(|c| c.name.clone()).collect())
            .unwrap_or_default();

        for container in containers {
            let ns_pods: Api<Pod> = Api::namespaced(vc_client.clone(), &pod_ns);
            let log_params = kube::api::LogParams {
                container: Some(container.clone()),
                tail_lines: Some(log_lines as i64),
                ..Default::default()
            };

            match ns_pods.logs(&pod_name, &log_params).await {
                Ok(logs) => {
                    pod_logs.push(PodLog {
                        namespace: pod_ns.clone(),
                        pod: pod_name.clone(),
                        container,
                        logs,
                    });
                }
                Err(e) => {
                    debug!(
                        pod = pod_name.as_str(),
                        ns = pod_ns.as_str(),
                        "Failed to capture logs: {e}"
                    );
                }
            }
        }
    }

    pod_logs
}

/// Capture Kubernetes events from the virtual cluster.
async fn capture_events(vc_client: &Client) -> String {
    let events: Api<k8s_openapi::api::core::v1::Event> = Api::all(vc_client.clone());
    match events.list(&ListParams::default()).await {
        Ok(event_list) => serde_json::to_string_pretty(&event_list)
            .unwrap_or_else(|e| format!("ERROR: Failed to serialize events: {e}")),
        Err(e) => {
            warn!("Failed to capture events for diagnostic bundle: {e}");
            format!("CAPTURE FAILED: {e}")
        }
    }
}

/// Capture secrets from the virtual cluster (only when include_secrets is true).
async fn capture_secrets(vc_client: &Client) -> String {
    let secrets: Api<k8s_openapi::api::core::v1::Secret> = Api::all(vc_client.clone());
    match secrets.list(&ListParams::default()).await {
        Ok(secret_list) => serde_json::to_string_pretty(&secret_list)
            .unwrap_or_else(|e| format!("ERROR: Failed to serialize secrets: {e}")),
        Err(e) => {
            warn!("Failed to capture secrets for diagnostic bundle: {e}");
            format!("CAPTURE FAILED: {e}")
        }
    }
}

/// Capture a resource dump from the virtual cluster.
async fn capture_resource_dump(vc_client: &Client) -> String {
    let mut dump = String::new();

    // Capture pods
    let pods: Api<Pod> = Api::all(vc_client.clone());
    match pods.list(&ListParams::default()).await {
        Ok(pod_list) => {
            dump.push_str("--- Pods ---\n");
            dump.push_str(
                &serde_json::to_string_pretty(&pod_list)
                    .unwrap_or_else(|e| format!("ERROR: Failed to serialize pod list: {e}")),
            );
            dump.push('\n');
        }
        Err(e) => {
            dump.push_str(&format!("--- Pods (CAPTURE FAILED: {e}) ---\n"));
        }
    }

    // Capture services
    let services: Api<k8s_openapi::api::core::v1::Service> = Api::all(vc_client.clone());
    match services.list(&ListParams::default()).await {
        Ok(svc_list) => {
            dump.push_str("--- Services ---\n");
            dump.push_str(
                &serde_json::to_string_pretty(&svc_list)
                    .unwrap_or_else(|e| format!("ERROR: Failed to serialize service list: {e}")),
            );
            dump.push('\n');
        }
        Err(e) => {
            dump.push_str(&format!("--- Services (CAPTURE FAILED: {e}) ---\n"));
        }
    }

    // Capture deployments
    let deployments: Api<k8s_openapi::api::apps::v1::Deployment> = Api::all(vc_client.clone());
    match deployments.list(&ListParams::default()).await {
        Ok(deploy_list) => {
            dump.push_str("--- Deployments ---\n");
            dump.push_str(
                &serde_json::to_string_pretty(&deploy_list)
                    .unwrap_or_else(|e| format!("ERROR: Failed to serialize deployment list: {e}")),
            );
            dump.push('\n');
        }
        Err(e) => {
            dump.push_str(&format!("--- Deployments (CAPTURE FAILED: {e}) ---\n"));
        }
    }

    dump
}

/// Capture node info from the virtual cluster.
async fn capture_node_info(vc_client: &Client) -> String {
    let nodes: Api<k8s_openapi::api::core::v1::Node> = Api::all(vc_client.clone());
    match nodes.list(&ListParams::default()).await {
        Ok(node_list) => serde_json::to_string_pretty(&node_list)
            .unwrap_or_else(|e| format!("ERROR: Failed to serialize node info: {e}")),
        Err(e) => {
            warn!("Failed to capture node info for diagnostic bundle: {e}");
            format!("CAPTURE FAILED: {e}")
        }
    }
}

/// Upload diagnostic bundle to S3 and return a presigned URL.
async fn upload_to_s3(storage_uri: &str, claim_id: &str, content: &str) -> Result<String> {
    let uri = storage_uri
        .strip_prefix("s3://")
        .context("Storage URI must start with s3://")?;
    let (bucket, prefix) = uri.split_once('/').unwrap_or((uri, ""));

    let key = if prefix.is_empty() {
        format!("{claim_id}/diagnostics.json")
    } else {
        let prefix = prefix.trim_end_matches('/');
        format!("{prefix}/{claim_id}/diagnostics.json")
    };

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let s3 = S3Client::new(&config);

    s3.put_object()
        .bucket(bucket)
        .key(&key)
        .body(ByteStream::from(content.as_bytes().to_vec()))
        .content_type("application/json")
        .send()
        .await
        .context("Failed to upload diagnostic bundle to S3")?;

    let presigning_config = aws_sdk_s3::presigning::PresigningConfig::builder()
        .expires_in(std::time::Duration::from_secs(7 * 24 * 3600))
        .build()
        .context("Failed to build presigning config")?;

    let presigned = s3
        .get_object()
        .bucket(bucket)
        .key(&key)
        .presigned(presigning_config)
        .await
        .context("Failed to generate presigned URL")?;

    Ok(presigned.uri().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn mock_client(server: &MockServer) -> Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::testutil::mock_k8s_client(server)
    }

    // -----------------------------------------------------------------------
    // DiagnosticBundle struct / serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn bundle_new_sets_fields_correctly() {
        let bundle = DiagnosticBundle::new("claim-42", "my-cluster");
        assert_eq!(bundle.claim_id, "claim-42");
        assert_eq!(bundle.cluster_name, "my-cluster");
        assert!(bundle.pod_logs.is_empty());
        assert!(bundle.events.is_empty());
        assert!(bundle.resource_dump.is_empty());
        assert!(bundle.secrets_dump.is_none());
        assert!(bundle.node_info.is_empty());
        // captured_at should be a valid RFC3339 timestamp
        assert!(!bundle.captured_at.is_empty());
        assert!(
            chrono::DateTime::parse_from_rfc3339(&bundle.captured_at).is_ok(),
            "captured_at should be valid RFC3339"
        );
    }

    #[test]
    fn bundle_serialization_contains_expected_keys() {
        let mut bundle = DiagnosticBundle::new("claim-1", "cluster-a");
        bundle.pod_logs = vec![PodLog {
            namespace: "default".to_string(),
            pod: "nginx-0".to_string(),
            container: "nginx".to_string(),
            logs: "log line 1\nlog line 2".to_string(),
        }];
        bundle.events = r#"{"items":[]}"#.to_string();
        bundle.resource_dump = "--- Pods ---\n".to_string();
        bundle.node_info = r#"{"items":[]}"#.to_string();

        let json = serde_json::to_string_pretty(&bundle).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["claim_id"], "claim-1");
        assert_eq!(v["cluster_name"], "cluster-a");
        assert!(v["captured_at"].is_string());
        assert!(v["pod_logs"].is_array());
        assert_eq!(v["pod_logs"][0]["namespace"], "default");
        assert_eq!(v["pod_logs"][0]["pod"], "nginx-0");
        assert_eq!(v["pod_logs"][0]["container"], "nginx");
        assert!(v["pod_logs"][0]["logs"]
            .as_str()
            .unwrap()
            .contains("log line 1"));
        // secrets_dump should be omitted when None
        assert!(v.get("secrets_dump").is_none());
    }

    #[test]
    fn bundle_serialization_includes_secrets_when_set() {
        let mut bundle = DiagnosticBundle::new("claim-2", "cluster-b");
        bundle.secrets_dump = Some("secret-data".to_string());

        let json = serde_json::to_string_pretty(&bundle).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["secrets_dump"], "secret-data");
    }

    // -----------------------------------------------------------------------
    // capture_pod_logs tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_capture_pod_logs_empty() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        let empty_list = crate::testutil::k8s_list_response(Vec::<serde_json::Value>::new());
        Mock::given(method("GET"))
            .and(path("/api/v1/pods"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&empty_list))
            .mount(&server)
            .await;

        let result = capture_pod_logs(&client, 100).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_capture_pod_logs_with_pods() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        // LIST pods returns 1 pod with 1 container
        let pod_json = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "web-0", "namespace": "app-ns" },
            "spec": {
                "containers": [
                    { "name": "web", "image": "nginx:latest" }
                ]
            }
        });
        let pod_list = crate::testutil::k8s_list_response(vec![pod_json]);
        Mock::given(method("GET"))
            .and(path("/api/v1/pods"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&pod_list))
            .mount(&server)
            .await;

        // GET logs for that pod's container — kube-rs sends the log request
        // to /api/v1/namespaces/{ns}/pods/{name}/log with query params.
        // We match on the path only; query params are optional for the mock.
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/app-ns/pods/web-0/log"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello from web container"))
            .mount(&server)
            .await;

        let result = capture_pod_logs(&client, 50).await;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].namespace, "app-ns");
        assert_eq!(result[0].pod, "web-0");
        assert_eq!(result[0].container, "web");
        assert_eq!(result[0].logs, "hello from web container");
    }

    #[tokio::test]
    async fn test_capture_pod_logs_list_error_returns_empty() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        // Return 500 for pod listing
        Mock::given(method("GET"))
            .and(path("/api/v1/pods"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "metadata": {},
                "status": "Failure",
                "message": "internal server error",
                "reason": "InternalError",
                "code": 500,
            })))
            .mount(&server)
            .await;

        let result = capture_pod_logs(&client, 100).await;
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // capture_events tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_capture_events_success() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        let event = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Event",
            "metadata": { "name": "ev-1", "namespace": "default" },
            "involvedObject": {
                "kind": "Pod",
                "name": "web-0",
                "namespace": "default",
                "apiVersion": "v1"
            },
            "reason": "Pulled",
            "message": "Successfully pulled image",
            "type": "Normal"
        });
        let event_list = crate::testutil::k8s_list_response(vec![event]);
        Mock::given(method("GET"))
            .and(path("/api/v1/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&event_list))
            .mount(&server)
            .await;

        let result = capture_events(&client).await;
        assert!(!result.is_empty());
        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed["items"].is_array());
    }

    #[tokio::test]
    async fn test_capture_events_error() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        Mock::given(method("GET"))
            .and(path("/api/v1/events"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "metadata": {},
                "status": "Failure",
                "message": "internal error",
                "reason": "InternalError",
                "code": 500,
            })))
            .mount(&server)
            .await;

        let result = capture_events(&client).await;
        assert!(
            result.starts_with("CAPTURE FAILED:"),
            "Expected error string, got: {result}"
        );
    }

    // -----------------------------------------------------------------------
    // capture_resource_dump tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_capture_resource_dump_success() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        // Mock LIST pods
        let pod = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "p1", "namespace": "default" },
            "spec": { "containers": [{ "name": "c1", "image": "img" }] }
        });
        Mock::given(method("GET"))
            .and(path("/api/v1/pods"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(crate::testutil::k8s_list_response(vec![pod])),
            )
            .mount(&server)
            .await;

        // Mock LIST services
        let svc = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "svc-1", "namespace": "default" },
            "spec": { "type": "ClusterIP", "ports": [] }
        });
        Mock::given(method("GET"))
            .and(path("/api/v1/services"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(crate::testutil::k8s_list_response(vec![svc])),
            )
            .mount(&server)
            .await;

        // Mock LIST deployments
        let deploy = serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "dep-1", "namespace": "default" },
            "spec": {
                "replicas": 1,
                "selector": { "matchLabels": { "app": "dep" } },
                "template": {
                    "metadata": { "labels": { "app": "dep" } },
                    "spec": { "containers": [{ "name": "c", "image": "img" }] }
                }
            }
        });
        Mock::given(method("GET"))
            .and(path("/apis/apps/v1/deployments"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(crate::testutil::k8s_list_response(vec![deploy])),
            )
            .mount(&server)
            .await;

        let result = capture_resource_dump(&client).await;
        assert!(result.contains("--- Pods ---"), "Expected pods section");
        assert!(
            result.contains("--- Services ---"),
            "Expected services section"
        );
        assert!(
            result.contains("--- Deployments ---"),
            "Expected deployments section"
        );
    }

    // -----------------------------------------------------------------------
    // capture_secrets tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_capture_secrets_success() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "my-secret", "namespace": "default" },
            "type": "Opaque",
            "data": { "key": "dmFsdWU=" }
        });
        Mock::given(method("GET"))
            .and(path("/api/v1/secrets"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(crate::testutil::k8s_list_response(vec![secret])),
            )
            .mount(&server)
            .await;

        let result = capture_secrets(&client).await;
        assert!(!result.is_empty());
        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed["items"].is_array());
    }

    #[tokio::test]
    async fn test_capture_secrets_error() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        Mock::given(method("GET"))
            .and(path("/api/v1/secrets"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "metadata": {},
                "status": "Failure",
                "message": "internal error",
                "reason": "InternalError",
                "code": 500,
            })))
            .mount(&server)
            .await;

        let result = capture_secrets(&client).await;
        assert!(
            result.starts_with("CAPTURE FAILED:"),
            "Expected error string, got: {result}"
        );
    }

    // -----------------------------------------------------------------------
    // capture_node_info tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_capture_node_info_success() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        let node = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": { "name": "node-1" },
            "status": {
                "conditions": [
                    { "type": "Ready", "status": "True" }
                ]
            }
        });
        Mock::given(method("GET"))
            .and(path("/api/v1/nodes"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(crate::testutil::k8s_list_response(vec![node])),
            )
            .mount(&server)
            .await;

        let result = capture_node_info(&client).await;
        assert!(!result.is_empty());
        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(parsed["items"].is_array());
    }

    #[tokio::test]
    async fn test_capture_node_info_error() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        Mock::given(method("GET"))
            .and(path("/api/v1/nodes"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "metadata": {},
                "status": "Failure",
                "message": "internal error",
                "reason": "InternalError",
                "code": 500,
            })))
            .mount(&server)
            .await;

        let result = capture_node_info(&client).await;
        assert!(
            result.starts_with("CAPTURE FAILED:"),
            "Expected error string, got: {result}"
        );
    }

    // -----------------------------------------------------------------------
    // upload_to_s3 URI parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn s3_uri_parsing_bucket_only() {
        // Inline test of the URI parsing logic from upload_to_s3
        let storage_uri = "s3://my-bucket";
        let uri = storage_uri.strip_prefix("s3://").unwrap();
        let (bucket, prefix) = uri.split_once('/').unwrap_or((uri, ""));
        assert_eq!(bucket, "my-bucket");
        assert_eq!(prefix, "");

        let claim_id = "claim-1";
        let key = if prefix.is_empty() {
            format!("{claim_id}/diagnostics.json")
        } else {
            let prefix = prefix.trim_end_matches('/');
            format!("{prefix}/{claim_id}/diagnostics.json")
        };
        assert_eq!(key, "claim-1/diagnostics.json");
    }

    #[test]
    fn s3_uri_parsing_with_prefix() {
        let storage_uri = "s3://my-bucket/some/prefix/";
        let uri = storage_uri.strip_prefix("s3://").unwrap();
        let (bucket, prefix) = uri.split_once('/').unwrap_or((uri, ""));
        assert_eq!(bucket, "my-bucket");

        let claim_id = "claim-1";
        let key = if prefix.is_empty() {
            format!("{claim_id}/diagnostics.json")
        } else {
            let prefix = prefix.trim_end_matches('/');
            format!("{prefix}/{claim_id}/diagnostics.json")
        };
        assert_eq!(key, "some/prefix/claim-1/diagnostics.json");
    }

    #[test]
    fn s3_uri_parsing_rejects_non_s3() {
        let storage_uri = "gs://wrong-scheme/path";
        assert!(
            storage_uri.strip_prefix("s3://").is_none(),
            "Non-s3 URIs should not parse"
        );
    }
}
