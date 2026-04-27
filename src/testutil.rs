//! Test utilities: mock backend, wiremock helpers, and K8s response builders.
//!
//! This module is compiled only under `#[cfg(test)]`.

use std::sync::{Arc, Mutex};

use anyhow::Result;

use crate::backend::ClusterBackend;
use crate::crd::{Addon, ClusterConfig, ReadinessGate};

// ---------------------------------------------------------------------------
// MockBackend – records every call and returns configurable results
// ---------------------------------------------------------------------------

/// Describes a single recorded call on [`MockBackend`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockCall {
    Create {
        name: String,
        namespace: String,
    },
    Delete {
        name: String,
        namespace: String,
    },
    CheckHealth {
        name: String,
        namespace: String,
    },
    ExtractKubeconfig {
        name: String,
        namespace: String,
    },
    CheckReadinessGate {
        name: String,
        namespace: String,
    },
    ApplyAddon {
        name: String,
        namespace: String,
        addon_name: String,
    },
}

/// Snapshot of how many calls of each kind have been recorded.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MockCalls {
    pub create: usize,
    pub delete: usize,
    pub check_health: usize,
    pub extract_kubeconfig: usize,
    pub check_readiness_gate: usize,
    pub apply_addon: usize,
}

/// Shared inner state behind an `Arc` so that [`MockBackend`] is `Clone`.
#[derive(Debug)]
struct MockInner {
    calls: Mutex<Vec<MockCall>>,
    create_error: Mutex<Option<String>>,
    healthy: Mutex<bool>,
    kubeconfig: Mutex<String>,
    ready: Mutex<bool>,
    readiness_error: Mutex<Option<String>>,
}

/// A hand-written test double for [`ClusterBackend`].
///
/// * Records every call in a shared log.
/// * Returns configurable results (defaults: success, healthy, ready,
///   kubeconfig = `"mock-kubeconfig"`).
/// * Is `Clone` + `Send` + `Sync` (via `Arc`).
#[derive(Debug, Clone)]
pub struct MockBackend {
    inner: Arc<MockInner>,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBackend {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MockInner {
                calls: Mutex::new(Vec::new()),
                create_error: Mutex::new(None),
                healthy: Mutex::new(true),
                kubeconfig: Mutex::new("mock-kubeconfig".to_string()),
                ready: Mutex::new(true),
                readiness_error: Mutex::new(None),
            }),
        }
    }

    // -- configuration helpers --

    /// Make subsequent `create` calls return an error with the given message.
    pub fn fail_create(&self, msg: &str) {
        *self.inner.create_error.lock().unwrap() = Some(msg.to_string());
    }

    /// Set the boolean returned by `check_health`.
    pub fn set_health(&self, healthy: bool) {
        *self.inner.healthy.lock().unwrap() = healthy;
    }

    /// Set the kubeconfig string returned by `extract_kubeconfig`.
    pub fn set_kubeconfig(&self, kc: &str) {
        *self.inner.kubeconfig.lock().unwrap() = kc.to_string();
    }

    /// Set the boolean returned by `check_readiness_gate`.
    pub fn set_readiness(&self, ready: bool) {
        *self.inner.ready.lock().unwrap() = ready;
    }

    /// Make subsequent `check_readiness_gate` calls return an error.
    pub fn fail_readiness(&self, msg: &str) {
        *self.inner.readiness_error.lock().unwrap() = Some(msg.to_string());
    }

    // -- introspection helpers --

    /// Return the raw list of recorded calls.
    pub fn calls(&self) -> Vec<MockCall> {
        self.inner.calls.lock().unwrap().clone()
    }

    /// Return a summary count of calls by kind.
    pub fn call_count(&self) -> MockCalls {
        let calls = self.inner.calls.lock().unwrap();
        let mut counts = MockCalls::default();
        for c in calls.iter() {
            match c {
                MockCall::Create { .. } => counts.create += 1,
                MockCall::Delete { .. } => counts.delete += 1,
                MockCall::CheckHealth { .. } => counts.check_health += 1,
                MockCall::ExtractKubeconfig { .. } => counts.extract_kubeconfig += 1,
                MockCall::CheckReadinessGate { .. } => counts.check_readiness_gate += 1,
                MockCall::ApplyAddon { .. } => counts.apply_addon += 1,
            }
        }
        counts
    }
}

impl ClusterBackend for MockBackend {
    async fn create(
        &self,
        name: &str,
        namespace: &str,
        _config: &ClusterConfig,
        _addons: &[Addon],
    ) -> Result<()> {
        self.inner.calls.lock().unwrap().push(MockCall::Create {
            name: name.to_string(),
            namespace: namespace.to_string(),
        });
        if let Some(msg) = self.inner.create_error.lock().unwrap().as_ref() {
            anyhow::bail!("{msg}");
        }
        Ok(())
    }

    async fn delete(&self, name: &str, namespace: &str) -> Result<()> {
        self.inner.calls.lock().unwrap().push(MockCall::Delete {
            name: name.to_string(),
            namespace: namespace.to_string(),
        });
        Ok(())
    }

    async fn check_health(&self, name: &str, namespace: &str) -> Result<bool> {
        self.inner
            .calls
            .lock()
            .unwrap()
            .push(MockCall::CheckHealth {
                name: name.to_string(),
                namespace: namespace.to_string(),
            });
        Ok(*self.inner.healthy.lock().unwrap())
    }

    async fn extract_kubeconfig(&self, name: &str, namespace: &str) -> Result<String> {
        self.inner
            .calls
            .lock()
            .unwrap()
            .push(MockCall::ExtractKubeconfig {
                name: name.to_string(),
                namespace: namespace.to_string(),
            });
        Ok(self.inner.kubeconfig.lock().unwrap().clone())
    }

    async fn check_readiness_gate(
        &self,
        name: &str,
        namespace: &str,
        _gate: &ReadinessGate,
    ) -> Result<bool> {
        self.inner
            .calls
            .lock()
            .unwrap()
            .push(MockCall::CheckReadinessGate {
                name: name.to_string(),
                namespace: namespace.to_string(),
            });
        if let Some(msg) = self.inner.readiness_error.lock().unwrap().as_ref() {
            anyhow::bail!("{msg}");
        }
        Ok(*self.inner.ready.lock().unwrap())
    }

    async fn apply_addon(&self, name: &str, namespace: &str, addon: &Addon) -> Result<()> {
        self.inner.calls.lock().unwrap().push(MockCall::ApplyAddon {
            name: name.to_string(),
            namespace: namespace.to_string(),
            addon_name: addon.name.clone(),
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// wiremock / kube::Client helper
// ---------------------------------------------------------------------------

/// Build a `kube::Client` that talks to a local [`wiremock::MockServer`].
#[allow(dead_code)]
pub fn mock_k8s_client(server: &wiremock::MockServer) -> kube::Client {
    let config = kube::Config {
        cluster_url: server.uri().parse().unwrap(),
        default_namespace: "test-ns".into(),
        ..kube::Config::new(server.uri().parse().unwrap())
    };
    kube::Client::try_from(config).unwrap()
}

// ---------------------------------------------------------------------------
// K8s response helpers
// ---------------------------------------------------------------------------

/// Build a Kubernetes-style **list** response envelope.
///
/// ```json
/// { "apiVersion": "v1", "kind": "List", "metadata": {}, "items": [...] }
/// ```
pub fn k8s_list_response<T: serde::Serialize>(items: Vec<T>) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "List",
        "metadata": { "resourceVersion": "" },
        "items": items,
    })
}

/// Build a Kubernetes-style **404 Not Found** error response.
pub fn k8s_not_found(resource: &str, name: &str) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1",
        "kind": "Status",
        "metadata": {},
        "status": "Failure",
        "message": format!("{resource} \"{name}\" not found"),
        "reason": "NotFound",
        "details": { "name": name, "kind": resource },
        "code": 404,
    })
}

// ---------------------------------------------------------------------------
// Tests for the helpers themselves
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> ClusterConfig {
        ClusterConfig {
            version: "v1.31.3+k3s1".to_string(),
            servers: 1,
            agents: None,
            server_args: vec![],
            persistence: None,
            expose: None,
            taints: None,
        }
    }

    // -- MockBackend default behaviour --

    #[tokio::test]
    async fn mock_backend_default_create_succeeds() {
        let mock = MockBackend::new();
        let result = mock.create("c1", "ns", &sample_config(), &[]).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_backend_default_delete_succeeds() {
        let mock = MockBackend::new();
        let result = mock.delete("c1", "ns").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn mock_backend_default_health_returns_true() {
        let mock = MockBackend::new();
        let healthy = mock.check_health("c1", "ns").await.unwrap();
        assert!(healthy);
    }

    #[tokio::test]
    async fn mock_backend_default_kubeconfig_returns_value() {
        let mock = MockBackend::new();
        let kc = mock.extract_kubeconfig("c1", "ns").await.unwrap();
        assert_eq!(kc, "mock-kubeconfig");
    }

    // -- configured failures --

    #[tokio::test]
    async fn mock_backend_fail_create_returns_error() {
        let mock = MockBackend::new();
        mock.fail_create("boom");
        let result = mock.create("c1", "ns", &sample_config(), &[]).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("boom"));
    }

    #[tokio::test]
    async fn mock_backend_set_health_false() {
        let mock = MockBackend::new();
        mock.set_health(false);
        let healthy = mock.check_health("c1", "ns").await.unwrap();
        assert!(!healthy);
    }

    #[tokio::test]
    async fn mock_backend_set_kubeconfig_custom() {
        let mock = MockBackend::new();
        mock.set_kubeconfig("custom-kc");
        let kc = mock.extract_kubeconfig("c1", "ns").await.unwrap();
        assert_eq!(kc, "custom-kc");
    }

    #[tokio::test]
    async fn mock_backend_set_readiness_false() {
        let mock = MockBackend::new();
        mock.set_readiness(false);
        let gate = ReadinessGate::CrdExists {
            name: "foo".to_string(),
        };
        let ready = mock.check_readiness_gate("c1", "ns", &gate).await.unwrap();
        assert!(!ready);
    }

    // -- call recording --

    #[tokio::test]
    async fn mock_backend_records_create_and_delete() {
        let mock = MockBackend::new();
        mock.create("c1", "ns1", &sample_config(), &[])
            .await
            .unwrap();
        mock.delete("c2", "ns2").await.unwrap();
        mock.create("c3", "ns3", &sample_config(), &[])
            .await
            .unwrap();

        let counts = mock.call_count();
        assert_eq!(counts.create, 2);
        assert_eq!(counts.delete, 1);
        assert_eq!(counts.check_health, 0);

        let calls = mock.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls[0],
            MockCall::Create {
                name: "c1".to_string(),
                namespace: "ns1".to_string(),
            }
        );
        assert_eq!(
            calls[1],
            MockCall::Delete {
                name: "c2".to_string(),
                namespace: "ns2".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn mock_backend_records_apply_addon() {
        let mock = MockBackend::new();
        let addon = Addon {
            name: "metrics".to_string(),
            manifest: Some("---".to_string()),
            url: None,
        };
        mock.apply_addon("c1", "ns", &addon).await.unwrap();
        let counts = mock.call_count();
        assert_eq!(counts.apply_addon, 1);
        assert_eq!(
            mock.calls()[0],
            MockCall::ApplyAddon {
                name: "c1".to_string(),
                namespace: "ns".to_string(),
                addon_name: "metrics".to_string(),
            }
        );
    }

    // -- K8s response helpers --

    #[test]
    fn k8s_list_response_wraps_items() {
        let resp = k8s_list_response(vec![serde_json::json!({"name": "a"})]);
        let items = resp["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(resp["kind"], "List");
    }

    #[test]
    fn k8s_not_found_has_correct_code() {
        let resp = k8s_not_found("pods", "my-pod");
        assert_eq!(resp["code"], 404);
        assert_eq!(resp["reason"], "NotFound");
        assert!(resp["message"].as_str().unwrap().contains("my-pod"));
    }
}
