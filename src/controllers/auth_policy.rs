use std::sync::Arc;

use futures::StreamExt;
use kube::api::{Api, ListParams};
use kube::runtime::watcher::{self, Config, Event};
use kube::Client;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::api::auth::JwtAuthenticator;
use crate::crd::AccessPolicy;

/// Watch AccessPolicy CRDs and update the authenticator whenever they change.
///
/// On any change (create, update, delete), re-lists all AccessPolicies and
/// compiles them into the authenticator's provider lookup table.
pub async fn run_auth_policy_watcher(
    client: Client,
    namespace: &str,
    authenticator: Arc<JwtAuthenticator>,
    shutdown: CancellationToken,
) {
    let policies_api: Api<AccessPolicy> = Api::namespaced(client.clone(), namespace);

    // Initial load — populate before the HTTP server starts accepting requests
    load_policies(&policies_api, &authenticator).await;

    info!("Starting AccessPolicy watcher");

    let watcher = watcher::watcher(policies_api.clone(), Config::default());
    let mut stream = Box::pin(watcher);

    loop {
        tokio::select! {
            event = stream.next() => {
                match event {
                    Some(Ok(Event::Apply(_) | Event::Delete(_))) => {
                        load_policies(&policies_api, &authenticator).await;
                    }
                    Some(Ok(Event::Init | Event::InitApply(_) | Event::InitDone)) => {
                        // Initial list completed — reload all policies
                        load_policies(&policies_api, &authenticator).await;
                    }
                    Some(Err(e)) => {
                        error!("AccessPolicy watcher error: {e}");
                    }
                    None => {
                        info!("AccessPolicy watcher stream ended");
                        break;
                    }
                }
            }
            _ = shutdown.cancelled() => {
                info!("AccessPolicy watcher shutting down");
                break;
            }
        }
    }
}

/// List all AccessPolicy CRDs and update the authenticator.
async fn load_policies(api: &Api<AccessPolicy>, authenticator: &JwtAuthenticator) {
    match api.list(&ListParams::default()).await {
        Ok(list) => {
            let count = list.items.len();
            authenticator.update_policies(list.items).await;
            info!(count, "Loaded AccessPolicy CRDs");
        }
        Err(e) => {
            error!("Failed to list AccessPolicy CRDs: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn mock_client(server: &MockServer) -> Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::testutil::mock_k8s_client(server)
    }

    fn access_policy_item(name: &str, issuer: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "kobe.kunobi.ninja/v1alpha1",
            "kind": "AccessPolicy",
            "metadata": { "name": name },
            "spec": {
                "auth": {
                    "oidc": {
                        "issuer": issuer,
                        "audience": ["https://github.com/my-org"]
                    }
                },
                "rules": [{
                    "pools": ["*"],
                    "maxTtl": "1h",
                    "maxConcurrentLeases": 10
                }]
            }
        })
    }

    #[tokio::test]
    async fn test_load_policies_updates_authenticator() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        let items = vec![
            access_policy_item(
                "github-policy",
                "https://token.actions.githubusercontent.com",
            ),
            access_policy_item("clerk-policy", "https://clerk.example.com"),
        ];

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/accesspolicies",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(crate::testutil::k8s_list_response(items)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let authenticator = JwtAuthenticator::new();
        let policies_api: Api<AccessPolicy> = Api::namespaced(client, "test-ns");

        load_policies(&policies_api, &authenticator).await;

        // Verify the authenticator has both providers compiled
        // No match clause — look up by policy name alone
        let github_policy = authenticator
            .policy_for_requester_type("github-policy")
            .await;
        assert!(
            github_policy.is_some(),
            "github-policy should be present after load_policies"
        );
        let policy = github_policy.unwrap();
        assert_eq!(policy.allowed_pools, vec!["*"]);
        assert_eq!(policy.max_concurrent_leases, 10);

        let clerk_policy = authenticator
            .policy_for_requester_type("clerk-policy")
            .await;
        assert!(
            clerk_policy.is_some(),
            "clerk-policy should be present after load_policies"
        );
    }

    #[tokio::test]
    async fn test_load_policies_empty() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/accesspolicies",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                crate::testutil::k8s_list_response::<serde_json::Value>(vec![]),
            ))
            .expect(1)
            .mount(&server)
            .await;

        let authenticator = JwtAuthenticator::new();
        let policies_api: Api<AccessPolicy> = Api::namespaced(client, "test-ns");

        load_policies(&policies_api, &authenticator).await;

        // Authenticator should have no providers
        let result = authenticator.policy_for_requester_type("anything").await;
        assert!(
            result.is_none(),
            "policy_for_requester_type should return None with empty policies"
        );
    }

    #[tokio::test]
    async fn test_load_policies_api_error() {
        let server = MockServer::start().await;
        let client = mock_client(&server);

        let error_response = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Status",
            "metadata": {},
            "status": "Failure",
            "message": "Internal server error",
            "reason": "InternalError",
            "code": 500
        });

        Mock::given(method("GET"))
            .and(path(
                "/apis/kobe.kunobi.ninja/v1alpha1/namespaces/test-ns/accesspolicies",
            ))
            .respond_with(ResponseTemplate::new(500).set_body_json(error_response))
            .expect(1)
            .mount(&server)
            .await;

        let authenticator = JwtAuthenticator::new();
        let policies_api: Api<AccessPolicy> = Api::namespaced(client, "test-ns");

        // Should complete without panic — logs the error and returns early
        load_policies(&policies_api, &authenticator).await;

        // Authenticator should remain empty (no policies loaded)
        let result = authenticator.policy_for_requester_type("anything").await;
        assert!(
            result.is_none(),
            "policy_for_requester_type should return None after API error"
        );
    }
}
