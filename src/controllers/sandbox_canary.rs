//! Pool-defined execution canary for Sandbox readiness (#73).
//!
//! # Why the upstream `Ready` condition is not enough
//!
//! Upstream reports `Ready` when the Sandbox's Pod is running and its probes
//! pass. That is a statement about the *container*, not about the agent inside
//! it. A Pod whose entrypoint crashed into a restart loop, whose model weights
//! failed to mount, or whose agent process is wedged on a lock can satisfy
//! every one of those checks — and the moment Kobe believes it, the caller's
//! runtime TTL starts and they are charged for a Sandbox that cannot serve.
//!
//! The canary closes that gap by asking the workload itself. Each pool declares
//! an argv and a timeout in `spec.readiness.canary`; readiness means that
//! command exited zero inside the Sandbox.
//!
//! # Administrator-owned, never caller-owned
//!
//! The argv comes from the `SandboxPool` spec, which only an administrator can
//! write. A lease selects a pool and nothing else. Were the argv reachable from
//! lease intent, this would be a remote-execution primitive against the
//! operator's own credentials rather than a health check.
//!
//! # Failing the canary is not the same as failing to run it
//!
//! A canary that runs and exits non-zero is evidence the Sandbox is not ready.
//! A canary that cannot be run at all — the Pod not resolvable yet, an exec
//! that times out, RBAC refused — is *absence of evidence*, and it is treated
//! as "not ready yet" rather than as either a pass or a hard failure. The
//! provisioning deadline already bounds how long that may continue, so an
//! unrunnable canary ends as an expiry rather than as a lease that hangs.

use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ApiResource, AttachParams, DynamicObject, ListParams};
use kube::{Client, ResourceExt};
use tracing::{debug, warn};

use crate::crd::SandboxExecutionCanary;

/// The upstream `Sandbox` kind, which lives in the *core* Agent Sandbox group —
/// not the `extensions.` group the templates, warm pools and claims are in.
pub const SANDBOX_API_VERSION: &str = "agents.x-k8s.io/v1beta1";
pub const SANDBOX_KIND: &str = "Sandbox";

/// What one canary attempt established.
///
/// Three outcomes, because "the agent said no" and "nobody could ask" are
/// different facts. Collapsing them would either mark a broken Sandbox ready
/// or fail a healthy one for a transient API error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryOutcome {
    /// The command ran inside the Sandbox and exited zero.
    Passed,
    /// The command ran and did not exit zero. The Sandbox is not ready.
    Failed { reason: String },
    /// The command could not be run. No conclusion either way.
    Inconclusive { reason: String },
}

impl CanaryOutcome {
    /// Only an observed success starts the clock.
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Passed)
    }

    /// Bounded reason code for status, events and logs — never a raw command
    /// output, which is workload data and may carry secrets.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Passed => "canary_passed",
            Self::Failed { .. } => "canary_failed",
            Self::Inconclusive { .. } => "canary_inconclusive",
        }
    }
}

fn sandbox_resource() -> ApiResource {
    ApiResource {
        group: "agents.x-k8s.io".into(),
        version: "v1beta1".into(),
        api_version: SANDBOX_API_VERSION.into(),
        kind: SANDBOX_KIND.into(),
        plural: "sandboxes".into(),
    }
}

/// Resolve the Pod backing one claim, following only documented upstream
/// fields.
///
/// `claim.status.sandbox.name` names the Sandbox, and `sandbox.status.selector`
/// is upstream's own label selector for its Pods. Both are followed rather than
/// guessed from a naming convention: a convention that upstream changes would
/// silently start selecting the wrong Pod, and the wrong Pod is one belonging
/// to another tenant.
/// The exact upstream objects behind one claim.
///
/// Identities, not just names: #81 resolves every Sandbox operation through
/// these UIDs, and a name that was reused between placement and access would
/// otherwise route a caller's exec into somebody else's Pod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSandboxPod {
    pub sandbox_name: String,
    pub sandbox_uid: String,
    pub pod_name: String,
    pub pod_uid: String,
}

pub async fn resolve_sandbox_pod(
    client: &Client,
    namespace: &str,
    claim: &DynamicObject,
) -> Result<Option<ResolvedSandboxPod>, String> {
    let Some(sandbox_name) = claim
        .data
        .get("status")
        .and_then(|status| status.get("sandbox"))
        .and_then(|sandbox| sandbox.get("name"))
        .and_then(|name| name.as_str())
        .filter(|name| !name.is_empty())
    else {
        // Normal immediately after readiness: the claim is bound but its status
        // has not been written back yet.
        return Ok(None);
    };

    let sandboxes: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), namespace, &sandbox_resource());
    let sandbox = match sandboxes.get(sandbox_name).await {
        Ok(sandbox) => sandbox,
        Err(kube::Error::Api(error)) if error.code == 404 => return Ok(None),
        Err(error) => return Err(format!("sandbox lookup failed: {error}")),
    };

    let Some(selector) = sandbox
        .data
        .get("status")
        .and_then(|status| status.get("selector"))
        .and_then(|selector| selector.as_str())
        .filter(|selector| !selector.is_empty())
    else {
        return Ok(None);
    };

    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let matching = pods
        .list(&ListParams::default().labels(selector))
        .await
        .map_err(|error| format!("pod lookup failed: {error}"))?;

    // Exactly one running Pod, or none. An ambiguous selector is refused
    // rather than resolved arbitrarily: executing into "whichever came first"
    // is how a canary ends up talking to a Pod that is not this lease's.
    let mut running = matching.into_iter().filter(|pod| {
        pod.status
            .as_ref()
            .and_then(|status| status.phase.as_deref())
            == Some("Running")
            && pod.metadata.deletion_timestamp.is_none()
    });
    let Some(pod) = running.next() else {
        return Ok(None);
    };
    if running.next().is_some() {
        return Err("sandbox selector matched more than one running pod".to_string());
    }

    // A Pod with no UID cannot be fenced, and an unfenceable target is one a
    // later same-named Pod could impersonate.
    let (Some(sandbox_uid), Some(pod_uid)) = (sandbox.uid(), pod.uid()) else {
        return Ok(None);
    };
    Ok(Some(ResolvedSandboxPod {
        sandbox_name: sandbox_name.to_string(),
        sandbox_uid,
        pod_name: pod.name_any(),
        pod_uid,
    }))
}

/// Run one pool-declared canary inside the Sandbox Pod.
///
/// The exec is wrapped in the pool's own timeout. Without it a wedged agent —
/// exactly the failure this check exists to catch — would hang the reconcile
/// rather than fail it, taking the controller's whole worker slot with it.
pub async fn run_canary(
    client: &Client,
    namespace: &str,
    pod: &str,
    container: &str,
    canary: &SandboxExecutionCanary,
) -> CanaryOutcome {
    let Some(timeout) = crate::pool::parse_duration(&canary.timeout)
        .and_then(|timeout| timeout.to_std().ok().filter(|timeout| !timeout.is_zero()))
    else {
        return CanaryOutcome::Inconclusive {
            reason: "canary timeout is not a valid positive duration".to_string(),
        };
    };

    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let params = AttachParams::default()
        .container(container)
        .stdin(false)
        .stdout(true)
        .stderr(true);

    let attached = match tokio::time::timeout(timeout, pods.exec(pod, &canary.argv, &params)).await
    {
        Ok(Ok(attached)) => attached,
        Ok(Err(error)) => {
            return CanaryOutcome::Inconclusive {
                reason: format!("exec could not be started: {error}"),
            };
        }
        Err(_) => {
            return CanaryOutcome::Inconclusive {
                reason: "exec did not start within the canary timeout".to_string(),
            };
        }
    };

    let mut attached = attached;
    let status = match tokio::time::timeout(timeout, attached.take_status().unwrap()).await {
        Ok(status) => status,
        Err(_) => {
            // Wedged. Abort so the connection does not outlive the reconcile.
            attached.abort();
            return CanaryOutcome::Failed {
                reason: "canary did not complete within its timeout".to_string(),
            };
        }
    };

    interpret_exec_status(status)
}

/// Turn an exec `Status` into a verdict.
///
/// Split out from the exec itself so the rule is testable without a cluster,
/// and because the interesting judgement is here: a *missing* status means the
/// command's fate is unknown, which must not read as success.
pub fn interpret_exec_status(
    status: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Status>,
) -> CanaryOutcome {
    let Some(status) = status else {
        return CanaryOutcome::Inconclusive {
            reason: "exec returned no completion status".to_string(),
        };
    };
    match status.status.as_deref() {
        Some("Success") => CanaryOutcome::Passed,
        // Upstream reports a non-zero exit as `Failure` with reason
        // `NonZeroExitCode`. The command ran; the workload said no.
        Some("Failure") => CanaryOutcome::Failed {
            reason: status
                .reason
                .unwrap_or_else(|| "canary exited non-zero".to_string()),
        },
        // Anything else is a shape this build does not understand. Refusing to
        // guess is the point: guessing "success" marks a broken Sandbox ready.
        other => CanaryOutcome::Inconclusive {
            reason: format!("unrecognised exec status: {}", other.unwrap_or("<none>")),
        },
    }
}

/// Run the pool's canary against a claim, resolving the Pod first.
///
/// Every failure to *reach* the workload is inconclusive rather than a pass or
/// a failure. The provisioning deadline bounds how long that may repeat.
pub async fn evaluate_readiness_canary(
    client: &Client,
    namespace: &str,
    claim: &DynamicObject,
    container: &str,
    canary: &SandboxExecutionCanary,
) -> CanaryOutcome {
    let pod = match resolve_sandbox_pod(client, namespace, claim).await {
        Ok(Some(resolved)) => resolved.pod_name,
        Ok(None) => {
            debug!(claim = %claim.name_any(), "sandbox pod not resolvable yet");
            return CanaryOutcome::Inconclusive {
                reason: "sandbox pod is not resolvable yet".to_string(),
            };
        }
        Err(reason) => {
            warn!(claim = %claim.name_any(), reason, "could not resolve sandbox pod");
            return CanaryOutcome::Inconclusive { reason };
        }
    };
    run_canary(client, namespace, &pod, container, canary).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Status;

    fn status(value: &str, reason: Option<&str>) -> Option<Status> {
        Some(Status {
            status: Some(value.to_string()),
            reason: reason.map(str::to_string),
            ..Default::default()
        })
    }

    /// Only an observed `Success` is a pass.
    ///
    /// This is the whole value of the canary: everything it cannot confirm has
    /// to fall short of "ready", because the alternative is starting a paid
    /// runtime TTL on a Sandbox that cannot serve.
    #[test]
    fn only_an_observed_success_passes() {
        assert_eq!(
            interpret_exec_status(status("Success", None)),
            CanaryOutcome::Passed
        );

        // The command ran and said no.
        let failed = interpret_exec_status(status("Failure", Some("NonZeroExitCode")));
        assert!(matches!(failed, CanaryOutcome::Failed { .. }));
        assert_eq!(failed.reason_code(), "canary_failed");
        assert!(!failed.is_pass());

        // Nobody could ask, or the answer was a shape we do not understand.
        for unknown in [None, status("Weird", None), status("", None)] {
            let outcome = interpret_exec_status(unknown);
            assert!(
                matches!(outcome, CanaryOutcome::Inconclusive { .. }),
                "expected inconclusive, got {outcome:?}"
            );
            assert!(!outcome.is_pass());
        }
    }

    /// A malformed timeout must not run an unbounded exec.
    ///
    /// The canary exists to catch a wedged agent. An exec with no bound against
    /// exactly that workload would hang the reconcile and take a controller
    /// worker with it — turning a detectable fault into an outage.
    #[tokio::test]
    async fn a_malformed_timeout_refuses_to_run_the_canary() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        for bad in ["", "  ", "0s", "not-a-duration", "-5m"] {
            let canary = SandboxExecutionCanary {
                argv: vec!["/agent".into(), "health".into()],
                timeout: bad.to_string(),
            };
            let outcome = run_canary(&client, "test-ns", "pod-1", "agent", &canary).await;
            assert!(
                matches!(outcome, CanaryOutcome::Inconclusive { .. }),
                "timeout {bad:?} must not run an unbounded exec, got {outcome:?}"
            );
        }

        // Nothing was ever sent: the refusal happens before the API is touched.
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty()
        );
    }

    /// The Pod is found through upstream's own fields, not a naming guess.
    ///
    /// A claim whose status is not yet populated is "not yet", never an error
    /// and never a pass — that state is normal for the first moments after the
    /// Ready condition appears.
    #[tokio::test]
    async fn an_unpopulated_claim_status_resolves_to_no_pod() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        for data in [
            serde_json::json!({}),
            serde_json::json!({ "status": {} }),
            serde_json::json!({ "status": { "sandbox": {} } }),
            serde_json::json!({ "status": { "sandbox": { "name": "" } } }),
        ] {
            let mut claim = DynamicObject::new(
                "kobe-sbx-1",
                &ApiResource {
                    group: "extensions.agents.x-k8s.io".into(),
                    version: "v1beta1".into(),
                    api_version: "extensions.agents.x-k8s.io/v1beta1".into(),
                    kind: "SandboxClaim".into(),
                    plural: "sandboxclaims".into(),
                },
            );
            claim.data = data.clone();
            assert_eq!(
                resolve_sandbox_pod(&client, "test-ns", &claim).await,
                Ok(None),
                "must not resolve a pod from {data}"
            );
        }

        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "an unpopulated status is answered without an API call"
        );
    }

    /// An ambiguous selector is refused rather than resolved arbitrarily.
    ///
    /// Executing into "whichever Pod came back first" is how a canary ends up
    /// talking to a Pod that belongs to another lease.
    #[tokio::test]
    async fn an_ambiguous_selector_is_refused() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        Mock::given(method("GET"))
            .and(path(
                "/apis/agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxes/sbx",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": SANDBOX_API_VERSION,
                "kind": SANDBOX_KIND,
                "metadata": { "name": "sbx", "namespace": "test-ns" },
                "status": { "selector": "agents.x-k8s.io/sandbox=sbx" },
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/test-ns/pods"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "PodList",
                "metadata": { "resourceVersion": "1" },
                "items": [
                    { "metadata": { "name": "pod-a", "namespace": "test-ns" },
                      "status": { "phase": "Running" } },
                    { "metadata": { "name": "pod-b", "namespace": "test-ns" },
                      "status": { "phase": "Running" } },
                ],
            })))
            .mount(&server)
            .await;

        let mut claim = DynamicObject::new(
            "kobe-sbx-1",
            &ApiResource {
                group: "extensions.agents.x-k8s.io".into(),
                version: "v1beta1".into(),
                api_version: "extensions.agents.x-k8s.io/v1beta1".into(),
                kind: "SandboxClaim".into(),
                plural: "sandboxclaims".into(),
            },
        );
        claim.data = serde_json::json!({ "status": { "sandbox": { "name": "sbx" } } });

        assert!(
            resolve_sandbox_pod(&client, "test-ns", &claim)
                .await
                .is_err(),
            "two running pods must be an error, not a coin flip"
        );
    }

    /// A Pod that is terminating is not a Pod to execute in.
    ///
    /// It still reports `Running` for the whole of its grace period, so a check
    /// on phase alone would run the canary against a Sandbox on its way out —
    /// and either pass on borrowed time or fail for the wrong reason.
    #[tokio::test]
    async fn a_terminating_pod_is_not_selected() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = wiremock::MockServer::start().await;
        let client = crate::testutil::mock_k8s_client(&server);

        Mock::given(method("GET"))
            .and(path(
                "/apis/agents.x-k8s.io/v1beta1/namespaces/test-ns/sandboxes/sbx",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": SANDBOX_API_VERSION,
                "kind": SANDBOX_KIND,
                "metadata": { "name": "sbx", "namespace": "test-ns" },
                "status": { "selector": "agents.x-k8s.io/sandbox=sbx" },
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/namespaces/test-ns/pods"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "PodList",
                "metadata": { "resourceVersion": "1" },
                "items": [{
                    "metadata": {
                        "name": "pod-a",
                        "namespace": "test-ns",
                        "deletionTimestamp": "2026-01-01T00:00:00Z",
                    },
                    "status": { "phase": "Running" },
                }],
            })))
            .mount(&server)
            .await;

        let mut claim = DynamicObject::new(
            "kobe-sbx-1",
            &ApiResource {
                group: "extensions.agents.x-k8s.io".into(),
                version: "v1beta1".into(),
                api_version: "extensions.agents.x-k8s.io/v1beta1".into(),
                kind: "SandboxClaim".into(),
                plural: "sandboxclaims".into(),
            },
        );
        claim.data = serde_json::json!({ "status": { "sandbox": { "name": "sbx" } } });

        assert_eq!(
            resolve_sandbox_pod(&client, "test-ns", &claim).await,
            Ok(None)
        );
    }
}
