//! Validation of an operator-installed upstream Agent Sandbox runtime.
//!
//! Kobe consumes `SandboxTemplate`, `SandboxWarmPool`, `SandboxClaim`, and
//! `Sandbox` from upstream Agent Sandbox. The operator installs and upgrades
//! Agent Sandbox v0.5.6; Kobe owns none of that installation. Before enabling
//! Sandbox admission, Kobe performs only read-only API/schema compatibility
//! checks. It never installs runtime resources or writes a sacrificial Claim.
//!
//! This is intentionally weaker than a live runtime canary: a compatible API
//! can still have a wedged controller. Actual tenant leases fail closed during
//! provisioning and run their administrator-declared readiness command before
//! becoming Ready.

use serde::{Deserialize, Serialize};

/// How the upstream Agent Sandbox runtime reaches a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AgentSandboxMode {
    /// New Sandbox admission and placement are off. Lifecycle and reaper loops
    /// remain cleanup-only so disabling the feature cannot strand prior work.
    #[default]
    Disabled,
    /// The operator installs and owns Agent Sandbox. Kobe only validates its
    /// consumed API surface and creates ordinary, lease-owned product objects.
    External,
}

impl AgentSandboxMode {
    /// Whether new Sandbox admission and placement may run.
    pub const fn enabled(self) -> bool {
        matches!(self, Self::External)
    }
}

/// Operator-installed Agent Sandbox release supported by this Kobe build.
pub const AGENT_SANDBOX_RELEASE: &str = "v0.5.6";

/// Extensions API version consumed by Kobe.
pub const REQUIRED_AGENT_SANDBOX_API_VERSION: &str = "extensions.agents.x-k8s.io/v1beta1";

/// Core API version consumed when resolving the Sandbox behind a Claim.
pub const CORE_AGENT_SANDBOX_API_VERSION: &str = "agents.x-k8s.io/v1beta1";

/// Required CRDs and the exact served API version Kobe consumes.
pub const REQUIRED_AGENT_SANDBOX_CRDS: &[(&str, &str)] = &[
    (
        "sandboxtemplates.extensions.agents.x-k8s.io",
        REQUIRED_AGENT_SANDBOX_API_VERSION,
    ),
    (
        "sandboxwarmpools.extensions.agents.x-k8s.io",
        REQUIRED_AGENT_SANDBOX_API_VERSION,
    ),
    (
        "sandboxclaims.extensions.agents.x-k8s.io",
        REQUIRED_AGENT_SANDBOX_API_VERSION,
    ),
    ("sandboxes.agents.x-k8s.io", CORE_AGENT_SANDBOX_API_VERSION),
];

/// Why an operator-installed runtime cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AgentSandboxUnusable {
    #[error("Agent Sandbox mode {configured:?} is invalid; expected disabled or external")]
    InvalidMode { configured: String },
    /// `managed` stays a distinct error rather than degrading to another mode.
    #[error(
        "Agent Sandbox managed mode is not implemented; install and upgrade Agent Sandbox {release} yourself, then use agentSandbox.mode=external"
    )]
    ManagedNotApproved { release: &'static str },
    #[error("Agent Sandbox CRD {crd} is not installed or not established")]
    CrdMissing { crd: String },
    /// Reading the CRD itself failed. A transport error, throttling, or a 5xx
    /// says nothing about whether the CRD exists, so this is deliberately not
    /// [`AgentSandboxUnusable::CrdMissing`]: the caller decides whether that
    /// distinction means retry or abort.
    #[error("could not read Agent Sandbox CRD {crd} from the API server: {detail}")]
    Unreachable { crd: String, detail: String },
    #[error("Agent Sandbox CRD {crd} does not serve {expected} (found: {found})")]
    VersionMismatch {
        crd: String,
        expected: String,
        found: String,
    },
    #[error("Agent Sandbox CRD {crd} is not {release}-compatible: {reason}")]
    SchemaMismatch {
        crd: String,
        release: &'static str,
        reason: &'static str,
    },
}

impl AgentSandboxUnusable {
    /// Bounded reason code safe for conditions and metrics.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidMode { .. } => "invalid_mode",
            Self::ManagedNotApproved { .. } => "managed_not_approved",
            Self::CrdMissing { .. } => "crd_missing",
            Self::Unreachable { .. } => "apiserver_unreachable",
            Self::VersionMismatch { .. } => "version_mismatch",
            Self::SchemaMismatch { .. } => "schema_mismatch",
        }
    }

    /// Whether re-running the validation later could plausibly succeed.
    ///
    /// Only [`AgentSandboxUnusable::Unreachable`] is transient: an absent or
    /// incompatible CRD stays absent until an operator acts, and retrying
    /// would hide a real misconfiguration behind a delay.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Unreachable { .. })
    }
}

/// Parse the configured ownership mode without silently degrading bad input.
pub fn parse_mode(configured: &str) -> Result<AgentSandboxMode, AgentSandboxUnusable> {
    match configured.trim().to_ascii_lowercase().as_str() {
        "disabled" | "" => Ok(AgentSandboxMode::Disabled),
        "external" => Ok(AgentSandboxMode::External),
        "managed" => Err(AgentSandboxUnusable::ManagedNotApproved {
            release: AGENT_SANDBOX_RELEASE,
        }),
        _ => Err(AgentSandboxUnusable::InvalidMode {
            configured: configured.trim().to_string(),
        }),
    }
}

/// Read the configured mode. Absence defaults safely to disabled.
pub fn mode_from_env() -> Result<AgentSandboxMode, AgentSandboxUnusable> {
    parse_mode(&std::env::var("AGENT_SANDBOX_MODE").unwrap_or_default())
}

/// Check that a CRD is established and serves the version Kobe consumes.
pub fn crd_is_compatible(
    crd: &str,
    expected_api_version: &str,
    established: bool,
    served_versions: &[String],
) -> Result<(), AgentSandboxUnusable> {
    if !established {
        return Err(AgentSandboxUnusable::CrdMissing {
            crd: crd.to_string(),
        });
    }
    let expected_version = expected_api_version.rsplit('/').next().unwrap_or_default();
    if served_versions
        .iter()
        .any(|version| version == expected_version)
    {
        return Ok(());
    }
    Err(AgentSandboxUnusable::VersionMismatch {
        crd: crd.to_string(),
        expected: expected_api_version.to_string(),
        found: if served_versions.is_empty() {
            "none".to_string()
        } else {
            served_versions.join(",")
        },
    })
}

/// Whether the served WarmPool schema carries the v0.5.6 generation ACK Kobe
/// uses before trusting replica counts. v0.5.4 serves the same `v1beta1`
/// version, so the served-version check alone cannot distinguish it.
fn warm_pool_crd_supports_observed_generation(
    crd: &k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition,
) -> bool {
    let expected_version = REQUIRED_AGENT_SANDBOX_API_VERSION
        .rsplit('/')
        .next()
        .unwrap_or_default();
    let Some(root) = crd
        .spec
        .versions
        .iter()
        .find(|version| version.name == expected_version && version.served)
        .and_then(|version| version.schema.as_ref())
        .and_then(|schema| schema.open_api_v3_schema.as_ref())
    else {
        return false;
    };
    let Some(observed_generation) = root
        .properties
        .as_ref()
        .and_then(|properties| properties.get("status"))
        .and_then(|status| status.properties.as_ref())
        .and_then(|properties| properties.get("observedGeneration"))
    else {
        return false;
    };

    observed_generation.type_.as_deref() == Some("integer")
        && observed_generation.format.as_deref() == Some("int64")
        && observed_generation.minimum == Some(0.0)
}

/// Validate an operator-installed runtime using GET requests only.
///
/// Kobe checks the four consumed CRDs, their served versions, and the v0.5.6
/// WarmPool generation field. It deliberately does not inspect a particular
/// Deployment/webhook topology and does not create any runtime object.
///
/// A CRD GET that fails for any reason other than a plain 404 surfaces as
/// [`AgentSandboxUnusable::Unreachable`] rather than collapsing into
/// `crd_missing`: a throttled or briefly unreachable API server says nothing
/// about what is installed, and this is the process's first API request —
/// reporting it as "CRD not installed" exits without retrying a transient
/// fault. Callers that want startup resilience wrap this in
/// [`validate_external_runtime_with_retry`].
pub async fn validate_external_runtime(client: &kube::Client) -> Result<(), AgentSandboxUnusable> {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::api::Api;

    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    for (name, expected_api_version) in REQUIRED_AGENT_SANDBOX_CRDS {
        let observed = match crds.get(name).await {
            Ok(crd) => Some(crd),
            Err(kube::Error::Api(error)) if error.code == 404 => None,
            Err(error) => {
                return Err(AgentSandboxUnusable::Unreachable {
                    crd: (*name).to_string(),
                    detail: error.to_string(),
                });
            }
        };
        let established = observed.as_ref().is_some_and(|crd| {
            crd.status
                .as_ref()
                .and_then(|status| status.conditions.as_ref())
                .is_some_and(|conditions| {
                    conditions.iter().any(|condition| {
                        condition.type_ == "Established" && condition.status == "True"
                    })
                })
        });
        let served: Vec<String> = observed
            .as_ref()
            .map(|crd| {
                crd.spec
                    .versions
                    .iter()
                    .filter(|version| version.served)
                    .map(|version| version.name.clone())
                    .collect()
            })
            .unwrap_or_default();
        crd_is_compatible(name, expected_api_version, established, &served)?;
        if *name == "sandboxwarmpools.extensions.agents.x-k8s.io"
            && observed
                .as_ref()
                .is_none_or(|crd| !warm_pool_crd_supports_observed_generation(crd))
        {
            return Err(AgentSandboxUnusable::SchemaMismatch {
                crd: name.to_string(),
                release: AGENT_SANDBOX_RELEASE,
                reason: "served v1beta1 schema lacks status.observedGeneration int64",
            });
        }
    }
    Ok(())
}

/// Retry startup validation while the API server is merely unreachable.
///
/// The shape mirrors [`crate::sandbox_ledger::validate`]: a bounded window
/// (30 seconds, 250 ms between attempts) inside which a transient fault —
/// the apiserver still coming up, a restart race, brief throttling — retries
/// instead of killing the process. A definitive finding never waits: an
/// absent or incompatible CRD aborts immediately, because no retry makes an
/// operator install anything, and burning the window on every pod start
/// would only delay an honest failure report. When the window closes on
/// persistent unreachability, that exact error surfaces with its source.
pub async fn validate_external_runtime_with_retry(
    client: &kube::Client,
) -> Result<(), AgentSandboxUnusable> {
    validate_with_retry_until(
        client,
        tokio::time::Instant::now() + std::time::Duration::from_secs(30),
    )
    .await
}

/// [`validate_external_runtime_with_retry`] with an injectable deadline.
async fn validate_with_retry_until(
    client: &kube::Client,
    deadline: tokio::time::Instant,
) -> Result<(), AgentSandboxUnusable> {
    loop {
        match validate_external_runtime(client).await {
            Ok(()) => return Ok(()),
            Err(error) if error.is_transient() && tokio::time::Instant::now() < deadline => {
                tracing::debug!(reason = error.reason_code(), "{error}");
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_is_rejected_and_external_is_the_only_enabled_mode() {
        assert_eq!(AgentSandboxMode::default(), AgentSandboxMode::Disabled);
        assert!(!AgentSandboxMode::Disabled.enabled());
        assert!(AgentSandboxMode::External.enabled());
        assert_eq!(parse_mode("external"), Ok(AgentSandboxMode::External));
        assert!(matches!(
            parse_mode(" managed "),
            Err(AgentSandboxUnusable::ManagedNotApproved { .. })
        ));
        assert!(matches!(
            parse_mode("typo"),
            Err(AgentSandboxUnusable::InvalidMode { .. })
        ));
    }

    #[test]
    fn every_consumed_crd_is_required_at_its_consumed_version() {
        assert_eq!(REQUIRED_AGENT_SANDBOX_CRDS.len(), 4);
        for (crd, expected) in REQUIRED_AGENT_SANDBOX_CRDS {
            let group = expected.rsplit_once('/').unwrap().0;
            assert!(crd.ends_with(&format!(".{group}")), "{crd} vs {expected}");
        }
    }

    #[test]
    fn served_version_and_establishment_are_fail_closed() {
        let crd = "sandboxclaims.extensions.agents.x-k8s.io";
        assert!(
            crd_is_compatible(
                crd,
                REQUIRED_AGENT_SANDBOX_API_VERSION,
                true,
                &["v1beta1".into()]
            )
            .is_ok()
        );
        assert!(matches!(
            crd_is_compatible(
                crd,
                REQUIRED_AGENT_SANDBOX_API_VERSION,
                true,
                &["v1alpha1".into()]
            ),
            Err(AgentSandboxUnusable::VersionMismatch { .. })
        ));
        assert!(matches!(
            crd_is_compatible(crd, REQUIRED_AGENT_SANDBOX_API_VERSION, false, &[]),
            Err(AgentSandboxUnusable::CrdMissing { .. })
        ));
    }

    fn crd_response(name: &str) -> serde_json::Value {
        let (plural, group, kind) = if name == "sandboxes.agents.x-k8s.io" {
            ("sandboxes", "agents.x-k8s.io", "Sandbox")
        } else if name.starts_with("sandboxtemplates") {
            (
                "sandboxtemplates",
                "extensions.agents.x-k8s.io",
                "SandboxTemplate",
            )
        } else if name.starts_with("sandboxwarmpools") {
            (
                "sandboxwarmpools",
                "extensions.agents.x-k8s.io",
                "SandboxWarmPool",
            )
        } else {
            (
                "sandboxclaims",
                "extensions.agents.x-k8s.io",
                "SandboxClaim",
            )
        };
        let mut schema = serde_json::json!({ "type": "object" });
        if plural == "sandboxwarmpools" {
            schema = serde_json::json!({
                "type": "object",
                "properties": {
                    "status": {
                        "type": "object",
                        "properties": {
                            "observedGeneration": {
                                "type": "integer",
                                "format": "int64",
                                "minimum": 0
                            }
                        }
                    }
                }
            });
        }
        serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": name },
            "spec": {
                "group": group,
                "scope": "Namespaced",
                "names": {
                    "plural": plural,
                    "singular": plural.trim_end_matches('s'),
                    "kind": kind,
                    "listKind": format!("{kind}List")
                },
                "versions": [{
                    "name": "v1beta1",
                    "served": true,
                    "storage": true,
                    "schema": { "openAPIV3Schema": schema }
                }]
            },
            "status": {
                "conditions": [{ "type": "Established", "status": "True" }]
            }
        })
    }

    #[tokio::test]
    async fn external_validation_is_get_only_and_writes_no_runtime_object() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        for (name, _) in REQUIRED_AGENT_SANDBOX_CRDS {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(crd_response(name)))
                .mount(&server)
                .await;
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = kube::Config::new(server.uri().parse().expect("mock URI"));
        let client = kube::Client::try_from(config).expect("mock kube client");
        validate_external_runtime(&client)
            .await
            .expect("compatible operator installation");

        let requests = server.received_requests().await.expect("request log");
        assert_eq!(requests.len(), REQUIRED_AGENT_SANDBOX_CRDS.len());
        assert!(
            requests
                .iter()
                .all(|request| request.method.as_str() == "GET")
        );
        assert!(requests.iter().all(|request| {
            !request.url.path().contains("sandboxclaims")
                || request.url.path().contains("customresourcedefinitions")
        }));
    }

    #[test]
    fn v054_shape_is_not_v056_compatible() {
        let mut value = crd_response("sandboxwarmpools.extensions.agents.x-k8s.io");
        value["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]
            ["status"]["properties"]
            .as_object_mut()
            .expect("status schema")
            .remove("observedGeneration");
        let crd = serde_json::from_value(value).expect("legacy CRD");
        assert!(!warm_pool_crd_supports_observed_generation(&crd));
    }

    /// A throttled or briefly unreachable API server is not evidence that a
    /// CRD is absent. Collapsing the two made this process's first API request
    /// its only unretried one, and a 503 during rollout surfaced as
    /// `crd_missing` and killed startup.
    #[tokio::test]
    async fn transient_api_errors_are_unreachable_not_crd_missing() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/sandboxtemplates.extensions.agents.x-k8s.io",
            ))
            .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
                "apiVersion":"v1", "kind":"Status", "status":"Failure",
                "reason":"ServiceUnavailable", "code":503
            })))
            .mount(&server)
            .await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = kube::Config::new(server.uri().parse().expect("mock URI"));
        let client = kube::Client::try_from(config).expect("mock kube client");

        assert!(matches!(
            validate_external_runtime(&client).await,
            Err(AgentSandboxUnusable::Unreachable { crd, .. })
                if crd == "sandboxtemplates.extensions.agents.x-k8s.io"
        ));
    }

    /// Startup tolerates a flaky apiserver for a bounded window: one failing
    /// GET followed by healthy responses validates cleanly. A definitive
    /// finding never waits — an absent CRD aborts on the first pass instead
    /// of burning the retry window at every pod start.
    #[tokio::test]
    async fn startup_retries_transient_faults_but_fails_fast_on_a_missing_crd() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

        struct FailTwiceThenServe {
            calls: Arc<AtomicUsize>,
        }
        impl Respond for FailTwiceThenServe {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                if self.calls.fetch_add(1, Ordering::SeqCst) < 2 {
                    return ResponseTemplate::new(500);
                }
                let name = request.url.path().rsplit('/').next().unwrap_or_default();
                match REQUIRED_AGENT_SANDBOX_CRDS
                    .iter()
                    .find(|(crd, _)| *crd == name)
                {
                    Some((name, _)) => ResponseTemplate::new(200).set_body_json(crd_response(name)),
                    None => ResponseTemplate::new(404),
                }
            }
        }

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(
                "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/.*",
            ))
            .respond_with(FailTwiceThenServe {
                calls: Arc::new(AtomicUsize::new(0)),
            })
            .mount(&server)
            .await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = kube::Config::new(server.uri().parse().expect("mock URI"));
        let client = kube::Client::try_from(config).expect("mock kube client");

        validate_with_retry_until(
            &client,
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await
        .expect("transient faults recover inside the window");

        // No CRDs installed at all: the first pass is definitive.
        let empty = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(
                "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/.*",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "apiVersion":"v1", "kind":"Status", "status":"Failure",
                "reason":"NotFound", "code":404
            })))
            .mount(&empty)
            .await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = kube::Config::new(empty.uri().parse().expect("mock URI"));
        let client = kube::Client::try_from(config).expect("mock kube client");
        let started = std::time::Instant::now();
        assert!(matches!(
            validate_with_retry_until(
                &client,
                tokio::time::Instant::now() + std::time::Duration::from_secs(30)
            )
            .await,
            Err(AgentSandboxUnusable::CrdMissing { .. })
        ));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "a genuinely missing CRD must abort immediately, not spend the window"
        );
    }
}
