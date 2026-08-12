//! Validation of an **operator-installed** upstream Agent Sandbox runtime.
//!
//! Kobe consumes `SandboxTemplate`, `SandboxWarmPool` and `SandboxClaim` from
//! the upstream [Agent Sandbox] project. Those APIs have to come from
//! somewhere, and #72 originally proposed three installation modes. Two of
//! them — `managed`, which installs and *retains* cluster-scoped CRDs, RBAC and
//! a webhook across uninstall, and a child-cluster bootstrap performing the
//! same install with cluster-admin — are paused behind an explicit approval and
//! are deliberately absent from this module.
//!
//! What remains is the mode that needs no approval: the operator installs the
//! runtime, and **Kobe owns nothing**. This module only answers "is a
//! compatible runtime present?" before any Sandbox work is admitted.
//!
//! # Why validate at all
//!
//! Without a check, a missing or mismatched runtime surfaces as an obscure
//! failure deep in placement — a `SandboxClaim` create that 404s, or worse, one
//! that succeeds against an incompatible schema and leaves an object no
//! controller reconciles. Refusing up front, with the version actually found,
//! turns that into one legible error.
//!
//! # What this deliberately does NOT do
//!
//! No create/delete canary. Proving the runtime *works* by writing a real
//! `SandboxClaim` was one of the paused effects, so readiness here rests on API
//! presence and version compatibility only. That is a genuinely weaker
//! guarantee — a runtime whose controller is wedged will pass this and fail
//! later — and it is recorded as such rather than papered over.
//!
//! [Agent Sandbox]: https://github.com/kubernetes-sigs/agent-sandbox

use serde::{Deserialize, Serialize};

/// How the upstream Agent Sandbox runtime reaches a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AgentSandboxMode {
    /// Sandbox features are off. Nothing is validated and no Sandbox API is
    /// served. The default, so an upgrade never starts depending on a runtime
    /// the operator has not installed.
    #[default]
    Disabled,
    /// The operator installs and owns the runtime; Kobe validates it and owns
    /// nothing.
    External,
}

/// The upstream API version this build is written against.
///
/// Pinned rather than "whatever is installed": Kobe projects pool and lease
/// configuration onto a specific upstream schema, and a different version can
/// accept the same object while meaning something else by it.
pub const REQUIRED_AGENT_SANDBOX_API_VERSION: &str = "extensions.agents.x-k8s.io/v1beta1";

/// The upstream CRDs Kobe consumes. All three are required: a runtime with
/// claims but no warm pools would pass a laxer check and then fail to serve.
/// The core Agent Sandbox group. The `Sandbox` object itself lives here, not
/// in the `extensions.` group its templates, warm pools and claims are in.
pub const CORE_AGENT_SANDBOX_API_VERSION: &str = "agents.x-k8s.io/v1beta1";

/// The upstream CRDs Kobe consumes, each with the API version it is consumed
/// at. All are required: a runtime missing any one of them passes a laxer
/// check and then fails to serve — and `sandboxes` in particular fails
/// *silently*, because it is read to find the Pod behind a claim, so its
/// absence surfaces as leases that never pass readiness rather than as an
/// error anyone can act on.
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
    #[error("Agent Sandbox is disabled; set agentSandbox.mode=external to use Sandbox features")]
    Disabled,
    #[error("Agent Sandbox CRD {crd} is not installed or not established")]
    CrdMissing { crd: String },
    #[error("Agent Sandbox CRD {crd} does not serve {expected} (found: {found})")]
    VersionMismatch {
        crd: String,
        expected: String,
        found: String,
    },
    /// `managed` mode is recognised but refused. Deliberately an explicit
    /// error, not a silent fall back to `external` or `disabled`: choosing it
    /// must stay a deliberate act that requires the approval on #72, rather
    /// than something a config typo can switch on.
    #[error(
        "Agent Sandbox managed mode is not implemented: it installs and retains \
         cluster-scoped CRDs, RBAC and a webhook, which is pending approval on #72. \
         Install the runtime yourself and use agentSandbox.mode=external."
    )]
    ManagedNotApproved,
}

impl AgentSandboxUnusable {
    /// Bounded reason code for status, events and metrics.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::CrdMissing { .. } => "crd_missing",
            Self::VersionMismatch { .. } => "version_mismatch",
            Self::ManagedNotApproved => "managed_not_approved",
        }
    }
}

/// Parse the configured mode, refusing `managed` explicitly.
///
/// An unrecognised value is refused rather than defaulted: silently treating a
/// typo as `disabled` would leave an operator who asked for Sandbox features
/// wondering why nothing works, and treating it as `external` would be worse.
pub fn parse_mode(configured: &str) -> Result<AgentSandboxMode, AgentSandboxUnusable> {
    match configured.trim().to_ascii_lowercase().as_str() {
        "disabled" | "" => Ok(AgentSandboxMode::Disabled),
        "external" => Ok(AgentSandboxMode::External),
        "managed" => Err(AgentSandboxUnusable::ManagedNotApproved),
        _ => Err(AgentSandboxUnusable::Disabled),
    }
}

/// Read the configured mode from the environment.
///
/// Absent means [`AgentSandboxMode::Disabled`] — a deployment that predates
/// this setting, or one that never opted in, must not start depending on a
/// runtime nobody installed.
pub fn mode_from_env() -> Result<AgentSandboxMode, AgentSandboxUnusable> {
    parse_mode(&std::env::var("AGENT_SANDBOX_MODE").unwrap_or_default())
}

/// Whether one CRD, as observed, is established and serves the pinned version.
///
/// Pure so the compatibility rule is testable without a cluster: the caller
/// supplies what the API server reported.
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
    // The pinned constant is `group/version`; a CRD reports versions alone.
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

/// Validate that a compatible operator-installed runtime is present.
///
/// Every required CRD must be established and serve the pinned version. The
/// first failure is returned rather than a collected list: an operator fixes
/// these one at a time, and the first one usually explains the rest.
pub async fn validate_external_runtime(client: &kube::Client) -> Result<(), AgentSandboxUnusable> {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
    use kube::api::Api;

    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    for (name, expected_api_version) in REQUIRED_AGENT_SANDBOX_CRDS {
        let observed = crds.get(name).await.ok();
        let established = observed.as_ref().is_some_and(|crd| {
            crd.status
                .as_ref()
                .and_then(|status| status.conditions.as_ref())
                .is_some_and(|conditions| {
                    conditions
                        .iter()
                        .any(|c| c.type_ == "Established" && c.status == "True")
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
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `managed` must fail loudly rather than degrade.
    ///
    /// It installs and retains cluster-scoped resources, which is pending
    /// approval on #72. Falling back to `external` or `disabled` would let a
    /// config value quietly select behaviour nobody approved — and, worse,
    /// would make the approval look granted to whoever read the running config.
    #[test]
    fn managed_mode_is_refused_explicitly_not_degraded() {
        assert_eq!(
            parse_mode("managed").unwrap_err(),
            AgentSandboxUnusable::ManagedNotApproved
        );
        assert_eq!(
            parse_mode("Managed").unwrap_err(),
            AgentSandboxUnusable::ManagedNotApproved,
            "case must not be a way around the refusal"
        );
    }

    #[test]
    fn disabled_is_the_default_and_external_is_opt_in() {
        assert_eq!(AgentSandboxMode::default(), AgentSandboxMode::Disabled);
        assert_eq!(parse_mode("").unwrap(), AgentSandboxMode::Disabled);
        assert_eq!(parse_mode("disabled").unwrap(), AgentSandboxMode::Disabled);
        assert_eq!(parse_mode("external").unwrap(), AgentSandboxMode::External);
        assert_eq!(
            parse_mode("  EXTERNAL  ").unwrap(),
            AgentSandboxMode::External
        );
    }

    /// A runtime serving a different version must be refused, not accepted
    /// because the CRD name matched.
    ///
    /// Kobe projects pool and lease configuration onto a specific upstream
    /// schema. A different version can accept the same object and mean
    /// something else by it, which surfaces as a claim no controller
    /// reconciles rather than as an error.
    #[test]
    fn a_different_upstream_version_is_refused() {
        let crd = "sandboxclaims.extensions.agents.x-k8s.io";

        let expected = REQUIRED_AGENT_SANDBOX_API_VERSION;
        assert!(crd_is_compatible(crd, expected, true, &["v1beta1".into()]).is_ok());
        // Serving several versions is fine as long as ours is among them.
        assert!(
            crd_is_compatible(crd, expected, true, &["v1alpha1".into(), "v1beta1".into()]).is_ok()
        );

        let err = crd_is_compatible(crd, expected, true, &["v1alpha1".into()]).unwrap_err();
        assert!(matches!(err, AgentSandboxUnusable::VersionMismatch { .. }));
        assert_eq!(err.reason_code(), "version_mismatch");
        // The found version belongs in the message: "incompatible" without it
        // sends an operator digging for what is actually installed.
        assert!(format!("{err}").contains("v1alpha1"));
    }

    /// A CRD that exists but is not established is not usable — during install
    /// or a failed upgrade it can be present and not yet serving.
    #[test]
    fn an_unestablished_crd_is_not_usable() {
        let err = crd_is_compatible(
            "sandboxclaims.extensions.agents.x-k8s.io",
            REQUIRED_AGENT_SANDBOX_API_VERSION,
            false,
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, AgentSandboxUnusable::CrdMissing { .. }));
        assert_eq!(err.reason_code(), "crd_missing");
    }

    /// All three CRDs are required. A runtime with claims but no warm pools
    /// would pass a laxer check and then fail to serve.
    #[test]
    fn every_consumed_crd_is_required_at_the_version_it_is_consumed_at() {
        assert_eq!(REQUIRED_AGENT_SANDBOX_CRDS.len(), 4);
        for (crd, expected) in REQUIRED_AGENT_SANDBOX_CRDS {
            // The name must sit under the group it is validated against;
            // otherwise a CRD could pass a version check that never applied
            // to it.
            let group = expected.rsplit_once('/').unwrap().0;
            assert!(crd.ends_with(&format!(".{group}")), "{crd} vs {expected}");
        }

        // `sandboxes` lives in the CORE group, and is the one whose absence
        // fails silently: it is read to find the Pod behind a claim, so a
        // runtime without it yields leases that never pass readiness rather
        // than an error.
        assert!(
            REQUIRED_AGENT_SANDBOX_CRDS
                .contains(&("sandboxes.agents.x-k8s.io", CORE_AGENT_SANDBOX_API_VERSION)),
            "the canary reads Sandbox objects, so the runtime must serve them"
        );
    }
}
