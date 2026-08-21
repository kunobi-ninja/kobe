//! Startup proof for the Sandbox admission coordination-Lease ledger.
//!
//! Predictable CAS names are safe only inside a namespace where the API server
//! rejects every non-operator writer and aggregate object growth is bounded.
//! The Helm chart installs those controls; this module makes them a runtime
//! precondition too, so a hand-written deployment cannot silently omit them.

use k8s_openapi::api::admissionregistration::v1::{
    ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding,
};
use k8s_openapi::api::authentication::v1::SelfSubjectReview;
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, ResourceQuota};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use kube::{
    Api, Client, ResourceExt,
    api::{ObjectMeta, PostParams},
};
use thiserror::Error;

const LEDGER_LABEL: &str = "kobe.kunobi.ninja/sandbox-ledger";
const LEASE_COUNT_QUOTA: &str = "count/leases.coordination.k8s.io";
const CONFIG_MAP_COUNT_QUOTA: &str = "count/configmaps";
const POLICY_CANARY_NAME: &str = "kobe-ledger-policy-enforcement-canary";
const POLICY_CANARY_MESSAGE: &str = "Sandbox ledger admission-policy enforcement canary";
const QUOTA_CANARY_NAME: &str = "kobe-ledger-quota-enforcement-canary";

#[derive(Debug, Error)]
pub enum SandboxLedgerError {
    #[error("Sandbox ledger control {0} is missing or does not match the fail-closed contract")]
    Invalid(&'static str),
    #[error("Sandbox ledger control {0} exists but is not active yet")]
    NotReady(&'static str),
    #[error(transparent)]
    Kubernetes(#[from] kube::Error),
}

/// Require the chart's exact namespace, quota, admission policy, and binding,
/// then prove that the authenticated identity and both admission plugins are
/// effective with server-side dry runs that can never persist an object.
///
/// This is deliberately stricter than checking that similarly named objects
/// exist. A weakened CEL expression or `Warn` binding would make the namespace
/// tenant-writable while startup still claimed the ledger was protected.
pub async fn validate(
    client: &Client,
    namespace: &str,
    policy_name: &str,
    operator_username: &str,
    object_limit: u32,
) -> Result<(), SandboxLedgerError> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match validate_once(
            client,
            namespace,
            policy_name,
            operator_username,
            object_limit,
        )
        .await
        {
            Ok(()) => return Ok(()),
            Err(error) if tokio::time::Instant::now() < deadline => {
                tracing::debug!(error = %error, "Waiting for Sandbox admission ledger controls");
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn validate_once(
    client: &Client,
    namespace: &str,
    policy_name: &str,
    operator_username: &str,
    object_limit: u32,
) -> Result<(), SandboxLedgerError> {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let quotas: Api<ResourceQuota> = Api::namespaced(client.clone(), namespace);
    let policies: Api<ValidatingAdmissionPolicy> = Api::all(client.clone());
    let bindings: Api<ValidatingAdmissionPolicyBinding> = Api::all(client.clone());
    let (namespace_object, quota, policy, binding) = tokio::try_join!(
        namespaces.get(namespace),
        quotas.get(policy_name),
        policies.get(policy_name),
        bindings.get(policy_name),
    )?;
    validate_objects(
        &namespace_object,
        &quota,
        &policy,
        &binding,
        namespace,
        policy_name,
        operator_username,
        object_limit,
    )?;
    validate_operator_identity(client, operator_username).await?;
    validate_lease_permissions(client, namespace).await?;
    validate_admission_enforcement(client, namespace).await
}

async fn validate_operator_identity(
    client: &Client,
    expected_username: &str,
) -> Result<(), SandboxLedgerError> {
    let reviews: Api<SelfSubjectReview> = Api::all(client.clone());
    let review = reviews
        .create(&PostParams::default(), &SelfSubjectReview::default())
        .await?;
    let actual_username = review
        .status
        .and_then(|status| status.user_info)
        .and_then(|user| user.username);
    if actual_username.as_deref() != Some(expected_username) {
        return Err(SandboxLedgerError::Invalid(
            "operator ServiceAccount identity",
        ));
    }
    Ok(())
}

/// Prove every verb used by admission and distributed access CAS before the
/// HTTP listener starts. A chart drift that omits `patch` must not produce a
/// healthy API that fails only when teardown tries to close an access gate.
async fn validate_lease_permissions(
    client: &Client,
    namespace: &str,
) -> Result<(), SandboxLedgerError> {
    let reviews: Api<SelfSubjectAccessReview> = Api::all(client.clone());
    for verb in ["get", "list", "create", "patch", "delete"] {
        let review = SelfSubjectAccessReview {
            spec: SelfSubjectAccessReviewSpec {
                resource_attributes: Some(ResourceAttributes {
                    group: Some("coordination.k8s.io".into()),
                    version: Some("v1".into()),
                    resource: Some("leases".into()),
                    namespace: Some(namespace.into()),
                    verb: Some(verb.into()),
                    ..ResourceAttributes::default()
                }),
                ..SelfSubjectAccessReviewSpec::default()
            },
            ..SelfSubjectAccessReview::default()
        };
        let result = reviews.create(&PostParams::default(), &review).await?;
        if !result.status.is_some_and(|status| status.allowed) {
            return Err(SandboxLedgerError::Invalid(
                "operator coordination-Lease permissions",
            ));
        }
    }
    Ok(())
}

async fn validate_admission_enforcement(
    client: &Client,
    namespace: &str,
) -> Result<(), SandboxLedgerError> {
    let dry_run = PostParams {
        dry_run: true,
        ..PostParams::default()
    };
    let leases: Api<Lease> = Api::namespaced(client.clone(), namespace);
    let policy_canary = Lease {
        metadata: ObjectMeta {
            name: Some(POLICY_CANARY_NAME.into()),
            namespace: Some(namespace.into()),
            ..ObjectMeta::default()
        },
        ..Lease::default()
    };
    match leases.create(&dry_run, &policy_canary).await {
        Err(kube::Error::Api(response))
            if response.code == 403 && response.message.contains(POLICY_CANARY_MESSAGE) => {}
        Ok(_) => {
            return Err(SandboxLedgerError::Invalid(
                "ValidatingAdmissionPolicy enforcement",
            ));
        }
        Err(error) => return Err(SandboxLedgerError::Kubernetes(error)),
    }

    // A second zero-object quota gives startup a bounded proof that the
    // ResourceQuota admission plugin is enforcing writes. Status alone only
    // proves that the quota controller reconciled the object; administrators
    // can independently disable the admission plugin.
    let config_maps: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let quota_canary = ConfigMap {
        metadata: ObjectMeta {
            name: Some(QUOTA_CANARY_NAME.into()),
            namespace: Some(namespace.into()),
            ..ObjectMeta::default()
        },
        ..ConfigMap::default()
    };
    match config_maps.create(&dry_run, &quota_canary).await {
        Err(kube::Error::Api(response))
            if response.code == 403
                && response
                    .message
                    .to_ascii_lowercase()
                    .contains("exceeded quota") =>
        {
            Ok(())
        }
        Ok(_) => Err(SandboxLedgerError::Invalid("ResourceQuota enforcement")),
        Err(error) => Err(SandboxLedgerError::Kubernetes(error)),
    }
}

fn normalized_expression(expression: &str) -> String {
    expression.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[allow(clippy::too_many_arguments)]
fn validate_objects(
    namespace_object: &Namespace,
    quota: &ResourceQuota,
    policy: &ValidatingAdmissionPolicy,
    binding: &ValidatingAdmissionPolicyBinding,
    namespace: &str,
    policy_name: &str,
    operator_username: &str,
    object_limit: u32,
) -> Result<(), SandboxLedgerError> {
    if namespace_object.name_any() != namespace
        || namespace_object
            .labels()
            .get(LEDGER_LABEL)
            .map(String::as_str)
            != Some("true")
    {
        return Err(SandboxLedgerError::Invalid("Namespace"));
    }
    let expected_hard = std::collections::BTreeMap::from([
        (
            LEASE_COUNT_QUOTA.to_string(),
            Quantity(object_limit.to_string()),
        ),
        (CONFIG_MAP_COUNT_QUOTA.to_string(), Quantity("0".into())),
    ]);
    let quota_spec = quota
        .spec
        .as_ref()
        .ok_or(SandboxLedgerError::Invalid("ResourceQuota"))?;
    if quota.name_any() != policy_name
        || quota.namespace().as_deref() != Some(namespace)
        || quota_spec.hard.as_ref() != Some(&expected_hard)
        || !quota_spec.scopes.as_deref().unwrap_or_default().is_empty()
        || quota_spec.scope_selector.is_some()
    {
        return Err(SandboxLedgerError::Invalid("ResourceQuota"));
    }
    let quota_status = quota
        .status
        .as_ref()
        .ok_or(SandboxLedgerError::NotReady("ResourceQuota"))?;
    let used = quota_status
        .used
        .as_ref()
        .ok_or(SandboxLedgerError::NotReady("ResourceQuota"))?;
    if quota_status.hard.as_ref() != Some(&expected_hard)
        || used.len() != 2
        || !used.contains_key(LEASE_COUNT_QUOTA)
        || !used.contains_key(CONFIG_MAP_COUNT_QUOTA)
    {
        return Err(SandboxLedgerError::NotReady("ResourceQuota"));
    }

    let spec = policy.spec.as_ref().ok_or(SandboxLedgerError::Invalid(
        "ValidatingAdmissionPolicy.spec",
    ))?;
    let constraints = spec
        .match_constraints
        .as_ref()
        .ok_or(SandboxLedgerError::Invalid(
            "ValidatingAdmissionPolicy.matchConstraints",
        ))?;
    let rules = constraints
        .resource_rules
        .as_deref()
        .ok_or(SandboxLedgerError::Invalid(
            "ValidatingAdmissionPolicy.resourceRules",
        ))?;
    let rule = match rules {
        [rule] => rule,
        _ => {
            return Err(SandboxLedgerError::Invalid(
                "ValidatingAdmissionPolicy.resourceRules",
            ));
        }
    };
    let exact_rule = rule.api_groups.as_deref() == Some(&["coordination.k8s.io".into()][..])
        && rule.api_versions.as_deref() == Some(&["v1".into()][..])
        && rule.resources.as_deref() == Some(&["leases".into()][..])
        && rule.operations.as_deref()
            == Some(&["CREATE".into(), "UPDATE".into(), "DELETE".into()][..])
        && rule
            .resource_names
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        && constraints
            .exclude_resource_rules
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        && constraints.namespace_selector.is_none()
        && constraints.object_selector.is_none();
    let expected_match = format!("request.namespace == \"{namespace}\"");
    let exact_match = matches!(spec.match_conditions.as_deref(), Some([condition])
        if condition.name == "only-sandbox-ledger-namespace"
            && normalized_expression(&condition.expression) == expected_match);
    let expected_writer_validation =
        format!("request.userInfo.username == \"{operator_username}\"");
    let expected_canary_validation = format!(
        "request.operation != \"CREATE\" || object.metadata.name != \"{POLICY_CANARY_NAME}\""
    );
    let exact_validation = matches!(spec.validations.as_deref(), Some([writer, canary])
        if normalized_expression(&writer.expression) == expected_writer_validation
            && normalized_expression(&canary.expression) == expected_canary_validation
            && canary.message.as_deref() == Some(POLICY_CANARY_MESSAGE));
    if policy.name_any() != policy_name {
        return Err(SandboxLedgerError::Invalid(
            "ValidatingAdmissionPolicy.metadata.name",
        ));
    }
    if spec.failure_policy.as_deref() != Some("Fail") {
        return Err(SandboxLedgerError::Invalid(
            "ValidatingAdmissionPolicy.failurePolicy",
        ));
    }
    if !exact_rule {
        return Err(SandboxLedgerError::Invalid(
            "ValidatingAdmissionPolicy.resourceRules",
        ));
    }
    if !exact_match {
        return Err(SandboxLedgerError::Invalid(
            "ValidatingAdmissionPolicy.matchConditions",
        ));
    }
    if !exact_validation {
        return Err(SandboxLedgerError::Invalid(
            "ValidatingAdmissionPolicy.validations",
        ));
    }
    let policy_generation = policy
        .metadata
        .generation
        .ok_or(SandboxLedgerError::NotReady("ValidatingAdmissionPolicy"))?;
    let policy_status = policy
        .status
        .as_ref()
        .ok_or(SandboxLedgerError::NotReady("ValidatingAdmissionPolicy"))?;
    let expression_warnings = policy_status
        .type_checking
        .as_ref()
        .ok_or(SandboxLedgerError::NotReady("ValidatingAdmissionPolicy"))?
        .expression_warnings
        .as_deref()
        .unwrap_or_default();
    if policy_status.observed_generation != Some(policy_generation) {
        return Err(SandboxLedgerError::NotReady("ValidatingAdmissionPolicy"));
    }
    if !expression_warnings.is_empty() {
        return Err(SandboxLedgerError::Invalid(
            "ValidatingAdmissionPolicy.typeChecking",
        ));
    }

    let binding_spec = binding.spec.as_ref().ok_or(SandboxLedgerError::Invalid(
        "ValidatingAdmissionPolicyBinding",
    ))?;
    if binding.name_any() != policy_name
        || binding_spec.policy_name.as_deref() != Some(policy_name)
        || binding_spec.validation_actions.as_deref() != Some(&["Deny".into()][..])
        || binding_spec.match_resources.is_some()
        || binding_spec.param_ref.is_some()
    {
        return Err(SandboxLedgerError::Invalid(
            "ValidatingAdmissionPolicyBinding",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn objects() -> (
        Namespace,
        ResourceQuota,
        ValidatingAdmissionPolicy,
        ValidatingAdmissionPolicyBinding,
    ) {
        (
            serde_json::from_value(serde_json::json!({
                "apiVersion":"v1", "kind":"Namespace",
                "metadata":{"name":"ledger","labels":{LEDGER_LABEL:"true"}}
            })).unwrap(),
            serde_json::from_value(serde_json::json!({
                "apiVersion":"v1", "kind":"ResourceQuota",
                "metadata":{"name":"policy","namespace":"ledger"},
                "spec":{"hard":{
                    LEASE_COUNT_QUOTA:"4096",
                    CONFIG_MAP_COUNT_QUOTA:"0"
                }},
                "status":{
                    "hard":{
                        LEASE_COUNT_QUOTA:"4096",
                        CONFIG_MAP_COUNT_QUOTA:"0"
                    },
                    "used":{
                        LEASE_COUNT_QUOTA:"0",
                        CONFIG_MAP_COUNT_QUOTA:"0"
                    }
                }
            })).unwrap(),
            serde_json::from_value(serde_json::json!({
                "apiVersion":"admissionregistration.k8s.io/v1",
                "kind":"ValidatingAdmissionPolicy",
                "metadata":{"name":"policy","generation":1},
                "spec":{
                    "failurePolicy":"Fail",
                    "matchConstraints":{"resourceRules":[{
                        "apiGroups":["coordination.k8s.io"], "apiVersions":["v1"],
                        "resources":["leases"], "operations":["CREATE","UPDATE","DELETE"]
                    }]},
                    "matchConditions":[{"name":"only-sandbox-ledger-namespace","expression":"request.namespace == \"ledger\""}],
                    "validations":[
                        {"expression":"request.userInfo.username == \"system:serviceaccount:kobe:kobe\""},
                        {
                            "expression":"request.operation != \"CREATE\" || object.metadata.name != \"kobe-ledger-policy-enforcement-canary\"",
                            "message":POLICY_CANARY_MESSAGE
                        }
                    ]
                },
                "status":{"observedGeneration":1,"typeChecking":{"expressionWarnings":[]}}
            })).unwrap(),
            serde_json::from_value(serde_json::json!({
                "apiVersion":"admissionregistration.k8s.io/v1",
                "kind":"ValidatingAdmissionPolicyBinding", "metadata":{"name":"policy"},
                "spec":{"policyName":"policy","validationActions":["Deny"]}
            })).unwrap(),
        )
    }

    #[test]
    fn exact_ledger_contract_is_accepted_and_any_warn_binding_is_rejected() {
        let (namespace, quota, policy, mut binding) = objects();
        assert!(
            validate_objects(
                &namespace,
                &quota,
                &policy,
                &binding,
                "ledger",
                "policy",
                "system:serviceaccount:kobe:kobe",
                4096
            )
            .is_ok()
        );
        binding.spec.as_mut().unwrap().validation_actions = Some(vec!["Warn".into()]);
        assert!(matches!(
            validate_objects(
                &namespace,
                &quota,
                &policy,
                &binding,
                "ledger",
                "policy",
                "system:serviceaccount:kobe:kobe",
                4096
            ),
            Err(SandboxLedgerError::Invalid(
                "ValidatingAdmissionPolicyBinding"
            ))
        ));
    }

    #[test]
    fn weakened_namespace_or_writer_expression_is_rejected() {
        let (namespace, quota, mut policy, binding) = objects();
        policy
            .spec
            .as_mut()
            .unwrap()
            .match_conditions
            .as_mut()
            .unwrap()[0]
            .expression = "true".into();
        assert!(
            validate_objects(
                &namespace,
                &quota,
                &policy,
                &binding,
                "ledger",
                "policy",
                "system:serviceaccount:kobe:kobe",
                4096
            )
            .is_err()
        );

        let (_, _, mut policy, _) = objects();
        policy.spec.as_mut().unwrap().validations.as_mut().unwrap()[0].expression = "true".into();
        assert!(
            validate_objects(
                &namespace,
                &quota,
                &policy,
                &binding,
                "ledger",
                "policy",
                "system:serviceaccount:kobe:kobe",
                4096
            )
            .is_err()
        );
    }

    #[test]
    fn quota_is_not_active_until_the_controller_publishes_exact_usage() {
        let (namespace, mut quota, policy, binding) = objects();
        quota.status = None;
        assert!(matches!(
            validate_objects(
                &namespace,
                &quota,
                &policy,
                &binding,
                "ledger",
                "policy",
                "system:serviceaccount:kobe:kobe",
                4096
            ),
            Err(SandboxLedgerError::NotReady("ResourceQuota"))
        ));
    }
}
