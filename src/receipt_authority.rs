//! Startup validation for the isolated teardown-evidence authority.
//!
//! Kubernetes RBAC cannot restrict individual status fields. The Helm chart
//! therefore combines a distinct ServiceAccount/process with a fail-closed
//! ValidatingAdmissionPolicy. This module refuses to start the producer unless
//! both the authenticated identity and the live policy/binding match that
//! contract.

use k8s_openapi::api::admissionregistration::v1::{
    ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding,
};
use k8s_openapi::api::authentication::v1::SelfSubjectReview;
use kube::{Api, Client, ResourceExt, api::PostParams};
use thiserror::Error;

/// Whether the Helm split-authority deployment is active for this process.
/// The default `all` role remains a backwards-compatible single-process mode
/// for local development and upgrades that have not installed the admission
/// boundary yet.
pub(crate) fn is_separate() -> bool {
    std::env::var("KOBE_PROCESS_ROLE").is_ok_and(|role| role == "control-plane")
}

#[derive(Debug, Error)]
pub enum ReceiptAuthorityError {
    #[error("teardown authority control {0} is missing or weakened")]
    Invalid(&'static str),
    #[error("teardown authority control {0} is not reconciled yet")]
    NotReady(&'static str),
    #[error(transparent)]
    Kubernetes(#[from] kube::Error),
}

pub async fn validate(
    client: &Client,
    policy_name: &str,
    expected_username: &str,
) -> Result<(), ReceiptAuthorityError> {
    if !expected_username.starts_with("system:serviceaccount:") {
        return Err(ReceiptAuthorityError::Invalid("ServiceAccount username"));
    }
    let policies: Api<ValidatingAdmissionPolicy> = Api::all(client.clone());
    let bindings: Api<ValidatingAdmissionPolicyBinding> = Api::all(client.clone());
    let reviews: Api<SelfSubjectReview> = Api::all(client.clone());
    let review_params = PostParams::default();
    let review_request = SelfSubjectReview::default();
    let (policy, binding, review) = tokio::try_join!(
        policies.get(policy_name),
        bindings.get(policy_name),
        reviews.create(&review_params, &review_request),
    )?;
    let actual_username = review
        .status
        .and_then(|status| status.user_info)
        .and_then(|user| user.username);
    if actual_username.as_deref() != Some(expected_username) {
        return Err(ReceiptAuthorityError::Invalid("ServiceAccount identity"));
    }
    validate_objects(&policy, &binding, policy_name, expected_username)
}

fn validate_objects(
    policy: &ValidatingAdmissionPolicy,
    binding: &ValidatingAdmissionPolicyBinding,
    policy_name: &str,
    expected_username: &str,
) -> Result<(), ReceiptAuthorityError> {
    let spec = policy
        .spec
        .as_ref()
        .ok_or(ReceiptAuthorityError::Invalid("ValidatingAdmissionPolicy"))?;
    let constraints = spec
        .match_constraints
        .as_ref()
        .ok_or(ReceiptAuthorityError::Invalid("ValidatingAdmissionPolicy"))?;
    let rules = constraints
        .resource_rules
        .as_deref()
        .ok_or(ReceiptAuthorityError::Invalid("ValidatingAdmissionPolicy"))?;
    let required = [
        "verifiedteardownevidence",
        "clusterleases",
        "clusterleases/status",
        "clusterinstances/status",
    ];
    let operations = ["CREATE", "UPDATE", "DELETE"];
    let exact_resource_rule = rules.iter().any(|rule| {
        let groups = rule.api_groups.as_deref().unwrap_or_default();
        let versions = rule.api_versions.as_deref().unwrap_or_default();
        let rule_operations: std::collections::BTreeSet<&str> = rule
            .operations
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(String::as_str)
            .collect();
        let resources: std::collections::BTreeSet<&str> = rule
            .resources
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(String::as_str)
            .collect();
        groups == ["kobe.kunobi.ninja"]
            && versions == ["v1alpha1"]
            && rule
                .resource_names
                .as_ref()
                .is_none_or(|names| names.is_empty())
            && rule.scope.is_none()
            && operations
                .iter()
                .all(|operation| rule_operations.contains(operation))
            && required.iter().all(|resource| resources.contains(resource))
    });
    let actual_expressions: std::collections::BTreeSet<String> = spec
        .validations
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|validation| normalize_expression(&validation.expression))
        .collect();
    let expected_expressions = required_authority_expressions(expected_username)
        .into_iter()
        .map(|expression| normalize_expression(&expression))
        .collect::<std::collections::BTreeSet<_>>();
    if policy.name_any() != policy_name
        || spec.failure_policy.as_deref() != Some("Fail")
        || spec.param_kind.is_some()
        || spec
            .match_conditions
            .as_ref()
            .is_some_and(|conditions| !conditions.is_empty())
        || constraints
            .exclude_resource_rules
            .as_ref()
            .is_some_and(|excluded| !excluded.is_empty())
        || constraints.namespace_selector.is_some()
        || constraints.object_selector.is_some()
        || !exact_resource_rule
        || !expected_expressions.is_subset(&actual_expressions)
    {
        return Err(ReceiptAuthorityError::Invalid("ValidatingAdmissionPolicy"));
    }
    let generation = policy
        .metadata
        .generation
        .ok_or(ReceiptAuthorityError::NotReady("ValidatingAdmissionPolicy"))?;
    let status = policy
        .status
        .as_ref()
        .ok_or(ReceiptAuthorityError::NotReady("ValidatingAdmissionPolicy"))?;
    if status.observed_generation != Some(generation)
        || !status.conditions.as_ref().is_some_and(|conditions| {
            conditions
                .iter()
                .any(|condition| condition.type_ == "Accepted" && condition.status == "True")
        })
        || status
            .type_checking
            .as_ref()
            .and_then(|checking| checking.expression_warnings.as_deref())
            .is_some_and(|warnings| !warnings.is_empty())
    {
        return Err(ReceiptAuthorityError::NotReady("ValidatingAdmissionPolicy"));
    }

    let binding_spec = binding.spec.as_ref().ok_or(ReceiptAuthorityError::Invalid(
        "ValidatingAdmissionPolicyBinding",
    ))?;
    if binding.name_any() != policy_name
        || binding_spec.policy_name.as_deref() != Some(policy_name)
        || binding_spec.validation_actions.as_deref() != Some(&["Deny".into()][..])
        || binding_spec.match_resources.is_some()
        || binding_spec.param_ref.is_some()
    {
        return Err(ReceiptAuthorityError::Invalid(
            "ValidatingAdmissionPolicyBinding",
        ));
    }
    Ok(())
}

fn normalize_expression(expression: &str) -> String {
    expression.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn unchanged_status_field_expression(resource: &str, field: &str, username: &str) -> String {
    let username = serde_json::to_string(username).expect("ServiceAccount username is JSON");
    format!(
        "request.resource.resource != '{resource}' || request.userInfo.username == {username} || request.operation == 'DELETE' || (oldObject == null ? (!has(object.status) || !has(object.status.{field})) : (((!has(oldObject.status) || !has(oldObject.status.{field})) && (!has(object.status) || !has(object.status.{field}))) || (has(oldObject.status) && has(oldObject.status.{field}) && has(object.status) && has(object.status.{field}) && object.status.{field} == oldObject.status.{field})))"
    )
}

/// Exact fail-closed expressions the installed VAP must contain. Startup
/// compares normalized full expressions, not marker substrings: a tautology
/// mentioning protected field names is not an enforcement boundary.
fn required_authority_expressions(username: &str) -> Vec<String> {
    let quoted_username = serde_json::to_string(username).expect("ServiceAccount username is JSON");
    let mut expressions = vec![format!(
        "request.resource.resource != 'verifiedteardownevidence' || request.userInfo.username == {quoted_username}"
    )];
    for field in [
        "teardownReceipt",
        "teardownEvidence",
        "teardownAttemptId",
        "unboundReleaseVerifiedAt",
        "teardownAcknowledgement",
    ] {
        expressions.push(unchanged_status_field_expression(
            "clusterleases",
            field,
            username,
        ));
    }
    for field in ["creationManifest", "teardownIdentities"] {
        expressions.push(unchanged_status_field_expression(
            "clusterinstances",
            field,
            username,
        ));
    }
    expressions.push(
        "request.resource.resource != 'clusterleases' || request.operation == 'DELETE' || !has(object.status) || !has(object.status.connectTokenCreation) || object.status.connectTokenCreation.phase == 'closed' || (has(object.status.binding) && (has(object.status.connectTokenCreation.identity) == has(object.status.binding.connectToken)) && (!has(object.status.connectTokenCreation.identity) || object.status.connectTokenCreation.identity == object.status.binding.connectToken))"
            .into(),
    );
    expressions.push(format!(
        "request.resource.resource != 'clusterleases' || request.userInfo.username == {quoted_username} || request.operation == 'DELETE' || ((oldObject == null || !has(oldObject.status) || !has(oldObject.status.conditions) ? [] : oldObject.status.conditions.filter(c, c.type == 'AllocationAbsent')) == (!has(object.status) || !has(object.status.conditions) ? [] : object.status.conditions.filter(c, c.type == 'AllocationAbsent')))"
    ));
    expressions.push(
        "request.resource.resource != 'clusterleases' || request.operation != 'UPDATE' || !has(oldObject.metadata.finalizers) || !oldObject.metadata.finalizers.exists(f, f == 'kobe.kunobi.ninja/teardown-receipt-retention') || (has(object.metadata.finalizers) && object.metadata.finalizers.exists(f, f == 'kobe.kunobi.ninja/teardown-receipt-retention')) || (has(oldObject.status) && has(oldObject.status.teardownAcknowledgement) && has(object.status) && has(object.status.teardownAcknowledgement) && object.status.teardownAcknowledgement == oldObject.status.teardownAcknowledgement)"
            .into(),
    );
    expressions
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_objects(
        username: &str,
    ) -> (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding) {
        let validations = required_authority_expressions(username)
            .into_iter()
            .map(|expression| serde_json::json!({"expression": expression}))
            .collect::<Vec<_>>();
        (
            serde_json::from_value(serde_json::json!({
                "apiVersion":"admissionregistration.k8s.io/v1",
                "kind":"ValidatingAdmissionPolicy",
                "metadata":{"name":"authority","generation":1},
                "spec":{
                    "failurePolicy":"Fail",
                    "matchConstraints":{"resourceRules":[{
                        "apiGroups":["kobe.kunobi.ninja"],
                        "apiVersions":["v1alpha1"],
                        "operations":["CREATE","UPDATE","DELETE"],
                        "resources":["verifiedteardownevidence","clusterleases","clusterleases/status","clusterinstances/status"]
                    }]},
                    "validations":validations
                },
                "status":{
                    "observedGeneration":1,
                    "conditions":[{
                        "type":"Accepted",
                        "status":"True",
                        "reason":"Accepted",
                        "message":"policy accepted",
                        "lastTransitionTime":"2026-01-01T00:00:00Z"
                    }],
                    "typeChecking":{}
                }
            }))
            .unwrap(),
            serde_json::from_value(serde_json::json!({
                "apiVersion":"admissionregistration.k8s.io/v1",
                "kind":"ValidatingAdmissionPolicyBinding",
                "metadata":{"name":"authority"},
                "spec":{"policyName":"authority","validationActions":["Deny"]}
            }))
            .unwrap(),
        )
    }

    #[test]
    fn rejects_policy_missing_a_protected_field() {
        let username = "system:serviceaccount:ns:authority";
        let (mut policy, binding) = policy_objects(username);
        assert!(validate_objects(&policy, &binding, "authority", username).is_ok());
        policy
            .spec
            .as_mut()
            .unwrap()
            .validations
            .as_mut()
            .unwrap()
            .remove(1);
        assert!(validate_objects(&policy, &binding, "authority", username).is_err());
    }

    #[test]
    fn rejects_tautology_that_only_mentions_every_marker() {
        let username = "system:serviceaccount:ns:authority";
        let (mut policy, binding) = policy_objects(username);
        policy.spec.as_mut().unwrap().validations = Some(vec![
            serde_json::from_value(serde_json::json!({
                "expression": format!(
                    "request.userInfo.username == {username:?} || (teardownReceipt == teardownReceipt && teardownEvidence == teardownEvidence && teardownAttemptId == teardownAttemptId && unboundReleaseVerifiedAt == unboundReleaseVerifiedAt && teardownAcknowledgement == teardownAcknowledgement && connectTokenCreation == connectTokenCreation && creationManifest == creationManifest && teardownIdentities == teardownIdentities)"
                )
            }))
            .unwrap(),
        ]);
        assert!(validate_objects(&policy, &binding, "authority", username).is_err());
    }

    #[test]
    fn rejects_warn_only_binding() {
        let username = "system:serviceaccount:ns:authority";
        let (policy, mut binding) = policy_objects(username);
        binding.spec.as_mut().unwrap().validation_actions = Some(vec!["Warn".into()]);
        assert!(validate_objects(&policy, &binding, "authority", username).is_err());
    }

    #[test]
    fn rejects_binding_that_scopes_away_protected_objects() {
        let username = "system:serviceaccount:ns:authority";
        let (policy, mut binding) = policy_objects(username);
        binding.spec.as_mut().unwrap().match_resources = Some(Default::default());
        assert!(validate_objects(&policy, &binding, "authority", username).is_err());
    }

    #[test]
    fn rejects_policy_selectors_that_scope_away_protected_objects() {
        let username = "system:serviceaccount:ns:authority";
        for selector in ["namespaceSelector", "objectSelector"] {
            let (policy, binding) = policy_objects(username);
            let mut policy: serde_json::Value = serde_json::to_value(policy).unwrap();
            policy["spec"]["matchConstraints"][selector] = serde_json::json!({
                "matchLabels": { "authority": "opt-in" }
            });
            let policy = serde_json::from_value(policy).unwrap();
            assert!(
                validate_objects(&policy, &binding, "authority", username).is_err(),
                "{selector} must not make proof protection opt-in"
            );
        }
    }

    #[test]
    fn rejects_name_or_cluster_scoped_resource_rules() {
        let username = "system:serviceaccount:ns:authority";
        for (field, value) in [
            ("resourceNames", serde_json::json!(["only-one-object"])),
            ("scope", serde_json::json!("Cluster")),
        ] {
            let (policy, binding) = policy_objects(username);
            let mut policy: serde_json::Value = serde_json::to_value(policy).unwrap();
            policy["spec"]["matchConstraints"]["resourceRules"][0][field] = value;
            let policy = serde_json::from_value(policy).unwrap();
            assert!(
                validate_objects(&policy, &binding, "authority", username).is_err(),
                "{field} must not narrow the protected namespaced resources"
            );
        }
    }
}
