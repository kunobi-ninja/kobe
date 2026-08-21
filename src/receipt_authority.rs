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
    firewall_policy_name: &str,
    expected_username: &str,
    control_plane_username: &str,
    authority_namespace: &str,
) -> Result<(), ReceiptAuthorityError> {
    validate_identity_contract(
        policy_name,
        firewall_policy_name,
        expected_username,
        control_plane_username,
        authority_namespace,
    )?;
    let policies: Api<ValidatingAdmissionPolicy> = Api::all(client.clone());
    let bindings: Api<ValidatingAdmissionPolicyBinding> = Api::all(client.clone());
    let reviews: Api<SelfSubjectReview> = Api::all(client.clone());
    let review_params = PostParams::default();
    let review_request = SelfSubjectReview::default();
    let (policy, binding, firewall_policy, firewall_binding, review) = tokio::try_join!(
        policies.get(policy_name),
        bindings.get(policy_name),
        policies.get(firewall_policy_name),
        bindings.get(firewall_policy_name),
        reviews.create(&review_params, &review_request),
    )?;
    let actual_username = review
        .status
        .and_then(|status| status.user_info)
        .and_then(|user| user.username);
    if actual_username.as_deref() != Some(expected_username) {
        return Err(ReceiptAuthorityError::Invalid("ServiceAccount identity"));
    }
    validate_objects(&policy, &binding, policy_name, expected_username)?;
    validate_firewall_objects(
        &firewall_policy,
        &firewall_binding,
        firewall_policy_name,
        control_plane_username,
        authority_namespace,
    )
}

fn validate_identity_contract(
    policy_name: &str,
    firewall_policy_name: &str,
    expected_username: &str,
    control_plane_username: &str,
    authority_namespace: &str,
) -> Result<(), ReceiptAuthorityError> {
    let authority_identity = service_account_identity(expected_username);
    let control_plane_identity = service_account_identity(control_plane_username);
    if authority_namespace.trim().is_empty()
        || policy_name.trim().is_empty()
        || firewall_policy_name.trim().is_empty()
        || authority_identity.is_none_or(|(namespace, _)| namespace != authority_namespace)
        || control_plane_identity.is_none_or(|(namespace, _)| namespace == authority_namespace)
        || expected_username == control_plane_username
        || policy_name == firewall_policy_name
    {
        return Err(ReceiptAuthorityError::Invalid("ServiceAccount username"));
    }
    Ok(())
}

fn service_account_identity(username: &str) -> Option<(&str, &str)> {
    let suffix = username.strip_prefix("system:serviceaccount:")?;
    let (namespace, name) = suffix.split_once(':')?;
    (!namespace.is_empty() && !name.is_empty() && !name.contains(':')).then_some((namespace, name))
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
        "clusterinstances",
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
        || constraints.match_policy.as_deref() == Some("Exact")
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

/// Keep the attestation identity from acquiring lifecycle authority merely
/// because both controllers share the same CRD status subresource.
fn authority_cannot_change_status_field_expression(
    resource: &str,
    field: &str,
    username: &str,
) -> String {
    let username = serde_json::to_string(username).expect("ServiceAccount username is JSON");
    format!(
        "request.resource.resource != '{resource}' || request.userInfo.username != {username} || request.operation == 'DELETE' || (oldObject == null ? (!has(object.status) || !has(object.status.{field})) : (((!has(oldObject.status) || !has(oldObject.status.{field})) && (!has(object.status) || !has(object.status.{field}))) || (has(oldObject.status) && has(oldObject.status.{field}) && has(object.status) && has(object.status.{field}) && object.status.{field} == oldObject.status.{field})))"
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
    expressions.push(format!(
        "request.userInfo.username != {quoted_username} || !(request.resource.resource in ['clusterleases', 'clusterinstances']) || request.subResource == 'status'"
    ));
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
    for field in ["binding", "clusterName", "phase", "connectTokenCreation"] {
        expressions.push(authority_cannot_change_status_field_expression(
            "clusterleases",
            field,
            username,
        ));
    }
    for field in ["binding", "leaseRef", "phase"] {
        expressions.push(authority_cannot_change_status_field_expression(
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

fn firewall_expressions(username: &str, authority_namespace: &str) -> Vec<String> {
    let username = serde_json::to_string(username).expect("ServiceAccount username is JSON");
    let namespace =
        serde_json::to_string(authority_namespace).expect("authority namespace is JSON");
    vec![
        format!(
            "request.userInfo.username != {username} || request.resource.resource in ['namespaces', 'clusterroles', 'clusterrolebindings'] || request.namespace != {namespace}"
        ),
        format!(
            "request.userInfo.username != {username} || request.resource.resource != 'namespaces' || request.name != {namespace}"
        ),
        format!(
            "request.userInfo.username != {username} || request.resource.group != 'rbac.authorization.k8s.io' || !(request.resource.resource in ['clusterroles', 'clusterrolebindings'])"
        ),
    ]
}

fn rule_covers(
    rule: &k8s_openapi::api::admissionregistration::v1::NamedRuleWithOperations,
    groups: &[&str],
    versions: &[&str],
    operations: &[&str],
    resources: &[&str],
) -> bool {
    let actual_groups: Vec<&str> = rule
        .api_groups
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect();
    let actual_versions: Vec<&str> = rule
        .api_versions
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect();
    let actual_operations: std::collections::BTreeSet<&str> = rule
        .operations
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect();
    let actual_resources: std::collections::BTreeSet<&str> = rule
        .resources
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect();
    actual_groups == groups
        && actual_versions == versions
        && rule
            .resource_names
            .as_ref()
            .is_none_or(|names| names.is_empty())
        && rule.scope.is_none()
        && operations
            .iter()
            .all(|operation| actual_operations.contains(operation))
        && resources
            .iter()
            .all(|resource| actual_resources.contains(resource))
}

/// Validate the identity firewall independently from RBAC. Even if the
/// lifecycle ServiceAccount later receives another RoleBinding, this named
/// fail-closed policy must still prevent it from minting or using the authority
/// identity, changing RBAC, or replacing the dedicated namespace boundary.
fn validate_firewall_objects(
    policy: &ValidatingAdmissionPolicy,
    binding: &ValidatingAdmissionPolicyBinding,
    policy_name: &str,
    control_plane_username: &str,
    authority_namespace: &str,
) -> Result<(), ReceiptAuthorityError> {
    let spec = policy
        .spec
        .as_ref()
        .ok_or(ReceiptAuthorityError::Invalid("identity firewall policy"))?;
    let constraints = spec
        .match_constraints
        .as_ref()
        .ok_or(ReceiptAuthorityError::Invalid("identity firewall policy"))?;
    let rules = constraints
        .resource_rules
        .as_deref()
        .ok_or(ReceiptAuthorityError::Invalid("identity firewall policy"))?;
    let coverage = [
        (
            &[""][..],
            &["v1"][..],
            &["CREATE", "UPDATE", "DELETE"][..],
            &[
                "configmaps",
                "endpoints",
                "events",
                "persistentvolumeclaims",
                "replicationcontrollers",
                "secrets",
                "serviceaccounts",
                "serviceaccounts/token",
                "services",
                "pods",
                "pods/status",
                "pods/ephemeralcontainers",
            ][..],
        ),
        (
            &[""][..],
            &["v1"][..],
            &["CONNECT"][..],
            &["pods/exec", "pods/attach", "pods/portforward"][..],
        ),
        (
            &["apps"][..],
            &["v1"][..],
            &["CREATE", "UPDATE", "DELETE"][..],
            &["deployments", "replicasets", "statefulsets", "daemonsets"][..],
        ),
        (
            &["batch"][..],
            &["v1"][..],
            &["CREATE", "UPDATE", "DELETE"][..],
            &["jobs", "jobs/status", "cronjobs"][..],
        ),
        (
            &["networking.k8s.io"][..],
            &["v1"][..],
            &["CREATE", "UPDATE", "DELETE"][..],
            &["ingresses", "networkpolicies"][..],
        ),
        (
            &["policy"][..],
            &["v1"][..],
            &["CREATE", "UPDATE", "DELETE"][..],
            &["poddisruptionbudgets"][..],
        ),
        (
            &["coordination.k8s.io"][..],
            &["v1"][..],
            &["CREATE", "UPDATE", "DELETE"][..],
            &["leases"][..],
        ),
        (
            &["rbac.authorization.k8s.io"][..],
            &["v1"][..],
            &["CREATE", "UPDATE", "DELETE"][..],
            &["roles", "rolebindings"][..],
        ),
        (
            &[""][..],
            &["v1"][..],
            &["CREATE", "UPDATE", "DELETE"][..],
            &["namespaces"][..],
        ),
        (
            &["rbac.authorization.k8s.io"][..],
            &["v1"][..],
            &["CREATE", "UPDATE", "DELETE"][..],
            &["clusterroles", "clusterrolebindings"][..],
        ),
    ];
    let expected_expressions = firewall_expressions(control_plane_username, authority_namespace)
        .into_iter()
        .map(|expression| normalize_expression(&expression))
        .collect::<std::collections::BTreeSet<_>>();
    let actual_expressions = spec
        .validations
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|validation| normalize_expression(&validation.expression))
        .collect::<std::collections::BTreeSet<_>>();
    if policy.name_any() != policy_name
        || spec.failure_policy.as_deref() != Some("Fail")
        || spec.param_kind.is_some()
        || spec
            .match_conditions
            .as_ref()
            .is_some_and(|conditions| !conditions.is_empty())
        || constraints.match_policy.as_deref() == Some("Exact")
        || constraints
            .exclude_resource_rules
            .as_ref()
            .is_some_and(|excluded| !excluded.is_empty())
        || constraints.namespace_selector.is_some()
        || constraints.object_selector.is_some()
        || !coverage
            .iter()
            .all(|(groups, versions, operations, resources)| {
                rules
                    .iter()
                    .any(|rule| rule_covers(rule, groups, versions, operations, resources))
            })
        || !expected_expressions.is_subset(&actual_expressions)
    {
        return Err(ReceiptAuthorityError::Invalid("identity firewall policy"));
    }
    let generation = policy
        .metadata
        .generation
        .ok_or(ReceiptAuthorityError::NotReady("identity firewall policy"))?;
    let status = policy
        .status
        .as_ref()
        .ok_or(ReceiptAuthorityError::NotReady("identity firewall policy"))?;
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
        return Err(ReceiptAuthorityError::NotReady("identity firewall policy"));
    }
    let binding_spec = binding
        .spec
        .as_ref()
        .ok_or(ReceiptAuthorityError::Invalid("identity firewall binding"))?;
    if binding.name_any() != policy_name
        || binding_spec.policy_name.as_deref() != Some(policy_name)
        || binding_spec.validation_actions.as_deref() != Some(&["Deny".into()][..])
        || binding_spec.match_resources.is_some()
        || binding_spec.param_ref.is_some()
    {
        return Err(ReceiptAuthorityError::Invalid("identity firewall binding"));
    }
    Ok(())
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
                        "resources":["verifiedteardownevidence","clusterleases","clusterleases/status","clusterinstances","clusterinstances/status"]
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

    fn firewall_objects(
        username: &str,
        namespace: &str,
    ) -> (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding) {
        let validations = firewall_expressions(username, namespace)
            .into_iter()
            .map(|expression| serde_json::json!({"expression": expression}))
            .collect::<Vec<_>>();
        let crud = serde_json::json!(["CREATE", "UPDATE", "DELETE"]);
        let rules = serde_json::json!([
            {
                "apiGroups":[""], "apiVersions":["v1"], "operations":crud,
                "resources":["configmaps","endpoints","events","persistentvolumeclaims","replicationcontrollers","secrets","serviceaccounts","serviceaccounts/token","services","pods","pods/status","pods/ephemeralcontainers"]
            },
            {
                "apiGroups":[""], "apiVersions":["v1"], "operations":["CONNECT"],
                "resources":["pods/exec","pods/attach","pods/portforward"]
            },
            {
                "apiGroups":["apps"], "apiVersions":["v1"], "operations":crud,
                "resources":["deployments","replicasets","statefulsets","daemonsets"]
            },
            {
                "apiGroups":["batch"], "apiVersions":["v1"], "operations":crud,
                "resources":["jobs","jobs/status","cronjobs"]
            },
            {
                "apiGroups":["networking.k8s.io"], "apiVersions":["v1"], "operations":crud,
                "resources":["ingresses","networkpolicies"]
            },
            {
                "apiGroups":["policy"], "apiVersions":["v1"], "operations":crud,
                "resources":["poddisruptionbudgets"]
            },
            {
                "apiGroups":["coordination.k8s.io"], "apiVersions":["v1"], "operations":crud,
                "resources":["leases"]
            },
            {
                "apiGroups":["rbac.authorization.k8s.io"], "apiVersions":["v1"], "operations":crud,
                "resources":["roles","rolebindings"]
            },
            {
                "apiGroups":[""], "apiVersions":["v1"], "operations":crud,
                "resources":["namespaces"]
            },
            {
                "apiGroups":["rbac.authorization.k8s.io"], "apiVersions":["v1"], "operations":crud,
                "resources":["clusterroles","clusterrolebindings"]
            }
        ]);
        (
            serde_json::from_value(serde_json::json!({
                "apiVersion":"admissionregistration.k8s.io/v1",
                "kind":"ValidatingAdmissionPolicy",
                "metadata":{"name":"firewall","generation":1},
                "spec":{
                    "failurePolicy":"Fail",
                    "matchConstraints":{"resourceRules":rules},
                    "validations":validations
                },
                "status":{
                    "observedGeneration":1,
                    "conditions":[{
                        "type":"Accepted", "status":"True", "reason":"Accepted",
                        "message":"policy accepted", "lastTransitionTime":"2026-01-01T00:00:00Z"
                    }],
                    "typeChecking":{}
                }
            }))
            .unwrap(),
            serde_json::from_value(serde_json::json!({
                "apiVersion":"admissionregistration.k8s.io/v1",
                "kind":"ValidatingAdmissionPolicyBinding",
                "metadata":{"name":"firewall"},
                "spec":{"policyName":"firewall","validationActions":["Deny"]}
            }))
            .unwrap(),
        )
    }

    #[test]
    fn accepts_complete_dual_policy_contract() {
        let authority = "system:serviceaccount:authority-ns:authority";
        let general = "system:serviceaccount:kobe-system:kobe";
        let (policy, binding) = policy_objects(authority);
        let (firewall, firewall_binding) = firewall_objects(general, "authority-ns");
        assert!(validate_objects(&policy, &binding, "authority", authority).is_ok());
        assert!(
            validate_firewall_objects(
                &firewall,
                &firewall_binding,
                "firewall",
                general,
                "authority-ns"
            )
            .is_ok()
        );
        assert!(
            validate_identity_contract("authority", "firewall", authority, general, "authority-ns")
                .is_ok()
        );
    }

    #[test]
    fn rejects_authority_lifecycle_field_mutation_gaps() {
        let username = "system:serviceaccount:ns:authority";
        for (resource, field) in [
            ("clusterleases", "binding"),
            ("clusterleases", "clusterName"),
            ("clusterleases", "phase"),
            ("clusterleases", "connectTokenCreation"),
            ("clusterinstances", "binding"),
            ("clusterinstances", "leaseRef"),
            ("clusterinstances", "phase"),
        ] {
            let (mut policy, binding) = policy_objects(username);
            let validations = policy.spec.as_mut().unwrap().validations.as_mut().unwrap();
            let index = validations
                .iter()
                .position(|validation| {
                    validation
                        .expression
                        .contains(&format!("request.resource.resource != '{resource}'"))
                        && validation.expression.contains(&format!(".{field}"))
                        && validation
                            .expression
                            .contains("request.userInfo.username !=")
                })
                .expect("fixture contains lifecycle expression");
            validations.remove(index);
            assert!(
                validate_objects(&policy, &binding, "authority", username).is_err(),
                "missing lifecycle protection for {resource}.{field} must fail startup"
            );
        }

        let (mut policy, binding) = policy_objects(username);
        policy
            .spec
            .as_mut()
            .unwrap()
            .validations
            .as_mut()
            .unwrap()
            .retain(|validation| {
                !validation
                    .expression
                    .contains("request.subResource == 'status'")
            });
        assert!(
            validate_objects(&policy, &binding, "authority", username).is_err(),
            "authority writes to the main lease/instance resources must fail startup"
        );
    }

    #[test]
    fn rejects_incomplete_identity_firewall_coverage() {
        let username = "system:serviceaccount:kobe-system:kobe";
        for resource in [
            "serviceaccounts/token",
            "pods/exec",
            "pods/attach",
            "pods/portforward",
            "deployments",
            "jobs",
            "rolebindings",
            "namespaces",
            "clusterrolebindings",
        ] {
            let (policy, binding) = firewall_objects(username, "authority-ns");
            let mut value = serde_json::to_value(policy).unwrap();
            let rules = value["spec"]["matchConstraints"]["resourceRules"]
                .as_array_mut()
                .unwrap();
            let resources = rules
                .iter_mut()
                .find_map(|rule| {
                    let resources = rule["resources"].as_array_mut()?;
                    resources
                        .iter()
                        .any(|candidate| candidate == resource)
                        .then_some(resources)
                })
                .expect("fixture covers resource");
            resources.retain(|candidate| candidate != resource);
            let policy = serde_json::from_value(value).unwrap();
            assert!(
                validate_firewall_objects(&policy, &binding, "firewall", username, "authority-ns")
                    .is_err(),
                "firewall missing {resource} must fail startup"
            );
        }
    }

    #[test]
    fn rejects_equal_identities_or_policy_names() {
        let authority = "system:serviceaccount:authority-ns:authority";
        assert!(
            validate_identity_contract(
                "same",
                "same",
                authority,
                "system:serviceaccount:kobe-system:kobe",
                "authority-ns"
            )
            .is_err()
        );
        assert!(
            validate_identity_contract(
                "authority",
                "firewall",
                authority,
                authority,
                "authority-ns"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_scoped_warn_or_unready_firewall() {
        let username = "system:serviceaccount:kobe-system:kobe";
        let namespace = "authority-ns";

        let (policy, mut binding) = firewall_objects(username, namespace);
        binding.spec.as_mut().unwrap().validation_actions = Some(vec!["Warn".into()]);
        assert!(
            validate_firewall_objects(&policy, &binding, "firewall", username, namespace).is_err()
        );

        let (policy, binding) = firewall_objects(username, namespace);
        let mut value = serde_json::to_value(policy).unwrap();
        value["spec"]["matchConstraints"]["matchPolicy"] = "Exact".into();
        let policy = serde_json::from_value(value).unwrap();
        assert!(
            validate_firewall_objects(&policy, &binding, "firewall", username, namespace).is_err()
        );

        let (mut policy, binding) = firewall_objects(username, namespace);
        policy.status.as_mut().unwrap().observed_generation = Some(0);
        assert!(matches!(
            validate_firewall_objects(&policy, &binding, "firewall", username, namespace),
            Err(ReceiptAuthorityError::NotReady(_))
        ));
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
