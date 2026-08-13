//! Short-lived, single-Pod credentials for one Sandbox operation (#81).
//!
//! The resolver answers *which* Pod. This answers *with what authority* Kobe
//! touches it.
//!
//! # Why not just use the operator's own client
//!
//! Because the operator's client is cluster-admin-adjacent, and a bug anywhere
//! in the request path — a mis-parsed name, a header that survived, a proxy
//! that followed a redirect — is then a bug with the operator's authority
//! behind it. Minting a credential that *cannot* name a second Pod turns those
//! bugs from privilege escalation into a 403.
//!
//! This is defence in depth, not the primary control: the resolver already
//! denies before anything is minted. But the two fail differently, and that is
//! the point of having both.
//!
//! # What the credential can do
//!
//! Exactly one Pod, by name, and only the subresources the operation needs.
//! `resourceNames` is what makes that true — an RBAC rule without it grants the
//! verb over every Pod in the namespace, which in a management cluster is every
//! tenant's Sandbox at once.
//!
//! It cannot read Secrets, mutate RBAC, create Pods, list anything, reach
//! Nodes, or cross namespaces. Those are not omissions to be filled in later:
//! a Sandbox operation needs none of them, and each would be reachable from a
//! caller-facing path.
//!
//! # Lifetime
//!
//! Minted per operation with a short expiry, and never persisted. A token in a
//! CRD, a response, an event or a log is a token somebody can replay after the
//! lease it belonged to is gone.

use k8s_openapi::api::authentication::v1::{TokenRequest, TokenRequestSpec};
use k8s_openapi::api::core::v1::ServiceAccount;
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, RoleBinding, RoleRef, Subject};
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};

use crate::api::sandbox_access::{SandboxAccessDenied, SandboxTarget};

/// How long a minted token is valid.
///
/// Long enough to complete an operation and survive a retry; short enough that
/// a leaked one is worthless before anyone can use it. Streams that outlive it
/// are already authenticated — Kubernetes does not re-check mid-connection —
/// which is why #83's revocation cancels streams rather than relying on expiry.
pub const TOKEN_LIFETIME_SECONDS: i64 = 600;

/// What a credential is being minted for.
///
/// Each operation gets only the subresources it needs. `Logs` cannot exec, and
/// `Exec` cannot port-forward: an operation that only reads output has no
/// business holding the verb that runs commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxOperation {
    Logs,
    Exec,
    /// Attaching to the container's EXISTING process, which is `pods/attach`
    /// rather than `pods/exec`.
    Attach,
    PortForward,
}

impl SandboxOperation {
    /// The exact Pod subresources this operation needs.
    ///
    /// The verb comes from the HTTP METHOD the client actually sends, not from
    /// what the operation feels like. `kube-rs` builds exec, attach and
    /// port-forward as `GET` requests — they are WebSocket upgrades — and the
    /// apiserver derives the RBAC verb from the method. Granting `create`, as
    /// `kubectl`'s SPDY `POST` would need, produced a Role that 403s every
    /// single one of these calls: a failure invisible to every unit test,
    /// because no unit test mints a real token.
    pub fn subresources(self) -> &'static [(&'static str, &'static str)] {
        match self {
            // `get` on `pods` as well: the caller verifies the Pod's UID before
            // touching it, and that read must not need a broader rule.
            Self::Logs => &[("pods", "get"), ("pods/log", "get")],
            Self::Exec => &[("pods", "get"), ("pods/exec", "get")],
            // A bare attach (no command) calls `pods/attach`, a DIFFERENT
            // subresource from exec. Sharing the exec identity meant that path
            // was a guaranteed 403 on a socket that had already upgraded
            // cleanly, so the caller saw an opaque transport error.
            Self::Attach => &[("pods", "get"), ("pods/attach", "get")],
            Self::PortForward => &[("pods", "get"), ("pods/portforward", "get")],
        }
    }

    /// Bounded label for audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Logs => "logs",
            Self::Exec => "exec",
            Self::Attach => "attach",
            Self::PortForward => "port-forward",
        }
    }
}

/// Names are derived from the lease UID, never from anything a caller supplies.
///
/// The UID rather than the name because lease names are recycled: a credential
/// object left behind by a previous lease would otherwise be adopted by its
/// same-named successor, quietly granting the new caller access scoped to the
/// old caller's Pod.
pub fn credential_name(lease_uid: &str, operation: SandboxOperation) -> String {
    // Per OPERATION, not just per lease. One object per lease meant a
    // concurrent `logs` and `exec` server-side-applied their rules over each
    // other under the same field manager: the loser's already-minted token
    // started 403ing, and in the interval the `logs` identity briefly held
    // exec. Separate objects make "operations do not borrow each other's
    // authority" true of the cluster, not just of the rule builder.
    //
    // A UID is 36 characters; the prefix and suffix keep this well inside the
    // 253-character limit.
    format!("kobe-sbx-{lease_uid}-{}", operation.as_str())
}

/// The RBAC rules for one operation against one exact Pod.
///
/// Pure, because this is the security boundary and it must be assertable
/// without a cluster.
pub fn scoped_rules(target: &SandboxTarget, operation: SandboxOperation) -> Vec<PolicyRule> {
    operation
        .subresources()
        .iter()
        .map(|(resource, verb)| PolicyRule {
            api_groups: Some(vec![String::new()]),
            resources: Some(vec![(*resource).to_string()]),
            verbs: vec![(*verb).to_string()],
            // The whole point. Without `resourceNames` this grants the verb
            // over every Pod in the namespace — in a management cluster, every
            // tenant's Sandbox at once.
            resource_names: Some(vec![target.pod_name.clone()]),
            non_resource_urls: None,
        })
        .collect()
}

/// Create — or converge — the ServiceAccount, Role and RoleBinding for a lease.
///
/// Server-side applied so a repeated operation converges instead of failing on
/// conflict, and so a drifted Role is corrected rather than trusted. Drift
/// matters here more than usual: a Role edited to drop its `resourceNames` is
/// a namespace-wide grant that looks, by name, exactly like the scoped one.
async fn ensure_scoped_identity(
    client: &kube::Client,
    target: &SandboxTarget,
    operation: SandboxOperation,
) -> Result<String, SandboxAccessDenied> {
    let name = credential_name(&target.lease_uid, operation);
    let namespace = &target.namespace;
    let params = PatchParams::apply(crate::sandbox::KOBE_MANAGED_BY).force();

    let metadata = || ObjectMeta {
        name: Some(name.clone()),
        namespace: Some(namespace.clone()),
        labels: Some(
            [
                (
                    "app.kubernetes.io/managed-by".to_string(),
                    crate::sandbox::KOBE_MANAGED_BY.to_string(),
                ),
                (
                    "kobe.kunobi.ninja/sandbox-lease-uid".to_string(),
                    target.lease_uid.clone(),
                ),
            ]
            .into_iter()
            .collect(),
        ),
        ..Default::default()
    };

    let accounts: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    accounts
        .patch(
            &name,
            &params,
            &Patch::Apply(&ServiceAccount {
                metadata: metadata(),
                // No automounted token: nothing runs as this account. It exists
                // only to be the subject of a TokenRequest.
                automount_service_account_token: Some(false),
                ..Default::default()
            }),
        )
        .await
        .map_err(|_| SandboxAccessDenied::Backend)?;

    let roles: Api<Role> = Api::namespaced(client.clone(), namespace);
    roles
        .patch(
            &name,
            &params,
            &Patch::Apply(&Role {
                metadata: metadata(),
                rules: Some(scoped_rules(target, operation)),
            }),
        )
        .await
        .map_err(|_| SandboxAccessDenied::Backend)?;

    let bindings: Api<RoleBinding> = Api::namespaced(client.clone(), namespace);
    bindings
        .patch(
            &name,
            &params,
            &Patch::Apply(&RoleBinding {
                metadata: metadata(),
                role_ref: RoleRef {
                    api_group: "rbac.authorization.k8s.io".to_string(),
                    kind: "Role".to_string(),
                    name: name.clone(),
                },
                subjects: Some(vec![Subject {
                    kind: "ServiceAccount".to_string(),
                    name: name.clone(),
                    namespace: Some(namespace.clone()),
                    api_group: None,
                }]),
            }),
        )
        .await
        .map_err(|_| SandboxAccessDenied::Backend)?;

    Ok(name)
}

/// Mint a short-lived token for one operation against one Pod.
///
/// The returned string is a bearer token. It is never logged, never returned to
/// a caller, and never stored — a token that outlives the operation is a token
/// somebody can replay after the lease it belonged to is gone.
pub async fn mint_scoped_token(
    client: &kube::Client,
    target: &SandboxTarget,
    operation: SandboxOperation,
) -> Result<String, SandboxAccessDenied> {
    let name = ensure_scoped_identity(client, target, operation).await?;
    let accounts: Api<ServiceAccount> = Api::namespaced(client.clone(), &target.namespace);

    let request = TokenRequest {
        metadata: ObjectMeta {
            name: Some(name.clone()),
            namespace: Some(target.namespace.clone()),
            ..Default::default()
        },
        spec: TokenRequestSpec {
            // No audiences override: the token is for this cluster's API
            // server, which is the only thing it should ever authenticate to.
            audiences: vec![],
            expiration_seconds: Some(TOKEN_LIFETIME_SECONDS),
            bound_object_ref: None,
        },
        status: None,
    };

    tracing::debug!(
        operation = operation.as_str(),
        pod = %target.pod_name,
        "minting scoped Sandbox credential"
    );
    let issued = accounts
        .create_token_request(&name, &PostParams::default(), &request)
        .await
        .map_err(|_| SandboxAccessDenied::Backend)?;

    issued
        .status
        .map(|status| status.token)
        .filter(|token| !token.is_empty())
        .ok_or(SandboxAccessDenied::Backend)
}

/// The operator's own cluster configuration, resolved once.
///
/// Reused so every scoped client keeps the operator's endpoint and trust
/// anchors — only the identity differs. Resolved lazily rather than at startup
/// so a deployment that never serves a Sandbox operation does not require it.
static BASE_CONFIG: tokio::sync::OnceCell<kube::Config> = tokio::sync::OnceCell::const_new();

pub async fn operator_config() -> Result<&'static kube::Config, SandboxAccessDenied> {
    BASE_CONFIG
        .get_or_try_init(|| async {
            kube::Config::infer()
                .await
                .map_err(|_| SandboxAccessDenied::Backend)
        })
        .await
}

/// Build a client that can reach only this Sandbox's Pod.
///
/// The endpoint and trust anchors come from the operator's own configuration;
/// only the identity differs. Every other authorisation on that config is
/// **dropped** rather than merged: an inherited client certificate would
/// out-rank the bearer token and silently restore the operator's authority,
/// which is the one thing this function exists to remove.
pub async fn scoped_client(
    cluster: &crate::api::sandbox_access::TargetCluster,
    target: &SandboxTarget,
    operation: SandboxOperation,
) -> Result<kube::Client, SandboxAccessDenied> {
    // Minted in the cluster the Pod is in — for a child composition that is the
    // child cluster, not Kobe's. A token issued by the management cluster would
    // not authenticate there at all, and reaching the child as its admin
    // identity is exactly what this replaces.
    let token = mint_scoped_token(&cluster.admin, target, operation).await?;

    let mut config = cluster.config.clone();
    config.auth_info = kube::config::AuthInfo {
        token: Some(token.into()),
        ..Default::default()
    };
    config.default_namespace = target.namespace.clone();

    kube::Client::try_from(config).map_err(|_| SandboxAccessDenied::Backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SandboxTarget {
        SandboxTarget {
            lease_uid: "lease-uid-1".into(),
            placement: crate::api::sandbox_access::TargetPlacement::Management,
            namespace: "kobe".into(),
            claim_uid: "claim-uid".into(),
            sandbox_name: "sbx".into(),
            sandbox_uid: "sandbox-uid".into(),
            pod_name: "sbx-0".into(),
            pod_uid: "pod-uid".into(),
            container: "agent".into(),
            ports: vec![],
        }
    }

    /// A credential must never be able to name a second Pod.
    ///
    /// `resourceNames` is the entire boundary. An RBAC rule without it grants
    /// the verb over every Pod in the namespace — in a management cluster,
    /// every tenant's Sandbox at once. This is the assertion that would catch
    /// that rule being loosened.
    #[test]
    fn every_rule_is_pinned_to_exactly_one_pod() {
        for operation in [
            SandboxOperation::Logs,
            SandboxOperation::Exec,
            SandboxOperation::Attach,
            SandboxOperation::PortForward,
        ] {
            let rules = scoped_rules(&target(), operation);
            assert!(!rules.is_empty(), "{operation:?} must grant something");
            for rule in &rules {
                assert_eq!(
                    rule.resource_names.as_deref(),
                    Some(["sbx-0".to_string()].as_slice()),
                    "{operation:?} rule {rule:?} is not pinned to one Pod"
                );
                assert_eq!(rule.api_groups.as_deref(), Some([String::new()].as_slice()));
                assert!(
                    rule.non_resource_urls.is_none(),
                    "a Sandbox operation needs no non-resource URLs"
                );
            }
        }
    }

    /// Each operation gets only what it needs.
    ///
    /// An operation that reads output has no business holding the verb that
    /// runs commands. If these ever collapsed into one rule set, a `logs`
    /// request would be minting an exec-capable token.
    #[test]
    fn operations_do_not_borrow_each_others_authority() {
        let verbs = |operation: SandboxOperation| -> Vec<String> {
            scoped_rules(&target(), operation)
                .iter()
                .flat_map(|rule| {
                    let resource = rule.resources.as_ref().unwrap()[0].clone();
                    rule.verbs
                        .iter()
                        .map(move |verb| format!("{resource}:{verb}"))
                })
                .collect()
        };

        let logs = verbs(SandboxOperation::Logs);
        assert!(logs.contains(&"pods/log:get".to_string()));
        assert!(
            !logs
                .iter()
                .any(|granted| granted.contains("exec")
                    || granted.contains("attach")
                    || granted.contains("portforward")),
            "reading logs must not grant execution: {logs:?}"
        );

        let exec = verbs(SandboxOperation::Exec);
        assert!(exec.contains(&"pods/exec:get".to_string()));
        assert!(!exec.iter().any(|granted| granted.contains("portforward")));

        let forward = verbs(SandboxOperation::PortForward);
        assert!(forward.contains(&"pods/portforward:get".to_string()));
        assert!(
            !forward.iter().any(|granted| granted.contains("exec")),
            "forwarding a port must not carry the verb that runs commands: {forward:?}"
        );
    }

    /// Nothing a Sandbox operation does requires the dangerous verbs.
    ///
    /// Enumerated explicitly rather than left implicit: this is the list #81
    /// commits to, and a rule set that grew one of them should fail here rather
    /// than in an audit.
    #[test]
    fn scoped_rules_reach_nothing_beyond_one_pod() {
        for operation in [
            SandboxOperation::Logs,
            SandboxOperation::Exec,
            SandboxOperation::Attach,
            SandboxOperation::PortForward,
        ] {
            for rule in scoped_rules(&target(), operation) {
                let resources = rule.resources.clone().unwrap_or_default();
                for forbidden in [
                    "secrets",
                    "configmaps",
                    "serviceaccounts",
                    "nodes",
                    "roles",
                    "rolebindings",
                    "namespaces",
                    "persistentvolumes",
                ] {
                    assert!(
                        !resources.iter().any(|resource| resource == forbidden),
                        "{operation:?} must not reach {forbidden}"
                    );
                }
                for forbidden in ["list", "watch", "delete", "deletecollection", "*"] {
                    assert!(
                        !rule.verbs.iter().any(|verb| verb == forbidden),
                        "{operation:?} must not be granted {forbidden}: {rule:?}"
                    );
                }
                // `create` on bare `pods` would be a way to start a workload
                // that outlives the lease entirely.
                if resources.iter().any(|resource| resource == "pods") {
                    assert_eq!(rule.verbs, vec!["get".to_string()]);
                }
            }
        }
    }

    /// Credential objects are named by lease UID and operation.
    ///
    /// By UID rather than lease NAME because names are recycled: a Role left
    /// behind by a previous lease and adopted by its same-named successor
    /// would scope the new caller's credential to the OLD caller's Pod — a
    /// cross-tenant grant produced entirely by naming.
    ///
    /// By OPERATION because one object per lease meant concurrent operations
    /// server-side-applied their rules over each other under the same field
    /// manager, so the loser's already-minted token began 403ing and the
    /// winner's briefly held authority it was never meant to have.
    #[test]
    fn credential_names_are_fenced_by_uid_and_operation() {
        assert_ne!(
            credential_name("uid-aaa", SandboxOperation::Exec),
            credential_name("uid-bbb", SandboxOperation::Exec),
            "two leases must not share a credential"
        );
        assert_ne!(
            credential_name("uid-aaa", SandboxOperation::Exec),
            credential_name("uid-aaa", SandboxOperation::Logs),
            "two operations on one lease must not share a Role to fight over"
        );

        for operation in [
            SandboxOperation::Logs,
            SandboxOperation::Exec,
            SandboxOperation::Attach,
            SandboxOperation::PortForward,
        ] {
            let name = credential_name(&"u".repeat(36), operation);
            assert!(name.len() <= 253, "{name} is too long to be an object name");
            assert!(name.starts_with("kobe-sbx-"));
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{name} is not a valid object name"
            );
        }
    }

    /// The granted verb must be the one the request actually sends.
    ///
    /// `kube-rs` builds exec, attach and port-forward as `GET` — they are
    /// WebSocket upgrades — and the apiserver derives the RBAC verb from the
    /// HTTP method. Granting `create`, which `kubectl`'s SPDY `POST` would
    /// need, produced Roles that 403'd every one of these calls: invisible to
    /// every unit test, because no unit test mints a real token.
    #[test]
    fn the_granted_verb_matches_the_method_the_client_sends() {
        for (operation, subresource) in [
            (SandboxOperation::Exec, "pods/exec"),
            (SandboxOperation::Attach, "pods/attach"),
            (SandboxOperation::PortForward, "pods/portforward"),
        ] {
            let rules = scoped_rules(&target(), operation);
            let rule = rules
                .iter()
                .find(|rule| {
                    rule.resources
                        .as_deref()
                        .is_some_and(|resources| resources.iter().any(|r| r == subresource))
                })
                .unwrap_or_else(|| panic!("{operation:?} must grant {subresource}"));
            assert_eq!(
                rule.verbs,
                vec!["get".to_string()],
                "{subresource} is reached over GET, so `create` would 403"
            );
        }

        // Attach addresses its OWN subresource. Reusing the exec identity made
        // a bare attach a guaranteed 403 on an already-upgraded socket.
        let attach: Vec<String> = scoped_rules(&target(), SandboxOperation::Attach)
            .iter()
            .flat_map(|rule| rule.resources.clone().unwrap_or_default())
            .collect();
        assert!(attach.iter().any(|r| r == "pods/attach"));
        assert!(!attach.iter().any(|r| r == "pods/exec"));
    }

    /// A minted token lives for minutes, not for the lease.
    ///
    /// A token valid for the lease's whole TTL is one a leak makes useful for
    /// hours. Short expiry does not revoke an already-upgraded stream —
    /// Kubernetes does not re-check mid-connection — which is exactly why #83
    /// cancels streams rather than relying on this.
    #[test]
    fn tokens_are_short_lived() {
        const { assert!(TOKEN_LIFETIME_SECONDS <= 900) };
        const { assert!(TOKEN_LIFETIME_SECONDS >= 60) };
        // Restated where a reader will see it: a token valid for an hour is one
        // a leak makes useful for an hour, and one too short to survive a retry
        // is its own failure mode.
    }
}
