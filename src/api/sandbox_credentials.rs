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

use super::sandbox_access::backend_denied;
use k8s_openapi::api::authentication::v1::{BoundObjectReference, TokenRequest, TokenRequestSpec};
use k8s_openapi::api::core::v1::ServiceAccount;
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, RoleBinding, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::Resource;
use kube::api::{Api, DeleteParams, ObjectMeta, Patch, PatchParams, PostParams, Preconditions};

use crate::api::sandbox_access::{SandboxAccessDenied, SandboxTarget};

/// How long a minted token is valid.
///
/// Long enough to complete an operation and survive a retry; short enough that
/// a leaked one is worthless before anyone can use it. Streams that outlive it
/// are already authenticated — Kubernetes does not re-check mid-connection —
/// which is why #83's revocation cancels streams rather than relying on expiry.
pub const TOKEN_LIFETIME_SECONDS: i64 = 600;

/// Maximum API-server clock skew accepted on the actual token expiry.
///
/// The requested lifetime remains ten minutes. These five seconds only keep a
/// slightly-ahead API-server clock from making an otherwise correctly bounded
/// response unusable; they are not added to the TokenRequest itself.
const TOKEN_EXPIRATION_SKEW_SECONDS: i64 = 5;

const SANDBOX_LEASE_UID_LABEL: &str = "kobe.kunobi.ninja/sandbox-lease-uid";

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
    const ALL: [Self; 4] = [Self::Logs, Self::Exec, Self::Attach, Self::PortForward];

    /// The AccessPolicy verb a caller must hold to perform this operation.
    ///
    /// `Attach` maps to `Exec`: attaching is an interactive shell on the
    /// workload, so it is at least as powerful as a one-shot command, and the
    /// verb set has no narrower grant for it. Being able to attach without
    /// holding `exec` is therefore deliberately not expressible, rather than
    /// silently free as it was before this mapping existed.
    pub fn required_verb(self) -> crate::crd::SandboxVerb {
        match self {
            Self::Logs => crate::crd::SandboxVerb::Logs,
            Self::Exec | Self::Attach => crate::crd::SandboxVerb::Exec,
            Self::PortForward => crate::crd::SandboxVerb::PortForward,
        }
    }

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
            // Upgrade subresources carry BOTH verbs. kube-rs sends the
            // WebSocket upgrade as a GET, which apiservers before 1.35
            // authorize as `get` — but 1.35's
            // `AuthorizePodWebsocketUpgradeCreatePermission` (default on,
            // KEP-4006) closed that read-verb escalation and demands `create`
            // for any upgrade. `resourceNames` still pins both verbs to the
            // one Pod: an upgrade request names its target in the URL.
            Self::Exec => &[
                ("pods", "get"),
                ("pods/exec", "get"),
                ("pods/exec", "create"),
            ],
            // A bare attach (no command) calls `pods/attach`, a DIFFERENT
            // subresource from exec. Sharing the exec identity meant that path
            // was a guaranteed 403 on a socket that had already upgraded
            // cleanly, so the caller saw an opaque transport error.
            Self::Attach => &[
                ("pods", "get"),
                ("pods/attach", "get"),
                ("pods/attach", "create"),
            ],
            Self::PortForward => &[
                ("pods", "get"),
                ("pods/portforward", "get"),
                ("pods/portforward", "create"),
            ],
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

/// Result of removing every short-lived identity for one Sandbox Pod.
///
/// `Clean` means every deterministic object was observed absent. `Retry`
/// means a transient response prevented that proof. `Quarantine` means Kobe
/// was forbidden from checking, or the deterministic name now identifies an
/// object whose provenance cannot be proven; callers must retain capacity and
/// require operator inspection rather than deleting by label or name alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) enum CredentialCleanupOutcome {
    Clean,
    Retry,
    Quarantine,
}

#[derive(Debug, Clone, Copy)]
enum CredentialResourceKind {
    RoleBinding,
    Role,
    ServiceAccount,
}

fn pod_owner_reference(pod_name: &str, pod_uid: &str) -> OwnerReference {
    OwnerReference {
        api_version: "v1".to_string(),
        kind: "Pod".to_string(),
        name: pod_name.to_string(),
        uid: pod_uid.to_string(),
        // The Pod's real controller remains the Sandbox runtime. These
        // credentials are dependants, never competing controllers.
        controller: Some(false),
        block_owner_deletion: Some(true),
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

fn credential_metadata(name: &str, target: &SandboxTarget) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.to_string()),
        namespace: Some(target.namespace.clone()),
        owner_references: Some(vec![pod_owner_reference(&target.pod_name, &target.pod_uid)]),
        labels: Some(
            [
                (
                    "app.kubernetes.io/managed-by".to_string(),
                    crate::sandbox::KOBE_MANAGED_BY.to_string(),
                ),
                (
                    SANDBOX_LEASE_UID_LABEL.to_string(),
                    target.lease_uid.clone(),
                ),
            ]
            .into_iter()
            .collect(),
        ),
        ..Default::default()
    }
}

/// Prove that an object at the deterministic name belongs to this exact lease
/// and Pod before Kobe is allowed to converge it.
///
/// A name is deliberately not treated as ownership. The singular, exact Pod
/// owner reference and the exact lease-UID label are independent provenance
/// checks, while UID/resourceVersion fence the later JSON Patch against a
/// same-name replacement.
fn owned_credential_fence<K: Resource>(
    object: &K,
    name: &str,
    target: &SandboxTarget,
) -> Result<(String, String), ()> {
    let metadata = object.meta();
    let expected_owner = pod_owner_reference(&target.pod_name, &target.pod_uid);
    if metadata.name.as_deref() != Some(name)
        || metadata.namespace.as_deref() != Some(target.namespace.as_str())
        || metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(SANDBOX_LEASE_UID_LABEL))
            .map(String::as_str)
            != Some(target.lease_uid.as_str())
        || metadata.owner_references.as_deref() != Some(std::slice::from_ref(&expected_owner))
    {
        return Err(());
    }

    let uid = metadata
        .uid
        .as_ref()
        .filter(|uid| !uid.is_empty())
        .cloned()
        .ok_or(())?;
    let resource_version = metadata
        .resource_version
        .as_ref()
        .filter(|version| !version.is_empty())
        .cloned()
        .ok_or(())?;
    Ok((uid, resource_version))
}

fn managed_label_matches<K: Resource>(object: &K) -> bool {
    object
        .meta()
        .labels
        .as_ref()
        .and_then(|labels| labels.get("app.kubernetes.io/managed-by"))
        .map(String::as_str)
        == Some(crate::sandbox::KOBE_MANAGED_BY)
}

/// Create a missing credential object, or converge only an object whose exact
/// lease and Pod provenance was proved by a pre-read.
///
/// JSON Patch `test` operations make that proof atomic with the repair. If the
/// object is replaced or its provenance changes after GET, Kubernetes rejects
/// the patch rather than letting Kobe adopt the replacement.
async fn ensure_owned_credential<K, F>(
    api: &Api<K>,
    name: &str,
    target: &SandboxTarget,
    desired: &K,
    shape_matches: F,
    mut convergence_operations: Vec<serde_json::Value>,
) -> Result<(), SandboxAccessDenied>
where
    K: Clone
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::fmt::Debug
        + Resource<DynamicType = ()>,
    F: Fn(&K) -> bool,
{
    let observed = match api.get(name).await {
        Ok(observed) => observed,
        Err(kube::Error::Api(response)) if response.code == 404 => {
            match api.create(&PostParams::default(), desired).await {
                Ok(created) => {
                    owned_credential_fence(&created, name, target).map_err(|()| {
                        backend_denied(&"credential object is not owned by the exact target")
                    })?;
                    if managed_label_matches(&created) && shape_matches(&created) {
                        return Ok(());
                    }
                    return Err(backend_denied(
                        &"freshly created credential object has a drifted shape",
                    ));
                }
                // A concurrent creator won. Re-read it and apply the same
                // ownership proof; never turn the conflict into adoption.
                Err(kube::Error::Api(response)) if response.code == 409 => api
                    .get(name)
                    .await
                    .map_err(|error| backend_denied(&error))?,
                Err(error) => return Err(backend_denied(&error)),
            }
        }
        Err(error) => return Err(backend_denied(&error)),
    };

    let (uid, resource_version) = owned_credential_fence(&observed, name, target)
        .map_err(|()| backend_denied(&"credential object is not owned by the exact target"))?;
    if managed_label_matches(&observed) && shape_matches(&observed) {
        return Ok(());
    }

    let expected_owner = pod_owner_reference(&target.pod_name, &target.pod_uid);
    let mut operations = vec![
        serde_json::json!({ "op": "test", "path": "/metadata/uid", "value": uid }),
        serde_json::json!({
            "op": "test",
            "path": "/metadata/resourceVersion",
            "value": resource_version,
        }),
        serde_json::json!({
            "op": "test",
            "path": "/metadata/labels/kobe.kunobi.ninja~1sandbox-lease-uid",
            "value": target.lease_uid,
        }),
        serde_json::json!({
            "op": "test",
            "path": "/metadata/ownerReferences",
            "value": [expected_owner],
        }),
        serde_json::json!({
            "op": "add",
            "path": "/metadata/labels/app.kubernetes.io~1managed-by",
            "value": crate::sandbox::KOBE_MANAGED_BY,
        }),
    ];
    operations.append(&mut convergence_operations);
    let patch = crate::controllers::lease::json_patch(serde_json::Value::Array(operations));
    let converged = api
        .patch(name, &PatchParams::default(), &Patch::Json::<()>(patch))
        .await
        .map_err(|error| backend_denied(&error))?;

    owned_credential_fence(&converged, name, target)
        .map_err(|()| backend_denied(&"credential object is not owned by the exact target"))?;
    if managed_label_matches(&converged) && shape_matches(&converged) {
        Ok(())
    } else {
        Err(backend_denied(
            &"converged credential object has a drifted shape",
        ))
    }
}

/// Create — or safely converge — the ServiceAccount, Role and RoleBinding.
///
/// Missing objects are created atomically. Existing objects are changed only
/// after exact lease/Pod provenance is proved, so a foreign same-name object
/// is rejected rather than force-adopted. Owned drift is still corrected: a
/// Role edited to drop `resourceNames` is a namespace-wide grant and must never
/// be trusted merely because its name looks scoped.
async fn ensure_scoped_identity(
    client: &kube::Client,
    target: &SandboxTarget,
    operation: SandboxOperation,
) -> Result<String, SandboxAccessDenied> {
    let name = credential_name(&target.lease_uid, operation);
    let namespace = &target.namespace;

    let accounts: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    let account = ServiceAccount {
        metadata: credential_metadata(&name, target),
        // No automounted token: nothing runs as this account. It exists only
        // to be the subject of a TokenRequest.
        automount_service_account_token: Some(false),
        ..Default::default()
    };
    ensure_owned_credential(
        &accounts,
        &name,
        target,
        &account,
        |observed| observed.automount_service_account_token == Some(false),
        vec![serde_json::json!({
            "op": "add",
            "path": "/automountServiceAccountToken",
            "value": false,
        })],
    )
    .await?;

    let roles: Api<Role> = Api::namespaced(client.clone(), namespace);
    let rules = scoped_rules(target, operation);
    let role = Role {
        metadata: credential_metadata(&name, target),
        rules: Some(rules.clone()),
    };
    ensure_owned_credential(
        &roles,
        &name,
        target,
        &role,
        |observed| observed.rules.as_deref() == Some(rules.as_slice()),
        vec![serde_json::json!({ "op": "add", "path": "/rules", "value": rules })],
    )
    .await?;

    let bindings: Api<RoleBinding> = Api::namespaced(client.clone(), namespace);
    let role_ref = RoleRef {
        api_group: "rbac.authorization.k8s.io".to_string(),
        kind: "Role".to_string(),
        name: name.clone(),
    };
    let subjects = vec![Subject {
        kind: "ServiceAccount".to_string(),
        name: name.clone(),
        namespace: Some(namespace.clone()),
        api_group: None,
    }];
    let binding = RoleBinding {
        metadata: credential_metadata(&name, target),
        role_ref: role_ref.clone(),
        subjects: Some(subjects.clone()),
    };
    ensure_owned_credential(
        &bindings,
        &name,
        target,
        &binding,
        |observed| {
            observed.role_ref == role_ref
                && observed.subjects.as_deref() == Some(subjects.as_slice())
        },
        vec![
            serde_json::json!({ "op": "add", "path": "/roleRef", "value": role_ref }),
            serde_json::json!({ "op": "add", "path": "/subjects", "value": subjects }),
        ],
    )
    .await?;

    Ok(name)
}

/// Validate the API server's actual expiry, independently of what was asked
/// for in the TokenRequest.
fn token_expiration_is_acceptable(
    expiration_timestamp: &str,
    requested_at: chrono::DateTime<chrono::Utc>,
    received_at: chrono::DateTime<chrono::Utc>,
) -> bool {
    let Ok(expiration) = chrono::DateTime::parse_from_rfc3339(expiration_timestamp) else {
        return false;
    };
    let expiration = expiration.with_timezone(&chrono::Utc);
    let latest_allowed = requested_at
        + chrono::Duration::seconds(TOKEN_LIFETIME_SECONDS + TOKEN_EXPIRATION_SKEW_SECONDS);
    expiration > received_at && expiration <= latest_allowed
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
            // The API server invalidates this credential when this exact Pod
            // identity disappears. Binding by UID prevents a same-named Pod
            // replacement from inheriting an already-issued token.
            bound_object_ref: Some(BoundObjectReference {
                api_version: Some("v1".to_string()),
                kind: Some("Pod".to_string()),
                name: Some(target.pod_name.clone()),
                uid: Some(target.pod_uid.clone()),
            }),
        },
        status: None,
    };

    tracing::debug!(
        operation = operation.as_str(),
        pod = %target.pod_name,
        "minting scoped Sandbox credential"
    );
    let requested_at = chrono::Utc::now();
    let issued = accounts
        .create_token_request(&name, &PostParams::default(), &request)
        .await
        .map_err(|error| backend_denied(&error))?;
    let received_at = chrono::Utc::now();
    let status = issued
        .status
        .ok_or_else(|| backend_denied(&"TokenRequest returned no status"))?;
    // Kubernetes parses the wire value into `Time`; parsing its canonical RFC
    // 3339 representation here also keeps the temporal comparison in one clock
    // type instead of relying on ordering across time-library versions.
    if status.token.is_empty()
        || !token_expiration_is_acceptable(
            &status.expiration_timestamp.0.to_string(),
            requested_at,
            received_at,
        )
    {
        return Err(backend_denied(
            &"TokenRequest returned an empty token or an unacceptable expiration",
        ));
    }

    Ok(status.token)
}

fn observed_credential_uid<K: Resource>(
    object: &K,
    name: &str,
    namespace: &str,
    lease_uid: &str,
    pod_name: &str,
    pod_uid: &str,
) -> Result<String, ()> {
    let metadata = object.meta();
    let expected_owner = pod_owner_reference(pod_name, pod_uid);
    if metadata.name.as_deref() != Some(name)
        || metadata.namespace.as_deref() != Some(namespace)
        || metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(SANDBOX_LEASE_UID_LABEL))
            .map(String::as_str)
            != Some(lease_uid)
        || metadata.owner_references.as_deref() != Some(std::slice::from_ref(&expected_owner))
    {
        return Err(());
    }

    metadata
        .uid
        .as_ref()
        .filter(|uid| !uid.is_empty())
        .cloned()
        .ok_or(())
}

fn inaccessible_or_replaced(error: &kube::Error) -> bool {
    matches!(error, kube::Error::Api(response) if matches!(response.code, 401 | 403 | 409))
}

/// Remove one exact credential object and prove its deterministic name absent.
///
/// The label only participates in provenance validation; it is never a delete
/// selector. Deletion is by the deterministic name and the UID read from that
/// exact object, and a successful DELETE is followed by another GET because
/// acceptance is not proof that asynchronous deletion has completed.
async fn cleanup_credential_object<K>(
    api: &Api<K>,
    name: &str,
    namespace: &str,
    lease_uid: &str,
    pod_name: &str,
    pod_uid: &str,
) -> CredentialCleanupOutcome
where
    K: Clone + serde::de::DeserializeOwned + std::fmt::Debug + Resource,
{
    let observed = match api.get(name).await {
        Ok(observed) => observed,
        Err(kube::Error::Api(response)) if response.code == 404 => {
            return CredentialCleanupOutcome::Clean;
        }
        Err(error) if inaccessible_or_replaced(&error) => {
            return CredentialCleanupOutcome::Quarantine;
        }
        Err(_) => return CredentialCleanupOutcome::Retry,
    };
    let observed_uid =
        match observed_credential_uid(&observed, name, namespace, lease_uid, pod_name, pod_uid) {
            Ok(uid) => uid,
            Err(()) => return CredentialCleanupOutcome::Quarantine,
        };

    let delete = DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(observed_uid.clone()),
            resource_version: None,
        }),
        ..DeleteParams::default()
    };
    match api.delete(name, &delete).await {
        Ok(_) => {}
        // A concurrent garbage collection can win between GET and DELETE.
        // Re-read below so even that race ends on an observed 404.
        Err(kube::Error::Api(response)) if response.code == 404 => {}
        Err(error) if inaccessible_or_replaced(&error) => {
            return CredentialCleanupOutcome::Quarantine;
        }
        Err(_) => return CredentialCleanupOutcome::Retry,
    }

    match api.get(name).await {
        Err(kube::Error::Api(response)) if response.code == 404 => CredentialCleanupOutcome::Clean,
        Err(error) if inaccessible_or_replaced(&error) => CredentialCleanupOutcome::Quarantine,
        Err(_) => CredentialCleanupOutcome::Retry,
        Ok(current) => {
            match observed_credential_uid(&current, name, namespace, lease_uid, pod_name, pod_uid) {
                Ok(current_uid) if current_uid == observed_uid => CredentialCleanupOutcome::Retry,
                // The name was replaced, or its provenance changed, between the
                // fenced delete and the proof read. It must never be deleted as if
                // it were the object Kobe just observed.
                Ok(_) | Err(()) => CredentialCleanupOutcome::Quarantine,
            }
        }
    }
}

/// Delete all operation credentials for one exact recorded Sandbox Pod.
///
/// RoleBindings are proven absent before any Role is touched, and every Role
/// is proven absent before any ServiceAccount is touched. Stopping on the
/// first non-clean outcome preserves that order across retries. A caller may
/// release the lease's cleanup gate only for [`CredentialCleanupOutcome::Clean`].
pub(crate) async fn cleanup_scoped_identities(
    client: &kube::Client,
    namespace: &str,
    lease_uid: &str,
    pod_name: &str,
    pod_uid: &str,
) -> CredentialCleanupOutcome {
    if namespace.is_empty() || lease_uid.is_empty() || pod_name.is_empty() || pod_uid.is_empty() {
        return CredentialCleanupOutcome::Quarantine;
    }

    let role_bindings: Api<RoleBinding> = Api::namespaced(client.clone(), namespace);
    let roles: Api<Role> = Api::namespaced(client.clone(), namespace);
    let service_accounts: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);

    for resource_kind in [
        CredentialResourceKind::RoleBinding,
        CredentialResourceKind::Role,
        CredentialResourceKind::ServiceAccount,
    ] {
        for operation in SandboxOperation::ALL {
            let name = credential_name(lease_uid, operation);
            let outcome = match resource_kind {
                CredentialResourceKind::RoleBinding => {
                    cleanup_credential_object(
                        &role_bindings,
                        &name,
                        namespace,
                        lease_uid,
                        pod_name,
                        pod_uid,
                    )
                    .await
                }
                CredentialResourceKind::Role => {
                    cleanup_credential_object(
                        &roles, &name, namespace, lease_uid, pod_name, pod_uid,
                    )
                    .await
                }
                CredentialResourceKind::ServiceAccount => {
                    cleanup_credential_object(
                        &service_accounts,
                        &name,
                        namespace,
                        lease_uid,
                        pod_name,
                        pod_uid,
                    )
                    .await
                }
            };
            if outcome != CredentialCleanupOutcome::Clean {
                return outcome;
            }
        }
    }

    CredentialCleanupOutcome::Clean
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
                .map_err(|error| backend_denied(&error))
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

    kube::Client::try_from(config).map_err(|error| backend_denied(&error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use serde_json::{Value, json};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn mock_client(server: &MockServer) -> kube::Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::testutil::mock_k8s_client(server)
    }

    fn k8s_error(code: u16) -> ResponseTemplate {
        let reason = match code {
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "NotFound",
            409 => "Conflict",
            _ => "InternalError",
        };
        ResponseTemplate::new(code).set_body_json(json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "message": reason,
            "reason": reason,
            "code": code,
        }))
    }

    fn credential_object(
        kind: &str,
        name: &str,
        uid: &str,
        owner_name: &str,
        owner_uid: &str,
    ) -> Value {
        let api_version = if kind == "ServiceAccount" {
            "v1"
        } else {
            "rbac.authorization.k8s.io/v1"
        };
        let mut object = json!({
            "apiVersion": api_version,
            "kind": kind,
            "metadata": {
                "name": name,
                "namespace": "kobe",
                "uid": uid,
                "labels": { (SANDBOX_LEASE_UID_LABEL): "lease-uid-1" },
                "ownerReferences": [{
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "name": owner_name,
                    "uid": owner_uid,
                    "controller": false,
                    "blockOwnerDeletion": true,
                }],
            },
        });
        match kind {
            "RoleBinding" => {
                object["roleRef"] = json!({
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": name,
                });
            }
            "Role" => object["rules"] = json!([]),
            "ServiceAccount" => {}
            _ => panic!("unsupported test credential kind"),
        }
        object
    }

    fn expected_identity_object(
        kind: &str,
        name: &str,
        uid: &str,
        target: &SandboxTarget,
        operation: SandboxOperation,
    ) -> Value {
        let mut object = credential_object(
            kind,
            name,
            uid,
            target.pod_name.as_str(),
            target.pod_uid.as_str(),
        );
        object["metadata"]["resourceVersion"] = json!(format!("rv-{uid}"));
        object["metadata"]["labels"]["app.kubernetes.io/managed-by"] =
            json!(crate::sandbox::KOBE_MANAGED_BY);
        match kind {
            "ServiceAccount" => object["automountServiceAccountToken"] = json!(false),
            "Role" => object["rules"] = json!(scoped_rules(target, operation)),
            "RoleBinding" => {
                object["subjects"] = json!([{
                    "kind": "ServiceAccount",
                    "name": name,
                    "namespace": target.namespace,
                }]);
            }
            _ => panic!("unsupported test credential kind"),
        }
        object
    }

    async fn mount_missing_identity_creation(
        server: &MockServer,
        target: &SandboxTarget,
        operation: SandboxOperation,
    ) {
        let name = credential_name(&target.lease_uid, operation);
        for (collection_path, kind, uid) in [
            (
                "/api/v1/namespaces/kobe/serviceaccounts",
                "ServiceAccount",
                "service-account-uid",
            ),
            (
                "/apis/rbac.authorization.k8s.io/v1/namespaces/kobe/roles",
                "Role",
                "role-uid",
            ),
            (
                "/apis/rbac.authorization.k8s.io/v1/namespaces/kobe/rolebindings",
                "RoleBinding",
                "role-binding-uid",
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("{collection_path}/{name}")))
                .respond_with(k8s_error(404))
                .expect(1)
                .mount(server)
                .await;
            Mock::given(method("POST"))
                .and(path(collection_path))
                .respond_with(
                    ResponseTemplate::new(201).set_body_json(expected_identity_object(
                        kind, &name, uid, target, operation,
                    )),
                )
                .expect(1)
                .mount(server)
                .await;
        }
    }

    #[derive(Clone)]
    struct FirstObjectThen {
        calls: Arc<AtomicUsize>,
        first: Value,
        later: Value,
    }

    impl Respond for FirstObjectThen {
        fn respond(&self, _: &Request) -> ResponseTemplate {
            let body = if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                &self.first
            } else {
                &self.later
            };
            ResponseTemplate::new(200).set_body_json(body)
        }
    }

    #[derive(Clone, Default)]
    struct DeletingCredentialApi {
        deleted: Arc<Mutex<HashSet<String>>>,
    }

    impl Respond for DeletingCredentialApi {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let request_path = request.url.path().to_string();
            if request.method.as_str() == "DELETE" {
                self.deleted.lock().unwrap().insert(request_path);
                return ResponseTemplate::new(200).set_body_json(json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Success",
                    "code": 200,
                }));
            }
            if self.deleted.lock().unwrap().contains(&request_path) {
                return k8s_error(404);
            }

            let name = request_path.rsplit('/').next().unwrap();
            let kind = if request_path.contains("/rolebindings/") {
                "RoleBinding"
            } else if request_path.contains("/roles/") {
                "Role"
            } else if request_path.contains("/serviceaccounts/") {
                "ServiceAccount"
            } else {
                panic!("unexpected credential API path {request_path}");
            };
            ResponseTemplate::new(200).set_body_json(credential_object(
                kind,
                name,
                &format!("uid-{name}"),
                "sbx-0",
                "pod-uid",
            ))
        }
    }

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
            runner_path: None,
        }
    }

    /// Applied identities and the issued token are tied to one exact Pod UID.
    ///
    /// The owner reference makes Kubernetes reap the RBAC footprint with the
    /// Pod, while the bound object reference makes an issued token invalid as
    /// soon as that exact Pod identity disappears.
    #[tokio::test]
    async fn identity_bodies_and_token_request_are_bound_to_the_exact_pod() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let target = target();
        let name = credential_name(&target.lease_uid, SandboxOperation::Exec);
        let service_account_path = format!("/api/v1/namespaces/kobe/serviceaccounts/{name}");
        mount_missing_identity_creation(&server, &target, SandboxOperation::Exec).await;

        let token_path = format!("{service_account_path}/token");
        let valid_expiry = (chrono::Utc::now()
            + chrono::Duration::seconds(TOKEN_LIFETIME_SECONDS - 1))
        .to_rfc3339();
        Mock::given(method("POST"))
            .and(path(token_path))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenRequest",
                "metadata": { "name": name, "namespace": "kobe" },
                "spec": {
                    "audiences": [],
                    "expirationSeconds": TOKEN_LIFETIME_SECONDS,
                    "boundObjectRef": {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "name": target.pod_name,
                        "uid": target.pod_uid,
                    },
                },
                "status": {
                    "expirationTimestamp": valid_expiry,
                    "token": "opaque-test-token",
                },
            })))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            mint_scoped_token(&client, &target, SandboxOperation::Exec).await,
            Ok("opaque-test-token".to_string())
        );

        let requests = server.received_requests().await.unwrap();
        let expected_owner = json!([{
            "apiVersion": "v1",
            "kind": "Pod",
            "name": "sbx-0",
            "uid": "pod-uid",
            "controller": false,
            "blockOwnerDeletion": true,
        }]);
        let creates: Vec<_> = requests
            .iter()
            .filter(|request| {
                request.method.as_str() == "POST" && !request.url.path().ends_with("/token")
            })
            .collect();
        assert_eq!(creates.len(), 3);
        for request in creates {
            let body: Value = request.body_json().unwrap();
            assert_eq!(body["metadata"]["ownerReferences"], expected_owner);
            assert_eq!(
                body["metadata"]["labels"][SANDBOX_LEASE_UID_LABEL],
                "lease-uid-1"
            );
        }
        assert!(
            requests
                .iter()
                .all(|request| request.method.as_str() != "PATCH"),
            "creating missing identities must not require force-adoption"
        );

        let token_request = requests
            .iter()
            .find(|request| request.url.path().ends_with("/token"))
            .expect("TokenRequest was issued");
        let body: Value = token_request.body_json().unwrap();
        assert_eq!(
            body["spec"]["boundObjectRef"],
            json!({
                "apiVersion": "v1",
                "kind": "Pod",
                "name": "sbx-0",
                "uid": "pod-uid",
            })
        );
    }

    /// The API server chooses the actual expiry, so the response — not merely
    /// our requested `expirationSeconds` — is the authority Kobe must bound.
    #[tokio::test]
    async fn a_token_with_an_excessive_actual_expiry_is_rejected() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let target = target();
        let name = credential_name(&target.lease_uid, SandboxOperation::Exec);
        let service_account_path = format!("/api/v1/namespaces/kobe/serviceaccounts/{name}");
        mount_missing_identity_creation(&server, &target, SandboxOperation::Exec).await;

        let excessive_expiry = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        Mock::given(method("POST"))
            .and(path(format!("{service_account_path}/token")))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenRequest",
                "metadata": { "name": name, "namespace": "kobe" },
                "spec": {
                    "audiences": [],
                    "expirationSeconds": TOKEN_LIFETIME_SECONDS,
                    "boundObjectRef": {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "name": target.pod_name,
                        "uid": target.pod_uid,
                    },
                },
                "status": {
                    "expirationTimestamp": excessive_expiry,
                    "token": "overlong-token",
                },
            })))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            mint_scoped_token(&client, &target, SandboxOperation::Exec).await,
            Err(SandboxAccessDenied::Backend)
        );
    }

    /// A deterministic name is not ownership. A foreign object at that name
    /// must be rejected before server-side apply can adopt or mutate it.
    #[tokio::test]
    async fn a_foreign_same_named_identity_is_rejected_without_patch() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let target = target();
        let name = credential_name(&target.lease_uid, SandboxOperation::Exec);
        let service_account_path = format!("/api/v1/namespaces/kobe/serviceaccounts/{name}");
        Mock::given(method("GET"))
            .and(path(&service_account_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(credential_object(
                "ServiceAccount",
                &name,
                "foreign-service-account-uid",
                "somebody-elses-pod",
                "foreign-pod-uid",
            )))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            mint_scoped_token(&client, &target, SandboxOperation::Exec).await,
            Err(SandboxAccessDenied::Backend)
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method.as_str(), "GET");
        assert_eq!(requests[0].url.path(), service_account_path);
    }

    #[tokio::test]
    async fn a_same_named_identity_with_the_wrong_lease_label_is_rejected_without_patch() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let target = target();
        let name = credential_name(&target.lease_uid, SandboxOperation::Exec);
        let service_account_path = format!("/api/v1/namespaces/kobe/serviceaccounts/{name}");
        let mut foreign = credential_object(
            "ServiceAccount",
            &name,
            "foreign-service-account-uid",
            &target.pod_name,
            &target.pod_uid,
        );
        foreign["metadata"]["labels"][SANDBOX_LEASE_UID_LABEL] = json!("another-lease-uid");
        Mock::given(method("GET"))
            .and(path(&service_account_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(foreign))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            mint_scoped_token(&client, &target, SandboxOperation::Exec).await,
            Err(SandboxAccessDenied::Backend)
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method.as_str(), "GET");
        assert_eq!(requests[0].url.path(), service_account_path);
    }

    /// Owned drift is repaired, but only through a patch fenced to the UID,
    /// resourceVersion, lease label and singular Pod owner read just before it.
    #[tokio::test]
    async fn owned_role_drift_is_converged_with_atomic_provenance_fences() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let target = target();
        let operation = SandboxOperation::Exec;
        let name = credential_name(&target.lease_uid, operation);
        let service_account_path = format!("/api/v1/namespaces/kobe/serviceaccounts/{name}");
        let role_path = format!("/apis/rbac.authorization.k8s.io/v1/namespaces/kobe/roles/{name}");
        let role_binding_path =
            format!("/apis/rbac.authorization.k8s.io/v1/namespaces/kobe/rolebindings/{name}");

        Mock::given(method("GET"))
            .and(path(&service_account_path))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(expected_identity_object(
                    "ServiceAccount",
                    &name,
                    "service-account-uid",
                    &target,
                    operation,
                )),
            )
            .expect(1)
            .mount(&server)
            .await;

        let mut drifted_role =
            expected_identity_object("Role", &name, "role-uid", &target, operation);
        drifted_role["rules"] = json!([{
            "apiGroups": [""],
            "resources": ["pods/exec"],
            "verbs": ["get"],
        }]);
        let expected_role = expected_identity_object("Role", &name, "role-uid", &target, operation);
        Mock::given(method("GET"))
            .and(path(&role_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(drifted_role))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(&role_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected_role))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path(&role_binding_path))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(expected_identity_object(
                    "RoleBinding",
                    &name,
                    "role-binding-uid",
                    &target,
                    operation,
                )),
            )
            .expect(1)
            .mount(&server)
            .await;

        let valid_expiry = (chrono::Utc::now()
            + chrono::Duration::seconds(TOKEN_LIFETIME_SECONDS - 1))
        .to_rfc3339();
        Mock::given(method("POST"))
            .and(path(format!("{service_account_path}/token")))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenRequest",
                "metadata": { "name": name, "namespace": "kobe" },
                "spec": {
                    "audiences": [],
                    "expirationSeconds": TOKEN_LIFETIME_SECONDS,
                    "boundObjectRef": {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "name": target.pod_name,
                        "uid": target.pod_uid,
                    },
                },
                "status": {
                    "expirationTimestamp": valid_expiry,
                    "token": "opaque-test-token",
                },
            })))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            mint_scoped_token(&client, &target, operation).await,
            Ok("opaque-test-token".to_string())
        );

        let requests = server.received_requests().await.unwrap();
        let patches: Vec<_> = requests
            .iter()
            .filter(|request| request.method.as_str() == "PATCH")
            .collect();
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].url.path(), role_path);
        let body: Value = patches[0].body_json().unwrap();
        let operations = body.as_array().expect("JSON Patch operation array");
        assert!(operations.iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/metadata/uid"
                && operation["value"] == "role-uid"
        }));
        assert!(operations.iter().any(|operation| {
            operation["op"] == "test"
                && operation["path"] == "/metadata/resourceVersion"
                && operation["value"] == "rv-role-uid"
        }));
        let rules = operations
            .iter()
            .find(|operation| operation["path"] == "/rules")
            .expect("Role rules convergence operation");
        assert_eq!(rules["value"], json!(scoped_rules(&target, operation)));
    }

    /// Cleanup removes grants before their identities and proves every name
    /// absent. A second run observes only 404s and remains clean.
    #[tokio::test]
    async fn cleanup_is_ordered_uid_fenced_and_idempotent_on_404() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let responder = DeletingCredentialApi::default();
        for request_method in ["GET", "DELETE"] {
            Mock::given(method(request_method))
                .respond_with(responder.clone())
                .mount(&server)
                .await;
        }

        assert_eq!(
            cleanup_scoped_identities(&client, "kobe", "lease-uid-1", "sbx-0", "pod-uid").await,
            CredentialCleanupOutcome::Clean
        );
        assert_eq!(
            cleanup_scoped_identities(&client, "kobe", "lease-uid-1", "sbx-0", "pod-uid").await,
            CredentialCleanupOutcome::Clean
        );

        let requests = server.received_requests().await.unwrap();
        let mut expected_first_run = Vec::new();
        for resource_path in [
            "/apis/rbac.authorization.k8s.io/v1/namespaces/kobe/rolebindings",
            "/apis/rbac.authorization.k8s.io/v1/namespaces/kobe/roles",
            "/api/v1/namespaces/kobe/serviceaccounts",
        ] {
            for operation in SandboxOperation::ALL {
                let object_path = format!(
                    "{resource_path}/{}",
                    credential_name("lease-uid-1", operation)
                );
                expected_first_run.extend([
                    ("GET".to_string(), object_path.clone()),
                    ("DELETE".to_string(), object_path.clone()),
                    ("GET".to_string(), object_path),
                ]);
            }
        }
        let first_run: Vec<_> = requests[..expected_first_run.len()]
            .iter()
            .map(|request| {
                (
                    request.method.as_str().to_string(),
                    request.url.path().to_string(),
                )
            })
            .collect();
        assert_eq!(first_run, expected_first_run);

        for request in requests
            .iter()
            .take(expected_first_run.len())
            .filter(|request| request.method.as_str() == "DELETE")
        {
            assert!(
                !request
                    .url
                    .query_pairs()
                    .any(|(key, _)| key == "labelSelector"),
                "credential cleanup must never turn the lease label into a delete selector"
            );
            let name = request.url.path().rsplit('/').next().unwrap();
            let body: Value = request.body_json().unwrap();
            assert_eq!(body["preconditions"]["uid"], format!("uid-{name}"));
        }

        let second_run = &requests[expected_first_run.len()..];
        assert_eq!(second_run.len(), SandboxOperation::ALL.len() * 3);
        assert!(
            second_run
                .iter()
                .all(|request| request.method.as_str() == "GET"),
            "already-absent credentials require no delete"
        );
    }

    /// Authorization failures make absence unverifiable and therefore require
    /// quarantine; a transient server failure instead remains retryable.
    #[tokio::test]
    async fn cleanup_distinguishes_retry_from_unauthorized_or_forbidden() {
        for code in [401, 403] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(k8s_error(code))
                .expect(1)
                .mount(&server)
                .await;
            assert_eq!(
                cleanup_scoped_identities(
                    &mock_client(&server),
                    "kobe",
                    "lease-uid-1",
                    "sbx-0",
                    "pod-uid"
                )
                .await,
                CredentialCleanupOutcome::Quarantine,
                "HTTP {code} must not be mistaken for absence"
            );
        }

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(k8s_error(500))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            cleanup_scoped_identities(
                &mock_client(&server),
                "kobe",
                "lease-uid-1",
                "sbx-0",
                "pod-uid"
            )
            .await,
            CredentialCleanupOutcome::Retry
        );
    }

    /// A deterministic name is not authority. Foreign provenance or a UID
    /// replacement is quarantined and never followed by a delete of the new
    /// object.
    #[tokio::test]
    async fn cleanup_quarantines_foreign_owner_and_name_reuse() {
        let name = credential_name("lease-uid-1", SandboxOperation::Logs);
        let role_binding_path =
            format!("/apis/rbac.authorization.k8s.io/v1/namespaces/kobe/rolebindings/{name}");

        let foreign_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(&role_binding_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(credential_object(
                "RoleBinding",
                &name,
                "foreign-object-uid",
                "somebody-elses-pod",
                "foreign-pod-uid",
            )))
            .expect(1)
            .mount(&foreign_server)
            .await;
        assert_eq!(
            cleanup_scoped_identities(
                &mock_client(&foreign_server),
                "kobe",
                "lease-uid-1",
                "sbx-0",
                "pod-uid"
            )
            .await,
            CredentialCleanupOutcome::Quarantine
        );
        assert!(
            foreign_server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() == "GET"),
            "a foreign owner must never be deleted"
        );

        let replacement_server = MockServer::start().await;
        let get_calls = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path(&role_binding_path))
            .respond_with(FirstObjectThen {
                calls: get_calls,
                first: credential_object(
                    "RoleBinding",
                    &name,
                    "old-object-uid",
                    "sbx-0",
                    "pod-uid",
                ),
                later: credential_object(
                    "RoleBinding",
                    &name,
                    "replacement-object-uid",
                    "sbx-0",
                    "pod-uid",
                ),
            })
            .expect(2)
            .mount(&replacement_server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(&role_binding_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(credential_object(
                "RoleBinding",
                &name,
                "old-object-uid",
                "sbx-0",
                "pod-uid",
            )))
            .expect(1)
            .mount(&replacement_server)
            .await;
        assert_eq!(
            cleanup_scoped_identities(
                &mock_client(&replacement_server),
                "kobe",
                "lease-uid-1",
                "sbx-0",
                "pod-uid"
            )
            .await,
            CredentialCleanupOutcome::Quarantine
        );
        let requests = replacement_server.received_requests().await.unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.method.as_str())
                .collect::<Vec<_>>(),
            vec!["GET", "DELETE", "GET"]
        );
        let delete: Value = requests[1].body_json().unwrap();
        assert_eq!(delete["preconditions"]["uid"], "old-object-uid");
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
            !logs.iter().any(|granted| granted.contains("exec")
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

    /// The verb granted must be the verb the client's request actually asks
    /// for.
    ///
    /// REVIEW FINDING (expected to fail). `scoped_rules` grants
    /// `pods/exec: create` and `pods/portforward: create` — the verbs
    /// `kubectl` needs, because `kubectl` opens these over SPDY with a POST.
    /// Kobe does not: it is built with kube-rs's `ws` feature, and
    /// `kube_core::Request::{exec, attach, portforward}` all issue an HTTP
    /// **GET** WebSocket upgrade. The apiserver derives the RBAC verb from the
    /// HTTP method, so those requests authorize as `get`, not `create`.
    ///
    /// Every exec, attach and port-forward therefore 403s under the credential
    /// this module exists to mint, and the caller sees `TargetError` on a
    /// socket that upgraded cleanly. The same mistake is in
    /// `charts/kobe/templates/rbac.yaml:87-89`, which is what the readiness
    /// canary runs under — so a management-placement lease's canary can never
    /// pass either.
    ///
    /// The existing tests here assert the verb set is *narrow* and never that
    /// it is *correct*, which is exactly why this is invisible to CI.
    #[test]
    fn the_minted_role_grants_the_verb_the_request_actually_uses() {
        use kube::api::AttachParams;

        // The verb the apiserver derives from a request's HTTP method.
        let rbac_verb = |method: &http::Method| match *method {
            http::Method::GET => "get",
            http::Method::POST => "create",
            http::Method::PUT => "update",
            http::Method::PATCH => "patch",
            http::Method::DELETE => "delete",
            ref other => panic!("unexpected method {other}"),
        };

        let request = kube::core::Request::new("/api/v1/namespaces/kobe/pods");
        let params = AttachParams::default().container("agent");
        let issued = [
            (
                "pods/exec",
                SandboxOperation::Exec,
                request
                    .exec("sbx-0", vec!["/agent", "status"], &params)
                    .unwrap(),
            ),
            (
                "pods/portforward",
                SandboxOperation::PortForward,
                request.portforward("sbx-0", &[3000]).unwrap(),
            ),
        ];

        for (subresource, operation, actual) in issued {
            let required = rbac_verb(actual.method());
            let granted: Vec<&str> = scoped_rules(&target(), operation)
                .iter()
                .filter(|rule| {
                    rule.resources
                        .as_ref()
                        .is_some_and(|resources| resources.iter().any(|r| r == subresource))
                })
                .flat_map(|rule| rule.verbs.clone())
                .map(|verb| Box::leak(verb.into_boxed_str()) as &str)
                .collect();
            assert!(
                granted.contains(&required),
                "{subresource} is issued as {} so it authorizes as {required:?}, \
                 but the minted Role grants {granted:?}",
                actual.method()
            );
        }
    }

    /// The chart must grant the operator every verb its own exec can need.
    ///
    /// Same root cause as
    /// [`the_minted_role_grants_the_verb_the_request_actually_uses`], one layer
    /// out. The readiness canary at `controllers/sandbox_canary.rs:206` execs
    /// with the **operator's own** client for management-placement pools, so it
    /// is governed by `charts/kobe/templates/rbac.yaml`. Which verb the
    /// apiserver demands depends on its version: pre-1.35 authorizes the GET
    /// WebSocket upgrade as `get`, while 1.35's
    /// `AuthorizePodWebsocketUpgradeCreatePermission` (default on) demands
    /// `create` for any connection upgrade. Granting only one verb 403s the
    /// canary on the other side of that boundary and fail-closes certification
    /// at `CleanupBlocked` — proven live against kind v1.36.
    ///
    /// A missing verb is a runtime 403 no unit test sees; asserting it against
    /// the chart text is the only place it can be caught before a cluster.
    #[test]
    fn the_chart_grants_the_verb_the_readiness_canary_actually_uses() {
        let chart = include_str!("../../charts/kobe/templates/rbac.yaml");
        // The rule block that names pods/exec, up to its own `verbs:` line, so
        // a neighbouring rule's verbs cannot satisfy this by accident.
        let block = chart
            .split("- apiGroups:")
            .find(|block| block.contains("\"pods/exec\""))
            .expect("the chart grants pods/exec");
        let verbs = block
            .lines()
            .find(|line| line.trim_start().starts_with("verbs:"))
            .expect("the pods/exec rule declares verbs");
        assert!(
            verbs.contains("\"get\""),
            "kube-rs upgrades pods/exec over a GET, which pre-1.35 apiservers \
             authorize as `get`, but the chart grants {}",
            verbs.trim()
        );
        assert!(
            verbs.contains("\"create\""),
            "1.35's AuthorizePodWebsocketUpgradeCreatePermission authorizes \
             every connection upgrade as `create`, but the chart grants {}",
            verbs.trim()
        );
    }

    /// Bare attach must be granted the subresource it actually calls.
    ///
    /// REVIEW FINDING (expected to fail). `sandbox_attach` prepares its upgrade
    /// with `SandboxOperation::Exec` and then branches: with a `command` it
    /// calls `pods.exec()`, without one it calls `pods.attach()`
    /// (`src/api/sandbox.rs:651-654`). `SandboxOperation` has no `Attach`
    /// variant and `Exec.subresources()` never mentions `pods/attach`, so the
    /// minted credential cannot perform the second branch at all — `kobe
    /// sandbox attach` with no command is a guaranteed 403 reported to the
    /// caller as an opaque `TargetError`.
    #[test]
    fn the_attach_path_can_address_the_subresource_it_calls() {
        // As written by the reviewer this asserted that `Exec` grants
        // `pods/attach` — a fix shape, not the property. Widening the exec
        // credential is exactly the "operations borrow each other's authority"
        // that `operations_do_not_borrow_each_others_authority` forbids, so
        // attach got its own operation instead. The PROPERTY the reviewer was
        // protecting is preserved and asserted here: whatever credential the
        // attach path mints must be able to address the subresource it calls.
        let resources = |operation| -> Vec<String> {
            scoped_rules(&target(), operation)
                .iter()
                .flat_map(|rule| rule.resources.clone().unwrap_or_default())
                .collect()
        };

        let attach = resources(SandboxOperation::Attach);
        assert!(
            attach.iter().any(|resource| resource == "pods/attach"),
            "a bare attach calls pods/attach; its credential grants only {attach:?}"
        );

        // And least privilege survives the fix: exec must NOT gain attach.
        let exec = resources(SandboxOperation::Exec);
        assert!(
            !exec.iter().any(|resource| resource == "pods/attach"),
            "granting attach to the exec credential would be the wrong repair"
        );
    }

    /// Credential objects are named by lease UID, not lease name.
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
