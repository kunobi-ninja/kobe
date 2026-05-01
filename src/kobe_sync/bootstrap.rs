//! One-shot RBAC bootstrap on the virtual apiserver.
//!
//! The vkobe virtual apiserver does not run the standard RBAC bootstrap
//! that creates `system:kube-controller-manager`, `system:basic-user`,
//! `system:discovery`, `system:public-info-viewer`, etc. — every watcher
//! authenticating as one of those subjects therefore dies on its
//! initial list with `clusterrole "..." not found`.
//!
//! Rather than depend on those built-in roles existing (or paper over
//! the whole problem with `system:masters`), kobe-sync installs its
//! own dedicated, least-privilege RBAC at startup:
//!
//! - **`kobe-sync` ClusterRole** — exactly the verbs and resources the
//!   syncers need on the virtual apiserver:
//!     * read every namespaced workload kind the syncers watch
//!       (Pod, Service, ConfigMap, Endpoints, Secret, PVC,
//!       NetworkPolicy, Ingress)
//!     * write to Pod `status` + `binding` subresources for the
//!       StatusSyncer (it patches status and binds virtual pods to
//!       fake nodes)
//!     * full lifecycle on Node so FakeNodeSyncer can mirror host
//!       nodes into the virtual cluster
//! - **`kobe-sync` ClusterRoleBinding** — binds User `system:kobe-sync`
//!   to that role.
//!
//! Both are server-side applied with `field_manager=kobe-sync`, which
//! is idempotent: running this twice (because the pod restarted, or a
//! cert rotated) is a no-op when the desired state already matches.
//!
//! This bootstrap path is the **only** time `system:masters` is held —
//! the bootstrap kube client is built from a one-shot kubeconfig
//! issued by [`crate::pki::generate_sync_bootstrap_kubeconfig`], the
//! two objects are applied, and the client is dropped. From that point
//! on the runtime kobe-sync identity is bound to the role we just
//! installed and `system:masters` is gone from process memory.

use anyhow::{Context, Result};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, PolicyRule, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, Patch, PatchParams};
use tracing::info;

/// User name (cert CN) bound to the `kobe-sync` ClusterRole.
pub const KOBE_SYNC_USER: &str = "system:kobe-sync";

/// Name of the ClusterRole + ClusterRoleBinding installed by [`ensure_rbac`].
pub const KOBE_SYNC_ROLE: &str = "kobe-sync";

const FIELD_MANAGER: &str = "kobe-sync";

/// Apply the `kobe-sync` ClusterRole and ClusterRoleBinding to the virtual
/// apiserver via server-side apply. Safe to call repeatedly.
///
/// `client` must authenticate with sufficient privileges to create RBAC
/// objects — in practice the bootstrap kubeconfig (CN
/// `system:kobe-sync-bootstrap`, O `system:masters`).
pub async fn ensure_rbac(client: &kube::Client) -> Result<()> {
    let role = build_cluster_role();
    let binding = build_cluster_role_binding();

    let roles: Api<ClusterRole> = Api::all(client.clone());
    let bindings: Api<ClusterRoleBinding> = Api::all(client.clone());

    let pp = PatchParams::apply(FIELD_MANAGER).force();

    roles
        .patch(KOBE_SYNC_ROLE, &pp, &Patch::Apply(&role))
        .await
        .with_context(|| format!("Failed to apply ClusterRole `{KOBE_SYNC_ROLE}`"))?;
    info!(role = KOBE_SYNC_ROLE, "Applied kobe-sync ClusterRole");

    bindings
        .patch(KOBE_SYNC_ROLE, &pp, &Patch::Apply(&binding))
        .await
        .with_context(|| format!("Failed to apply ClusterRoleBinding `{KOBE_SYNC_ROLE}`"))?;
    info!(
        binding = KOBE_SYNC_ROLE,
        user = KOBE_SYNC_USER,
        "Applied kobe-sync ClusterRoleBinding"
    );

    Ok(())
}

/// Construct the `kobe-sync` ClusterRole with least-privilege rules
/// matching exactly what each syncer does against the virtual apiserver.
///
/// Public so unit tests can assert the rule set is what we expect.
pub fn build_cluster_role() -> ClusterRole {
    let s = |x: &str| x.to_string();
    let rules = vec![
        // Read-only watchers on every workload kind the v->h syncers
        // project to the host cluster. (Each item maps to exactly one
        // syncer in `src/kobe_sync/syncer/*.rs`.)
        PolicyRule {
            api_groups: Some(vec![s("")]),
            resources: Some(vec![
                s("pods"),
                s("services"),
                s("configmaps"),
                s("endpoints"),
                s("secrets"),
                s("persistentvolumeclaims"),
            ]),
            verbs: vec![s("get"), s("list"), s("watch")],
            ..Default::default()
        },
        PolicyRule {
            api_groups: Some(vec![s("networking.k8s.io")]),
            resources: Some(vec![s("networkpolicies"), s("ingresses")]),
            verbs: vec![s("get"), s("list"), s("watch")],
            ..Default::default()
        },
        // ServiceAccountSyncer materializes virtual SAs as host SAs
        // so projected pods that reference custom SAs (flux, etc.)
        // pass host-apiserver admission. Needs full CRUD because the
        // virtual side may create / patch / delete SAs at any time.
        PolicyRule {
            api_groups: Some(vec![s("")]),
            resources: Some(vec![s("serviceaccounts")]),
            verbs: vec![
                s("get"),
                s("list"),
                s("watch"),
                s("create"),
                s("update"),
                s("patch"),
                s("delete"),
            ],
            ..Default::default()
        },
        // StatusSyncer patches the virtual Pod's status subresource (so
        // the user sees real Pending/Running/etc.) and binds virtual
        // pods to fake nodes (no scheduler runs inside the virtual
        // cluster).
        PolicyRule {
            api_groups: Some(vec![s("")]),
            resources: Some(vec![s("pods/status"), s("pods/binding")]),
            verbs: vec![s("get"), s("patch"), s("update"), s("create")],
            ..Default::default()
        },
        // FakeNodeSyncer mirrors host nodes into the virtual cluster as
        // fake Node objects so guest pods can be bound to a node-name
        // that actually exists from the apiserver's point of view.
        PolicyRule {
            api_groups: Some(vec![s("")]),
            resources: Some(vec![s("nodes")]),
            verbs: vec![
                s("get"),
                s("list"),
                s("watch"),
                s("create"),
                s("update"),
                s("patch"),
                s("delete"),
            ],
            ..Default::default()
        },
        PolicyRule {
            api_groups: Some(vec![s("")]),
            resources: Some(vec![s("nodes/status")]),
            verbs: vec![s("get"), s("patch"), s("update")],
            ..Default::default()
        },
    ];

    ClusterRole {
        metadata: ObjectMeta {
            name: Some(KOBE_SYNC_ROLE.to_string()),
            ..Default::default()
        },
        rules: Some(rules),
        ..Default::default()
    }
}

/// Construct the `kobe-sync` ClusterRoleBinding that links the
/// `system:kobe-sync` User identity to the [`build_cluster_role`] role.
///
/// Public for unit tests.
pub fn build_cluster_role_binding() -> ClusterRoleBinding {
    ClusterRoleBinding {
        metadata: ObjectMeta {
            name: Some(KOBE_SYNC_ROLE.to_string()),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "ClusterRole".to_string(),
            name: KOBE_SYNC_ROLE.to_string(),
        },
        subjects: Some(vec![Subject {
            api_group: Some("rbac.authorization.k8s.io".to_string()),
            kind: "User".to_string(),
            name: KOBE_SYNC_USER.to_string(),
            ..Default::default()
        }]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ClusterRoleBinding must point at the same name + role as the
    /// constants we hand to the kobe-sync runtime kubeconfig generator.
    /// If anyone renames one without renaming the other, kobe-sync's
    /// runtime client gets 403 from the virtual apiserver and the pool
    /// recycles — same failure mode as the bug this whole change exists
    /// to fix.
    #[test]
    fn binding_targets_role_and_user_constants() {
        let binding = build_cluster_role_binding();

        assert_eq!(binding.role_ref.kind, "ClusterRole");
        assert_eq!(binding.role_ref.name, KOBE_SYNC_ROLE);

        let subjects = binding.subjects.as_deref().unwrap_or(&[]);
        assert_eq!(
            subjects.len(),
            1,
            "binding should target exactly one subject"
        );
        let s = &subjects[0];
        assert_eq!(s.kind, "User");
        assert_eq!(s.name, KOBE_SYNC_USER);
        assert_eq!(s.api_group.as_deref(), Some("rbac.authorization.k8s.io"));
    }

    /// Lock the rule set down to exactly what kobe-sync actually uses.
    /// Adding scope here is intentional — but it should be intentional;
    /// the test fails so the reviewer notices instead of silent privilege
    /// creep.
    #[test]
    fn cluster_role_grants_exactly_the_documented_rules() {
        let role = build_cluster_role();
        let rules = role.rules.unwrap_or_default();

        let mut found = std::collections::BTreeSet::new();
        for r in &rules {
            for grp in r.api_groups.clone().unwrap_or_default() {
                for res in r.resources.clone().unwrap_or_default() {
                    for verb in &r.verbs {
                        found.insert(format!("{grp}/{res}:{verb}"));
                    }
                }
            }
        }

        // Exactly these (verb, group/resource) tuples must be granted.
        // Any drift fails the test on purpose.
        let expected: &[&str] = &[
            // Read-only watchers (core)
            "/pods:get",
            "/pods:list",
            "/pods:watch",
            "/services:get",
            "/services:list",
            "/services:watch",
            "/configmaps:get",
            "/configmaps:list",
            "/configmaps:watch",
            "/endpoints:get",
            "/endpoints:list",
            "/endpoints:watch",
            "/secrets:get",
            "/secrets:list",
            "/secrets:watch",
            "/persistentvolumeclaims:get",
            "/persistentvolumeclaims:list",
            "/persistentvolumeclaims:watch",
            // Read-only watchers (networking.k8s.io)
            "networking.k8s.io/networkpolicies:get",
            "networking.k8s.io/networkpolicies:list",
            "networking.k8s.io/networkpolicies:watch",
            "networking.k8s.io/ingresses:get",
            "networking.k8s.io/ingresses:list",
            "networking.k8s.io/ingresses:watch",
            // ServiceAccountSyncer (full CRUD)
            "/serviceaccounts:get",
            "/serviceaccounts:list",
            "/serviceaccounts:watch",
            "/serviceaccounts:create",
            "/serviceaccounts:update",
            "/serviceaccounts:patch",
            "/serviceaccounts:delete",
            // StatusSyncer subresources
            "/pods/status:get",
            "/pods/status:patch",
            "/pods/status:update",
            "/pods/status:create",
            "/pods/binding:get",
            "/pods/binding:patch",
            "/pods/binding:update",
            "/pods/binding:create",
            // FakeNodeSyncer
            "/nodes:get",
            "/nodes:list",
            "/nodes:watch",
            "/nodes:create",
            "/nodes:update",
            "/nodes:patch",
            "/nodes:delete",
            "/nodes/status:get",
            "/nodes/status:patch",
            "/nodes/status:update",
        ];

        let expected: std::collections::BTreeSet<String> =
            expected.iter().map(|s| s.to_string()).collect();

        let extra: Vec<&String> = found.difference(&expected).collect();
        let missing: Vec<&String> = expected.difference(&found).collect();

        assert!(
            extra.is_empty() && missing.is_empty(),
            "kobe-sync ClusterRole rules drifted from documented set.\n\
             Extra (delete from role or add to expected): {extra:?}\n\
             Missing (add back to role): {missing:?}"
        );
    }

    /// Names + the subject User name + field manager are the three
    /// strings that have to agree across the bootstrap module, the
    /// runtime cert generator, and any operator code that audits this
    /// RBAC. Pin them.
    #[test]
    fn names_match_documented_constants() {
        assert_eq!(KOBE_SYNC_ROLE, "kobe-sync");
        assert_eq!(KOBE_SYNC_USER, "system:kobe-sync");
        assert_eq!(FIELD_MANAGER, "kobe-sync");
        assert_eq!(
            build_cluster_role().metadata.name.as_deref(),
            Some(KOBE_SYNC_ROLE)
        );
        assert_eq!(
            build_cluster_role_binding().metadata.name.as_deref(),
            Some(KOBE_SYNC_ROLE)
        );
    }
}
