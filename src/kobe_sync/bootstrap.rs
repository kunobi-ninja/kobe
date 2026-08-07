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

    // ── Privilege containment ─────────────────────────────────────────

    /// The whole point of this module is to avoid running kobe-sync as
    /// `system:masters`. A wildcard anywhere in the role would quietly
    /// give it back cluster-admin-equivalent reach on the virtual
    /// apiserver, so reject `*` in every position.
    #[test]
    fn cluster_role_contains_no_wildcards() {
        for rule in build_cluster_role().rules.unwrap_or_default() {
            assert!(
                !rule.verbs.iter().any(|v| v == "*"),
                "wildcard verb in rule: {rule:?}"
            );
            assert!(
                !rule
                    .resources
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .any(|r| r == "*"),
                "wildcard resource in rule: {rule:?}"
            );
            assert!(
                !rule
                    .api_groups
                    .clone()
                    .unwrap_or_default()
                    .iter()
                    .any(|g| g == "*"),
                "wildcard apiGroup in rule: {rule:?}"
            );
            assert!(
                rule.resource_names.is_none(),
                "resourceNames are not used by kobe-sync; an entry here would silently \
                 narrow a rule the syncers rely on: {rule:?}"
            );
        }
    }

    /// Secrets are watched (the SecretSyncer projects them to the host)
    /// but never written back to the virtual apiserver. Granting write
    /// here would let a compromised kobe-sync mint credentials inside a
    /// leased cluster. Same for the other read-only watch targets.
    #[test]
    fn read_only_watch_targets_are_granted_no_write_verbs() {
        const READ_ONLY: &[&str] = &[
            "pods",
            "services",
            "configmaps",
            "endpoints",
            "secrets",
            "persistentvolumeclaims",
            "networkpolicies",
            "ingresses",
        ];
        const WRITE_VERBS: &[&str] = &[
            "create",
            "update",
            "patch",
            "delete",
            "deletecollection",
            "*",
        ];

        for rule in build_cluster_role().rules.unwrap_or_default() {
            let resources = rule.resources.clone().unwrap_or_default();
            for res in &resources {
                if !READ_ONLY.contains(&res.as_str()) {
                    continue;
                }
                for verb in &rule.verbs {
                    assert!(
                        !WRITE_VERBS.contains(&verb.as_str()),
                        "`{res}` is a read-only watch target but the role grants `{verb}`"
                    );
                }
            }
        }
    }

    /// ClusterRole and ClusterRoleBinding are cluster-scoped. A stray
    /// namespace in `metadata` would make the server-side apply in
    /// [`ensure_rbac`] target a namespaced path that does not exist.
    #[test]
    fn rbac_objects_are_cluster_scoped() {
        assert!(build_cluster_role().metadata.namespace.is_none());
        assert!(build_cluster_role_binding().metadata.namespace.is_none());
        assert_eq!(
            build_cluster_role_binding().role_ref.api_group,
            "rbac.authorization.k8s.io"
        );
    }

    // ── ensure_rbac against a fake apiserver ──────────────────────────

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(server: &MockServer) -> kube::Client {
        crate::kobe_sync::testkit::mock_client(server)
    }

    const ROLE_PATH: &str = "/apis/rbac.authorization.k8s.io/v1/clusterroles/kobe-sync";
    const BINDING_PATH: &str = "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/kobe-sync";

    /// Both applies succeed, each echoing back the object it was sent —
    /// which is what a real apiserver does for a server-side apply.
    async fn mount_happy_path(server: &MockServer) {
        Mock::given(method("PATCH"))
            .and(path(ROLE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(build_cluster_role()))
            .mount(server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(BINDING_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(build_cluster_role_binding()))
            .mount(server)
            .await;
    }

    /// `ensure_rbac` must hit exactly the two cluster-scoped RBAC
    /// endpoints named after [`KOBE_SYNC_ROLE`], and nothing else — the
    /// bootstrap client holds `system:masters`, so every extra call it
    /// makes is privileged.
    #[tokio::test]
    async fn ensure_rbac_applies_exactly_the_role_and_the_binding() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path(ROLE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(build_cluster_role()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(BINDING_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(build_cluster_role_binding()))
            .expect(1)
            .mount(&server)
            .await;

        ensure_rbac(&client(&server)).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 2, "no other apiserver calls may be made");
        assert_eq!(reqs[0].url.path(), ROLE_PATH);
        assert_eq!(
            reqs[1].url.path(),
            BINDING_PATH,
            "the role must be applied BEFORE the binding that references it"
        );
    }

    /// The two objects go up as **server-side apply** (not a merge
    /// patch) under the `kobe-sync` field manager, with `force` set.
    /// Without `force`, a rerun after a kobe upgrade that changes the
    /// rule set fails with a field-manager conflict and the pod
    /// crash-loops; without the apply content-type the apiserver
    /// interprets the body as a merge patch and never prunes removed
    /// rules.
    #[tokio::test]
    async fn ensure_rbac_uses_forced_server_side_apply_as_kobe_sync() {
        let server = MockServer::start().await;
        mount_happy_path(&server).await;

        ensure_rbac(&client(&server)).await.unwrap();

        for req in server.received_requests().await.unwrap() {
            let query: std::collections::HashMap<_, _> = req.url.query_pairs().collect();
            assert_eq!(
                query.get("fieldManager").map(|v| v.as_ref()),
                Some(FIELD_MANAGER),
                "field manager must be `{FIELD_MANAGER}`; query was {:?}",
                req.url.query()
            );
            assert_eq!(
                query.get("force").map(|v| v.as_ref()),
                Some("true"),
                "apply must be forced; query was {:?}",
                req.url.query()
            );

            let ct = req
                .headers
                .get("content-type")
                .expect("content-type must be set")
                .to_str()
                .unwrap();
            assert!(
                ct.starts_with("application/apply-patch"),
                "must be a server-side apply patch, got `{ct}`"
            );
        }
    }

    /// Server-side apply is rejected by the apiserver unless the body
    /// carries `apiVersion` and `kind`. The typed k8s-openapi structs
    /// supply them; a refactor to a hand-rolled JSON body that dropped
    /// either would fail at runtime only, inside a bootstrap path that
    /// runs before any syncer starts.
    #[tokio::test]
    async fn ensure_rbac_bodies_carry_api_version_and_kind() {
        let server = MockServer::start().await;
        mount_happy_path(&server).await;

        ensure_rbac(&client(&server)).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let role: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(role["apiVersion"], "rbac.authorization.k8s.io/v1");
        assert_eq!(role["kind"], "ClusterRole");
        assert_eq!(role["metadata"]["name"], KOBE_SYNC_ROLE);

        let binding: serde_json::Value = serde_json::from_slice(&reqs[1].body).unwrap();
        assert_eq!(binding["apiVersion"], "rbac.authorization.k8s.io/v1");
        assert_eq!(binding["kind"], "ClusterRoleBinding");
        assert_eq!(binding["subjects"][0]["name"], KOBE_SYNC_USER);
        assert_eq!(binding["roleRef"]["name"], KOBE_SYNC_ROLE);
    }

    /// If the ClusterRole apply fails, the binding must NOT be applied:
    /// a binding pointing at a role that does not exist grants nothing,
    /// so kobe-sync would start up and 403 on its first list with a
    /// confusing "forbidden" instead of the actual bootstrap error. The
    /// error also has to name the object that failed.
    #[tokio::test]
    async fn ensure_rbac_aborts_before_the_binding_when_the_role_apply_fails() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path(ROLE_PATH))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "message": "clusterroles.rbac.authorization.k8s.io is forbidden",
                "reason": "Forbidden",
                "code": 403,
            })))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(BINDING_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(build_cluster_role_binding()))
            .expect(0)
            .mount(&server)
            .await;

        let err = ensure_rbac(&client(&server)).await.unwrap_err();
        assert!(
            err.to_string().contains("ClusterRole `kobe-sync`"),
            "error must name the failing object, got: {err}"
        );

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1, "binding must not be attempted");
    }

    /// A failure on the binding is surfaced too — it is the half that
    /// actually grants the permissions, so swallowing it would leave a
    /// role nobody is bound to and kobe-sync 403ing at runtime.
    #[tokio::test]
    async fn ensure_rbac_surfaces_a_binding_failure() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path(ROLE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(build_cluster_role()))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(BINDING_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "message": "etcdserver: request timed out",
                "code": 500,
            })))
            .mount(&server)
            .await;

        let err = ensure_rbac(&client(&server)).await.unwrap_err();
        assert!(
            err.to_string().contains("ClusterRoleBinding `kobe-sync`"),
            "error must name the failing object, got: {err}"
        );
    }
}
