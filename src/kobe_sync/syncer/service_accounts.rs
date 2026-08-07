//! ServiceAccount syncer: virtual -> host.
//!
//! Watches the virtual kube-apiserver for `ServiceAccount` resources and
//! mirrors them onto the host cluster with the standard
//! `{name}-x-{vns}-x-vc` translated naming. Without this, the host
//! apiserver rejects every projected pod that references a custom SA
//! (e.g. flux's `source-controller`, `kustomize-controller`, etc.) with
//! `error looking up service account <ns>/<sa>: serviceaccount "<sa>" not
//! found`. That rejection breaks the chain that builds fake nodes
//! (PodSyncer projects → host scheduler picks up → FakeNodeSyncer
//! materializes a virtual node), so the virtual cluster ends up with 0
//! schedulable nodes for any workload that touches a non-default SA.
//!
//! # What we sync
//!
//! Just the SA object itself. We deliberately do **not** sync the
//! per-SA token Secrets that the apiserver auto-creates for legacy
//! mountable tokens — those are for in-cluster auth against the
//! virtual apiserver, not the host. Projected ServiceAccount tokens
//! (the modern default) flow through the projected-volume mechanism
//! at pod-mount time and don't depend on the SA-secret link.
//!
//! # Translation
//!
//! Identical to the other v->h syncers via [`super::translator`]:
//! `default/source-controller` (virtual) → `kobe-system` (host
//! namespace) with name `source-controller-x-default-x-vc`. The
//! corresponding [`super::pods::PodSyncer`] rewrites
//! `pod.spec.serviceAccountName` to the translated name when projecting
//! pods, so SA references resolve on the host.

use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::ServiceAccount;
use kube::ResourceExt;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::traits::{ResourceSyncer, SyncerContext};
use super::translator::NameTranslator;

// ===========================================================================
// Pure translation
// ===========================================================================

/// Translate a virtual `ServiceAccount` into a host `ServiceAccount`
/// ready for creation on the host cluster.
///
/// **What carries over:**
/// - `metadata` (translated by [`NameTranslator::translate_object_meta`])
/// - `image_pull_secrets` — pulls in the virtual cluster's image-pull
///   credentials, but the secrets themselves still need to be synced
///   by [`super::secrets::SecretSyncer`] for the references to resolve.
/// - `automount_service_account_token` — preserved verbatim.
///
/// **What we drop:**
/// - `secrets` — the legacy `<sa>-token-<rand>` Secret link is for
///   in-cluster auth against the *virtual* apiserver and is irrelevant
///   on the host. The host kube-apiserver projects modern tokens via
///   the volume API regardless.
pub fn translate_service_account_to_host(
    sa: &ServiceAccount,
    translator: &NameTranslator,
    virtual_ns: &str,
) -> anyhow::Result<ServiceAccount> {
    let translated_meta = translator.translate_object_meta(&sa.metadata, virtual_ns)?;
    Ok(ServiceAccount {
        metadata: translated_meta,
        automount_service_account_token: sa.automount_service_account_token,
        image_pull_secrets: sa.image_pull_secrets.clone(),
        // Drop `secrets` — see fn doc.
        secrets: None,
    })
}

// ===========================================================================
// ServiceAccountSyncer -- ResourceSyncer implementation
// ===========================================================================

/// ServiceAccount syncer: watches the virtual kube-apiserver for SAs
/// and mirrors them as translated SAs on the host cluster.
///
/// Direction: virtual -> host. Same skip-namespaces and translation
/// rules as other v->h syncers.
pub struct ServiceAccountSyncer;

#[async_trait::async_trait]
impl ResourceSyncer for ServiceAccountSyncer {
    fn name(&self) -> &str {
        "service_accounts"
    }

    async fn run(&self, ctx: Arc<SyncerContext>, shutdown: CancellationToken) {
        let virtual_api: Api<ServiceAccount> = Api::all(ctx.virtual_client.clone());
        let host_api: Api<ServiceAccount> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        let watcher_config = watcher::Config::default();
        let mut stream = std::pin::pin!(watcher::watcher(virtual_api, watcher_config));

        info!("ServiceAccountSyncer: starting watch on virtual apiserver");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("ServiceAccountSyncer: shutdown signal received");
                    break;
                }
                event = stream.next() => {
                    match event {
                        Some(Ok(ev)) => {
                            if let Err(e) = handle_service_account_event(&ev, &ctx, &host_api).await {
                                warn!(error = %e, "ServiceAccountSyncer: error handling event");
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "ServiceAccountSyncer: watcher error");
                        }
                        None => {
                            info!("ServiceAccountSyncer: watcher stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Handle a single watcher event for the ServiceAccount syncer.
async fn handle_service_account_event(
    event: &Event<ServiceAccount>,
    ctx: &SyncerContext,
    host_api: &Api<ServiceAccount>,
) -> anyhow::Result<()> {
    match event {
        Event::Apply(sa) | Event::InitApply(sa) => {
            let virtual_ns = sa.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = sa.name_any();
            debug!(
                name = %virtual_name,
                ns = %virtual_ns,
                "ServiceAccountSyncer: translating SA"
            );

            let host_sa = translate_service_account_to_host(sa, &ctx.translator, &virtual_ns)?;
            let host_name = host_sa.metadata.name.as_deref().unwrap_or_default();

            match host_api.get_opt(host_name).await? {
                Some(_existing) => {
                    let patch = Patch::Apply(&host_sa);
                    host_api
                        .patch(host_name, &PatchParams::apply("kobe-sync").force(), &patch)
                        .await?;
                    debug!(name = %host_name, "ServiceAccountSyncer: patched host SA");
                }
                None => {
                    host_api.create(&PostParams::default(), &host_sa).await?;
                    debug!(name = %host_name, "ServiceAccountSyncer: created host SA");
                }
            }
        }
        Event::Delete(sa) => {
            let virtual_ns = sa.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }
            let virtual_name = sa.name_any();
            // If the name can't be translated (contains the `-x-` separator),
            // the object was never synced to the host — nothing to delete.
            let Ok(host_name) = ctx.translator.to_host_name(&virtual_name, &virtual_ns) else {
                return Ok(());
            };

            debug!(
                name = %host_name,
                "ServiceAccountSyncer: deleting host SA"
            );

            match host_api.delete(&host_name, &DeleteParams::default()).await {
                Ok(_) => debug!(name = %host_name, "ServiceAccountSyncer: deleted host SA"),
                Err(kube::Error::Api(err)) if err.code == 404 => {
                    debug!(name = %host_name, "ServiceAccountSyncer: host SA already gone");
                }
                Err(e) => return Err(e.into()),
            }
        }
        Event::Init => {
            debug!("ServiceAccountSyncer: watcher init bookmark");
        }
        Event::InitDone => {
            info!("ServiceAccountSyncer: initial list complete");
        }
    }

    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::super::translator::{LABEL_MANAGED, LABEL_VNS, NameTranslator};
    use super::*;
    use k8s_openapi::api::core::v1::{LocalObjectReference, ServiceAccount};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_translator() -> NameTranslator {
        NameTranslator::new("pool-test".to_string())
    }

    /// Translation produces a host SA whose name matches the standard
    /// `{name}-x-{vns}-x-vc` convention and whose namespace is the
    /// pool's host namespace — same as every other v->h syncer.
    #[test]
    fn translate_service_account_uses_standard_naming_and_host_namespace() {
        let t = make_translator();
        let sa = ServiceAccount {
            metadata: ObjectMeta {
                name: Some("source-controller".into()),
                namespace: Some("flux-system".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let host_sa = translate_service_account_to_host(&sa, &t, "flux-system").unwrap();
        assert_eq!(
            host_sa.metadata.name.as_deref(),
            Some("source-controller-x-flux-system-x-vc")
        );
        assert_eq!(host_sa.metadata.namespace.as_deref(), Some("pool-test"));
    }

    /// `image_pull_secrets` references on the virtual SA must carry over
    /// to the host SA — without them, a private-registry pull on a
    /// projected pod would silently fail. The referenced Secrets
    /// themselves are kept in sync by `SecretSyncer`.
    #[test]
    fn translate_service_account_preserves_image_pull_secrets() {
        let t = make_translator();
        let sa = ServiceAccount {
            metadata: ObjectMeta {
                name: Some("private-pull".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            image_pull_secrets: Some(vec![LocalObjectReference {
                name: "regcred".into(),
            }]),
            ..Default::default()
        };
        let host_sa = translate_service_account_to_host(&sa, &t, "default").unwrap();
        let pulls = host_sa.image_pull_secrets.as_ref().expect("set");
        assert_eq!(pulls.len(), 1);
        assert_eq!(pulls[0].name, "regcred");
    }

    /// The legacy `<sa>-token-<rand>` Secret link in `spec.secrets`
    /// is for in-cluster auth against the virtual apiserver and is
    /// irrelevant on the host. Dropping it on translation prevents
    /// host apiserver complaints about non-existent token secrets.
    #[test]
    fn translate_service_account_drops_legacy_token_secret_links() {
        use k8s_openapi::api::core::v1::ObjectReference;
        let t = make_translator();
        let sa = ServiceAccount {
            metadata: ObjectMeta {
                name: Some("legacy".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            secrets: Some(vec![ObjectReference {
                name: Some("legacy-token-abcd".into()),
                ..Default::default()
            }]),
            ..Default::default()
        };
        let host_sa = translate_service_account_to_host(&sa, &t, "default").unwrap();
        assert!(host_sa.secrets.is_none());
    }

    /// Translated SAs carry the standard managed/vns labels so
    /// downstream syncers and operators can identify them.
    #[test]
    fn translate_service_account_stamps_managed_labels() {
        let t = make_translator();
        let sa = ServiceAccount {
            metadata: ObjectMeta {
                name: Some("my-sa".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let host_sa = translate_service_account_to_host(&sa, &t, "default").unwrap();
        let labels = host_sa.metadata.labels.expect("labels set");
        assert_eq!(labels.get(LABEL_MANAGED).map(String::as_str), Some("true"));
        assert_eq!(labels.get(LABEL_VNS).map(String::as_str), Some("default"));
    }

    /// `automountServiceAccountToken: false` is a deliberate hardening
    /// choice on the virtual SA. Dropping it (or coercing it to the
    /// `None` default, which the host apiserver reads as *true*) would
    /// silently mount a token into every projected pod that opted out.
    /// Both explicit values must survive verbatim.
    #[test]
    fn translate_service_account_preserves_automount_opt_out() {
        let t = make_translator();
        for want in [Some(false), Some(true), None] {
            let sa = ServiceAccount {
                metadata: ObjectMeta {
                    name: Some("hardened".into()),
                    namespace: Some("default".into()),
                    ..Default::default()
                },
                automount_service_account_token: want,
                ..Default::default()
            };
            let host_sa = translate_service_account_to_host(&sa, &t, "default").unwrap();
            assert_eq!(
                host_sa.automount_service_account_token, want,
                "automountServiceAccountToken must round-trip verbatim"
            );
        }
    }

    /// Server-assigned identity from the *virtual* apiserver
    /// (uid / resourceVersion / creationTimestamp / ownerReferences)
    /// must not be carried onto the host object. A create carrying a
    /// foreign `resourceVersion` is rejected outright, and a stale
    /// `ownerReferences` entry pointing at a virtual object would make
    /// the host garbage collector delete the SA immediately.
    #[test]
    fn translate_service_account_strips_virtual_side_identity() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
        let t = make_translator();
        let sa = ServiceAccount {
            metadata: ObjectMeta {
                name: Some("owned".into()),
                namespace: Some("default".into()),
                uid: Some("11111111-2222-3333-4444-555555555555".into()),
                resource_version: Some("98765".into()),
                owner_references: Some(vec![OwnerReference {
                    api_version: "v1".into(),
                    kind: "Deployment".into(),
                    name: "virtual-owner".into(),
                    uid: "deadbeef".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        };
        let host_sa = translate_service_account_to_host(&sa, &t, "default").unwrap();
        assert!(host_sa.metadata.uid.is_none());
        assert!(host_sa.metadata.resource_version.is_none());
        assert!(host_sa.metadata.owner_references.is_none());
        assert!(host_sa.metadata.creation_timestamp.is_none());
    }

    /// A virtual name carrying the `-x-` translation separator is
    /// ambiguous (see `translator::to_host_name`), so translation must
    /// fail loudly rather than produce a host name that could collide
    /// with a different tenant's object.
    #[test]
    fn translate_service_account_rejects_names_containing_the_separator() {
        let t = make_translator();
        let sa = ServiceAccount {
            metadata: ObjectMeta {
                name: Some("evil-x-sa".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(translate_service_account_to_host(&sa, &t, "default").is_err());
    }

    // ── Event handling against a fake host apiserver ──────────────────

    use crate::kobe_sync::testkit::{HOST_NS, k8s_not_found, syncer_ctx};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Namespaced ServiceAccount collection path on the fake host.
    fn sa_collection() -> String {
        format!("/api/v1/namespaces/{HOST_NS}/serviceaccounts")
    }

    fn sa_item(name: &str) -> String {
        format!("{}/{name}", sa_collection())
    }

    fn virtual_sa(name: &str, ns: &str) -> ServiceAccount {
        ServiceAccount {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some(ns.into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// First sight of a virtual SA: the host has nothing, so the syncer
    /// must CREATE — under the translated name, in the pool's host
    /// namespace. A wrong name here is exactly the
    /// `serviceaccount "<sa>" not found` pod-admission failure this
    /// syncer exists to prevent.
    #[tokio::test]
    async fn apply_event_creates_the_host_sa_when_absent() {
        let server = MockServer::start().await;
        let host = "source-controller-x-flux-system-x-vc";
        Mock::given(method("GET"))
            .and(path(sa_item(host)))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(k8s_not_found("serviceaccounts", host)),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(sa_collection()))
            .respond_with(ResponseTemplate::new(201).set_body_json(virtual_sa(host, HOST_NS)))
            .expect(1)
            .mount(&server)
            .await;

        let ctx = syncer_ctx(&server, &[]);
        let host_api: Api<ServiceAccount> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);
        let ev = Event::Apply(virtual_sa("source-controller", "flux-system"));

        handle_service_account_event(&ev, &ctx, &host_api)
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 2, "expected a GET probe then a POST create");
        let body: serde_json::Value = serde_json::from_slice(&reqs[1].body).unwrap();
        assert_eq!(body["metadata"]["name"], host);
        assert_eq!(body["metadata"]["namespace"], HOST_NS);
    }

    /// When the host SA already exists the syncer must reconcile it with
    /// a forced server-side apply under the `kobe-sync` field manager —
    /// not a second create (409 Conflict) and not an unforced patch
    /// (field-manager conflict after an operator upgrade).
    #[tokio::test]
    async fn apply_event_force_applies_the_existing_host_sa() {
        let server = MockServer::start().await;
        let host = "my-sa-x-default-x-vc";
        Mock::given(method("GET"))
            .and(path(sa_item(host)))
            .respond_with(ResponseTemplate::new(200).set_body_json(virtual_sa(host, HOST_NS)))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(sa_item(host)))
            .respond_with(ResponseTemplate::new(200).set_body_json(virtual_sa(host, HOST_NS)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(sa_collection()))
            .respond_with(ResponseTemplate::new(201))
            .expect(0)
            .mount(&server)
            .await;

        let ctx = syncer_ctx(&server, &[]);
        let host_api: Api<ServiceAccount> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        handle_service_account_event(
            &Event::Apply(virtual_sa("my-sa", "default")),
            &ctx,
            &host_api,
        )
        .await
        .unwrap();

        let patch = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.method.as_str() == "PATCH")
            .expect("a PATCH must have been issued");
        let query: std::collections::HashMap<_, _> = patch.url.query_pairs().collect();
        assert_eq!(
            query.get("fieldManager").map(|v| v.as_ref()),
            Some("kobe-sync")
        );
        assert_eq!(query.get("force").map(|v| v.as_ref()), Some("true"));
    }

    /// `InitApply` (the replay of the initial list) must take the same
    /// path as `Apply`. Treating it as a no-op would leave every SA that
    /// existed before kobe-sync started unmirrored until it happened to
    /// be edited.
    #[tokio::test]
    async fn init_apply_event_syncs_like_apply() {
        let server = MockServer::start().await;
        let host = "pre-existing-x-default-x-vc";
        Mock::given(method("GET"))
            .and(path(sa_item(host)))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(k8s_not_found("serviceaccounts", host)),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(sa_collection()))
            .respond_with(ResponseTemplate::new(201).set_body_json(virtual_sa(host, HOST_NS)))
            .expect(1)
            .mount(&server)
            .await;

        let ctx = syncer_ctx(&server, &[]);
        let host_api: Api<ServiceAccount> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        handle_service_account_event(
            &Event::InitApply(virtual_sa("pre-existing", "default")),
            &ctx,
            &host_api,
        )
        .await
        .unwrap();

        server.verify().await;
    }

    /// Namespaces in `skip_namespaces` are invisible to the syncer: not
    /// even the existence probe may go out. `kube-system` SAs belong to
    /// the virtual control plane and mirroring them would collide with
    /// the host's own.
    #[tokio::test]
    async fn skipped_namespaces_produce_no_host_traffic_at_all() {
        let server = MockServer::start().await;
        let ctx = syncer_ctx(&server, &["kube-system"]);
        let host_api: Api<ServiceAccount> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        for ev in [
            Event::Apply(virtual_sa("default", "kube-system")),
            Event::InitApply(virtual_sa("default", "kube-system")),
            Event::Delete(virtual_sa("default", "kube-system")),
        ] {
            handle_service_account_event(&ev, &ctx, &host_api)
                .await
                .unwrap();
        }

        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "skipped namespaces must not reach the host apiserver"
        );
    }

    /// Watcher bookmarks carry no object; they must be pure no-ops
    /// rather than triggering a spurious host call.
    #[tokio::test]
    async fn init_and_init_done_bookmarks_are_no_ops() {
        let server = MockServer::start().await;
        let ctx = syncer_ctx(&server, &[]);
        let host_api: Api<ServiceAccount> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        handle_service_account_event(&Event::Init, &ctx, &host_api)
            .await
            .unwrap();
        handle_service_account_event(&Event::InitDone, &ctx, &host_api)
            .await
            .unwrap();

        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A virtual delete must delete the *translated* host object.
    #[tokio::test]
    async fn delete_event_deletes_the_translated_host_sa() {
        let server = MockServer::start().await;
        let host = "gone-x-default-x-vc";
        Mock::given(method("DELETE"))
            .and(path(sa_item(host)))
            .respond_with(ResponseTemplate::new(200).set_body_json(virtual_sa(host, HOST_NS)))
            .expect(1)
            .mount(&server)
            .await;

        let ctx = syncer_ctx(&server, &[]);
        let host_api: Api<ServiceAccount> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        handle_service_account_event(
            &Event::Delete(virtual_sa("gone", "default")),
            &ctx,
            &host_api,
        )
        .await
        .unwrap();

        server.verify().await;
    }

    /// Deleting an already-absent host SA is the normal race (the host
    /// object was reaped first, or the watch replayed). It must be
    /// swallowed, otherwise the syncer logs a spurious error on every
    /// namespace teardown.
    #[tokio::test]
    async fn delete_event_tolerates_a_host_sa_that_is_already_gone() {
        let server = MockServer::start().await;
        let host = "vanished-x-default-x-vc";
        Mock::given(method("DELETE"))
            .and(path(sa_item(host)))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(k8s_not_found("serviceaccounts", host)),
            )
            .mount(&server)
            .await;

        let ctx = syncer_ctx(&server, &[]);
        let host_api: Api<ServiceAccount> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        handle_service_account_event(
            &Event::Delete(virtual_sa("vanished", "default")),
            &ctx,
            &host_api,
        )
        .await
        .expect("404 on delete must be treated as success");
    }

    /// Any delete failure that is *not* 404 must surface, so the syncer
    /// loop logs it instead of leaking a host SA forever.
    #[tokio::test]
    async fn delete_event_propagates_non_404_failures() {
        let server = MockServer::start().await;
        let host = "stuck-x-default-x-vc";
        Mock::given(method("DELETE"))
            .and(path(sa_item(host)))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "Status", "status": "Failure",
                "message": "etcdserver: request timed out", "code": 500,
            })))
            .mount(&server)
            .await;

        let ctx = syncer_ctx(&server, &[]);
        let host_api: Api<ServiceAccount> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        assert!(
            handle_service_account_event(
                &Event::Delete(virtual_sa("stuck", "default")),
                &ctx,
                &host_api
            )
            .await
            .is_err()
        );
    }

    /// An untranslatable virtual name was never mirrored (the apply path
    /// errored out), so its delete has nothing to do — and must not fire
    /// a DELETE at a guessed name that could belong to another tenant.
    #[tokio::test]
    async fn delete_event_of_an_untranslatable_name_issues_no_request() {
        let server = MockServer::start().await;
        let ctx = syncer_ctx(&server, &[]);
        let host_api: Api<ServiceAccount> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        handle_service_account_event(
            &Event::Delete(virtual_sa("evil-x-sa", "default")),
            &ctx,
            &host_api,
        )
        .await
        .expect("an untranslatable delete is a no-op, not an error");

        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// An untranslatable name on the *apply* path is an error, not a
    /// silent skip: it means a user created an object kobe-sync cannot
    /// mirror, and the syncer loop should log it.
    #[tokio::test]
    async fn apply_event_of_an_untranslatable_name_errors_without_touching_the_host() {
        let server = MockServer::start().await;
        let ctx = syncer_ctx(&server, &[]);
        let host_api: Api<ServiceAccount> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        assert!(
            handle_service_account_event(
                &Event::Apply(virtual_sa("evil-x-sa", "default")),
                &ctx,
                &host_api
            )
            .await
            .is_err()
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
