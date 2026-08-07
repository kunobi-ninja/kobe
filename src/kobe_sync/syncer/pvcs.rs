use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::PersistentVolumeClaim;
use kube::ResourceExt;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::traits::{ResourceSyncer, SyncerContext};
use super::translator::NameTranslator;

// ===========================================================================
// PVC syncer (virtual -> host)
// ===========================================================================

/// Translate a virtual PersistentVolumeClaim into a host PVC ready for creation
/// on the host cluster.
///
/// This is a pure function. Only ObjectMeta is translated; spec is preserved
/// as-is. StorageClassName is cluster-scoped and does not need translation.
pub fn translate_pvc_to_host(
    pvc: &PersistentVolumeClaim,
    translator: &NameTranslator,
    virtual_ns: &str,
) -> anyhow::Result<PersistentVolumeClaim> {
    let translated_meta = translator.translate_object_meta(&pvc.metadata, virtual_ns)?;

    Ok(PersistentVolumeClaim {
        metadata: translated_meta,
        spec: pvc.spec.clone(),
        status: None,
    })
}

// ---------------------------------------------------------------------------
// PvcSyncer -- ResourceSyncer implementation
// ---------------------------------------------------------------------------

/// PVC syncer: watches the virtual kube-apiserver for PersistentVolumeClaims
/// and creates translated PVCs on the host cluster.
pub struct PvcSyncer;

#[async_trait::async_trait]
impl ResourceSyncer for PvcSyncer {
    fn name(&self) -> &str {
        "pvcs"
    }

    async fn run(&self, ctx: Arc<SyncerContext>, shutdown: CancellationToken) {
        let virtual_api: Api<PersistentVolumeClaim> = Api::all(ctx.virtual_client.clone());
        let host_api: Api<PersistentVolumeClaim> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        let watcher_config = watcher::Config::default();
        let mut stream = std::pin::pin!(watcher::watcher(virtual_api, watcher_config));

        info!("PvcSyncer: starting watch on virtual apiserver");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("PvcSyncer: shutdown signal received");
                    break;
                }
                event = stream.next() => {
                    match event {
                        Some(Ok(ev)) => {
                            if let Err(e) = handle_pvc_event(&ev, &ctx, &host_api).await {
                                warn!(error = %e, "PvcSyncer: error handling event");
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "PvcSyncer: watcher error");
                        }
                        None => {
                            info!("PvcSyncer: watcher stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Handle a single watcher event for the PVC syncer.
async fn handle_pvc_event(
    event: &Event<PersistentVolumeClaim>,
    ctx: &SyncerContext,
    host_api: &Api<PersistentVolumeClaim>,
) -> anyhow::Result<()> {
    match event {
        Event::Apply(pvc) | Event::InitApply(pvc) => {
            let virtual_ns = pvc.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = pvc.name_any();
            debug!(
                name = %virtual_name,
                ns = %virtual_ns,
                "PvcSyncer: translating pvc"
            );

            let host_pvc = translate_pvc_to_host(pvc, &ctx.translator, &virtual_ns)?;
            let host_name = host_pvc.metadata.name.as_deref().unwrap_or_default();

            match host_api.get_opt(host_name).await? {
                Some(_existing) => {
                    let patch = Patch::Apply(&host_pvc);
                    host_api
                        .patch(host_name, &PatchParams::apply("kobe-sync").force(), &patch)
                        .await?;
                    debug!(name = %host_name, "PvcSyncer: patched host pvc");
                }
                None => {
                    host_api.create(&PostParams::default(), &host_pvc).await?;
                    debug!(name = %host_name, "PvcSyncer: created host pvc");
                }
            }
        }
        Event::Delete(pvc) => {
            let virtual_ns = pvc.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = pvc.name_any();
            // If the name can't be translated (contains the `-x-` separator),
            // the object was never synced to the host — nothing to delete.
            let Ok(host_name) = ctx.translator.to_host_name(&virtual_name, &virtual_ns) else {
                return Ok(());
            };

            debug!(
                name = %host_name,
                "PvcSyncer: deleting host pvc"
            );

            match host_api.delete(&host_name, &DeleteParams::default()).await {
                Ok(_) => {
                    debug!(name = %host_name, "PvcSyncer: deleted host pvc");
                }
                Err(kube::Error::Api(err)) if err.code == 404 => {
                    debug!(name = %host_name, "PvcSyncer: host pvc already gone");
                }
                Err(e) => return Err(e.into()),
            }
        }
        Event::Init => {
            debug!("PvcSyncer: watcher init bookmark");
        }
        Event::InitDone => {
            info!("PvcSyncer: initial list complete");
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
    use k8s_openapi::api::core::v1::{
        PersistentVolumeClaim, PersistentVolumeClaimSpec, VolumeResourceRequirements,
    };
    use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    fn make_translator() -> NameTranslator {
        NameTranslator::new("pool-test".to_string())
    }

    #[test]
    fn test_translate_pvc_name_and_namespace() {
        let t = make_translator();
        let pvc = PersistentVolumeClaim {
            metadata: ObjectMeta {
                name: Some("my-data".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(PersistentVolumeClaimSpec {
                access_modes: Some(vec!["ReadWriteOnce".into()]),
                resources: Some(VolumeResourceRequirements {
                    requests: Some({
                        let mut m = BTreeMap::new();
                        m.insert("storage".into(), Quantity("10Gi".into()));
                        m
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let host_pvc = translate_pvc_to_host(&pvc, &t, "default").unwrap();
        assert_eq!(
            host_pvc.metadata.name,
            Some("my-data-x-default-x-vc".into())
        );
        assert_eq!(host_pvc.metadata.namespace, Some("pool-test".into()));
    }

    #[test]
    fn test_translate_pvc_preserves_spec() {
        let t = make_translator();
        let pvc = PersistentVolumeClaim {
            metadata: ObjectMeta {
                name: Some("my-data".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(PersistentVolumeClaimSpec {
                access_modes: Some(vec!["ReadWriteOnce".into()]),
                storage_class_name: Some("standard".into()),
                resources: Some(VolumeResourceRequirements {
                    requests: Some({
                        let mut m = BTreeMap::new();
                        m.insert("storage".into(), Quantity("10Gi".into()));
                        m
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let host_pvc = translate_pvc_to_host(&pvc, &t, "default").unwrap();
        let spec = host_pvc.spec.as_ref().unwrap();
        assert_eq!(spec.storage_class_name, Some("standard".into()));
        assert_eq!(
            spec.access_modes.as_ref().unwrap(),
            &vec!["ReadWriteOnce".to_string()]
        );
        assert_eq!(
            spec.resources
                .as_ref()
                .unwrap()
                .requests
                .as_ref()
                .unwrap()
                .get("storage"),
            Some(&Quantity("10Gi".into()))
        );
    }

    #[test]
    fn test_translate_pvc_management_labels() {
        let t = make_translator();
        let pvc = PersistentVolumeClaim {
            metadata: ObjectMeta {
                name: Some("my-data".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let host_pvc = translate_pvc_to_host(&pvc, &t, "default").unwrap();
        let labels = host_pvc.metadata.labels.unwrap();
        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".to_string()));
        assert_eq!(labels.get(LABEL_VNS), Some(&"default".to_string()));
    }

    #[test]
    fn test_translate_pvc_no_status() {
        let t = make_translator();
        let pvc = PersistentVolumeClaim {
            metadata: ObjectMeta {
                name: Some("my-data".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let host_pvc = translate_pvc_to_host(&pvc, &t, "default").unwrap();
        assert!(host_pvc.status.is_none());
    }

    /// The *virtual* status describes a binding that only exists in the
    /// virtual cluster's view. Carrying it onto the host would claim the
    /// host PVC is already `Bound` to a PersistentVolume that the host
    /// has never heard of. The status must be dropped even when the
    /// source object has a fully populated one.
    #[test]
    fn translate_pvc_drops_a_populated_virtual_status() {
        use k8s_openapi::api::core::v1::PersistentVolumeClaimStatus;
        let t = make_translator();
        let pvc = PersistentVolumeClaim {
            metadata: ObjectMeta {
                name: Some("bound".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            status: Some(PersistentVolumeClaimStatus {
                phase: Some("Bound".into()),
                capacity: Some({
                    let mut m = BTreeMap::new();
                    m.insert("storage".to_string(), Quantity("10Gi".into()));
                    m
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let host_pvc = translate_pvc_to_host(&pvc, &t, "default").unwrap();
        assert!(
            host_pvc.status.is_none(),
            "virtual PVC status must never be projected onto the host"
        );
    }

    /// A spec-less PVC stays spec-less rather than gaining a defaulted
    /// (and therefore invalid — no accessModes, no resources) spec.
    #[test]
    fn translate_pvc_leaves_an_absent_spec_absent() {
        let t = make_translator();
        let pvc = PersistentVolumeClaim {
            metadata: ObjectMeta {
                name: Some("bare".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            translate_pvc_to_host(&pvc, &t, "default")
                .unwrap()
                .spec
                .is_none()
        );
    }

    /// The spec is passed through untouched — including `volumeName`,
    /// `volumeMode` and `selector`, which are *not* name-translated
    /// because PersistentVolumes and storage classes are cluster-scoped
    /// on the host and share no namespace with the virtual cluster.
    #[test]
    fn translate_pvc_passes_the_whole_spec_through_verbatim() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
        let t = make_translator();
        let spec = PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteMany".into()]),
            storage_class_name: Some("fast".into()),
            volume_name: Some("pv-0001".into()),
            volume_mode: Some("Block".into()),
            selector: Some(LabelSelector {
                match_labels: Some({
                    let mut m = BTreeMap::new();
                    m.insert("tier".to_string(), "ssd".to_string());
                    m
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let pvc = PersistentVolumeClaim {
            metadata: ObjectMeta {
                name: Some("verbatim".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(spec.clone()),
            ..Default::default()
        };
        let host_pvc = translate_pvc_to_host(&pvc, &t, "default").unwrap();
        assert_eq!(
            serde_json::to_value(host_pvc.spec.as_ref().unwrap()).unwrap(),
            serde_json::to_value(&spec).unwrap()
        );
    }

    /// Server-assigned identity from the virtual apiserver must not ride
    /// along: a `resourceVersion` makes the host create fail outright,
    /// and an `ownerReferences` entry pointing at a virtual object gets
    /// the host PVC garbage-collected the moment the host GC runs.
    #[test]
    fn translate_pvc_strips_virtual_side_identity() {
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
        let t = make_translator();
        let pvc = PersistentVolumeClaim {
            metadata: ObjectMeta {
                name: Some("owned".into()),
                namespace: Some("default".into()),
                uid: Some("11111111-2222-3333-4444-555555555555".into()),
                resource_version: Some("4242".into()),
                owner_references: Some(vec![OwnerReference {
                    api_version: "apps/v1".into(),
                    kind: "StatefulSet".into(),
                    name: "virtual-sts".into(),
                    uid: "deadbeef".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        };
        let host_pvc = translate_pvc_to_host(&pvc, &t, "default").unwrap();
        assert!(host_pvc.metadata.uid.is_none());
        assert!(host_pvc.metadata.resource_version.is_none());
        assert!(host_pvc.metadata.owner_references.is_none());
        assert!(host_pvc.metadata.creation_timestamp.is_none());
    }

    /// A name carrying the `-x-` translation separator is ambiguous and
    /// must be rejected rather than mapped onto a host name that could
    /// collide with another tenant's volume.
    #[test]
    fn translate_pvc_rejects_names_containing_the_separator() {
        let t = make_translator();
        let pvc = PersistentVolumeClaim {
            metadata: ObjectMeta {
                name: Some("data-x-vol".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(translate_pvc_to_host(&pvc, &t, "default").is_err());
    }

    // ── Event handling against a fake host apiserver ──────────────────

    use crate::kobe_sync::testkit::{HOST_NS, k8s_not_found, syncer_ctx};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn pvc_collection() -> String {
        format!("/api/v1/namespaces/{HOST_NS}/persistentvolumeclaims")
    }

    fn pvc_item(name: &str) -> String {
        format!("{}/{name}", pvc_collection())
    }

    fn virtual_pvc(name: &str, ns: &str) -> PersistentVolumeClaim {
        PersistentVolumeClaim {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some(ns.into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn host_api_of(ctx: &SyncerContext) -> Api<PersistentVolumeClaim> {
        Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace)
    }

    /// Unknown on the host ⇒ CREATE, under the translated name in the
    /// pool's host namespace. The pod syncer rewrites
    /// `volumes[].persistentVolumeClaim.claimName` to the same
    /// translated name, so a mismatch here strands every projected pod
    /// in `Pending` on an unbound claim.
    #[tokio::test]
    async fn apply_event_creates_the_host_pvc_when_absent() {
        let server = MockServer::start().await;
        let host = "my-data-x-default-x-vc";
        Mock::given(method("GET"))
            .and(path(pvc_item(host)))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(k8s_not_found("persistentvolumeclaims", host)),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(pvc_collection()))
            .respond_with(ResponseTemplate::new(201).set_body_json(virtual_pvc(host, HOST_NS)))
            .expect(1)
            .mount(&server)
            .await;

        let ctx = syncer_ctx(&server, &[]);
        handle_pvc_event(
            &Event::Apply(virtual_pvc("my-data", "default")),
            &ctx,
            &host_api_of(&ctx),
        )
        .await
        .unwrap();

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 2, "expected a GET probe then a POST create");
        let body: serde_json::Value = serde_json::from_slice(&reqs[1].body).unwrap();
        assert_eq!(body["metadata"]["name"], host);
        assert_eq!(body["metadata"]["namespace"], HOST_NS);
        assert!(
            body.get("status").is_none() || body["status"].is_null(),
            "no virtual status may be sent on create: {body}"
        );
    }

    /// Already present on the host ⇒ forced server-side apply under the
    /// `kobe-sync` field manager, never a second create.
    #[tokio::test]
    async fn apply_event_force_applies_the_existing_host_pvc() {
        let server = MockServer::start().await;
        let host = "my-data-x-default-x-vc";
        Mock::given(method("GET"))
            .and(path(pvc_item(host)))
            .respond_with(ResponseTemplate::new(200).set_body_json(virtual_pvc(host, HOST_NS)))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(pvc_item(host)))
            .respond_with(ResponseTemplate::new(200).set_body_json(virtual_pvc(host, HOST_NS)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(pvc_collection()))
            .respond_with(ResponseTemplate::new(201))
            .expect(0)
            .mount(&server)
            .await;

        let ctx = syncer_ctx(&server, &[]);
        handle_pvc_event(
            &Event::Apply(virtual_pvc("my-data", "default")),
            &ctx,
            &host_api_of(&ctx),
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

    /// `InitApply` (initial-list replay) syncs exactly like `Apply`, so
    /// PVCs that predate the kobe-sync process are mirrored too.
    #[tokio::test]
    async fn init_apply_event_syncs_like_apply() {
        let server = MockServer::start().await;
        let host = "old-data-x-default-x-vc";
        Mock::given(method("GET"))
            .and(path(pvc_item(host)))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(k8s_not_found("persistentvolumeclaims", host)),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(pvc_collection()))
            .respond_with(ResponseTemplate::new(201).set_body_json(virtual_pvc(host, HOST_NS)))
            .expect(1)
            .mount(&server)
            .await;

        let ctx = syncer_ctx(&server, &[]);
        handle_pvc_event(
            &Event::InitApply(virtual_pvc("old-data", "default")),
            &ctx,
            &host_api_of(&ctx),
        )
        .await
        .unwrap();

        server.verify().await;
    }

    /// Skipped namespaces never reach the host apiserver, on any event
    /// kind — not even the existence probe.
    #[tokio::test]
    async fn skipped_namespaces_produce_no_host_traffic_at_all() {
        let server = MockServer::start().await;
        let ctx = syncer_ctx(&server, &["kube-system"]);
        let host_api = host_api_of(&ctx);

        for ev in [
            Event::Apply(virtual_pvc("d", "kube-system")),
            Event::InitApply(virtual_pvc("d", "kube-system")),
            Event::Delete(virtual_pvc("d", "kube-system")),
        ] {
            handle_pvc_event(&ev, &ctx, &host_api).await.unwrap();
        }

        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// Watcher bookmarks are pure no-ops.
    #[tokio::test]
    async fn init_and_init_done_bookmarks_are_no_ops() {
        let server = MockServer::start().await;
        let ctx = syncer_ctx(&server, &[]);
        let host_api = host_api_of(&ctx);

        handle_pvc_event(&Event::Init, &ctx, &host_api)
            .await
            .unwrap();
        handle_pvc_event(&Event::InitDone, &ctx, &host_api)
            .await
            .unwrap();

        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A virtual delete deletes the translated host PVC — the backing
    /// volume is only reclaimed once the *host* claim goes away.
    #[tokio::test]
    async fn delete_event_deletes_the_translated_host_pvc() {
        let server = MockServer::start().await;
        let host = "gone-x-default-x-vc";
        Mock::given(method("DELETE"))
            .and(path(pvc_item(host)))
            .respond_with(ResponseTemplate::new(200).set_body_json(virtual_pvc(host, HOST_NS)))
            .expect(1)
            .mount(&server)
            .await;

        let ctx = syncer_ctx(&server, &[]);
        handle_pvc_event(
            &Event::Delete(virtual_pvc("gone", "default")),
            &ctx,
            &host_api_of(&ctx),
        )
        .await
        .unwrap();

        server.verify().await;
    }

    /// An already-deleted host PVC is the normal teardown race and must
    /// not be reported as an error.
    #[tokio::test]
    async fn delete_event_tolerates_a_host_pvc_that_is_already_gone() {
        let server = MockServer::start().await;
        let host = "vanished-x-default-x-vc";
        Mock::given(method("DELETE"))
            .and(path(pvc_item(host)))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(k8s_not_found("persistentvolumeclaims", host)),
            )
            .mount(&server)
            .await;

        let ctx = syncer_ctx(&server, &[]);
        handle_pvc_event(
            &Event::Delete(virtual_pvc("vanished", "default")),
            &ctx,
            &host_api_of(&ctx),
        )
        .await
        .expect("404 on delete must be treated as success");
    }

    /// Any non-404 delete failure surfaces, so a leaked host PVC (which
    /// keeps a real volume allocated) is at least logged.
    #[tokio::test]
    async fn delete_event_propagates_non_404_failures() {
        let server = MockServer::start().await;
        let host = "stuck-x-default-x-vc";
        Mock::given(method("DELETE"))
            .and(path(pvc_item(host)))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "Status", "status": "Failure",
                "message": "Operation cannot be fulfilled", "code": 409,
            })))
            .mount(&server)
            .await;

        let ctx = syncer_ctx(&server, &[]);
        assert!(
            handle_pvc_event(
                &Event::Delete(virtual_pvc("stuck", "default")),
                &ctx,
                &host_api_of(&ctx)
            )
            .await
            .is_err()
        );
    }

    /// An untranslatable name was never mirrored, so its delete must be
    /// a silent no-op — issuing a DELETE at a guessed name could destroy
    /// another tenant's volume.
    #[tokio::test]
    async fn delete_event_of_an_untranslatable_name_issues_no_request() {
        let server = MockServer::start().await;
        let ctx = syncer_ctx(&server, &[]);

        handle_pvc_event(
            &Event::Delete(virtual_pvc("data-x-vol", "default")),
            &ctx,
            &host_api_of(&ctx),
        )
        .await
        .expect("an untranslatable delete is a no-op, not an error");

        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// On the apply path an untranslatable name is an error (the user
    /// created something kobe-sync cannot mirror), and no host request
    /// is made.
    #[tokio::test]
    async fn apply_event_of_an_untranslatable_name_errors_without_touching_the_host() {
        let server = MockServer::start().await;
        let ctx = syncer_ctx(&server, &[]);

        assert!(
            handle_pvc_event(
                &Event::Apply(virtual_pvc("data-x-vol", "default")),
                &ctx,
                &host_api_of(&ctx)
            )
            .await
            .is_err()
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
