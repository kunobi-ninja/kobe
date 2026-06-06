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
}
