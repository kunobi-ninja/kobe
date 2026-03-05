use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use kube::ResourceExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::traits::{ResourceSyncer, SyncerContextV2};
use super::translator::NameTranslator;

// ===========================================================================
// v2: ConfigMap syncer (virtual -> host)
// ===========================================================================

/// Translate a virtual ConfigMap into a host ConfigMap ready for creation on the
/// host cluster.
///
/// This is a pure function: it translates ObjectMeta and preserves data as-is.
pub fn translate_configmap_to_host(
    cm: &ConfigMap,
    translator: &NameTranslator,
    virtual_ns: &str,
) -> anyhow::Result<ConfigMap> {
    let translated_meta = translator.translate_object_meta(&cm.metadata, virtual_ns);

    Ok(ConfigMap {
        metadata: translated_meta,
        data: cm.data.clone(),
        binary_data: cm.binary_data.clone(),
        immutable: cm.immutable,
    })
}

// ---------------------------------------------------------------------------
// ConfigMapSyncerV2 -- ResourceSyncer implementation
// ---------------------------------------------------------------------------

/// v2 ConfigMap syncer: watches the virtual kube-apiserver for ConfigMaps and
/// creates translated ConfigMaps on the host cluster.
pub struct ConfigMapSyncerV2;

#[async_trait::async_trait]
impl ResourceSyncer for ConfigMapSyncerV2 {
    fn name(&self) -> &str {
        "configmaps"
    }

    async fn run(&self, ctx: Arc<SyncerContextV2>, shutdown: CancellationToken) {
        let virtual_api: Api<ConfigMap> = Api::all(ctx.virtual_client.clone());
        let host_api: Api<ConfigMap> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        let watcher_config = watcher::Config::default();
        let mut stream = std::pin::pin!(watcher::watcher(virtual_api, watcher_config));

        info!("ConfigMapSyncerV2: starting watch on virtual apiserver");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("ConfigMapSyncerV2: shutdown signal received");
                    break;
                }
                event = stream.next() => {
                    match event {
                        Some(Ok(ev)) => {
                            if let Err(e) = handle_configmap_event(&ev, &ctx, &host_api).await {
                                warn!(error = %e, "ConfigMapSyncerV2: error handling event");
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "ConfigMapSyncerV2: watcher error");
                        }
                        None => {
                            info!("ConfigMapSyncerV2: watcher stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Handle a single watcher event for the ConfigMap syncer.
async fn handle_configmap_event(
    event: &Event<ConfigMap>,
    ctx: &SyncerContextV2,
    host_api: &Api<ConfigMap>,
) -> anyhow::Result<()> {
    match event {
        Event::Apply(cm) | Event::InitApply(cm) => {
            let virtual_ns = cm.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = cm.name_any();
            debug!(
                name = %virtual_name,
                ns = %virtual_ns,
                "ConfigMapSyncerV2: translating configmap"
            );

            let host_cm = translate_configmap_to_host(cm, &ctx.translator, &virtual_ns)?;
            let host_name = host_cm.metadata.name.as_deref().unwrap_or_default();

            match host_api.get_opt(host_name).await? {
                Some(_existing) => {
                    let patch = Patch::Apply(&host_cm);
                    host_api
                        .patch(host_name, &PatchParams::apply("kobe-sync").force(), &patch)
                        .await?;
                    debug!(name = %host_name, "ConfigMapSyncerV2: patched host configmap");
                }
                None => {
                    host_api.create(&PostParams::default(), &host_cm).await?;
                    debug!(name = %host_name, "ConfigMapSyncerV2: created host configmap");
                }
            }
        }
        Event::Delete(cm) => {
            let virtual_ns = cm.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = cm.name_any();
            let host_name = ctx.translator.to_host_name(&virtual_name, &virtual_ns);

            debug!(
                name = %host_name,
                "ConfigMapSyncerV2: deleting host configmap"
            );

            match host_api.delete(&host_name, &DeleteParams::default()).await {
                Ok(_) => {
                    debug!(name = %host_name, "ConfigMapSyncerV2: deleted host configmap");
                }
                Err(kube::Error::Api(err)) if err.code == 404 => {
                    debug!(name = %host_name, "ConfigMapSyncerV2: host configmap already gone");
                }
                Err(e) => return Err(e.into()),
            }
        }
        Event::Init => {
            debug!("ConfigMapSyncerV2: watcher init bookmark");
        }
        Event::InitDone => {
            info!("ConfigMapSyncerV2: initial list complete");
        }
    }

    Ok(())
}

// ===========================================================================
// v2 tests
// ===========================================================================

#[cfg(test)]
mod tests_v2 {
    use super::super::translator::{NameTranslator, LABEL_MANAGED, LABEL_VNS};
    use super::*;
    use k8s_openapi::api::core::v1::ConfigMap;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    fn make_translator() -> NameTranslator {
        NameTranslator::new("pool-test".to_string())
    }

    #[test]
    fn test_translate_configmap_to_host() {
        let t = make_translator();
        let cm = ConfigMap {
            metadata: ObjectMeta {
                name: Some("app-config".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            data: Some({
                let mut m = BTreeMap::new();
                m.insert("key".into(), "value".into());
                m
            }),
            ..Default::default()
        };
        let host_cm = translate_configmap_to_host(&cm, &t, "default").unwrap();
        assert_eq!(
            host_cm.metadata.name,
            Some("app-config-x-default-x-vc".into())
        );
        assert_eq!(host_cm.metadata.namespace, Some("pool-test".into()));
        assert_eq!(
            host_cm.data.as_ref().unwrap().get("key"),
            Some(&"value".into())
        );
    }

    #[test]
    fn test_translate_configmap_preserves_binary_data() {
        let t = make_translator();
        let cm = ConfigMap {
            metadata: ObjectMeta {
                name: Some("bin-config".into()),
                namespace: Some("staging".into()),
                ..Default::default()
            },
            binary_data: Some({
                let mut m = BTreeMap::new();
                m.insert("cert".into(), k8s_openapi::ByteString(vec![1, 2, 3, 4]));
                m
            }),
            ..Default::default()
        };
        let host_cm = translate_configmap_to_host(&cm, &t, "staging").unwrap();
        assert_eq!(
            host_cm.binary_data.as_ref().unwrap().get("cert").unwrap().0,
            vec![1, 2, 3, 4]
        );
    }

    #[test]
    fn test_translate_configmap_management_labels() {
        let t = make_translator();
        let cm = ConfigMap {
            metadata: ObjectMeta {
                name: Some("my-cm".into()),
                namespace: Some("default".into()),
                labels: Some({
                    let mut m = BTreeMap::new();
                    m.insert("app".into(), "web".into());
                    m
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let host_cm = translate_configmap_to_host(&cm, &t, "default").unwrap();
        let labels = host_cm.metadata.labels.unwrap();
        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".to_string()));
        assert_eq!(labels.get(LABEL_VNS), Some(&"default".to_string()));
        assert_eq!(labels.get("app"), Some(&"web".to_string()));
    }

    #[test]
    fn test_translate_configmap_empty_data() {
        let t = make_translator();
        let cm = ConfigMap {
            metadata: ObjectMeta {
                name: Some("empty".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let host_cm = translate_configmap_to_host(&cm, &t, "default").unwrap();
        assert!(host_cm.data.is_none());
        assert_eq!(host_cm.metadata.name, Some("empty-x-default-x-vc".into()));
    }
}
