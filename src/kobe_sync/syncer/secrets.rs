use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::ResourceExt;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::traits::{ResourceSyncer, SyncerContext};
use super::translator::NameTranslator;

// ===========================================================================
// Secret syncer (virtual -> host)
// ===========================================================================

/// Translate a virtual Secret into a host Secret ready for creation on the host
/// cluster.
///
/// This is a pure function: it translates ObjectMeta and preserves data as-is.
pub fn translate_secret_to_host(
    secret: &Secret,
    translator: &NameTranslator,
    virtual_ns: &str,
) -> anyhow::Result<Secret> {
    let translated_meta = translator.translate_object_meta(&secret.metadata, virtual_ns)?;

    Ok(Secret {
        metadata: translated_meta,
        data: secret.data.clone(),
        string_data: secret.string_data.clone(),
        immutable: secret.immutable,
        type_: secret.type_.clone(),
    })
}

// ---------------------------------------------------------------------------
// SecretSyncer -- ResourceSyncer implementation
// ---------------------------------------------------------------------------

/// Secret syncer: watches the virtual kube-apiserver for Secrets and creates
/// translated Secrets on the host cluster.
pub struct SecretSyncer;

#[async_trait::async_trait]
impl ResourceSyncer for SecretSyncer {
    fn name(&self) -> &str {
        "secrets"
    }

    async fn run(&self, ctx: Arc<SyncerContext>, shutdown: CancellationToken) {
        let virtual_api: Api<Secret> = Api::all(ctx.virtual_client.clone());
        let host_api: Api<Secret> = Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        let watcher_config = watcher::Config::default();
        let mut stream = std::pin::pin!(watcher::watcher(virtual_api, watcher_config));

        info!("SecretSyncer: starting watch on virtual apiserver");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("SecretSyncer: shutdown signal received");
                    break;
                }
                event = stream.next() => {
                    match event {
                        Some(Ok(ev)) => {
                            if let Err(e) = handle_secret_event(&ev, &ctx, &host_api).await {
                                warn!(error = %e, "SecretSyncer: error handling event");
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "SecretSyncer: watcher error");
                        }
                        None => {
                            info!("SecretSyncer: watcher stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Handle a single watcher event for the Secret syncer.
async fn handle_secret_event(
    event: &Event<Secret>,
    ctx: &SyncerContext,
    host_api: &Api<Secret>,
) -> anyhow::Result<()> {
    match event {
        Event::Apply(secret) | Event::InitApply(secret) => {
            let virtual_ns = secret.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = secret.name_any();
            debug!(
                name = %virtual_name,
                ns = %virtual_ns,
                "SecretSyncer: translating secret"
            );

            let host_secret = translate_secret_to_host(secret, &ctx.translator, &virtual_ns)?;
            let host_name = host_secret.metadata.name.as_deref().unwrap_or_default();

            match host_api.get_opt(host_name).await? {
                Some(_existing) => {
                    let patch = Patch::Apply(&host_secret);
                    host_api
                        .patch(host_name, &PatchParams::apply("kobe-sync").force(), &patch)
                        .await?;
                    debug!(name = %host_name, "SecretSyncer: patched host secret");
                }
                None => {
                    host_api
                        .create(&PostParams::default(), &host_secret)
                        .await?;
                    debug!(name = %host_name, "SecretSyncer: created host secret");
                }
            }
        }
        Event::Delete(secret) => {
            let virtual_ns = secret.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = secret.name_any();
            // If the name can't be translated (contains the `-x-` separator),
            // the object was never synced to the host — nothing to delete.
            let Ok(host_name) = ctx.translator.to_host_name(&virtual_name, &virtual_ns) else {
                return Ok(());
            };

            debug!(
                name = %host_name,
                "SecretSyncer: deleting host secret"
            );

            match host_api.delete(&host_name, &DeleteParams::default()).await {
                Ok(_) => {
                    debug!(name = %host_name, "SecretSyncer: deleted host secret");
                }
                Err(kube::Error::Api(err)) if err.code == 404 => {
                    debug!(name = %host_name, "SecretSyncer: host secret already gone");
                }
                Err(e) => return Err(e.into()),
            }
        }
        Event::Init => {
            debug!("SecretSyncer: watcher init bookmark");
        }
        Event::InitDone => {
            info!("SecretSyncer: initial list complete");
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
    use k8s_openapi::api::core::v1::Secret;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    fn make_translator() -> NameTranslator {
        NameTranslator::new("pool-test".to_string())
    }

    #[test]
    fn test_translate_secret_to_host() {
        let t = make_translator();
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some("db-creds".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            data: Some({
                let mut m = BTreeMap::new();
                m.insert(
                    "password".into(),
                    k8s_openapi::ByteString(b"s3cret".to_vec()),
                );
                m
            }),
            type_: Some("Opaque".into()),
            ..Default::default()
        };
        let host_secret = translate_secret_to_host(&secret, &t, "default").unwrap();
        assert_eq!(
            host_secret.metadata.name,
            Some("db-creds-x-default-x-vc".into())
        );
        assert_eq!(host_secret.metadata.namespace, Some("pool-test".into()));
        assert_eq!(
            host_secret
                .data
                .as_ref()
                .unwrap()
                .get("password")
                .unwrap()
                .0,
            b"s3cret"
        );
        assert_eq!(host_secret.type_, Some("Opaque".into()));
    }

    #[test]
    fn test_translate_secret_preserves_string_data() {
        let t = make_translator();
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some("my-secret".into()),
                namespace: Some("staging".into()),
                ..Default::default()
            },
            string_data: Some({
                let mut m = BTreeMap::new();
                m.insert("token".into(), "abc123".into());
                m
            }),
            ..Default::default()
        };
        let host_secret = translate_secret_to_host(&secret, &t, "staging").unwrap();
        assert_eq!(
            host_secret.string_data.as_ref().unwrap().get("token"),
            Some(&"abc123".to_string())
        );
    }

    #[test]
    fn test_translate_secret_management_labels() {
        let t = make_translator();
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some("my-secret".into()),
                namespace: Some("default".into()),
                labels: Some({
                    let mut m = BTreeMap::new();
                    m.insert("app".into(), "backend".into());
                    m
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let host_secret = translate_secret_to_host(&secret, &t, "default").unwrap();
        let labels = host_secret.metadata.labels.unwrap();
        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".to_string()));
        assert_eq!(labels.get(LABEL_VNS), Some(&"default".to_string()));
        assert_eq!(labels.get("app"), Some(&"backend".to_string()));
    }
}
