use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Endpoints;
use kube::ResourceExt;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::traits::{ResourceSyncer, SyncerContext};
use super::translator::NameTranslator;

// ===========================================================================
// Endpoints syncer (virtual -> host)
// ===========================================================================

/// Translate a virtual Endpoints object into a host Endpoints ready for creation
/// on the host cluster.
///
/// This is a pure function. In addition to ObjectMeta translation, subset
/// targetRef names get translated and their namespace set to the host namespace.
pub fn translate_endpoints_to_host(
    ep: &Endpoints,
    translator: &NameTranslator,
    virtual_ns: &str,
) -> anyhow::Result<Endpoints> {
    let translated_meta = translator.translate_object_meta(&ep.metadata, virtual_ns)?;

    let translated_subsets = match ep.subsets.as_ref() {
        Some(subsets) => {
            let mut new_subsets = Vec::with_capacity(subsets.len());
            for subset in subsets {
                let mut new_subset = subset.clone();

                // Translate addresses targetRef names.
                if let Some(ref addresses) = subset.addresses {
                    new_subset.addresses = Some(translate_endpoint_addresses(
                        addresses, translator, virtual_ns,
                    )?);
                }

                // Translate not_ready_addresses targetRef names.
                if let Some(ref not_ready) = subset.not_ready_addresses {
                    new_subset.not_ready_addresses = Some(translate_endpoint_addresses(
                        not_ready, translator, virtual_ns,
                    )?);
                }

                new_subsets.push(new_subset);
            }
            Some(new_subsets)
        }
        None => None,
    };

    Ok(Endpoints {
        metadata: translated_meta,
        subsets: translated_subsets,
    })
}

/// Translate the `targetRef` pod name + namespace on each EndpointAddress to
/// its host-side equivalent. Addresses whose targetRef is already a host name
/// (or absent) are passed through unchanged.
fn translate_endpoint_addresses(
    addresses: &[k8s_openapi::api::core::v1::EndpointAddress],
    translator: &NameTranslator,
    virtual_ns: &str,
) -> anyhow::Result<Vec<k8s_openapi::api::core::v1::EndpointAddress>> {
    let mut out = Vec::with_capacity(addresses.len());
    for addr in addresses {
        let mut new_addr = addr.clone();
        if let Some(ref target_ref) = addr.target_ref
            && let Some(ref pod_name) = target_ref.name
            && translator.to_virtual(pod_name).is_none()
        {
            let mut new_ref = target_ref.clone();
            new_ref.name = Some(translator.to_host_name(pod_name, virtual_ns)?);
            new_ref.namespace = Some(translator.host_namespace().to_string());
            new_addr.target_ref = Some(new_ref);
        }
        out.push(new_addr);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// EndpointSyncer -- ResourceSyncer implementation
// ---------------------------------------------------------------------------

/// Endpoints syncer: watches the virtual kube-apiserver for Endpoints and
/// creates translated Endpoints on the host cluster.
pub struct EndpointSyncer;

#[async_trait::async_trait]
impl ResourceSyncer for EndpointSyncer {
    fn name(&self) -> &str {
        "endpoints"
    }

    async fn run(&self, ctx: Arc<SyncerContext>, shutdown: CancellationToken) {
        let virtual_api: Api<Endpoints> = Api::all(ctx.virtual_client.clone());
        let host_api: Api<Endpoints> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        let watcher_config = watcher::Config::default();
        let mut stream = std::pin::pin!(watcher::watcher(virtual_api, watcher_config));

        info!("EndpointSyncer: starting watch on virtual apiserver");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("EndpointSyncer: shutdown signal received");
                    break;
                }
                event = stream.next() => {
                    match event {
                        Some(Ok(ev)) => {
                            if let Err(e) = handle_endpoints_event(&ev, &ctx, &host_api).await {
                                warn!(error = %e, "EndpointSyncer: error handling event");
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "EndpointSyncer: watcher error");
                        }
                        None => {
                            info!("EndpointSyncer: watcher stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Handle a single watcher event for the Endpoints syncer.
async fn handle_endpoints_event(
    event: &Event<Endpoints>,
    ctx: &SyncerContext,
    host_api: &Api<Endpoints>,
) -> anyhow::Result<()> {
    match event {
        Event::Apply(ep) | Event::InitApply(ep) => {
            let virtual_ns = ep.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = ep.name_any();
            debug!(
                name = %virtual_name,
                ns = %virtual_ns,
                "EndpointSyncer: translating endpoints"
            );

            let host_ep = translate_endpoints_to_host(ep, &ctx.translator, &virtual_ns)?;
            let host_name = host_ep.metadata.name.as_deref().unwrap_or_default();

            match host_api.get_opt(host_name).await? {
                Some(_existing) => {
                    let patch = Patch::Apply(&host_ep);
                    host_api
                        .patch(host_name, &PatchParams::apply("kobe-sync").force(), &patch)
                        .await?;
                    debug!(name = %host_name, "EndpointSyncer: patched host endpoints");
                }
                None => {
                    host_api.create(&PostParams::default(), &host_ep).await?;
                    debug!(name = %host_name, "EndpointSyncer: created host endpoints");
                }
            }
        }
        Event::Delete(ep) => {
            let virtual_ns = ep.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = ep.name_any();
            // If the name can't be translated (contains the `-x-` separator),
            // the object was never synced to the host — nothing to delete.
            let Ok(host_name) = ctx.translator.to_host_name(&virtual_name, &virtual_ns) else {
                return Ok(());
            };

            debug!(
                name = %host_name,
                "EndpointSyncer: deleting host endpoints"
            );

            match host_api.delete(&host_name, &DeleteParams::default()).await {
                Ok(_) => {
                    debug!(name = %host_name, "EndpointSyncer: deleted host endpoints");
                }
                Err(kube::Error::Api(err)) if err.code == 404 => {
                    debug!(name = %host_name, "EndpointSyncer: host endpoints already gone");
                }
                Err(e) => return Err(e.into()),
            }
        }
        Event::Init => {
            debug!("EndpointSyncer: watcher init bookmark");
        }
        Event::InitDone => {
            info!("EndpointSyncer: initial list complete");
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
        EndpointAddress, EndpointPort, EndpointSubset, Endpoints, ObjectReference,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    fn make_translator() -> NameTranslator {
        NameTranslator::new("pool-test".to_string())
    }

    #[test]
    fn test_translate_endpoints_name_and_namespace() {
        let t = make_translator();
        let ep = Endpoints {
            metadata: ObjectMeta {
                name: Some("my-svc".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            subsets: None,
        };
        let host_ep = translate_endpoints_to_host(&ep, &t, "default").unwrap();
        assert_eq!(host_ep.metadata.name, Some("my-svc-x-default-x-vc".into()));
        assert_eq!(host_ep.metadata.namespace, Some("pool-test".into()));
    }

    #[test]
    fn test_translate_endpoints_targetref_names() {
        let t = make_translator();
        let ep = Endpoints {
            metadata: ObjectMeta {
                name: Some("my-svc".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            subsets: Some(vec![EndpointSubset {
                addresses: Some(vec![EndpointAddress {
                    ip: "10.0.0.1".into(),
                    target_ref: Some(ObjectReference {
                        name: Some("my-pod".into()),
                        namespace: Some("default".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ports: Some(vec![EndpointPort {
                    port: 8080,
                    protocol: Some("TCP".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }]),
        };
        let host_ep = translate_endpoints_to_host(&ep, &t, "default").unwrap();
        let subsets = host_ep.subsets.as_ref().unwrap();
        assert_eq!(subsets.len(), 1);

        let addr = &subsets[0].addresses.as_ref().unwrap()[0];
        let target_ref = addr.target_ref.as_ref().unwrap();
        assert_eq!(target_ref.name, Some("my-pod-x-default-x-vc".into()));
        assert_eq!(target_ref.namespace, Some("pool-test".into()));
        // IP should be preserved.
        assert_eq!(addr.ip, "10.0.0.1");
    }

    #[test]
    fn test_translate_endpoints_not_ready_addresses() {
        let t = make_translator();
        let ep = Endpoints {
            metadata: ObjectMeta {
                name: Some("my-svc".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            subsets: Some(vec![EndpointSubset {
                not_ready_addresses: Some(vec![EndpointAddress {
                    ip: "10.0.0.2".into(),
                    target_ref: Some(ObjectReference {
                        name: Some("failing-pod".into()),
                        namespace: Some("default".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }]),
        };
        let host_ep = translate_endpoints_to_host(&ep, &t, "default").unwrap();
        let subsets = host_ep.subsets.as_ref().unwrap();
        let not_ready = subsets[0].not_ready_addresses.as_ref().unwrap();
        assert_eq!(
            not_ready[0].target_ref.as_ref().unwrap().name,
            Some("failing-pod-x-default-x-vc".into())
        );
        assert_eq!(
            not_ready[0].target_ref.as_ref().unwrap().namespace,
            Some("pool-test".into())
        );
    }

    #[test]
    fn test_translate_endpoints_preserves_ports() {
        let t = make_translator();
        let ep = Endpoints {
            metadata: ObjectMeta {
                name: Some("my-svc".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            subsets: Some(vec![EndpointSubset {
                ports: Some(vec![
                    EndpointPort {
                        port: 8080,
                        protocol: Some("TCP".into()),
                        name: Some("http".into()),
                        ..Default::default()
                    },
                    EndpointPort {
                        port: 443,
                        protocol: Some("TCP".into()),
                        name: Some("https".into()),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }]),
        };
        let host_ep = translate_endpoints_to_host(&ep, &t, "default").unwrap();
        let ports = host_ep.subsets.as_ref().unwrap()[0].ports.as_ref().unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].port, 8080);
        assert_eq!(ports[1].port, 443);
    }

    #[test]
    fn test_translate_endpoints_management_labels() {
        let t = make_translator();
        let ep = Endpoints {
            metadata: ObjectMeta {
                name: Some("my-svc".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            subsets: None,
        };
        let host_ep = translate_endpoints_to_host(&ep, &t, "default").unwrap();
        let labels = host_ep.metadata.labels.unwrap();
        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".to_string()));
        assert_eq!(labels.get(LABEL_VNS), Some(&"default".to_string()));
    }
}
