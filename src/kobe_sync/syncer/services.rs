use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::ResourceExt;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::traits::{ResourceSyncer, SyncerContext};
use super::translator::NameTranslator;

// ===========================================================================
// Service syncer (virtual -> host)
// ===========================================================================

/// Translate a virtual Service into a host Service ready for creation on the
/// host cluster.
///
/// This is a pure function. In addition to ObjectMeta translation, the
/// service selector labels get the management labels merged so the service
/// matches translated pods carrying the VNS label.
pub fn translate_service_to_host(
    svc: &Service,
    translator: &NameTranslator,
    virtual_ns: &str,
) -> anyhow::Result<Service> {
    let translated_meta = translator.translate_object_meta(&svc.metadata, virtual_ns)?;

    let translated_spec = svc.spec.as_ref().map(|spec| {
        let mut new_spec = spec.clone();

        // Translate selector labels so the host service targets translated pods.
        if let Some(ref selector) = spec.selector {
            new_spec.selector = Some(translator.translate_labels(selector, virtual_ns));
        }

        // Clear clusterIP / clusterIPs -- let the host cluster assign them.
        new_spec.cluster_ip = None;
        new_spec.cluster_ips = None;

        new_spec
    });

    Ok(Service {
        metadata: translated_meta,
        spec: translated_spec,
        status: None,
    })
}

// ---------------------------------------------------------------------------
// ServiceSyncer -- ResourceSyncer implementation
// ---------------------------------------------------------------------------

/// Service syncer: watches the virtual kube-apiserver for Services and
/// creates translated Services on the host cluster.
pub struct ServiceSyncer;

#[async_trait::async_trait]
impl ResourceSyncer for ServiceSyncer {
    fn name(&self) -> &str {
        "services"
    }

    async fn run(&self, ctx: Arc<SyncerContext>, shutdown: CancellationToken) {
        let virtual_api: Api<Service> = Api::all(ctx.virtual_client.clone());
        let host_api: Api<Service> = Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        let watcher_config = watcher::Config::default();
        let mut stream = std::pin::pin!(watcher::watcher(virtual_api, watcher_config));

        info!("ServiceSyncer: starting watch on virtual apiserver");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("ServiceSyncer: shutdown signal received");
                    break;
                }
                event = stream.next() => {
                    match event {
                        Some(Ok(ev)) => {
                            if let Err(e) = handle_service_event(&ev, &ctx, &host_api).await {
                                warn!(error = %e, "ServiceSyncer: error handling event");
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "ServiceSyncer: watcher error");
                        }
                        None => {
                            info!("ServiceSyncer: watcher stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Handle a single watcher event for the Service syncer.
async fn handle_service_event(
    event: &Event<Service>,
    ctx: &SyncerContext,
    host_api: &Api<Service>,
) -> anyhow::Result<()> {
    match event {
        Event::Apply(svc) | Event::InitApply(svc) => {
            let virtual_ns = svc.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = svc.name_any();
            debug!(
                name = %virtual_name,
                ns = %virtual_ns,
                "ServiceSyncer: translating service"
            );

            let host_svc = translate_service_to_host(svc, &ctx.translator, &virtual_ns)?;
            let host_name = host_svc.metadata.name.as_deref().unwrap_or_default();

            match host_api.get_opt(host_name).await? {
                Some(_existing) => {
                    let patch = Patch::Apply(&host_svc);
                    host_api
                        .patch(host_name, &PatchParams::apply("kobe-sync").force(), &patch)
                        .await?;
                    debug!(name = %host_name, "ServiceSyncer: patched host service");
                }
                None => {
                    host_api.create(&PostParams::default(), &host_svc).await?;
                    debug!(name = %host_name, "ServiceSyncer: created host service");
                }
            }
        }
        Event::Delete(svc) => {
            let virtual_ns = svc.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = svc.name_any();
            // If the name can't be translated (contains the `-x-` separator),
            // the object was never synced to the host — nothing to delete.
            let Ok(host_name) = ctx.translator.to_host_name(&virtual_name, &virtual_ns) else {
                return Ok(());
            };

            debug!(
                name = %host_name,
                "ServiceSyncer: deleting host service"
            );

            match host_api.delete(&host_name, &DeleteParams::default()).await {
                Ok(_) => {
                    debug!(name = %host_name, "ServiceSyncer: deleted host service");
                }
                Err(kube::Error::Api(err)) if err.code == 404 => {
                    debug!(name = %host_name, "ServiceSyncer: host service already gone");
                }
                Err(e) => return Err(e.into()),
            }
        }
        Event::Init => {
            debug!("ServiceSyncer: watcher init bookmark");
        }
        Event::InitDone => {
            info!("ServiceSyncer: initial list complete");
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
    use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use std::collections::BTreeMap;

    fn make_translator() -> NameTranslator {
        NameTranslator::new("pool-test".to_string())
    }

    #[test]
    fn test_translate_service_name_and_namespace() {
        let t = make_translator();
        let svc = Service {
            metadata: ObjectMeta {
                name: Some("my-svc".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                ..Default::default()
            }),
            ..Default::default()
        };
        let host_svc = translate_service_to_host(&svc, &t, "default").unwrap();
        assert_eq!(host_svc.metadata.name, Some("my-svc-x-default-x-vc".into()));
        assert_eq!(host_svc.metadata.namespace, Some("pool-test".into()));
    }

    #[test]
    fn test_translate_service_selector_gets_vns_label() {
        let t = make_translator();
        let mut selector = BTreeMap::new();
        selector.insert("app".into(), "web".into());

        let svc = Service {
            metadata: ObjectMeta {
                name: Some("my-svc".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                selector: Some(selector),
                ..Default::default()
            }),
            ..Default::default()
        };
        let host_svc = translate_service_to_host(&svc, &t, "default").unwrap();
        let host_selector = host_svc.spec.as_ref().unwrap().selector.as_ref().unwrap();
        assert_eq!(host_selector.get("app"), Some(&"web".to_string()));
        assert_eq!(host_selector.get(LABEL_VNS), Some(&"default".to_string()));
        assert_eq!(host_selector.get(LABEL_MANAGED), Some(&"true".to_string()));
    }

    #[test]
    fn test_translate_service_preserves_ports() {
        let t = make_translator();
        let svc = Service {
            metadata: ObjectMeta {
                name: Some("my-svc".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(vec![ServicePort {
                    port: 80,
                    target_port: Some(IntOrString::Int(8080)),
                    protocol: Some("TCP".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let host_svc = translate_service_to_host(&svc, &t, "default").unwrap();
        let ports = host_svc.spec.as_ref().unwrap().ports.as_ref().unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 80);
        assert_eq!(ports[0].target_port, Some(IntOrString::Int(8080)));
    }

    #[test]
    fn test_translate_service_clears_cluster_ip() {
        let t = make_translator();
        let svc = Service {
            metadata: ObjectMeta {
                name: Some("my-svc".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ip: Some("10.0.0.5".into()),
                cluster_ips: Some(vec!["10.0.0.5".into()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let host_svc = translate_service_to_host(&svc, &t, "default").unwrap();
        assert_eq!(host_svc.spec.as_ref().unwrap().cluster_ip, None);
        assert_eq!(host_svc.spec.as_ref().unwrap().cluster_ips, None);
    }

    #[test]
    fn test_translate_service_no_status() {
        let t = make_translator();
        let svc = Service {
            metadata: ObjectMeta {
                name: Some("my-svc".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let host_svc = translate_service_to_host(&svc, &t, "default").unwrap();
        assert!(host_svc.status.is_none());
    }
}
