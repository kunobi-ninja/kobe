use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::networking::v1::Ingress;
use kube::ResourceExt;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::traits::{ResourceSyncer, SyncerContextV2};
use super::translator::NameTranslator;

// ===========================================================================
// v2: Ingress syncer (virtual -> host)
// ===========================================================================

/// Translate a virtual Ingress into a host Ingress ready for creation on the
/// host cluster.
///
/// This is a pure function. In addition to ObjectMeta translation:
/// - Backend service names are translated.
/// - TLS secret names are translated.
pub fn translate_ingress_to_host(
    ing: &Ingress,
    translator: &NameTranslator,
    virtual_ns: &str,
) -> anyhow::Result<Ingress> {
    let translated_meta = translator.translate_object_meta(&ing.metadata, virtual_ns);

    let translated_spec = ing.spec.as_ref().map(|spec| {
        let mut new_spec = spec.clone();

        // Translate the default backend service name.
        if let Some(ref mut default_backend) = new_spec.default_backend {
            if let Some(ref mut svc) = default_backend.service {
                if !svc.name.is_empty() && translator.to_virtual(&svc.name).is_none() {
                    svc.name = translator.to_host_name(&svc.name, virtual_ns);
                }
            }
        }

        // Translate rule backend service names.
        if let Some(ref mut rules) = new_spec.rules {
            for rule in rules.iter_mut() {
                if let Some(ref mut http) = rule.http {
                    for path in &mut http.paths {
                        if let Some(ref mut svc) = path.backend.service {
                            if !svc.name.is_empty() && translator.to_virtual(&svc.name).is_none() {
                                svc.name = translator.to_host_name(&svc.name, virtual_ns);
                            }
                        }
                    }
                }
            }
        }

        // Translate TLS secret names.
        if let Some(ref mut tls_list) = new_spec.tls {
            for tls in tls_list.iter_mut() {
                if let Some(ref secret_name) = tls.secret_name.clone() {
                    if !secret_name.is_empty() && translator.to_virtual(secret_name).is_none() {
                        tls.secret_name = Some(translator.to_host_name(secret_name, virtual_ns));
                    }
                }
            }
        }

        new_spec
    });

    Ok(Ingress {
        metadata: translated_meta,
        spec: translated_spec,
        status: None,
    })
}

// ---------------------------------------------------------------------------
// IngressSyncerV2 -- ResourceSyncer implementation
// ---------------------------------------------------------------------------

/// v2 Ingress syncer: watches the virtual kube-apiserver for Ingresses and
/// creates translated Ingresses on the host cluster.
pub struct IngressSyncerV2;

#[async_trait::async_trait]
impl ResourceSyncer for IngressSyncerV2 {
    fn name(&self) -> &str {
        "ingresses"
    }

    async fn run(&self, ctx: Arc<SyncerContextV2>, shutdown: CancellationToken) {
        let virtual_api: Api<Ingress> = Api::all(ctx.virtual_client.clone());
        let host_api: Api<Ingress> = Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        let watcher_config = watcher::Config::default();
        let mut stream = std::pin::pin!(watcher::watcher(virtual_api, watcher_config));

        info!("IngressSyncerV2: starting watch on virtual apiserver");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("IngressSyncerV2: shutdown signal received");
                    break;
                }
                event = stream.next() => {
                    match event {
                        Some(Ok(ev)) => {
                            if let Err(e) = handle_ingress_event(&ev, &ctx, &host_api).await {
                                warn!(error = %e, "IngressSyncerV2: error handling event");
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "IngressSyncerV2: watcher error");
                        }
                        None => {
                            info!("IngressSyncerV2: watcher stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Handle a single watcher event for the Ingress syncer.
async fn handle_ingress_event(
    event: &Event<Ingress>,
    ctx: &SyncerContextV2,
    host_api: &Api<Ingress>,
) -> anyhow::Result<()> {
    match event {
        Event::Apply(ing) | Event::InitApply(ing) => {
            let virtual_ns = ing.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = ing.name_any();
            debug!(
                name = %virtual_name,
                ns = %virtual_ns,
                "IngressSyncerV2: translating ingress"
            );

            let host_ing = translate_ingress_to_host(ing, &ctx.translator, &virtual_ns)?;
            let host_name = host_ing.metadata.name.as_deref().unwrap_or_default();

            match host_api.get_opt(host_name).await? {
                Some(_existing) => {
                    let patch = Patch::Apply(&host_ing);
                    host_api
                        .patch(host_name, &PatchParams::apply("kobe-sync").force(), &patch)
                        .await?;
                    debug!(name = %host_name, "IngressSyncerV2: patched host ingress");
                }
                None => {
                    host_api.create(&PostParams::default(), &host_ing).await?;
                    debug!(name = %host_name, "IngressSyncerV2: created host ingress");
                }
            }
        }
        Event::Delete(ing) => {
            let virtual_ns = ing.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = ing.name_any();
            let host_name = ctx.translator.to_host_name(&virtual_name, &virtual_ns);

            debug!(
                name = %host_name,
                "IngressSyncerV2: deleting host ingress"
            );

            match host_api.delete(&host_name, &DeleteParams::default()).await {
                Ok(_) => {
                    debug!(name = %host_name, "IngressSyncerV2: deleted host ingress");
                }
                Err(kube::Error::Api(err)) if err.code == 404 => {
                    debug!(name = %host_name, "IngressSyncerV2: host ingress already gone");
                }
                Err(e) => return Err(e.into()),
            }
        }
        Event::Init => {
            debug!("IngressSyncerV2: watcher init bookmark");
        }
        Event::InitDone => {
            info!("IngressSyncerV2: initial list complete");
        }
    }

    Ok(())
}

// ===========================================================================
// v2 tests
// ===========================================================================

#[cfg(test)]
mod tests_v2 {
    use super::super::translator::{LABEL_MANAGED, LABEL_VNS, NameTranslator};
    use super::*;
    use k8s_openapi::api::networking::v1::{
        HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule,
        IngressServiceBackend, IngressSpec, IngressTLS, ServiceBackendPort,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_translator() -> NameTranslator {
        NameTranslator::new("pool-test".to_string())
    }

    #[test]
    fn test_translate_ingress_name_and_namespace() {
        let t = make_translator();
        let ing = Ingress {
            metadata: ObjectMeta {
                name: Some("my-ingress".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(IngressSpec::default()),
            ..Default::default()
        };
        let host_ing = translate_ingress_to_host(&ing, &t, "default").unwrap();
        assert_eq!(
            host_ing.metadata.name,
            Some("my-ingress-x-default-x-vc".into())
        );
        assert_eq!(host_ing.metadata.namespace, Some("pool-test".into()));
    }

    #[test]
    fn test_translate_ingress_default_backend_service_name() {
        let t = make_translator();
        let ing = Ingress {
            metadata: ObjectMeta {
                name: Some("my-ingress".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                default_backend: Some(IngressBackend {
                    service: Some(IngressServiceBackend {
                        name: "my-svc".into(),
                        port: Some(ServiceBackendPort {
                            number: Some(80),
                            ..Default::default()
                        }),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let host_ing = translate_ingress_to_host(&ing, &t, "default").unwrap();
        let backend = host_ing
            .spec
            .as_ref()
            .unwrap()
            .default_backend
            .as_ref()
            .unwrap();
        assert_eq!(
            backend.service.as_ref().unwrap().name,
            "my-svc-x-default-x-vc"
        );
        // Port should be preserved.
        assert_eq!(
            backend
                .service
                .as_ref()
                .unwrap()
                .port
                .as_ref()
                .unwrap()
                .number,
            Some(80)
        );
    }

    #[test]
    fn test_translate_ingress_rule_backend_service_names() {
        let t = make_translator();
        let ing = Ingress {
            metadata: ObjectMeta {
                name: Some("my-ingress".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                rules: Some(vec![IngressRule {
                    host: Some("example.com".into()),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![
                            HTTPIngressPath {
                                path: Some("/api".into()),
                                path_type: "Prefix".into(),
                                backend: IngressBackend {
                                    service: Some(IngressServiceBackend {
                                        name: "api-svc".into(),
                                        port: Some(ServiceBackendPort {
                                            number: Some(8080),
                                            ..Default::default()
                                        }),
                                    }),
                                    ..Default::default()
                                },
                            },
                            HTTPIngressPath {
                                path: Some("/web".into()),
                                path_type: "Prefix".into(),
                                backend: IngressBackend {
                                    service: Some(IngressServiceBackend {
                                        name: "web-svc".into(),
                                        port: Some(ServiceBackendPort {
                                            number: Some(80),
                                            ..Default::default()
                                        }),
                                    }),
                                    ..Default::default()
                                },
                            },
                        ],
                    }),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let host_ing = translate_ingress_to_host(&ing, &t, "default").unwrap();
        let rules = host_ing.spec.as_ref().unwrap().rules.as_ref().unwrap();
        let paths = &rules[0].http.as_ref().unwrap().paths;
        assert_eq!(
            paths[0].backend.service.as_ref().unwrap().name,
            "api-svc-x-default-x-vc"
        );
        assert_eq!(
            paths[1].backend.service.as_ref().unwrap().name,
            "web-svc-x-default-x-vc"
        );
        // Host should be preserved.
        assert_eq!(rules[0].host, Some("example.com".into()));
    }

    #[test]
    fn test_translate_ingress_tls_secret_names() {
        let t = make_translator();
        let ing = Ingress {
            metadata: ObjectMeta {
                name: Some("my-ingress".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                tls: Some(vec![IngressTLS {
                    hosts: Some(vec!["example.com".into()]),
                    secret_name: Some("tls-cert".into()),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let host_ing = translate_ingress_to_host(&ing, &t, "default").unwrap();
        let tls = host_ing.spec.as_ref().unwrap().tls.as_ref().unwrap();
        assert_eq!(tls[0].secret_name, Some("tls-cert-x-default-x-vc".into()));
        // Hosts should be preserved.
        assert_eq!(tls[0].hosts, Some(vec!["example.com".into()]));
    }

    #[test]
    fn test_translate_ingress_management_labels() {
        let t = make_translator();
        let ing = Ingress {
            metadata: ObjectMeta {
                name: Some("my-ingress".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let host_ing = translate_ingress_to_host(&ing, &t, "default").unwrap();
        let labels = host_ing.metadata.labels.unwrap();
        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".to_string()));
        assert_eq!(labels.get(LABEL_VNS), Some(&"default".to_string()));
    }

    #[test]
    fn test_translate_ingress_no_status() {
        let t = make_translator();
        let ing = Ingress {
            metadata: ObjectMeta {
                name: Some("my-ingress".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let host_ing = translate_ingress_to_host(&ing, &t, "default").unwrap();
        assert!(host_ing.status.is_none());
    }
}
