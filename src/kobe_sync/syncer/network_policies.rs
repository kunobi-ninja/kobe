use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::ResourceExt;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::traits::{ResourceSyncer, SyncerContext};
use super::translator::NameTranslator;

// ===========================================================================
// NetworkPolicy syncer (virtual -> host)
// ===========================================================================

/// Translate a virtual NetworkPolicy into a host NetworkPolicy ready for
/// creation on the host cluster.
///
/// This is a pure function. Only ObjectMeta is translated; spec is preserved
/// as-is (network policies reference labels/CIDR blocks, not resource names).
pub fn translate_network_policy_to_host(
    np: &NetworkPolicy,
    translator: &NameTranslator,
    virtual_ns: &str,
) -> anyhow::Result<NetworkPolicy> {
    let translated_meta = translator.translate_object_meta(&np.metadata, virtual_ns);

    Ok(NetworkPolicy {
        metadata: translated_meta,
        spec: np.spec.clone(),
    })
}

// ---------------------------------------------------------------------------
// NetworkPolicySyncer -- ResourceSyncer implementation
// ---------------------------------------------------------------------------

/// NetworkPolicy syncer: watches the virtual kube-apiserver for
/// NetworkPolicies and creates translated NetworkPolicies on the host cluster.
pub struct NetworkPolicySyncer;

#[async_trait::async_trait]
impl ResourceSyncer for NetworkPolicySyncer {
    fn name(&self) -> &str {
        "network_policies"
    }

    async fn run(&self, ctx: Arc<SyncerContext>, shutdown: CancellationToken) {
        let virtual_api: Api<NetworkPolicy> = Api::all(ctx.virtual_client.clone());
        let host_api: Api<NetworkPolicy> =
            Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        let watcher_config = watcher::Config::default();
        let mut stream = std::pin::pin!(watcher::watcher(virtual_api, watcher_config));

        info!("NetworkPolicySyncer: starting watch on virtual apiserver");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("NetworkPolicySyncer: shutdown signal received");
                    break;
                }
                event = stream.next() => {
                    match event {
                        Some(Ok(ev)) => {
                            if let Err(e) = handle_network_policy_event(&ev, &ctx, &host_api).await {
                                warn!(error = %e, "NetworkPolicySyncer: error handling event");
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "NetworkPolicySyncer: watcher error");
                        }
                        None => {
                            info!("NetworkPolicySyncer: watcher stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Handle a single watcher event for the NetworkPolicy syncer.
async fn handle_network_policy_event(
    event: &Event<NetworkPolicy>,
    ctx: &SyncerContext,
    host_api: &Api<NetworkPolicy>,
) -> anyhow::Result<()> {
    match event {
        Event::Apply(np) | Event::InitApply(np) => {
            let virtual_ns = np.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = np.name_any();
            debug!(
                name = %virtual_name,
                ns = %virtual_ns,
                "NetworkPolicySyncer: translating network policy"
            );

            let host_np = translate_network_policy_to_host(np, &ctx.translator, &virtual_ns)?;
            let host_name = host_np.metadata.name.as_deref().unwrap_or_default();

            match host_api.get_opt(host_name).await? {
                Some(_existing) => {
                    let patch = Patch::Apply(&host_np);
                    host_api
                        .patch(host_name, &PatchParams::apply("kobe-sync").force(), &patch)
                        .await?;
                    debug!(name = %host_name, "NetworkPolicySyncer: patched host network policy");
                }
                None => {
                    host_api.create(&PostParams::default(), &host_np).await?;
                    debug!(name = %host_name, "NetworkPolicySyncer: created host network policy");
                }
            }
        }
        Event::Delete(np) => {
            let virtual_ns = np.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = np.name_any();
            let host_name = ctx.translator.to_host_name(&virtual_name, &virtual_ns);

            debug!(
                name = %host_name,
                "NetworkPolicySyncer: deleting host network policy"
            );

            match host_api.delete(&host_name, &DeleteParams::default()).await {
                Ok(_) => {
                    debug!(name = %host_name, "NetworkPolicySyncer: deleted host network policy");
                }
                Err(kube::Error::Api(err)) if err.code == 404 => {
                    debug!(name = %host_name, "NetworkPolicySyncer: host network policy already gone");
                }
                Err(e) => return Err(e.into()),
            }
        }
        Event::Init => {
            debug!("NetworkPolicySyncer: watcher init bookmark");
        }
        Event::InitDone => {
            info!("NetworkPolicySyncer: initial list complete");
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
    use k8s_openapi::api::networking::v1::{
        NetworkPolicy, NetworkPolicyIngressRule, NetworkPolicyPort, NetworkPolicySpec,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use std::collections::BTreeMap;

    fn make_translator() -> NameTranslator {
        NameTranslator::new("pool-test".to_string())
    }

    #[test]
    fn test_translate_network_policy_name_and_namespace() {
        let t = make_translator();
        let np = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("deny-all".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector::default()),
                ..Default::default()
            }),
        };
        let host_np = translate_network_policy_to_host(&np, &t, "default").unwrap();
        assert_eq!(
            host_np.metadata.name,
            Some("deny-all-x-default-x-vc".into())
        );
        assert_eq!(host_np.metadata.namespace, Some("pool-test".into()));
    }

    #[test]
    fn test_translate_network_policy_preserves_spec() {
        let t = make_translator();
        let np = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("allow-http".into()),
                namespace: Some("default".into()),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector {
                    match_labels: Some({
                        let mut m = BTreeMap::new();
                        m.insert("app".into(), "web".into());
                        m
                    }),
                    ..Default::default()
                }),
                ingress: Some(vec![NetworkPolicyIngressRule {
                    ports: Some(vec![NetworkPolicyPort {
                        port: Some(IntOrString::Int(80)),
                        protocol: Some("TCP".into()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
                policy_types: Some(vec!["Ingress".into()]),
                ..Default::default()
            }),
        };
        let host_np = translate_network_policy_to_host(&np, &t, "default").unwrap();
        let spec = host_np.spec.as_ref().unwrap();
        assert_eq!(
            spec.pod_selector
                .as_ref()
                .unwrap()
                .match_labels
                .as_ref()
                .unwrap()
                .get("app"),
            Some(&"web".to_string())
        );
        assert_eq!(
            spec.policy_types.as_ref().unwrap(),
            &vec!["Ingress".to_string()]
        );
        let ingress_rules = spec.ingress.as_ref().unwrap();
        assert_eq!(ingress_rules.len(), 1);
        assert_eq!(
            ingress_rules[0].ports.as_ref().unwrap()[0].port,
            Some(IntOrString::Int(80))
        );
    }

    #[test]
    fn test_translate_network_policy_management_labels() {
        let t = make_translator();
        let np = NetworkPolicy {
            metadata: ObjectMeta {
                name: Some("deny-all".into()),
                namespace: Some("staging".into()),
                labels: Some({
                    let mut m = BTreeMap::new();
                    m.insert("env".into(), "staging".into());
                    m
                }),
                ..Default::default()
            },
            spec: Some(NetworkPolicySpec {
                pod_selector: Some(LabelSelector::default()),
                ..Default::default()
            }),
        };
        let host_np = translate_network_policy_to_host(&np, &t, "staging").unwrap();
        let labels = host_np.metadata.labels.unwrap();
        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".to_string()));
        assert_eq!(labels.get(LABEL_VNS), Some(&"staging".to_string()));
        assert_eq!(labels.get("env"), Some(&"staging".to_string()));
    }
}
