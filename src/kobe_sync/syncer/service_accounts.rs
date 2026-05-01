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
    let translated_meta = translator.translate_object_meta(&sa.metadata, virtual_ns);
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
            let host_name = ctx.translator.to_host_name(&virtual_name, &virtual_ns);

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
}
