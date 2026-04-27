use std::collections::HashSet;
use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::core::v1::{
    ConfigMapEnvSource, ConfigMapKeySelector, ConfigMapVolumeSource, Container, EnvVar,
    LocalObjectReference, PersistentVolumeClaimVolumeSource, Pod, PodSpec, SecretEnvSource,
    SecretKeySelector, SecretVolumeSource, Volume,
};
use kube::ResourceExt;
use kube::api::{Api, DeleteParams, PostParams};
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::traits::{ResourceSyncer, SyncerContextV2};
use super::translator::{LABEL_MANAGED, LABEL_VNS, NameTranslator};

// ===========================================================================
// v2: Pod syncer (virtual -> host)
// ===========================================================================

/// Translate a virtual Pod into a host Pod ready for creation on the host
/// cluster.
///
/// This is a pure function: it takes an immutable reference to the virtual Pod
/// and produces a new Pod with all names, volumes, env vars, and image pull
/// secrets translated to their host-side equivalents.
pub fn translate_pod_to_host(
    pod: &Pod,
    translator: &NameTranslator,
    virtual_ns: &str,
) -> anyhow::Result<Pod> {
    let virtual_meta = pod.metadata.clone();
    let translated_meta = translator.translate_object_meta(&virtual_meta, virtual_ns);

    let spec = pod
        .spec
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Pod has no spec"))?;

    let mut translated_spec = spec.clone();

    // 1. Translate volumes (ConfigMap, Secret, PVC refs).
    //    Also remove projected SA token volumes and track their names.
    let dropped_volumes: HashSet<String>;
    if let Some(ref volumes) = spec.volumes {
        let (translated_vols, dropped) = translate_volumes_v2(volumes, translator, virtual_ns);
        translated_spec.volumes = Some(translated_vols);
        dropped_volumes = dropped;
    } else {
        dropped_volumes = HashSet::new();
    }

    // 2. Disable automountServiceAccountToken -- host Pod should not mount
    //    the host cluster's SA token.
    translated_spec.automount_service_account_token = Some(false);

    // 3. Clear service_account_name -- not meaningful on host.
    translated_spec.service_account_name = None;

    // 4. Translate containers (env vars, envFrom, volume mounts).
    translated_spec.containers =
        translate_containers_v2(&spec.containers, translator, virtual_ns, &dropped_volumes);
    if let Some(ref init_containers) = spec.init_containers {
        translated_spec.init_containers = Some(translate_containers_v2(
            init_containers,
            translator,
            virtual_ns,
            &dropped_volumes,
        ));
    }

    // 5. Translate imagePullSecrets.
    if let Some(ref pull_secrets) = spec.image_pull_secrets {
        translated_spec.image_pull_secrets = Some(
            pull_secrets
                .iter()
                .map(|lor| {
                    let name = &lor.name;
                    if !name.is_empty() && translator.to_virtual(name).is_none() {
                        LocalObjectReference {
                            name: translator.to_host_name(name, virtual_ns),
                        }
                    } else {
                        lor.clone()
                    }
                })
                .collect(),
        );
    }

    // 6. Clear nodeName -- let the host scheduler place the Pod.
    translated_spec.node_name = None;

    Ok(Pod {
        metadata: translated_meta,
        spec: Some(translated_spec),
        status: None,
    })
}

/// Translate volume sources for v2 (uses `NameTranslator` directly).
///
/// ConfigMap, Secret, and PVC volume references are translated. Projected
/// volumes containing service account tokens are removed (replaced by the
/// automountServiceAccountToken=false approach).
///
/// Returns:
/// - The translated volumes (with names/references rewritten).
/// - The **set of original volume names** that were dropped, so callers can
///   consistently filter out the corresponding volume mounts.
fn translate_volumes_v2(
    volumes: &[Volume],
    translator: &NameTranslator,
    virtual_ns: &str,
) -> (Vec<Volume>, HashSet<String>) {
    let mut translated_volumes = Vec::new();
    let mut dropped_names: HashSet<String> = HashSet::new();

    for vol in volumes {
        // Remove projected volumes that contain service account token
        // projections. These are auto-injected by Kubernetes for SA token
        // mounting and should not exist on the host Pod.
        if let Some(ref projected) = vol.projected
            && let Some(ref sources) = projected.sources
        {
            let has_sa_token = sources.iter().any(|s| s.service_account_token.is_some());
            if has_sa_token {
                dropped_names.insert(vol.name.clone());
                continue;
            }
        }

        let mut translated = vol.clone();

        // ConfigMap volume source.
        if let Some(ref cm) = vol.config_map {
            let cm_name = &cm.name;
            if !cm_name.is_empty() && translator.to_virtual(cm_name).is_none() {
                translated.config_map = Some(ConfigMapVolumeSource {
                    name: translator.to_host_name(cm_name, virtual_ns),
                    ..cm.clone()
                });
            }
        }

        // Secret volume source.
        if let Some(ref secret) = vol.secret
            && let Some(ref secret_name) = secret.secret_name
            && translator.to_virtual(secret_name).is_none()
        {
            translated.secret = Some(SecretVolumeSource {
                secret_name: Some(translator.to_host_name(secret_name, virtual_ns)),
                ..secret.clone()
            });
        }

        // PVC volume source.
        if let Some(ref pvc) = vol.persistent_volume_claim {
            let claim_name = &pvc.claim_name;
            if translator.to_virtual(claim_name).is_none() {
                translated.persistent_volume_claim = Some(PersistentVolumeClaimVolumeSource {
                    claim_name: translator.to_host_name(claim_name, virtual_ns),
                    ..pvc.clone()
                });
            }
        }

        translated_volumes.push(translated);
    }

    (translated_volumes, dropped_names)
}

/// Translate environment variable references for v2 (uses `NameTranslator` directly).
fn translate_env_vars_v2(
    env: &[EnvVar],
    translator: &NameTranslator,
    virtual_ns: &str,
) -> Vec<EnvVar> {
    env.iter()
        .map(|var| {
            let mut translated = var.clone();

            if let Some(ref value_from) = var.value_from {
                let mut translated_vf = value_from.clone();

                // configMapKeyRef
                if let Some(ref cm_ref) = value_from.config_map_key_ref {
                    let cm_name = &cm_ref.name;
                    if !cm_name.is_empty() && translator.to_virtual(cm_name).is_none() {
                        translated_vf.config_map_key_ref = Some(ConfigMapKeySelector {
                            name: translator.to_host_name(cm_name, virtual_ns),
                            ..cm_ref.clone()
                        });
                    }
                }

                // secretKeyRef
                if let Some(ref secret_ref) = value_from.secret_key_ref {
                    let secret_name = &secret_ref.name;
                    if !secret_name.is_empty() && translator.to_virtual(secret_name).is_none() {
                        translated_vf.secret_key_ref = Some(SecretKeySelector {
                            name: translator.to_host_name(secret_name, virtual_ns),
                            ..secret_ref.clone()
                        });
                    }
                }

                translated.value_from = Some(translated_vf);
            }

            translated
        })
        .collect()
}

/// Translate containers for v2 (env vars, envFrom, volume mounts).
///
/// `dropped_volumes` is the set of volume names that were removed during
/// volume translation. Any volume mount whose `name` is in this set is
/// silently removed so we never produce a pod spec with a dangling mount.
fn translate_containers_v2(
    containers: &[Container],
    translator: &NameTranslator,
    virtual_ns: &str,
    dropped_volumes: &HashSet<String>,
) -> Vec<Container> {
    containers
        .iter()
        .map(|container| {
            let mut translated = container.clone();

            // Translate env vars.
            if let Some(ref env) = container.env {
                translated.env = Some(translate_env_vars_v2(env, translator, virtual_ns));
            }

            // Translate envFrom sources.
            if let Some(ref env_from) = container.env_from {
                translated.env_from = Some(
                    env_from
                        .iter()
                        .map(|ef| {
                            let mut translated_ef = ef.clone();

                            if let Some(ref cm_ref) = ef.config_map_ref {
                                let cm_name = &cm_ref.name;
                                if !cm_name.is_empty() && translator.to_virtual(cm_name).is_none() {
                                    translated_ef.config_map_ref = Some(ConfigMapEnvSource {
                                        name: translator.to_host_name(cm_name, virtual_ns),
                                        ..cm_ref.clone()
                                    });
                                }
                            }

                            if let Some(ref secret_ref) = ef.secret_ref {
                                let secret_name = &secret_ref.name;
                                if !secret_name.is_empty()
                                    && translator.to_virtual(secret_name).is_none()
                                {
                                    translated_ef.secret_ref = Some(SecretEnvSource {
                                        name: translator.to_host_name(secret_name, virtual_ns),
                                        ..secret_ref.clone()
                                    });
                                }
                            }

                            translated_ef
                        })
                        .collect(),
                );
            }

            // Remove volume mounts that reference dropped volumes (e.g. projected
            // SA token volumes). Uses the exact set of dropped names rather than
            // a fragile string-prefix heuristic.
            if let Some(ref mounts) = container.volume_mounts {
                translated.volume_mounts = Some(
                    mounts
                        .iter()
                        .filter(|m| !dropped_volumes.contains(&m.name))
                        .cloned()
                        .collect(),
                );
            }

            translated
        })
        .collect()
}

// ---------------------------------------------------------------------------
// PodSyncerV2 -- ResourceSyncer implementation
// ---------------------------------------------------------------------------

/// v2 Pod syncer: watches the virtual kube-apiserver for Pods and creates
/// translated Pods on the host cluster.
pub struct PodSyncerV2;

#[async_trait::async_trait]
impl ResourceSyncer for PodSyncerV2 {
    fn name(&self) -> &str {
        "pods"
    }

    async fn run(&self, ctx: Arc<SyncerContextV2>, shutdown: CancellationToken) {
        let virtual_api: Api<Pod> = Api::all(ctx.virtual_client.clone());
        let host_api: Api<Pod> = Api::namespaced(ctx.host_client.clone(), &ctx.host_namespace);

        let watcher_config = watcher::Config::default();
        let mut stream = std::pin::pin!(watcher::watcher(virtual_api, watcher_config));

        info!("PodSyncerV2: starting watch on virtual apiserver");

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("PodSyncerV2: shutdown signal received");
                    break;
                }
                event = stream.next() => {
                    match event {
                        Some(Ok(ev)) => {
                            if let Err(e) = handle_pod_event(&ev, &ctx, &host_api).await {
                                warn!(error = %e, "PodSyncerV2: error handling event");
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "PodSyncerV2: watcher error");
                        }
                        None => {
                            info!("PodSyncerV2: watcher stream ended");
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Handle a single watcher event for the Pod syncer.
async fn handle_pod_event(
    event: &Event<Pod>,
    ctx: &SyncerContextV2,
    host_api: &Api<Pod>,
) -> anyhow::Result<()> {
    match event {
        Event::Apply(pod) | Event::InitApply(pod) => {
            let virtual_ns = pod.namespace().unwrap_or_default();

            // Skip kube-system pods.
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = pod.name_any();
            debug!(
                name = %virtual_name,
                ns = %virtual_ns,
                "PodSyncerV2: translating pod"
            );

            let host_pod = translate_pod_to_host(pod, &ctx.translator, &virtual_ns)?;
            let host_name = host_pod.metadata.name.as_deref().unwrap_or_default();

            // Pods are largely immutable after creation. If the host pod
            // already exists, skip -- we cannot patch immutable spec fields.
            // Only create new pods.
            match host_api.get_opt(host_name).await? {
                Some(_existing) => {
                    debug!(name = %host_name, "PodSyncerV2: host pod already exists, skipping (immutable spec)");
                }
                None => {
                    host_api.create(&PostParams::default(), &host_pod).await?;
                    debug!(name = %host_name, "PodSyncerV2: created host pod");
                }
            }
        }
        Event::Delete(pod) => {
            let virtual_ns = pod.namespace().unwrap_or_default();
            if ctx.skip_namespaces.iter().any(|ns| ns == &virtual_ns) {
                return Ok(());
            }

            let virtual_name = pod.name_any();
            let host_name = ctx.translator.to_host_name(&virtual_name, &virtual_ns);

            debug!(
                name = %host_name,
                "PodSyncerV2: deleting host pod"
            );

            match host_api.delete(&host_name, &DeleteParams::default()).await {
                Ok(_) => {
                    debug!(name = %host_name, "PodSyncerV2: deleted host pod");
                }
                Err(kube::Error::Api(err)) if err.code == 404 => {
                    debug!(name = %host_name, "PodSyncerV2: host pod already gone");
                }
                Err(e) => return Err(e.into()),
            }
        }
        Event::Init => {
            debug!("PodSyncerV2: watcher init bookmark");
        }
        Event::InitDone => {
            info!("PodSyncerV2: initial list complete");
        }
    }

    Ok(())
}

// ===========================================================================
// v2 tests
// ===========================================================================

#[cfg(test)]
mod tests_v2 {
    use super::*;
    use k8s_openapi::api::core::v1::{
        ConfigMapEnvSource, ConfigMapKeySelector, ConfigMapVolumeSource, Container, EnvFromSource,
        EnvVar, EnvVarSource, LocalObjectReference, PersistentVolumeClaimVolumeSource, Pod,
        PodSpec, ProjectedVolumeSource, SecretVolumeSource, ServiceAccountTokenProjection, Volume,
        VolumeMount, VolumeProjection,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn make_translator() -> NameTranslator {
        NameTranslator::new("host-ns".to_string())
    }

    fn make_pod(name: &str, ns: &str, spec: PodSpec) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(ns.to_string()),
                ..Default::default()
            },
            spec: Some(spec),
            status: None,
        }
    }

    fn minimal_spec() -> PodSpec {
        PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                image: Some("nginx:latest".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn test_translate_pod_name_and_namespace() {
        let translator = make_translator();
        let pod = make_pod("my-app", "default", minimal_spec());

        let result = translate_pod_to_host(&pod, &translator, "default").unwrap();

        assert_eq!(
            result.metadata.name,
            Some("my-app-x-default-x-vc".to_string())
        );
        assert_eq!(result.metadata.namespace, Some("host-ns".to_string()));
    }

    #[test]
    fn test_translate_configmap_volume_refs() {
        let translator = make_translator();
        let spec = PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                ..Default::default()
            }],
            volumes: Some(vec![Volume {
                name: "config-vol".to_string(),
                config_map: Some(ConfigMapVolumeSource {
                    name: "my-config".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        };
        let pod = make_pod("test", "default", spec);

        let result = translate_pod_to_host(&pod, &translator, "default").unwrap();
        let volumes = result.spec.unwrap().volumes.unwrap();

        assert_eq!(volumes.len(), 1);
        assert_eq!(
            volumes[0].config_map.as_ref().unwrap().name,
            "my-config-x-default-x-vc"
        );
    }

    #[test]
    fn test_translate_secret_volume_refs() {
        let translator = make_translator();
        let spec = PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                ..Default::default()
            }],
            volumes: Some(vec![Volume {
                name: "secret-vol".to_string(),
                secret: Some(SecretVolumeSource {
                    secret_name: Some("my-secret".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            ..Default::default()
        };
        let pod = make_pod("test", "default", spec);

        let result = translate_pod_to_host(&pod, &translator, "default").unwrap();
        let volumes = result.spec.unwrap().volumes.unwrap();

        assert_eq!(volumes.len(), 1);
        assert_eq!(
            volumes[0].secret.as_ref().unwrap().secret_name,
            Some("my-secret-x-default-x-vc".to_string())
        );
    }

    #[test]
    fn test_translate_env_configmap_ref() {
        let translator = make_translator();
        let spec = PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                env: Some(vec![EnvVar {
                    name: "MY_VAR".to_string(),
                    value_from: Some(EnvVarSource {
                        config_map_key_ref: Some(ConfigMapKeySelector {
                            name: "app-config".to_string(),
                            key: "key1".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }],
            ..Default::default()
        };
        let pod = make_pod("test", "default", spec);

        let result = translate_pod_to_host(&pod, &translator, "default").unwrap();
        let containers = &result.spec.unwrap().containers;
        let env = containers[0].env.as_ref().unwrap();

        assert_eq!(
            env[0]
                .value_from
                .as_ref()
                .unwrap()
                .config_map_key_ref
                .as_ref()
                .unwrap()
                .name,
            "app-config-x-default-x-vc"
        );
        // Key should be preserved.
        assert_eq!(
            env[0]
                .value_from
                .as_ref()
                .unwrap()
                .config_map_key_ref
                .as_ref()
                .unwrap()
                .key,
            "key1"
        );
    }

    #[test]
    fn test_translate_image_pull_secrets() {
        let translator = make_translator();
        let spec = PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                ..Default::default()
            }],
            image_pull_secrets: Some(vec![
                LocalObjectReference {
                    name: "my-registry-creds".to_string(),
                },
                LocalObjectReference {
                    name: "other-creds".to_string(),
                },
            ]),
            ..Default::default()
        };
        let pod = make_pod("test", "default", spec);

        let result = translate_pod_to_host(&pod, &translator, "default").unwrap();
        let pull_secrets = result.spec.unwrap().image_pull_secrets.unwrap();

        assert_eq!(pull_secrets.len(), 2);
        assert_eq!(pull_secrets[0].name, "my-registry-creds-x-default-x-vc");
        assert_eq!(pull_secrets[1].name, "other-creds-x-default-x-vc");
    }

    #[test]
    fn test_translate_pvc_volume_refs() {
        let translator = make_translator();
        let spec = PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                ..Default::default()
            }],
            volumes: Some(vec![Volume {
                name: "data-vol".to_string(),
                persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                    claim_name: "my-data".to_string(),
                    read_only: Some(false),
                }),
                ..Default::default()
            }]),
            ..Default::default()
        };
        let pod = make_pod("test", "default", spec);

        let result = translate_pod_to_host(&pod, &translator, "default").unwrap();
        let volumes = result.spec.unwrap().volumes.unwrap();

        assert_eq!(volumes.len(), 1);
        assert_eq!(
            volumes[0]
                .persistent_volume_claim
                .as_ref()
                .unwrap()
                .claim_name,
            "my-data-x-default-x-vc"
        );
        // read_only should be preserved.
        assert_eq!(
            volumes[0]
                .persistent_volume_claim
                .as_ref()
                .unwrap()
                .read_only,
            Some(false)
        );
    }

    #[test]
    fn test_translate_removes_sa_projected_volume() {
        let translator = make_translator();
        let spec = PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                ..Default::default()
            }],
            volumes: Some(vec![
                // Normal volume that should be kept.
                Volume {
                    name: "config-vol".to_string(),
                    config_map: Some(ConfigMapVolumeSource {
                        name: "my-config".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                // Projected SA token volume that should be removed.
                Volume {
                    name: "kube-api-access-abcde".to_string(),
                    projected: Some(ProjectedVolumeSource {
                        sources: Some(vec![VolumeProjection {
                            service_account_token: Some(ServiceAccountTokenProjection {
                                path: "token".to_string(),
                                expiration_seconds: Some(3600),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };
        let pod = make_pod("test", "default", spec);

        let result = translate_pod_to_host(&pod, &translator, "default").unwrap();
        let spec = result.spec.unwrap();

        // Projected SA volume should be removed.
        let volumes = spec.volumes.unwrap();
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].name, "config-vol");

        // automountServiceAccountToken should be false.
        assert_eq!(spec.automount_service_account_token, Some(false));
    }

    #[test]
    fn test_management_labels_present() {
        let translator = make_translator();
        let pod = make_pod("my-app", "staging", minimal_spec());

        let result = translate_pod_to_host(&pod, &translator, "staging").unwrap();
        let labels = result.metadata.labels.unwrap();

        assert_eq!(labels.get(LABEL_MANAGED), Some(&"true".to_string()));
        assert_eq!(labels.get(LABEL_VNS), Some(&"staging".to_string()));
    }

    #[test]
    fn test_translate_clears_node_name() {
        let translator = make_translator();
        let spec = PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                ..Default::default()
            }],
            node_name: Some("virtual-node-1".to_string()),
            ..Default::default()
        };
        let pod = make_pod("test", "default", spec);

        let result = translate_pod_to_host(&pod, &translator, "default").unwrap();
        assert_eq!(result.spec.unwrap().node_name, None);
    }

    #[test]
    fn test_translate_env_secret_ref() {
        let translator = make_translator();
        let spec = PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                env: Some(vec![EnvVar {
                    name: "SECRET_VAR".to_string(),
                    value_from: Some(EnvVarSource {
                        secret_key_ref: Some(SecretKeySelector {
                            name: "db-creds".to_string(),
                            key: "password".to_string(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }],
            ..Default::default()
        };
        let pod = make_pod("test", "default", spec);

        let result = translate_pod_to_host(&pod, &translator, "default").unwrap();
        let containers = &result.spec.unwrap().containers;
        let env = containers[0].env.as_ref().unwrap();

        assert_eq!(
            env[0]
                .value_from
                .as_ref()
                .unwrap()
                .secret_key_ref
                .as_ref()
                .unwrap()
                .name,
            "db-creds-x-default-x-vc"
        );
    }

    #[test]
    fn test_translate_envfrom_configmap_ref() {
        let translator = make_translator();
        let spec = PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                env_from: Some(vec![EnvFromSource {
                    config_map_ref: Some(ConfigMapEnvSource {
                        name: "env-config".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }],
            ..Default::default()
        };
        let pod = make_pod("test", "default", spec);

        let result = translate_pod_to_host(&pod, &translator, "default").unwrap();
        let containers = &result.spec.unwrap().containers;
        let env_from = containers[0].env_from.as_ref().unwrap();

        assert_eq!(
            env_from[0].config_map_ref.as_ref().unwrap().name,
            "env-config-x-default-x-vc"
        );
    }

    #[test]
    fn test_translate_preserves_container_image() {
        let translator = make_translator();
        let spec = PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                image: Some("my-registry.io/app:v1.2.3".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let pod = make_pod("test", "default", spec);

        let result = translate_pod_to_host(&pod, &translator, "default").unwrap();
        let containers = &result.spec.unwrap().containers;

        assert_eq!(
            containers[0].image,
            Some("my-registry.io/app:v1.2.3".to_string())
        );
    }

    #[test]
    fn test_translate_clears_service_account_name() {
        let translator = make_translator();
        let spec = PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                ..Default::default()
            }],
            service_account_name: Some("my-sa".to_string()),
            ..Default::default()
        };
        let pod = make_pod("test", "default", spec);

        let result = translate_pod_to_host(&pod, &translator, "default").unwrap();
        assert_eq!(result.spec.unwrap().service_account_name, None);
    }

    #[test]
    fn test_translate_drops_sa_volume_and_matching_mount() {
        let translator = make_translator();
        let spec = PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                volume_mounts: Some(vec![
                    VolumeMount {
                        name: "config-vol".to_string(),
                        mount_path: "/etc/config".to_string(),
                        ..Default::default()
                    },
                    VolumeMount {
                        name: "my-sa-token".to_string(),
                        mount_path: "/var/run/secrets/kubernetes.io/serviceaccount".to_string(),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }],
            volumes: Some(vec![
                Volume {
                    name: "config-vol".to_string(),
                    config_map: Some(ConfigMapVolumeSource {
                        name: "my-config".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                Volume {
                    name: "my-sa-token".to_string(),
                    projected: Some(ProjectedVolumeSource {
                        sources: Some(vec![VolumeProjection {
                            service_account_token: Some(ServiceAccountTokenProjection {
                                path: "token".to_string(),
                                expiration_seconds: Some(3600),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };
        let pod = make_pod("test", "default", spec);

        let result = translate_pod_to_host(&pod, &translator, "default").unwrap();
        let result_spec = result.spec.unwrap();

        // The projected SA volume should be dropped.
        let volumes = result_spec.volumes.unwrap();
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].name, "config-vol");

        // The matching volume mount should also be dropped.
        let mounts = result_spec.containers[0].volume_mounts.as_ref().unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].name, "config-vol");
    }
}
