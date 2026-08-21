//! Live certification for management-cluster `SandboxPool` capacity.
//!
//! Upstream `readyReplicas` is only a count. Before Kobe publishes
//! `SandboxPool Ready=True`, this module proves that the count resolves to the
//! exact WarmPool-owned Sandboxes, scheduled Pods, strict NetworkPolicy and
//! administrator-owned execution canary described by the current Pool
//! generation. Admission repeats this live proof before its final Claim
//! create, so status is discovery, not a substitute for target evidence.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{
    ConfigMap, Container, Node, PersistentVolume, PersistentVolumeClaim, Pod, PodSpec, Service,
    ServicePort,
};
use k8s_openapi::api::networking::v1::{
    IPBlock, NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyIngressRule, NetworkPolicyPeer,
    NetworkPolicySpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Api, ApiResource, DynamicObject, ListParams, ObjectMeta, PostParams, TypeMeta};
use kube::{Client, Resource, ResourceExt};
use sha2::{Digest, Sha256};

use crate::controllers::sandbox_canary::{
    CanaryOutcome, ResolvedSandboxPod, SANDBOX_API_VERSION, SANDBOX_KIND, resolve_sandbox_pod,
    run_canary,
};
use crate::crd::{
    SandboxIsolation, SandboxObjectReference, SandboxPool, SandboxPoolCertificationPhase,
    SandboxPoolCertificationStatus,
};
use crate::sandbox::{
    AGENT_SANDBOX_API_VERSION, KOBE_MANAGED_BY, SANDBOX_TEMPLATE_KIND, SANDBOX_WARM_POOL_KIND,
    build_sandbox_template, build_sandbox_warm_pool,
};

const WARM_POOL_LABEL: &str = "agents.x-k8s.io/warm-pool-sandbox";
const TEMPLATE_REF_HASH_LABEL: &str = "agents.x-k8s.io/sandbox-template-ref-hash";
const SANDBOX_HASH_LABEL: &str = "agents.x-k8s.io/sandbox";
const CERTIFICATION_POOL_UID_LABEL: &str = "kobe.kunobi.ninja/sandbox-pool-uid";
const CERTIFICATION_POOL_GENERATION_LABEL: &str = "kobe.kunobi.ninja/sandbox-pool-generation";
const TEARDOWN_FENCE_LABEL: &str = "kobe.kunobi.ninja/sandbox-teardown-fence";
const TEARDOWN_FENCE_FINALIZER: &str = "kobe.kunobi.ninja/sandbox-teardown-fence";
const TEARDOWN_FENCE_DENIAL_MESSAGE: &str =
    "Sandbox teardown has fenced descendant creation for this controller owner UID";
const REQUIRED_POOL_ACK_RELEASE: &str = "v0.5.6";
const POST_FENCE_MUTATION_BLOCKER: &str = "The exact teardown fence exists and its VAP denial was proven with a dry-run descendant CREATE. Agent Sandbox v0.5.6 exposes SandboxWarmPool.status.observedGeneration, but installing that fence does not increment the WarmPool generation. A causal drain ACK therefore requires the separately approved exact transition: UID/resourceVersion-fenced scale-to-zero, wait for that generation plus zero replicas, foreground-delete the sacrificial Claim, prove exact descendant/storage absence, restore capacity, prove clean new UIDs, then remove the fence. observedGeneration alone is not teardown or storage proof";

fn sandbox_resource() -> ApiResource {
    ApiResource {
        group: "agents.x-k8s.io".into(),
        version: "v1beta1".into(),
        api_version: SANDBOX_API_VERSION.into(),
        kind: SANDBOX_KIND.into(),
        plural: "sandboxes".into(),
    }
}

fn claim_resource() -> ApiResource {
    ApiResource {
        group: "extensions.agents.x-k8s.io".into(),
        version: "v1beta1".into(),
        api_version: AGENT_SANDBOX_API_VERSION.into(),
        kind: "SandboxClaim".into(),
        plural: "sandboxclaims".into(),
    }
}

fn management_object_name(pool: &SandboxPool) -> String {
    format!("kobe-{}", pool.name_any())
}

fn certification_claim_name(pool_uid: &str) -> String {
    let digest = hex::encode(Sha256::digest(pool_uid.as_bytes()));
    format!("kobe-cert-{}", &digest[..48])
}

fn certification_claim(
    pool: &SandboxPool,
    namespace: &str,
    warm_pool_name: &str,
) -> Result<DynamicObject, String> {
    let pool_uid = pool
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| "SandboxPool UID is missing".to_string())?;
    let pool_generation = pool
        .metadata
        .generation
        .ok_or_else(|| "SandboxPool generation is missing".to_string())?;
    let owner = pool
        .controller_owner_ref(&())
        .ok_or_else(|| "SandboxPool cannot own its certification Claim".to_string())?;
    Ok(DynamicObject {
        types: Some(TypeMeta {
            api_version: AGENT_SANDBOX_API_VERSION.to_string(),
            kind: "SandboxClaim".to_string(),
        }),
        metadata: ObjectMeta {
            name: Some(certification_claim_name(&pool_uid)),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner]),
            labels: Some(BTreeMap::from([
                (
                    "app.kubernetes.io/managed-by".to_string(),
                    KOBE_MANAGED_BY.to_string(),
                ),
                (CERTIFICATION_POOL_UID_LABEL.to_string(), pool_uid),
                (
                    CERTIFICATION_POOL_GENERATION_LABEL.to_string(),
                    pool_generation.to_string(),
                ),
            ])),
            ..ObjectMeta::default()
        },
        data: serde_json::json!({
            "spec": {
                "warmPoolRef": { "name": warm_pool_name },
                "lifecycle": { "shutdownPolicy": "DeleteForeground" }
            }
        }),
    })
}

fn exact_reference_matches(
    expected: &crate::crd::SandboxObjectReference,
    object: &DynamicObject,
    api_version: &str,
    kind: &str,
    namespace: &str,
    name: &str,
) -> bool {
    expected.api_version == api_version
        && expected.kind == kind
        && expected.namespace.as_deref() == Some(namespace)
        && expected.name == name
        && object.uid().as_deref() == Some(expected.uid.as_str())
        && expected
            .generation
            .is_none_or(|generation| object.metadata.generation == Some(generation))
}

fn validate_pool_object_identity(
    pool: &SandboxPool,
    namespace: &str,
    object: &DynamicObject,
    kind: &str,
    expected: Option<&crate::crd::SandboxObjectReference>,
) -> Result<String, String> {
    let pool_uid = pool
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| "SandboxPool UID is missing".to_string())?;
    let name = management_object_name(pool);
    let uid = object
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| format!("{kind} UID is missing"))?;
    if object.metadata.deletion_timestamp.is_some()
        || object.namespace().as_deref() != Some(namespace)
        || object.name_any() != name
        || !super::sandbox::metadata_is_controlled_by(
            &object.metadata,
            "kobe.kunobi.ninja/v1alpha1",
            "SandboxPool",
            &pool.name_any(),
            &pool_uid,
        )
    {
        return Err(format!(
            "{kind} is deleting, misplaced or not controlled by the exact SandboxPool"
        ));
    }
    if expected.is_some_and(|expected| {
        !exact_reference_matches(
            expected,
            object,
            AGENT_SANDBOX_API_VERSION,
            kind,
            namespace,
            &name,
        )
    }) {
        return Err(format!(
            "{kind} no longer matches the immutable lease provenance"
        ));
    }
    Ok(uid)
}

fn validate_pool_objects(
    pool: &SandboxPool,
    namespace: &str,
    template: &DynamicObject,
    warm_pool: &DynamicObject,
    expected_template: Option<&crate::crd::SandboxObjectReference>,
    expected_warm_pool: Option<&crate::crd::SandboxObjectReference>,
) -> Result<(String, String), String> {
    if pool.namespace().as_deref() != Some(namespace) {
        return Err("SandboxPool is outside the certified management namespace".into());
    }
    let template_uid = validate_pool_object_identity(
        pool,
        namespace,
        template,
        SANDBOX_TEMPLATE_KIND,
        expected_template,
    )?;
    let warm_pool_uid = validate_pool_object_identity(
        pool,
        namespace,
        warm_pool,
        SANDBOX_WARM_POOL_KIND,
        expected_warm_pool,
    )?;
    let owner = pool
        .controller_owner_ref(&())
        .ok_or_else(|| "SandboxPool cannot own its upstream objects".to_string())?;
    let name = management_object_name(pool);
    let desired_template = build_sandbox_template(&name, namespace, &pool.spec, Some(&owner))
        .map_err(|error| format!("could not project SandboxTemplate: {error}"))?;
    let desired_warm_pool = build_sandbox_warm_pool(
        &name,
        namespace,
        &name,
        pool.spec.warm_capacity,
        Some(&owner),
    )
    .map_err(|error| format!("could not project SandboxWarmPool: {error}"))?;
    if template.data.get("spec") != desired_template.data.get("spec") {
        return Err("SandboxTemplate spec drifted from the current Pool generation".into());
    }
    if warm_pool.data.get("spec") != desired_warm_pool.data.get("spec") {
        return Err("SandboxWarmPool spec drifted from the current Pool generation".into());
    }
    Ok((template_uid, warm_pool_uid))
}

/// The exact number of live, structurally certified idle Sandboxes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagementPoolCertification {
    pub ready: u32,
}

/// One restart-safe management certification reconcile result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementPoolCertificationProgress {
    pub status: SandboxPoolCertificationStatus,
    pub ready: u32,
    pub certified: bool,
    pub mutated: bool,
    pub reason: &'static str,
    pub message: String,
}

fn dynamic_reference(
    object: &DynamicObject,
    api_version: &str,
    kind: &str,
) -> Result<SandboxObjectReference, String> {
    Ok(SandboxObjectReference {
        api_version: api_version.into(),
        kind: kind.into(),
        namespace: object.metadata.namespace.clone(),
        name: object.name_any(),
        uid: object
            .uid()
            .filter(|uid| !uid.is_empty())
            .ok_or_else(|| format!("{kind} UID is missing"))?,
        generation: object.metadata.generation,
    })
}

fn typed_reference<K>(
    object: &K,
    api_version: &str,
    kind: &str,
) -> Result<SandboxObjectReference, String>
where
    K: Resource<DynamicType = ()> + ResourceExt,
{
    Ok(SandboxObjectReference {
        api_version: api_version.into(),
        kind: kind.into(),
        namespace: object.namespace(),
        name: object.name_any(),
        uid: object
            .uid()
            .filter(|uid| !uid.is_empty())
            .ok_or_else(|| format!("{kind} UID is missing"))?,
        generation: object.meta().generation,
    })
}

pub(super) fn certification_fingerprint(
    pool: &SandboxPool,
    template: &DynamicObject,
    warm_pool: &DynamicObject,
) -> Result<String, String> {
    let pool_uid = pool
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| "SandboxPool UID is missing".to_string())?;
    let generation = pool
        .metadata
        .generation
        .ok_or_else(|| "SandboxPool generation is missing".to_string())?;
    let evidence = serde_json::json!({
        "pool": { "uid": pool_uid, "generation": generation },
        "template": {
            "name": template.name_any(),
            "uid": template.uid(),
        },
        "warmPool": {
            "name": warm_pool.name_any(),
            "uid": warm_pool.uid(),
        },
        "runtime": {
            "release": REQUIRED_POOL_ACK_RELEASE,
            "controllerImage": crate::sandbox_runtime::AGENT_SANDBOX_CONTROLLER_IMAGE,
        },
        "probe": &pool.spec.readiness,
        "isolation": &pool.spec.isolation,
        "templateSpec": &pool.spec.template,
    });
    let encoded = serde_json::to_vec(&evidence)
        .map_err(|error| format!("could not encode certification fingerprint: {error}"))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn fence_name(fingerprint: &str) -> String {
    format!("kobe-cert-fence-{}", &fingerprint[..40])
}

fn certification_fence(
    namespace: &str,
    status: &SandboxPoolCertificationStatus,
) -> Result<ConfigMap, String> {
    let mut data = BTreeMap::new();
    for reference in [
        Some(&status.sandbox_warm_pool),
        status.sandbox_claim.as_ref(),
        status.sandbox.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        data.insert(reference.uid.clone(), "blocked".into());
    }
    if data.is_empty() {
        return Err("certification teardown fence has no exact controller owner UID".into());
    }
    Ok(ConfigMap {
        metadata: ObjectMeta {
            name: Some(fence_name(&status.fingerprint)),
            namespace: Some(namespace.into()),
            labels: Some(BTreeMap::from([(
                TEARDOWN_FENCE_LABEL.into(),
                "true".into(),
            )])),
            finalizers: Some(vec![TEARDOWN_FENCE_FINALIZER.into()]),
            ..ObjectMeta::default()
        },
        immutable: Some(true),
        data: Some(data),
        ..ConfigMap::default()
    })
}

async fn verify_teardown_fence_enforcement(
    client: &Client,
    namespace: &str,
    status: &SandboxPoolCertificationStatus,
) -> Result<bool, String> {
    let sandbox = status
        .sandbox
        .as_ref()
        .ok_or_else(|| "teardown fence has no exact Sandbox UID to probe".to_string())?;
    let probe = Pod {
        metadata: ObjectMeta {
            name: Some(format!("{}-probe", fence_name(&status.fingerprint))),
            namespace: Some(namespace.into()),
            owner_references: Some(vec![
                k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                    api_version: sandbox.api_version.clone(),
                    kind: sandbox.kind.clone(),
                    name: sandbox.name.clone(),
                    uid: sandbox.uid.clone(),
                    controller: Some(true),
                    block_owner_deletion: Some(true),
                },
            ]),
            ..ObjectMeta::default()
        },
        spec: Some(PodSpec {
            automount_service_account_token: Some(false),
            containers: vec![Container {
                name: "probe".into(),
                image: Some("registry.k8s.io/pause:3.10".into()),
                ..Container::default()
            }],
            enable_service_links: Some(false),
            restart_policy: Some("Never".into()),
            ..PodSpec::default()
        }),
        ..Pod::default()
    };
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let dry_run = PostParams {
        dry_run: true,
        ..PostParams::default()
    };
    match pods.create(&dry_run, &probe).await {
        Err(kube::Error::Api(response))
            if response.code == 403 && response.message.contains(TEARDOWN_FENCE_DENIAL_MESSAGE) =>
        {
            Ok(true)
        }
        // The ConfigMap parameter informer may not have observed a newly
        // created fence yet. A dry-run success persists nothing; retain the
        // exact fence reference and retry without crossing the barrier.
        Ok(_) => Ok(false),
        Err(error) => Err(format!(
            "teardown-fence VAP denial could not be proven by dry-run CREATE: {error}"
        )),
    }
}

fn dynamic_status_count(warm_pool: &DynamicObject, field: &str) -> Option<u32> {
    warm_pool
        .data
        .pointer(&format!("/status/{field}"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
}

fn warm_pool_status_is_current(warm_pool: &DynamicObject) -> bool {
    warm_pool.metadata.generation.is_some_and(|generation| {
        warm_pool
            .data
            .pointer("/status/observedGeneration")
            .and_then(serde_json::Value::as_i64)
            == Some(generation)
    })
}

fn object_has_controller_uid(meta: &ObjectMeta, owner_uids: &[String]) -> bool {
    meta.owner_references.as_ref().is_some_and(|owners| {
        owners.iter().any(|owner| {
            owner.controller == Some(true) && owner_uids.iter().any(|uid| uid == &owner.uid)
        })
    })
}

async fn capture_storage_manifest(
    client: &Client,
    namespace: &str,
    sandbox_uid: &str,
) -> Result<(Vec<SandboxObjectReference>, Vec<SandboxObjectReference>), String> {
    let pvcs: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), namespace);
    let pvs: Api<PersistentVolume> = Api::all(client.clone());
    let mut pvc_refs = Vec::new();
    for pvc in pvcs
        .list(&ListParams::default())
        .await
        .map_err(|error| format!("certification PVC manifest list failed: {error}"))?
    {
        if object_has_controller_uid(&pvc.metadata, &[sandbox_uid.to_string()]) {
            pvc_refs.push(typed_reference(&pvc, "v1", "PersistentVolumeClaim")?);
        }
    }
    pvc_refs.sort_by(|left, right| left.uid.cmp(&right.uid));
    let pvc_uids: Vec<&str> = pvc_refs
        .iter()
        .map(|reference| reference.uid.as_str())
        .collect();
    let mut pv_refs = Vec::new();
    for pv in pvs
        .list(&ListParams::default())
        .await
        .map_err(|error| format!("certification PV manifest list failed: {error}"))?
    {
        let bound_uid = pv
            .spec
            .as_ref()
            .and_then(|spec| spec.claim_ref.as_ref())
            .and_then(|claim| claim.uid.as_deref());
        if bound_uid.is_some_and(|uid| pvc_uids.contains(&uid)) {
            pv_refs.push(typed_reference(&pv, "v1", "PersistentVolume")?);
        }
    }
    pv_refs.sort_by(|left, right| left.uid.cmp(&right.uid));
    Ok((pvc_refs, pv_refs))
}

/// Exact v0.5.6 `NameHash`: FNV-1a rendered as eight lower-case hex digits.
pub(super) fn upstream_name_hash(value: &str) -> String {
    let mut hash = 2_166_136_261u32;
    for byte in value.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    format!("{hash:08x}")
}

fn dynamic_ready_at_generation(object: &DynamicObject) -> bool {
    let Some(generation) = object.metadata.generation else {
        return false;
    };
    object
        .data
        .get("status")
        .and_then(|status| status.get("conditions"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|conditions| {
            conditions.iter().any(|condition| {
                condition.get("type").and_then(serde_json::Value::as_str) == Some("Ready")
                    && condition.get("status").and_then(serde_json::Value::as_str) == Some("True")
                    && condition
                        .get("observedGeneration")
                        .and_then(serde_json::Value::as_i64)
                        == Some(generation)
            })
        })
}

fn pod_ready(pod: &Pod) -> bool {
    pod.metadata.deletion_timestamp.is_none()
        && pod
            .status
            .as_ref()
            .and_then(|status| status.conditions.as_ref())
            .is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|condition| condition.type_ == "Ready" && condition.status == "True")
            })
}

fn empty<T>(value: &Option<Vec<T>>) -> bool {
    value.as_ref().is_none_or(Vec::is_empty)
}

fn container_matches(expected: &Container, actual: &Container) -> bool {
    expected.name == actual.name
        && expected.image == actual.image
        && expected.command == actual.command
        && expected.args == actual.args
        && expected.ports == actual.ports
        && expected.resources == actual.resources
        && expected.security_context == actual.security_context
        && empty(&actual.env)
        && empty(&actual.env_from)
        && empty(&actual.volume_mounts)
        && empty(&actual.volume_devices)
}

fn expected_pod_spec(pool: &SandboxPool, namespace: &str) -> Result<PodSpec, String> {
    let template = build_sandbox_template("certification", namespace, &pool.spec, None)
        .map_err(|error| format!("could not project the restricted template: {error}"))?;
    let spec = template
        .data
        .get("spec")
        .and_then(|spec| spec.get("podTemplate"))
        .and_then(|template| template.get("spec"))
        .cloned()
        .ok_or_else(|| "restricted template has no Pod spec".to_string())?;
    serde_json::from_value(spec).map_err(|error| format!("invalid projected Pod spec: {error}"))
}

fn validate_pod_spec(expected: &PodSpec, actual: &PodSpec) -> Result<(), String> {
    if expected.runtime_class_name != actual.runtime_class_name {
        return Err("scheduled Pod does not use the exact pool RuntimeClass".into());
    }
    if actual.node_name.as_deref().is_none_or(str::is_empty) {
        return Err("Sandbox Pod is not scheduled to a node".into());
    }
    if expected.automount_service_account_token != actual.automount_service_account_token
        || expected.enable_service_links != actual.enable_service_links
        || expected.security_context != actual.security_context
        || expected.host_users != actual.host_users
        || actual.restart_policy.as_deref() != Some("Never")
    {
        return Err("Sandbox Pod security context drifted from the restricted projection".into());
    }
    if actual.host_network == Some(true)
        || actual.host_pid == Some(true)
        || actual.host_ipc == Some(true)
        || actual.share_process_namespace == Some(true)
        || !empty(&actual.volumes)
        || !empty(&actual.init_containers)
        || !empty(&actual.ephemeral_containers)
    {
        return Err(
            "Sandbox Pod contains a prohibited host, volume, init or ephemeral surface".into(),
        );
    }
    if expected.containers.len() != actual.containers.len()
        || expected
            .containers
            .iter()
            .zip(&actual.containers)
            .any(|(expected, actual)| !container_matches(expected, actual))
    {
        return Err("Sandbox Pod containers drifted from the closed pool template".into());
    }
    Ok(())
}

fn validate_pod_labels(
    pod: &Pod,
    sandbox_name: &str,
    template_name: &str,
    policy: &NetworkPolicy,
) -> Result<(), String> {
    let labels = pod.labels();
    if labels.get(SANDBOX_HASH_LABEL).map(String::as_str)
        != Some(upstream_name_hash(sandbox_name).as_str())
        || labels.get(TEMPLATE_REF_HASH_LABEL).map(String::as_str)
            != Some(upstream_name_hash(template_name).as_str())
        || !policy_selects_pod(policy, pod)
    {
        return Err(
            "Sandbox Pod is not selected by its exact Sandbox and strict Template policy labels"
                .into(),
        );
    }
    Ok(())
}

pub(super) fn expected_network_policy_spec(template_name: &str) -> NetworkPolicySpec {
    let selector = LabelSelector {
        match_labels: Some(BTreeMap::from([(
            TEMPLATE_REF_HASH_LABEL.to_string(),
            upstream_name_hash(template_name),
        )])),
        ..Default::default()
    };
    let router = NetworkPolicyPeer {
        namespace_selector: Some(LabelSelector {
            match_labels: Some(BTreeMap::from([(
                "kubernetes.io/metadata.name".into(),
                "agent-sandbox-system".into(),
            )])),
            ..Default::default()
        }),
        pod_selector: Some(LabelSelector {
            match_labels: Some(BTreeMap::from([("app".into(), "sandbox-router".into())])),
            ..Default::default()
        }),
        ..Default::default()
    };
    let public = |cidr: &str, except: &[&str]| NetworkPolicyPeer {
        ip_block: Some(IPBlock {
            cidr: cidr.into(),
            except: Some(except.iter().map(|value| (*value).to_string()).collect()),
        }),
        ..Default::default()
    };
    NetworkPolicySpec {
        pod_selector: Some(selector),
        policy_types: Some(vec!["Ingress".into(), "Egress".into()]),
        ingress: Some(vec![NetworkPolicyIngressRule {
            from: Some(vec![router]),
            ..Default::default()
        }]),
        egress: Some(vec![NetworkPolicyEgressRule {
            to: Some(vec![
                public(
                    "0.0.0.0/0",
                    &[
                        "10.0.0.0/8",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                        "169.254.0.0/16",
                    ],
                ),
                public("::/0", &["fc00::/7", "fe80::/10"]),
            ]),
            ..Default::default()
        }]),
    }
}

fn policy_selects_pod(policy: &NetworkPolicy, pod: &Pod) -> bool {
    let Some(selector) = policy
        .spec
        .as_ref()
        .and_then(|spec| spec.pod_selector.as_ref())
    else {
        return false;
    };
    if selector
        .match_expressions
        .as_ref()
        .is_some_and(|expressions| !expressions.is_empty())
    {
        return false;
    }
    let labels = pod.labels();
    selector.match_labels.as_ref().is_some_and(|required| {
        required
            .iter()
            .all(|(key, value)| labels.get(key) == Some(value))
    })
}

fn expected_service_ports(pool: &SandboxPool) -> Vec<(String, i32)> {
    let mut by_port = BTreeMap::<i32, String>::new();
    for container in &pool.spec.template.containers {
        for port in pool
            .spec
            .template
            .exposed_ports
            .iter()
            .filter(|port| port.container == container.name)
        {
            by_port
                .entry(i32::from(port.port))
                .or_insert_with(|| port.name.clone());
        }
    }
    by_port
        .into_iter()
        .map(|(port, name)| (name, port))
        .collect()
}

fn service_ports_match(actual: &[ServicePort], expected: &[(String, i32)]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.name.as_deref() == Some(expected.0.as_str())
                && actual
                    .protocol
                    .as_deref()
                    .is_none_or(|protocol| protocol == "TCP")
                && actual.port == expected.1
                && actual.target_port == Some(IntOrString::Int(expected.1))
                && actual.node_port.is_none()
                && actual.app_protocol.is_none()
        })
}

fn validate_service(
    pool: &SandboxPool,
    service: &Service,
    sandbox_name: &str,
    sandbox_uid: &str,
) -> Result<(), String> {
    let spec = service
        .spec
        .as_ref()
        .ok_or_else(|| "Sandbox Service spec is missing".to_string())?;
    let selector = BTreeMap::from([(
        SANDBOX_HASH_LABEL.to_string(),
        upstream_name_hash(sandbox_name),
    )]);
    let tracking_label = service.labels().get(SANDBOX_HASH_LABEL).cloned();
    if service.metadata.deletion_timestamp.is_some()
        || !super::sandbox::metadata_is_controlled_by(
            &service.metadata,
            SANDBOX_API_VERSION,
            SANDBOX_KIND,
            sandbox_name,
            sandbox_uid,
        )
        || tracking_label.as_deref() != selector.get(SANDBOX_HASH_LABEL).map(String::as_str)
        || spec.cluster_ip.as_deref() != Some("None")
        || spec.selector.as_ref() != Some(&selector)
        || spec
            .type_
            .as_deref()
            .is_some_and(|kind| kind != "ClusterIP")
        || spec.external_name.is_some()
        || spec
            .external_ips
            .as_ref()
            .is_some_and(|values| !values.is_empty())
        || spec.load_balancer_class.is_some()
        || spec.load_balancer_ip.is_some()
        || spec
            .load_balancer_source_ranges
            .as_ref()
            .is_some_and(|values| !values.is_empty())
        || spec.health_check_node_port.is_some()
        || spec.allocate_load_balancer_node_ports == Some(true)
        || spec.publish_not_ready_addresses == Some(true)
        || !service_ports_match(
            spec.ports.as_deref().unwrap_or_default(),
            &expected_service_ports(pool),
        )
    {
        return Err(
            "Sandbox Service is not the exact headless, internal-only template projection".into(),
        );
    }
    Ok(())
}

fn validate_node(node: &Node) -> Result<(), String> {
    if node.metadata.deletion_timestamp.is_some()
        || node
            .spec
            .as_ref()
            .is_some_and(|spec| spec.unschedulable == Some(true))
    {
        return Err("Sandbox Pod node is deleting or unschedulable".into());
    }
    let ready = node
        .status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .is_some_and(|conditions| {
            conditions
                .iter()
                .any(|condition| condition.type_ == "Ready" && condition.status == "True")
        });
    if !ready {
        return Err("Sandbox Pod node is not Ready".into());
    }
    Ok(())
}

fn validate_certification_claim(
    pool: &SandboxPool,
    desired: &DynamicObject,
    claim: &DynamicObject,
) -> Result<(), String> {
    let pool_uid = pool
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| "SandboxPool UID is missing".to_string())?;
    let pool_generation = pool
        .metadata
        .generation
        .ok_or_else(|| "SandboxPool generation is missing".to_string())?;
    if !super::sandbox::metadata_is_controlled_by(
        &claim.metadata,
        "kobe.kunobi.ninja/v1alpha1",
        "SandboxPool",
        &pool.name_any(),
        &pool_uid,
    ) {
        return Err("certification Claim is not controlled by the exact SandboxPool".into());
    }
    if claim.metadata.deletion_timestamp.is_some() {
        return Err("certification Claim is already deleting".into());
    }

    let observed_generation = claim
        .labels()
        .get(CERTIFICATION_POOL_GENERATION_LABEL)
        .and_then(|value| value.parse::<i64>().ok());
    if observed_generation != Some(pool_generation) {
        return Err("same-named certification Claim belongs to another Pool generation".into());
    }

    let labels = claim.labels();
    let required_labels = [
        ("app.kubernetes.io/managed-by", KOBE_MANAGED_BY),
        (CERTIFICATION_POOL_UID_LABEL, pool_uid.as_str()),
    ];
    let generation_label = pool_generation.to_string();
    if required_labels
        .iter()
        .any(|(key, value)| labels.get(*key).map(String::as_str) != Some(*value))
        || labels
            .get(CERTIFICATION_POOL_GENERATION_LABEL)
            .map(String::as_str)
            != Some(generation_label.as_str())
        || claim.data.get("spec") != desired.data.get("spec")
    {
        return Err("certification Claim metadata or spec drifted from the exact Pool".into());
    }
    Ok(())
}

async fn resolve_idle_sandbox(
    client: &Client,
    namespace: &str,
    sandbox: &DynamicObject,
) -> Result<ResolvedSandboxPod, String> {
    let sandbox_uid = sandbox
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| "WarmPool Sandbox UID is missing".to_string())?;
    let selector = sandbox
        .data
        .get("status")
        .and_then(|status| status.get("selector"))
        .and_then(serde_json::Value::as_str)
        .filter(|selector| !selector.is_empty())
        .ok_or_else(|| "Ready Sandbox has no Pod selector".to_string())?;
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let mut matching = pods
        .list(&ListParams::default().labels(selector))
        .await
        .map_err(|error| format!("Sandbox Pod list failed: {error}"))?
        .items;
    if matching.len() != 1 {
        return Err("Ready Sandbox does not resolve to exactly one Pod".into());
    }
    let pod = matching.remove(0);
    let pod_uid = pod
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| "Sandbox Pod UID is missing".to_string())?;
    if !super::sandbox::metadata_is_controlled_by(
        &pod.metadata,
        SANDBOX_API_VERSION,
        SANDBOX_KIND,
        &sandbox.name_any(),
        &sandbox_uid,
    ) {
        return Err("Sandbox Pod is not controlled by the exact Sandbox".into());
    }

    let service_name = sandbox
        .data
        .get("status")
        .and_then(|status| status.get("service"))
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.is_empty())
        .map(str::to_string);
    let service_uid = if let Some(name) = service_name.as_ref() {
        let services: Api<Service> = Api::namespaced(client.clone(), namespace);
        Some(
            services
                .get(name)
                .await
                .map_err(|error| format!("Sandbox Service lookup failed: {error}"))?
                .uid()
                .filter(|uid| !uid.is_empty())
                .ok_or_else(|| "Sandbox Service UID is missing".to_string())?,
        )
    } else {
        None
    };
    Ok(ResolvedSandboxPod {
        sandbox_name: sandbox.name_any(),
        sandbox_uid,
        pod_name: pod.name_any(),
        pod_uid,
        service_name,
        service_uid,
    })
}

struct WorkloadValidation<'a> {
    pool: &'a SandboxPool,
    template_name: &'a str,
    policy: &'a NetworkPolicy,
    expected_pod: &'a PodSpec,
}

async fn validate_resolved_workload(
    client: &Client,
    namespace: &str,
    validation: &WorkloadValidation<'_>,
    sandbox: &DynamicObject,
    resolved: &ResolvedSandboxPod,
) -> Result<(), String> {
    let WorkloadValidation {
        pool,
        template_name,
        policy,
        expected_pod,
    } = validation;
    if sandbox.name_any() != resolved.sandbox_name
        || sandbox.uid().as_deref() != Some(resolved.sandbox_uid.as_str())
        || sandbox.metadata.deletion_timestamp.is_some()
        || !dynamic_ready_at_generation(sandbox)
        || sandbox
            .labels()
            .get(TEMPLATE_REF_HASH_LABEL)
            .map(String::as_str)
            != Some(upstream_name_hash(template_name).as_str())
    {
        return Err("Sandbox is deleting, replaced or not Ready for the current generation".into());
    }
    let selector = sandbox
        .data
        .get("status")
        .and_then(|status| status.get("selector"))
        .and_then(serde_json::Value::as_str)
        .filter(|selector| !selector.is_empty())
        .ok_or_else(|| "Ready Sandbox has no Pod selector".to_string())?;
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let matching = pods
        .list(&ListParams::default().labels(selector))
        .await
        .map_err(|error| format!("Sandbox Pod revalidation failed: {error}"))?;
    if matching.items.len() != 1
        || matching.items[0].uid().as_deref() != Some(resolved.pod_uid.as_str())
    {
        return Err("Sandbox Pod selector no longer resolves to the exact single Pod".into());
    }
    let pod = &matching.items[0];
    if pod.name_any() != resolved.pod_name
        || !super::sandbox::metadata_is_controlled_by(
            &pod.metadata,
            SANDBOX_API_VERSION,
            SANDBOX_KIND,
            &resolved.sandbox_name,
            &resolved.sandbox_uid,
        )
        || !pod_ready(pod)
    {
        return Err("Sandbox Pod is foreign, deleting or not Ready".into());
    }
    validate_pod_labels(pod, &resolved.sandbox_name, template_name, policy)?;
    let pod_spec = pod
        .spec
        .as_ref()
        .ok_or_else(|| "Sandbox Pod spec is missing".to_string())?;
    validate_pod_spec(expected_pod, pod_spec)?;
    let node_name = pod_spec
        .node_name
        .as_deref()
        .expect("validated by Pod spec");
    let nodes: Api<Node> = Api::all(client.clone());
    let node = nodes
        .get(node_name)
        .await
        .map_err(|error| format!("Sandbox node lookup failed: {error}"))?;
    validate_node(&node)?;

    if pool.spec.template.exposed_ports.is_empty() {
        if resolved.service_name.is_some() || resolved.service_uid.is_some() {
            return Err("Sandbox unexpectedly exposes a Service".into());
        }
    } else {
        let (Some(service_name), Some(service_uid)) = (
            resolved.service_name.as_deref(),
            resolved.service_uid.as_deref(),
        ) else {
            return Err("Sandbox has no exact required Service identity".into());
        };
        let services: Api<Service> = Api::namespaced(client.clone(), namespace);
        let service = services
            .get(service_name)
            .await
            .map_err(|error| format!("Sandbox Service revalidation failed: {error}"))?;
        if service.uid().as_deref() != Some(service_uid) {
            return Err("Sandbox Service was replaced before certification".into());
        }
        validate_service(
            pool,
            &service,
            &resolved.sandbox_name,
            &resolved.sandbox_uid,
        )?;
    }
    Ok(())
}

#[derive(Debug)]
struct ValidatedPopulation {
    ready: u32,
    baseline_idle_sandbox_uids: Vec<String>,
    policy: NetworkPolicy,
    expected_pod: PodSpec,
}

/// Validate the immutable pool objects and every currently idle member without
/// allocating or executing in capacity. This proof is repeated at the final
/// tenant Claim gate; only the durable certification receipt authorizes use.
async fn validate_management_population(
    client: &Client,
    namespace: &str,
    pool: &SandboxPool,
    template: &DynamicObject,
    warm_pool: &DynamicObject,
    expected_template: Option<&crate::crd::SandboxObjectReference>,
    expected_warm_pool: Option<&crate::crd::SandboxObjectReference>,
) -> Result<ValidatedPopulation, String> {
    if !matches!(pool.spec.isolation, SandboxIsolation::TrustedRunc {}) {
        return Err(
            "gVisor and Kata remain unqualified until isolation issue #14 is closed".into(),
        );
    }
    crate::sandbox_runtime::validate_runtime_components(client)
        .await
        .map_err(|error| format!("runtime components are not certified: {error}"))?;

    let (template_uid, warm_pool_uid) = validate_pool_objects(
        pool,
        namespace,
        template,
        warm_pool,
        expected_template,
        expected_warm_pool,
    )?;
    let desired = pool.spec.warm_capacity;
    let status = warm_pool
        .data
        .get("status")
        .ok_or_else(|| "SandboxWarmPool status is missing".to_string())?;
    let replicas = status
        .get("replicas")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    let ready = status
        .get("readyReplicas")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    let expected_selector = format!(
        "{WARM_POOL_LABEL}={}",
        upstream_name_hash(&warm_pool.name_any())
    );
    if !warm_pool_status_is_current(warm_pool)
        || replicas != Some(desired)
        || ready != Some(desired)
        || status.get("selector").and_then(serde_json::Value::as_str)
            != Some(expected_selector.as_str())
    {
        return Err(
            "SandboxWarmPool has not observed its current generation and converged to its exact desired Ready population".into(),
        );
    }

    let network_policies: Api<NetworkPolicy> = Api::namespaced(client.clone(), namespace);
    let policy = network_policies
        .get(&format!("{}-network-policy", template.name_any()))
        .await
        .map_err(|error| format!("strict NetworkPolicy lookup failed: {error}"))?;
    if policy.metadata.deletion_timestamp.is_some()
        || policy.uid().is_none_or(|uid| uid.is_empty())
        || !super::sandbox::metadata_is_controlled_by(
            &policy.metadata,
            AGENT_SANDBOX_API_VERSION,
            SANDBOX_TEMPLATE_KIND,
            &template.name_any(),
            &template_uid,
        )
        || policy.spec.as_ref() != Some(&expected_network_policy_spec(&template.name_any()))
    {
        return Err("the exact Template-owned strict NetworkPolicy is absent or drifted".into());
    }

    let sandboxes: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), namespace, &sandbox_resource());
    let sandboxes = sandboxes
        .list(&ListParams::default().labels(&expected_selector))
        .await
        .map_err(|error| format!("WarmPool Sandbox list failed: {error}"))?;
    if sandboxes.items.len() != usize::try_from(desired).unwrap_or(usize::MAX) {
        return Err("WarmPool status count does not match its exact live Sandbox list".into());
    }

    let expected_pod = expected_pod_spec(pool, namespace)?;
    let mut baseline_idle_sandbox_uids = Vec::with_capacity(sandboxes.items.len());
    for sandbox in sandboxes {
        if sandbox.metadata.deletion_timestamp.is_some()
            || !super::sandbox::metadata_is_controlled_by(
                &sandbox.metadata,
                AGENT_SANDBOX_API_VERSION,
                SANDBOX_WARM_POOL_KIND,
                &warm_pool.name_any(),
                &warm_pool_uid,
            )
            || !dynamic_ready_at_generation(&sandbox)
        {
            return Err("WarmPool contains a deleting, foreign or stale-ready Sandbox".into());
        }
        if sandbox
            .labels()
            .get(TEMPLATE_REF_HASH_LABEL)
            .map(String::as_str)
            != Some(upstream_name_hash(&template.name_any()).as_str())
        {
            return Err("WarmPool Sandbox does not identify the current Template".into());
        }
        let resolved = resolve_idle_sandbox(client, namespace, &sandbox).await?;
        validate_resolved_workload(
            client,
            namespace,
            &WorkloadValidation {
                pool,
                template_name: &template.name_any(),
                policy: &policy,
                expected_pod: &expected_pod,
            },
            &sandbox,
            &resolved,
        )
        .await?;
        baseline_idle_sandbox_uids.push(
            sandbox
                .uid()
                .filter(|uid| !uid.is_empty())
                .ok_or_else(|| "WarmPool Sandbox UID is missing".to_string())?,
        );
    }
    baseline_idle_sandbox_uids.sort();
    Ok(ValidatedPopulation {
        ready: desired,
        baseline_idle_sandbox_uids,
        policy,
        expected_pod,
    })
}

fn initialized_status(
    pool: &SandboxPool,
    template: &DynamicObject,
    warm_pool: &DynamicObject,
    fingerprint: String,
    baseline_idle_sandbox_uids: Vec<String>,
) -> Result<SandboxPoolCertificationStatus, String> {
    Ok(SandboxPoolCertificationStatus {
        fingerprint,
        observed_generation: pool
            .metadata
            .generation
            .ok_or_else(|| "SandboxPool generation is missing".to_string())?,
        phase: SandboxPoolCertificationPhase::Initialized,
        sandbox_template: dynamic_reference(
            template,
            AGENT_SANDBOX_API_VERSION,
            SANDBOX_TEMPLATE_KIND,
        )?,
        sandbox_warm_pool: dynamic_reference(
            warm_pool,
            AGENT_SANDBOX_API_VERSION,
            SANDBOX_WARM_POOL_KIND,
        )?,
        sandbox_claim: None,
        sandbox: None,
        pod: None,
        service: None,
        persistent_volume_claims: vec![],
        persistent_volumes: vec![],
        teardown_fence: None,
        baseline_idle_sandbox_uids,
        drain_generation: None,
        replenish_generation: None,
        canary_passed_at: None,
        certified_at: None,
        message: None,
    })
}

fn progress(
    status: SandboxPoolCertificationStatus,
    ready: u32,
    certified: bool,
    mutated: bool,
    reason: &'static str,
    message: impl Into<String>,
) -> ManagementPoolCertificationProgress {
    ManagementPoolCertificationProgress {
        status,
        ready,
        certified,
        mutated,
        reason,
        message: message.into(),
    }
}

fn cleanup_blocked(
    mut status: SandboxPoolCertificationStatus,
    ready: u32,
    message: impl Into<String>,
) -> ManagementPoolCertificationProgress {
    let message = message.into();
    status.phase = SandboxPoolCertificationPhase::CleanupBlocked;
    status.message = Some(message.clone());
    progress(status, ready, false, false, "CleanupBlocked", message)
}

fn attempt_has_live_cleanup(status: &SandboxPoolCertificationStatus) -> bool {
    status.phase != SandboxPoolCertificationPhase::Certified
        && (status.sandbox_claim.is_some()
            || status.sandbox.is_some()
            || status.teardown_fence.is_some())
}

fn reference_from_resolved(
    resolved: &ResolvedSandboxPod,
    namespace: &str,
) -> (SandboxObjectReference, Option<SandboxObjectReference>) {
    let pod = SandboxObjectReference {
        api_version: "v1".into(),
        kind: "Pod".into(),
        namespace: Some(namespace.into()),
        name: resolved.pod_name.clone(),
        uid: resolved.pod_uid.clone(),
        generation: None,
    };
    let service = resolved
        .service_name
        .as_ref()
        .zip(resolved.service_uid.as_ref())
        .map(|(name, uid)| SandboxObjectReference {
            api_version: "v1".into(),
            kind: "Service".into(),
            namespace: Some(namespace.into()),
            name: name.clone(),
            uid: uid.clone(),
            generation: None,
        });
    (pod, service)
}

/// Re-read every captured workload identity before executing or fencing it.
///
/// The Claim may stay Ready while its Sandbox, Pod or Service is replaced.
/// Treat any such ambiguity as cleanup-blocking so the later absence proof can
/// never address an obsolete UID while a replacement remains live.
async fn revalidate_captured_workload(
    client: &Client,
    namespace: &str,
    pool: &SandboxPool,
    template_name: &str,
    status: &SandboxPoolCertificationStatus,
    policy: &NetworkPolicy,
    expected_pod: &PodSpec,
) -> Result<ResolvedSandboxPod, String> {
    let (Some(recorded_claim), Some(recorded_sandbox), Some(recorded_pod)) = (
        status.sandbox_claim.as_ref(),
        status.sandbox.as_ref(),
        status.pod.as_ref(),
    ) else {
        return Err(
            "captured certification workload is missing an exact Claim, Sandbox or Pod reference"
                .into(),
        );
    };
    let claims: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), namespace, &claim_resource());
    let claim = claims
        .get(&recorded_claim.name)
        .await
        .map_err(|error| format!("captured certification Claim cannot be proven: {error}"))?;
    if !exact_reference_matches(
        recorded_claim,
        &claim,
        AGENT_SANDBOX_API_VERSION,
        "SandboxClaim",
        namespace,
        &recorded_claim.name,
    ) || !dynamic_ready_at_generation(&claim)
    {
        return Err("captured certification Claim changed or is no longer current Ready".into());
    }

    let sandboxes: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), namespace, &sandbox_resource());
    let sandbox = sandboxes
        .get(&recorded_sandbox.name)
        .await
        .map_err(|error| format!("captured certification Sandbox cannot be proven: {error}"))?;
    if !exact_reference_matches(
        recorded_sandbox,
        &sandbox,
        SANDBOX_API_VERSION,
        SANDBOX_KIND,
        namespace,
        &recorded_sandbox.name,
    ) {
        return Err("captured certification Sandbox was replaced".into());
    }

    let resolved = resolve_sandbox_pod(client, namespace, &claim)
        .await?
        .ok_or_else(|| "captured certification Claim has no exact Ready workload".to_string())?;
    if resolved.sandbox_name != recorded_sandbox.name
        || resolved.sandbox_uid != recorded_sandbox.uid
        || resolved.pod_name != recorded_pod.name
        || resolved.pod_uid != recorded_pod.uid
    {
        return Err("captured certification Sandbox or Pod identity changed".into());
    }
    match (
        status.service.as_ref(),
        resolved.service_name.as_deref(),
        resolved.service_uid.as_deref(),
    ) {
        (None, None, None) => {}
        (Some(recorded), Some(name), Some(uid)) if recorded.name == name && recorded.uid == uid => {
        }
        _ => return Err("captured certification Service identity changed".into()),
    }
    validate_resolved_workload(
        client,
        namespace,
        &WorkloadValidation {
            pool,
            template_name,
            policy,
            expected_pod,
        },
        &sandbox,
        &resolved,
    )
    .await?;
    let (pvcs, pvs) = capture_storage_manifest(client, namespace, &recorded_sandbox.uid).await?;
    if pvcs != status.persistent_volume_claims || pvs != status.persistent_volumes {
        return Err("captured certification PVC/PV identity manifest changed".into());
    }
    Ok(resolved)
}

/// Advance at most one durable certification transition.
///
/// Agent Sandbox v0.5.6 supplies the `observedGeneration` needed for a causal
/// WarmPool barrier, but the fence itself does not bump that generation. Until
/// the explicitly approved scale-to-zero/delete/restore transition is wired,
/// the state machine stops fail-closed with the exact Claim and immutable fence
/// retained. It must not approximate the barrier with a sleep or list.
pub async fn reconcile_management_pool_certification(
    client: &Client,
    namespace: &str,
    pool: &SandboxPool,
    template: &DynamicObject,
    warm_pool: &DynamicObject,
) -> Result<ManagementPoolCertificationProgress, String> {
    if crate::sandbox_runtime::AGENT_SANDBOX_RELEASE != REQUIRED_POOL_ACK_RELEASE {
        return Err(format!(
            "durable pool certification requires Agent Sandbox {REQUIRED_POOL_ACK_RELEASE} for SandboxWarmPool.status.observedGeneration; this build pins {}",
            crate::sandbox_runtime::AGENT_SANDBOX_RELEASE
        ));
    }
    let existing = pool
        .status
        .as_ref()
        .and_then(|status| status.certification.clone());
    let reduced_validation = existing.as_ref().is_some_and(|status| {
        matches!(
            status.phase,
            SandboxPoolCertificationPhase::FenceInstalled
                | SandboxPoolCertificationPhase::DrainAcknowledged
                | SandboxPoolCertificationPhase::ClaimDeleting
                | SandboxPoolCertificationPhase::AbsenceProven
                | SandboxPoolCertificationPhase::Replenished
                | SandboxPoolCertificationPhase::FenceFinalizerRemoved
                | SandboxPoolCertificationPhase::FenceDeleting
                | SandboxPoolCertificationPhase::CleanupBlocked
        )
    });
    let validated = if reduced_validation {
        if !matches!(pool.spec.isolation, SandboxIsolation::TrustedRunc {}) {
            return Err(
                "gVisor and Kata remain unqualified until isolation issue #14 is closed".into(),
            );
        }
        crate::sandbox_runtime::validate_runtime_components(client)
            .await
            .map_err(|error| format!("runtime components are not certified: {error}"))?;
        let current = existing.as_ref().expect("reduced validation has status");
        validate_pool_object_identity(
            pool,
            namespace,
            template,
            SANDBOX_TEMPLATE_KIND,
            Some(&current.sandbox_template),
        )?;
        let mut warm_pool_identity = current.sandbox_warm_pool.clone();
        warm_pool_identity.generation = None;
        validate_pool_object_identity(
            pool,
            namespace,
            warm_pool,
            SANDBOX_WARM_POOL_KIND,
            Some(&warm_pool_identity),
        )?;
        ValidatedPopulation {
            ready: dynamic_status_count(warm_pool, "readyReplicas").unwrap_or_default(),
            baseline_idle_sandbox_uids: current.baseline_idle_sandbox_uids.clone(),
            policy: NetworkPolicy::default(),
            expected_pod: PodSpec::default(),
        }
    } else {
        validate_management_population(client, namespace, pool, template, warm_pool, None, None)
            .await?
    };
    let fingerprint = certification_fingerprint(pool, template, warm_pool)?;
    let fresh = initialized_status(
        pool,
        template,
        warm_pool,
        fingerprint.clone(),
        validated.baseline_idle_sandbox_uids.clone(),
    )?;
    let Some(mut status) = existing else {
        return Ok(progress(
            fresh,
            validated.ready,
            false,
            false,
            "CertificationInitialized",
            "checkpointed exact Template/WarmPool identity before creating the certification Claim",
        ));
    };

    if status.fingerprint != fingerprint
        || status.observed_generation != fresh.observed_generation
        || status.sandbox_template.uid != fresh.sandbox_template.uid
        || status.sandbox_template.name != fresh.sandbox_template.name
        || status.sandbox_warm_pool.uid != fresh.sandbox_warm_pool.uid
        || status.sandbox_warm_pool.name != fresh.sandbox_warm_pool.name
    {
        if attempt_has_live_cleanup(&status) {
            return Ok(cleanup_blocked(
                status,
                validated.ready,
                "Pool generation or exact upstream identity changed during certification; retained the old attempt for exact cleanup",
            ));
        }
        return Ok(progress(
            fresh,
            validated.ready,
            false,
            false,
            "CertificationRestarted",
            "restarted certification from the current exact Pool generation",
        ));
    }

    let claims: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), namespace, &claim_resource());
    let desired_claim = certification_claim(pool, namespace, &warm_pool.name_any())?;

    match status.phase {
        SandboxPoolCertificationPhase::Initialized => {
            match claims.get(&desired_claim.name_any()).await {
                Ok(claim) => {
                    if let Err(error) = validate_certification_claim(pool, &desired_claim, &claim) {
                        return Ok(cleanup_blocked(status, validated.ready, error));
                    }
                    status.sandbox_claim = Some(dynamic_reference(
                        &claim,
                        AGENT_SANDBOX_API_VERSION,
                        "SandboxClaim",
                    )?);
                    status.phase = SandboxPoolCertificationPhase::ClaimCreated;
                    status.message = None;
                    Ok(progress(
                        status,
                        validated.ready,
                        false,
                        false,
                        "CertificationClaimCreated",
                        "checkpointed the exact sacrificial SandboxClaim",
                    ))
                }
                Err(kube::Error::Api(error)) if error.code == 404 => {
                    claims
                        .create(&PostParams::default(), &desired_claim)
                        .await
                        .map_err(|error| format!("certification Claim create failed: {error}"))?;
                    Ok(progress(
                        status,
                        validated.ready,
                        false,
                        true,
                        "CertificationClaimCreating",
                        "created the deterministic sacrificial SandboxClaim; identity will be checkpointed on the next reconcile",
                    ))
                }
                Err(kube::Error::Api(error)) if error.code == 403 => Ok(cleanup_blocked(
                    status,
                    validated.ready,
                    format!("certification Claim lookup is forbidden: {error}"),
                )),
                Err(error) => Err(format!("certification Claim lookup failed: {error}")),
            }
        }
        SandboxPoolCertificationPhase::ClaimCreated => {
            let Some(recorded_claim) = status.sandbox_claim.as_ref() else {
                return Ok(cleanup_blocked(
                    status,
                    validated.ready,
                    "ClaimCreated checkpoint has no exact SandboxClaim reference",
                ));
            };
            let claim = match claims.get(&recorded_claim.name).await {
                Ok(claim) => claim,
                Err(kube::Error::Api(error)) if error.code == 404 || error.code == 403 => {
                    return Ok(cleanup_blocked(
                        status,
                        validated.ready,
                        format!("recorded certification Claim cannot be proven: {error}"),
                    ));
                }
                Err(error) => return Err(format!("certification Claim lookup failed: {error}")),
            };
            if !exact_reference_matches(
                recorded_claim,
                &claim,
                AGENT_SANDBOX_API_VERSION,
                "SandboxClaim",
                namespace,
                &recorded_claim.name,
            ) {
                return Ok(cleanup_blocked(
                    status,
                    validated.ready,
                    "recorded certification Claim was replaced or changed identity",
                ));
            }
            if !dynamic_ready_at_generation(&claim) {
                return Ok(progress(
                    status,
                    validated.ready,
                    false,
                    false,
                    "CertificationClaimPending",
                    "waiting for the exact certification Claim to become Ready",
                ));
            }
            let resolved = resolve_sandbox_pod(client, namespace, &claim)
                .await?
                .ok_or_else(|| {
                    "dedicated certification Claim has no exact Ready workload".to_string()
                })?;
            let sandboxes: Api<DynamicObject> =
                Api::namespaced_with(client.clone(), namespace, &sandbox_resource());
            let sandbox = match sandboxes.get(&resolved.sandbox_name).await {
                Ok(sandbox) => sandbox,
                Err(error) => {
                    return Ok(cleanup_blocked(
                        status,
                        validated.ready,
                        format!("certification Sandbox cannot be proven: {error}"),
                    ));
                }
            };
            if let Err(error) = validate_resolved_workload(
                client,
                namespace,
                &WorkloadValidation {
                    pool,
                    template_name: &template.name_any(),
                    policy: &validated.policy,
                    expected_pod: &validated.expected_pod,
                },
                &sandbox,
                &resolved,
            )
            .await
            {
                return Ok(cleanup_blocked(status, validated.ready, error));
            }
            let (pod, service) = reference_from_resolved(&resolved, namespace);
            status.sandbox = Some(dynamic_reference(
                &sandbox,
                SANDBOX_API_VERSION,
                SANDBOX_KIND,
            )?);
            status.pod = Some(pod);
            status.service = service;
            let (pvcs, pvs) =
                capture_storage_manifest(client, namespace, &resolved.sandbox_uid).await?;
            status.persistent_volume_claims = pvcs;
            status.persistent_volumes = pvs;
            status.phase = SandboxPoolCertificationPhase::WorkloadCaptured;
            status.message = None;
            Ok(progress(
                status,
                validated.ready,
                false,
                false,
                "CertificationWorkloadCaptured",
                "checkpointed exact Claim, Sandbox, Pod and Service identities",
            ))
        }
        SandboxPoolCertificationPhase::WorkloadCaptured => {
            let target = match revalidate_captured_workload(
                client,
                namespace,
                pool,
                &template.name_any(),
                &status,
                &validated.policy,
                &validated.expected_pod,
            )
            .await
            {
                Ok(target) => target,
                Err(error) => return Ok(cleanup_blocked(status, validated.ready, error)),
            };
            match run_canary(
                client,
                namespace,
                &target,
                &pool.spec.template.default_container,
                &pool.spec.readiness.canary,
            )
            .await
            {
                CanaryOutcome::Passed => {
                    status.phase = SandboxPoolCertificationPhase::CanaryPassed;
                    status.canary_passed_at = Some(chrono::Utc::now().to_rfc3339());
                    status.message = None;
                    Ok(progress(
                        status,
                        validated.ready,
                        false,
                        false,
                        "CertificationCanaryPassed",
                        "the bounded execution canary passed in the exact sacrificial workload",
                    ))
                }
                CanaryOutcome::Failed { reason } | CanaryOutcome::Inconclusive { reason } => {
                    Ok(cleanup_blocked(
                        status,
                        validated.ready,
                        format!("pool execution canary did not pass: {reason}"),
                    ))
                }
            }
        }
        SandboxPoolCertificationPhase::CanaryPassed => {
            if let Err(error) = revalidate_captured_workload(
                client,
                namespace,
                pool,
                &template.name_any(),
                &status,
                &validated.policy,
                &validated.expected_pod,
            )
            .await
            {
                return Ok(cleanup_blocked(status, validated.ready, error));
            }
            let desired_fence = certification_fence(namespace, &status)?;
            let fences: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
            match fences.get(&desired_fence.name_any()).await {
                Ok(fence) => {
                    if fence.metadata.deletion_timestamp.is_some()
                        || fence.immutable != Some(true)
                        || fence.data != desired_fence.data
                        || fence.labels().get(TEARDOWN_FENCE_LABEL).map(String::as_str)
                            != Some("true")
                        || !fence
                            .finalizers()
                            .iter()
                            .any(|value| value == TEARDOWN_FENCE_FINALIZER)
                    {
                        return Ok(cleanup_blocked(
                            status,
                            validated.ready,
                            "same-named certification teardown fence is deleting or drifted",
                        ));
                    }
                    status.teardown_fence = Some(typed_reference(&fence, "v1", "ConfigMap")?);
                    match verify_teardown_fence_enforcement(client, namespace, &status).await {
                        Ok(true) => {}
                        Ok(false) => {
                            status.message = Some(
                                "waiting for the teardown-fence VAP parameter informer to deny the exact dry-run descendant CREATE"
                                    .into(),
                            );
                            return Ok(progress(
                                status,
                                validated.ready,
                                false,
                                false,
                                "CertificationFencePropagationPending",
                                "teardown fence exists but its exact VAP denial is not observable yet",
                            ));
                        }
                        Err(error) => {
                            return Ok(cleanup_blocked(status, validated.ready, error));
                        }
                    }
                    status.phase = SandboxPoolCertificationPhase::FenceInstalled;
                    status.message = None;
                    Ok(progress(
                        status,
                        validated.ready,
                        false,
                        false,
                        "CertificationFenceInstalled",
                        "checkpointed the immutable exact-UID teardown fence after proving its VAP denial",
                    ))
                }
                Err(kube::Error::Api(error)) if error.code == 404 => {
                    fences
                        .create(&PostParams::default(), &desired_fence)
                        .await
                        .map_err(|error| format!("certification fence create failed: {error}"))?;
                    Ok(progress(
                        status,
                        validated.ready,
                        false,
                        true,
                        "CertificationFenceCreating",
                        "created the immutable exact-UID teardown fence; identity will be checkpointed on the next reconcile",
                    ))
                }
                Err(kube::Error::Api(error)) if error.code == 403 => Ok(cleanup_blocked(
                    status,
                    validated.ready,
                    format!("certification fence lookup is forbidden: {error}"),
                )),
                Err(error) => Err(format!("certification fence lookup failed: {error}")),
            }
        }
        SandboxPoolCertificationPhase::FenceInstalled => Ok(cleanup_blocked(
            status,
            validated.ready,
            POST_FENCE_MUTATION_BLOCKER,
        )),
        SandboxPoolCertificationPhase::Certified => {
            status.message = None;
            Ok(progress(
                status,
                validated.ready,
                true,
                false,
                "Certified",
                "current-generation exact pool certification receipt is valid",
            ))
        }
        SandboxPoolCertificationPhase::CleanupBlocked => Ok(progress(
            status.clone(),
            validated.ready,
            false,
            false,
            "CleanupBlocked",
            status
                .message
                .clone()
                .unwrap_or_else(|| "certification cleanup is blocked".into()),
        )),
        SandboxPoolCertificationPhase::DrainAcknowledged
        | SandboxPoolCertificationPhase::ClaimDeleting
        | SandboxPoolCertificationPhase::AbsenceProven
        | SandboxPoolCertificationPhase::Replenished
        | SandboxPoolCertificationPhase::FenceFinalizerRemoved
        | SandboxPoolCertificationPhase::FenceDeleting => Ok(cleanup_blocked(
            status,
            validated.ready,
            "unsupported certification phase was observed without the approved v0.5.6 causal drain transition",
        )),
    }
}

/// Revalidate a completed receipt at the final tenant Claim gate. This never
/// creates a sacrificial Claim or re-runs its canary.
pub async fn revalidate_certified_management_pool(
    client: &Client,
    namespace: &str,
    pool: &SandboxPool,
    template: &DynamicObject,
    warm_pool: &DynamicObject,
    expected_template: Option<&SandboxObjectReference>,
    expected_warm_pool: Option<&SandboxObjectReference>,
) -> Result<ManagementPoolCertification, String> {
    let receipt = pool
        .status
        .as_ref()
        .and_then(|status| status.certification.as_ref())
        .ok_or_else(|| "SandboxPool has no durable certification receipt".to_string())?;
    if receipt.phase != SandboxPoolCertificationPhase::Certified
        || receipt.observed_generation != pool.metadata.generation.unwrap_or_default()
        || receipt.fingerprint != certification_fingerprint(pool, template, warm_pool)?
    {
        return Err("SandboxPool certification receipt is not current and Certified".into());
    }
    let mut warm_pool_reference = expected_warm_pool
        .cloned()
        .unwrap_or_else(|| receipt.sandbox_warm_pool.clone());
    // Certification itself advances WarmPool generation for the causal drain
    // and clean restore. The immutable UID remains the authority; the receipt
    // carries the final generation once that transition is approved/wired.
    if receipt.replenish_generation.is_some() {
        warm_pool_reference.generation = receipt.replenish_generation;
    }
    let population = validate_management_population(
        client,
        namespace,
        pool,
        template,
        warm_pool,
        expected_template.or(Some(&receipt.sandbox_template)),
        Some(&warm_pool_reference),
    )
    .await?;
    Ok(ManagementPoolCertification {
        ready: population.ready,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::ServiceSpec;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn pool(warm_capacity: u32) -> SandboxPool {
        SandboxPool {
            metadata: ObjectMeta {
                name: Some("agents".into()),
                namespace: Some("kobe-system".into()),
                uid: Some("11111111-1111-4111-8111-111111111111".into()),
                generation: Some(7),
                ..ObjectMeta::default()
            },
            spec: serde_json::from_value(serde_json::json!({
                "warmCapacity": warm_capacity,
                "defaultTtl": "1h",
                "maxTtl": "8h",
                "provisioningTimeout": "10m",
                "placement": { "type": "management" },
                "template": {
                    "defaultContainer": "agent",
                    "containers": [{
                        "name": "agent",
                        "image": "example.invalid/agent@sha256:abc",
                        "command": ["/agent"],
                        "resources": {
                            "requests": {
                                "cpu": "100m", "memory": "128Mi", "ephemeralStorage": "128Mi"
                            },
                            "limits": {
                                "cpu": "1", "memory": "1Gi", "ephemeralStorage": "1Gi"
                            }
                        }
                    }],
                    "exposedPorts": [{ "name": "http", "container": "agent", "port": 3000 }]
                },
                "isolation": { "tier": "trusted-runc" },
                "readiness": {
                    "canary": { "argv": ["/agent", "health"], "timeout": "30s" }
                }
            }))
            .unwrap(),
            status: None,
        }
    }

    fn controller_owner(kind: &str, name: &str, uid: &str) -> OwnerReference {
        OwnerReference {
            api_version: if kind == "Sandbox" {
                SANDBOX_API_VERSION.into()
            } else {
                "kobe.kunobi.ninja/v1alpha1".into()
            },
            kind: kind.into(),
            name: name.into(),
            uid: uid.into(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }
    }

    #[test]
    fn upstream_hash_is_pinned_to_v0_5_6() {
        assert_eq!(upstream_name_hash("kobe-agents"), "8bc6ef7b");
    }

    #[test]
    fn default_network_policy_is_exactly_strict() {
        let spec = expected_network_policy_spec("kobe-agents");
        assert_eq!(
            spec.pod_selector
                .as_ref()
                .and_then(|selector| selector.match_labels.as_ref())
                .and_then(|labels| labels.get(TEMPLATE_REF_HASH_LABEL)),
            Some(&upstream_name_hash("kobe-agents"))
        );
        assert_eq!(spec.ingress.as_ref().map(Vec::len), Some(1));
        assert_eq!(spec.egress.as_ref().map(Vec::len), Some(1));
        assert_eq!(
            spec.policy_types,
            Some(vec!["Ingress".into(), "Egress".into()])
        );
    }

    #[test]
    fn certification_claim_is_exclusive_and_warm_zero_compatible() {
        let pool = pool(0);
        let claim = certification_claim(&pool, "kobe-system", "kobe-agents").unwrap();
        assert!(claim.name_any().len() <= 63);
        assert_eq!(claim.namespace().as_deref(), Some("kobe-system"));
        assert!(super::super::sandbox::metadata_is_controlled_by(
            &claim.metadata,
            "kobe.kunobi.ninja/v1alpha1",
            "SandboxPool",
            "agents",
            "11111111-1111-4111-8111-111111111111",
        ));
        assert_eq!(
            claim
                .labels()
                .get(CERTIFICATION_POOL_GENERATION_LABEL)
                .map(String::as_str),
            Some("7")
        );
        assert_eq!(
            claim
                .data
                .pointer("/spec/warmPoolRef/name")
                .and_then(serde_json::Value::as_str),
            Some("kobe-agents")
        );
        assert!(claim.data.pointer("/spec/lifecycle/shutdownTime").is_none());
    }

    #[test]
    fn immutable_pool_refs_reject_same_name_replacements() {
        let pool = pool(1);
        let owner = pool.controller_owner_ref(&()).unwrap();
        let mut template =
            build_sandbox_template("kobe-agents", "kobe-system", &pool.spec, Some(&owner)).unwrap();
        template.metadata.uid = Some("template-uid".into());
        template.metadata.generation = Some(2);
        let mut warm_pool =
            build_sandbox_warm_pool("kobe-agents", "kobe-system", "kobe-agents", 1, Some(&owner))
                .unwrap();
        warm_pool.metadata.uid = Some("warm-pool-uid".into());
        warm_pool.metadata.generation = Some(3);
        let template_ref = crate::crd::SandboxObjectReference {
            api_version: AGENT_SANDBOX_API_VERSION.into(),
            kind: SANDBOX_TEMPLATE_KIND.into(),
            namespace: Some("kobe-system".into()),
            name: "kobe-agents".into(),
            uid: "template-uid".into(),
            generation: Some(2),
        };
        let warm_pool_ref = crate::crd::SandboxObjectReference {
            api_version: AGENT_SANDBOX_API_VERSION.into(),
            kind: SANDBOX_WARM_POOL_KIND.into(),
            namespace: Some("kobe-system".into()),
            name: "kobe-agents".into(),
            uid: "warm-pool-uid".into(),
            generation: Some(3),
        };
        validate_pool_objects(
            &pool,
            "kobe-system",
            &template,
            &warm_pool,
            Some(&template_ref),
            Some(&warm_pool_ref),
        )
        .unwrap();

        warm_pool.metadata.uid = Some("replacement-uid".into());
        assert!(
            validate_pool_objects(
                &pool,
                "kobe-system",
                &template,
                &warm_pool,
                Some(&template_ref),
                Some(&warm_pool_ref),
            )
            .unwrap_err()
            .contains("immutable lease provenance")
        );
    }

    #[test]
    fn strict_policy_must_select_the_exact_template_pod() {
        let policy = NetworkPolicy {
            spec: Some(expected_network_policy_spec("kobe-agents")),
            ..NetworkPolicy::default()
        };
        let mut pod = Pod::default();
        pod.metadata.labels = Some(BTreeMap::from([
            (SANDBOX_HASH_LABEL.into(), upstream_name_hash("sandbox-one")),
            (
                TEMPLATE_REF_HASH_LABEL.into(),
                upstream_name_hash("kobe-agents"),
            ),
        ]));
        validate_pod_labels(&pod, "sandbox-one", "kobe-agents", &policy).unwrap();
        pod.metadata
            .labels
            .as_mut()
            .unwrap()
            .remove(TEMPLATE_REF_HASH_LABEL);
        assert!(validate_pod_labels(&pod, "sandbox-one", "kobe-agents", &policy).is_err());
    }

    #[test]
    fn service_certificate_rejects_external_exposure() {
        let pool = pool(1);
        let sandbox_name = "sandbox-one";
        let sandbox_uid = "sandbox-uid";
        let hash = upstream_name_hash(sandbox_name);
        let mut service = Service {
            metadata: ObjectMeta {
                name: Some(sandbox_name.into()),
                namespace: Some("kobe-system".into()),
                uid: Some("service-uid".into()),
                labels: Some(BTreeMap::from([(SANDBOX_HASH_LABEL.into(), hash.clone())])),
                owner_references: Some(vec![controller_owner(
                    SANDBOX_KIND,
                    sandbox_name,
                    sandbox_uid,
                )]),
                ..ObjectMeta::default()
            },
            spec: Some(ServiceSpec {
                cluster_ip: Some("None".into()),
                selector: Some(BTreeMap::from([(SANDBOX_HASH_LABEL.into(), hash)])),
                ports: Some(vec![ServicePort {
                    name: Some("http".into()),
                    protocol: Some("TCP".into()),
                    port: 3000,
                    target_port: Some(IntOrString::Int(3000)),
                    ..ServicePort::default()
                }]),
                ..ServiceSpec::default()
            }),
            ..Service::default()
        };
        validate_service(&pool, &service, sandbox_name, sandbox_uid).unwrap();
        service.spec.as_mut().unwrap().type_ = Some("LoadBalancer".into());
        assert!(validate_service(&pool, &service, sandbox_name, sandbox_uid).is_err());
    }

    fn certification_status(
        phase: SandboxPoolCertificationPhase,
    ) -> SandboxPoolCertificationStatus {
        let reference = |kind: &str, uid: &str| SandboxObjectReference {
            api_version: if matches!(kind, "Pod" | "Service" | "ConfigMap") {
                "v1".into()
            } else if kind == SANDBOX_KIND {
                SANDBOX_API_VERSION.into()
            } else {
                AGENT_SANDBOX_API_VERSION.into()
            },
            kind: kind.into(),
            namespace: Some("kobe-system".into()),
            name: format!("cert-{}", kind.to_ascii_lowercase()),
            uid: uid.into(),
            generation: (!matches!(kind, "Pod" | "Service" | "ConfigMap")).then_some(3),
        };
        SandboxPoolCertificationStatus {
            fingerprint: "a".repeat(64),
            observed_generation: 7,
            phase,
            sandbox_template: reference(SANDBOX_TEMPLATE_KIND, "template-uid"),
            sandbox_warm_pool: reference(SANDBOX_WARM_POOL_KIND, "warm-pool-uid"),
            sandbox_claim: Some(reference("SandboxClaim", "claim-uid")),
            sandbox: Some(reference(SANDBOX_KIND, "sandbox-uid")),
            pod: Some(reference("Pod", "pod-uid")),
            service: Some(reference("Service", "service-uid")),
            persistent_volume_claims: vec![],
            persistent_volumes: vec![],
            teardown_fence: Some(reference("ConfigMap", "fence-uid")),
            baseline_idle_sandbox_uids: vec!["old-idle-uid".into()],
            drain_generation: Some(8),
            replenish_generation: Some(9),
            canary_passed_at: Some("2026-08-21T00:00:00Z".into()),
            certified_at: None,
            message: None,
        }
    }

    #[test]
    fn v0_5_6_generation_ack_precedes_replica_trust() {
        let mut warm_pool = DynamicObject {
            metadata: ObjectMeta {
                generation: Some(4),
                ..ObjectMeta::default()
            },
            data: serde_json::json!({
                "status": {
                    "observedGeneration": 3,
                    "replicas": 1,
                    "readyReplicas": 1
                }
            }),
            types: None,
        };
        assert!(!warm_pool_status_is_current(&warm_pool));
        warm_pool.data["status"]["observedGeneration"] = serde_json::json!(4);
        assert!(warm_pool_status_is_current(&warm_pool));
    }

    #[test]
    fn every_certification_phase_survives_a_crash_round_trip() {
        for phase in [
            SandboxPoolCertificationPhase::Initialized,
            SandboxPoolCertificationPhase::ClaimCreated,
            SandboxPoolCertificationPhase::WorkloadCaptured,
            SandboxPoolCertificationPhase::CanaryPassed,
            SandboxPoolCertificationPhase::FenceInstalled,
            SandboxPoolCertificationPhase::DrainAcknowledged,
            SandboxPoolCertificationPhase::ClaimDeleting,
            SandboxPoolCertificationPhase::AbsenceProven,
            SandboxPoolCertificationPhase::Replenished,
            SandboxPoolCertificationPhase::FenceFinalizerRemoved,
            SandboxPoolCertificationPhase::FenceDeleting,
            SandboxPoolCertificationPhase::Certified,
            SandboxPoolCertificationPhase::CleanupBlocked,
        ] {
            let before = certification_status(phase);
            let after: SandboxPoolCertificationStatus =
                serde_json::from_value(serde_json::to_value(&before).unwrap()).unwrap();
            assert_eq!(after, before, "phase {phase:?} lost restart evidence");
        }
    }

    #[test]
    fn a_completed_attempt_never_blocks_the_next_pool_generation() {
        let completed = certification_status(SandboxPoolCertificationPhase::Certified);
        assert!(!attempt_has_live_cleanup(&completed));

        let active = certification_status(SandboxPoolCertificationPhase::FenceInstalled);
        assert!(attempt_has_live_cleanup(&active));
    }

    #[test]
    fn post_fence_blocker_retains_every_exact_cleanup_reference() {
        let before = certification_status(SandboxPoolCertificationPhase::FenceInstalled);
        let blocked = cleanup_blocked(before.clone(), 0, POST_FENCE_MUTATION_BLOCKER);
        assert_eq!(
            blocked.status.phase,
            SandboxPoolCertificationPhase::CleanupBlocked
        );
        assert_eq!(blocked.status.sandbox_claim, before.sandbox_claim);
        assert_eq!(blocked.status.sandbox, before.sandbox);
        assert_eq!(blocked.status.pod, before.pod);
        assert_eq!(blocked.status.service, before.service);
        assert_eq!(blocked.status.teardown_fence, before.teardown_fence);
        for required in [
            "scale-to-zero",
            "foreground-delete",
            "descendant/storage absence",
            "restore capacity",
            "clean new UIDs",
            "remove the fence",
        ] {
            assert!(blocked.message.contains(required), "missing {required}");
        }
    }

    #[tokio::test]
    async fn fence_checkpoint_requires_the_exact_vap_denial() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/namespaces/kobe-system/pods"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "code": 403,
                "reason": "Forbidden",
                "message": TEARDOWN_FENCE_DENIAL_MESSAGE
            })))
            .mount(&server)
            .await;
        let client = crate::testutil::mock_k8s_client(&server);
        let status = certification_status(SandboxPoolCertificationPhase::CanaryPassed);
        assert!(
            verify_teardown_fence_enforcement(&client, "kobe-system", &status)
                .await
                .unwrap()
        );
        let request = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.method.as_str() == "POST")
            .expect("dry-run Pod CREATE");
        assert!(
            request
                .url
                .query()
                .is_some_and(|query| query.contains("dryRun=All"))
        );
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(
            body["metadata"]["ownerReferences"][0]["uid"],
            status.sandbox.unwrap().uid
        );
    }
}
