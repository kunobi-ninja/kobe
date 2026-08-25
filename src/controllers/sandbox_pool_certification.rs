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
const SANDBOX_HASH_LABEL: &str = "agents.x-k8s.io/sandbox-name-hash";
const CERTIFICATION_POOL_UID_LABEL: &str = "kobe.kunobi.ninja/sandbox-pool-uid";
const CERTIFICATION_POOL_GENERATION_LABEL: &str = "kobe.kunobi.ninja/sandbox-pool-generation";
const TEARDOWN_FENCE_LABEL: &str = "kobe.kunobi.ninja/sandbox-teardown-fence";
const TEARDOWN_FENCE_FINALIZER: &str = "kobe.kunobi.ninja/sandbox-teardown-fence";
const TEARDOWN_FENCE_DENIAL_MESSAGE: &str =
    "Sandbox teardown has fenced descendant creation for this controller owner UID";
const REQUIRED_POOL_ACK_RELEASE: &str = "v0.5.6";

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

fn warm_pool_resource() -> ApiResource {
    ApiResource {
        group: "extensions.agents.x-k8s.io".into(),
        version: "v1beta1".into(),
        api_version: AGENT_SANDBOX_API_VERSION.into(),
        kind: SANDBOX_WARM_POOL_KIND.into(),
        plural: "sandboxwarmpools".into(),
    }
}

fn pvc_resource() -> ApiResource {
    ApiResource {
        group: "".into(),
        version: "v1".into(),
        api_version: "v1".into(),
        kind: "PersistentVolumeClaim".into(),
        plural: "persistentvolumeclaims".into(),
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
            "apiVersion": crate::sandbox_runtime::REQUIRED_AGENT_SANDBOX_API_VERSION,
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
    // Only the teardown TARGETS — the sacrificial Claim and its Sandbox — are
    // fenced. The WarmPool's UID must stay out: upstream's reconcile writes
    // `status.observedGeneration` only after a pass with no errors, so fencing
    // WarmPool-owned creates wedges the very ACK the drain and replenish
    // barriers wait for (and the fence is immutable, so the restore leg could
    // never replenish). A new-UID warm member cannot perturb the proofs —
    // every absence and clean-UID check is pinned to the recorded UIDs.
    for reference in [status.sandbox_claim.as_ref(), status.sandbox.as_ref()]
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

/// Outcome of one UID/resourceVersion-fenced write.
enum FencedWrite {
    Updated(Box<DynamicObject>),
    /// The object changed underneath the CAS; the next reconcile re-reads it.
    Contended,
    /// A definitive fail-closed finding: identity drift or deletion in flight.
    Blocked(String),
}

/// Outcome of proving one exact recorded identity absent.
enum Absence {
    Proven,
    Present,
    Blocked(String),
}

/// The recorded identity a given kind maps to inside one certification
/// attempt. Claim and Sandbox are mandatory from `WorkloadCaptured` onward.
fn identity_for_kind<'a>(
    status: &'a SandboxPoolCertificationStatus,
    kind: &str,
) -> Option<&'a SandboxObjectReference> {
    if kind == "SandboxClaim" {
        status.sandbox_claim.as_ref()
    } else if kind == SANDBOX_KIND {
        status.sandbox.as_ref()
    } else {
        None
    }
}

/// Scale the exact recorded WarmPool under a UID/resourceVersion CAS.
///
/// The write is the only mutation of a pass; `metadata.generation` on the
/// accepted object is the drain/replenish generation whose
/// `status.observedGeneration` ACK the later phases wait for. Identity fences
/// run before the CAS so a same-named replacement can never be scaled as
/// somebody else's capacity.
async fn scale_warm_pool_fenced(
    client: &Client,
    namespace: &str,
    recorded_warm_pool: &SandboxObjectReference,
    replicas: u32,
) -> Result<FencedWrite, String> {
    let pools: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), namespace, &warm_pool_resource());
    let current = read_dynamic_exact(&pools, namespace, recorded_warm_pool).await?;
    let (Some(uid), Some(resource_version)) = (current.uid(), current.resource_version()) else {
        return Ok(FencedWrite::Blocked(
            "recorded certification WarmPool has no UID/resourceVersion to fence".into(),
        ));
    };
    let patch = crate::controllers::lease::json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": uid },
        { "op": "test", "path": "/metadata/resourceVersion", "value": resource_version },
        { "op": "test", "path": "/spec/replicas",
          "value": current.data.pointer("/spec/replicas").cloned().unwrap_or(serde_json::Value::Null) },
        { "op": "replace", "path": "/spec/replicas", "value": replicas }
    ]));
    match pools
        .patch(
            &recorded_warm_pool.name,
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Json::<()>(patch),
        )
        .await
    {
        Ok(updated) => Ok(FencedWrite::Updated(Box::new(updated))),
        Err(error) if crate::controllers::lease::optimistic_conflict(&error) => {
            Ok(FencedWrite::Contended)
        }
        Err(kube::Error::Api(response)) if response.code == 404 || response.code == 403 => {
            Ok(FencedWrite::Blocked(format!(
                "recorded certification WarmPool cannot be scaled: {response}"
            )))
        }
        Err(error) => Err(format!("certification WarmPool scale failed: {error}")),
    }
}

/// GET one dynamic object and enforce its exact recorded identity.
///
/// Transport failures are retryable (`Err`); a deleting, misplaced, or
/// replaced object is a definitive fail-closed finding.
async fn read_dynamic_exact(
    api: &Api<DynamicObject>,
    namespace: &str,
    recorded: &SandboxObjectReference,
) -> Result<DynamicObject, String> {
    let object = api
        .get(&recorded.name)
        .await
        .map_err(|error| match &error {
            kube::Error::Api(response) if response.code == 404 || response.code == 403 => {
                format!("recorded {} cannot be proven: {response}", recorded.kind)
            }
            _ => format!("recorded {} lookup failed: {error}", recorded.kind),
        })?;
    if object.metadata.deletion_timestamp.is_some()
        || object.namespace().as_deref() != Some(namespace)
        || object.uid().as_deref() != Some(recorded.uid.as_str())
    {
        return Err(format!(
            "recorded {} is deleting or no longer matches its checkpointed identity",
            recorded.kind
        ));
    }
    Ok(object)
}

/// Whether one exact recorded object is provably absent from its namespace.
///
/// Presence with the same UID means the deletion has not completed; presence
/// with any other UID means a replacement appeared, which the fence exists to
/// make impossible and which must never be deleted around.
async fn reference_absent(
    client: &Client,
    namespace: &str,
    api_resource: &ApiResource,
    recorded: &SandboxObjectReference,
) -> Result<Absence, String> {
    let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), namespace, api_resource);
    match api.get(&recorded.name).await {
        Err(kube::Error::Api(response)) if response.code == 404 => Ok(Absence::Proven),
        Err(kube::Error::Api(response)) if response.code == 403 => Ok(Absence::Blocked(format!(
            "recorded {} absence cannot be proven: {response}",
            recorded.kind
        ))),
        Err(error) => Err(format!(
            "recorded {} absence check failed: {error}",
            recorded.kind
        )),
        Ok(object) => {
            if object.uid().as_deref() != Some(recorded.uid.as_str()) {
                Ok(Absence::Blocked(format!(
                    "recorded {} was replaced by same-named UID {} before absence was proven",
                    recorded.kind,
                    object.uid().unwrap_or_else(|| "<none>".into())
                )))
            } else {
                Ok(Absence::Present)
            }
        }
    }
}

/// Read the recorded teardown fence and return `(uid, resourceVersion)` after
/// enforcing its exact checkpointed identity. The fence must not be deleting;
/// the caller decides what its finalizer set must be.
async fn read_fence_exact(
    fences: &Api<ConfigMap>,
    desired_fence: &ConfigMap,
    status: &SandboxPoolCertificationStatus,
) -> Result<(String, String), String> {
    let recorded = status.teardown_fence.as_ref().ok_or_else(|| {
        "certification checkpoint has no exact teardown fence reference".to_string()
    })?;
    let fence = fences
        .get(desired_fence.name_any().as_str())
        .await
        .map_err(|error| format!("teardown fence lookup failed: {error}"))?;
    if fence.metadata.deletion_timestamp.is_some()
        || fence.uid().as_deref() != Some(recorded.uid.as_str())
    {
        return Err("same-named certification teardown fence is deleting or drifted".to_string());
    }
    let uid = fence
        .uid()
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| "teardown fence has no UID".to_string())?;
    let resource_version = fence
        .resource_version()
        .filter(|version| !version.is_empty())
        .ok_or_else(|| "teardown fence has no resourceVersion".to_string())?;
    Ok((uid, resource_version))
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
    for (key, value) in required_labels {
        if labels.get(key).map(String::as_str) != Some(value) {
            return Err(format!(
                "certification Claim metadata drifted from the exact Pool: label {key} is {:?}, expected {value:?}",
                labels.get(key).map(String::as_str).unwrap_or("<absent>")
            ));
        }
    }
    if labels
        .get(CERTIFICATION_POOL_GENERATION_LABEL)
        .map(String::as_str)
        != Some(generation_label.as_str())
    {
        return Err(format!(
            "certification Claim metadata drifted from the exact Pool: label {} is {:?}, expected {generation_label:?}",
            CERTIFICATION_POOL_GENERATION_LABEL,
            labels
                .get(CERTIFICATION_POOL_GENERATION_LABEL)
                .map(String::as_str)
                .unwrap_or("<absent>")
        ));
    }
    let observed_spec = normalize_claim_spec(claim.data.get("spec"));
    let desired_spec = normalize_claim_spec(desired.data.get("spec"));
    if observed_spec != desired_spec {
        return Err(format!(
            "certification Claim spec drifted from the exact Pool: observed {}, desired {}",
            serde_json::to_string(&observed_spec).unwrap_or_else(|_| "<unserializable>".into()),
            serde_json::to_string(&desired_spec).unwrap_or_else(|_| "<unserializable>".into()),
        ));
    }
    Ok(())
}

/// The upstream runtime persists defaulted-but-empty containers (for example
/// `additionalPodMetadata: {}`) that carry no pod-facing payload. Pruning empty
/// objects before the exact comparison forgives only those; any non-empty
/// addition or mutation still fails closed.
fn normalize_claim_spec(spec: Option<&serde_json::Value>) -> serde_json::Value {
    fn prune(value: &serde_json::Value) -> Option<serde_json::Value> {
        match value {
            serde_json::Value::Object(map) => {
                let pruned: serde_json::Map<String, serde_json::Value> = map
                    .iter()
                    .filter_map(|(key, child)| prune(child).map(|kept| (key.clone(), kept)))
                    .collect();
                if pruned.is_empty() {
                    None
                } else {
                    Some(serde_json::Value::Object(pruned))
                }
            }
            other => Some(other.clone()),
        }
    }
    spec.and_then(prune)
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()))
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
    crate::sandbox_runtime::validate_external_runtime(client)
        .await
        .map_err(|error| format!("runtime APIs are not compatible: {error}"))?;

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
/// The post-fence drain/restore transition is implemented exactly as the
/// fence's own contract specifies: a UID/resourceVersion-fenced scale-to-zero,
/// the v0.5.6 `observedGeneration` ACK plus zero ready replicas as a causal
/// drain barrier, foreground deletion of the sacrificial Claim, exact
/// descendant and storage absence, a fenced capacity restore with clean new
/// UID proof, then fence release. `observedGeneration` alone is never treated
/// as teardown or storage proof; every side effect checkpoints before the next.
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
        crate::sandbox_runtime::validate_external_runtime(client)
            .await
            .map_err(|error| format!("runtime APIs are not compatible: {error}"))?;
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
        // The post-fence drain/restore transition, exactly as the fence's own
        // contract specifies. Each step checkpoints before its side effect;
        // observedGeneration alone is never teardown or storage proof.
        SandboxPoolCertificationPhase::FenceInstalled => {
            fenced_scale_to_zero_drains(client, namespace, status, validated.ready).await
        }
        SandboxPoolCertificationPhase::DrainAcknowledged => {
            drain_waits_for_the_causal_barrier(client, namespace, status, validated.ready).await
        }
        SandboxPoolCertificationPhase::ClaimDeleting => {
            claim_deleting_foreground_deletes(client, namespace, status, validated.ready).await
        }
        SandboxPoolCertificationPhase::AbsenceProven => {
            absence_proven_restores_capacity(
                client,
                namespace,
                pool.spec.warm_capacity,
                status,
                validated.ready,
            )
            .await
        }
        SandboxPoolCertificationPhase::Replenished => {
            replenished_proves_and_releases_the_fence(
                client,
                namespace,
                pool.spec.warm_capacity,
                status,
                validated.ready,
            )
            .await
        }
        SandboxPoolCertificationPhase::FenceFinalizerRemoved => {
            released_fence_is_deleted(client, namespace, status, validated.ready).await
        }
        SandboxPoolCertificationPhase::FenceDeleting => {
            deleted_fence_completes_certification(client, namespace, status, validated.ready).await
        }
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
    }
}
/// FenceInstalled: one fenced scale-to-zero write, then checkpoint the
/// drain generation whose observedGeneration ACK the next phase waits for.
async fn fenced_scale_to_zero_drains(
    client: &Client,
    namespace: &str,
    mut status: SandboxPoolCertificationStatus,
    ready: u32,
) -> Result<ManagementPoolCertificationProgress, String> {
    match scale_warm_pool_fenced(client, namespace, &status.sandbox_warm_pool, 0).await? {
        FencedWrite::Updated(updated) => {
            let updated = *updated;
            let generation = updated
                .metadata
                .generation
                .ok_or_else(|| "drained certification WarmPool has no generation".to_string())?;
            status.drain_generation = Some(generation);
            status.phase = SandboxPoolCertificationPhase::DrainAcknowledged;
            status.message = None;
            Ok(progress(
                status,
                ready,
                false,
                true,
                "CertificationDrainRequested",
                format!(
                    "scale-to-zero written under a UID/resourceVersion fence; waiting for generation {generation} plus zero ready replicas"
                ),
            ))
        }
        FencedWrite::Contended => Ok(progress(
            status,
            ready,
            false,
            false,
            "CertificationDrainContended",
            "the WarmPool changed during scale-to-zero; retrying against its current snapshot",
        )),
        FencedWrite::Blocked(message) => Ok(cleanup_blocked(status, ready, message)),
    }
}

/// DrainAcknowledged: wait without mutating until the exact recorded
/// generation is observed AND both replica counters read zero.
async fn drain_waits_for_the_causal_barrier(
    client: &Client,
    namespace: &str,
    mut status: SandboxPoolCertificationStatus,
    ready: u32,
) -> Result<ManagementPoolCertificationProgress, String> {
    let Some(drain_generation) = status.drain_generation else {
        return Ok(cleanup_blocked(
            status,
            ready,
            "DrainAcknowledged checkpoint has no exact WarmPool drain generation",
        ));
    };
    let pools: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), namespace, &warm_pool_resource());
    let warm_pool = read_dynamic_exact(&pools, namespace, &status.sandbox_warm_pool).await?;
    if !warm_pool_status_is_current(&warm_pool)
        || warm_pool
            .data
            .pointer("/status/observedGeneration")
            .and_then(serde_json::Value::as_i64)
            != Some(drain_generation)
    {
        return Ok(progress(
            status,
            ready,
            false,
            false,
            "CertificationDraining",
            format!("waiting for WarmPool generation {drain_generation} to be observed"),
        ));
    }
    let (Some(replicas), Some(ready_replicas)) = (
        dynamic_status_count(&warm_pool, "replicas"),
        dynamic_status_count(&warm_pool, "readyReplicas"),
    ) else {
        return Ok(progress(
            status,
            ready,
            false,
            false,
            "CertificationDraining",
            "WarmPool ACKed the drain but its replica counts are not observable yet",
        ));
    };
    if replicas != 0 || ready_replicas != 0 {
        return Ok(progress(
            status,
            ready,
            false,
            false,
            "CertificationDraining",
            format!(
                "waiting for the drained WarmPool to report zero replicas (now {replicas}/{ready_replicas})"
            ),
        ));
    }
    status.phase = SandboxPoolCertificationPhase::ClaimDeleting;
    status.message = None;
    Ok(progress(
        status,
        ready,
        false,
        false,
        "CertificationDrained",
        "causal drain barrier proven: current generation observed with zero ready replicas",
    ))
}

/// ClaimDeleting: foreground-delete the exact sacrificial Claim under a UID
/// precondition until it is provably gone.
async fn claim_deleting_foreground_deletes(
    client: &Client,
    namespace: &str,
    mut status: SandboxPoolCertificationStatus,
    ready: u32,
) -> Result<ManagementPoolCertificationProgress, String> {
    let Some(recorded_claim) = status.sandbox_claim.clone() else {
        return Ok(cleanup_blocked(
            status,
            ready,
            "ClaimDeleting checkpoint has no exact SandboxClaim reference",
        ));
    };
    match reference_absent(client, namespace, &claim_resource(), &recorded_claim).await? {
        Absence::Proven => {}
        Absence::Blocked(message) => {
            return Ok(cleanup_blocked(status, ready, message));
        }
        Absence::Present => {
            let params = kube::api::DeleteParams {
                propagation_policy: Some(kube::api::PropagationPolicy::Foreground),
                preconditions: Some(kube::api::Preconditions {
                    uid: Some(recorded_claim.uid.clone()),
                    ..kube::api::Preconditions::default()
                }),
                ..kube::api::DeleteParams::default()
            };
            let claims: Api<DynamicObject> =
                Api::namespaced_with(client.clone(), namespace, &claim_resource());
            match claims.delete(&recorded_claim.name, &params).await {
                Ok(_) => {}
                Err(kube::Error::Api(response)) if response.code == 404 => {}
                Err(kube::Error::Api(response)) if response.code == 409 => {
                    return Ok(progress(
                        status,
                        ready,
                        false,
                        false,
                        "CertificationClaimDeleting",
                        "foreground Claim deletion is contended; retrying against the surviving object",
                    ));
                }
                Err(kube::Error::Api(response)) if response.code == 403 => {
                    return Ok(cleanup_blocked(
                        status,
                        ready,
                        format!("foreground Claim deletion is forbidden: {response}"),
                    ));
                }
                Err(error) => return Err(format!("certification Claim deletion failed: {error}")),
            }
            return Ok(progress(
                status,
                ready,
                false,
                true,
                "CertificationClaimDeleting",
                "foreground-deleting the exact sacrificial Claim",
            ));
        }
    }
    status.phase = SandboxPoolCertificationPhase::AbsenceProven;
    status.message = None;
    Ok(progress(
        status,
        ready,
        false,
        false,
        "CertificationClaimGone",
        "exact sacrificial Claim is absent; proving descendant and storage absence",
    ))
}

/// AbsenceProven: prove every captured descendant and storage identity
/// absent, then restore capacity under a fence and checkpoint its generation.
async fn absence_proven_restores_capacity(
    client: &Client,
    namespace: &str,
    warm_capacity: u32,
    mut status: SandboxPoolCertificationStatus,
    ready: u32,
) -> Result<ManagementPoolCertificationProgress, String> {
    for (api_resource, kind) in [
        (claim_resource(), "SandboxClaim"),
        (sandbox_resource(), SANDBOX_KIND),
    ] {
        let Some(recorded) = identity_for_kind(&status, kind) else {
            return Ok(cleanup_blocked(
                status,
                ready,
                format!("AbsenceProven checkpoint has no exact {kind} reference"),
            ));
        };
        match reference_absent(client, namespace, &api_resource, recorded).await? {
            Absence::Proven => {}
            Absence::Present => {
                return Ok(progress(
                    status,
                    ready,
                    false,
                    false,
                    "CertificationAbsencePending",
                    format!("waiting for recorded {kind} to finish terminating"),
                ));
            }
            Absence::Blocked(message) => {
                return Ok(cleanup_blocked(status, ready, message));
            }
        }
    }
    for recorded in status.persistent_volume_claims.iter() {
        match reference_absent(client, namespace, &pvc_resource(), recorded).await? {
            Absence::Proven => {}
            Absence::Present => {
                return Ok(progress(
                    status,
                    ready,
                    false,
                    false,
                    "CertificationAbsencePending",
                    "waiting for captured certification PVC to be reclaimed",
                ));
            }
            Absence::Blocked(message) => {
                return Ok(cleanup_blocked(status, ready, message));
            }
        }
    }
    for recorded in status.persistent_volumes.iter() {
        let volumes: Api<k8s_openapi::api::core::v1::PersistentVolume> = Api::all(client.clone());
        match volumes.get(&recorded.name).await {
            Err(kube::Error::Api(response)) if response.code == 404 => {}
            Err(kube::Error::Api(response)) if response.code == 403 => {
                return Ok(cleanup_blocked(
                    status,
                    ready,
                    format!("captured PV absence cannot be proven: {response}"),
                ));
            }
            Err(error) => return Err(format!("captured PV absence check failed: {error}")),
            Ok(volume) => {
                if volume.uid().as_deref() != Some(recorded.uid.as_str()) {
                    return Ok(cleanup_blocked(
                        status,
                        ready,
                        "captured certification PV was replaced before absence was proven",
                    ));
                }
                return Ok(progress(
                    status,
                    ready,
                    false,
                    false,
                    "CertificationAbsencePending",
                    "waiting for captured certification PV to be reclaimed",
                ));
            }
        }
    }
    match scale_warm_pool_fenced(client, namespace, &status.sandbox_warm_pool, warm_capacity)
        .await?
    {
        FencedWrite::Updated(updated) => {
            let updated = *updated;
            let generation = updated.metadata.generation.ok_or_else(|| {
                "replenished certification WarmPool has no generation".to_string()
            })?;
            status.replenish_generation = Some(generation);
            status.phase = SandboxPoolCertificationPhase::Replenished;
            status.message = None;
            Ok(progress(
                status,
                ready,
                false,
                true,
                "CertificationRestoringCapacity",
                format!(
                    "descendant and storage absence proven; capacity restored and waiting for generation {generation}"
                ),
            ))
        }
        FencedWrite::Contended => Ok(progress(
            status,
            ready,
            false,
            false,
            "CertificationRestoreContended",
            "the WarmPool changed during capacity restore; retrying against its current snapshot",
        )),
        FencedWrite::Blocked(message) => Ok(cleanup_blocked(status, ready, message)),
    }
}

/// Replenished: wait for the replenish ACK plus full ready capacity, prove
/// no replaced-generation UID survived, then release the fence's finalizer.
async fn replenished_proves_and_releases_the_fence(
    client: &Client,
    namespace: &str,
    warm_capacity: u32,
    mut status: SandboxPoolCertificationStatus,
    ready: u32,
) -> Result<ManagementPoolCertificationProgress, String> {
    let Some(replenish_generation) = status.replenish_generation else {
        return Ok(cleanup_blocked(
            status,
            ready,
            "Replenished checkpoint has no exact WarmPool replenish generation",
        ));
    };
    let warm_pool_name = status.sandbox_warm_pool.name.as_str();
    let pools: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), namespace, &warm_pool_resource());
    let warm_pool = read_dynamic_exact(&pools, namespace, &status.sandbox_warm_pool).await?;
    if !warm_pool_status_is_current(&warm_pool)
        || warm_pool
            .data
            .pointer("/status/observedGeneration")
            .and_then(serde_json::Value::as_i64)
            != Some(replenish_generation)
    {
        return Ok(progress(
            status,
            ready,
            false,
            false,
            "CertificationReplenishing",
            format!("waiting for WarmPool generation {replenish_generation} to be observed"),
        ));
    }
    let expected = u64::from(warm_capacity);
    let ready_replicas = warm_pool
        .data
        .pointer("/status/readyReplicas")
        .and_then(serde_json::Value::as_u64);
    if ready_replicas != Some(expected) {
        return Ok(progress(
            status,
            ready,
            false,
            false,
            "CertificationReplenishing",
            format!(
                "waiting for {expected} replenished ready replicas (now {:?})",
                ready_replicas
            ),
        ));
    }
    let sandboxes: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), namespace, &sandbox_resource());
    let listed = sandboxes
        .list(&ListParams::default().labels(&format!(
            "{WARM_POOL_LABEL}={}",
            upstream_name_hash(warm_pool_name)
        )))
        .await
        .map_err(|error| format!("replenished Sandbox list failed: {error}"))?;
    let mut forbidden: std::collections::BTreeSet<&str> = status
        .baseline_idle_sandbox_uids
        .iter()
        .map(String::as_str)
        .collect();
    if let Some(sacrificed) = status.sandbox.as_ref() {
        forbidden.insert(sacrificed.uid.as_str());
    }
    for sandbox in &listed.items {
        let Some(uid) = sandbox.uid() else {
            continue;
        };
        if forbidden.contains(uid.as_str()) {
            return Ok(cleanup_blocked(
                status,
                ready,
                format!("replenished capacity preserved replaced-generation Sandbox UID {uid}"),
            ));
        }
    }
    // The proof is complete only after every live UID was checked.
    if listed.items.len() < usize::try_from(expected).unwrap_or(usize::MAX) {
        return Ok(progress(
            status,
            ready,
            false,
            false,
            "CertificationReplenishing",
            "waiting for the full replenished Sandbox set to be listable",
        ));
    }

    let fences: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let desired_fence = certification_fence(namespace, &status)?;
    let fence = read_fence_exact(&fences, &desired_fence, &status).await?;
    let patch = crate::controllers::lease::json_patch(serde_json::json!([
        { "op": "test", "path": "/metadata/uid", "value": fence.0 },
        { "op": "test", "path": "/metadata/finalizers",
          "value": [TEARDOWN_FENCE_FINALIZER] },
        { "op": "replace", "path": "/metadata/finalizers", "value": [] }
    ]));
    match fences
        .patch(
            &desired_fence.name_any(),
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Json::<()>(patch),
        )
        .await
    {
        Ok(_) => {}
        Err(error) if crate::controllers::lease::optimistic_conflict(&error) => {
            return Ok(progress(
                status,
                ready,
                false,
                false,
                "CertificationFenceReleaseContended",
                "the teardown fence changed while releasing its finalizer; retrying",
            ));
        }
        Err(error) => return Err(format!("teardown fence finalizer release failed: {error}")),
    }
    status.phase = SandboxPoolCertificationPhase::FenceFinalizerRemoved;
    status.message = None;
    Ok(progress(
        status,
        ready,
        false,
        true,
        "CertificationReplenished",
        "capacity restored on a fresh generation with only new UIDs; releasing the exact teardown fence",
    ))
}

/// FenceFinalizerRemoved: delete the released fence under UID/resourceVersion
/// preconditions so absence on the next pass completes certification.
async fn released_fence_is_deleted(
    client: &Client,
    namespace: &str,
    mut status: SandboxPoolCertificationStatus,
    ready: u32,
) -> Result<ManagementPoolCertificationProgress, String> {
    let fences: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let desired_fence = certification_fence(namespace, &status)?;
    let (fence_uid, resource_version) = read_fence_exact(&fences, &desired_fence, &status).await?;
    let params = kube::api::DeleteParams {
        preconditions: Some(kube::api::Preconditions {
            uid: Some(fence_uid),
            resource_version: Some(resource_version),
        }),
        ..kube::api::DeleteParams::default()
    };
    match fences.delete(&desired_fence.name_any(), &params).await {
        Ok(_) => {}
        Err(kube::Error::Api(response)) if response.code == 404 => {}
        Err(kube::Error::Api(response)) if response.code == 409 => {
            return Ok(progress(
                status,
                ready,
                false,
                false,
                "CertificationFenceTerminating",
                "teardown fence deletion is contended; retrying against the surviving object",
            ));
        }
        Err(kube::Error::Api(response)) if response.code == 403 => {
            return Ok(cleanup_blocked(
                status,
                ready,
                format!("teardown fence deletion is forbidden: {response}"),
            ));
        }
        Err(error) => return Err(format!("teardown fence deletion failed: {error}")),
    }
    status.phase = SandboxPoolCertificationPhase::FenceDeleting;
    status.message = None;
    Ok(progress(
        status,
        ready,
        false,
        true,
        "CertificationFenceDeleting",
        "deleted the released teardown fence; absence confirms the next pass",
    ))
}

/// FenceDeleting: confirmed fence absence is the final proof; stamp
/// `certifiedAt` and enter `Certified`.
async fn deleted_fence_completes_certification(
    client: &Client,
    namespace: &str,
    mut status: SandboxPoolCertificationStatus,
    ready: u32,
) -> Result<ManagementPoolCertificationProgress, String> {
    let fences: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let desired_fence = certification_fence(namespace, &status)?;
    match fences.get(&desired_fence.name_any()).await {
        Err(kube::Error::Api(error)) if error.code == 404 => {
            status.certified_at = Some(chrono::Utc::now().to_rfc3339());
            status.phase = SandboxPoolCertificationPhase::Certified;
            status.message = None;
            Ok(progress(
                status,
                ready,
                true,
                true,
                "Certified",
                "current-generation exact pool certification receipt is complete",
            ))
        }
        Err(error) => Err(format!("teardown fence lookup failed: {error}")),
        Ok(fence) => {
            if fence.metadata.deletion_timestamp.is_some() {
                return Ok(progress(
                    status,
                    ready,
                    false,
                    false,
                    "CertificationFenceDeleting",
                    "waiting for the released teardown fence to disappear",
                ));
            }
            Ok(cleanup_blocked(
                status,
                ready,
                "released teardown fence exists without a deletion timestamp",
            ))
        }
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
    use wiremock::matchers::{body_partial_json, method, path};
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

    /// The upstream runtime persists `additionalPodMetadata: {}` on stored
    /// Claims even though kobe never asked for it. Empty containers must not
    /// read as tampering, while any non-empty payload still fails closed.
    #[test]
    fn certification_claim_tolerates_empty_defaulted_containers_only() {
        let pool = pool(0);
        let desired = certification_claim(&pool, "kobe-system", "kobe-agents").unwrap();

        let mut observed = desired.clone();
        observed.data["spec"]["additionalPodMetadata"] = serde_json::json!({});
        validate_certification_claim(&pool, &desired, &observed).unwrap();

        observed.data["spec"]["additionalPodMetadata"] =
            serde_json::json!({ "labels": {}, "annotations": {} });
        validate_certification_claim(&pool, &desired, &observed).unwrap();

        observed.data["spec"]["additionalPodMetadata"] =
            serde_json::json!({ "labels": { "escape": "hatch" } });
        let error = validate_certification_claim(&pool, &desired, &observed).unwrap_err();
        assert!(
            error.contains("certification Claim spec drifted"),
            "{error}"
        );

        let mut mutated = desired.clone();
        mutated.data["spec"]["lifecycle"]["shutdownPolicy"] = serde_json::json!("Retain");
        let error = validate_certification_claim(&pool, &desired, &mutated).unwrap_err();
        assert!(
            error.contains("certification Claim spec drifted"),
            "{error}"
        );
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

    /// The workload labels must be the exact keys Agent Sandbox v0.5.6 puts on
    /// Pods and Services. Every earlier test compared our constant against
    /// itself, so a mistyped key passed every fixture while rejecting every
    /// real upstream workload — which is how certification timed out for its
    /// full 900-second window in live conformance while unit tests stayed
    /// green.
    #[test]
    fn workload_label_keys_match_the_pinned_upstream_release() {
        assert_eq!(
            SANDBOX_HASH_LABEL, "agents.x-k8s.io/sandbox-name-hash",
            "v0.5.6 labels Pods and Services with sandbox-name-hash (controllers/sandbox_controller.go sandboxLabel)"
        );
        assert_eq!(
            TEMPLATE_REF_HASH_LABEL, "agents.x-k8s.io/sandbox-template-ref-hash",
            "v0.5.6 propagates the template's self-label to Pods (SandboxTemplateRefHashLabel)"
        );
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

    /// Upstream only writes `status.observedGeneration` after an error-free
    /// reconcile, and its reconcile errors on any denied create — so a fence
    /// that blocks WarmPool-owned creates deadlocks the drain and replenish
    /// ACKs the protocol waits for. Only the teardown targets may be fenced.
    #[test]
    fn the_fence_blocks_teardown_targets_but_never_the_warm_pool() {
        let fence = certification_fence(
            "kobe-system",
            &certification_status(SandboxPoolCertificationPhase::CanaryPassed),
        )
        .unwrap();
        let data = fence.data.unwrap();
        assert!(data.contains_key("claim-uid"));
        assert!(data.contains_key("sandbox-uid"));
        assert!(
            !data.contains_key("warm-pool-uid"),
            "fencing the WarmPool UID starves upstream's status ACK and makes \
             the fenced restore unreplenishable"
        );
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

    /// Fixture warm-pool object for the drain/restore phases: generation 8,
    /// observed ACK 7, one ready replica.
    fn certification_warm_pool() -> serde_json::Value {
        serde_json::json!({
            "apiVersion": AGENT_SANDBOX_API_VERSION,
            "kind": SANDBOX_WARM_POOL_KIND,
            "metadata": {
                "name": "cert-sandboxwarmpool",
                "namespace": "kobe-system",
                "uid": "warm-pool-uid",
                "resourceVersion": "41",
                "generation": 8
            },
            "spec": { "replicas": 1 },
            "status": {
                "observedGeneration": 7,
                "replicas": 1,
                "readyReplicas": 1
            }
        })
    }

    #[tokio::test]
    async fn fenced_scale_to_zero_records_the_drain_generation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxwarmpools/cert-sandboxwarmpool",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(certification_warm_pool()))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxwarmpools/cert-sandboxwarmpool",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json({
                let mut updated = certification_warm_pool();
                updated["spec"]["replicas"] = serde_json::json!(0);
                updated["metadata"]["resourceVersion"] = serde_json::json!("42");
                updated
            }))
            .expect(1)
            .mount(&server)
            .await;
        let client = crate::testutil::mock_k8s_client(&server);

        let progress = fenced_scale_to_zero_drains(
            &client,
            "kobe-system",
            certification_status(SandboxPoolCertificationPhase::FenceInstalled),
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            progress.status.phase,
            SandboxPoolCertificationPhase::DrainAcknowledged
        );
        assert_eq!(progress.status.drain_generation, Some(8));
        assert_eq!(progress.reason, "CertificationDrainRequested");

        let patch = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.method.as_str() == "PATCH")
            .expect("fenced scale-to-zero");
        let body: serde_json::Value = serde_json::from_slice(&patch.body).unwrap();
        assert_eq!(body[0]["value"], "warm-pool-uid");
        assert_eq!(body[1]["value"], "41");
        assert_eq!(body[3]["path"], "/spec/replicas");
        assert_eq!(body[3]["value"], 0);
    }

    #[tokio::test]
    async fn the_drain_barrier_waits_for_ack_and_zero_replicas() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Not yet observed: wait without mutating.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxwarmpools/cert-sandboxwarmpool",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(certification_warm_pool()))
            .expect(1)
            .mount(&server)
            .await;
        let client = crate::testutil::mock_k8s_client(&server);
        let progress = drain_waits_for_the_causal_barrier(
            &client,
            "kobe-system",
            certification_status(SandboxPoolCertificationPhase::DrainAcknowledged),
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            progress.status.phase,
            SandboxPoolCertificationPhase::DrainAcknowledged
        );
        assert_eq!(progress.reason, "CertificationDraining");
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() == "GET"),
            "waiting must not write anything"
        );

        // Observed with zero replicas: advance.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxwarmpools/cert-sandboxwarmpool",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json({
                let mut drained = certification_warm_pool();
                drained["status"]["observedGeneration"] = serde_json::json!(8);
                drained["status"]["replicas"] = serde_json::json!(0);
                drained["status"]["readyReplicas"] = serde_json::json!(0);
                drained
            }))
            .expect(1)
            .mount(&server)
            .await;
        let client = crate::testutil::mock_k8s_client(&server);
        let progress = drain_waits_for_the_causal_barrier(
            &client,
            "kobe-system",
            certification_status(SandboxPoolCertificationPhase::DrainAcknowledged),
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            progress.status.phase,
            SandboxPoolCertificationPhase::ClaimDeleting
        );
        assert_eq!(progress.reason, "CertificationDrained");
    }

    #[tokio::test]
    async fn claim_deleting_foreground_deletes_the_exact_claim() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxclaims/cert-sandboxclaim",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": AGENT_SANDBOX_API_VERSION,
                "kind": "SandboxClaim",
                "metadata": {
                    "name": "cert-sandboxclaim", "namespace": "kobe-system", "uid": "claim-uid"
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxclaims/cert-sandboxclaim",
            ))
            .and(body_partial_json(serde_json::json!({
                "preconditions": { "uid": "claim-uid" },
                "propagationPolicy": "Foreground"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": AGENT_SANDBOX_API_VERSION, "kind": "SandboxClaim",
                "metadata": {"name": "cert-sandboxclaim", "namespace": "kobe-system",
                             "uid": "claim-uid", "deletionTimestamp": "2026-08-24T00:00:00Z"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = crate::testutil::mock_k8s_client(&server);

        let progress = claim_deleting_foreground_deletes(
            &client,
            "kobe-system",
            certification_status(SandboxPoolCertificationPhase::ClaimDeleting),
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            progress.status.phase,
            SandboxPoolCertificationPhase::ClaimDeleting,
            "the pass that issues the delete must not also claim absence"
        );
        assert_eq!(progress.reason, "CertificationClaimDeleting");
    }

    #[tokio::test]
    async fn a_missing_claim_checkpoints_absence_proven() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxclaims/cert-sandboxclaim",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "apiVersion":"v1","kind":"Status","status":"Failure",
                "reason":"NotFound","code":404
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = crate::testutil::mock_k8s_client(&server);

        let progress = claim_deleting_foreground_deletes(
            &client,
            "kobe-system",
            certification_status(SandboxPoolCertificationPhase::ClaimDeleting),
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            progress.status.phase,
            SandboxPoolCertificationPhase::AbsenceProven
        );
        assert_eq!(progress.reason, "CertificationClaimGone");
    }

    #[tokio::test]
    async fn absence_proven_restores_capacity_under_a_fence() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        for (missing_path, group) in [
            (
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxclaims/cert-sandboxclaim",
                "claims",
            ),
            (
                "/apis/agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxes/cert-sandbox",
                "sandboxes",
            ),
        ] {
            let _ = group;
            Mock::given(method("GET"))
                .and(path(missing_path))
                .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                    "apiVersion":"v1","kind":"Status","status":"Failure",
                    "reason":"NotFound","code":404
                })))
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxwarmpools/cert-sandboxwarmpool",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(certification_warm_pool()))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxwarmpools/cert-sandboxwarmpool",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json({
                let mut restored = certification_warm_pool();
                restored["spec"]["replicas"] = serde_json::json!(1);
                restored["metadata"]["generation"] = serde_json::json!(9);
                restored["metadata"]["resourceVersion"] = serde_json::json!("43");
                restored
            }))
            .expect(1)
            .mount(&server)
            .await;
        let client = crate::testutil::mock_k8s_client(&server);

        let status = certification_status(SandboxPoolCertificationPhase::AbsenceProven);
        let progress = absence_proven_restores_capacity(&client, "kobe-system", 1, status, 0)
            .await
            .unwrap();
        assert_eq!(
            progress.status.phase,
            SandboxPoolCertificationPhase::Replenished
        );
        assert_eq!(progress.status.replenish_generation, Some(9));
        assert_eq!(progress.reason, "CertificationRestoringCapacity");
    }

    #[tokio::test]
    async fn replenished_capacity_must_be_generation_fresh_and_uid_clean() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // A preserved replaced-generation UID is fail-closed evidence.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxwarmpools/cert-sandboxwarmpool",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json({
                let mut fresh = certification_warm_pool();
                fresh["metadata"]["generation"] = serde_json::json!(9);
                fresh["status"]["observedGeneration"] = serde_json::json!(9);
                fresh["status"]["replicas"] = serde_json::json!(1);
                fresh["status"]["readyReplicas"] = serde_json::json!(1);
                fresh
            }))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxes",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": SANDBOX_API_VERSION, "kind": "SandboxList",
                "metadata": {"resourceVersion": "1"},
                "items": [{
                    "apiVersion": SANDBOX_API_VERSION, "kind": SANDBOX_KIND,
                    "metadata": {
                        "name": "idle-old", "namespace": "kobe-system", "uid": "old-idle-uid"
                    },
                    "status": {}
                }]
            })))
            .mount(&server)
            .await;
        let client = crate::testutil::mock_k8s_client(&server);
        let blocked = replenished_proves_and_releases_the_fence(
            &client,
            "kobe-system",
            1,
            certification_status(SandboxPoolCertificationPhase::Replenished),
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            blocked.status.phase,
            SandboxPoolCertificationPhase::CleanupBlocked
        );
        assert!(
            blocked.message.contains("old-idle-uid"),
            "the exact preserved UID names the failure: {}",
            blocked.message
        );

        // All-new UIDs on an ACKed full-capacity generation release the fence.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/extensions.agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxwarmpools/cert-sandboxwarmpool",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json({
                let mut fresh = certification_warm_pool();
                fresh["metadata"]["generation"] = serde_json::json!(9);
                fresh["status"]["observedGeneration"] = serde_json::json!(9);
                fresh["status"]["replicas"] = serde_json::json!(1);
                fresh["status"]["readyReplicas"] = serde_json::json!(1);
                fresh
            }))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/apis/agents.x-k8s.io/v1beta1/namespaces/kobe-system/sandboxes",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": SANDBOX_API_VERSION, "kind": "SandboxList",
                "metadata": {"resourceVersion": "1"},
                "items": [{
                    "apiVersion": SANDBOX_API_VERSION, "kind": SANDBOX_KIND,
                    "metadata": {
                        "name": "idle-new", "namespace": "kobe-system", "uid": "fresh-idle-uid"
                    },
                    "status": {}
                }]
            })))
            .mount(&server)
            .await;
        let fence_name = format!("kobe-cert-fence-{}", &"a".repeat(64)[..40]);
        let fence_path = format!("/api/v1/namespaces/kobe-system/configmaps/{fence_name}");
        Mock::given(method("GET"))
            .and(path(fence_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "name": fence_name.clone(), "namespace": "kobe-system",
                    "uid": "fence-uid", "resourceVersion": "44",
                    "finalizers": ["kobe.kunobi.ninja/sandbox-teardown-fence"]
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path(fence_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {
                    "name": fence_name.clone(), "namespace": "kobe-system",
                    "uid": "fence-uid", "resourceVersion": "45", "finalizers": []
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = crate::testutil::mock_k8s_client(&server);
        let progress = replenished_proves_and_releases_the_fence(
            &client,
            "kobe-system",
            1,
            certification_status(SandboxPoolCertificationPhase::Replenished),
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            progress.status.phase,
            SandboxPoolCertificationPhase::FenceFinalizerRemoved
        );
        assert_eq!(progress.reason, "CertificationReplenished");
    }

    #[tokio::test]
    async fn confirmed_fence_absence_stamps_certified() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        let fence_name = format!("kobe-cert-fence-{}", &"a".repeat(64)[..40]);
        let fence_path = format!("/api/v1/namespaces/kobe-system/configmaps/{fence_name}");
        Mock::given(method("GET"))
            .and(path(fence_path.clone()))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "apiVersion":"v1","kind":"Status","status":"Failure",
                "reason":"NotFound","code":404
            })))
            .mount(&server)
            .await;
        let client = crate::testutil::mock_k8s_client(&server);

        let progress = deleted_fence_completes_certification(
            &client,
            "kobe-system",
            certification_status(SandboxPoolCertificationPhase::FenceDeleting),
            0,
        )
        .await
        .unwrap();
        assert!(progress.certified);
        assert_eq!(
            progress.status.phase,
            SandboxPoolCertificationPhase::Certified
        );
        assert!(progress.status.certified_at.is_some());
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
