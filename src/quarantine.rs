//! Operator override for quarantined leases and instances.
//!
//! Quarantine holds a `ClusterLease` or `ClusterInstance` until the same exact
//! subject produces verified teardown evidence. When that evidence can never
//! arrive (the backend objects were removed by hand, the evidence store was
//! lost), the object would be held forever and keep counting against the
//! pool's `maxClusters`.
//!
//! [`RELEASE_QUARANTINE_ANNOTATION`] lets an operator release one object on
//! purpose. The value must equal the object's own UID, so the annotation
//! cannot be copied onto a same-named replacement, applied from a stale
//! manifest, or set with a blanket `kubectl annotate --all`. Without it every
//! quarantine stays fail-closed.

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

use k8s_openapi::api::core::v1::ObjectReference;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::Client;
use kube::runtime::events::{Event, EventType, Recorder, Reporter};
use tracing::warn;

/// Set to the object's UID to release a quarantined lease or instance without
/// verified teardown evidence.
pub const RELEASE_QUARANTINE_ANNOTATION: &str = "kobe.kunobi.ninja/release-quarantine";

/// Which quarantined object an override released. Metric label values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantinedKind {
    Lease,
    Instance,
}

impl QuarantinedKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lease => "lease",
            Self::Instance => "instance",
        }
    }
}

/// Whether an operator asked to release this object: the annotation is
/// present and its value equals the object's UID. An object without a UID
/// never matches.
pub fn release_requested(meta: &ObjectMeta) -> bool {
    let Some(uid) = meta.uid.as_deref().filter(|uid| !uid.is_empty()) else {
        return false;
    };
    meta.annotations
        .as_ref()
        .and_then(|annotations| annotations.get(RELEASE_QUARANTINE_ANNOTATION))
        // Exact, like the admission policy that lets the control plane drop
        // a quarantined lease's receipt finalizer. A looser match here would
        // start a release the API server then refuses on every retry.
        .is_some_and(|value| value == uid)
}

/// `profile` label for a quarantine metric: the pool name, or a fixed value
/// for an instance outside any pool, so object names never become labels.
pub fn pool_label(pool_ref: Option<&crate::crd::ResourceRef>) -> &str {
    pool_ref
        .map(|reference| reference.name.as_str())
        .unwrap_or(STANDALONE_POOL_LABEL)
}

/// `profile` label for objects that belong to no pool.
pub const STANDALONE_POOL_LABEL: &str = "standalone";

/// UIDs whose override this process already refused and announced.
static REFUSED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Default::default);

/// Whether this is the first refusal of `uid` in this process. A restart
/// announces an unchanged refusal once more, which is acceptable; a Warning
/// event on every requeue is not.
pub fn first_refusal(uid: &str) -> bool {
    REFUSED
        .lock()
        .map(|mut refused| refused.insert(uid.to_string()))
        .unwrap_or(true)
}

/// Record that an override released capacity without verified teardown
/// evidence: bump the counter and post a Warning event on the object.
/// The event is best-effort; a failure to post it is logged, not returned.
pub async fn record_release(
    client: &Client,
    reference: &ObjectReference,
    kind: QuarantinedKind,
    pool: &str,
    note: String,
) {
    crate::metrics::QUARANTINE_RELEASES_TOTAL
        .with_label_values(&[pool, kind.as_str()])
        .inc();
    publish_warning(client, reference, "QuarantineReleased", note).await;
}

/// Post a Warning event about a quarantine override. Best-effort.
pub async fn publish_warning(
    client: &Client,
    reference: &ObjectReference,
    reason: &str,
    note: String,
) {
    let recorder = Recorder::new(
        client.clone(),
        Reporter {
            controller: "kobe-operator".into(),
            instance: None,
        },
    );
    let event = Event {
        type_: EventType::Warning,
        reason: reason.into(),
        note: Some(note),
        action: "ReleaseQuarantine".into(),
        secondary: None,
    };
    if let Err(error) = recorder.publish(&event, reference).await {
        warn!(
            object = reference.name.as_deref().unwrap_or_default(),
            reason,
            error = %error,
            "could not post quarantine override event"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn meta(uid: Option<&str>, annotation: Option<&str>) -> ObjectMeta {
        ObjectMeta {
            uid: uid.map(str::to_string),
            annotations: annotation.map(|value| {
                BTreeMap::from([(RELEASE_QUARANTINE_ANNOTATION.to_string(), value.to_string())])
            }),
            ..Default::default()
        }
    }

    #[test]
    fn release_requires_the_annotation_to_name_the_object_uid() {
        assert!(release_requested(&meta(Some("abc-123"), Some("abc-123"))));
        // Exact only: the admission policy compares the raw value.
        assert!(!release_requested(&meta(
            Some("abc-123"),
            Some(" abc-123\n")
        )));

        assert!(!release_requested(&meta(Some("abc-123"), None)));
        assert!(!release_requested(&meta(Some("abc-123"), Some("true"))));
        assert!(!release_requested(&meta(Some("abc-123"), Some(""))));
        assert!(!release_requested(&meta(
            Some("abc-123"),
            Some("other-uid")
        )));
        assert!(!release_requested(&meta(None, Some(""))));
        assert!(!release_requested(&meta(Some(""), Some(""))));
    }

    #[test]
    fn a_refusal_is_announced_once_per_uid() {
        assert!(first_refusal("refusal-test-uid-a"));
        assert!(!first_refusal("refusal-test-uid-a"));
        assert!(first_refusal("refusal-test-uid-b"));
    }

    #[test]
    fn standalone_objects_get_a_fixed_label() {
        assert_eq!(pool_label(None), STANDALONE_POOL_LABEL);
        let pool = crate::crd::ResourceRef {
            name: "ci".into(),
            uid: None,
        };
        assert_eq!(pool_label(Some(&pool)), "ci");
    }
}
