//! Per-principal admission lock for Cluster lease creates.
//!
//! Cluster admission counts the caller's active `ClusterLease`s, checks alias
//! uniqueness, and then creates the lease. Those three steps are only correct
//! if no other request for the same principal runs them at the same time, on
//! this replica or any other. A `LIST` cannot provide that on its own, and a
//! post-create re-rank by `creationTimestamp` cannot either: the timestamp has
//! one-second resolution, and two requests that each list before the other's
//! create lands both see themselves inside the cap.
//!
//! The lock is a `coordination.k8s.io/v1` `Lease` in the operator namespace,
//! named from the principal hash. The API server serializes `CREATE` on object
//! name, so exactly one request holds it. The holder deletes it when admission
//! is done. A holder that dies leaves the object behind; once its
//! `renewTime + leaseDurationSeconds` has passed, the next request takes it
//! over with a `resourceVersion`-fenced replace, so two contenders racing to
//! take over the same stale lock cannot both win.
//!
//! The lock is never renewed. Callers must finish their critical section well
//! inside [`LOCK_DURATION`]; [`AdmissionLockGuard::still_safe`] reports whether
//! enough of the lease remains to start the create.

use std::time::{Duration, Instant};

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use kube::ResourceExt;
use kube::api::{Api, DeleteParams, ObjectMeta, PostParams, Preconditions};
use tracing::warn;

/// How long a lock stays valid after it was acquired or taken over.
///
/// Admission is one LIST and one CREATE, normally well under a second. The
/// generous duration keeps a slow API server from letting a second request
/// take over a lock whose holder is still working.
pub(crate) const LOCK_DURATION: Duration = Duration::from_secs(30);

/// The holder must start its create before this much of [`LOCK_DURATION`] has
/// elapsed. The remaining 20 seconds cover the create itself plus clock skew
/// between replicas, which judge expiry against their own clocks.
pub(crate) const LOCK_SAFE_WINDOW: Duration = Duration::from_secs(10);

/// How long a request waits for another request of the same principal to
/// finish admission before giving up with a retryable `503 admission_busy`.
///
/// Admission for one principal is serial, and CI matrix jobs share one
/// principal (repository and ref), so a matrix of a few dozen jobs queues
/// here. One admission is normally well under a second; 25 seconds lets a
/// burst drain without failing jobs, while staying bounded so a wedged holder
/// cannot hold requests open indefinitely. Clients should still retry
/// `admission_busy` (the `kobe` CLI does).
#[cfg(not(test))]
pub(crate) const LOCK_WAIT_BUDGET: Duration = Duration::from_secs(25);
/// Handler tests exercise the busy path without waiting 25 seconds.
#[cfg(test)]
pub(crate) const LOCK_WAIT_BUDGET: Duration = Duration::from_millis(250);

/// First pause after finding the lock held by a live holder.
const LOCK_RETRY_INITIAL: Duration = Duration::from_millis(50);

/// Longest pause between attempts. Keeps a long queue from polling the API
/// server every few milliseconds while still noticing a release quickly.
const LOCK_RETRY_MAX: Duration = Duration::from_secs(1);

/// Pause before retry `attempt` (0-based) while the lock is held.
///
/// Exponential from [`LOCK_RETRY_INITIAL`] up to [`LOCK_RETRY_MAX`], with
/// "equal jitter": half the step is fixed and half is random. Waiters that
/// arrived together (a CI matrix starting at once) then spread out instead
/// of hitting the API server in lockstep.
pub(crate) fn lock_retry_delay(attempt: u32) -> Duration {
    use rand::Rng;
    let step = LOCK_RETRY_INITIAL
        .saturating_mul(1u32 << attempt.min(16))
        .min(LOCK_RETRY_MAX);
    let half = step / 2;
    let jitter_ms = rand::rng().random_range(0..=half.as_millis() as u64);
    half + Duration::from_millis(jitter_ms)
}

/// Label marking admission-lock objects so an operator can find them.
pub(crate) const ADMISSION_LOCK_LABEL: &str = "kobe.kunobi.ninja/cluster-admission-lock";

/// Lock object name for a principal hash (32 hex chars, from
/// [`crate::api::sandbox::principal_hash_for`]).
pub(crate) fn lock_name(principal_hash: &str) -> String {
    format!("kobe-cluster-admission-{principal_hash}")
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AdmissionLockError {
    /// Another request for the same principal held the lock for the whole
    /// wait budget.
    #[error("another lease request for this identity is being admitted")]
    Busy,
    /// The API server returned a lock object without the metadata needed to
    /// release it safely.
    #[error("admission lock object is missing its uid or resourceVersion")]
    MissingMetadata,
    #[error(transparent)]
    Api(#[from] kube::Error),
}

/// Proof that this request holds the admission lock.
///
/// Release is fenced on both UID and `resourceVersion`: a takeover replaces
/// the object in place, so it keeps the UID, and only the version tells the
/// original holder that the lock is no longer theirs.
///
/// Call [`AdmissionLockGuard::release`] when admission is done. A guard
/// dropped without it (a cancelled request future, a panic) spawns the same
/// fenced delete on the current Tokio runtime, so the principal is not
/// blocked for the rest of [`LOCK_DURATION`].
#[derive(Debug)]
pub(crate) struct AdmissionLockGuard {
    api: Api<Lease>,
    held: Option<HeldLock>,
    acquired_at: Instant,
}

#[derive(Debug)]
struct HeldLock {
    name: String,
    uid: String,
    resource_version: String,
}

impl AdmissionLockGuard {
    /// Whether enough of the lock's validity remains to start the create.
    pub(crate) fn still_safe(&self) -> bool {
        self.acquired_at.elapsed() < LOCK_SAFE_WINDOW
    }

    /// Delete the lock if it is still ours.
    ///
    /// 404 and 409 mean the lock expired and was taken over or already
    /// removed; neither is an error for this request. Other failures are
    /// returned: the lock then expires on its own after [`LOCK_DURATION`], and
    /// the next request for this principal waits or takes it over.
    pub(crate) async fn release(mut self) -> Result<(), kube::Error> {
        match self.held.take() {
            Some(held) => delete_fenced(&self.api, &held).await,
            None => Ok(()),
        }
    }
}

impl Drop for AdmissionLockGuard {
    fn drop(&mut self) {
        let Some(held) = self.held.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            warn!(
                lock = %held.name,
                "Cluster admission lock dropped outside a runtime; it expires on its own"
            );
            return;
        };
        warn!(
            lock = %held.name,
            "Cluster admission lock dropped without release; releasing in the background"
        );
        let api = self.api.clone();
        runtime.spawn(async move {
            if let Err(error) = delete_fenced(&api, &held).await {
                warn!(
                    lock = %held.name,
                    error = %error,
                    "Failed to release a dropped Cluster admission lock; it expires on its own"
                );
            }
        });
    }
}

async fn delete_fenced(api: &Api<Lease>, held: &HeldLock) -> Result<(), kube::Error> {
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(held.uid.clone()),
            resource_version: Some(held.resource_version.clone()),
        }),
        ..DeleteParams::default()
    };
    match api.delete(&held.name, &params).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(error)) if error.code == 404 || error.code == 409 => {
            warn!(
                lock = %held.name,
                code = error.code,
                "Cluster admission lock was no longer ours at release"
            );
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Acquire the admission lock `name`, waiting up to `wait_budget` for a live
/// holder to finish. Retries back off per [`lock_retry_delay`].
pub(crate) async fn acquire(
    api: &Api<Lease>,
    name: &str,
    wait_budget: Duration,
) -> Result<AdmissionLockGuard, AdmissionLockError> {
    let deadline = Instant::now() + wait_budget;
    let mut attempt = 0;
    loop {
        if let Some(guard) = try_acquire(api, name).await? {
            return Ok(guard);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(AdmissionLockError::Busy);
        }
        let pause = lock_retry_delay(attempt).min(deadline - now);
        attempt = attempt.saturating_add(1);
        tokio::time::sleep(pause).await;
    }
}

/// One acquire attempt. `Ok(None)` means a live holder has the lock or a
/// concurrent contender won the takeover; the caller should wait and retry.
async fn try_acquire(
    api: &Api<Lease>,
    name: &str,
) -> Result<Option<AdmissionLockGuard>, AdmissionLockError> {
    // Both clocks are read before the write, so the validity the guard
    // assumes never exceeds what the stored renewTime grants.
    let now = chrono::Utc::now();
    let started = Instant::now();
    match api
        .create(&PostParams::default(), &lock_object(name, now, None))
        .await
    {
        Ok(created) => return guard_for(api, created, started).map(Some),
        Err(kube::Error::Api(error)) if error.code == 409 => {}
        Err(error) => return Err(error.into()),
    }

    let existing = match api.get_opt(name).await? {
        Some(existing) => existing,
        // Released between our CREATE and GET; the next attempt can create it.
        None => return Ok(None),
    };
    if !lock_expired(&existing, now) {
        return Ok(None);
    }

    let Some(resource_version) = existing.resource_version() else {
        return Err(AdmissionLockError::MissingMetadata);
    };
    let replacement = lock_object(name, now, Some(resource_version));
    match api
        .replace(name, &PostParams::default(), &replacement)
        .await
    {
        Ok(taken) => {
            warn!(lock = %name, "Took over an expired Cluster admission lock");
            guard_for(api, taken, started).map(Some)
        }
        // Another contender took it over first, or the holder deleted it.
        Err(kube::Error::Api(error)) if error.code == 409 || error.code == 404 => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn guard_for(
    api: &Api<Lease>,
    lease: Lease,
    started: Instant,
) -> Result<AdmissionLockGuard, AdmissionLockError> {
    let (Some(uid), Some(resource_version)) = (lease.uid(), lease.resource_version()) else {
        return Err(AdmissionLockError::MissingMetadata);
    };
    Ok(AdmissionLockGuard {
        api: api.clone(),
        held: Some(HeldLock {
            name: lease.name_any(),
            uid,
            resource_version,
        }),
        acquired_at: started,
    })
}

fn lock_object(
    name: &str,
    now: chrono::DateTime<chrono::Utc>,
    resource_version: Option<String>,
) -> Lease {
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(ADMISSION_LOCK_LABEL.to_string(), "true".to_string());
    let stamp = to_micro_time(now);
    Lease {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(labels),
            resource_version,
            ..ObjectMeta::default()
        },
        spec: Some(LeaseSpec {
            holder_identity: Some(uuid::Uuid::new_v4().to_string()),
            lease_duration_seconds: Some(LOCK_DURATION.as_secs() as i32),
            acquire_time: Some(stamp.clone()),
            renew_time: Some(stamp),
            ..LeaseSpec::default()
        }),
    }
}

/// A lock is expired once `renewTime` (or `acquireTime`, or the object's
/// creation time) plus its duration is in the past. A lock with no usable
/// timestamp or duration is treated as expired so a malformed object cannot
/// block a principal forever.
fn lock_expired(lease: &Lease, now: chrono::DateTime<chrono::Utc>) -> bool {
    let spec = lease.spec.as_ref();
    let stamp = spec
        .and_then(|spec| spec.renew_time.as_ref().or(spec.acquire_time.as_ref()))
        .map(from_micro_time)
        .or_else(|| {
            lease
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|time| from_jiff(time.0))
        });
    let duration = spec
        .and_then(|spec| spec.lease_duration_seconds)
        .filter(|seconds| *seconds > 0);
    match (stamp, duration) {
        (Some(Some(stamp)), Some(seconds)) => {
            stamp + chrono::Duration::seconds(i64::from(seconds)) <= now
        }
        _ => true,
    }
}

fn to_micro_time(time: chrono::DateTime<chrono::Utc>) -> MicroTime {
    let timestamp = k8s_openapi::jiff::Timestamp::from_microsecond(time.timestamp_micros())
        .unwrap_or(k8s_openapi::jiff::Timestamp::UNIX_EPOCH);
    MicroTime(timestamp)
}

fn from_micro_time(time: &MicroTime) -> Option<chrono::DateTime<chrono::Utc>> {
    from_jiff(time.0)
}

fn from_jiff(time: k8s_openapi::jiff::Timestamp) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp_micros(time.as_microsecond())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const LEASES: &str = "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases";

    fn lock_path() -> String {
        format!("{LEASES}/{}", lock_name("abc"))
    }

    fn lock_json(renew: chrono::DateTime<chrono::Utc>, rv: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": lock_name("abc"),
                "namespace": "test-ns",
                "uid": "lock-uid",
                "resourceVersion": rv,
            },
            "spec": {
                "holderIdentity": "someone",
                "leaseDurationSeconds": LOCK_DURATION.as_secs(),
                "acquireTime": renew.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
                "renewTime": renew.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
            }
        })
    }

    fn conflict() -> ResponseTemplate {
        ResponseTemplate::new(409).set_body_json(serde_json::json!({
            "kind": "Status", "apiVersion": "v1", "status": "Failure",
            "reason": "AlreadyExists", "code": 409, "message": "exists"
        }))
    }

    async fn api(server: &MockServer) -> Api<Lease> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Api::namespaced(crate::testutil::mock_k8s_client(server), "test-ns")
    }

    #[tokio::test]
    async fn acquire_creates_the_lock_when_free() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LEASES))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(lock_json(chrono::Utc::now(), "7")),
            )
            .expect(1)
            .mount(&server)
            .await;

        let guard = acquire(&api(&server).await, &lock_name("abc"), Duration::ZERO)
            .await
            .expect("a free lock is acquired");
        let held = guard.held.as_ref().unwrap();
        assert_eq!(held.uid, "lock-uid");
        assert_eq!(held.resource_version, "7");
        assert!(guard.still_safe());
        std::mem::forget(guard);

        let requests = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(
            body["spec"]["leaseDurationSeconds"],
            LOCK_DURATION.as_secs()
        );
        assert!(body["metadata"].get("resourceVersion").is_none());
    }

    /// Two requests for one principal in the same second: the second one finds
    /// the first holder's live lock and does not proceed. This is the scenario
    /// the old post-create ranking let through.
    #[tokio::test]
    async fn acquire_refuses_while_a_live_holder_has_the_lock() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LEASES))
            .respond_with(conflict())
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(lock_path()))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(lock_json(chrono::Utc::now(), "7")),
            )
            .mount(&server)
            .await;

        let result = acquire(&api(&server).await, &lock_name("abc"), Duration::ZERO).await;
        assert!(
            matches!(result, Err(AdmissionLockError::Busy)),
            "{result:?}"
        );
        let replaced = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .any(|request| request.method == http::Method::PUT);
        assert!(!replaced, "a live lock must never be taken over");
    }

    #[tokio::test]
    async fn acquire_takes_over_an_expired_lock_with_a_version_fence() {
        let server = MockServer::start().await;
        let stale = chrono::Utc::now() - chrono::Duration::seconds(120);
        Mock::given(method("POST"))
            .and(path(LEASES))
            .respond_with(conflict())
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(lock_path()))
            .respond_with(ResponseTemplate::new(200).set_body_json(lock_json(stale, "7")))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(lock_path()))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(lock_json(chrono::Utc::now(), "8")),
            )
            .expect(1)
            .mount(&server)
            .await;

        let guard = acquire(&api(&server).await, &lock_name("abc"), Duration::ZERO)
            .await
            .expect("an expired lock is taken over");
        assert_eq!(guard.held.as_ref().unwrap().resource_version, "8");
        std::mem::forget(guard);

        let put = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.method == http::Method::PUT)
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&put.body).unwrap();
        assert_eq!(
            body["metadata"]["resourceVersion"], "7",
            "takeover must be fenced on the observed resourceVersion"
        );
    }

    /// Two contenders see the same expired lock; the API server accepts only
    /// one replace. The loser must not treat itself as the holder.
    #[tokio::test]
    async fn acquire_loses_a_contended_takeover() {
        let server = MockServer::start().await;
        let stale = chrono::Utc::now() - chrono::Duration::seconds(120);
        Mock::given(method("POST"))
            .and(path(LEASES))
            .respond_with(conflict())
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(lock_path()))
            .respond_with(ResponseTemplate::new(200).set_body_json(lock_json(stale, "7")))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path(lock_path()))
            .respond_with(conflict())
            .mount(&server)
            .await;

        let result = acquire(&api(&server).await, &lock_name("abc"), Duration::ZERO).await;
        assert!(
            matches!(result, Err(AdmissionLockError::Busy)),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn acquire_surfaces_api_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LEASES))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "Forbidden", "code": 403, "message": "forbidden"
            })))
            .mount(&server)
            .await;

        let result = acquire(
            &api(&server).await,
            &lock_name("abc"),
            Duration::from_secs(5),
        )
        .await;
        assert!(
            matches!(result, Err(AdmissionLockError::Api(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn release_is_fenced_on_uid_and_resource_version() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path(lock_path()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Success", "code": 200
            })))
            .expect(1)
            .mount(&server)
            .await;

        let guard = held_guard(api(&server).await);
        guard.release().await.unwrap();

        let delete = &server.received_requests().await.unwrap()[0];
        let body: serde_json::Value = serde_json::from_slice(&delete.body).unwrap();
        assert_eq!(body["preconditions"]["uid"], "lock-uid");
        assert_eq!(body["preconditions"]["resourceVersion"], "7");
    }

    /// A lock taken over after expiry must survive the original holder's
    /// release: the precondition fails and the release reports success.
    #[tokio::test]
    async fn release_after_takeover_leaves_the_new_holder_alone() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path(lock_path()))
            .respond_with(conflict())
            .mount(&server)
            .await;

        let guard = held_guard(api(&server).await);
        guard.release().await.unwrap();
    }

    fn held_guard(api: Api<Lease>) -> AdmissionLockGuard {
        AdmissionLockGuard {
            api,
            held: Some(HeldLock {
                name: lock_name("abc"),
                uid: "lock-uid".into(),
                resource_version: "7".into(),
            }),
            acquired_at: Instant::now(),
        }
    }

    /// A request future cancelled while holding the lock (client disconnect,
    /// pod shutdown, a panic unwinding) must not leave the principal blocked
    /// until the lock expires: dropping the guard sends the same fenced
    /// delete as an explicit release.
    #[tokio::test]
    async fn dropping_the_guard_releases_the_lock() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path(lock_path()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Success", "code": 200
            })))
            .expect(1)
            .mount(&server)
            .await;

        let handler = tokio::spawn({
            let api = api(&server).await;
            async move {
                let _guard = held_guard(api);
                std::future::pending::<()>().await;
            }
        });
        tokio::task::yield_now().await;
        handler.abort();
        let _ = handler.await;

        let delete = wait_for_delete(&server).await;
        let body: serde_json::Value = serde_json::from_slice(&delete.body).unwrap();
        assert_eq!(body["preconditions"]["uid"], "lock-uid");
        assert_eq!(body["preconditions"]["resourceVersion"], "7");
    }

    /// An explicit release is the only delete: the guard's drop does not send
    /// a second one.
    #[tokio::test]
    async fn release_then_drop_deletes_once() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path(lock_path()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Success", "code": 200
            })))
            .expect(1)
            .mount(&server)
            .await;
        held_guard(api(&server).await).release().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    async fn wait_for_delete(server: &MockServer) -> wiremock::Request {
        for _ in 0..200 {
            if let Some(delete) = server
                .received_requests()
                .await
                .unwrap()
                .into_iter()
                .find(|request| request.method == http::Method::DELETE)
            {
                return delete;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the admission lock was never released");
    }

    #[test]
    fn lock_retry_delay_backs_off_with_jitter_up_to_the_cap() {
        for attempt in 0..40 {
            let step = LOCK_RETRY_INITIAL
                .saturating_mul(1u32 << attempt.min(16))
                .min(LOCK_RETRY_MAX);
            let delay = lock_retry_delay(attempt);
            assert!(delay >= step / 2 && delay <= step, "{attempt}: {delay:?}");
            assert!(delay <= LOCK_RETRY_MAX);
        }
        assert!(lock_retry_delay(0) <= Duration::from_millis(50));
        assert!(lock_retry_delay(20) >= Duration::from_millis(500));
        let spread: std::collections::HashSet<_> = (0..32).map(|_| lock_retry_delay(10)).collect();
        assert!(spread.len() > 1, "retries must be jittered");
    }

    #[test]
    fn lock_expiry_uses_renew_time_plus_duration() {
        let now = chrono::Utc::now();
        let live: Lease = serde_json::from_value(lock_json(now, "1")).unwrap();
        assert!(!lock_expired(&live, now));
        assert!(!lock_expired(&live, now + chrono::Duration::seconds(29)));
        assert!(lock_expired(&live, now + chrono::Duration::seconds(31)));

        let malformed = Lease {
            metadata: ObjectMeta::default(),
            spec: Some(LeaseSpec::default()),
        };
        assert!(lock_expired(&malformed, now));
    }

    #[test]
    fn lock_name_is_a_valid_object_name() {
        let name = lock_name(&"a".repeat(32));
        assert!(crate::pool::is_valid_k8s_name(&name), "{name}");
    }
}
