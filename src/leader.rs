use std::time::Duration;

use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use kube::Client;
use tracing::{info, warn};

const LEASE_DURATION_SECS: i32 = 15;
const RENEW_INTERVAL: Duration = Duration::from_secs(10);
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Convert chrono::DateTime<Utc> to k8s-openapi's jiff::Timestamp (used by MicroTime in k8s-openapi 0.27+).
fn chrono_to_timestamp(
    dt: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<k8s_openapi::jiff::Timestamp> {
    k8s_openapi::jiff::Timestamp::from_second(dt.timestamp())
        .map_err(|e| anyhow::anyhow!("Timestamp conversion failed: {e}"))
}

/// Convert k8s-openapi's jiff::Timestamp back to chrono::DateTime<Utc>.
/// Returns None if the timestamp is not representable, which callers should
/// treat as "lease is expired" (safe default).
fn timestamp_to_chrono(ts: &k8s_openapi::jiff::Timestamp) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp(ts.as_second(), 0)
}

/// Run leader election using a Kubernetes Lease object.
pub async fn run_leader_election(
    client: Client,
    namespace: &str,
    lease_name: &str,
) -> anyhow::Result<tokio::sync::watch::Receiver<bool>> {
    let leases: Api<Lease> = Api::namespaced(client.clone(), namespace);
    let identity = pod_identity();

    info!(identity = %identity, lease = lease_name, "Starting leader election");

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(300);
    loop {
        if tokio::time::Instant::now() > deadline {
            anyhow::bail!("Failed to acquire leader lease within 5 minutes");
        }
        match try_acquire(&leases, lease_name, &identity).await {
            Ok(true) => {
                info!(identity = %identity, "Acquired leader lease");
                break;
            }
            Ok(false) => {
                info!("Another instance is leader, waiting...");
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
            Err(e) => {
                warn!("Leader election error: {e}, retrying...");
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
    }

    let (tx, rx) = tokio::sync::watch::channel(true);
    let ns = namespace.to_string();
    let ln = lease_name.to_string();
    tokio::spawn(async move {
        renew_loop(client, &ns, &ln, &identity, tx).await;
    });

    Ok(rx)
}

#[tracing::instrument(skip_all)]
async fn try_acquire(leases: &Api<Lease>, name: &str, identity: &str) -> anyhow::Result<bool> {
    let now = chrono::Utc::now();
    let micro_now = MicroTime(chrono_to_timestamp(now)?);

    match leases.get(name).await {
        Ok(existing) => {
            let spec = existing.spec.as_ref();
            let holder = spec.and_then(|s| s.holder_identity.as_deref());
            let renew_time = spec.and_then(|s| s.renew_time.as_ref());
            let lease_dur = spec
                .and_then(|s| s.lease_duration_seconds)
                .unwrap_or(LEASE_DURATION_SECS);

            if holder == Some(identity) {
                renew_lease(leases, name, identity).await?;
                return Ok(true);
            }

            let expired = match renew_time {
                Some(MicroTime(t)) => match timestamp_to_chrono(t) {
                    Some(renew_chrono) => {
                        let deadline = renew_chrono + chrono::Duration::seconds(lease_dur as i64);
                        now > deadline
                    }
                    None => {
                        // Unrepresentable timestamp — treat as expired
                        warn!(
                            lease = name,
                            "Lease has unrepresentable renew timestamp, treating as expired"
                        );
                        true
                    }
                },
                None => true,
            };

            if expired {
                let transitions = spec.and_then(|s| s.lease_transitions).unwrap_or(0) + 1;

                let patch = serde_json::json!({
                    "spec": {
                        "holderIdentity": identity,
                        "leaseDurationSeconds": LEASE_DURATION_SECS,
                        "acquireTime": micro_now,
                        "renewTime": micro_now,
                        "leaseTransitions": transitions
                    }
                });
                leases
                    .patch(
                        name,
                        &PatchParams::apply("kunobi-pool-operator"),
                        &Patch::Merge(&patch),
                    )
                    .await?;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            let lease = Lease {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    ..Default::default()
                },
                spec: Some(k8s_openapi::api::coordination::v1::LeaseSpec {
                    holder_identity: Some(identity.to_string()),
                    lease_duration_seconds: Some(LEASE_DURATION_SECS),
                    acquire_time: Some(micro_now.clone()),
                    renew_time: Some(micro_now),
                    lease_transitions: Some(0),
                    ..Default::default()
                }),
            };
            leases.create(&PostParams::default(), &lease).await?;
            Ok(true)
        }
        Err(e) => Err(e.into()),
    }
}

async fn renew_lease(leases: &Api<Lease>, name: &str, identity: &str) -> anyhow::Result<()> {
    let now = MicroTime(chrono_to_timestamp(chrono::Utc::now())?);
    let patch = serde_json::json!({
        "spec": {
            "holderIdentity": identity,
            "renewTime": now
        }
    });
    leases
        .patch(
            name,
            &PatchParams::apply("kunobi-pool-operator"),
            &Patch::Merge(&patch),
        )
        .await?;
    Ok(())
}

async fn renew_loop(
    client: Client,
    namespace: &str,
    lease_name: &str,
    identity: &str,
    tx: tokio::sync::watch::Sender<bool>,
) {
    let leases: Api<Lease> = Api::namespaced(client, namespace);
    let mut interval = tokio::time::interval(RENEW_INTERVAL);
    let mut consecutive_failures = 0u32;

    loop {
        interval.tick().await;

        match renew_lease(&leases, lease_name, identity).await {
            Ok(()) => {
                consecutive_failures = 0;
            }
            Err(e) => {
                consecutive_failures += 1;
                warn!(
                    failures = consecutive_failures,
                    "Failed to renew leader lease: {e}"
                );
                if consecutive_failures >= 2 {
                    warn!("Lost leader lease — stepping down");
                    let _ = tx.send(false);
                    return;
                }
            }
        }
    }
}

fn pod_identity() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // -----------------------------------------------------------------------
    // Pure function tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_chrono_to_timestamp_now() {
        let now = chrono::Utc::now();
        let result = chrono_to_timestamp(now);
        assert!(
            result.is_ok(),
            "chrono_to_timestamp(Utc::now()) should succeed"
        );
    }

    #[test]
    fn test_chrono_to_timestamp_epoch() {
        let epoch = chrono::DateTime::from_timestamp(0, 0).unwrap();
        let result = chrono_to_timestamp(epoch);
        assert!(result.is_ok(), "chrono_to_timestamp(epoch) should succeed");
        assert_eq!(result.unwrap().as_second(), 0);
    }

    #[test]
    fn test_timestamp_to_chrono_roundtrip() {
        let original = chrono::Utc::now();
        // Truncate to seconds since MicroTime/jiff::Timestamp only preserves seconds
        let original_secs = chrono::DateTime::from_timestamp(original.timestamp(), 0).unwrap();
        let ts = chrono_to_timestamp(original_secs).unwrap();
        let back = timestamp_to_chrono(&ts);
        assert_eq!(
            back,
            Some(original_secs),
            "roundtrip should preserve the chrono value (truncated to seconds)"
        );
    }

    #[test]
    fn test_pod_identity_non_empty() {
        let id = pod_identity();
        assert!(
            !id.is_empty(),
            "pod_identity() must return a non-empty string"
        );
    }

    #[test]
    fn test_pod_identity_deterministic_with_hostname() {
        // Use a unique value to avoid interference with other tests
        let unique = format!("test-leader-host-{}", uuid::Uuid::new_v4());
        // Safety: this test is not run in parallel with others that read HOSTNAME
        // because we use a unique value and check it immediately.
        unsafe {
            std::env::set_var("HOSTNAME", &unique);
        }
        let id = pod_identity();
        assert_eq!(
            id, unique,
            "pod_identity() should return HOSTNAME env value"
        );
        // Clean up
        unsafe {
            std::env::remove_var("HOSTNAME");
        }
    }

    // -----------------------------------------------------------------------
    // Helper: build a kube::Client backed by a wiremock MockServer
    // -----------------------------------------------------------------------

    fn mock_client(server: &MockServer) -> Client {
        // Ensure a TLS crypto provider is available (rustls 0.23+ requires one).
        // Both aws-lc-rs and ring features are active in the dependency tree, so
        // we must manually install a default before kube creates its HTTP client.
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::testutil::mock_k8s_client(server)
    }

    /// Build a Lease JSON response for wiremock.
    fn lease_json(name: &str, ns: &str, holder: &str, renew_time: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": name,
                "namespace": ns
            },
            "spec": {
                "holderIdentity": holder,
                "leaseDurationSeconds": LEASE_DURATION_SECS,
                "renewTime": renew_time
            }
        })
    }

    // -----------------------------------------------------------------------
    // wiremock-based K8s Lease tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_try_acquire_creates_lease_when_not_found() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let leases: Api<Lease> = Api::namespaced(client, "test-ns");
        let identity = "my-pod-id";

        // GET returns 404 — lease does not exist
        Mock::given(method("GET"))
            .and(path(
                "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases/my-lease",
            ))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(crate::testutil::k8s_not_found("leases", "my-lease")),
            )
            .expect(1)
            .mount(&server)
            .await;

        // POST creates the lease — return 201
        Mock::given(method("POST"))
            .and(path(
                "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases",
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(lease_json(
                "my-lease",
                "test-ns",
                identity,
                "2026-02-26T10:00:00.000000Z",
            )))
            .expect(1)
            .mount(&server)
            .await;

        let result = try_acquire(&leases, "my-lease", identity).await;
        assert!(result.is_ok(), "try_acquire should succeed: {result:?}");
        assert!(result.unwrap(), "try_acquire should return true (created)");
    }

    #[tokio::test]
    async fn test_try_acquire_renews_own_lease() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let leases: Api<Lease> = Api::namespaced(client, "test-ns");
        let identity = "my-pod-id";

        // GET returns 200 with lease held by us
        Mock::given(method("GET"))
            .and(path(
                "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases/my-lease",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease_json(
                "my-lease",
                "test-ns",
                identity,
                "2026-02-26T10:00:00.000000Z",
            )))
            .expect(1)
            .mount(&server)
            .await;

        // PATCH to renew — return 200
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases/my-lease",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease_json(
                "my-lease",
                "test-ns",
                identity,
                "2026-02-26T10:00:01.000000Z",
            )))
            .expect(1)
            .mount(&server)
            .await;

        let result = try_acquire(&leases, "my-lease", identity).await;
        assert!(result.is_ok(), "try_acquire should succeed: {result:?}");
        assert!(
            result.unwrap(),
            "try_acquire should return true (renewed own lease)"
        );
    }

    #[tokio::test]
    async fn test_try_acquire_returns_false_when_held_by_other() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let leases: Api<Lease> = Api::namespaced(client, "test-ns");
        let identity = "my-pod-id";

        // renewTime = now (not expired). Use a time far in the future to ensure it's fresh.
        let renew_time = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.6fZ")
            .to_string();

        // GET returns 200 with lease held by another pod
        Mock::given(method("GET"))
            .and(path(
                "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases/my-lease",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease_json(
                "my-lease",
                "test-ns",
                "other-pod",
                &renew_time,
            )))
            .expect(1)
            .mount(&server)
            .await;

        let result = try_acquire(&leases, "my-lease", identity).await;
        assert!(result.is_ok(), "try_acquire should succeed: {result:?}");
        assert!(
            !result.unwrap(),
            "try_acquire should return false (held by another pod, not expired)"
        );
    }

    #[tokio::test]
    async fn test_renew_lease_success() {
        let server = MockServer::start().await;
        let client = mock_client(&server);
        let leases: Api<Lease> = Api::namespaced(client, "test-ns");
        let identity = "my-pod-id";

        // PATCH returns 200
        Mock::given(method("PATCH"))
            .and(path(
                "/apis/coordination.k8s.io/v1/namespaces/test-ns/leases/my-lease",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(lease_json(
                "my-lease",
                "test-ns",
                identity,
                "2026-02-26T10:00:01.000000Z",
            )))
            .expect(1)
            .mount(&server)
            .await;

        let result = renew_lease(&leases, "my-lease", identity).await;
        assert!(result.is_ok(), "renew_lease should succeed: {result:?}");
    }
}
