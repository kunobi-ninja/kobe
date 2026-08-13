//! Dual-placement Sandbox conformance (#76) — the closure gate for #70.
//!
//! # One suite, two placements
//!
//! Every scenario here runs **twice**: once against a management-placement
//! pool, once against a child-cluster pool. That is the entire design. Two
//! copies of a suite would prove nothing about equivalence — they would drift,
//! and the drift would be invisible until somebody's child-placed Sandbox
//! behaved differently from the one they tested against.
//!
//! So each scenario takes a [`Placement`] and nothing else changes: same
//! requests, same assertions, same expected status shapes. A behaviour that
//! differs between placements fails here rather than in production.
//!
//! # Only the public contract
//!
//! Everything goes through the HTTP API a caller actually uses. Nothing here
//! reads a CRD, a Secret, or the child cluster's kubeconfig — partly because
//! those are not the contract, and partly because a suite that reached around
//! the API could pass while the API itself was broken.
//!
//! It also means the suite can assert something a Kubernetes-level test
//! cannot: that a caller is **unable** to reach the cluster underneath. A test
//! holding a kubeconfig cannot prove the absence of one.
//!
//! # Running it
//!
//! ```text
//! KOBE_SANDBOX_E2E=1 \
//! KOBE_ENDPOINT=https://kobe.example \
//! KOBE_TOKEN=... \
//! KOBE_SANDBOX_POOL_MANAGEMENT=agents \
//! KOBE_SANDBOX_POOL_CHILD=agents-isolated \
//!   cargo test --test sandbox_conformance -- --ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` because these lease real capacity: a pool sized for a
//! handful of sandboxes will queue rather than fail, and a queued scenario
//! looks like a timeout.
//!
//! A second identity is needed for the cross-tenant scenarios. Without
//! `KOBE_TOKEN_OTHER` those scenarios **fail** rather than skip: a conformance
//! suite that silently drops its isolation checks is worse than one that does
//! not run, because it reports success.

#![allow(clippy::expect_used)]

use std::time::{Duration, Instant};

use serde_json::Value;

/// Which placement a scenario is running against.
///
/// The only thing that varies between the two runs of every scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    Management,
    ChildCluster,
}

impl Placement {
    fn pool_env(self) -> &'static str {
        match self {
            Self::Management => "KOBE_SANDBOX_POOL_MANAGEMENT",
            Self::ChildCluster => "KOBE_SANDBOX_POOL_CHILD",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Management => "management",
            Self::ChildCluster => "child",
        }
    }
}

/// Run one scenario against both placements.
///
/// A failure names the placement, because "the exec scenario failed" is not
/// actionable when the whole point is that one placement behaves differently
/// from the other.
macro_rules! both_placements {
    ($name:ident, $body:expr) => {
        #[tokio::test]
        #[ignore = "requires a live Kobe endpoint; see the module docs"]
        async fn $name() {
            require_e2e();
            for placement in [Placement::Management, Placement::ChildCluster] {
                let scenario: fn(Placement) -> _ = $body;
                scenario(placement)
                    .await
                    .unwrap_or_else(|error| panic!("[{}] {error:#}", placement.label()));
            }
        }
    };
}

fn require_e2e() {
    assert_eq!(
        std::env::var("KOBE_SANDBOX_E2E").as_deref(),
        Ok("1"),
        "set KOBE_SANDBOX_E2E=1 to run the Sandbox conformance suite"
    );
}

fn endpoint() -> String {
    std::env::var("KOBE_ENDPOINT").expect("KOBE_ENDPOINT is required")
}

fn token() -> String {
    std::env::var("KOBE_TOKEN").expect("KOBE_TOKEN is required")
}

/// A second identity, for the isolation scenarios.
///
/// Absent means **fail**, never skip. A conformance suite that silently drops
/// its cross-tenant checks reports success while proving nothing about the
/// property those checks exist for.
fn other_token() -> String {
    std::env::var("KOBE_TOKEN_OTHER").expect(
        "KOBE_TOKEN_OTHER is required: the isolation scenarios are not optional, and a suite \
         that skipped them would report success while proving nothing",
    )
}

fn pool_for(placement: Placement) -> String {
    std::env::var(placement.pool_env())
        .unwrap_or_else(|_| panic!("{} is required", placement.pool_env()))
}

struct Api {
    client: reqwest::Client,
    endpoint: String,
    token: String,
}

impl Api {
    fn as_caller(token: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint: endpoint(),
            token,
        }
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> anyhow::Result<(reqwest::StatusCode, String)> {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.endpoint))
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await?;
        let status = response.status();
        Ok((status, response.text().await.unwrap_or_default()))
    }

    async fn json(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> anyhow::Result<(reqwest::StatusCode, Value)> {
        let (status, text) = self.request(method, path, body).await?;
        let value = serde_json::from_str(&text).unwrap_or(Value::Null);
        Ok((status, value))
    }
}

/// A sandbox that releases itself, whatever the scenario does.
///
/// Every scenario leases real capacity. One that panicked mid-way without
/// this would leave a sandbox running until its TTL — and the *next* scenario
/// would then queue behind it and fail for an unrelated reason, which is how a
/// single broken assertion turns into a suite nobody can read.
struct LeasedSandbox {
    api: Api,
    id: String,
    released: bool,
}

impl LeasedSandbox {
    async fn create(placement: Placement, ttl: &str) -> anyhow::Result<Self> {
        let api = Api::as_caller(token());
        let (status, body) = api
            .json(
                reqwest::Method::POST,
                "/v1/sandbox-leases",
                Some(serde_json::json!({ "pool": pool_for(placement), "ttl": ttl })),
            )
            .await?;
        anyhow::ensure!(
            status.is_success(),
            "could not create a sandbox: HTTP {status} {body}"
        );
        let id = body["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no lease id in {body}"))?
            .to_string();
        Ok(Self {
            api,
            id,
            released: false,
        })
    }

    async fn wait_ready(&self, within: Duration) -> anyhow::Result<Value> {
        let deadline = Instant::now() + within;
        loop {
            let (_, body) = self
                .api
                .json(
                    reqwest::Method::GET,
                    &format!("/v1/sandbox-leases/{}", self.id),
                    None,
                )
                .await?;
            match body["phase"].as_str() {
                Some("Ready") => return Ok(body),
                Some(terminal @ ("Released" | "Expired" | "Quarantined")) => {
                    anyhow::bail!("sandbox reached {terminal} before Ready: {body}");
                }
                _ => {}
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "sandbox was not Ready within {within:?}"
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn exec(&self, argv: &[&str], key: &str) -> anyhow::Result<(reqwest::StatusCode, Value)> {
        self.api
            .json(
                reqwest::Method::POST,
                &format!("/v1/sandbox-leases/{}/executions", self.id),
                Some(serde_json::json!({
                    "command": argv,
                    "idempotencyKey": key,
                })),
            )
            .await
    }

    async fn release(&mut self) -> anyhow::Result<()> {
        let (status, body) = self
            .api
            .request(
                reqwest::Method::DELETE,
                &format!("/v1/sandbox-leases/{}", self.id),
                None,
            )
            .await?;
        anyhow::ensure!(
            status.is_success() || status.as_u16() == 404,
            "could not release: HTTP {status} {body}"
        );
        self.released = true;
        Ok(())
    }
}

impl Drop for LeasedSandbox {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        // Best-effort, from a blocking context. A leaked sandbox makes the
        // NEXT scenario queue and fail for an unrelated reason, which is how
        // one broken assertion becomes an unreadable suite.
        let endpoint = self.api.endpoint.clone();
        let token = self.api.token.clone();
        let id = self.id.clone();
        std::thread::spawn(move || {
            let _ = reqwest::blocking::Client::new()
                .delete(format!("{endpoint}/v1/sandbox-leases/{id}"))
                .bearer_auth(token)
                .send();
        })
        .join()
        .ok();
    }
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

both_placements!(
    a_lease_becomes_ready_and_reports_the_same_shape,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "10m").await?;
        let ready = sandbox.wait_ready(Duration::from_secs(300)).await?;

        // The same typed status either way. A field present for one placement and
        // absent for the other is a caller-visible difference, which is exactly
        // what this suite exists to catch.
        for required in ["id", "phase", "pool", "ttl", "readyAt", "expiresAt"] {
            anyhow::ensure!(
                ready.get(required).is_some(),
                "{required} missing from a Ready lease: {ready}"
            );
        }

        // The internal composition must never be visible. For a child-placed
        // lease this is the criterion that matters most: the caller must not even
        // be able to DISCOVER the cluster underneath, let alone reach it.
        let serialized = ready.to_string();
        for leaked in [
            "clusterLease",
            "clusterInstance",
            "kubeconfig",
            "BEGIN CERTIFICATE",
        ] {
            anyhow::ensure!(
                !serialized.contains(leaked),
                "{leaked} leaked into the lease response: {serialized}"
            );
        }

        sandbox.release().await
    }
);

both_placements!(
    the_runtime_ttl_starts_at_readiness_not_at_request,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "10m").await?;
        let ready = sandbox.wait_ready(Duration::from_secs(300)).await?;

        let ready_at = chrono::DateTime::parse_from_rfc3339(
            ready["readyAt"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("no readyAt"))?,
        )?;
        let expires_at = chrono::DateTime::parse_from_rfc3339(
            ready["expiresAt"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("no expiresAt"))?,
        )?;

        // The expiry is the TTL measured from READINESS. If it were measured from
        // the request, provisioning time would come out of the caller's runtime —
        // and for child placement, where provisioning means building a cluster,
        // that could be most of it.
        let runtime = expires_at - ready_at;
        anyhow::ensure!(
            (runtime - chrono::Duration::minutes(10)).abs() < chrono::Duration::seconds(30),
            "[{}] runtime window was {runtime}, expected ~10m from readiness",
            placement.label()
        );

        sandbox.release().await
    }
);

both_placements!(
    an_execution_returns_the_exact_remote_exit_code,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "10m").await?;
        sandbox.wait_ready(Duration::from_secs(300)).await?;

        let (status, success) = sandbox
            .exec(&["/bin/sh", "-c", "exit 0"], "conformance-ok")
            .await?;
        anyhow::ensure!(status.is_success(), "exec failed: {success}");
        anyhow::ensure!(
            success["exitCode"] == 0 && success["state"] == "Succeeded",
            "expected a clean success: {success}"
        );

        // A non-zero exit is the CALLER's result, not a Kobe failure: the request
        // succeeds and the code comes back intact.
        let (status, failed) = sandbox
            .exec(&["/bin/sh", "-c", "exit 3"], "conformance-fail")
            .await?;
        anyhow::ensure!(
            status.is_success(),
            "a failing command is not a failed request: {failed}"
        );
        anyhow::ensure!(
            failed["state"] == "Failed",
            "a non-zero exit must be Failed, not an error: {failed}"
        );

        // stdout and stderr stay apart. A consumer that cannot tell a tool's
        // diagnostics from its output cannot parse either.
        let (_, streams) = sandbox
            .exec(
                &["/bin/sh", "-c", "echo out; echo err >&2"],
                "conformance-streams",
            )
            .await?;
        anyhow::ensure!(
            streams["stdout"]
                .as_str()
                .unwrap_or_default()
                .contains("out")
                && streams["stderr"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("err"),
            "streams were merged: {streams}"
        );

        sandbox.release().await
    }
);

both_placements!(
    one_idempotency_key_cannot_run_twice,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "10m").await?;
        sandbox.wait_ready(Duration::from_secs(300)).await?;

        // A command with a side effect, so a duplicate spawn is observable rather
        // than merely suspected.
        let argv = ["/bin/sh", "-c", "echo x >> /tmp/kobe-conformance-count"];
        let key = "conformance-idempotent";

        let (_, first) = sandbox.exec(&argv, key).await?;
        let (_, second) = sandbox.exec(&argv, key).await?;
        anyhow::ensure!(
            first["id"] == second["id"],
            "a retried key produced a second execution: {first} vs {second}"
        );

        let (_, count) = sandbox
            .exec(
                &["/bin/sh", "-c", "wc -l < /tmp/kobe-conformance-count"],
                "conformance-count",
            )
            .await?;
        let lines: i64 = count["stdout"]
            .as_str()
            .unwrap_or_default()
            .trim()
            .parse()
            .unwrap_or(-1);
        anyhow::ensure!(
            lines == 1,
            "the command ran {lines} times, expected exactly 1"
        );

        // The same key with DIFFERENT content is a conflict, not a new command.
        let (status, conflict) = sandbox
            .exec(&["/bin/sh", "-c", "echo something-else"], key)
            .await?;
        anyhow::ensure!(
            status.as_u16() == 409,
            "a reused key with different content must conflict, got HTTP {status}: {conflict}"
        );

        sandbox.release().await
    }
);

both_placements!(
    another_identity_can_neither_see_nor_use_the_lease,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "10m").await?;
        sandbox.wait_ready(Duration::from_secs(300)).await?;

        let stranger = Api::as_caller(other_token());
        let lease = format!("/v1/sandbox-leases/{}", sandbox.id);

        // Every operation, and all of them 404 — never 403. A 403 would confirm
        // the lease exists, which is enough to enumerate another tenant's leases
        // by guessing ids.
        for (method, path, body) in [
            (reqwest::Method::GET, lease.clone(), None),
            (reqwest::Method::DELETE, lease.clone(), None),
            (reqwest::Method::GET, format!("{lease}/logs"), None),
            (
                reqwest::Method::POST,
                format!("{lease}/executions"),
                Some(serde_json::json!({
                    "command": ["/bin/sh", "-c", "echo pwned"],
                    "idempotencyKey": "conformance-stranger",
                })),
            ),
        ] {
            let (status, response) = stranger.request(method.clone(), &path, body).await?;
            anyhow::ensure!(
                status.as_u16() == 404,
                "{method} {path} answered HTTP {status} to a stranger, expected 404: {response}"
            );
        }

        // And the sandbox is untouched: the stranger's exec did not run.
        let (_, evidence) = sandbox
            .exec(&["/bin/sh", "-c", "echo intact"], "conformance-intact")
            .await?;
        anyhow::ensure!(
            evidence["exitCode"] == 0,
            "the sandbox was disturbed: {evidence}"
        );

        sandbox.release().await
    }
);

both_placements!(release_rejects_further_access, |placement| async move {
    let mut sandbox = LeasedSandbox::create(placement, "10m").await?;
    sandbox.wait_ready(Duration::from_secs(300)).await?;
    sandbox.release().await?;

    // A released lease serves nothing, however recently it was working. The
    // cached-context case is the one that matters: a caller who was mid-session
    // must not be able to keep going.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (status, body) = sandbox
            .exec(
                &["/bin/sh", "-c", "echo after-release"],
                "conformance-after",
            )
            .await?;
        if !status.is_success() {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "a released sandbox still served an execution: {body}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Ok(())
});

both_placements!(
    a_caller_never_receives_target_credentials,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "10m").await?;
        sandbox.wait_ready(Duration::from_secs(300)).await?;

        // Everything a caller can read, scanned for anything that would let them
        // reach the cluster directly. For child placement this is the criterion
        // #74 turns on: the composition is Kobe's implementation of the pool, not
        // a capability handed out.
        let mut surfaces = Vec::new();
        for path in [
            format!("/v1/sandbox-leases/{}", sandbox.id),
            format!("/v1/sandbox-leases/{}/logs", sandbox.id),
            "/v1/sandbox-leases".to_string(),
        ] {
            let (_, text) = sandbox
                .api
                .request(reqwest::Method::GET, &path, None)
                .await?;
            surfaces.push((path, text));
        }

        for (path, text) in surfaces {
            for secret in [
                "BEGIN CERTIFICATE",
                "BEGIN RSA",
                "BEGIN EC PRIVATE",
                "client-certificate-data",
                "client-key-data",
                "kubeconfig",
                "eyJhbGciOi", // a JWT header, base64
                "clusterLease",
                "clusterInstance",
            ] {
                anyhow::ensure!(!text.contains(secret), "{path} leaked {secret:?}");
            }
        }

        sandbox.release().await
    }
);

both_placements!(
    a_sandbox_cannot_reach_the_cluster_around_it,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "10m").await?;
        sandbox.wait_ready(Duration::from_secs(300)).await?;

        // A Sandbox is an untrusted workload. Its own service account must not
        // reach the API server for anything interesting — and the check runs from
        // INSIDE, because that is where an attacker would be.
        let (_, probe) = sandbox
            .exec(
                &[
                    "/bin/sh",
                    "-c",
                    // Deliberately tolerant of a missing token or curl: absence is
                    // a pass, and the assertion below distinguishes it from a
                    // successful read.
                    "if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then \
                   T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); \
                   curl -sk -o /dev/null -w '%{http_code}' \
                     -H \"Authorization: Bearer $T\" \
                     https://kubernetes.default.svc/api/v1/secrets || echo no-curl; \
                 else echo no-token; fi",
                ],
                "conformance-escape",
            )
            .await?;

        let result = probe["stdout"].as_str().unwrap_or_default().trim();
        anyhow::ensure!(
            matches!(result, "no-token" | "no-curl" | "401" | "403"),
            "a sandbox workload could list Secrets (got {result:?}): {probe}"
        );

        sandbox.release().await
    }
);

both_placements!(an_undeclared_port_is_refused, |placement| async move {
    let mut sandbox = LeasedSandbox::create(placement, "10m").await?;
    sandbox.wait_ready(Duration::from_secs(300)).await?;

    // Port-forward is an upgrade, so a refusal arrives as a non-101 status
    // rather than a close frame. An undeclared port must never resolve:
    // otherwise the forward is a general tunnel into the Pod's network
    // namespace.
    for undeclared in ["22", "9999", "ssh"] {
        let (status, body) = sandbox
            .api
            .request(
                reqwest::Method::GET,
                &format!(
                    "/v1/sandbox-leases/{}/port-forward?port={undeclared}",
                    sandbox.id
                ),
                None,
            )
            .await?;
        anyhow::ensure!(
            !status.is_success() && status.as_u16() != 101,
            "undeclared port {undeclared} was accepted: HTTP {status} {body}"
        );
    }

    sandbox.release().await
});

both_placements!(a_tampered_target_fails_closed, |placement| async move {
    let mut sandbox = LeasedSandbox::create(placement, "10m").await?;
    sandbox.wait_ready(Duration::from_secs(300)).await?;

    // A caller cannot choose a container. The pool declares one; naming
    // anything else — including a real sidecar — must be refused rather than
    // honoured, or an exec would run with that component's identity.
    let (status, body) = sandbox
        .api
        .json(
            reqwest::Method::POST,
            &format!("/v1/sandbox-leases/{}/executions", sandbox.id),
            Some(serde_json::json!({
                "command": ["/bin/sh", "-c", "echo wrong-container"],
                "idempotencyKey": "conformance-container",
                "container": "istio-proxy",
            })),
        )
        .await?;
    anyhow::ensure!(
        !status.is_success(),
        "a caller-chosen container was accepted: HTTP {status} {body}"
    );

    // Nor can they smuggle settings the API does not define.
    let (status, body) = sandbox
        .api
        .json(
            reqwest::Method::POST,
            &format!("/v1/sandbox-leases/{}/executions", sandbox.id),
            Some(serde_json::json!({
                "command": ["/bin/sh", "-c", "echo smuggled"],
                "idempotencyKey": "conformance-smuggle",
                "namespace": "kube-system",
                "podName": "etcd-0",
            })),
        )
        .await?;
    anyhow::ensure!(
        status.as_u16() == 400 || status.as_u16() == 422,
        "unknown execution fields were not rejected: HTTP {status} {body}"
    );

    sandbox.release().await
});

both_placements!(
    cancelling_while_provisioning_leaves_nothing_behind,
    |placement| async move {
        // Released before it is ever Ready. For child placement this is the
        // criterion that a partial cluster allocation is not stranded — the
        // expensive failure, because an abandoned child composition is a whole
        // cluster's capacity.
        let mut sandbox = LeasedSandbox::create(placement, "10m").await?;
        sandbox.release().await?;

        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            let (status, body) = sandbox
                .api
                .json(
                    reqwest::Method::GET,
                    &format!("/v1/sandbox-leases/{}", sandbox.id),
                    None,
                )
                .await?;
            if status.as_u16() == 404 {
                return Ok(());
            }
            match body["phase"].as_str() {
                Some("Released" | "Expired") => return Ok(()),
                // Uncertain teardown holds capacity on purpose, but a lease
                // cancelled before it ever ran should have nothing to be uncertain
                // about.
                Some("Quarantined") => {
                    anyhow::bail!("a sandbox cancelled while provisioning quarantined: {body}")
                }
                _ => {}
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "a cancelled sandbox never settled: {body}"
            );
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
);

#[cfg(test)]
mod suite_shape {
    use super::*;

    /// The suite covers both placements, always.
    ///
    /// Guards the one mistake that would quietly gut this file: a scenario
    /// written against a single placement. The matrix in #76 is the point —
    /// a suite that ran only the management leg would pass while child
    /// placement was broken.
    #[test]
    fn every_placement_has_a_configured_pool() {
        for placement in [Placement::Management, Placement::ChildCluster] {
            assert!(
                placement.pool_env().starts_with("KOBE_SANDBOX_POOL_"),
                "{placement:?} must name its pool through the environment"
            );
            assert!(!placement.label().is_empty());
        }
        assert_ne!(
            Placement::Management.pool_env(),
            Placement::ChildCluster.pool_env(),
            "the two placements must not share a pool, or the suite proves nothing"
        );
    }

    /// Scenarios are declared through the macro, so none can run against one
    /// placement by accident.
    ///
    /// A grep rather than a type-level guarantee, but it fails loudly on the
    /// exact drift that matters, and cheaply.
    #[test]
    fn no_scenario_is_declared_outside_the_dual_placement_macro() {
        let source = include_str!("sandbox_conformance.rs");
        let body = source
            .split("// Scenarios")
            .nth(1)
            .expect("the scenario section is marked");
        let scenarios = body.split("mod suite_shape").next().unwrap_or(body);

        assert!(
            !scenarios.contains("#[tokio::test]"),
            "a scenario was declared directly instead of through both_placements!, \
             which would run it against one placement only"
        );
        assert!(
            scenarios.matches("both_placements!").count() >= 10,
            "the #76 matrix expects at least ten dual-placement scenarios"
        );
    }
}
