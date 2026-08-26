//! Dual-placement Sandbox conformance (#76) — the closure gate for #70.
//!
//! # One suite, two placements
//!
//! Every scenario here runs its behaviour against a management-placement pool
//! and then proves the child-cluster pool's **current ship-state boundary**:
//! child placement has no in-child certification and teardown receipt
//! protocol yet, so its pool must refuse every lease fail-closed — and each
//! scenario asserts exactly that refusal for the lease it would otherwise
//! run under. When in-child certification lands, the child arm goes back to
//! executing the scenario itself, restoring full equivalence coverage.
//!
//! The one-suite shape is still the point: two copies of a suite would prove
//! nothing about equivalence — they would drift, and the drift would be
//! invisible until somebody's child-placed Sandbox behaved differently from
//! the one they tested against. Each scenario takes a [`Placement`] and
//! nothing else changes: same requests, same assertions, same expected
//! status shapes.
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
//! # The harness is not the target
//!
//! Some properties cannot be provoked through the contract at all. A crash
//! never causing a duplicate spawn needs a crash; uncertain teardown withholding
//! capacity needs teardown made uncertain; Ctrl-C reaching the workload needs a
//! terminal. #138 supplies the lifecycle/terminal disturbances and #82 adds
//! the exact execution crashpoints through `hack/e2e.ts`; this suite
//! *invokes* them, but it still does not perform them and still asserts only
//! through HTTP.
//!
//! That boundary is the point rather than an inconvenience. A suite that could
//! break its own target could also mask a break it did not intend, and a suite
//! reaching into the cluster to check its work could pass while the API was
//! broken. So the disturbance happens in another process, and every assertion
//! about the result comes back through the same public surface every other
//! scenario uses.
//!
//! `KOBE_SANDBOX_HARNESS` names that command — `bun run ./hack/e2e.ts`. Absent,
//! the scenarios that need it **fail**, exactly like a missing
//! `KOBE_TOKEN_OTHER`. #138 says why in one line: a scenario that cannot run
//! reads as a scenario that passed.
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
///
/// Leading attributes are forwarded, so a scenario can carry the doc comment
/// that says what breaks when it does not hold. Without the passthrough that
/// reasoning would have to live in an ordinary comment, where `cargo doc` and
/// a reader jumping to the definition both miss it.
macro_rules! both_placements {
    ($(#[$attribute:meta])* $name:ident, $body:expr) => {
        $(#[$attribute])*
        #[tokio::test]
        #[ignore = "requires a live Kobe endpoint; see the module docs"]
        async fn $name() {
            require_e2e();
            let scenario: fn(Placement) -> _ = $body;
            scenario(Placement::Management)
                .await
                .unwrap_or_else(|error| panic!("[{}] {error:#}", Placement::Management.label()));
            // Child placement deliberately ships fail-closed: no in-child
            // certification and teardown receipt protocol exists yet, so the
            // honest child-placement property every scenario can prove today
            // is that the uncertified pool REFUSES the lease the scenario
            // would otherwise run under. When in-child certification lands,
            // this arm goes back to running the scenario itself.
            assert_child_placement_refuses_leases()
                .await
                .unwrap_or_else(|error| {
                    panic!("[{}] {error:#}", Placement::ChildCluster.label())
                });
        }
    };
}

/// The child-placement ship-state boundary, proven at the API surface: an
/// uncertified pool must refuse admission with the fail-closed 503 before any
/// pending lease exists — never accept-and-strand.
async fn assert_child_placement_refuses_leases() -> anyhow::Result<()> {
    let api = Api::as_caller(token());
    let (status, body) = api
        .json(
            reqwest::Method::POST,
            "/v1/sandbox-leases",
            Some(serde_json::json!({
                "pool": pool_for(Placement::ChildCluster),
                "ttl": "5m"
            })),
        )
        .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "an uncertified child pool must refuse leases fail-closed with 503, \
         got HTTP {status} {body}"
    );
    Ok(())
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

/// The command that disturbs the target.
///
/// Absent means **fail**, never skip — the same rule as [`other_token`], for
/// the same reason. The properties this unlocks are otherwise asserted by
/// construction and proven nowhere; a scenario that quietly declined to run
/// would leave them looking covered.
fn harness_command() -> Vec<String> {
    let configured = std::env::var("KOBE_SANDBOX_HARNESS").expect(
        "KOBE_SANDBOX_HARNESS is required: it names the command that restarts, breaks and \
         attaches to the target (e.g. `bun run ./hack/e2e.ts`). The restart, failure-injection \
         and pty scenarios cannot run without it, and a skipped scenario reads as a passing one",
    );
    configured
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>()
}

/// Invoke the harness, failing with everything it printed.
///
/// The whole output rather than a status: these subcommands fail for reasons
/// the suite cannot see — a lease that never reached the stage a restart was
/// aimed at, a ClusterRole that never granted the verb being revoked — and a
/// bare exit code would send the reader to the wrong side of the boundary.
async fn harness(argv: &[&str]) -> anyhow::Result<String> {
    let command = harness_command();
    let (program, prefix) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("KOBE_SANDBOX_HARNESS is set but empty"))?;

    let output = tokio::process::Command::new(program)
        .args(prefix)
        .args(argv)
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    anyhow::ensure!(
        output.status.success(),
        "harness `{} {}` failed ({}):\n{stdout}\n{}",
        command.join(" "),
        argv.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(stdout)
}

async fn inject_execution_crash(kind: &str, lease: &str, key: &str) -> anyhow::Result<()> {
    harness(&[
        "inject-failure",
        "--kind",
        kind,
        "--lease",
        lease,
        "--idempotency-key",
        key,
        "--timeout",
        "600",
    ])
    .await
    .map(|_| ())
}

async fn clear_execution_crash(kind: &str) -> anyhow::Result<()> {
    harness(&["clear-failure", "--kind", kind, "--timeout", "600"])
        .await
        .map(|_| ())
}

fn interrupted_request(
    attempted: &anyhow::Result<(reqwest::StatusCode, Value)>,
    window: &str,
) -> anyhow::Result<()> {
    if let Ok((status, body)) = attempted {
        anyhow::ensure!(
            !status.is_success(),
            "{window} returned success instead of interrupting the first request: {body}"
        );
    }
    Ok(())
}

fn stable_execution(first: &Value, second: &Value, window: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        first == second,
        "{window} changed its durable answer across an exact retry: {first} then {second}"
    );
    Ok(())
}

/// A value no other run of this suite can produce.
///
/// A restart scenario outlives reconciles and retries, so a fixed marker from
/// an earlier run could still be sitting in the sandbox — and matching it would
/// pass without anything having happened this time.
fn nonce(placement: Placement) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    format!("{}-{now}", placement.label())
}

/// The UID a lease recorded for one composed object.
///
/// UIDs rather than names throughout, because a same-named replacement is
/// fresh capacity rather than evidence of continuity — the exact distinction
/// the operator's own teardown receipts are built on.
fn provenance_uid(lease: &Value, field: &str) -> anyhow::Result<String> {
    lease["target"][field]["uid"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("no target.{field}.uid in {lease}"))
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
        anyhow::ensure!(
            body["provisioning_deadline"].as_str().is_some(),
            "accepted lease has no provisioning_deadline: {body}"
        );
        if body["status"] == "admission_pending" {
            anyhow::ensure!(
                body["retry"] == false && body["statusUrl"] == format!("/v1/sandbox-leases/{id}"),
                "admission_pending must be a durable non-retry handle: {body}"
            );
        }
        Ok(Self {
            api,
            id,
            released: false,
        })
    }

    /// The lease as its own holder sees it, right now.
    async fn status(&self) -> anyhow::Result<(reqwest::StatusCode, Value)> {
        self.api
            .json(
                reqwest::Method::GET,
                &format!("/v1/sandbox-leases/{}", self.id),
                None,
            )
            .await
    }

    async fn wait_ready(&self, within: Duration) -> anyhow::Result<Value> {
        let deadline = Instant::now() + within;
        loop {
            let (status, body) = self
                .api
                .json(
                    reqwest::Method::GET,
                    &format!("/v1/sandbox-leases/{}", self.id),
                    None,
                )
                .await?;
            anyhow::ensure!(
                status != reqwest::StatusCode::NOT_FOUND,
                "sandbox admission was cancelled before Ready: {body}"
            );
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

    /// Wait for a clean terminal checkpoint exposed through the caller API.
    ///
    /// A terminal phase alone is not teardown evidence. `FootprintAbsent` is
    /// the placement-specific proof (exact descendant scans for management, a
    /// consumed destroy receipt for child placement), while `CleanupVerified`
    /// proves execution records and admission reservations were retired before
    /// capacity moved.
    async fn wait_terminal_cleanup(
        &self,
        expected_phase: &str,
        expected_cause: &str,
        within: Duration,
    ) -> anyhow::Result<Value> {
        let deadline = Instant::now() + within;
        loop {
            let (status, body) = self.status().await?;
            anyhow::ensure!(
                status.is_success(),
                "could not read terminal status: {body}"
            );
            match body["phase"].as_str() {
                Some(phase) if phase == expected_phase => {
                    anyhow::ensure!(
                        body["release_cause"] == expected_cause,
                        "{expected_phase} recorded the wrong release cause: {body}"
                    );
                    for required in ["FootprintAbsent", "CleanupVerified"] {
                        let proven = body["conditions"].as_array().is_some_and(|conditions| {
                            conditions.iter().any(|condition| {
                                condition["type"] == required && condition["status"] == "True"
                            })
                        });
                        anyhow::ensure!(
                            proven,
                            "{expected_phase} was exposed without {required}=True: {body}"
                        );
                    }
                    return Ok(body);
                }
                Some(terminal @ ("Released" | "Expired" | "Quarantined")) => {
                    anyhow::bail!("expected {expected_phase}, reached {terminal} instead: {body}");
                }
                _ => {}
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "sandbox did not reach verified {expected_phase} cleanup within {within:?}: {body}"
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

    /// Count an execution's externally visible side effect without assuming
    /// the marker exists. Zero is therefore evidence for the pre-spawn window,
    /// while one distinguishes idempotency from a duplicated hidden spawn.
    async fn marker_count(&self, marker: &str, key: &str) -> anyhow::Result<i64> {
        let script = format!("if [ -f {marker} ]; then wc -l < {marker}; else echo 0; fi");
        let (status, observed) = self.exec(&["/bin/sh", "-c", script.as_str()], key).await?;
        anyhow::ensure!(
            status.is_success() && observed["state"] == "Succeeded",
            "could not inspect execution side effects: HTTP {status} {observed}"
        );
        observed["stdout"]
            .as_str()
            .unwrap_or_default()
            .trim()
            .parse()
            .map_err(Into::into)
    }

    /// Start one supervised process and prove its retained output is readable.
    ///
    /// Returning only after the marker appears makes teardown tests
    /// non-vacuous: they release or expire a lease that definitely owns a live
    /// execution record and process group.
    async fn start_detached(
        &self,
        key: &str,
        marker: &str,
        timeout: &str,
    ) -> anyhow::Result<String> {
        let script = format!("echo {marker}; while :; do sleep 1; done");
        self.start_detached_script(key, &script, marker, timeout)
            .await
    }

    /// Start an exact background script and wait until its retained output
    /// proves the process reached the caller-selected readiness point.
    async fn start_detached_script(
        &self,
        key: &str,
        script: &str,
        marker: &str,
        timeout: &str,
    ) -> anyhow::Result<String> {
        let (status, created) = self
            .api
            .json(
                reqwest::Method::POST,
                &format!("/v1/sandbox-leases/{}/executions", self.id),
                Some(serde_json::json!({
                    "command": ["/bin/sh", "-c", script],
                    "idempotencyKey": key,
                    "detach": true,
                    "timeout": timeout,
                })),
            )
            .await?;
        anyhow::ensure!(
            status == reqwest::StatusCode::ACCEPTED,
            "detached execution was not accepted: HTTP {status} {created}"
        );
        let execution = created["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("detached execution returned no id: {created}"))?
            .to_string();
        let execution_path = format!("/v1/sandbox-leases/{}/executions/{execution}", self.id);

        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let (status, logs) = self
                .api
                .json(
                    reqwest::Method::GET,
                    &format!("{execution_path}/logs?stdoutOffset=0&stderrOffset=0"),
                    None,
                )
                .await?;
            anyhow::ensure!(
                status.is_success(),
                "could not read detached logs: HTTP {status} {logs}"
            );
            if logs["stdout"]["data"]
                .as_str()
                .unwrap_or_default()
                .contains(marker)
            {
                anyhow::ensure!(
                    logs["state"] == "Running"
                        && logs["stdout"]["nextOffset"].as_u64().unwrap_or_default() > 0,
                    "the marked detached execution was not durably running: {logs}"
                );
                return Ok(execution);
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "detached output never contained {marker:?}: {logs}"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Prove an attached shell has started before its lease is ended.
    async fn wait_for_file(&self, marker: &str, key: &str) -> anyhow::Result<()> {
        let script = format!("while [ ! -f /tmp/{marker} ]; do sleep 1; done");
        let (status, observed) = self.exec(&["/bin/sh", "-c", &script], key).await?;
        anyhow::ensure!(
            status.is_success() && observed["state"] == "Succeeded" && observed["exitCode"] == 0,
            "the attached stream never published its readiness marker: HTTP {status} {observed}"
        );
        Ok(())
    }

    /// Retry one idempotent request until the ended lease rejects it.
    ///
    /// A request that wins the release race can create at most one record: all
    /// retries use the same key and command. Once the shared access gate closes,
    /// the exact caller-visible status must replace that successful response.
    async fn wait_execution_denied(
        &self,
        key: &str,
        expected: &[reqwest::StatusCode],
        within: Duration,
    ) -> anyhow::Result<()> {
        let deadline = Instant::now() + within;
        loop {
            let (status, body) = self.exec(&["/bin/sh", "-c", "exit 0"], key).await?;
            if expected.contains(&status) {
                return Ok(());
            }
            anyhow::ensure!(
                status.is_success(),
                "ended lease rejected access with HTTP {status}, expected one of {expected:?}: {body}"
            );
            anyhow::ensure!(
                Instant::now() < deadline,
                "lease still accepted execution after its authority ended: {body}"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
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
        for required in [
            "id",
            "phase",
            "pool",
            "ttl",
            "provisioning_deadline",
            "ready_at",
            "expires_at",
        ] {
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
            ready["ready_at"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("no ready_at"))?,
        )?;
        let expires_at = chrono::DateTime::parse_from_rfc3339(
            ready["expires_at"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("no expires_at"))?,
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
            failed["state"] == "Failed" && failed["exitCode"] == 3,
            "a non-zero exit must preserve its exact code and be Failed, not an error: {failed}"
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
    detached_logs_resume_and_cancel_stops_the_process,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "10m").await?;
        sandbox.wait_ready(Duration::from_secs(300)).await?;

        // Output is addressed independently of the create response. Polling
        // from offset zero must recover bytes produced before this client
        // attached, which is the reconnect contract detached mode exists for.
        let execution = sandbox
            .start_detached("conformance-detached-cancel", "detached-started", "5m")
            .await?;
        let execution_path = format!("/v1/sandbox-leases/{}/executions/{execution}", sandbox.id);

        let (status, cancelled) = sandbox
            .api
            .json(reqwest::Method::DELETE, &execution_path, None)
            .await?;
        anyhow::ensure!(
            status.is_success(),
            "execution cancellation failed: HTTP {status} {cancelled}"
        );
        anyhow::ensure!(
            cancelled["id"] == execution && cancelled["state"] == "Cancelled",
            "cancellation did not terminate the exact execution: {cancelled}"
        );

        // Cancellation is durable, not merely the DELETE response. A fresh
        // GET must report the same terminal state and never rediscover a
        // running process after the request that signalled it has returned.
        let (status, observed) = sandbox
            .api
            .json(reqwest::Method::GET, &execution_path, None)
            .await?;
        anyhow::ensure!(status.is_success(), "cancelled record vanished: {observed}");
        anyhow::ensure!(
            observed["state"] == "Cancelled",
            "cancelled execution did not stay terminal: {observed}"
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

        // Streaming operations use a real WebSocket handshake. A plain HTTP
        // GET could be rejected by Axum before Kobe resolves the lease and
        // would therefore prove nothing about tenant isolation.
        //
        // Exit 125, not 1: attach never passes a remote exit through (there
        // is no remote command), and the CLI's contract reserves 125 for its
        // own failures precisely so they cannot collide with a command's
        // exit. The isolation property is carried by the REQUIRED 404 in the
        // output — the denial must be indistinguishable from absence.
        let attach = harness(&[
            "attach-pty",
            "--target",
            "e2e-other",
            "--lease",
            &sandbox.id,
            "--expect",
            "404",
            "--expect-exit",
            "125",
            "--timeout",
            "30",
            "--",
            "/bin/sh",
            "-c",
            "echo pwned",
        ])
        .await?;
        anyhow::ensure!(
            attach.contains("404"),
            "stranger attach did not fail as an undiscoverable lease: {attach}"
        );
        let forward = harness(&[
            "port-forward",
            "--target",
            "e2e-other",
            "--lease",
            &sandbox.id,
            "--port",
            "http",
            "--expect-http-status",
            "404",
            "--timeout",
            "30",
        ])
        .await?;
        anyhow::ensure!(
            forward.contains("HTTP 404"),
            "stranger port-forward did not fail as an undiscoverable lease: {forward}"
        );

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

    // Give teardown a live supervised process and durable record to retire.
    // Without one, CleanupVerified could pass while the execution path was
    // never exercised.
    let execution_marker = format!("release-execution-{}", nonce(placement));
    let _execution = sandbox
        .start_detached("conformance-release-execution", &execution_marker, "5m")
        .await?;

    // Keep a real upgraded stream open across the release. Its readiness file
    // proves the stream was established before DELETE; exit 125 plus the
    // bounded `revoked` reason proves cached authority did not survive it.
    let stream_marker = format!("release-stream-{}", nonce(placement));
    let attach_script = format!("echo {stream_marker}; touch /tmp/{stream_marker}; sleep 300");
    let lease = sandbox.id.clone();
    let argv = [
        "attach-pty",
        "--lease",
        &lease,
        "--expect",
        &stream_marker,
        "--expect-exit",
        "125",
        "--timeout",
        "180",
        "--",
        "/bin/sh",
        "-c",
        &attach_script,
    ];
    let revoke = async {
        sandbox
            .wait_for_file(&stream_marker, "conformance-release-stream-ready")
            .await?;
        sandbox.release().await?;
        sandbox
            .wait_execution_denied(
                "conformance-after-release",
                &[reqwest::StatusCode::CONFLICT],
                Duration::from_secs(60),
            )
            .await
    };
    let (attached, revoked) = tokio::join!(harness(&argv), revoke);
    revoked?;
    let transcript = attached?;
    anyhow::ensure!(
        transcript.contains("session ended: revoked"),
        "the released upgraded stream did not report revocation: {transcript}"
    );

    sandbox
        .wait_terminal_cleanup("Released", "Requested", Duration::from_secs(900))
        .await?;
    Ok(())
});

both_placements!(
    natural_expiry_rejects_further_access,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "90s").await?;
        let ready = sandbox.wait_ready(Duration::from_secs(300)).await?;
        let expires_at = chrono::DateTime::parse_from_rfc3339(
            ready["expires_at"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Ready lease returned no expires_at: {ready}"))?,
        )?
        .with_timezone(&chrono::Utc);

        let execution_marker = format!("expiry-execution-{}", nonce(placement));
        let _execution = sandbox
            .start_detached("conformance-expiry-execution", &execution_marker, "5m")
            .await?;

        let stream_marker = format!("expiry-stream-{}", nonce(placement));
        let attach_script = format!("echo {stream_marker}; touch /tmp/{stream_marker}; sleep 300");
        let lease = sandbox.id.clone();
        let argv = [
            "attach-pty",
            "--lease",
            &lease,
            "--expect",
            &stream_marker,
            "--expect-exit",
            "125",
            "--timeout",
            "180",
            "--",
            "/bin/sh",
            "-c",
            &attach_script,
        ];
        let expire = async {
            sandbox
                .wait_for_file(&stream_marker, "conformance-expiry-stream-ready")
                .await?;
            let remaining = (expires_at - chrono::Utc::now())
                .to_std()
                .unwrap_or_default();
            tokio::time::sleep(remaining + Duration::from_secs(1)).await;
            sandbox
                .wait_execution_denied(
                    "conformance-after-expiry",
                    &[
                        // Ready + elapsed timestamp is 410. If the lifecycle
                        // controller checkpointed Releasing first, it is 409.
                        // Both are ended authority; the terminal cause below
                        // distinguishes natural expiry from caller release.
                        reqwest::StatusCode::GONE,
                        reqwest::StatusCode::CONFLICT,
                    ],
                    Duration::from_secs(60),
                )
                .await
        };
        let (attached, expired) = tokio::join!(harness(&argv), expire);
        expired?;
        let transcript = attached?;
        anyhow::ensure!(
            transcript.contains("session ended: revoked"),
            "the expired upgraded stream did not report revocation: {transcript}"
        );

        sandbox
            .wait_terminal_cleanup("Expired", "RuntimeTtl", Duration::from_secs(900))
            .await?;
        sandbox.released = true;
        Ok(())
    }
);

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

    // Exercise the real CLI/WebSocket handshake. A plain GET can fail in
    // Axum's WebSocket extractor before Kobe ever checks the declared port.
    for undeclared in ["22", "9999", "ssh"] {
        let transcript = harness(&[
            "port-forward",
            "--lease",
            &sandbox.id,
            "--port",
            undeclared,
            "--expect-http-status",
            "400",
            "--timeout",
            "30",
        ])
        .await?;
        anyhow::ensure!(
            transcript.contains("HTTP 400"),
            "undeclared port {undeclared} did not fail at the upgraded authorization path: {transcript}"
        );
    }

    sandbox.release().await
});

both_placements!(
    a_declared_port_forwards_exact_bytes_over_loopback,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "10m").await?;
        sandbox.wait_ready(Duration::from_secs(300)).await?;

        let marker = format!("kobe-forwarded-{}", nonce(placement));
        let expected = format!("{marker}\n");
        let content_length = expected.len();
        let script = format!(
            "set -eu; echo {marker}; while :; do \
             printf 'HTTP/1.1 200 OK\\r\\nContent-Length: {content_length}\\r\\nConnection: close\\r\\n\\r\\n{marker}\\n' \
             | /usr/bin/nc -l -p 8080; done"
        );
        let _server = sandbox
            .start_detached_script("conformance-declared-port", &script, &marker, "5m")
            .await?;

        let transcript = harness(&[
            "port-forward",
            "--lease",
            &sandbox.id,
            "--port",
            "http",
            "--expect",
            &expected,
            "--timeout",
            "120",
        ])
        .await?;
        anyhow::ensure!(
            transcript.contains(&marker),
            "declared port did not return the workload's exact marker: {transcript}"
        );

        sandbox.release().await
    }
);

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
                Some("Released") => {
                    anyhow::ensure!(
                        body["release_cause"] == "Requested",
                        "an immediately released sandbox recorded the wrong cause: {body}"
                    );
                    return Ok(());
                }
                Some("Expired") => anyhow::bail!(
                    "an immediate caller-requested release was reported as expiry: {body}"
                ),
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

// ---------------------------------------------------------------------------
// Harness-driven scenarios (#82, #138)
//
// The rows of #76/#82 that need the target disturbed rather than merely
// queried. Each covers a property the design leans on and that nothing proves
// end to end: every execution crash window is idempotent, uncertain teardown
// withholds capacity rather than releasing it, and Ctrl-C reaches the workload.
//
// A restart takes longer than an untouched lease does, so these use wider
// budgets than the scenarios above. That is not slack — a restart scenario that
// timed out during the restart would report the operator as broken for having
// been asked to reboot.
// ---------------------------------------------------------------------------

both_placements!(
    /// A restart before readiness resumes the same composition rather than
    /// starting a second one.
    ///
    /// If this does not hold, a crash mid-provision leaves a Sandbox nobody
    /// owns while the lease builds another — and for child placement the
    /// orphan is an entire cluster, charged to a pool that has stopped
    /// counting it.
    a_restart_before_readiness_resumes_the_same_composition,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "20m").await?;

        // Aimed at the claim, not at a wall-clock delay. A restart timed by
        // sleeping lands somewhere different on every run, and a scenario that
        // sometimes restarts after readiness is not running the same test
        // twice — which is precisely the class of flake that gets an
        // idempotency suite switched off.
        harness(&[
            "restart-operator",
            "--wait-for-phase",
            "claim",
            "--lease",
            &sandbox.id,
            "--timeout",
            "600",
        ])
        .await?;

        let ready = sandbox.wait_ready(Duration::from_secs(600)).await?;
        let claim = provenance_uid(&ready, "sandboxClaim")?;
        let pod = provenance_uid(&ready, "pod")?;

        // A second restart, now past readiness. Same objects, and the same
        // readiness instant: a moved `ready_at` would mean the runtime TTL
        // restarted along with the operator, quietly handing the caller time
        // they did not buy — or taking time they did.
        harness(&[
            "restart-operator",
            "--wait-for-phase",
            "ready",
            "--lease",
            &sandbox.id,
            "--timeout",
            "600",
        ])
        .await?;

        let (_, after) = sandbox.status().await?;
        anyhow::ensure!(
            after["phase"] == "Ready",
            "a restart moved a Ready lease to {}: {after}",
            after["phase"]
        );
        anyhow::ensure!(
            provenance_uid(&after, "sandboxClaim")? == claim,
            "the resumed operator composed a second claim: {claim} then {after}"
        );
        anyhow::ensure!(
            provenance_uid(&after, "pod")? == pod,
            "the resumed operator landed on a different Pod: {pod} then {after}"
        );
        anyhow::ensure!(
            after["ready_at"] == ready["ready_at"],
            "ready_at moved across a restart ({} then {}); the runtime TTL restarted with the operator",
            ready["ready_at"],
            after["ready_at"]
        );

        sandbox.release().await
    }
);

both_placements!(
    /// A restart between a retry and its original still runs the command once.
    ///
    /// The reservation that makes two concurrent retries race for one object
    /// lives in the cluster, so it must survive the process that wrote it. If
    /// it does not, a client that retried across a Kobe restart runs its
    /// command twice — and the commands people least want run twice are exactly
    /// the ones they wrap in an idempotency key.
    a_restart_between_a_retry_and_its_original_still_runs_it_once,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "20m").await?;
        sandbox.wait_ready(Duration::from_secs(600)).await?;

        let marker = format!("/tmp/kobe-restart-{}", nonce(placement));
        let script = format!("echo x >> {marker}");
        let argv = ["/bin/sh", "-c", script.as_str()];
        let key = "conformance-restart-idempotent";

        let (_, first) = sandbox.exec(&argv, key).await?;
        harness(&[
            "restart-operator",
            "--wait-for-phase",
            "ready",
            "--lease",
            &sandbox.id,
            "--timeout",
            "600",
        ])
        .await?;
        let (_, second) = sandbox.exec(&argv, key).await?;

        anyhow::ensure!(
            first["id"] == second["id"],
            "a retry across a restart produced a second execution: {first} vs {second}"
        );

        // The side effect settles it. Two executions sharing an id would still
        // be one spawn; two spawns sharing an id would not show up in the ids
        // at all, and this is where they would.
        let count_script = format!("wc -l < {marker}");
        let (_, count) = sandbox
            .exec(
                &["/bin/sh", "-c", count_script.as_str()],
                "conformance-restart-count",
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
            "the command ran {lines} times across a restart, expected exactly 1"
        );

        sandbox.release().await
    }
);

both_placements!(
    /// Kobe may die after its durable Running checkpoint but before the target
    /// runner sees `start`. The workload can also remove the runner spool, so
    /// `NotFound` cannot restore spawn authority. The exact retry must settle
    /// one stable Unknown, run nothing, and still permit target destruction.
    crash_after_running_before_target_reservation_is_unknown_and_never_started,
    |placement| async move {
        const WINDOW: &str = "execution-after-running-before-target-reservation";
        const KEY: &str = "conformance-crash-before-target-reservation";
        let mut sandbox = LeasedSandbox::create(placement, "20m").await?;
        sandbox.wait_ready(Duration::from_secs(600)).await?;

        let marker = format!("/tmp/kobe-before-target-reservation-{}", nonce(placement));
        let script = format!("echo x >> {marker}; echo must-not-run");
        let argv = ["/bin/sh", "-c", script.as_str()];

        inject_execution_crash(WINDOW, &sandbox.id, KEY).await?;
        let attempted = sandbox.exec(&argv, KEY).await;
        let cleared = clear_execution_crash(WINDOW).await;
        interrupted_request(&attempted, WINDOW)?;
        cleared?;

        let (status, first) = sandbox.exec(&argv, KEY).await?;
        anyhow::ensure!(status.is_success(), "pre-target retry failed: {first}");
        anyhow::ensure!(
            first["state"] == "Unknown"
                && first["reason"] == "runner_forgot_execution"
                && first["exitCode"].is_null()
                && first["stdout"] == ""
                && first["stderr"] == "",
            "pre-target retry did not fail closed to the exact Unknown: {first}"
        );
        let (second_status, second) = sandbox.exec(&argv, KEY).await?;
        anyhow::ensure!(
            second_status == status,
            "pre-target retry changed HTTP status from {status} to {second_status}: {second}"
        );
        stable_execution(&first, &second, WINDOW)?;
        anyhow::ensure!(
            sandbox
                .marker_count(&marker, "conformance-before-target-reservation-count")
                .await?
                == 0,
            "the command ran after NotFound restored no spawn authority"
        );

        sandbox.release().await
    }
);

both_placements!(
    /// A runner crash after its target-side reservation but before supervisor
    /// spawn returns one stable Unknown and never manufactures the command.
    crash_before_spawn_is_unknown_and_never_retried,
    |placement| async move {
        const WINDOW: &str = "execution-before-spawn";
        const KEY: &str = "conformance-crash-before-spawn";
        let mut sandbox = LeasedSandbox::create(placement, "20m").await?;
        sandbox.wait_ready(Duration::from_secs(600)).await?;

        let marker = format!("/tmp/kobe-before-spawn-{}", nonce(placement));
        let script = format!("echo x >> {marker}");
        let argv = ["/bin/sh", "-c", script.as_str()];

        inject_execution_crash(WINDOW, &sandbox.id, KEY).await?;
        let attempted = sandbox.exec(&argv, KEY).await;
        let cleared = clear_execution_crash(WINDOW).await;
        cleared?;
        let (status, interrupted) = attempted?;
        anyhow::ensure!(
            status == reqwest::StatusCode::BAD_GATEWAY,
            "pre-spawn runner crash returned HTTP {status}, expected 502: {interrupted}"
        );

        let (status, first) = sandbox.exec(&argv, KEY).await?;
        anyhow::ensure!(status.is_success(), "pre-spawn retry failed: {first}");
        anyhow::ensure!(
            first["state"] == "Unknown"
                && first["reason"] == "runner_unreachable"
                && first["exitCode"].is_null()
                && first["stdout"] == ""
                && first["stderr"] == "",
            "pre-spawn crash did not settle as the exact Unknown: {first}"
        );
        let (second_status, second) = sandbox.exec(&argv, KEY).await?;
        anyhow::ensure!(
            second_status == status,
            "pre-spawn retry changed HTTP status from {status} to {second_status}: {second}"
        );
        stable_execution(&first, &second, WINDOW)?;
        anyhow::ensure!(
            sandbox
                .marker_count(&marker, "conformance-before-spawn-count")
                .await?
                == 0,
            "the command ran despite a crash before spawn"
        );

        sandbox.release().await
    }
);

both_placements!(
    /// The runner may spawn and then disappear before acknowledging Kobe. The
    /// caller gets one stable Unknown, while the target-side reservation keeps
    /// an exact retry from spawning the side effect twice.
    crash_after_spawn_before_ack_is_unknown_and_runs_once,
    |placement| async move {
        const WINDOW: &str = "execution-after-spawn-before-ack";
        const KEY: &str = "conformance-crash-before-ack";
        let mut sandbox = LeasedSandbox::create(placement, "20m").await?;
        sandbox.wait_ready(Duration::from_secs(600)).await?;

        let marker = format!("/tmp/kobe-before-ack-{}", nonce(placement));
        let script = format!("echo x >> {marker}");
        let argv = ["/bin/sh", "-c", script.as_str()];

        inject_execution_crash(WINDOW, &sandbox.id, KEY).await?;
        let attempted = sandbox.exec(&argv, KEY).await;
        let cleared = clear_execution_crash(WINDOW).await;
        cleared?;
        let (status, interrupted) = attempted?;
        anyhow::ensure!(
            status == reqwest::StatusCode::BAD_GATEWAY,
            "lost runner acknowledgement returned HTTP {status}, expected 502: {interrupted}"
        );

        let (status, first) = sandbox.exec(&argv, KEY).await?;
        anyhow::ensure!(status.is_success(), "lost-ack retry failed: {first}");
        anyhow::ensure!(
            first["state"] == "Unknown"
                && first["reason"] == "runner_unreachable"
                && first["exitCode"].is_null()
                && first["stdout"] == ""
                && first["stderr"] == "",
            "lost acknowledgement did not stay the exact Unknown: {first}"
        );
        let (second_status, second) = sandbox.exec(&argv, KEY).await?;
        anyhow::ensure!(
            second_status == status,
            "lost-ack retry changed HTTP status from {status} to {second_status}: {second}"
        );
        stable_execution(&first, &second, WINDOW)?;
        anyhow::ensure!(
            sandbox
                .marker_count(&marker, "conformance-before-ack-count")
                .await?
                == 1,
            "the lost-ack command did not run exactly once"
        );

        sandbox.release().await
    }
);

both_placements!(
    /// Once Kobe has parsed the runner acknowledgement, a process crash before
    /// terminal status persistence is recovered by polling that same runner
    /// reservation. Exact output, exit status and side effects stay stable.
    crash_after_ack_before_status_recovers_the_original_outcome,
    |placement| async move {
        const WINDOW: &str = "execution-after-ack-before-status";
        const KEY: &str = "conformance-crash-after-ack";
        let mut sandbox = LeasedSandbox::create(placement, "20m").await?;
        sandbox.wait_ready(Duration::from_secs(600)).await?;

        let marker = format!("/tmp/kobe-after-ack-{}", nonce(placement));
        let script = format!("echo x >> {marker}; echo ack-out; echo ack-err >&2; exit 7");
        let argv = ["/bin/sh", "-c", script.as_str()];

        inject_execution_crash(WINDOW, &sandbox.id, KEY).await?;
        let attempted = sandbox.exec(&argv, KEY).await;
        let cleared = clear_execution_crash(WINDOW).await;
        interrupted_request(&attempted, WINDOW)?;
        cleared?;

        let (status, first) = sandbox.exec(&argv, KEY).await?;
        anyhow::ensure!(status.is_success(), "post-ack retry failed: {first}");
        anyhow::ensure!(
            first["state"] == "Failed"
                && first["exitCode"] == 7
                && first["stdout"].as_str().unwrap_or_default().contains("ack-out")
                && first["stderr"].as_str().unwrap_or_default().contains("ack-err"),
            "post-ack retry did not recover the exact runner outcome: {first}"
        );
        let (second_status, second) = sandbox.exec(&argv, KEY).await?;
        anyhow::ensure!(
            second_status == status,
            "post-ack retry changed HTTP status from {status} to {second_status}: {second}"
        );
        stable_execution(&first, &second, WINDOW)?;
        anyhow::ensure!(
            sandbox
                .marker_count(&marker, "conformance-after-ack-count")
                .await?
                == 1,
            "the post-ack command did not run exactly once"
        );

        sandbox.release().await
    }
);

both_placements!(
    /// A restart during teardown still settles the lease exactly once.
    ///
    /// Teardown is where a restart is most expensive to get wrong: a resumed
    /// operator that forgets it was mid-release either strands the capacity or
    /// declares it clean without proof. Neither is visible until somebody
    /// counts a pool that no longer adds up.
    a_restart_during_teardown_still_settles_the_lease_once,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "20m").await?;
        sandbox.wait_ready(Duration::from_secs(600)).await?;

        // Started BEFORE the release, not after. `Releasing` is a state the
        // management path can pass through in well under a second, and a
        // harness asked to wait for it afterwards would be waiting for
        // something already gone.
        let id = sandbox.id.clone();
        let argv = [
            "restart-operator",
            "--wait-for-phase",
            "teardown",
            "--lease",
            id.as_str(),
            "--timeout",
            "600",
        ];
        let (restarted, released) = tokio::join!(harness(&argv), sandbox.release());
        released?;
        restarted?;

        let deadline = Instant::now() + Duration::from_secs(600);
        loop {
            let (status, body) = sandbox.status().await?;
            if status.as_u16() == 404 {
                return Ok(());
            }
            match body["phase"].as_str() {
                Some("Released") => {
                    anyhow::ensure!(
                        body["release_cause"] == "Requested",
                        "a release resumed after restart recorded the wrong cause: {body}"
                    );
                    return Ok(());
                }
                Some("Expired") => anyhow::bail!(
                    "a caller-requested release became expiry after restart: {body}"
                ),
                // A lease that was already mid-teardown when the operator
                // restarted has proof available; withholding capacity here
                // would mean the restart itself destroyed the evidence.
                Some("Quarantined") => anyhow::bail!(
                    "a restart during teardown quarantined a lease that had proof: {body}"
                ),
                _ => {}
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "a lease restarted mid-teardown never settled: {body}"
            );
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }
);

both_placements!(
    /// An unverifiable teardown withholds capacity instead of releasing it.
    ///
    /// The safe direction is the counter-intuitive one. An under-counted pool
    /// is visible and an administrator can reconcile it; a Sandbox that was
    /// quietly double-booked is visible to nobody, and the second tenant finds
    /// out by sharing a workload with the first.
    ///
    /// Asserted by construction today: the code path is unit-tested with a
    /// faked 403. What is not tested is that a real revocation produces one.
    an_unverifiable_teardown_withholds_capacity_instead_of_releasing_it,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "20m").await?;
        sandbox.wait_ready(Duration::from_secs(600)).await?;

        // Revokes `get` — not `delete`. A revoked delete stalls in `Releasing`
        // and retries forever, which is a clean failure; only a read the
        // operator is not permitted to make is DURABLE uncertainty, and
        // durable uncertainty is what quarantine exists for.
        harness(&["inject-failure", "--kind", "teardown-unverifiable"]).await?;

        let observed = quarantine_after_release(&mut sandbox).await;

        // Both cleanups run whatever the assertion did. An injection left
        // behind breaks every scenario after this one, and a quarantined lease
        // holds a pool slot on purpose and has no exit through the API — the
        // next scenario would queue behind capacity it cannot see and fail for
        // a reason it does not assert.
        let cleared = harness(&["clear-failure", "--kind", "teardown-unverifiable"]).await;
        let reaped = harness(&[
            "reap-lease",
            "--lease",
            &sandbox.id,
            "--timeout",
            "600",
        ])
        .await;

        observed?;
        cleared?;
        reaped?;
        anyhow::Ok(())
    }
);

both_placements!(
    /// A keystroke typed on a real terminal reaches the workload.
    ///
    /// Framing, key encoding and URL derivation are unit-tested on both sides.
    /// The round trip is not, and it is the only part a user experiences: an
    /// attach that connects, renders output and swallows every keystroke
    /// passes every existing test.
    a_keystroke_typed_on_a_real_terminal_reaches_the_workload,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "20m").await?;
        sandbox.wait_ready(Duration::from_secs(600)).await?;

        let token = nonce(placement);
        // What is typed and what is expected are deliberately different
        // strings. A pty echoes input, so an expectation matching the
        // keystrokes would be satisfied by the terminal alone, without the
        // workload ever seeing them. Only the shell's own concatenation
        // produces the joined form.
        let typed = format!("echo ko\"\"be-typed-{token}\\r");
        let expected = format!("kobe-typed-{token}");

        // A shell is started rather than attaching to whatever the pool
        // declared: the pool's process is an administrator's choice and nothing
        // promises it reads stdin, so attaching to it would make this scenario
        // a test of that pool's configuration.
        harness(&[
            "attach-pty",
            "--lease",
            &sandbox.id,
            "--send",
            &typed,
            "--expect",
            &expected,
            "--timeout",
            "120",
            "--",
            "/bin/sh",
        ])
        .await?;

        sandbox.release().await
    }
);

both_placements!(
    /// Resizing the caller's real terminal reaches the remote PTY.
    ///
    /// The initial 80x24 and final 120x40 sizes are intentionally different;
    /// observing `40 120` from `stty` proves a live channel-4 resize rather
    /// than the initial size Kobe sends when attach opens.
    a_real_terminal_resize_reaches_the_remote_pty,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "20m").await?;
        sandbox.wait_ready(Duration::from_secs(600)).await?;

        let ready = format!("kobe-resize-ready-{}", nonce(placement));
        let resized = format!("kobe-resized-{}", nonce(placement));
        let script = format!(
            "trap 'echo {resized}; stty size' WINCH; echo {ready}; while :; do read _ || :; done"
        );
        let transcript = harness(&[
            "attach-pty",
            "--lease",
            &sandbox.id,
            "--resize",
            "120x40",
            "--resize-after",
            &ready,
            "--expect",
            "40 120",
            "--timeout",
            "120",
            "--",
            "/bin/sh",
            "-c",
            &script,
        ])
        .await?;
        anyhow::ensure!(
            transcript.contains(&resized) && transcript.contains("40 120"),
            "remote PTY did not observe the exact resize: {transcript}"
        );

        sandbox.release().await
    }
);

both_placements!(
    /// Ctrl-C reaches the workload rather than the client.
    ///
    /// Raw mode exists for this one keystroke. If it regressed, `kobe` would
    /// die and the caller's process would keep running inside a sandbox they
    /// can no longer see — the failure that costs the most and announces
    /// itself the least.
    ctrl_c_reaches_the_workload_rather_than_the_client,
    |placement| async move {
        let mut sandbox = LeasedSandbox::create(placement, "20m").await?;
        sandbox.wait_ready(Duration::from_secs(600)).await?;

        let token = nonce(placement);
        let marker = format!("echo ko\"\"be-interrupted-{token}\\r");
        let expected = format!("kobe-interrupted-{token}");

        // Three keystrokes, and only one outcome produces the marker. If
        // Ctrl-C killed the client, the session is gone and nothing more is
        // typed. If it never arrived, the shell is still sleeping and the
        // marker waits behind it. It appears only when the interrupt was
        // delivered to the process on the other end.
        harness(&[
            "attach-pty",
            "--lease",
            &sandbox.id,
            "--send",
            "sleep 300\\r",
            "--send",
            "\\x03",
            "--send",
            &marker,
            "--expect",
            &expected,
            // Wider than the default gap between keystrokes, because the
            // interrupt has to arrive while `sleep` is the foreground process.
            // Sent too early it lands on the prompt, the shell shrugs, and the
            // sleep then runs for its full five minutes — a pass turned into a
            // timeout by a race the assertion never mentions.
            "--send-delay",
            "1000",
            "--timeout",
            "120",
            "--",
            "/bin/sh",
        ])
        .await?;

        sandbox.release().await
    }
);

/// Release a lease whose teardown cannot be proven, and hold it to quarantine.
///
/// Split out because the assertion has to run between the injection and its
/// cleanup, and inlining it would put the `?` that skips the cleanup in the
/// middle of the scenario.
async fn quarantine_after_release(sandbox: &mut LeasedSandbox) -> anyhow::Result<()> {
    sandbox.release().await?;

    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let (status, body) = sandbox.status().await?;
        anyhow::ensure!(
            status.as_u16() != 404,
            "a lease whose teardown could not be proven was retired anyway"
        );
        match body["phase"].as_str() {
            Some("Quarantined") => {
                anyhow::ensure!(
                    body["release_cause"] == "Requested",
                    "a quarantined caller-requested release lost or changed its cause: {body}"
                );
                break;
            }
            // The failure this scenario exists to catch: capacity handed back
            // on the strength of a teardown nothing confirmed.
            Some(clean @ ("Released" | "Expired")) => anyhow::bail!(
                "an unverifiable teardown reported {clean}, releasing capacity it could not prove free: {body}"
            ),
            _ => {}
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "an unverifiable teardown never settled either way: {body}"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    // Withheld, not merely marked. A quarantined lease that had dropped out of
    // the caller's own listing would be holding a slot nobody can account for,
    // which is the under-counting this phase exists to make visible.
    let api = Api::as_caller(token());
    let (_, listed) = api
        .json(reqwest::Method::GET, "/v1/sandbox-leases", None)
        .await?;
    anyhow::ensure!(
        listed.to_string().contains(&sandbox.id),
        "a quarantined lease vanished from its holder's listing: {listed}"
    );
    Ok(())
}

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
        // Anchored to the start of a line. `"// Scenarios"` alone is also a
        // substring of any doc comment beginning `/// Scenarios`, and writing
        // one silently moved this marker forward — the guard then examined an
        // empty span and reported an under-populated suite. A guard that can be
        // relocated by prose is not a guard.
        let body = source
            .split("\n// Scenarios\n")
            .nth(1)
            .expect("the scenario section is marked");
        let scenarios = body.split("mod suite_shape").next().unwrap_or(body);

        assert!(
            !scenarios.contains("#[tokio::test]"),
            "a scenario was declared directly instead of through both_placements!, \
             which would run it against one placement only"
        );
        assert!(
            scenarios.matches("both_placements!").count() >= 17,
            "the #76 matrix expects at least eleven dual-placement scenarios, plus the six \
             #138 unlocked; a floor rather than an exact count, because the failure being \
             guarded is deletion, not addition"
        );
    }

    /// The PR gate (`just test-sandbox-conformance-pr`) selects scenarios by
    /// exact name, and libtest exits 0 when a filter matches nothing — so a
    /// scenario renamed or deleted here would be silently skipped while the
    /// gate stayed green. The recipe itself now demands "1 passed" per run;
    /// this test closes the loop from the other side by parsing that same
    /// justfile list and asserting every name it selects is a scenario this
    /// file actually declares. Renames must touch both, or CI fails fast in
    /// the cheap unit pass instead of never.
    #[test]
    fn every_pr_gate_scenario_exists_in_the_suite() {
        let justfile = include_str!("../justfile");
        let list = justfile
            .split("for scenario in \\")
            .nth(1)
            .and_then(|rest| rest.split("; do").next())
            .expect("the PR gate's scenario list is marked in the justfile");
        let names: Vec<&str> = list
            .lines()
            .map(|line| line.trim().trim_end_matches('\\').trim())
            .filter(|line| !line.is_empty())
            .collect();
        assert!(
            names.len() >= 12,
            "the PR gate should keep at least its current twelve scenarios; found {}: {:?}",
            names.len(),
            names
        );

        let source = include_str!("sandbox_conformance.rs");
        let declared = declared_scenarios(source);
        for name in names {
            assert!(
                declared.iter().any(|scenario| scenario == name),
                "the PR gate lists scenario '{name}', but no such test exists in this file; \
                 update both the justfile list and the suite together"
            );
        }
    }

    /// Scenario names as the compiler sees them: the identifiers handed to
    /// `both_placements!`, since the test functions they expand into never
    /// appear literally in this file. A hand-rolled scan rather than a regex
    /// dependency, for one pattern.
    fn declared_scenarios(source: &str) -> Vec<String> {
        source
            .match_indices("both_placements!(")
            .filter_map(|(start, _)| {
                // The macro forwards doc comments, so they sit between the
                // paren and the name; skip whitespace and `///` lines.
                let mut rest = source[start + "both_placements!(".len()..].trim_start();
                while rest.starts_with("///") {
                    rest = match rest.split_once('\n') {
                        Some((_, tail)) => tail.trim_start(),
                        None => "",
                    };
                }
                let ident: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                (!ident.is_empty()).then_some(ident)
            })
            .collect()
    }
}
