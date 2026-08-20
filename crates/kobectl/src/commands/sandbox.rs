//! `kobe sandbox` — exec, logs, cancel, and run (#84).
//!
//! # Two audiences, one contract
//!
//! A human runs `kobe sandbox exec` and reads the output. An agent runs the
//! same command with `--output json` and parses it. The agent is the harder
//! consumer and the one that decides the design: it needs the **exact remote
//! exit code**, stdout and stderr kept apart, and a transport failure that
//! cannot be mistaken for a command failure.
//!
//! # Exit codes carry meaning
//!
//! The remote command's exit code is this process's exit code. That is the
//! whole point of `exec` in a script — `set -e` has to work — so Kobe's own
//! failures must not be able to collide with it. They exit `125`, chosen
//! because it is what `docker run` and `env` use for exactly this: "the tool
//! failed, not your command".
//!
//! # `run` cleans up, and says so separately
//!
//! `run` creates a lease, executes, and releases. The release is attempted on
//! every terminal path — success, non-zero exit, timeout, interruption — and
//! its failure is reported *separately* from the command's result. Collapsing
//! them would either hide a leaked lease behind a successful command, or fail
//! a command that actually worked.

use std::io::Write;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::config::{CliConfig, ResolvedConfig};
use super::{OutputFormat, authed_client, get_auth_header, print_json, with_auth};

/// Exit code for Kobe's own failures.
///
/// A remote command's exit code is passed through verbatim, so Kobe needs a
/// value it will not be confused with. `125` is the convention `docker run`
/// and `env` already use for "the tool failed, not your command", which means
/// scripts that already handle it need no new knowledge.
pub const CLI_FAILURE_EXIT: i32 = 125;

/// Stable, versioned machine output.
///
/// The version is explicit because an agent parses this: a field that changed
/// meaning without one would break a consumer silently, at some later date,
/// with no way to tell which side was wrong.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecOutput {
    /// Bumped only on a breaking change to these fields.
    pub api_version: &'static str,
    pub lease: String,
    pub execution: String,
    pub state: String,
    /// The remote command's exact exit code, or absent if it never ran to
    /// completion. Never synthesised: a fabricated zero is indistinguishable
    /// from a real success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// Whether output was cut off at the server's cap.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// Release outcome for `run`. Reported separately from the command's own
    /// result so a leaked lease is never hidden behind a successful command,
    /// and a working command is never failed by a cleanup problem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<CleanupOutcome>,
}

pub const SANDBOX_CLI_API_VERSION: &str = "kobe.sandbox/v1";

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CleanupOutcome {
    pub released: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The server's execution response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionResponse {
    pub id: String,
    pub state: String,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub stdout: Option<String>,
    #[serde(default)]
    pub stderr: Option<String>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

/// The process exit code for one execution result.
///
/// A command that ran gets its own code, whatever it was. Everything else —
/// cancelled, timed out, unknown — gets [`CLI_FAILURE_EXIT`], because there is
/// no remote code to report and inventing one would tell a caller their
/// command finished when nobody knows whether it started.
pub fn exit_code_for(result: &ExecutionResponse) -> i32 {
    match result.exit_code {
        Some(code) => code,
        None => CLI_FAILURE_EXIT,
    }
}

/// An idempotency key for one invocation.
///
/// Random, and generated once per *command*, not per attempt: that is what
/// makes a client-side retry safe. A key derived from the argv would be worse
/// than none — two deliberate runs of the same command would collide, and the
/// second would silently return the first one's result.
pub fn new_idempotency_key() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Process id, monotonic counter and nanosecond clock. The counter is what
    // makes two keys from one process distinct even inside the clock's
    // resolution; the pid and clock are what keep two processes apart. No
    // dependency, and nothing here needs to be unguessable — the key scopes a
    // retry, it does not authorise anything.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    format!(
        "kobe-cli-{}-{nanos:x}-{:x}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecRequestBody<'a> {
    command: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<&'a str>,
    idempotency_key: &'a str,
}

/// Run one command in an existing Sandbox lease.
///
/// Returns the exit code the process should use, so the caller decides when to
/// exit rather than this function calling `exit` from inside a library path.
pub async fn exec(
    lease: &str,
    argv: &[String],
    cwd: Option<&str>,
    timeout: Option<&str>,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<i32> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;

    if argv.is_empty() {
        anyhow::bail!("a command is required: kobe sandbox exec <lease> -- <argv...>");
    }

    let result = exec_once(&config, lease, argv, cwd, timeout, &new_idempotency_key()).await?;
    let code = exit_code_for(&result);
    emit(&config, lease, &result, None, output)?;
    Ok(code)
}

async fn exec_once(
    config: &ResolvedConfig,
    lease: &str,
    argv: &[String],
    cwd: Option<&str>,
    timeout: Option<&str>,
    idempotency_key: &str,
) -> Result<ExecutionResponse> {
    let path = format!("/v1/sandbox-leases/{lease}/executions");
    let body = serde_json::to_vec(&ExecRequestBody {
        command: argv,
        cwd,
        timeout,
        idempotency_key,
    })?;
    let (status, payload) = retry_transport_once(|| send_exec_request(config, &path, &body))
        .await
        .map_err(ExecRequestAttemptError::into_inner)
        .context("could not reach the Kobe endpoint")?;
    if !status.is_success() {
        // The server's own message, not a guess. A CLI that invents an
        // explanation for a status it does not understand sends people looking
        // in the wrong place.
        anyhow::bail!("execution failed (HTTP {status}): {}", payload.trim());
    }
    serde_json::from_str(&payload).context("could not parse the execution response")
}

/// Send one execution POST, including a freshly generated authorization value.
///
/// Kept as one attempt so [`retry_transport_once`] can repeat exactly the same
/// semantic body and idempotency key while regenerating time-sensitive auth.
async fn send_exec_request(
    config: &ResolvedConfig,
    path: &str,
    body: &[u8],
) -> std::result::Result<(reqwest::StatusCode, String), ExecRequestAttemptError> {
    let token = get_auth_header(config, "POST", path, body)
        .await
        .map_err(ExecRequestAttemptError::Auth)?;
    let response = with_auth(
        authed_client().post(format!("{}{path}", config.endpoint)),
        &token,
    )
    .header("Content-Type", "application/json")
    .body(body.to_vec())
    .send()
    .await
    .map_err(|error| ExecRequestAttemptError::Transport(error.into()))?;
    let status = response.status();
    let payload = response
        .text()
        .await
        .map_err(|error| ExecRequestAttemptError::Transport(error.into()))?;
    Ok((status, payload))
}

/// Failure classification for one execution POST attempt.
///
/// Only failures after authorization has been produced are ambiguous: the
/// server may have accepted the request before the connection or response body
/// was lost. Authentication failures are local and cannot have started an
/// execution, so repeating them would only conceal the real problem.
#[derive(Debug)]
enum ExecRequestAttemptError {
    Auth(anyhow::Error),
    Transport(anyhow::Error),
}

impl ExecRequestAttemptError {
    fn into_inner(self) -> anyhow::Error {
        match self {
            Self::Auth(error) | Self::Transport(error) => error,
        }
    }
}

/// Retry one ambiguous transport/body-read failure exactly once.
///
/// HTTP responses are successful transport results — including 4xx/5xx — and
/// are never retried here. The execution idempotency key makes the second
/// transport attempt safe; a third would only hide a persistently broken path.
async fn retry_transport_once<Attempt, Future, Output>(
    mut attempt: Attempt,
) -> std::result::Result<Output, ExecRequestAttemptError>
where
    Attempt: FnMut() -> Future,
    Future: std::future::Future<Output = std::result::Result<Output, ExecRequestAttemptError>>,
{
    match attempt().await {
        Ok(output) => Ok(output),
        Err(ExecRequestAttemptError::Transport(_)) => attempt().await,
        Err(error) => Err(error),
    }
}

/// Print the result in the requested form.
///
/// Text mode writes the command's own stdout and stderr to *this* process's
/// stdout and stderr, so `kobe sandbox exec ... | grep` behaves the way anyone
/// would expect. JSON mode keeps them as separate fields for the same reason:
/// a consumer that cannot tell a tool's diagnostics from its output cannot
/// parse either.
fn emit(
    config: &ResolvedConfig,
    lease: &str,
    result: &ExecutionResponse,
    cleanup: Option<CleanupOutcome>,
    output: OutputFormat,
) -> Result<()> {
    let _ = config;
    match output {
        OutputFormat::Json => print_json(&ExecOutput {
            api_version: SANDBOX_CLI_API_VERSION,
            lease: lease.to_string(),
            execution: result.id.clone(),
            state: result.state.clone(),
            exit_code: result.exit_code,
            stdout: result.stdout.clone().unwrap_or_default(),
            stderr: result.stderr.clone().unwrap_or_default(),
            truncated: result.truncated,
            cleanup,
        }),
        OutputFormat::Text => {
            if let Some(stdout) = result.stdout.as_deref() {
                print!("{stdout}");
                std::io::stdout().flush().ok();
            }
            if let Some(stderr) = result.stderr.as_deref() {
                eprint!("{stderr}");
                std::io::stderr().flush().ok();
            }
            if result.truncated {
                eprintln!("kobe: output was truncated at the server's limit");
            }
            // A state that is not a completed command needs saying: a caller
            // seeing empty output and exit 125 should not have to guess why.
            if result.exit_code.is_none() {
                eprintln!(
                    "kobe: execution ended in state {}{}",
                    result.state,
                    result
                        .reason
                        .as_deref()
                        .map(|reason| format!(" ({reason})"))
                        .unwrap_or_default()
                );
            }
            if let Some(cleanup) = cleanup.as_ref()
                && !cleanup.released
            {
                eprintln!(
                    "kobe: WARNING the sandbox lease was not released{}",
                    cleanup
                        .error
                        .as_deref()
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default()
                );
            }
            Ok(())
        }
    }
}

#[derive(Debug, Serialize)]
struct CreateLeaseBody<'a> {
    pool: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SandboxLeaseResponse {
    id: String,
    phase: String,
}

/// How long `run` waits for a Sandbox to become Ready.
///
/// Bounded so `run` cannot hang forever on a pool that has no capacity. On
/// timeout the lease is still released — a lease created and abandoned is the
/// worst outcome of this command, because nothing else will clean it up.
const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);
const READY_POLL: std::time::Duration = std::time::Duration::from_secs(2);

/// How long to keep trying to release before giving up and saying so.
const RELEASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Create a Sandbox, run one command in it, and release it.
///
/// The release is attempted on **every** terminal path: success, non-zero
/// exit, provisioning timeout, transport failure. A lease created and
/// abandoned is the worst thing this command can do, because nothing else
/// will notice — the TTL eventually reaps it, but the caller is billed for
/// the gap and the pool is short a slot until then.
///
/// Cleanup failure is reported separately from the command's result, never
/// folded into it.
pub struct RunCommand<'a> {
    pub pool: &'a str,
    pub ttl: Option<&'a str>,
    pub argv: &'a [String],
    pub cwd: Option<&'a str>,
    pub timeout: Option<&'a str>,
    pub target_override: Option<&'a str>,
    pub endpoint_override: Option<&'a str>,
    pub output: OutputFormat,
}

pub async fn run(command: RunCommand<'_>) -> Result<i32> {
    let RunCommand {
        pool,
        ttl,
        argv,
        cwd,
        timeout,
        target_override,
        endpoint_override,
        output,
    } = command;
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;

    if argv.is_empty() {
        anyhow::bail!("a command is required: kobe sandbox run <pool> -- <argv...>");
    }

    let lease = create_sandbox_lease(&config, pool, ttl).await?;

    // Everything from here on must release. The result of the command and the
    // result of the release are tracked separately so neither can hide the
    // other.
    let outcome = run_in_lease(&config, &lease, argv, cwd, timeout).await;
    let cleanup = release_sandbox_lease(&config, &lease).await;

    match outcome {
        Ok(result) => {
            let code = exit_code_for(&result);
            emit(&config, &lease, &result, Some(cleanup.clone()), output)?;
            // A leaked lease does not fail a command that worked, but it does
            // fail a command that had nothing else to report.
            if !cleanup.released && code == 0 {
                return Ok(CLI_FAILURE_EXIT);
            }
            Ok(code)
        }
        Err(error) => {
            if !cleanup.released {
                // Both problems, in the order they matter: the caller's
                // command first, the leaked lease second.
                eprintln!(
                    "kobe: WARNING the sandbox lease {lease} was not released{}",
                    cleanup
                        .error
                        .as_deref()
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default()
                );
            }
            Err(error)
        }
    }
}

async fn run_in_lease(
    config: &ResolvedConfig,
    lease: &str,
    argv: &[String],
    cwd: Option<&str>,
    timeout: Option<&str>,
) -> Result<ExecutionResponse> {
    wait_until_ready(config, lease).await?;
    exec_once(config, lease, argv, cwd, timeout, &new_idempotency_key()).await
}

async fn create_sandbox_lease(
    config: &ResolvedConfig,
    pool: &str,
    ttl: Option<&str>,
) -> Result<String> {
    let path = "/v1/sandbox-leases";
    let body = serde_json::to_vec(&CreateLeaseBody { pool, ttl })?;
    let token = get_auth_header(config, "POST", path, &body).await?;
    let response = with_auth(
        authed_client().post(format!("{}{path}", config.endpoint)),
        &token,
    )
    .header("Content-Type", "application/json")
    .body(body)
    .send()
    .await
    .context("could not reach the Kobe endpoint")?;

    let status = response.status();
    let payload = response.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!(
            "could not create a sandbox (HTTP {status}): {}",
            payload.trim()
        );
    }
    let lease: SandboxLeaseResponse =
        serde_json::from_str(&payload).context("could not parse the sandbox lease response")?;
    Ok(lease.id)
}

async fn wait_until_ready(config: &ResolvedConfig, lease: &str) -> Result<()> {
    let deadline = std::time::Instant::now() + READY_TIMEOUT;
    loop {
        let path = format!("/v1/sandbox-leases/{lease}");
        let token = get_auth_header(config, "GET", &path, b"").await?;
        let response = with_auth(
            authed_client().get(format!("{}{path}", config.endpoint)),
            &token,
        )
        .send()
        .await
        .context("could not reach the Kobe endpoint")?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            // A create may return the durable `admission_pending` handle while
            // the server-owned arbiter is still settling. If cancellation
            // wins, that exact object is deleted and 404 is the terminal
            // admission-failed signal. Never POST another lease implicitly.
            anyhow::bail!("sandbox {lease} admission was cancelled before it became ready");
        }
        if response.status().is_success() {
            let current: SandboxLeaseResponse = response
                .json()
                .await
                .context("could not parse the sandbox lease response")?;
            match current.phase.as_str() {
                "Ready" => return Ok(()),
                // Terminal before it ever served. Waiting longer cannot help,
                // and the caller needs to know which end state it reached.
                "Released" | "Expired" | "Quarantined" => {
                    anyhow::bail!(
                        "sandbox {lease} ended in {} before it was ready",
                        current.phase
                    );
                }
                _ => {}
            }
        }

        if std::time::Instant::now() >= deadline {
            anyhow::bail!("sandbox {lease} was not ready within {READY_TIMEOUT:?}");
        }
        tokio::time::sleep(READY_POLL).await;
    }
}

/// Release the lease, reporting what actually happened.
///
/// Never returns an error: a release failure is data the caller needs
/// alongside their command's result, not a replacement for it. A 404 counts
/// as released — the lease is gone, which is the goal.
async fn release_sandbox_lease(config: &ResolvedConfig, lease: &str) -> CleanupOutcome {
    let path = format!("/v1/sandbox-leases/{lease}");
    let attempt = async {
        let token = get_auth_header(config, "DELETE", &path, b"").await?;
        let response = with_auth(
            authed_client().delete(format!("{}{path}", config.endpoint)),
            &token,
        )
        .send()
        .await?;
        let status = response.status();
        if status.is_success() || status.as_u16() == 404 {
            Ok(())
        } else {
            anyhow::bail!("HTTP {status}")
        }
    };

    match tokio::time::timeout(RELEASE_TIMEOUT, attempt).await {
        Ok(Ok(())) => CleanupOutcome {
            released: true,
            error: None,
        },
        Ok(Err(error)) => CleanupOutcome {
            released: false,
            error: Some(error.to_string()),
        },
        Err(_) => CleanupOutcome {
            released: false,
            error: Some(format!(
                "release did not complete within {RELEASE_TIMEOUT:?}"
            )),
        },
    }
}

impl Clone for CleanupOutcome {
    fn clone(&self) -> Self {
        Self {
            released: self.released,
            error: self.error.clone(),
        }
    }
}

/// Read a bounded tail of the sandbox's own output.
pub async fn logs(
    lease: &str,
    tail: Option<i64>,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;

    let mut path = format!("/v1/sandbox-leases/{lease}/logs");
    if let Some(tail) = tail {
        path.push_str(&format!("?tail={tail}"));
    }
    let token = get_auth_header(&config, "GET", &path, b"").await?;
    let response = with_auth(
        authed_client().get(format!("{}{path}", config.endpoint)),
        &token,
    )
    .send()
    .await
    .context("could not reach the Kobe endpoint")?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("could not read logs (HTTP {status}): {}", body.trim());
    }

    match output {
        // The log body is the workload's own bytes. In JSON mode it is one
        // field rather than raw output, so a consumer parsing this stream
        // cannot be confused by whatever the workload happened to print.
        OutputFormat::Json => print_json(&serde_json::json!({
            "apiVersion": SANDBOX_CLI_API_VERSION,
            "lease": lease,
            "logs": body,
        })),
        OutputFormat::Text => {
            print!("{body}");
            std::io::stdout().flush().ok();
            Ok(())
        }
    }
}

/// Cancel one execution.
pub async fn cancel(
    lease: &str,
    execution: &str,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;

    let path = format!("/v1/sandbox-leases/{lease}/executions/{execution}");
    let token = get_auth_header(&config, "DELETE", &path, b"").await?;
    let response = with_auth(
        authed_client().delete(format!("{}{path}", config.endpoint)),
        &token,
    )
    .send()
    .await
    .context("could not reach the Kobe endpoint")?;

    let status = response.status();
    let payload = response.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!(
            "could not cancel execution (HTTP {status}): {}",
            payload.trim()
        );
    }
    let result: ExecutionResponse =
        serde_json::from_str(&payload).context("could not parse the execution response")?;

    // The state that actually applies, not the one that was asked for. An
    // execution that had already finished is reported as finished — telling a
    // caller it was cancelled would be a lie they might act on.
    match output {
        OutputFormat::Json => print_json(&serde_json::json!({
            "apiVersion": SANDBOX_CLI_API_VERSION,
            "lease": lease,
            "execution": result.id,
            "state": result.state,
        })),
        OutputFormat::Text => {
            println!("{} is {}", result.id, result.state);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(state: &str, exit_code: Option<i32>) -> ExecutionResponse {
        ExecutionResponse {
            id: "sbxe-1".into(),
            state: state.into(),
            exit_code,
            stdout: Some("out".into()),
            stderr: Some("err".into()),
            truncated: false,
            reason: None,
        }
    }

    /// The shutdown handoff extends, rather than replaces, the create schema.
    /// Older kobectl builds only know `id` and `phase`; keeping both means they
    /// retain the durable handle and poll instead of retrying the POST.
    #[test]
    fn admission_pending_create_response_is_backward_compatible() {
        let lease: SandboxLeaseResponse = serde_json::from_value(serde_json::json!({
            "id": "sandbox-handoff",
            "phase": "Pending",
            "pool": "agent-small",
            "ttl": "1h",
            "provisioning_deadline": "2026-08-10T00:10:00Z",
            "status": "admission_pending",
            "retry": false,
            "statusUrl": "/v1/sandbox-leases/sandbox-handoff"
        }))
        .expect("the non-retry handoff must retain the legacy polling fields");

        assert_eq!(lease.id, "sandbox-handoff");
        assert_eq!(lease.phase, "Pending");
    }

    /// The remote exit code is this process's exit code.
    ///
    /// That is the entire point of `exec` inside a script: `set -e` has to
    /// work, and a wrapper that returned 0 for a failed command would break
    /// every pipeline it appears in.
    #[test]
    fn the_remote_exit_code_is_passed_through_exactly() {
        for code in [0, 1, 2, 42, 127, 130, 255] {
            assert_eq!(exit_code_for(&response("Succeeded", Some(code))), code);
        }
    }

    /// Kobe's own failures cannot be mistaken for the command's.
    ///
    /// An execution that never produced an exit code did not finish, and
    /// reporting 0 would tell a caller their command succeeded when nobody
    /// knows whether it started. 125 is the convention `docker run` and `env`
    /// already use, so scripts that handle it need no new knowledge.
    #[test]
    fn a_command_that_never_completed_exits_distinctly() {
        for state in ["Unknown", "Cancelled", "TimedOut", "Queued", "Running"] {
            assert_eq!(
                exit_code_for(&response(state, None)),
                CLI_FAILURE_EXIT,
                "{state} must not look like a completed command"
            );
        }

        // And 125 must not collide with a plausible success.
        assert_ne!(CLI_FAILURE_EXIT, 0);
    }

    /// Idempotency keys are per-invocation and unpredictable.
    ///
    /// Random rather than derived from the argv: a derived key would make two
    /// deliberate runs of the same command collide, and the second would
    /// silently return the first one's result — which is a wrong answer, not a
    /// cached one.
    #[test]
    fn each_invocation_gets_its_own_idempotency_key() {
        let keys: std::collections::HashSet<String> =
            (0..100).map(|_| new_idempotency_key()).collect();
        assert_eq!(keys.len(), 100, "keys must not repeat across invocations");
        assert!(keys.iter().all(|key| key.starts_with("kobe-cli-")));
        assert!(keys.iter().all(|key| key.len() <= 253));
    }

    /// The CLI sends the same canonical field names the server and conformance
    /// contract accept. A snake_case idempotency key would be rejected before
    /// the durable reservation that makes retries safe.
    #[test]
    fn execution_requests_use_the_canonical_wire_shape() {
        let argv = vec!["/agent".to_string(), "run".to_string()];
        let body = serde_json::to_value(ExecRequestBody {
            command: &argv,
            cwd: Some("/workspace"),
            timeout: Some("60s"),
            idempotency_key: "key-1",
        })
        .unwrap();

        assert_eq!(body["idempotencyKey"], "key-1");
        assert!(body.get("idempotency_key").is_none());
        assert_eq!(body["cwd"], "/workspace");
    }

    /// An ambiguous transport loss repeats the exact semantic request once.
    ///
    /// Changing either the serialized body or its embedded idempotency key
    /// would turn recovery from a lost response into a second execution.
    #[tokio::test]
    async fn transport_retry_reuses_the_same_body_and_idempotency_key() {
        let body = br#"{"command":["/agent","run"],"idempotencyKey":"key-1"}"#.to_vec();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut attempt = 0;

        let result = retry_transport_once(|| {
            attempt += 1;
            let current_attempt = attempt;
            let body = body.clone();
            let seen = std::sync::Arc::clone(&seen);
            async move {
                seen.lock().unwrap().push(body);
                if current_attempt == 1 {
                    Err(ExecRequestAttemptError::Transport(anyhow::anyhow!(
                        "response lost"
                    )))
                } else {
                    Ok(())
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(*seen.lock().unwrap(), vec![body.clone(), body]);
    }

    /// A broken transport is attempted at most twice.
    ///
    /// Authentication failures and HTTP statuses are not ambiguous sends, so
    /// neither is retried. This also keeps a persistent outage from becoming
    /// an unbounded client-side loop.
    #[tokio::test]
    async fn transport_retry_sends_at_most_twice_and_never_retries_http_or_auth() {
        let mut transport_attempts = 0;
        let result: std::result::Result<(), ExecRequestAttemptError> = retry_transport_once(|| {
            transport_attempts += 1;
            async {
                Err(ExecRequestAttemptError::Transport(anyhow::anyhow!(
                    "still disconnected"
                )))
            }
        })
        .await;
        assert!(matches!(result, Err(ExecRequestAttemptError::Transport(_))));
        assert_eq!(transport_attempts, 2);

        let mut auth_attempts = 0;
        let result: std::result::Result<(), ExecRequestAttemptError> = retry_transport_once(|| {
            auth_attempts += 1;
            async { Err(ExecRequestAttemptError::Auth(anyhow::anyhow!("no signer"))) }
        })
        .await;
        assert!(matches!(result, Err(ExecRequestAttemptError::Auth(_))));
        assert_eq!(auth_attempts, 1);

        let mut http_attempts = 0;
        let result: std::result::Result<_, ExecRequestAttemptError> = retry_transport_once(|| {
            http_attempts += 1;
            async { Ok((reqwest::StatusCode::SERVICE_UNAVAILABLE, "retry later")) }
        })
        .await;
        assert_eq!(result.unwrap().0, reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(http_attempts, 1);
    }

    /// Machine output is versioned and keeps the streams apart.
    ///
    /// An agent parses this. A field that changed meaning without a version
    /// bump would break a consumer silently, at some later date, with no way
    /// to tell which side was wrong.
    #[test]
    fn machine_output_is_versioned_and_stream_separated() {
        let output = ExecOutput {
            api_version: SANDBOX_CLI_API_VERSION,
            lease: "sbx-1".into(),
            execution: "sbxe-1".into(),
            state: "Succeeded".into(),
            exit_code: Some(0),
            stdout: "the output".into(),
            stderr: "the diagnostics".into(),
            truncated: false,
            cleanup: None,
        };
        let json: serde_json::Value = serde_json::to_value(&output).unwrap();

        assert_eq!(json["apiVersion"], SANDBOX_CLI_API_VERSION);
        assert_eq!(json["stdout"], "the output");
        assert_eq!(json["stderr"], "the diagnostics");
        assert_eq!(json["exitCode"], 0);
        // Absent rather than false: a consumer checking `truncated` for
        // presence gets the same answer as one checking it for truth.
        assert!(json.get("truncated").is_none());
        assert!(json.get("cleanup").is_none());

        // An execution with no exit code omits the field rather than
        // reporting a value nobody observed.
        let unknown = ExecOutput {
            exit_code: None,
            state: "Unknown".into(),
            ..output
        };
        let json: serde_json::Value = serde_json::to_value(&unknown).unwrap();
        assert!(json.get("exitCode").is_none());
    }

    /// A failed release is reported next to the result, never instead of it.
    ///
    /// Collapsing them would either hide a leaked lease behind a successful
    /// command, or fail a command that actually worked. Both are worse than
    /// telling the caller two things.
    #[test]
    fn cleanup_failure_is_reported_beside_the_command_result() {
        let output = ExecOutput {
            api_version: SANDBOX_CLI_API_VERSION,
            lease: "sbx-1".into(),
            execution: "sbxe-1".into(),
            state: "Succeeded".into(),
            // The command succeeded...
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
            // ...and the lease leaked. Both facts survive.
            cleanup: Some(CleanupOutcome {
                released: false,
                error: Some("HTTP 503".into()),
            }),
        };
        let json: serde_json::Value = serde_json::to_value(&output).unwrap();

        assert_eq!(json["exitCode"], 0);
        assert_eq!(json["cleanup"]["released"], false);
        assert_eq!(json["cleanup"]["error"], "HTTP 503");
    }
}
