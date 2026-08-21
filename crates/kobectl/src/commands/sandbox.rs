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

use std::future::Future;
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CleanupOutcome {
    /// True only after a GET observes the controller's `Releasing` checkpoint,
    /// a clean terminal phase, or that the lease is already absent.
    pub released: bool,
    /// The phase that proved the release request became observable. `Absent`
    /// means a 404 proved there was no lease left to clean up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
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

/// How long to wait for release intent to become observable before giving up.
const RELEASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const RELEASE_POLL: std::time::Duration = std::time::Duration::from_millis(500);
const LOGS_FOLLOW_POLL: std::time::Duration = std::time::Duration::from_millis(500);

#[derive(Debug, PartialEq, Eq)]
enum ReleasePhaseObservation<'a> {
    Pending,
    Observed(&'a str),
    Failed(&'static str),
}

fn observe_release_phase(phase: &str) -> ReleasePhaseObservation<'_> {
    match phase {
        "Releasing" | "Released" | "Expired" => ReleasePhaseObservation::Observed(phase),
        "Quarantined" => ReleasePhaseObservation::Failed("sandbox cleanup entered Quarantined"),
        _ => ReleasePhaseObservation::Pending,
    }
}

/// A catchable process signal that interrupted `sandbox run`.
///
/// It is an orchestration outcome, not a remote command result: Kobe never
/// fabricates an execution id or exit code for a response it did not observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunInterruption {
    SigInt,
    SigTerm,
}

impl RunInterruption {
    fn name(self) -> &'static str {
        match self {
            Self::SigInt => "SIGINT",
            Self::SigTerm => "SIGTERM",
        }
    }

    fn exit_code(self) -> i32 {
        match self {
            Self::SigInt => 130,
            Self::SigTerm => 143,
        }
    }
}

/// The execution side of one `run` lifecycle.
#[derive(Debug)]
enum RunOutcome {
    Execution(Result<ExecutionResponse>),
    Interrupted(RunInterruption),
}

/// A complete `run` lifecycle. Cleanup is always present because this value is
/// only constructed after the release observation attempt has finished.
#[derive(Debug)]
struct RunLifecycle {
    outcome: RunOutcome,
    cleanup: CleanupOutcome,
}

/// Finish an in-flight create after shutdown so its durable lease id is not
/// lost between POST and release.
///
/// Cancelling the request future when SIGINT/SIGTERM wins would be unsafe: the
/// server may already have committed the lease even though the response body
/// has not reached the client. Once a shutdown signal is observed, this waits
/// for that same request to return its handle; the caller then skips execution
/// and releases the exact lease.
async fn create_before_shutdown<Create, Shutdown>(
    create: Create,
    mut shutdown: std::pin::Pin<&mut Shutdown>,
) -> Result<(String, Option<RunInterruption>)>
where
    Create: Future<Output = Result<String>>,
    Shutdown: Future<Output = RunInterruption>,
{
    tokio::pin!(create);
    tokio::select! {
        biased;
        result = &mut create => result.map(|lease| (lease, None)),
        signal = &mut shutdown => {
            let lease = (&mut create).await?;
            Ok((lease, Some(signal)))
        }
    }
}

/// Race one execution against client shutdown, then always await release.
///
/// Dropping the losing execution future on interruption closes its HTTP
/// request, but does not return from this function: the release future is
/// awaited to its own bound first. Keeping the orchestration generic makes the
/// signal, timeout, disconnect, cancellation and cleanup-failure invariants
/// deterministic unit tests rather than timing-sensitive process tests.
async fn orchestrate_run<Execution, Shutdown, Release, ReleaseFuture>(
    execution: Execution,
    shutdown: Shutdown,
    release: Release,
) -> RunLifecycle
where
    Execution: Future<Output = Result<ExecutionResponse>>,
    Shutdown: Future<Output = RunInterruption>,
    Release: FnOnce() -> ReleaseFuture,
    ReleaseFuture: Future<Output = CleanupOutcome>,
{
    tokio::pin!(execution);
    tokio::pin!(shutdown);
    let outcome = tokio::select! {
        // If both became ready in the same scheduler turn, an observed remote
        // result is stronger evidence than a concurrent local signal.
        biased;
        result = &mut execution => RunOutcome::Execution(result),
        signal = &mut shutdown => RunOutcome::Interrupted(signal),
    };
    let cleanup = release().await;
    RunLifecycle { outcome, cleanup }
}

#[cfg(unix)]
async fn shutdown_signal() -> RunInterruption {
    use tokio::signal::unix::{SignalKind, signal};

    match signal(SignalKind::terminate()) {
        Ok(mut sigterm) => tokio::select! {
            _ = tokio::signal::ctrl_c() => RunInterruption::SigInt,
            _ = sigterm.recv() => RunInterruption::SigTerm,
        },
        // If SIGTERM registration is unavailable, SIGINT is still catchable.
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
            RunInterruption::SigInt
        }
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> RunInterruption {
    let _ = tokio::signal::ctrl_c().await;
    RunInterruption::SigInt
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InterruptedRunOutput<'a> {
    api_version: &'static str,
    lease: &'a str,
    state: &'static str,
    signal: &'static str,
    cleanup: &'a CleanupOutcome,
}

fn emit_interruption(
    lease: &str,
    signal: RunInterruption,
    cleanup: &CleanupOutcome,
    output: OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json => print_json(&InterruptedRunOutput {
            api_version: SANDBOX_CLI_API_VERSION,
            lease,
            state: "Interrupted",
            signal: signal.name(),
            cleanup,
        }),
        OutputFormat::Text => {
            eprintln!(
                "kobe: {} received; sandbox release {}",
                signal.name(),
                if cleanup.released {
                    "was observed"
                } else {
                    "could not be confirmed"
                }
            );
            if let Some(error) = cleanup.error.as_deref() {
                eprintln!("kobe: WARNING the sandbox lease was not released: {error}");
            }
            Ok(())
        }
    }
}

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

    // Install signal handling before sending the create. If shutdown races the
    // response, keep the same POST future alive until its durable handle is
    // known; only then can cleanup address the exact lease.
    let mut shutdown = Box::pin(shutdown_signal());
    let (lease, interrupted_during_create) =
        create_before_shutdown(create_sandbox_lease(&config, pool, ttl), shutdown.as_mut()).await?;

    // Everything from here on must release. The result of the command and the
    // result of the release are tracked separately so neither can hide the
    // other.
    let lifecycle = if let Some(signal) = interrupted_during_create {
        RunLifecycle {
            outcome: RunOutcome::Interrupted(signal),
            cleanup: release_sandbox_lease(&config, &lease).await,
        }
    } else {
        orchestrate_run(
            run_in_lease(&config, &lease, argv, cwd, timeout),
            shutdown,
            || release_sandbox_lease(&config, &lease),
        )
        .await
    };
    let RunLifecycle { outcome, cleanup } = lifecycle;

    match outcome {
        RunOutcome::Execution(Ok(result)) => {
            let code = exit_code_for(&result);
            emit(&config, &lease, &result, Some(cleanup.clone()), output)?;
            // Cleanup is a separate result. Rewriting a real remote zero to
            // 125 would violate the exact-exit-code contract; JSON callers can
            // inspect `cleanup`, while text callers receive the warning above.
            Ok(code)
        }
        RunOutcome::Execution(Err(error)) => {
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
        RunOutcome::Interrupted(signal) => {
            emit_interruption(&lease, signal, &cleanup, output)?;
            Ok(signal.exit_code())
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
/// alongside their command's result, not a replacement for it. A successful
/// DELETE only requests release, so this waits until GET observes `Releasing`,
/// a clean terminal phase, or absence. A 404 counts as released — the lease is
/// gone, which is the goal.
async fn release_sandbox_lease(config: &ResolvedConfig, lease: &str) -> CleanupOutcome {
    let observe = async {
        let path = format!("/v1/sandbox-leases/{lease}");
        let token = get_auth_header(config, "DELETE", &path, b"").await?;
        let response = with_auth(
            authed_client().delete(format!("{}{path}", config.endpoint)),
            &token,
        )
        .send()
        .await;
        if let Ok(response) = response {
            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok("Absent".to_string());
            }
            if !status.is_success() {
                anyhow::bail!("HTTP {status}")
            }
        }
        // A DELETE transport loss is ambiguous: it may have committed. Polling
        // the exact lease is both safe and stronger than reporting a leak from
        // a response body that merely failed to arrive.

        loop {
            let token = get_auth_header(config, "GET", &path, b"").await?;
            let response = with_auth(
                authed_client().get(format!("{}{path}", config.endpoint)),
                &token,
            )
            .send()
            .await;
            let Ok(response) = response else {
                tokio::time::sleep(RELEASE_POLL).await;
                continue;
            };
            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok("Absent".to_string());
            }
            if !status.is_success() {
                anyhow::bail!("release observation failed with HTTP {status}");
            }
            let current: SandboxLeaseResponse = response
                .json()
                .await
                .context("could not parse the sandbox release status")?;
            match observe_release_phase(&current.phase) {
                ReleasePhaseObservation::Observed(_) => return Ok(current.phase),
                ReleasePhaseObservation::Failed(message) => anyhow::bail!(message),
                ReleasePhaseObservation::Pending => tokio::time::sleep(RELEASE_POLL).await,
            }
        }
    };

    match tokio::time::timeout(RELEASE_TIMEOUT, observe).await {
        Ok(Ok(phase)) => CleanupOutcome {
            released: true,
            phase: Some(phase),
            error: None,
        },
        Ok(Err(error)) => CleanupOutcome {
            released: false,
            phase: None,
            error: Some(error.to_string()),
        },
        Err(_) => CleanupOutcome {
            released: false,
            phase: None,
            error: Some(format!(
                "release did not become observable within {RELEASE_TIMEOUT:?}"
            )),
        },
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ExecutionLogWindow {
    data: String,
    next_offset: u64,
    more: bool,
    truncated: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ExecutionLogsResponse {
    id: String,
    state: String,
    stdout: ExecutionLogWindow,
    stderr: ExecutionLogWindow,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionLogsOutput<'a> {
    api_version: &'static str,
    lease: &'a str,
    execution: &'a str,
    state: &'a str,
    stdout: &'a ExecutionLogWindow,
    stderr: &'a ExecutionLogWindow,
}

fn execution_is_terminal(state: &str) -> bool {
    matches!(
        state,
        "Succeeded" | "Failed" | "Cancelled" | "TimedOut" | "Unknown"
    )
}

/// Read logs for a Sandbox or for one durable execution.
///
/// `--execution` selects the reconnectable offset route. With `--follow`, each
/// response advances the stdout and stderr offsets independently, so a retry
/// never duplicates one stream merely because the other advanced more slowly.
/// Text writes bytes to their original streams. JSON follow mode emits one
/// compact JSON object per window (NDJSON); non-follow JSON remains one normal
/// pretty-printed object.
pub async fn logs(
    lease: &str,
    tail: Option<i64>,
    execution: Option<&str>,
    follow: bool,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;

    if let Some(execution) = execution {
        return execution_logs(&config, lease, execution, follow, output).await;
    }
    if follow {
        anyhow::bail!("--follow requires --execution <id>");
    }

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

async fn execution_logs(
    config: &ResolvedConfig,
    lease: &str,
    execution: &str,
    follow: bool,
    output: OutputFormat,
) -> Result<()> {
    let mut stdout_offset = 0;
    let mut stderr_offset = 0;

    loop {
        let previous_offsets = (stdout_offset, stderr_offset);
        let current =
            read_execution_logs(config, lease, execution, stdout_offset, stderr_offset).await?;
        emit_execution_logs(lease, &current, follow, output)?;

        stdout_offset = current.stdout.next_offset;
        stderr_offset = current.stderr.next_offset;
        let more = current.stdout.more || current.stderr.more;
        if !follow || (execution_is_terminal(&current.state) && !more) {
            return Ok(());
        }
        if !more || previous_offsets == (stdout_offset, stderr_offset) {
            tokio::time::sleep(LOGS_FOLLOW_POLL).await;
        }
    }
}

fn execution_logs_path(
    lease: &str,
    execution: &str,
    stdout_offset: u64,
    stderr_offset: u64,
) -> String {
    format!(
        "/v1/sandbox-leases/{lease}/executions/{execution}/logs?stdoutOffset={stdout_offset}&stderrOffset={stderr_offset}"
    )
}

async fn read_execution_logs(
    config: &ResolvedConfig,
    lease: &str,
    execution: &str,
    stdout_offset: u64,
    stderr_offset: u64,
) -> Result<ExecutionLogsResponse> {
    let path = execution_logs_path(lease, execution, stdout_offset, stderr_offset);
    let token = get_auth_header(config, "GET", &path, b"").await?;
    let response = with_auth(
        authed_client().get(format!("{}{path}", config.endpoint)),
        &token,
    )
    .send()
    .await
    .context("could not reach the Kobe endpoint")?;
    let status = response.status();
    let payload = response.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!(
            "could not read execution logs (HTTP {status}): {}",
            payload.trim()
        );
    }
    serde_json::from_str(&payload).context("could not parse the execution logs response")
}

fn emit_execution_logs(
    lease: &str,
    current: &ExecutionLogsResponse,
    follow: bool,
    output: OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Json => {
            let output = ExecutionLogsOutput {
                api_version: SANDBOX_CLI_API_VERSION,
                lease,
                execution: &current.id,
                state: &current.state,
                stdout: &current.stdout,
                stderr: &current.stderr,
            };
            if follow {
                println!("{}", serde_json::to_string(&output)?);
                Ok(())
            } else {
                print_json(&output)
            }
        }
        OutputFormat::Text => {
            print!("{}", current.stdout.data);
            std::io::stdout().flush().ok();
            eprint!("{}", current.stderr.data);
            std::io::stderr().flush().ok();
            if current.stdout.truncated || current.stderr.truncated {
                eprintln!("kobe: execution output was truncated at the server's retention cap");
            }
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

    fn observed_cleanup() -> CleanupOutcome {
        CleanupOutcome {
            released: true,
            phase: Some("Releasing".into()),
            error: None,
        }
    }

    fn failed_cleanup() -> CleanupOutcome {
        CleanupOutcome {
            released: false,
            phase: None,
            error: Some("HTTP 503".into()),
        }
    }

    /// A 204 DELETE is only intent. Cleanup becomes successful after a later
    /// read observes the controller checkpoint or a clean terminal phase;
    /// Quarantined is terminal uncertainty, never success.
    #[test]
    fn cleanup_requires_an_observable_release_phase() {
        for pending in ["Pending", "Provisioning", "Ready"] {
            assert_eq!(
                observe_release_phase(pending),
                ReleasePhaseObservation::Pending
            );
        }
        for observed in ["Releasing", "Released", "Expired"] {
            assert_eq!(
                observe_release_phase(observed),
                ReleasePhaseObservation::Observed(observed)
            );
        }
        assert_eq!(
            observe_release_phase("Quarantined"),
            ReleasePhaseObservation::Failed("sandbox cleanup entered Quarantined")
        );
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

    /// SIGINT cancels the in-flight HTTP future but not the cleanup future.
    ///
    /// Returning as soon as the signal arrives would make `sandbox run` leak a
    /// lease whenever a CI job or human interrupted it. The lifecycle remains
    /// pending until release has reached its own observable bound.
    #[tokio::test]
    async fn signal_waits_for_observable_release_before_returning() {
        let (release_started_tx, release_started_rx) = tokio::sync::oneshot::channel();
        let (release_finish_tx, release_finish_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(orchestrate_run(
            std::future::pending::<Result<ExecutionResponse>>(),
            std::future::ready(RunInterruption::SigInt),
            move || async move {
                let _ = release_started_tx.send(());
                let _ = release_finish_rx.await;
                observed_cleanup()
            },
        ));

        release_started_rx.await.unwrap();
        assert!(
            !task.is_finished(),
            "signal handling must not return before cleanup settles"
        );
        release_finish_tx.send(()).unwrap();

        let lifecycle = task.await.unwrap();
        assert!(matches!(
            lifecycle.outcome,
            RunOutcome::Interrupted(RunInterruption::SigInt)
        ));
        assert_eq!(RunInterruption::SigInt.exit_code(), 130);
        assert_eq!(lifecycle.cleanup, observed_cleanup());
    }

    /// A signal racing lease creation must not discard a possibly committed
    /// POST response. The same request is allowed to return its durable handle,
    /// after which the caller can release that exact lease without executing.
    #[tokio::test]
    async fn signal_during_create_waits_for_the_handle_needed_by_cleanup() {
        let (create_started_tx, create_started_rx) = tokio::sync::oneshot::channel();
        let (create_finish_tx, create_finish_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut shutdown = Box::pin(std::future::ready(RunInterruption::SigTerm));
            create_before_shutdown(
                async move {
                    let _ = create_started_tx.send(());
                    let _ = create_finish_rx.await;
                    Ok("sandbox-created".to_string())
                },
                shutdown.as_mut(),
            )
            .await
        });

        create_started_rx.await.unwrap();
        assert!(
            !task.is_finished(),
            "shutdown must wait for the in-flight create handle"
        );
        create_finish_tx.send(()).unwrap();

        let (lease, signal) = task.await.unwrap().unwrap();
        assert_eq!(lease, "sandbox-created");
        assert_eq!(signal, Some(RunInterruption::SigTerm));
        assert_eq!(RunInterruption::SigTerm.exit_code(), 143);
    }

    /// A runner-enforced timeout is a terminal execution outcome, not a reason
    /// to skip release. No exit code is invented for it.
    #[tokio::test]
    async fn timeout_still_releases_and_keeps_the_remote_outcome() {
        let lifecycle = orchestrate_run(
            std::future::ready(Ok(response("TimedOut", None))),
            std::future::pending::<RunInterruption>(),
            || std::future::ready(observed_cleanup()),
        )
        .await;

        let RunOutcome::Execution(Ok(result)) = lifecycle.outcome else {
            panic!("timeout must remain an execution outcome")
        };
        assert_eq!(result.state, "TimedOut");
        assert_eq!(exit_code_for(&result), CLI_FAILURE_EXIT);
        assert_eq!(lifecycle.cleanup, observed_cleanup());
    }

    /// Losing the execution response is ambiguous, but cleanup is not optional.
    /// The original transport error survives after the release attempt.
    #[tokio::test]
    async fn disconnect_still_releases_and_preserves_the_transport_error() {
        let lifecycle = orchestrate_run(
            std::future::ready(Err(anyhow::anyhow!("response disconnected"))),
            std::future::pending::<RunInterruption>(),
            || std::future::ready(observed_cleanup()),
        )
        .await;

        let RunOutcome::Execution(Err(error)) = lifecycle.outcome else {
            panic!("disconnect must remain an execution transport error")
        };
        assert_eq!(error.to_string(), "response disconnected");
        assert_eq!(lifecycle.cleanup, observed_cleanup());
    }

    /// Server-confirmed cancellation is terminal and still followed by lease
    /// release. It has no remote exit code, so Kobe's distinct 125 applies.
    #[tokio::test]
    async fn cancelled_execution_still_releases_without_fabricating_an_exit_code() {
        let lifecycle = orchestrate_run(
            std::future::ready(Ok(response("Cancelled", None))),
            std::future::pending::<RunInterruption>(),
            || std::future::ready(observed_cleanup()),
        )
        .await;

        let RunOutcome::Execution(Ok(result)) = lifecycle.outcome else {
            panic!("cancellation must remain a remote execution outcome")
        };
        assert_eq!(exit_code_for(&result), CLI_FAILURE_EXIT);
        assert_eq!(lifecycle.cleanup, observed_cleanup());
    }

    /// Cleanup failure is reported beside the command and never rewrites its
    /// exact exit code — including a successful zero.
    #[tokio::test]
    async fn release_failure_never_rewrites_the_remote_exit_code() {
        let lifecycle = orchestrate_run(
            std::future::ready(Ok(response("Succeeded", Some(0)))),
            std::future::pending::<RunInterruption>(),
            || std::future::ready(failed_cleanup()),
        )
        .await;

        let RunOutcome::Execution(Ok(result)) = lifecycle.outcome else {
            panic!("the command result must survive cleanup failure")
        };
        assert_eq!(exit_code_for(&result), 0);
        assert_eq!(lifecycle.cleanup, failed_cleanup());
    }

    /// The CLI uses the reconnectable execution-log route and advances each
    /// stream independently using the API's canonical camel-case query names.
    #[test]
    fn execution_log_route_carries_both_resume_offsets() {
        assert_eq!(
            execution_logs_path("sandbox-1", "sbxe-1", 7, 11),
            "/v1/sandbox-leases/sandbox-1/executions/sbxe-1/logs?stdoutOffset=7&stderrOffset=11"
        );
    }

    #[test]
    fn execution_log_terminal_states_match_the_api_contract() {
        for terminal in ["Succeeded", "Failed", "Cancelled", "TimedOut", "Unknown"] {
            assert!(execution_is_terminal(terminal), "{terminal}");
        }
        for active in ["Queued", "Running"] {
            assert!(!execution_is_terminal(active), "{active}");
        }
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
                phase: None,
                error: Some("HTTP 503".into()),
            }),
        };
        let json: serde_json::Value = serde_json::to_value(&output).unwrap();

        assert_eq!(json["exitCode"], 0);
        assert_eq!(json["cleanup"]["released"], false);
        assert_eq!(json["cleanup"]["error"], "HTTP 503");
    }
}
