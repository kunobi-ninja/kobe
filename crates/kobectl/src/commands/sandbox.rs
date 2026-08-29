//! Capability adapters for `kobe exec`, `logs`, `cancel`, and `run` (#84).
//!
//! # Two audiences, one contract
//!
//! A human runs `kobe exec` and reads the output. An agent runs the
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
//! them would either hide an unconfirmed release behind a successful command,
//! or fail a command that actually worked.

use std::io::Write;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::config::{CliConfig, ResolvedConfig};
use super::{
    OutputFormat, authed_client, get_auth_header, get_auth_header_noninteractive, print_json,
    with_auth,
};

async fn sandbox_auth_header(
    config: &ResolvedConfig,
    method: &str,
    path: &str,
    body: &[u8],
    output: OutputFormat,
) -> Result<Option<String>> {
    match output {
        OutputFormat::Text => get_auth_header(config, method, path, body).await,
        OutputFormat::Json => get_auth_header_noninteractive(config, method, path, body).await,
    }
}

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
    /// result so an unconfirmed release is never hidden behind a successful
    /// command, and a working command is never failed by a cleanup problem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<CleanupOutcome>,
}

pub const SANDBOX_CLI_API_VERSION: &str = "kobe.sandbox/v1";

/// Emit a machine-readable executable-resource failure when command dispatch
/// itself fails. Human diagnostics never share stderr with `--output json`.
pub fn emit_cli_error(error: &anyhow::Error) -> Result<()> {
    emit_client_error(&format!("{error:#}"), CLI_FAILURE_EXIT)
}

/// Emit a stable machine envelope for a command-line syntax error.
///
/// Clap normally exits before `main` and writes human diagnostics to stderr.
/// The entry point diverts executable-resource `--output json` parse failures
/// here so machine mode keeps the same versioned shape before dispatch.
pub fn emit_cli_parse_error(error: &str, process_exit_code: i32) -> Result<()> {
    emit_client_error(error, process_exit_code)
}

fn emit_client_error(error: &str, process_exit_code: i32) -> Result<()> {
    let mut envelope = RunEnvelope::empty();
    envelope.process_exit_code = process_exit_code;
    envelope.error = Some(error.to_string());
    print_json(&envelope)
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CleanupOutcome {
    /// True only after a GET observes the controller's `Releasing` checkpoint,
    /// a clean terminal phase, or that the lease is already absent.
    pub released: bool,
    /// The phase that proved the release request became observable. `Absent`
    /// means a 404 proved there was no lease left to clean up.
    pub phase: Option<String>,
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
    format!("kobe-cli-{}", uuid::Uuid::new_v4().simple())
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
        anyhow::bail!("a command is required: kobe exec <lease> -- <argv...>");
    }

    let result = exec_once(
        &config,
        lease,
        argv,
        cwd,
        timeout,
        &new_idempotency_key(),
        output,
    )
    .await?;
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
    output: OutputFormat,
) -> Result<ExecutionResponse> {
    let path = format!("/v1/sandbox-leases/{lease}/executions");
    let body = serde_json::to_vec(&ExecRequestBody {
        command: argv,
        cwd,
        timeout,
        idempotency_key,
    })?;
    let (status, payload) =
        retry_transport_once(|| send_exec_request(config, &path, &body, output))
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
    output: OutputFormat,
) -> std::result::Result<(reqwest::StatusCode, String), ExecRequestAttemptError> {
    let token = sandbox_auth_header(config, "POST", path, body, output)
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
/// stdout and stderr, so `kobe exec ... | grep` behaves the way anyone
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
#[serde(rename_all = "camelCase")]
struct CreateLeaseBody<'a> {
    pool: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<&'a str>,
    idempotency_key: &'a str,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SandboxLeaseResponse {
    id: String,
    phase: String,
    #[serde(default)]
    pool: String,
    #[serde(default)]
    ttl: String,
    #[serde(default)]
    effective_ttl: Option<String>,
    #[serde(default)]
    alias: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LeaseOutput<'a> {
    api_version: &'static str,
    id: &'a str,
    phase: &'a str,
    pool: &'a str,
    resource_kind: &'static str,
    capabilities: &'a [String],
    ttl: Option<&'a str>,
    alias: Option<&'a str>,
    expires_at: Option<&'a str>,
}

const SANDBOX_CAPABILITIES: &[&str] = &[
    "exec",
    "cancel",
    "logs",
    "attach",
    "port-forward",
    "extend",
    "release",
];

fn default_sandbox_actions() -> Vec<String> {
    SANDBOX_CAPABILITIES
        .iter()
        .map(|action| (*action).to_string())
        .collect()
}

pub(crate) async fn sandbox_actions_for_pool(
    config: &ResolvedConfig,
    pool: &str,
    output: OutputFormat,
) -> Vec<String> {
    match super::pools::fetch_pool_for_config_with_output(config, pool, output).await {
        Ok(summary) if !summary.capabilities.is_empty() => summary.capabilities,
        _ => default_sandbox_actions(),
    }
}

fn next_sandbox_hint(id: &str, phase: &str, actions: &[String]) -> Option<String> {
    if !phase.eq_ignore_ascii_case("ready") {
        return None;
    }
    if actions.iter().any(|action| action == "exec") {
        Some(format!("kobe exec {id} -- <command>"))
    } else {
        Some(format!(
            "this pool has no exec (actions: {})",
            actions.join(", ")
        ))
    }
}

#[cfg(test)]
mod next_hint_tests {
    use super::next_sandbox_hint;

    #[test]
    fn pending_has_no_next_hint() {
        let actions = vec!["lease".into(), "release".into()];
        assert!(next_sandbox_hint("sandbox-abc", "Pending", &actions).is_none());
    }

    #[test]
    fn ready_without_exec_says_so() {
        let actions = vec!["lease".into(), "logs".into(), "release".into()];
        let hint = next_sandbox_hint("sandbox-abc", "Ready", &actions).unwrap();
        assert!(hint.contains("no exec"), "{hint}");
        assert!(hint.contains("logs"), "{hint}");
    }

    #[test]
    fn ready_with_exec_points_at_kobe_exec() {
        let actions = vec!["lease".into(), "exec".into(), "release".into()];
        let hint = next_sandbox_hint("sandbox-abc", "Ready", &actions).unwrap();
        assert_eq!(hint, "kobe exec sandbox-abc -- <command>");
    }
}

/// One stable schema for every `sandbox run --output json` outcome.
///
/// Optional values are serialized as JSON `null`, rather than changing the
/// shape between success, timeout, signal and transport failure. `exit_code` is
/// always the observed remote code; `process_exit_code` is what this CLI uses.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunEnvelope {
    api_version: &'static str,
    outcome: &'static str,
    lease: Option<String>,
    execution: Option<String>,
    state: Option<String>,
    exit_code: Option<i32>,
    process_exit_code: i32,
    stdout: String,
    stderr: String,
    truncated: bool,
    signal: Option<&'static str>,
    error: Option<String>,
    cleanup: Option<CleanupOutcome>,
}

impl RunEnvelope {
    fn empty() -> Self {
        Self {
            api_version: SANDBOX_CLI_API_VERSION,
            outcome: "clientError",
            lease: None,
            execution: None,
            state: None,
            exit_code: None,
            process_exit_code: CLI_FAILURE_EXIT,
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
            signal: None,
            error: None,
            cleanup: None,
        }
    }
}

/// The create handler owns an eight-minute admission budget plus bounded
/// resolution. Waiting nine minutes is long, but finite and larger than the
/// server's contract, so a signal cannot discard an ambiguous committed lease.
const CREATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(9 * 60);
/// After a POST loses all response headers, its server task may still be in
/// eight-minute admission plus bounded resolution. A 404 is not absence proof
/// until this fresh window (measured from the transport failure) has elapsed.
const CREATE_SETTLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(9 * 60);
const CREATE_RECOVERY_POLL: std::time::Duration = std::time::Duration::from_millis(500);
const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);
const READY_POLL: std::time::Duration = std::time::Duration::from_secs(2);
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

/// Signal streams are constructed synchronously before the create future is
/// even built. Tokio installs the process handlers in `signal(...)`, so no
/// scheduler choice can poll the POST before SIGINT/SIGTERM are registered.
#[cfg(unix)]
struct ShutdownSignals {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignals {
    fn arm() -> Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            sigint: signal(SignalKind::interrupt()).context("could not register SIGINT")?,
            sigterm: signal(SignalKind::terminate()).context("could not register SIGTERM")?,
        })
    }

    async fn recv(&mut self) -> RunInterruption {
        tokio::select! {
            biased;
            _ = self.sigint.recv() => RunInterruption::SigInt,
            _ = self.sigterm.recv() => RunInterruption::SigTerm,
        }
    }
}

#[cfg(windows)]
struct ShutdownSignals {
    ctrl_c: tokio::signal::windows::CtrlC,
    ctrl_break: tokio::signal::windows::CtrlBreak,
}

#[cfg(windows)]
impl ShutdownSignals {
    fn arm() -> Result<Self> {
        Ok(Self {
            ctrl_c: tokio::signal::windows::ctrl_c().context("could not register Ctrl-C")?,
            ctrl_break: tokio::signal::windows::ctrl_break()
                .context("could not register Ctrl-Break")?,
        })
    }

    async fn recv(&mut self) -> RunInterruption {
        tokio::select! {
            biased;
            _ = self.ctrl_c.recv() => RunInterruption::SigInt,
            _ = self.ctrl_break.recv() => RunInterruption::SigTerm,
        }
    }
}

#[cfg(not(any(unix, windows)))]
struct ShutdownSignals;

#[cfg(not(any(unix, windows)))]
impl ShutdownSignals {
    fn arm() -> Result<Self> {
        Ok(Self)
    }

    async fn recv(&mut self) -> RunInterruption {
        let _ = tokio::signal::ctrl_c().await;
        RunInterruption::SigInt
    }
}

#[derive(Debug)]
struct CreateFailure {
    error: anyhow::Error,
    may_have_committed: bool,
}

impl CreateFailure {
    fn definite(error: impl Into<anyhow::Error>) -> Self {
        Self {
            error: error.into(),
            may_have_committed: false,
        }
    }

    fn ambiguous(error: impl Into<anyhow::Error>) -> Self {
        Self {
            error: error.into(),
            may_have_committed: true,
        }
    }
}

#[derive(Debug)]
enum RunExecutionError {
    ReadyTimeout(String),
    Disconnected(anyhow::Error),
    Failure(anyhow::Error),
}

impl RunExecutionError {
    fn message(&self) -> String {
        match self {
            Self::ReadyTimeout(message) => message.clone(),
            Self::Disconnected(error) | Self::Failure(error) => format!("{error:#}"),
        }
    }
}

/// Create a Sandbox, run one command in it, and release it.
///
/// The release is attempted on **every** terminal path: success, non-zero
/// exit, provisioning timeout, transport failure. A lease created and
/// abandoned holds capacity until its TTL eventually reaps it.
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

/// Persistent Sandbox allocation behind the resource-neutral `kobe lease`
/// command. Storage and admission remain Sandbox-specific; the public
/// lifecycle does not.
pub(crate) struct LeaseCommand<'a> {
    pub pool: &'a str,
    pub ttl: Option<&'a str>,
    pub alias: Option<&'a str>,
    pub no_wait: bool,
    pub wait_timeout: Option<&'a str>,
    pub keepalive: bool,
    pub output: OutputFormat,
}

pub(crate) async fn lease(config: &ResolvedConfig, command: LeaseCommand<'_>) -> Result<()> {
    let key = new_idempotency_key();
    let expected_lease = lease_id_for_create_key(&key);
    let post_started = std::cell::Cell::new(false);
    let lease_id = match create_sandbox_lease(
        config,
        CreateLeaseBody {
            pool: command.pool,
            ttl: command.ttl,
            alias: command.alias,
            idempotency_key: &key,
        },
        &expected_lease,
        command.output,
        &post_started,
    )
    .await
    {
        Ok(lease) => lease,
        Err(failure) if failure.may_have_committed => {
            anyhow::bail!(
                "Sandbox lease {expected_lease} may have been created: {:#}",
                failure.error
            )
        }
        Err(failure) => return Err(failure.error),
    };

    let actions = sandbox_actions_for_pool(config, command.pool, command.output).await;

    if command.no_wait {
        return emit_lease_output(
            &lease_id,
            "Pending",
            command.pool,
            command.ttl,
            command.alias,
            None,
            &actions,
            command.output,
        );
    }

    if command.output == OutputFormat::Text {
        eprintln!("Waiting for Sandbox lease {lease_id} to become ready (canary)...");
    }
    let ready_timeout = match command.wait_timeout {
        Some(value) => super::lease_create::parse_cli_duration(value)
            .ok_or_else(|| anyhow::anyhow!("Invalid --wait-timeout '{value}'"))?,
        None => READY_TIMEOUT,
    };
    // Ctrl-C is handled here, not inside `wait_until_ready`. `kobe run` shares
    // that helper and has its own signal machine that always releases.
    let ready = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            anyhow::bail!(super::lease_create::interrupted_waiting(&lease_id));
        }
        result = wait_until_ready(config, &lease_id, command.output, ready_timeout) => {
            result.map_err(|error| {
                let timed_out = matches!(error, RunExecutionError::ReadyTimeout(_));
                let message = error.message();
                if timed_out {
                    anyhow::anyhow!("{message}. Release with: kobe release {lease_id}")
                } else {
                    anyhow::anyhow!(message)
                }
            })?
        }
    };
    emit_lease_output(
        &ready.id,
        &ready.phase,
        command.pool,
        ready.effective_ttl.as_deref().or(command.ttl),
        ready.alias.as_deref().or(command.alias),
        ready.expires_at.as_deref(),
        &actions,
        command.output,
    )?;

    if command.keepalive {
        let ttl = command.ttl.unwrap_or(ready.ttl.as_str());
        if ttl.is_empty() {
            anyhow::bail!("Sandbox lease did not report a TTL for --keepalive");
        }
        let stop = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        super::keepalive::heartbeat_until(
            config,
            &lease_id,
            ttl,
            stop,
            command.output == OutputFormat::Text,
        )
        .await?;
    }
    Ok(())
}

pub(crate) fn emit_lease_output(
    id: &str,
    phase: &str,
    pool: &str,
    ttl: Option<&str>,
    alias: Option<&str>,
    expires_at: Option<&str>,
    capabilities: &[String],
    output: OutputFormat,
) -> Result<()> {
    match output {
        OutputFormat::Text => {
            println!("Lease:   {id}");
            println!("Pool:    {pool}");
            println!("Kind:    Sandbox");
            println!("Status:  {}", phase.to_ascii_lowercase());
            if let Some(expires_at) = expires_at {
                println!("Expires: {expires_at}");
            }
            println!("Actions: {}", capabilities.join(", "));
            if let Some(next) = next_sandbox_hint(id, phase, capabilities) {
                println!("Next:    {next}");
            }
            Ok(())
        }
        OutputFormat::Json => print_json(&LeaseOutput {
            api_version: SANDBOX_CLI_API_VERSION,
            id,
            phase,
            pool,
            resource_kind: "Sandbox",
            capabilities,
            ttl,
            alias,
            expires_at,
        }),
    }
}

/// Create, execute and release as one bounded, signal-aware state machine.
///
/// The first SIGINT/SIGTERM changes the command outcome but never skips cleanup.
/// Signal delivery remains armed while release is observed. A second signal is
/// an explicit request to stop waiting after the DELETE attempt has produced
/// headers or a transport result. Observation is then stopped, cleanup is
/// reported as unconfirmed, and the process still exits for the first signal
/// (130 for SIGINT, 143 for SIGTERM).
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
    let mut envelope = RunEnvelope::empty();
    if argv.is_empty() {
        envelope.error = Some("a command is required: kobe run <pool> -- <argv...>".to_string());
        return emit_run_envelope(&envelope, output);
    }
    let config = match CliConfig::load()
        .and_then(|config| config.resolve(target_override, endpoint_override))
    {
        Ok(config) => config,
        Err(error) => {
            envelope.error = Some(format!("{error:#}"));
            return emit_run_envelope(&envelope, output);
        }
    };
    let mut signals = match ShutdownSignals::arm() {
        Ok(signals) => signals,
        Err(error) => {
            envelope.error = Some(format!("{error:#}"));
            return emit_run_envelope(&envelope, output);
        }
    };

    let create_key = new_idempotency_key();
    let expected_lease = lease_id_for_create_key(&create_key);
    envelope.lease = Some(expected_lease.clone());
    let post_started = std::cell::Cell::new(false);
    let create = create_sandbox_lease(
        &config,
        CreateLeaseBody {
            pool,
            ttl,
            alias: None,
            idempotency_key: &create_key,
        },
        &expected_lease,
        output,
        &post_started,
    );
    tokio::pin!(create);
    let mut first_signal = None;
    let created = tokio::select! {
        // Signal wins a same-turn race. Registration happened synchronously
        // above, before this POST future was constructed or polled.
        biased;
        signal = signals.recv() => {
            first_signal = Some(signal);
            // Authorization may be in flight, but no lease can exist until
            // the POST itself has been polled. Do not start a new create for a
            // cancellation that won before that boundary.
            if post_started.get() {
                Some(create.await)
            } else {
                None
            }
        }
        result = &mut create => Some(result),
    };
    let created = match created {
        Some(result) => result,
        None => {
            envelope.lease = None;
            if let Some(signal) = first_signal {
                envelope.outcome = "signal";
                envelope.signal = Some(signal.name());
                envelope.process_exit_code = signal.exit_code();
            }
            return emit_run_envelope(&envelope, output);
        }
    };

    let mut execution = None;
    let mut run_error = None;
    let cleanup_needed = match created {
        Ok(lease) => {
            envelope.lease = Some(lease.clone());
            if first_signal.is_none() {
                let running = run_in_lease(&config, &lease, argv, cwd, timeout, output);
                tokio::pin!(running);
                tokio::select! {
                    biased;
                    signal = signals.recv() => first_signal = Some(signal),
                    result = &mut running => match result {
                        Ok(result) => execution = Some(result),
                        Err(error) => run_error = Some(error),
                    },
                }
            }
            true
        }
        Err(failure) => {
            envelope.outcome = "createError";
            envelope.error = Some(format!("{:#}", failure.error));
            if !failure.may_have_committed {
                envelope.lease = None;
            }
            failure.may_have_committed
        }
    };

    if cleanup_needed {
        envelope.cleanup = Some(
            release_while_listening(
                &config,
                envelope.lease.as_deref().unwrap_or(&expected_lease),
                &mut signals,
                &mut first_signal,
            )
            .await,
        );
    }

    if let Some(result) = execution {
        envelope.process_exit_code = exit_code_for(&result);
        envelope.execution = Some(result.id);
        envelope.state = Some(result.state.clone());
        envelope.exit_code = result.exit_code;
        envelope.stdout = result.stdout.unwrap_or_default();
        envelope.stderr = result.stderr.unwrap_or_default();
        envelope.truncated = result.truncated;
        envelope.outcome = match (result.state.as_str(), result.exit_code) {
            ("TimedOut", _) => "timeout",
            ("Cancelled", _) => "cancelled",
            (_, Some(0)) => "success",
            (_, Some(_)) => "nonzero",
            _ => "executionFailure",
        };
    } else if let Some(error) = run_error {
        envelope.outcome = match error {
            RunExecutionError::ReadyTimeout(_) => "timeout",
            RunExecutionError::Disconnected(_) => "disconnect",
            RunExecutionError::Failure(_) => "executionError",
        };
        envelope.error = Some(error.message());
    }

    if let Some(signal) = first_signal {
        envelope.outcome = "signal";
        envelope.signal = Some(signal.name());
        envelope.process_exit_code = signal.exit_code();
    }

    emit_run_envelope(&envelope, output)
}

fn emit_run_envelope(envelope: &RunEnvelope, output: OutputFormat) -> Result<i32> {
    match output {
        OutputFormat::Json => print_json(envelope)?,
        OutputFormat::Text => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(envelope.stdout.as_bytes())?;
            stdout.flush()?;
            let mut stderr = std::io::stderr().lock();
            stderr.write_all(envelope.stderr.as_bytes())?;
            if envelope.truncated {
                writeln!(stderr, "kobe: execution output was truncated by the server")?;
            }
            if let Some(signal) = envelope.signal {
                writeln!(stderr, "kobe: {signal} received")?;
            } else if let Some(error) = envelope.error.as_deref() {
                writeln!(stderr, "kobe: {error}")?;
            } else if envelope.exit_code.is_none() && envelope.state.is_some() {
                writeln!(
                    stderr,
                    "kobe: execution ended in state {}",
                    envelope.state.as_deref().unwrap_or_default()
                )?;
            }
            if let Some(cleanup) = envelope.cleanup.as_ref()
                && !cleanup.released
            {
                writeln!(
                    stderr,
                    "kobe: WARNING the sandbox lease release was not confirmed{}",
                    cleanup
                        .error
                        .as_deref()
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default()
                )?;
            }
            stderr.flush()?;
        }
    }
    Ok(envelope.process_exit_code)
}

async fn run_in_lease(
    config: &ResolvedConfig,
    lease: &str,
    argv: &[String],
    cwd: Option<&str>,
    timeout: Option<&str>,
    output: OutputFormat,
) -> std::result::Result<ExecutionResponse, RunExecutionError> {
    let _ = wait_until_ready(config, lease, output, READY_TIMEOUT).await?;
    exec_once_for_run(
        config,
        lease,
        argv,
        cwd,
        timeout,
        &new_idempotency_key(),
        output,
    )
    .await
}

async fn exec_once_for_run(
    config: &ResolvedConfig,
    lease: &str,
    argv: &[String],
    cwd: Option<&str>,
    timeout: Option<&str>,
    idempotency_key: &str,
    output: OutputFormat,
) -> std::result::Result<ExecutionResponse, RunExecutionError> {
    let path = format!("/v1/sandbox-leases/{lease}/executions");
    let body = serde_json::to_vec(&ExecRequestBody {
        command: argv,
        cwd,
        timeout,
        idempotency_key,
    })
    .map_err(|error| RunExecutionError::Failure(anyhow::Error::from(error)))?;
    let (status, payload) =
        retry_transport_once(|| send_exec_request(config, &path, &body, output))
            .await
            .map_err(|error| match error {
                ExecRequestAttemptError::Auth(error) => RunExecutionError::Failure(error),
                ExecRequestAttemptError::Transport(error) => RunExecutionError::Disconnected(
                    error.context("could not reach the Kobe endpoint"),
                ),
            })?;
    if !status.is_success() {
        return Err(RunExecutionError::Failure(anyhow::anyhow!(
            "execution failed (HTTP {status}): {}",
            payload.trim()
        )));
    }
    serde_json::from_str(&payload)
        .context("could not parse the execution response")
        .map_err(RunExecutionError::Failure)
}

fn lease_id_for_create_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update((key.len() as u64).to_be_bytes());
    hasher.update(key.as_bytes());
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sandbox-{}", &digest[..24])
}

#[derive(Debug)]
enum CreateHeaderFailure {
    Auth(anyhow::Error),
    Transport(anyhow::Error),
}

async fn create_sandbox_lease(
    config: &ResolvedConfig,
    request: CreateLeaseBody<'_>,
    expected_lease: &str,
    output: OutputFormat,
    post_started: &std::cell::Cell<bool>,
) -> std::result::Result<String, CreateFailure> {
    let path = "/v1/sandbox-leases";
    let body = serde_json::to_vec(&request)
        .map_err(|error| CreateFailure::definite(anyhow::Error::from(error)))?;
    let deadline = tokio::time::Instant::now() + CREATE_TIMEOUT;

    let mut attempt = 0;
    let mut ambiguous_send = None;
    let response = loop {
        attempt += 1;
        match send_create_headers(config, path, &body, deadline, output, post_started).await {
            Ok(response) => break response,
            Err(CreateHeaderFailure::Transport(error)) if attempt == 1 => {
                ambiguous_send = Some(error);
                continue;
            }
            Err(CreateHeaderFailure::Transport(error)) => {
                let context = ambiguous_send
                    .map(|first| {
                        format!("first create response was lost: {first:#}; second: {error:#}")
                    })
                    .unwrap_or_else(|| format!("create response was lost: {error:#}"));
                return recover_expected_lease(
                    config,
                    expected_lease,
                    tokio::time::Instant::now() + CREATE_SETTLE_TIMEOUT,
                    output,
                    context,
                )
                .await;
            }
            Err(CreateHeaderFailure::Auth(error)) if ambiguous_send.is_some() => {
                return recover_expected_lease(
                    config,
                    expected_lease,
                    tokio::time::Instant::now() + CREATE_SETTLE_TIMEOUT,
                    output,
                    format!("create retry authorization failed after an ambiguous send: {error:#}"),
                )
                .await;
            }
            Err(CreateHeaderFailure::Auth(error)) => return Err(CreateFailure::definite(error)),
        }
    };

    let status = response.status();
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .map(|value| value.to_str().map(str::to_owned));
    let payload = tokio::time::timeout_at(deadline, response.bytes()).await;
    if !status.is_success() {
        let detail = match payload {
            Ok(Ok(bytes)) => String::from_utf8_lossy(&bytes).trim().to_string(),
            Ok(Err(error)) => format!("response body failed: {error}"),
            Err(_) => "response body exceeded the create deadline".to_string(),
        };
        let error = anyhow::anyhow!("could not create a sandbox (HTTP {status}): {detail}");
        if ambiguous_send.is_some() {
            return recover_expected_lease(
                config,
                expected_lease,
                tokio::time::Instant::now() + CREATE_SETTLE_TIMEOUT,
                output,
                format!("{error:#}"),
            )
            .await;
        }
        if status.is_server_error() {
            // A server-side failure can be returned while a Kubernetes CREATE
            // whose response was uncertain is still becoming observable. Do
            // not let cleanup turn an immediate 404 into false absence proof:
            // settle the deterministic handle first, then report the original
            // create failure so `run` releases that exact object.
            return match recover_expected_lease(
                config,
                expected_lease,
                tokio::time::Instant::now() + CREATE_SETTLE_TIMEOUT,
                output,
                format!("{error:#}"),
            )
            .await
            {
                Ok(_) => Err(CreateFailure::ambiguous(error)),
                Err(failure) => Err(failure),
            };
        }
        return Err(CreateFailure::definite(error));
    }

    if let Ok(Ok(bytes)) = payload
        && let Ok(lease) = serde_json::from_slice::<SandboxLeaseResponse>(&bytes)
    {
        return validate_created_lease(lease, expected_lease).map_err(CreateFailure::ambiguous);
    }

    // Once response headers exist, never repeat the POST. Location is the
    // server's durable recovery handle for a body that was cut short.
    let expected_path = format!("/v1/sandbox-leases/{expected_lease}");
    let expected_absolute = format!("{}{}", config.endpoint.trim_end_matches('/'), expected_path);
    let recovery_context = match location.transpose() {
        Ok(Some(location)) if location == expected_path || location == expected_absolute => {
            "create response body was incomplete; recovering its Location".to_string()
        }
        Ok(Some(location)) => {
            format!("create response carried an unexpected Location {location}; recovering only the deterministic keyed Location")
        }
        Ok(None) => {
            "create response was incomplete and carried no Location; recovering the deterministic keyed Location".to_string()
        }
        Err(error) => format!(
            "create response carried an invalid Location header ({error}); recovering only the deterministic keyed Location"
        ),
    };
    let recovery_deadline = if ambiguous_send.is_some() {
        tokio::time::Instant::now() + CREATE_SETTLE_TIMEOUT
    } else {
        deadline
    };
    recover_expected_lease(
        config,
        expected_lease,
        recovery_deadline,
        output,
        recovery_context,
    )
    .await
}

async fn send_create_headers(
    config: &ResolvedConfig,
    path: &str,
    body: &[u8],
    deadline: tokio::time::Instant,
    output: OutputFormat,
    post_started: &std::cell::Cell<bool>,
) -> std::result::Result<reqwest::Response, CreateHeaderFailure> {
    let token = tokio::time::timeout_at(
        deadline,
        sandbox_auth_header(config, "POST", path, body, output),
    )
    .await
    .map_err(|_| {
        CreateHeaderFailure::Auth(anyhow::anyhow!(
            "sandbox create authorization exceeded {CREATE_TIMEOUT:?}"
        ))
    })?
    .map_err(CreateHeaderFailure::Auth)?;
    let request = with_auth(
        authed_client().post(format!("{}{path}", config.endpoint)),
        &token,
    )
    .header("Content-Type", "application/json")
    .body(body.to_vec())
    .send();
    // Set immediately before the send future's first poll. If a signal wins
    // before this point, dropping create is proof that no lease was requested.
    post_started.set(true);
    tokio::time::timeout_at(deadline, request)
        .await
        .map_err(|_| {
            CreateHeaderFailure::Transport(anyhow::anyhow!(
                "sandbox create response headers exceeded {CREATE_TIMEOUT:?}"
            ))
        })?
        .map_err(|error| {
            CreateHeaderFailure::Transport(
                anyhow::Error::from(error)
                    .context("could not reach the Kobe endpoint while creating a sandbox"),
            )
        })
}

/// Poll the deterministic keyed Location until the still-running create
/// handler can no longer materialize it.
///
/// A 404 immediately after a no-header disconnect is not absence proof: the
/// server may not have reached its durable parent CREATE yet. The fresh settle
/// window is deliberately measured after the last ambiguous send.
async fn recover_expected_lease(
    config: &ResolvedConfig,
    expected_lease: &str,
    deadline: tokio::time::Instant,
    output: OutputFormat,
    mut last_error: String,
) -> std::result::Result<String, CreateFailure> {
    let path = format!("/v1/sandbox-leases/{expected_lease}");
    let absolute = format!("{}{}", config.endpoint.trim_end_matches('/'), path);
    loop {
        let attempt = async {
            let token = sandbox_auth_header(config, "GET", &path, b"", output).await?;
            let response = with_auth(authed_client().get(&absolute), &token)
                .send()
                .await?;
            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if !status.is_success() {
                anyhow::bail!("recovery GET returned HTTP {status}");
            }
            let bytes = response.bytes().await?;
            let lease: SandboxLeaseResponse = serde_json::from_slice(&bytes)
                .context("could not parse the recovered sandbox lease")?;
            Ok(Some(lease))
        };
        match tokio::time::timeout_at(deadline, attempt).await {
            Ok(Ok(Some(lease))) => {
                return validate_created_lease(lease, expected_lease)
                    .map_err(CreateFailure::ambiguous);
            }
            Ok(Ok(None)) => {
                last_error = format!("{expected_lease} is not observable yet");
            }
            Ok(Err(error)) => last_error = format!("{error:#}"),
            Err(_) => break,
        }
        if tokio::time::timeout_at(deadline, tokio::time::sleep(CREATE_RECOVERY_POLL))
            .await
            .is_err()
        {
            break;
        }
    }
    Err(CreateFailure::ambiguous(anyhow::anyhow!(
        "sandbox create recovery did not find {expected_lease} before its bounded settle window ended: {last_error}"
    )))
}

fn validate_created_lease(lease: SandboxLeaseResponse, expected_lease: &str) -> Result<String> {
    if lease.id != expected_lease {
        anyhow::bail!(
            "sandbox create returned lease {}, expected the keyed lease {expected_lease}",
            lease.id
        );
    }
    Ok(lease.id)
}

async fn wait_until_ready(
    config: &ResolvedConfig,
    lease: &str,
    output: OutputFormat,
    ready_timeout: std::time::Duration,
) -> std::result::Result<SandboxLeaseResponse, RunExecutionError> {
    let deadline = tokio::time::Instant::now() + ready_timeout;
    loop {
        let path = format!("/v1/sandbox-leases/{lease}");
        let token = tokio::time::timeout_at(
            deadline,
            sandbox_auth_header(config, "GET", &path, b"", output),
        )
        .await
        .map_err(|_| ready_deadline_error(lease))?
        .map_err(RunExecutionError::Failure)?;
        let response = tokio::time::timeout_at(
            deadline,
            with_auth(
                authed_client().get(format!("{}{path}", config.endpoint)),
                &token,
            )
            .send(),
        )
        .await
        .map_err(|_| ready_deadline_error(lease))?
        .context("could not reach the Kobe endpoint")
        .map_err(RunExecutionError::Failure)?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            // A create may return the durable `admission_pending` handle while
            // the server-owned arbiter is still settling. If cancellation
            // wins, that exact object is deleted and 404 is the terminal
            // admission-failed signal. Never POST another lease implicitly.
            return Err(RunExecutionError::Failure(anyhow::anyhow!(
                "sandbox {lease} admission was cancelled before it became ready"
            )));
        }
        if !response.status().is_success() {
            return Err(RunExecutionError::Failure(anyhow::anyhow!(
                "sandbox readiness failed with HTTP {}",
                response.status()
            )));
        }
        let current: SandboxLeaseResponse = tokio::time::timeout_at(deadline, response.json())
            .await
            .map_err(|_| ready_deadline_error(lease))?
            .context("could not parse the sandbox lease response")
            .map_err(RunExecutionError::Failure)?;
        match current.phase.as_str() {
            "Ready" => return Ok(current),
            "Released" | "Expired" | "Quarantined" => {
                return Err(RunExecutionError::Failure(anyhow::anyhow!(
                    "sandbox {lease} ended in {} before it was ready",
                    current.phase
                )));
            }
            _ => {}
        }
        tokio::time::timeout_at(deadline, tokio::time::sleep(READY_POLL))
            .await
            .map_err(|_| ready_deadline_error(lease))?;
    }
}

fn ready_deadline_error(lease: &str) -> RunExecutionError {
    RunExecutionError::ReadyTimeout(format!(
        "sandbox {lease} was not ready within the wait deadline"
    ))
}

async fn release_while_listening(
    config: &ResolvedConfig,
    lease: &str,
    signals: &mut ShutdownSignals,
    first_signal: &mut Option<RunInterruption>,
) -> CleanupOutcome {
    let delete_attempted = tokio::sync::Notify::new();
    let release = release_sandbox_lease(config, lease, &delete_attempted);
    tokio::pin!(release);
    let mut stop_after_delete: Option<RunInterruption> = None;
    loop {
        if let Some(signal) = stop_after_delete {
            tokio::select! {
                biased;
                cleanup = &mut release => return cleanup,
                _ = delete_attempted.notified() => {
                    return CleanupOutcome {
                        released: false,
                        phase: None,
                        error: Some(format!(
                            "cleanup observation interrupted by second {} after the release request was attempted",
                            signal.name()
                        )),
                    };
                }
            }
        }
        tokio::select! {
            biased;
            signal = signals.recv() => {
                if first_signal.is_none() {
                    *first_signal = Some(signal);
                    continue;
                }
                // A signal queued while create was resolving must not prevent
                // cleanup from issuing DELETE at all. Stop only after that
                // bounded request has produced headers or a transport result.
                stop_after_delete = Some(signal);
            }
            cleanup = &mut release => return cleanup,
        }
    }
}

/// Release the lease, reporting what actually happened.
///
/// Never returns an error: a release failure is data the caller needs
/// alongside their command's result, not a replacement for it. A successful
/// DELETE only requests release, so this waits until GET observes `Releasing`,
/// a clean terminal phase, or absence. A 404 counts as released — the lease is
/// gone, which is the goal.
async fn release_sandbox_lease(
    config: &ResolvedConfig,
    lease: &str,
    delete_attempted: &tokio::sync::Notify,
) -> CleanupOutcome {
    let observe = async {
        let path = format!("/v1/sandbox-leases/{lease}");
        // Cleanup is never interactive, even in text mode. A TOFU prompt runs
        // on Tokio's blocking pool and cannot be cancelled once stdin blocks;
        // allowing one here would make the advertised 30-second bound false
        // and could retain the runtime after a successful remote command.
        let token = get_auth_header_noninteractive(config, "DELETE", &path, b"").await?;
        let response = with_auth(
            authed_client().delete(format!("{}{path}", config.endpoint)),
            &token,
        )
        .send()
        .await;
        // Wakes a queued second-signal path only after the DELETE request has
        // returned response headers or a transport result. Observation may be
        // skipped by that signal; the release attempt itself never is.
        delete_attempted.notify_one();
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
        // the exact lease is both safe and stronger than reporting release as
        // unconfirmed because a response body merely failed to arrive.

        loop {
            let token = get_auth_header_noninteractive(config, "GET", &path, b"").await?;
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
/// Text writes returned strings to their original streams. JSON follow mode
/// emits one compact JSON object per window (NDJSON); non-follow JSON remains
/// one normal pretty-printed object.
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
    let token = sandbox_auth_header(&config, "GET", &path, b"", output).await?;
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
        // The log body is the workload's own returned text. In JSON mode it is one
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
        let current = read_execution_logs(
            config,
            lease,
            execution,
            stdout_offset,
            stderr_offset,
            output,
        )
        .await?;
        stdout_offset = current.stdout.next_offset;
        stderr_offset = current.stderr.next_offset;
        let more = current.stdout.more || current.stderr.more;
        let progressed = previous_offsets != (stdout_offset, stderr_offset);
        let visible = !follow
            || progressed
            || !current.stdout.data.is_empty()
            || !current.stderr.data.is_empty()
            || current.stdout.truncated
            || current.stderr.truncated
            || (execution_is_terminal(&current.state) && !more);
        if visible {
            emit_execution_logs(lease, &current, follow, output)?;
        }
        if !follow || (execution_is_terminal(&current.state) && !more) {
            return Ok(());
        }
        if !more || !progressed {
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
    output: OutputFormat,
) -> Result<ExecutionLogsResponse> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        match read_execution_logs_once(
            config,
            lease,
            execution,
            stdout_offset,
            stderr_offset,
            output,
        )
        .await
        {
            Ok(current) => {
                validate_log_response(&current, execution, stdout_offset, stderr_offset)?;
                return Ok(current);
            }
            Err(LogReadFailure::Transport(_)) if attempt == 1 => continue,
            Err(error) => return Err(error.into_inner()),
        }
    }
}

#[derive(Debug)]
enum LogReadFailure {
    Auth(anyhow::Error),
    Transport(anyhow::Error),
    Http(anyhow::Error),
}

impl LogReadFailure {
    fn into_inner(self) -> anyhow::Error {
        match self {
            Self::Auth(error) | Self::Transport(error) | Self::Http(error) => error,
        }
    }
}

async fn read_execution_logs_once(
    config: &ResolvedConfig,
    lease: &str,
    execution: &str,
    stdout_offset: u64,
    stderr_offset: u64,
    output: OutputFormat,
) -> std::result::Result<ExecutionLogsResponse, LogReadFailure> {
    let path = execution_logs_path(lease, execution, stdout_offset, stderr_offset);
    let token = sandbox_auth_header(config, "GET", &path, b"", output)
        .await
        .map_err(LogReadFailure::Auth)?;
    let response = with_auth(
        authed_client().get(format!("{}{path}", config.endpoint)),
        &token,
    )
    .send()
    .await
    .map_err(|error| {
        LogReadFailure::Transport(
            anyhow::Error::from(error).context("could not reach the Kobe endpoint"),
        )
    })?;
    let status = response.status();
    if !status.is_success() {
        let payload = response.bytes().await.unwrap_or_default();
        let error = anyhow::anyhow!(
            "could not read execution logs (HTTP {status}): {}",
            String::from_utf8_lossy(&payload).trim()
        );
        return Err(
            if matches!(
                status,
                reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
            ) {
                // Authentication and authorization failures are terminal. Retrying
                // them would only duplicate load and obscure the policy result.
                LogReadFailure::Auth(error)
            } else {
                LogReadFailure::Http(error)
            },
        );
    }
    let payload = response.bytes().await.map_err(|error| {
        LogReadFailure::Transport(
            anyhow::Error::from(error).context("execution log response body was interrupted"),
        )
    })?;
    serde_json::from_slice(&payload)
        .context("could not parse the execution logs response")
        .map_err(LogReadFailure::Transport)
}

fn validate_log_response(
    current: &ExecutionLogsResponse,
    execution: &str,
    stdout_offset: u64,
    stderr_offset: u64,
) -> Result<()> {
    if current.id != execution {
        anyhow::bail!(
            "execution log response changed id from {execution} to {}",
            current.id
        );
    }
    validate_log_window("stdout", stdout_offset, &current.stdout)?;
    validate_log_window("stderr", stderr_offset, &current.stderr)
}

fn validate_log_window(stream: &str, requested: u64, window: &ExecutionLogWindow) -> Result<()> {
    if window.next_offset < requested {
        anyhow::bail!(
            "execution {stream} offset regressed from {requested} to {}",
            window.next_offset
        );
    }
    if !window.data.is_empty() && window.next_offset == requested {
        anyhow::bail!("execution {stream} returned bytes without advancing its offset");
    }
    if window.data.is_empty() && window.next_offset > requested && !window.truncated {
        anyhow::bail!(
            "execution {stream} advanced its offset without bytes or a truncation marker"
        );
    }
    Ok(())
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
                let mut stdout = std::io::stdout().lock();
                serde_json::to_writer(&mut stdout, &output)?;
                stdout.write_all(b"\n")?;
                stdout.flush()?;
                Ok(())
            } else {
                print_json(&output)
            }
        }
        OutputFormat::Text => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(current.stdout.data.as_bytes())?;
            stdout.flush()?;
            let mut stderr = std::io::stderr().lock();
            stderr.write_all(current.stderr.data.as_bytes())?;
            if current.stdout.truncated || current.stderr.truncated {
                writeln!(
                    stderr,
                    "kobe: execution output was truncated at the server's retention cap"
                )?;
            }
            stderr.flush()?;
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
    let token = sandbox_auth_header(&config, "DELETE", &path, b"", output).await?;
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

    #[test]
    fn create_key_deterministically_names_only_its_retry() {
        assert_eq!(
            lease_id_for_create_key("caller-key-1"),
            "sandbox-74e5a3f11fea32a242354940"
        );
        assert_eq!(
            lease_id_for_create_key("same-key"),
            lease_id_for_create_key("same-key")
        );
        assert_ne!(
            lease_id_for_create_key("same-key"),
            lease_id_for_create_key("another-key")
        );
        assert!(lease_id_for_create_key("same-key").starts_with("sandbox-"));
    }

    #[tokio::test(start_paused = true)]
    async fn ready_deadline_includes_a_stalled_get_response() {
        use std::io::Read;
        use std::net::TcpListener;
        use std::sync::mpsc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let request_seen = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen_by_server = std::sync::Arc::clone(&request_seen);
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            seen_by_server.store(true, std::sync::atomic::Ordering::SeqCst);
            // Headers never arrive. The absolute ready deadline must cancel
            // this request rather than starting its clock after `send()`.
            release_rx.recv().unwrap();
        });
        let config = ResolvedConfig {
            target: None,
            endpoint: format!("http://{address}"),
            auth: crate::commands::config::AuthMode::None,
            token: None,
            ssh_fingerprint: None,
        };
        let started = tokio::time::Instant::now();
        let result = wait_until_ready(
            &config,
            "sandbox-stalled",
            OutputFormat::Json,
            READY_TIMEOUT,
        );
        tokio::pin!(result);
        while !request_seen.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::select! {
                biased;
                result = &mut result => panic!("readiness ended before the stalled request: {result:?}"),
                _ = tokio::task::yield_now() => {}
            }
        }
        tokio::time::advance(READY_TIMEOUT).await;
        let result = result.await;
        assert!(matches!(result, Err(RunExecutionError::ReadyTimeout(_))));
        assert_eq!(tokio::time::Instant::now() - started, READY_TIMEOUT);
        release_tx.send(()).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn run_json_envelope_has_one_shape_for_every_outcome() {
        let mut output = RunEnvelope::empty();
        output.outcome = "signal";
        output.signal = Some("SIGTERM");
        output.cleanup = Some(failed_cleanup());
        let json = serde_json::to_value(output).unwrap();
        for field in [
            "apiVersion",
            "outcome",
            "lease",
            "execution",
            "state",
            "exitCode",
            "processExitCode",
            "stdout",
            "stderr",
            "truncated",
            "signal",
            "error",
            "cleanup",
        ] {
            assert!(json.get(field).is_some(), "missing stable field {field}");
        }
        let cleanup = json["cleanup"].as_object().unwrap();
        for field in ["released", "phase", "error"] {
            assert!(
                cleanup.get(field).is_some(),
                "missing cleanup field {field}"
            );
        }
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

    #[test]
    fn execution_log_offsets_never_regress_or_emit_without_progress() {
        let mut window = ExecutionLogWindow {
            data: String::new(),
            next_offset: 9,
            more: true,
            truncated: false,
        };
        assert!(validate_log_window("stdout", 10, &window).is_err());
        window.next_offset = 10;
        window.data = "duplicate".into();
        assert!(validate_log_window("stdout", 10, &window).is_err());
        window.next_offset = 11;
        window.data.clear();
        assert!(validate_log_window("stdout", 10, &window).is_err());
        window.truncated = true;
        assert!(validate_log_window("stdout", 10, &window).is_ok());
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
    /// Collapsing them would either hide an unconfirmed release behind a successful
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
            // ...and release was not confirmed. Both facts survive.
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
