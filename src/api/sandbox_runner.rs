//! Kobe's half of the Sandbox runner contract (#82).
//!
//! # Why durable execution needs a second process at all
//!
//! A Kubernetes exec is a connection. Everything Kobe starts through one dies
//! with it: the caller disconnects, the operator restarts, a node drains, and
//! the command goes with them. Wait mode also needs exact `cwd`, timeout, exit
//! status, retained output and process-group cancellation. Building either
//! response mode on raw exec would make those guarantees depend on whether the
//! HTTP connection happened to survive.
//!
//! So the container runs [`kobe-runner`](kobe_runner), which is re-executed
//! into a session of its own and reparented to the container's init. Kobe then
//! talks to it the way you would talk to a small daemon, except that the
//! transport is one short exec per verb:
//!
//! ```text
//! start   <- the request on stdin, one line   -> a report
//! status                                       -> a report
//! logs    (by offset, per stream)              -> one bounded window
//! cancel                                       -> a report, after the group dies
//! ```
//!
//! # Why exec, and not a port
//!
//! A listening socket inside the Sandbox would be reachable by the tenant's own
//! workload, would need an authentication scheme of its own, and would have to
//! be declared by the pool before anybody could reach it. Exec is already
//! fenced — to one lease, one Pod UID, one container — and #81's resolver
//! re-runs that fence on *every* call, so a lease that expires mid-execution
//! stops being able to poll it.
//!
//! # Why the tenant's command never appears in an argument
//!
//! An exec's argv is a URL, and the target apiserver audit-logs it verbatim.
//! Only the execution id — a hash Kobe derived — is ever passed as an argument;
//! the command itself is written to the runner's stdin, which nothing on the
//! path records.

use kobe_runner::protocol::{
    Envelope, ExecutionReport, LogStream, MAX_LOG_CHUNK_BYTES, MAX_REQUEST_BYTES, PROTOCOL_VERSION,
    Reply, RunnerErrorCode, RunnerState, StartRequest, TEST_EXIT_AFTER_SPAWN_BEFORE_ACK_FLAG,
    TEST_EXIT_BEFORE_SPAWN_FLAG,
};

use crate::api::sandbox_access::{SandboxAccessDenied, SandboxTarget, exec_capped_until};
use crate::crd::ExecutionState;

/// How long one control call may take.
///
/// Bounded independently of the command's own timeout: `status` on a command
/// with an hour left to run must answer in a moment, and an API worker blocked
/// on a wedged container is one that is not serving anybody else.
pub const RUNNER_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Longer, because `cancel` deliberately waits.
///
/// The runner asks the process group to stop, gives it a grace period, and then
/// kills it. Returning before that resolves would hand the caller a
/// non-terminal answer to the one request whose entire purpose is to reach a
/// terminal one.
pub const RUNNER_CANCEL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Most output one runner reply may occupy.
///
/// A log window is `MAX_LOG_CHUNK_BYTES` of base64 plus a little JSON; this
/// leaves room without letting a broken runner make the operator buffer
/// unbounded memory.
const RUNNER_REPLY_CAP: usize = 2 * MAX_LOG_CHUNK_BYTES;

/// Why a runner call did not produce an answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunnerCallFailure {
    /// The runner could not be reached, or did not answer. The command may be
    /// running perfectly well — this says only that Kobe cannot see it.
    #[error("the sandbox runner did not answer")]
    Unreachable,
    /// It answered with something Kobe will not interpret: another protocol
    /// version, a truncated document, anything but exactly one reply.
    #[error("the sandbox runner answered with an unreadable reply")]
    Unreadable,
    /// It answered, and refused.
    #[error("the sandbox runner refused the request")]
    Refused(RunnerErrorCode),
}

impl RunnerCallFailure {
    /// Bounded reason code for the durable record.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Unreachable => "runner_unreachable",
            Self::Unreadable => "runner_unreadable",
            Self::Refused(RunnerErrorCode::NotFound) => "runner_forgot_execution",
            Self::Refused(RunnerErrorCode::Conflict) => "runner_id_conflict",
            Self::Refused(RunnerErrorCode::InvalidRequest) => "runner_rejected_request",
            Self::Refused(RunnerErrorCode::Internal) => "runner_internal_error",
        }
    }

    /// What the caller is told.
    ///
    /// Never 500: none of these mean Kobe is broken, and a caller retrying a
    /// 500 is precisely the behaviour a duplicate-spawn design must not invite.
    pub fn http_status(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            Self::Refused(RunnerErrorCode::Conflict) => StatusCode::CONFLICT,
            Self::Refused(RunnerErrorCode::NotFound) => StatusCode::NOT_FOUND,
            _ => StatusCode::BAD_GATEWAY,
        }
    }
}

/// What one runner report means in Kobe's own vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerOutcome {
    pub state: ExecutionState,
    pub exit_code: Option<i32>,
    pub reason: String,
}

/// Bounded output captured by the runner for one completed wait-mode command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
}

/// One validated output window from the exact requested runner record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerLogChunk {
    pub offset: u64,
    pub next_offset: u64,
    pub bytes: Vec<u8>,
    pub truncated: bool,
    pub more: bool,
}

/// Translate a report into the record a caller reads.
///
/// This is the function that decides what a caller will do next, so every arm
/// is chosen for the action it invites rather than for how it reads:
///
/// * `Succeeded` without an observed exit code becomes `Unknown`. A success
///   nobody backed with a number is a claim, not an observation.
/// * A process killed by a foreign signal — an OOM kill, an administrator —
///   becomes `Failed`. It definitely ran and definitely did not finish, so
///   `Unknown` would understate what is known. The record carries the POSIX
///   `128 + signal` convention because [`crate::crd::SandboxExecutionStatus`]
///   requires a code for `Failed`, and `reason = signalled` is what keeps it
///   distinguishable from a command that deliberately exited 137.
/// * Everything the runner could not establish becomes `Unknown`, never
///   `Failed`: `Failed` reads as "it ran and said no", which tells a caller
///   their retry is safe when it may not be.
pub fn outcome_from_report(report: &ExecutionReport) -> RunnerOutcome {
    let reason = report
        .reason
        .as_deref()
        .map(bounded_reason)
        .unwrap_or_else(|| "runner_gave_no_reason".to_string());

    let (state, exit_code) = match report.state {
        RunnerState::Running => (ExecutionState::Running, None),
        RunnerState::Succeeded => match report.exit_code {
            Some(0) => (ExecutionState::Succeeded, Some(0)),
            // A success reported with a non-zero code, or with none at all, is
            // a report contradicting itself. The caller decides.
            _ => (ExecutionState::Unknown, None),
        },
        RunnerState::Failed => match (report.exit_code, report.signal) {
            (Some(code), _) if code != 0 => (ExecutionState::Failed, Some(code)),
            (_, Some(signal)) => (ExecutionState::Failed, Some(128i32.saturating_add(signal))),
            _ => (ExecutionState::Unknown, None),
        },
        RunnerState::Cancelled => (ExecutionState::Cancelled, None),
        RunnerState::TimedOut => (ExecutionState::TimedOut, None),
        RunnerState::Unknown => (ExecutionState::Unknown, None),
    };

    RunnerOutcome {
        state,
        exit_code,
        reason,
    }
}

/// Clamp a runner-supplied reason to something that may be persisted.
///
/// The reason is the ONE value that crosses from inside a tenant's container
/// into a Kubernetes object. A runner that is old, broken, or replaced could
/// put anything here — a path, an error message, a line of the command's own
/// output — and object status is readable by anyone with `get` on the type,
/// replicated to every etcd member, and included in backups. So anything
/// outside the closed vocabulary is replaced rather than truncated: a
/// truncated secret is still a secret.
pub fn bounded_reason(reason: &str) -> String {
    let recognised = !reason.is_empty()
        && reason.len() <= 64
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_');
    if recognised {
        reason.to_string()
    } else {
        "runner_reason_unrecognised".to_string()
    }
}

/// The request Kobe writes to the runner's stdin.
pub fn start_request(
    id: &str,
    argv: &[String],
    cwd: Option<&str>,
    timeout: std::time::Duration,
    request_digest: Option<&str>,
) -> StartRequest {
    StartRequest {
        protocol: PROTOCOL_VERSION,
        id: id.to_string(),
        request_digest: request_digest.map(str::to_string),
        argv: argv.to_vec(),
        cwd: cwd.map(str::to_string),
        // Rounded up, never down: a request for one and a half seconds that
        // became one would kill a command before its own bound elapsed.
        timeout_seconds: (timeout.as_secs() + u64::from(timeout.subsec_nanos() > 0)).max(1),
        max_output_bytes: crate::api::sandbox_executions::EXECUTION_OUTPUT_RETENTION_BYTES,
    }
}

/// One line, because the runner reads one line.
pub fn start_line(request: &StartRequest) -> Result<Vec<u8>, RunnerCallFailure> {
    let mut line = serde_json::to_vec(request).map_err(|_| RunnerCallFailure::Unreadable)?;
    line.push(b'\n');
    if line.len() > MAX_REQUEST_BYTES {
        return Err(RunnerCallFailure::Refused(RunnerErrorCode::InvalidRequest));
    }
    Ok(line)
}

/// The argv of one control call.
///
/// Everything here is either a fixed word, the administrator's runner path, or
/// Kobe's own derived execution id. Nothing a caller supplied ever appears —
/// this argv becomes a URL in the target apiserver's audit log.
pub fn control_argv(runner_path: &str, verb: &str, id: &str, extra: &[String]) -> Vec<String> {
    let mut argv = vec![
        runner_path.to_string(),
        verb.to_string(),
        "--id".to_string(),
        id.to_string(),
    ];
    argv.extend_from_slice(extra);
    argv
}

/// Administrator-selected target-side boundary for the #82 live gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartCrashWindow {
    BeforeSpawn,
    AfterSpawnBeforeAcknowledgement,
}

fn start_argv(runner_path: &str, crash: Option<StartCrashWindow>) -> Vec<String> {
    let mut argv = vec![runner_path.to_string(), "start".to_string()];
    if let Some(crash) = crash {
        // A fixed administrator-selected flag, never caller input. It asks the
        // runner to disappear at one exact reserve/spawn boundary before it
        // writes the acknowledgement Kobe would otherwise parse.
        argv.push(
            match crash {
                StartCrashWindow::BeforeSpawn => TEST_EXIT_BEFORE_SPAWN_FLAG,
                StartCrashWindow::AfterSpawnBeforeAcknowledgement => {
                    TEST_EXIT_AFTER_SPAWN_BEFORE_ACK_FLAG
                }
            }
            .to_string(),
        );
    }
    argv
}

/// Read exactly one reply.
///
/// A reply from another protocol version is refused rather than parsed on a
/// best-effort basis. A Sandbox image is built by an administrator and can be
/// months older than the Kobe talking to it, and guessing at an older shape is
/// how "running" gets read as "succeeded".
pub fn parse_reply(stdout: &[u8]) -> Result<Reply, RunnerCallFailure> {
    let text = std::str::from_utf8(stdout).map_err(|_| RunnerCallFailure::Unreadable)?;
    // The last non-empty line: a well-behaved runner prints one document and
    // nothing else, but a container's `ENTRYPOINT` wrapper or a libc warning can
    // still land on stdout ahead of it, and losing an entire outcome to somebody
    // else's banner would be a poor trade.
    let line = text
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .ok_or(RunnerCallFailure::Unreachable)?;

    let envelope: Envelope =
        serde_json::from_str(line).map_err(|_| RunnerCallFailure::Unreadable)?;
    if envelope.protocol != PROTOCOL_VERSION {
        return Err(RunnerCallFailure::Unreadable);
    }
    match envelope.reply {
        Reply::Error { code } => Err(RunnerCallFailure::Refused(code)),
        reply => Ok(reply),
    }
}

#[derive(Clone, Copy)]
enum ExpectedReportReply {
    Started,
    State,
}

fn report_from(
    reply: Reply,
    expected: ExpectedReportReply,
    expected_id: &str,
) -> Result<ExecutionReport, RunnerCallFailure> {
    let report = match (expected, reply) {
        (ExpectedReportReply::Started, Reply::Started { report })
        | (ExpectedReportReply::State, Reply::State { report }) => report,
        _ => return Err(RunnerCallFailure::Unreadable),
    };
    if report.id != expected_id {
        return Err(RunnerCallFailure::Unreadable);
    }
    Ok(report)
}

/// Start one command, and return once it is supervised — not once it is done.
///
/// Idempotent on both sides of the boundary: Kobe has already reserved the id
/// durably, and the runner refuses to spawn a second process for an id it has
/// seen. A retry of this call after a lost reply reports the original.
pub async fn start(
    client: &kube::Client,
    target: &SandboxTarget,
    container: &str,
    runner_path: &str,
    request: &StartRequest,
    crash: Option<StartCrashWindow>,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<ExecutionReport, RunnerCallFailure> {
    let line = start_line(request)?;
    let argv = start_argv(runner_path, crash);
    let output = call(
        client,
        target,
        container,
        &argv,
        Some(&line),
        RUNNER_CALL_TIMEOUT,
        shutdown,
    )
    .await?;
    report_from(
        parse_reply(&output)?,
        ExpectedReportReply::Started,
        &request.id,
    )
}

/// Ask what one execution is doing.
pub async fn poll(
    client: &kube::Client,
    target: &SandboxTarget,
    container: &str,
    runner_path: &str,
    id: &str,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<ExecutionReport, RunnerCallFailure> {
    let output = call(
        client,
        target,
        container,
        &control_argv(runner_path, "status", id, &[]),
        None,
        RUNNER_CALL_TIMEOUT,
        shutdown,
    )
    .await?;
    report_from(parse_reply(&output)?, ExpectedReportReply::State, id)
}

/// Terminate one execution's process group.
pub async fn cancel(
    client: &kube::Client,
    target: &SandboxTarget,
    container: &str,
    runner_path: &str,
    id: &str,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<ExecutionReport, RunnerCallFailure> {
    let output = call(
        client,
        target,
        container,
        &control_argv(runner_path, "cancel", id, &[]),
        None,
        RUNNER_CANCEL_TIMEOUT,
        shutdown,
    )
    .await?;
    report_from(parse_reply(&output)?, ExpectedReportReply::State, id)
}

/// Read one bounded window of one stream.
#[allow(clippy::too_many_arguments)]
pub async fn read_output(
    client: &kube::Client,
    target: &SandboxTarget,
    container: &str,
    runner_path: &str,
    id: &str,
    stream: LogStream,
    offset: u64,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<RunnerLogChunk, RunnerCallFailure> {
    let stream_name = match stream {
        LogStream::Stdout => "stdout",
        LogStream::Stderr => "stderr",
    };
    let output = call(
        client,
        target,
        container,
        &control_argv(
            runner_path,
            "logs",
            id,
            &[
                "--stream".into(),
                stream_name.into(),
                "--offset".into(),
                offset.to_string(),
                "--max-bytes".into(),
                MAX_LOG_CHUNK_BYTES.to_string(),
            ],
        ),
        None,
        RUNNER_CALL_TIMEOUT,
        shutdown,
    )
    .await?;
    match parse_reply(&output)? {
        Reply::Logs { chunk } => validate_log_chunk(*chunk, id, stream, offset),
        _ => Err(RunnerCallFailure::Unreadable),
    }
}

fn validate_log_chunk(
    chunk: kobe_runner::protocol::LogChunk,
    expected_id: &str,
    expected_stream: LogStream,
    expected_offset: u64,
) -> Result<RunnerLogChunk, RunnerCallFailure> {
    use base64::Engine;

    if chunk.id != expected_id || chunk.stream != expected_stream || chunk.offset != expected_offset
    {
        return Err(RunnerCallFailure::Unreadable);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&chunk.data_base64)
        .map_err(|_| RunnerCallFailure::Unreadable)?;
    if bytes.len() > MAX_LOG_CHUNK_BYTES
        || chunk.next_offset
            != chunk
                .offset
                .checked_add(bytes.len() as u64)
                .ok_or(RunnerCallFailure::Unreadable)?
        || (chunk.more && bytes.is_empty())
    {
        return Err(RunnerCallFailure::Unreadable);
    }
    Ok(RunnerLogChunk {
        offset: chunk.offset,
        next_offset: chunk.next_offset,
        bytes,
        truncated: chunk.truncated,
        more: chunk.more,
    })
}

/// Read both retained streams to the API response cap.
///
/// Streams are fetched concurrently and by monotonically advancing offsets.
/// A broken runner that repeats an offset is refused rather than allowed to
/// spin forever, and output beyond Kobe's response cap is reported as
/// truncated even if the runner retained more on disk.
pub async fn read_wait_output(
    client: &kube::Client,
    target: &SandboxTarget,
    container: &str,
    runner_path: &str,
    id: &str,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<RunnerOutput, RunnerCallFailure> {
    let stdout = read_stream_to_cap(
        client,
        target,
        container,
        runner_path,
        id,
        LogStream::Stdout,
        shutdown,
    );
    let stderr = read_stream_to_cap(
        client,
        target,
        container,
        runner_path,
        id,
        LogStream::Stderr,
        shutdown,
    );
    let (stdout, stderr) = tokio::join!(stdout, stderr);
    let (stdout, stdout_truncated) = stdout?;
    let (stderr, stderr_truncated) = stderr?;
    Ok(RunnerOutput {
        stdout,
        stderr,
        truncated: stdout_truncated || stderr_truncated,
    })
}

async fn read_stream_to_cap(
    client: &kube::Client,
    target: &SandboxTarget,
    container: &str,
    runner_path: &str,
    id: &str,
    stream: LogStream,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<(Vec<u8>, bool), RunnerCallFailure> {
    let mut offset = 0;
    let mut output = Vec::new();
    let mut truncated = false;
    loop {
        let chunk = read_output(
            client,
            target,
            container,
            runner_path,
            id,
            stream,
            offset,
            shutdown,
        )
        .await?;

        let remaining =
            crate::api::sandbox_access::MAX_EXEC_OUTPUT_BYTES.saturating_sub(output.len());
        let kept = chunk.bytes.len().min(remaining);
        output.extend_from_slice(&chunk.bytes[..kept]);
        truncated |= chunk.truncated || kept < chunk.bytes.len();
        if output.len() == crate::api::sandbox_access::MAX_EXEC_OUTPUT_BYTES {
            truncated |= chunk.more;
            break;
        }
        if !chunk.more {
            break;
        }
        if chunk.next_offset == offset {
            return Err(RunnerCallFailure::Unreadable);
        }
        offset = chunk.next_offset;
    }
    Ok((output, truncated))
}

/// One exec against the runner.
///
/// A truncated reply is `Unreadable` rather than an attempt at partial JSON,
/// and a denial from the resolver is `Unreachable` — from Kobe's side those are
/// the same fact: nobody can currently say what the command is doing.
async fn call(
    client: &kube::Client,
    target: &SandboxTarget,
    container: &str,
    argv: &[String],
    stdin: Option<&[u8]>,
    timeout: std::time::Duration,
    shutdown: &tokio_util::sync::CancellationToken,
) -> Result<Vec<u8>, RunnerCallFailure> {
    let deadline = tokio::time::Instant::now() + timeout;
    let raw = exec_capped_until(
        client,
        target,
        container,
        argv,
        stdin,
        deadline,
        shutdown,
        RUNNER_REPLY_CAP,
    )
    .await
    .map_err(|denied| match denied {
        // Kept as one failure on purpose: the caller must not be able to tell a
        // replaced Pod from an unreachable one by probing an execution.
        SandboxAccessDenied::NotDeclared { .. } => RunnerCallFailure::Unreadable,
        _ => RunnerCallFailure::Unreachable,
    })?;
    if raw.truncated {
        return Err(RunnerCallFailure::Unreadable);
    }
    if raw.stdout.is_empty() {
        // The exec succeeded and the runner said nothing. That is not an
        // outcome; it is the absence of one.
        return Err(RunnerCallFailure::Unreachable);
    }
    Ok(raw.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(state: RunnerState) -> ExecutionReport {
        ExecutionReport {
            id: "sbxe-1".into(),
            state,
            reason: Some("completed".into()),
            ..Default::default()
        }
    }

    /// Nothing a caller supplied ever becomes an exec argument.
    ///
    /// An exec's argv is a URL, recorded verbatim by the target apiserver's
    /// audit log. A tenant's command line routinely carries secrets — a token
    /// in a flag, a connection string in an argument — and that log belongs to
    /// somebody who cannot redact it.
    #[test]
    fn a_control_call_carries_no_caller_supplied_data() {
        let argv = control_argv("/kobe-runner", "status", "sbxe-abc123", &[]);
        assert_eq!(
            argv,
            vec!["/kobe-runner", "status", "--id", "sbxe-abc123"],
            "a control call is a fixed verb and a derived id"
        );

        let request = start_request(
            "sbxe-abc123",
            &["/agent".into(), "--token".into(), "s3cret".into()],
            Some("/work"),
            std::time::Duration::from_secs(60),
            None,
        );
        let line = String::from_utf8(start_line(&request).unwrap()).unwrap();
        assert!(line.contains("s3cret"), "the command travels on stdin");
        assert!(line.ends_with('\n'), "the runner reads exactly one line");

        // The start call's own argv is two fixed words. Nothing else.
        assert_eq!(start_argv("/kobe-runner", None), ["/kobe-runner", "start"]);
        assert_eq!(
            start_argv("/kobe-runner", Some(StartCrashWindow::BeforeSpawn)),
            ["/kobe-runner", "start", TEST_EXIT_BEFORE_SPAWN_FLAG]
        );
        assert_eq!(
            start_argv(
                "/kobe-runner",
                Some(StartCrashWindow::AfterSpawnBeforeAcknowledgement)
            ),
            [
                "/kobe-runner",
                "start",
                TEST_EXIT_AFTER_SPAWN_BEFORE_ACK_FLAG
            ]
        );
        // And no reading of the request may be spliced into an argument.
        for argument in control_argv("/kobe-runner", "status", "sbxe-abc123", &[]) {
            assert!(!argument.contains("s3cret"));
            assert!(
                !argument.contains(';') && !argument.contains('&') && !argument.contains('|'),
                "{argument} looks like a shell fragment"
            );
        }
    }

    /// A reply Kobe cannot read never becomes an outcome.
    ///
    /// Every one of these inputs is a way to be told nothing. Parsing any of
    /// them optimistically would put a state in front of a caller that nothing
    /// inside the container ever asserted.
    #[test]
    fn an_unreadable_reply_is_never_read_as_an_outcome() {
        let good = serde_json::to_vec(&Envelope::new(Reply::State {
            report: report(RunnerState::Succeeded),
        }))
        .unwrap();
        assert!(parse_reply(&good).is_ok());

        // Another protocol version is refused outright, however well-formed.
        let future =
            br#"{"protocol":2,"reply":"state","report":{"id":"sbxe-1","state":"succeeded"}}"#;
        assert_eq!(
            parse_reply(future).unwrap_err(),
            RunnerCallFailure::Unreadable
        );

        for unreadable in [
            &b""[..],
            b"   ",
            b"not json",
            b"{\"protocol\":1}",
            // Truncated mid-document: the shape of a capped read.
            b"{\"protocol\":1,\"reply\":\"state\",\"report\":{\"id\"",
            b"{\"protocol\":\"1\",\"reply\":\"state\",\"report\":{}}",
        ] {
            assert!(
                parse_reply(unreadable).is_err(),
                "{:?} must not parse",
                String::from_utf8_lossy(unreadable)
            );
        }

        // A banner ahead of the reply does not cost the outcome.
        let mut noisy = b"WARNING: locale not set\n".to_vec();
        noisy.extend_from_slice(&good);
        assert!(parse_reply(&noisy).is_ok());
    }

    /// A well-formed reply for the wrong verb or execution is still hostile.
    #[test]
    fn reports_are_bound_to_the_exact_verb_and_execution_id() {
        let exact = report(RunnerState::Running);
        assert!(
            report_from(
                Reply::Started {
                    report: exact.clone()
                },
                ExpectedReportReply::Started,
                "sbxe-1",
            )
            .is_ok()
        );
        assert_eq!(
            report_from(
                Reply::State {
                    report: exact.clone()
                },
                ExpectedReportReply::Started,
                "sbxe-1",
            )
            .unwrap_err(),
            RunnerCallFailure::Unreadable,
            "status must not acknowledge start"
        );
        assert_eq!(
            report_from(
                Reply::State { report: exact },
                ExpectedReportReply::State,
                "sbxe-another",
            )
            .unwrap_err(),
            RunnerCallFailure::Unreadable,
            "one spool id must never answer for another"
        );
    }

    /// Log bytes are accepted only with exact identity, stream, and offsets.
    #[test]
    fn log_chunks_reject_identity_offset_and_encoding_drift() {
        use base64::Engine;
        use kobe_runner::protocol::LogChunk;

        let exact = LogChunk {
            id: "sbxe-1".into(),
            stream: LogStream::Stdout,
            offset: 7,
            next_offset: 10,
            data_base64: base64::engine::general_purpose::STANDARD.encode(b"abc"),
            truncated: false,
            more: false,
        };
        assert_eq!(
            validate_log_chunk(exact.clone(), "sbxe-1", LogStream::Stdout, 7)
                .unwrap()
                .bytes,
            b"abc"
        );

        let mut hostile = Vec::new();
        let mut wrong_id = exact.clone();
        wrong_id.id = "sbxe-2".into();
        hostile.push(wrong_id);
        let mut wrong_stream = exact.clone();
        wrong_stream.stream = LogStream::Stderr;
        hostile.push(wrong_stream);
        let mut wrong_offset = exact.clone();
        wrong_offset.offset = 8;
        hostile.push(wrong_offset);
        let mut wrong_next = exact.clone();
        wrong_next.next_offset = 11;
        hostile.push(wrong_next);
        let mut malformed = exact.clone();
        malformed.data_base64 = "%%%".into();
        hostile.push(malformed);
        let mut no_progress = exact.clone();
        no_progress.data_base64.clear();
        no_progress.next_offset = no_progress.offset;
        no_progress.more = true;
        hostile.push(no_progress);
        let mut oversized = exact;
        oversized.data_base64 =
            base64::engine::general_purpose::STANDARD.encode(vec![b'x'; MAX_LOG_CHUNK_BYTES + 1]);
        oversized.next_offset = oversized.offset + MAX_LOG_CHUNK_BYTES as u64 + 1;
        hostile.push(oversized);

        for chunk in hostile {
            assert_eq!(
                validate_log_chunk(chunk, "sbxe-1", LogStream::Stdout, 7).unwrap_err(),
                RunnerCallFailure::Unreadable
            );
        }
    }

    /// Kobe and the runner share the exact encoded request ceiling.
    #[test]
    fn start_request_bound_includes_the_newline() {
        let mut request = start_request(
            "sbxe-1",
            &[String::new()],
            None,
            std::time::Duration::from_secs(1),
            None,
        );
        let base = start_line(&request).unwrap().len();
        request.argv[0] = "x".repeat(MAX_REQUEST_BYTES - base);
        assert_eq!(start_line(&request).unwrap().len(), MAX_REQUEST_BYTES);
        request.argv[0].push('x');
        assert_eq!(
            start_line(&request).unwrap_err(),
            RunnerCallFailure::Refused(RunnerErrorCode::InvalidRequest)
        );
    }

    /// A refusal is a refusal, not an outcome.
    ///
    /// `NotFound` from the runner means the container has no record of an
    /// execution Kobe reserved. Reading that as a result would let a Pod that
    /// restarted answer for a command it never ran.
    #[test]
    fn a_refusal_is_reported_as_one() {
        for (code, expected) in [
            (RunnerErrorCode::NotFound, "runner_forgot_execution"),
            (RunnerErrorCode::Conflict, "runner_id_conflict"),
            (RunnerErrorCode::InvalidRequest, "runner_rejected_request"),
            (RunnerErrorCode::Internal, "runner_internal_error"),
        ] {
            let encoded = serde_json::to_vec(&Envelope::new(Reply::Error { code })).unwrap();
            assert_eq!(
                parse_reply(&encoded).unwrap_err(),
                RunnerCallFailure::Refused(code)
            );
            assert_eq!(
                RunnerCallFailure::Refused(code).reason_code(),
                expected,
                "an operator has to be able to tell these apart"
            );
        }
    }

    /// No failure to reach the runner is ever a 500 or a success.
    ///
    /// A 500 invites a retry, and a retry of an execution that may already have
    /// run is the exact damage the reserve-then-spawn design exists to prevent.
    #[test]
    fn a_runner_failure_never_invites_a_blind_retry() {
        use axum::http::StatusCode;
        for failure in [
            RunnerCallFailure::Unreachable,
            RunnerCallFailure::Unreadable,
            RunnerCallFailure::Refused(RunnerErrorCode::NotFound),
            RunnerCallFailure::Refused(RunnerErrorCode::Conflict),
            RunnerCallFailure::Refused(RunnerErrorCode::Internal),
        ] {
            let status = failure.http_status();
            assert!(!status.is_success(), "{failure} must not read as a success");
            assert_ne!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{failure} is not Kobe being broken"
            );
            assert!(!failure.reason_code().is_empty());
            assert!(failure.reason_code().len() <= 64);
        }
    }

    /// An outcome nobody observed is `Unknown`, never `Failed` or `Succeeded`.
    ///
    /// `Failed` reads as "it ran and said no", which tells a caller their retry
    /// is safe. `Succeeded` is simply a lie. `Unknown` is the state that makes
    /// the decision theirs — which is the correct amount of work to impose when
    /// the truth is that nobody knows.
    #[test]
    fn an_unobserved_outcome_is_unknown() {
        assert_eq!(
            outcome_from_report(&report(RunnerState::Unknown)).state,
            ExecutionState::Unknown
        );

        // A success with no exit code contradicts itself: nothing observed a
        // number, so nothing may claim the command completed.
        let hollow = ExecutionReport {
            exit_code: None,
            ..report(RunnerState::Succeeded)
        };
        assert_eq!(
            outcome_from_report(&hollow).state,
            ExecutionState::Unknown,
            "a success nobody backed with a code is a claim, not an observation"
        );
        assert_eq!(outcome_from_report(&hollow).exit_code, None);

        // As does a failure with neither a code nor a signal.
        let empty = report(RunnerState::Failed);
        assert_eq!(outcome_from_report(&empty).state, ExecutionState::Unknown);
        assert_eq!(outcome_from_report(&empty).exit_code, None);
    }

    /// An exit code reaches the record exactly as the process gave it.
    ///
    /// A caller's failing test must look like a failing test and not like an
    /// infrastructure fault — and a synthesised zero would be indistinguishable
    /// from a real success.
    #[test]
    fn an_exit_code_survives_the_translation_unchanged() {
        let succeeded = ExecutionReport {
            exit_code: Some(0),
            ..report(RunnerState::Succeeded)
        };
        let outcome = outcome_from_report(&succeeded);
        assert_eq!(outcome.state, ExecutionState::Succeeded);
        assert_eq!(outcome.exit_code, Some(0));

        for code in [1, 2, 127, 255] {
            let failed = ExecutionReport {
                exit_code: Some(code),
                ..report(RunnerState::Failed)
            };
            let outcome = outcome_from_report(&failed);
            assert_eq!(outcome.state, ExecutionState::Failed, "exit {code}");
            assert_eq!(outcome.exit_code, Some(code));
        }
    }

    /// A killed command is distinguishable from one that chose to exit.
    ///
    /// An OOM kill definitely ran and definitely did not finish, so it is a
    /// failure rather than an unknown. The status field requires a code, so it
    /// carries the POSIX `128 + signal` convention — and `reason = signalled`
    /// is what keeps it from being read as a command that deliberately exited
    /// 137.
    #[test]
    fn a_signalled_command_is_a_failure_that_still_says_it_was_signalled() {
        let killed = ExecutionReport {
            exit_code: None,
            signal: Some(9),
            reason: Some("signalled".into()),
            ..report(RunnerState::Failed)
        };
        let outcome = outcome_from_report(&killed);
        assert_eq!(outcome.state, ExecutionState::Failed);
        assert_eq!(outcome.exit_code, Some(137));
        assert_eq!(
            outcome.reason, "signalled",
            "the record must say the code was not chosen"
        );
    }

    /// Cancelled and timed-out carry no exit code at all.
    ///
    /// Neither process chose an outcome; the runner imposed one. A code here
    /// would assert something nobody observed — and the CRD refuses it for
    /// exactly that reason.
    #[test]
    fn an_imposed_ending_carries_no_exit_code() {
        for (runner_state, expected) in [
            (RunnerState::Cancelled, ExecutionState::Cancelled),
            (RunnerState::TimedOut, ExecutionState::TimedOut),
        ] {
            let outcome = outcome_from_report(&ExecutionReport {
                exit_code: Some(0),
                signal: Some(9),
                ..report(runner_state)
            });
            assert_eq!(outcome.state, expected);
            assert_eq!(
                outcome.exit_code, None,
                "{expected} must not carry an exit code"
            );
        }
    }

    /// Nothing from inside the container reaches a Kubernetes object unbounded.
    ///
    /// The reason is the one value that crosses that boundary. A runner that is
    /// old, broken, or replaced could put a path, an error message, or a line
    /// of the command's own output there — and object status is readable by
    /// anyone with `get`, replicated to every etcd member, and in every backup.
    #[test]
    fn a_runner_reason_can_never_reach_the_record_unbounded() {
        assert_eq!(bounded_reason("completed"), "completed");
        assert_eq!(bounded_reason("cancelled_by_caller"), "cancelled_by_caller");

        for hostile in [
            "",
            "Bearer eyJhbGciOi",
            "failed to open /home/agent/.aws/credentials",
            "postgres://user:password@host/db",
            &"x".repeat(65),
            "completed\nAWS_SECRET=1",
            "réussi",
        ] {
            assert_eq!(
                bounded_reason(hostile),
                "runner_reason_unrecognised",
                "reason {hostile:?} must not be persisted"
            );
        }

        // Every reason the record can carry fits the status field's own bound.
        for state in [
            RunnerState::Running,
            RunnerState::Succeeded,
            RunnerState::Failed,
            RunnerState::Cancelled,
            RunnerState::TimedOut,
            RunnerState::Unknown,
        ] {
            let outcome = outcome_from_report(&report(state));
            assert!(outcome.reason.len() <= 64);
        }
    }

    /// A command's own bound is never rounded down.
    ///
    /// A request for 1.5 seconds that became 1 would have the runner kill a
    /// command before its own deadline, and the caller would read `TimedOut`
    /// for a command that still had time.
    #[test]
    fn a_timeout_is_never_rounded_down() {
        let seconds = |timeout: std::time::Duration| {
            start_request("sbxe-1", &["/agent".into()], None, timeout, None).timeout_seconds
        };

        assert_eq!(seconds(std::time::Duration::from_secs(60)), 60);
        assert_eq!(seconds(std::time::Duration::from_millis(1500)), 2);
        // A bound below one second still has to be at least one: zero is not a
        // timeout, it is a command that can never succeed.
        assert_eq!(seconds(std::time::Duration::from_millis(1)), 1);
        assert_eq!(seconds(std::time::Duration::ZERO), 1);
    }

    /// The retention the runner is asked for is Kobe's decision, not the
    /// caller's.
    ///
    /// The spool sits on the ephemeral disk the whole Pod shares. A cap a
    /// caller could choose is a way to fill it from inside a sandbox that
    /// exists precisely because its occupant is not trusted.
    #[test]
    fn retention_is_bounded_by_kobe_rather_than_by_the_caller() {
        let request = start_request(
            "sbxe-1",
            &["/agent".into()],
            None,
            std::time::Duration::from_secs(60),
            None,
        );
        assert_eq!(
            request.max_output_bytes,
            crate::api::sandbox_executions::EXECUTION_OUTPUT_RETENTION_BYTES
        );
        assert!(request.max_output_bytes <= kobe_runner::protocol::MAX_RETENTION_BYTES);
    }
}
