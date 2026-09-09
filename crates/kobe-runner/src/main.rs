//! `kobe-runner` — the supervisor Kobe drives inside a Sandbox container.
//!
//! # The whole interface
//!
//! ```text
//! kobe-runner start                  # request on stdin, reply on stdout
//! kobe-runner status --id ID
//! kobe-runner logs   --id ID --stream stdout --offset N
//! kobe-runner cancel --id ID
//! ```
//!
//! Every invocation is a short-lived process started by one exec, prints
//! exactly one JSON reply on stdout, and exits. Nothing here listens on a
//! socket: a port would be reachable by the tenant's own workload, would need
//! its own authentication, and would have to be declared by the pool before
//! anybody could reach it. Exec is already fenced to one lease, one Pod UID and
//! one container by the time Kobe gets here, and each call is re-authorised.
//!
//! # Why the request arrives on stdin
//!
//! An exec's argv is a URL. The target apiserver audit-logs it verbatim, and a
//! tenant's command line routinely carries secrets. Only the execution id — a
//! hash Kobe derived — ever appears as an argument; the command itself travels
//! on stdin, which nothing on the path records. It is one line, so the runner
//! never has to wait for an EOF that the exec transport may never deliver.
//!
//! The request may carry the supervised process's own stdin for the same
//! reason. A command that reads a credential — `gh auth login --with-token` —
//! could otherwise only be given one in a flag, which is precisely the argv
//! this design exists to keep secrets out of. Those bytes are never written to
//! the spool: `start` hands them to the supervisor over a pipe and only their
//! length appears in an argument.

use std::io::BufRead;

use clap::{Parser, Subcommand};

use kobe_runner::protocol::{
    Envelope, ExecutionReport, LogStream, MAX_LOG_CHUNK_BYTES, MAX_REQUEST_BYTES,
    MAX_RETENTION_BYTES, MAX_TIMEOUT_SECONDS, PROTOCOL_VERSION, Reply, RunnerErrorCode,
    RunnerState, StartRequest, TEST_EXECUTION_CRASH_EXIT_CODE, is_valid_id, reason,
};
use kobe_runner::spool::{self, Reservation, Spool, SpoolError};
#[cfg(unix)]
use kobe_runner::supervisor;

#[derive(Parser)]
#[command(name = "kobe-runner", about = "Supervise one Kobe Sandbox execution")]
struct Cli {
    /// Where executions are spooled. Kobe never names a path inside somebody
    /// else's container and never treats this workload-writable path as
    /// security authority.
    #[arg(long, default_value = spool::DEFAULT_STATE_DIR, global = true)]
    state_dir: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Reserve an id and supervise its command. The request is read from stdin.
    Start {
        /// Administrator-driven #82 conformance crashpoint.
        #[arg(long, hide = true, conflicts_with = "test_exit_after_spawn_before_ack")]
        test_exit_before_spawn: bool,
        /// Administrator-driven #82 conformance crashpoint.
        #[arg(long, hide = true, conflicts_with = "test_exit_before_spawn")]
        test_exit_after_spawn_before_ack: bool,
    },
    /// Run the supervision loop. Started by `start`, never by Kobe.
    #[command(hide = true)]
    Supervise {
        #[arg(long)]
        id: String,
        /// How many bytes of the command's stdin are waiting on this process's
        /// own stdin.
        ///
        /// A count, never the bytes: the count is all the supervisor needs, and
        /// a count is not a secret. (This argv is an internal re-exec inside
        /// the container, so it never reaches the apiserver's audit log either
        /// way.) Absent means the command reads `/dev/null`, exactly as it did
        /// before stdin forwarding existed — which is also what keeps a
        /// `supervise` run by hand from blocking on a terminal.
        #[arg(long)]
        stdin_bytes: Option<usize>,
    },
    /// Report what one execution is doing.
    Status {
        #[arg(long)]
        id: String,
    },
    /// Read one bounded window of one stream.
    Logs {
        #[arg(long)]
        id: String,
        #[arg(long)]
        stream: String,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long, default_value_t = MAX_LOG_CHUNK_BYTES as u64)]
        max_bytes: u64,
    },
    /// Terminate the execution's process group.
    Cancel {
        #[arg(long)]
        id: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let spool = Spool::new(&cli.state_dir);

    // `supervise` is the one subcommand that is not a request/response: it IS
    // the long-lived process, and it prints nothing because nobody is reading.
    if let Commands::Supervise { id, stdin_bytes } = &cli.command {
        #[cfg(unix)]
        supervisor::supervise(&spool, id, *stdin_bytes, std::io::stdin());
        return;
    }

    let reply = match &cli.command {
        Commands::Start {
            test_exit_before_spawn,
            test_exit_after_spawn_before_ack,
        } => start(
            &spool,
            &cli.state_dir,
            *test_exit_before_spawn,
            *test_exit_after_spawn_before_ack,
        ),
        Commands::Status { id } => status(&spool, id),
        Commands::Logs {
            id,
            stream,
            offset,
            max_bytes,
        } => logs(&spool, id, stream, *offset, *max_bytes),
        Commands::Cancel { id } => cancel(&spool, id),
        Commands::Supervise { .. } => unreachable!("handled above"),
    };

    // Exactly one document, on stdout, and nothing else — diagnostics go to
    // stderr precisely so a stray line can never turn a reply into a parse
    // failure that Kobe has to read as `Unknown`.
    let failed = matches!(reply, Reply::Error { .. });
    println!(
        "{}",
        serde_json::to_string(&Envelope::new(reply))
            .unwrap_or_else(|_| r#"{"protocol":1,"reply":"error","code":"internal"}"#.into())
    );
    if failed {
        // The reply is what Kobe decides on; this only makes a failure visible
        // to a human running the binary by hand.
        std::process::exit(1);
    }
}

fn error(code: RunnerErrorCode) -> Reply {
    Reply::Error { code }
}

/// Reserve an id and start supervising it.
///
/// Reservation happens before the supervisor exists, and the supervisor is
/// spawned exactly once per intact reservation. A retry that finds the same
/// reservation reports it and spawns nothing. Kobe itself never retries this
/// verb after its Running checkpoint because the workload can remove the spool.
fn start(
    spool: &Spool,
    state_dir: &str,
    exit_before_spawn: bool,
    exit_after_spawn_before_ack: bool,
) -> Reply {
    // One line, not "until EOF". The request arrives over an exec connection
    // whose write half Kobe cannot reliably half-close, so waiting for EOF is
    // waiting for something that may never come — and the command would not
    // start until the timeout fired. JSON never contains a raw newline, so a
    // line IS the document.
    let Ok(request) = read_start_request(std::io::stdin()) else {
        return error(RunnerErrorCode::InvalidRequest);
    };
    if let Err(code) = validate(&request) {
        return error(code);
    }
    // Decoded before anything is reserved, and held only in memory from here
    // on. `validate` has already proved this succeeds; re-deriving the failure
    // rather than defaulting to "no stdin" is deliberate, because silently
    // dropping the bytes would start the command with an empty stdin and then
    // report success.
    let stdin = match request.stdin_bytes() {
        Ok(stdin) => stdin,
        Err(_) => return error(RunnerErrorCode::InvalidRequest),
    };

    match spool.reserve(&request) {
        Ok(Reservation::Created(_start_reservation)) => {
            if exit_before_spawn {
                // The target-side reservation and its exclusive starter lock
                // are durable, but no spawn intent exists. Hard exit releases
                // the lock, so a retry can settle this exact record Unknown
                // without ever manufacturing the command.
                std::process::exit(TEST_EXECUTION_CRASH_EXIT_CODE);
            }
            match spawn_supervisor(state_dir, &request.id, stdin.as_deref()) {
                Ok(()) if exit_after_spawn_before_ack => {
                    // The reservation and supervisor are both durable, but no
                    // reply is written. Kobe must settle the lost
                    // acknowledgement as Unknown and must never spawn again.
                    std::process::exit(TEST_EXECUTION_CRASH_EXIT_CODE);
                }
                Ok(()) => {}
                Err(_) => {
                    // Nothing was started, but this process cannot prove that
                    // to Kobe in a way it could distinguish from a lost reply —
                    // so the execution settles as the state that never invites
                    // a blind retry.
                    let _ = spool.write_report(&ExecutionReport {
                        id: request.id.clone(),
                        state: RunnerState::Unknown,
                        finished_at_unix_ms: Some(spool::now_unix_ms()),
                        reason: Some(reason::SUPERVISOR_NOT_STARTED.into()),
                        ..Default::default()
                    });
                }
            }
        }
        Ok(Reservation::AlreadyReserved) => {}
        Err(SpoolError::Conflict(_)) => return error(RunnerErrorCode::Conflict),
        Err(_) => return error(RunnerErrorCode::Internal),
    }

    match reconcile(spool, &request.id) {
        Ok(report) => Reply::Started { report },
        Err(code) => error(code),
    }
}

fn read_start_request(reader: impl std::io::Read) -> Result<StartRequest, RunnerErrorCode> {
    let mut raw = Vec::new();
    if std::io::BufReader::new(reader.take((MAX_REQUEST_BYTES + 1) as u64))
        .read_until(b'\n', &mut raw)
        .is_err()
        || raw.len() > MAX_REQUEST_BYTES
        || !raw.ends_with(b"\n")
    {
        return Err(RunnerErrorCode::InvalidRequest);
    }
    serde_json::from_slice(&raw).map_err(|_| RunnerErrorCode::InvalidRequest)
}

/// Refuse a request that could never run, before anything is reserved.
///
/// Each of these would otherwise become a reservation for a command that cannot
/// exist — a record Kobe then has to reason about on every retry.
fn validate(request: &StartRequest) -> Result<(), RunnerErrorCode> {
    if request.protocol != PROTOCOL_VERSION {
        // A Kobe from another protocol is refused rather than served on a
        // best-effort basis: the fields it means are not necessarily the fields
        // this binary reads.
        return Err(RunnerErrorCode::InvalidRequest);
    }
    if !is_valid_id(&request.id) {
        return Err(RunnerErrorCode::InvalidRequest);
    }
    if request.argv.is_empty() || request.argv.iter().any(String::is_empty) {
        return Err(RunnerErrorCode::InvalidRequest);
    }
    if request.argv.iter().any(|argument| argument.contains('\0')) {
        return Err(RunnerErrorCode::InvalidRequest);
    }
    if let Some(cwd) = &request.cwd {
        // Validated here as well as in Kobe. `chdir` with an embedded nul
        // truncates the path rather than failing, so a directory that is not
        // the one anybody named would silently become the working directory.
        if cwd.is_empty() || !cwd.starts_with('/') || cwd.contains('\0') {
            return Err(RunnerErrorCode::InvalidRequest);
        }
    }
    if request.timeout_seconds == 0 || request.timeout_seconds > MAX_TIMEOUT_SECONDS {
        return Err(RunnerErrorCode::InvalidRequest);
    }
    if request.max_output_bytes == 0 || request.max_output_bytes > MAX_RETENTION_BYTES {
        // Unbounded retention inside a tenant's container is a way to fill the
        // ephemeral disk the whole Pod shares.
        return Err(RunnerErrorCode::InvalidRequest);
    }
    if request.stdin_bytes().is_err() {
        // Refused, never truncated to fit. Half a token is still a secret, and
        // the command that received it would fail somewhere a long way from
        // the request that caused it. Checked here — before the reservation —
        // so an unusable stdin cannot spend an idempotency key.
        return Err(RunnerErrorCode::InvalidRequest);
    }
    Ok(())
}

/// Re-exec this binary as the supervisor, in a session of its own.
///
/// Re-exec rather than `fork`: forking a process that is about to allocate and
/// spawn threads is a well-known way to inherit a broken heap, and there is
/// nothing here that needs the parent's memory. The parent exits immediately
/// afterwards, so the supervisor is reparented to the container's init and
/// survives the teardown of the exec that started it — which is the entire
/// reason "detached" means anything.
///
/// The command's stdin, when it has any, is handed over through a pipe rather
/// than through the spool. That is the whole reason this feature is worth
/// having: a secret that never touches a filesystem cannot be read out of one
/// later. Only its LENGTH travels as an argument, so the supervisor can read
/// exactly that many bytes and can tell a short read — a lost secret — from a
/// caller who asked for an empty stdin.
#[cfg(unix)]
fn spawn_supervisor(state_dir: &str, id: &str, stdin: Option<&[u8]>) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let spool = Spool::new(state_dir);
    // Durable before the OS spawn boundary. If the starter later disappears
    // with neither this marker nor a supervisor pid, a retry proves the
    // command never existed. Once present, missing pid remains Unknown.
    spool
        .mark_spawn_intent(id)
        .map_err(|_| std::io::Error::other("could not persist supervisor spawn intent"))?;

    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg("--state-dir")
        .arg(state_dir)
        .arg("supervise")
        .arg("--id")
        .arg(id)
        // None of the exec's descriptors are inherited. A supervisor still
        // holding the exec's stdout would keep the connection's pipe open, and
        // the caller's client would wait for a stream that nobody is going to
        // close.
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match stdin {
        // A fresh pipe, never this process's own stdin: that descriptor belongs
        // to the exec connection, and a supervisor holding it would keep the
        // connection alive after the caller stopped reading.
        Some(stdin) => {
            command
                .arg("--stdin-bytes")
                .arg(stdin.len().to_string())
                .stdin(Stdio::piped());
        }
        None => {
            command.stdin(Stdio::null());
        }
    }

    // SAFETY: `setsid` is async-signal-safe and is the only call between fork
    // and exec. It detaches the supervisor from this process's session, so the
    // kubelet tearing down the exec cannot signal it.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;

    if let Some(stdin) = stdin {
        // Written and then closed, in that order, before this process returns.
        // The supervisor reads exactly this many bytes as its first act, so a
        // payload larger than the pipe buffer blocks here only until it is
        // drained. A failure is fatal to the spawn on purpose: the alternative
        // is a supervisor that starts the command with a truncated secret.
        let mut sink = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("the supervisor has no stdin to write"))?;
        sink.write_all(stdin)?;
        // Explicit, so the supervisor's bounded read cannot be left waiting on
        // a descriptor that only closes when this process happens to exit.
        drop(sink);
    }

    // Recorded so a later `status` or `cancel` can tell "still running" from
    // "the supervisor is gone and nobody will ever record an outcome".
    let _ = spool.write_supervisor_pid(id, child.id());
    Ok(())
}

#[cfg(not(unix))]
fn spawn_supervisor(_state_dir: &str, _id: &str, _stdin: Option<&[u8]>) -> std::io::Result<()> {
    Err(std::io::Error::other("the runner supervises only on unix"))
}

fn status(spool: &Spool, id: &str) -> Reply {
    match reconcile(spool, id) {
        Ok(report) => Reply::State { report },
        Err(code) => error(code),
    }
}

/// Report one execution, settling it if nobody is left to.
///
/// A supervisor that died — OOM-killed, or taken with the container's other
/// processes — leaves a report that says `Running` forever. Kobe's own verdict
/// deadline would eventually call that `Unknown`, but only minutes later; the
/// runner can see the supervisor is gone right now, and an `Unknown` a caller
/// can act on immediately is worth more than the same answer after a timeout.
///
/// Liveness is a pid check, which a recycled pid can defeat. It errs towards
/// "still running": the failure is a delayed `Unknown` from Kobe's deadline
/// rather than a premature one here.
fn reconcile(spool: &Spool, id: &str) -> Result<ExecutionReport, RunnerErrorCode> {
    let report = spool.read_report(id).map_err(map_error)?;
    if report.state.is_terminal() {
        return Ok(report);
    }
    let reason = match supervisor_liveness(spool, id) {
        SupervisorLiveness::Alive => return Ok(report),
        SupervisorLiveness::NeverStarted => reason::SUPERVISOR_NOT_STARTED,
        SupervisorLiveness::Lost => reason::SUPERVISOR_LOST,
    };

    let settled = ExecutionReport {
        state: RunnerState::Unknown,
        finished_at_unix_ms: Some(spool::now_unix_ms()),
        reason: Some(reason.into()),
        ..report
    };
    // The supervisor may have committed an exact terminal result after our
    // initial Running read. `write_report` re-reads under the per-execution lock
    // and returns that authoritative result instead of downgrading it.
    spool.write_report(&settled).map_err(map_error)
}

enum SupervisorLiveness {
    Alive,
    NeverStarted,
    Lost,
}

#[cfg(unix)]
fn supervisor_liveness(spool: &Spool, id: &str) -> SupervisorLiveness {
    let Some(pid) = spool.read_supervisor_pid(id) else {
        if spool.starter_active(id) {
            return SupervisorLiveness::Alive;
        }
        return if spool.spawn_was_intended(id) {
            SupervisorLiveness::Lost
        } else {
            SupervisorLiveness::NeverStarted
        };
    };
    // SAFETY: signal 0 performs the permission and existence checks without
    // delivering anything.
    if unsafe { libc::kill(pid, 0) != 0 } {
        return SupervisorLiveness::Lost;
    }
    // kill(2) still acknowledges an unreaped zombie, and no container
    // guarantees that an orphaned supervisor's parent reaps it. A zombie can
    // no longer supervise or commit a verdict, so reporting it Alive would
    // leave the execution Running forever. Where /proc is absent this keeps
    // the kill(2) answer.
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            let state = stat
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.trim_start().chars().next());
            if state == Some('Z') {
                SupervisorLiveness::Lost
            } else {
                SupervisorLiveness::Alive
            }
        }
        Err(_) => SupervisorLiveness::Alive,
    }
}

#[cfg(not(unix))]
fn supervisor_liveness(_spool: &Spool, _id: &str) -> SupervisorLiveness {
    SupervisorLiveness::Alive
}

fn logs(spool: &Spool, id: &str, stream: &str, offset: u64, max_bytes: u64) -> Reply {
    let Ok(stream) = stream.parse::<LogStream>() else {
        return error(RunnerErrorCode::InvalidRequest);
    };
    // Clamped rather than refused: a caller asking for more than one response
    // may carry wants as much as they can have, and failing the request teaches
    // them to retry in a loop.
    let max_bytes = max_bytes.clamp(1, MAX_LOG_CHUNK_BYTES as u64) as usize;

    match spool.read_chunk(id, stream, offset, max_bytes) {
        Ok(chunk) => Reply::Logs {
            chunk: Box::new(chunk),
        },
        Err(error_) => error(map_error(error_)),
    }
}

/// Terminate one execution's process group and report where it ended up.
///
/// The kill is asked for, not performed here: this process knows the command's
/// pid only from a file, and signalling a pid it did not reap races with the
/// kernel reusing that number for something else in the same container. The
/// supervisor holds the child, so only the supervisor can know the pid still
/// means what it meant.
fn cancel(spool: &Spool, id: &str) -> Reply {
    let report = match reconcile(spool, id) {
        Ok(report) => report,
        Err(code) => return error(code),
    };
    // A settled execution is not re-opened: every answer already given about it
    // would otherwise become provisional.
    if report.state.is_terminal() {
        return Reply::State { report };
    }
    if let Err(error_) = spool.request_cancel(id) {
        return error(map_error(error_));
    }

    // Bounded wait for the supervisor to act, so the caller usually gets the
    // terminal state in the same response. Timing out here is not a failure —
    // the marker is durable, and the next poll will see the outcome.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        match spool.read_report(id) {
            Ok(report) if report.state.is_terminal() => return Reply::State { report },
            Ok(_) => {}
            Err(error_) => return error(map_error(error_)),
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    match spool.read_report(id) {
        Ok(report) => Reply::State { report },
        Err(error_) => error(map_error(error_)),
    }
}

fn map_error(error: SpoolError) -> RunnerErrorCode {
    match error {
        SpoolError::NotFound => RunnerErrorCode::NotFound,
        SpoolError::Conflict(_) => RunnerErrorCode::Conflict,
        SpoolError::Corrupt | SpoolError::Io(_) => RunnerErrorCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> StartRequest {
        StartRequest {
            protocol: PROTOCOL_VERSION,
            id: "sbxe-1".into(),
            argv: vec!["/agent".into(), "run".into()],
            cwd: Some("/work".into()),
            timeout_seconds: 60,
            max_output_bytes: 1024,
            stdin_base64: None,
        }
    }

    /// Kobe and the runner share exact hidden flags for both target-side crash
    /// boundaries, and clap refuses an invocation that tries to select both.
    #[test]
    fn crash_flags_select_one_exact_runner_boundary() {
        for (flag, before_spawn, after_spawn) in [
            (
                kobe_runner::protocol::TEST_EXIT_BEFORE_SPAWN_FLAG,
                true,
                false,
            ),
            (
                kobe_runner::protocol::TEST_EXIT_AFTER_SPAWN_BEFORE_ACK_FLAG,
                false,
                true,
            ),
        ] {
            let cli = Cli::try_parse_from(["kobe-runner", "start", flag]).unwrap();
            assert!(matches!(
                cli.command,
                Commands::Start {
                    test_exit_before_spawn,
                    test_exit_after_spawn_before_ack,
                } if test_exit_before_spawn == before_spawn
                    && test_exit_after_spawn_before_ack == after_spawn
            ));
        }
        assert!(
            Cli::try_parse_from([
                "kobe-runner",
                "start",
                kobe_runner::protocol::TEST_EXIT_BEFORE_SPAWN_FLAG,
                kobe_runner::protocol::TEST_EXIT_AFTER_SPAWN_BEFORE_ACK_FLAG,
            ])
            .is_err()
        );
    }

    /// A request that could never run is refused before anything is reserved.
    ///
    /// A reservation for an unrunnable command is worse than a rejection: Kobe
    /// has already recorded the id, so the caller cannot reuse it, and every
    /// retry has to reason about a record that describes nothing.
    #[test]
    fn an_unrunnable_request_reserves_nothing() {
        assert!(validate(&request()).is_ok());

        let with = |mutate: &dyn Fn(&mut StartRequest)| {
            let mut request = request();
            mutate(&mut request);
            validate(&request)
        };

        // A peer speaking another protocol is refused, never served on a
        // best-effort basis.
        assert!(with(&|r| r.protocol = PROTOCOL_VERSION + 1).is_err());
        assert!(with(&|r| r.protocol = 0).is_err());

        assert!(with(&|r| r.argv = vec![]).is_err());
        assert!(with(&|r| r.argv = vec![String::new()]).is_err());
        assert!(with(&|r| r.argv = vec!["/bin/sh".into(), "\0".into()]).is_err());
        assert!(with(&|r| r.id = "../escape".into()).is_err());
        for bad in ["", "work", "./work", "/work\0/etc"] {
            assert!(
                with(&|r| r.cwd = Some(bad.to_string())).is_err(),
                "cwd {bad:?} must be refused"
            );
        }
        assert!(with(&|r| r.cwd = None).is_ok());
    }

    /// Stdin that cannot be delivered whole reserves nothing.
    ///
    /// Refusing before the reservation is what keeps an oversized or malformed
    /// secret from spending an idempotency key on a command that could never
    /// have been given its input. Truncating to fit is the one response that is
    /// never correct: half a token is still a secret, and the command would
    /// fail somewhere a long way from the cause.
    #[test]
    fn stdin_that_cannot_be_delivered_whole_reserves_nothing() {
        use base64::Engine;
        use kobe_runner::protocol::MAX_STDIN_BYTES;

        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
        let with = |encoded: Option<String>| {
            let mut request = request();
            request.stdin_base64 = encoded;
            validate(&request)
        };

        assert!(with(None).is_ok(), "no stdin at all stays valid");
        assert!(
            with(Some(String::new())).is_ok(),
            "an empty stdin is a request"
        );
        assert!(with(Some(encode(b"ghp_token"))).is_ok());
        assert!(with(Some(encode(&vec![b'x'; MAX_STDIN_BYTES]))).is_ok());

        assert_eq!(
            with(Some(encode(&vec![b'x'; MAX_STDIN_BYTES + 1]))),
            Err(RunnerErrorCode::InvalidRequest),
            "one byte past the bound is refused, not trimmed"
        );
        assert_eq!(
            with(Some("not base64!!".into())),
            Err(RunnerErrorCode::InvalidRequest)
        );
    }

    /// A request carrying stdin still has to fit the encoded-request bound.
    ///
    /// [`MAX_STDIN_BYTES`] and [`MAX_REQUEST_BYTES`] are two different ceilings
    /// and both apply. Neither is allowed to become a silent truncation of the
    /// other.
    #[test]
    fn stdin_is_bounded_inside_the_encoded_request_bound() {
        use base64::Engine;
        use kobe_runner::protocol::MAX_STDIN_BYTES;

        let mut request = request();
        request.stdin_base64 =
            Some(base64::engine::general_purpose::STANDARD.encode(vec![b'x'; MAX_STDIN_BYTES]));
        let mut encoded = serde_json::to_vec(&request).unwrap();
        encoded.push(b'\n');
        assert!(
            encoded.len() < MAX_REQUEST_BYTES,
            "a maximal stdin must still leave room for a command: {} bytes",
            encoded.len()
        );
        assert_eq!(read_start_request(encoded.as_slice()).unwrap(), request);

        // Padding the argv past the whole-request bound is refused by the
        // reader, before the stdin ceiling is ever consulted.
        request.argv.push("y".repeat(MAX_REQUEST_BYTES));
        let mut oversized = serde_json::to_vec(&request).unwrap();
        oversized.push(b'\n');
        assert_eq!(
            read_start_request(oversized.as_slice()).unwrap_err(),
            RunnerErrorCode::InvalidRequest
        );
    }

    /// Neither bound may be absent, and neither may be unbounded.
    ///
    /// A zero timeout is a command that can never finish successfully; an
    /// unbounded one holds a lease's CPU until teardown. An unbounded retention
    /// cap fills the ephemeral disk the whole Pod shares — from inside a
    /// container that exists because its occupant is not trusted.
    #[test]
    fn a_command_is_bounded_in_time_and_in_output() {
        let with = |timeout: u64, output: u64| {
            let mut request = request();
            request.timeout_seconds = timeout;
            request.max_output_bytes = output;
            validate(&request)
        };

        assert!(with(1, 1).is_ok());
        assert!(with(MAX_TIMEOUT_SECONDS, MAX_RETENTION_BYTES).is_ok());

        assert!(with(0, 1024).is_err());
        assert!(with(MAX_TIMEOUT_SECONDS + 1, 1024).is_err());
        assert!(with(u64::MAX, 1024).is_err());
        assert!(with(60, 0).is_err());
        assert!(with(60, MAX_RETENTION_BYTES + 1).is_err());
        assert!(with(60, u64::MAX).is_err());
    }

    /// The runner reads exactly the same encoded boundary Kobe validates.
    #[test]
    fn encoded_request_bound_is_exact_and_requires_a_complete_line() {
        let mut request = request();
        request.argv = vec![String::new()];
        let mut encoded = serde_json::to_vec(&request).unwrap();
        encoded.push(b'\n');
        let fill = MAX_REQUEST_BYTES - encoded.len();
        request.argv[0] = "x".repeat(fill);
        let mut exact = serde_json::to_vec(&request).unwrap();
        exact.push(b'\n');
        assert_eq!(exact.len(), MAX_REQUEST_BYTES);
        assert_eq!(read_start_request(exact.as_slice()).unwrap(), request);

        let mut oversized = request.clone();
        oversized.argv[0].push('x');
        let mut oversized = serde_json::to_vec(&oversized).unwrap();
        oversized.push(b'\n');
        assert_eq!(oversized.len(), MAX_REQUEST_BYTES + 1);
        assert_eq!(
            read_start_request(oversized.as_slice()).unwrap_err(),
            RunnerErrorCode::InvalidRequest
        );

        assert_eq!(
            read_start_request(&exact[..exact.len() - 1]).unwrap_err(),
            RunnerErrorCode::InvalidRequest,
            "EOF without the line receipt is incomplete"
        );
    }
}
