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
    Envelope, ExecutionReport, LogStream, MAX_LOG_CHUNK_BYTES, PROTOCOL_VERSION, Reply,
    RunnerErrorCode, RunnerState, StartRequest, TEST_EXECUTION_CRASH_EXIT_CODE, is_valid_id,
    reason,
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
    /// Persistent terminal sessions that survive a dropped connection.
    Session {
        /// Where session sockets live.
        #[arg(long, default_value = DEFAULT_SESSIONS_DIR)]
        dir: std::path::PathBuf,

        #[command(subcommand)]
        action: SessionAction,
    },
}

#[derive(Subcommand)]
enum SessionAction {
    /// Attach this terminal to a session, starting it when it does not exist.
    Attach {
        #[arg(long, default_value = "main")]
        name: String,
        /// Program for a new session. The login shell when empty. Ignored
        /// when the session already exists.
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// Own one session's shell. Started by `attach`, never by hand.
    #[command(hide = true)]
    Serve {
        #[arg(long)]
        name: String,
        #[arg(last = true)]
        argv: Vec<String>,
    },
    /// Print the live sessions as JSON.
    List,
    /// Print current session usage and the optional ceiling as Prometheus metrics.
    Metrics,
}

#[cfg(unix)]
const DEFAULT_SESSIONS_DIR: &str = kobe_runner::session::DEFAULT_SESSIONS_DIR;
#[cfg(not(unix))]
const DEFAULT_SESSIONS_DIR: &str = "";

/// `session` is interactive, not request/response: its replies are a terminal.
#[cfg(unix)]
fn session(dir: &std::path::Path, action: &SessionAction) -> i32 {
    use kobe_runner::session;
    match action {
        SessionAction::Attach { name, argv } => session::attach(dir, name, argv),
        SessionAction::Serve { name, argv } => match session::serve(dir, name, argv) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("kobe-runner: session {name}: {error}");
                1
            }
        },
        SessionAction::Metrics => match session::metrics(dir) {
            Ok(metrics) => {
                print!("{metrics}");
                0
            }
            Err(error) => {
                eprintln!("{error}");
                1
            }
        },
        SessionAction::List => {
            println!("{}", serde_json::json!({ "sessions": session::list(dir) }));
            0
        }
    }
}

#[cfg(not(unix))]
fn session(_dir: &std::path::Path, _action: &SessionAction) -> i32 {
    eprintln!("kobe-runner: sessions are supported only on unix");
    1
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
    if let Commands::Session { dir, action } = &cli.command {
        std::process::exit(session(dir, action));
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
        Commands::Supervise { .. } | Commands::Session { .. } => unreachable!("handled above"),
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
    if std::io::BufReader::new(reader)
        .read_until(b'\n', &mut raw)
        .is_err()
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
    // No upper bound here: Kobe clamps every timeout to the lease that
    // authorises it, and the lease's teardown deletes this container. A fixed
    // ceiling in the runner could only cut off work the lease allows.
    if request.timeout_seconds == 0 {
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

    /// Input size is validated by the operator; encoding is validated here.
    #[test]
    fn large_stdin_is_valid_but_malformed_base64_is_refused() {
        use base64::Engine;
        let mut request = request();
        request.stdin_base64 =
            Some(base64::engine::general_purpose::STANDARD.encode(vec![b'x'; 2 * 1024 * 1024]));
        assert!(validate(&request).is_ok());
        request.stdin_base64 = Some("!invalid!".into());
        assert_eq!(validate(&request), Err(RunnerErrorCode::InvalidRequest));
    }

    /// No hidden request-size cap may truncate forwarded stdin.
    #[test]
    fn large_stdin_survives_the_complete_start_request() {
        use base64::Engine;
        let mut request = request();
        request.stdin_base64 =
            Some(base64::engine::general_purpose::STANDARD.encode(vec![b'x'; 2 * 1024 * 1024]));
        let mut encoded = serde_json::to_vec(&request).unwrap();
        encoded.push(b'\n');
        assert_eq!(read_start_request(encoded.as_slice()).unwrap(), request);
    }

    /// Zero means unlimited output. Execution time remains lease-scoped.
    #[test]
    fn output_retention_is_unlimited_with_zero_and_accepts_explicit_caps() {
        for output in [0, 1, 8 * 1024 * 1024 + 1, u64::MAX] {
            let mut request = request();
            request.max_output_bytes = output;
            assert!(validate(&request).is_ok());
        }
        let mut request = request();
        request.timeout_seconds = 0;
        assert!(validate(&request).is_err());
    }

    /// A complete request line is required, regardless of its size.
    #[test]
    fn start_request_requires_a_complete_line_without_a_size_ceiling() {
        let mut request = request();
        request.argv.push("x".repeat(128 * 1024));
        let mut encoded = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            read_start_request(encoded.as_slice()).unwrap_err(),
            RunnerErrorCode::InvalidRequest
        );
        encoded.push(b'\n');
        assert_eq!(read_start_request(encoded.as_slice()).unwrap(), request);
    }
}
