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

use std::io::{BufRead, Read};

use clap::{Parser, Subcommand};

use kobe_runner::protocol::{
    Envelope, ExecutionReport, LogStream, MAX_LOG_CHUNK_BYTES, MAX_RETENTION_BYTES,
    MAX_TIMEOUT_SECONDS, PROTOCOL_VERSION, Reply, RunnerErrorCode, RunnerState, StartRequest,
    is_valid_id,
};
use kobe_runner::spool::{self, Reservation, Spool, SpoolError};
#[cfg(unix)]
use kobe_runner::supervisor;

/// Largest start request the runner will read.
///
/// The request arrives on a pipe from outside the container. Reading it
/// unbounded would let whoever holds that pipe make the runner allocate without
/// limit, inside the tenant's own memory cgroup.
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

#[derive(Parser)]
#[command(name = "kobe-runner", about = "Supervise one Kobe Sandbox execution")]
struct Cli {
    /// Where executions are spooled. Owned by the runner: Kobe never names a
    /// path inside somebody else's container.
    #[arg(long, default_value = spool::DEFAULT_STATE_DIR, global = true)]
    state_dir: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Reserve an id and supervise its command. The request is read from stdin.
    Start,
    /// Run the supervision loop. Started by `start`, never by Kobe.
    #[command(hide = true)]
    Supervise {
        #[arg(long)]
        id: String,
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
    if let Commands::Supervise { id } = &cli.command {
        #[cfg(unix)]
        supervisor::supervise(&spool, id);
        return;
    }

    let reply = match &cli.command {
        Commands::Start => start(&spool, &cli.state_dir),
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
/// spawned exactly once per reservation. A retry of the same request finds the
/// reservation and reports it; it never spawns a second command.
fn start(spool: &Spool, state_dir: &str) -> Reply {
    // One line, not "until EOF". The request arrives over an exec connection
    // whose write half Kobe cannot reliably half-close, so waiting for EOF is
    // waiting for something that may never come — and the command would not
    // start until the timeout fired. JSON never contains a raw newline, so a
    // line IS the document.
    let mut raw = Vec::new();
    if std::io::BufReader::new(std::io::stdin().take(MAX_REQUEST_BYTES))
        .read_until(b'\n', &mut raw)
        .is_err()
    {
        return error(RunnerErrorCode::InvalidRequest);
    }
    let Ok(request) = serde_json::from_slice::<StartRequest>(&raw) else {
        return error(RunnerErrorCode::InvalidRequest);
    };
    if let Err(code) = validate(&request) {
        return error(code);
    }

    match spool.reserve(&request) {
        Ok(Reservation::Created) => {
            if spawn_supervisor(state_dir, &request.id).is_err() {
                // Nothing was started, but this process cannot prove that to
                // Kobe in a way it could distinguish from a lost reply — so the
                // execution settles as the state that never invites a blind
                // retry.
                let _ = spool.write_report(&ExecutionReport {
                    id: request.id.clone(),
                    state: RunnerState::Unknown,
                    finished_at_unix_ms: Some(spool::now_unix_ms()),
                    reason: Some("supervisor_not_started".into()),
                    ..Default::default()
                });
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
#[cfg(unix)]
fn spawn_supervisor(state_dir: &str, id: &str) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

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
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

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
    let child = command.spawn()?;
    // Recorded so a later `status` or `cancel` can tell "still running" from
    // "the supervisor is gone and nobody will ever record an outcome".
    let _ = Spool::new(state_dir).write_supervisor_pid(id, child.id());
    Ok(())
}

#[cfg(not(unix))]
fn spawn_supervisor(_state_dir: &str, _id: &str) -> std::io::Result<()> {
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
    if supervisor_alive(spool, id) {
        return Ok(report);
    }

    let settled = ExecutionReport {
        state: RunnerState::Unknown,
        finished_at_unix_ms: Some(spool::now_unix_ms()),
        reason: Some("supervisor_lost".into()),
        ..report
    };
    let _ = spool.write_report(&settled);
    Ok(settled)
}

#[cfg(unix)]
fn supervisor_alive(spool: &Spool, id: &str) -> bool {
    let Some(pid) = spool.read_supervisor_pid(id) else {
        // No pid recorded yet: `start` writes it immediately after spawning, so
        // the window is a few microseconds wide. Treating it as alive costs a
        // poll; treating it as dead would settle a command that is running.
        return true;
    };
    // SAFETY: signal 0 performs the permission and existence checks without
    // delivering anything.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[cfg(not(unix))]
fn supervisor_alive(_spool: &Spool, _id: &str) -> bool {
    true
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
        }
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
}
