//! The process that outlives the connection.
//!
//! # What "detached" actually requires
//!
//! An exec connection is a pipe held open by an API server. When it closes —
//! because the caller disconnected, or because the operator restarted — the
//! kubelet tears down what it started. A "detached" execution implemented as
//! "an exec we stopped reading from" therefore dies with the connection, which
//! is strictly worse than not offering one: the caller has built on a guarantee
//! that was never there.
//!
//! So the supervisor is re-executed into its **own session** and its parent
//! exits immediately. It is reparented to the container's init, holds none of
//! the exec's file descriptors, and there is nothing left for the teardown to
//! find.
//!
//! # Why the command gets a session of its own too
//!
//! Cancelling has to kill the process group, not the leader: a build script
//! that spawned four compilers and then exited leaves those compilers running,
//! holding the CPU the lease is paying for. The command is therefore put in its
//! own session, and cancellation signals the negative pid — every descendant
//! that has not deliberately left the group.
//!
//! Its own session, separate from the supervisor's, is what lets the supervisor
//! survive the kill it just issued and record the outcome.
//!
//! # Why the command's stdin arrives through a pipe and not the spool
//!
//! stdin exists on this contract so a Sandbox can receive a secret without it
//! appearing in argv, which the target apiserver audit-logs verbatim. Passing
//! those bytes to the supervisor through the spool would move the secret off
//! the audit log and onto a filesystem the tenant's workload shares and that
//! outlives the command — a worse place, not a better one. So `start` hands
//! them over a pipe, this process holds them in memory, writes them to the
//! command, and closes.

use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::protocol::{
    ExecutionReport, LogStream, MAX_STDIN_BYTES, RunnerState, StartRequest, reason,
};
use crate::spool::{Spool, now_unix_ms};

/// How often the supervisor looks at the world.
///
/// Short enough that a cancellation feels immediate, long enough that a
/// supervisor idling next to a tenant's workload costs nothing measurable.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How long a terminated process group is given to exit on its own.
///
/// SIGTERM first, because a command that traps it may need to finish a write or
/// release a lock; SIGKILL after, because "asked politely" is not a guarantee
/// and the lease that pays for the CPU is ending either way.
const TERMINATION_GRACE: Duration = Duration::from_secs(5);

/// How long the outcome waits for the output pipes to close.
///
/// A grandchild that outlived its parent can hold the pipe open indefinitely.
/// The exit status is already observed at that point, and refusing to record it
/// because a stray process still has the write end would turn a known outcome
/// into an `Unknown` for no reason.
const OUTPUT_SETTLE: Duration = Duration::from_secs(2);

/// Supervise one reserved execution until it settles, then exit.
///
/// `stdin_bytes` says how many bytes of the command's stdin are waiting on
/// `source` — this process's own stdin in production. They are read first,
/// before the spool and before anything is spawned: the writer is the `start`
/// process, which exits as soon as the handover completes, so the bytes have to
/// be taken while they are still there. `None` means the command reads
/// `/dev/null`, which is what every execution did before stdin forwarding
/// existed.
///
/// The bytes stay in this process's memory and are never written to the spool.
/// That is the point of the feature: the request travels on stdin because argv
/// is audit-logged, and it would be a poor trade to move a secret off the audit
/// log and onto a disk the tenant's workload shares. In *memory* they are an
/// ordinary `Vec<u8>`, neither zeroized nor `mlock`ed: a core dump of this
/// process, or the container's swap, can still hold them. Bounding the exposure
/// to one process's lifetime is the guarantee on offer here; defeating an
/// attacker who can read the runner's own address space is not.
///
/// Once the command exists, nothing may unwind out of this function. It has
/// been spawned into a session of its own and dropping [`Child`] does not kill
/// it, so a supervisor that dies here leaves a command running past its
/// deadline with nobody to cancel or reap it. Every step after the spawn
/// therefore reports its failure instead of panicking on it — see
/// [`spawn_helper`] — and each one tears the process group down before
/// settling the execution.
pub fn supervise(spool: &Spool, id: &str, stdin_bytes: Option<usize>, source: impl Read) {
    let started_at = now_unix_ms();
    let stdin = match read_stdin(stdin_bytes, source) {
        Ok(stdin) => stdin,
        Err(_) => {
            // Part of a secret arrived and the rest did not. Running the
            // command anyway would hand it a truncated credential and then
            // report whatever it made of that, so nothing is spawned and the
            // execution settles as the state that never invites a blind retry.
            let _ = spool.write_report(&ExecutionReport {
                id: id.to_string(),
                state: RunnerState::Unknown,
                started_at_unix_ms: Some(started_at),
                finished_at_unix_ms: Some(now_unix_ms()),
                reason: Some(reason::SUPERVISOR_SETUP_FAILED.into()),
                ..Default::default()
            });
            return;
        }
    };

    let request = match spool.read_request(id) {
        Ok(request) => request,
        Err(_) => {
            // Nothing to supervise and nothing to record it against. Writing a
            // report for an id whose request cannot be read would be inventing
            // one.
            return;
        }
    };

    if enable_child_subreaper().is_err() {
        // A Linux container's PID 1 is not required to reap orphans. Without
        // becoming a subreaper, this process cannot prove that every member of
        // the command's process group is gone before reporting cancellation.
        let _ = spool.write_report(&ExecutionReport {
            id: id.to_string(),
            state: RunnerState::Unknown,
            started_at_unix_ms: Some(started_at),
            finished_at_unix_ms: Some(now_unix_ms()),
            reason: Some(reason::SUPERVISOR_SETUP_FAILED.into()),
            ..Default::default()
        });
        return;
    }
    let mut child = match spawn(&request, stdin.is_some()) {
        Ok(child) => child,
        Err(_) => {
            // The command definitely did not run, but this process cannot tell
            // Kobe that in a way Kobe can distinguish from "we never heard
            // back" — so it reports the state that never invites a blind retry.
            let _ = spool.write_report(&ExecutionReport {
                id: id.to_string(),
                state: RunnerState::Unknown,
                started_at_unix_ms: Some(started_at),
                finished_at_unix_ms: Some(now_unix_ms()),
                reason: Some(reason::SPAWN_FAILED.into()),
                ..Default::default()
            });
            return;
        }
    };

    // The command's own session leader. Signalling the NEGATIVE of this reaches
    // every descendant that has not deliberately left the group — the four
    // compilers a build script spawned before exiting.
    let group = child.id() as i32;

    // Everything below this point needs a thread the OS may refuse, and the
    // command is already running in a session of its own. A supervisor that
    // gave up here without killing the group would leave that command with no
    // deadline and nobody to reap it — the very failure the whole "outlives the
    // connection" design exists to make impossible. So teardown is ATTEMPTED
    // before the execution is settled, in that order.
    //
    // Attempted, not guaranteed: [`terminate_group`] signals the group and then
    // waits at most TERMINATION_GRACE per drain for it to actually leave, and
    // the call below discards its answer. Signal delivery is not reaping, so a
    // process that outlives both windows outlives this supervisor too. That is
    // exactly why the report is `Unknown` — the honest word for a group whose
    // absence nobody proved — and why the lease, not this function, is the last
    // line of defence: the Pod dying takes the group with it.
    let helpers = feed(child.stdin.take(), stdin).and_then(|()| {
        let stdout = pump(
            child.stdout.take(),
            spool,
            id,
            LogStream::Stdout,
            request.max_output_bytes,
        )?;
        let stderr = pump(
            child.stderr.take(),
            spool,
            id,
            LogStream::Stderr,
            request.max_output_bytes,
        )?;
        Ok((stdout, stderr))
    });

    let (stdout, stderr) = match helpers {
        Ok(pumps) => pumps,
        Err(_) => {
            terminate_group(group, &mut child);
            // `Unknown`, not `Failed`: the command may have done all of its
            // work in the moment it had, and `Failed` is the answer that tells
            // a caller their retry is safe. `supervisor_setup_failed` is the
            // same code the pre-spawn setup failures use, and means the same
            // thing to Kobe — this process never reached the point of watching
            // anything, so the target is destroyed rather than reused.
            //
            // The write can fail and the error is discarded, so this is a
            // terminal report ATTEMPTED rather than one guaranteed: a workload
            // that removed its own `state.lock` gets a refused pump here and
            // then a `write_report` that cannot take the lock either, and the
            // supervisor exits leaving `Running` behind. Nothing better can be
            // done from inside a spool the tenant owns, and Kobe's verdict
            // deadline is what turns that stale `Running` into `Unknown`.
            let _ = spool.write_report(&ExecutionReport {
                id: id.to_string(),
                state: RunnerState::Unknown,
                started_at_unix_ms: Some(started_at),
                finished_at_unix_ms: Some(now_unix_ms()),
                reason: Some(reason::SUPERVISOR_SETUP_FAILED.into()),
                ..Default::default()
            });
            return;
        }
    };

    let deadline = Instant::now() + Duration::from_secs(request.timeout_seconds);
    let mut ended_by: Option<&'static str> = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // The session leader is only one member of the execution. A
                // build script can exit zero after backgrounding compilers,
                // and reporting Succeeded at that point would leave work
                // running outside the execution record. Preserve the leader's
                // status, but settle it only after the whole group is absent.
                break if process_group_exists(group) {
                    terminate_group_with_status(group, &mut child, Some(status))
                } else {
                    Some(status)
                };
            }
            Ok(None) => {}
            // The child cannot be reaped. Nobody can say what it did.
            Err(_) => break None,
        }

        if ended_by.is_none() {
            if spool.cancel_requested(id) {
                ended_by = Some(reason::CANCELLED);
            } else if Instant::now() >= deadline {
                ended_by = Some(reason::TIMED_OUT);
            }
            if ended_by.is_some() {
                // `None` is deliberately an Unknown outcome: reporting
                // Cancelled or TimedOut while a descendant may still be alive
                // would claim teardown the supervisor did not prove.
                break terminate_group(group, &mut child);
            }
        }

        std::thread::sleep(POLL_INTERVAL);
    };

    // Both pumps are given a bounded chance to drain what is still buffered.
    // The exit status is already known, so a grandchild holding the pipe open
    // must not be able to prevent the outcome being recorded.
    let settle = Instant::now() + OUTPUT_SETTLE;
    while Instant::now() < settle && !(stdout.finished() && stderr.finished()) {
        std::thread::sleep(POLL_INTERVAL);
    }

    let report = settle_report(
        id,
        started_at,
        status,
        ended_by,
        stdout.truncated(),
        stderr.truncated(),
    );
    let _ = spool.write_report(&report);
}

/// Turn what was observed into the outcome that is honest about it.
///
/// Split out from the wait loop so the mapping is testable without a process:
/// this function is where an unverifiable outcome becomes `Unknown` rather than
/// `Failed`, and that distinction is the one a caller acts on.
pub fn settle_report(
    id: &str,
    started_at: u64,
    status: Option<std::process::ExitStatus>,
    ended_by: Option<&str>,
    stdout_truncated: bool,
    stderr_truncated: bool,
) -> ExecutionReport {
    let finished_at = now_unix_ms();
    let base = ExecutionReport {
        id: id.to_string(),
        state: RunnerState::Unknown,
        started_at_unix_ms: Some(started_at),
        finished_at_unix_ms: Some(finished_at),
        stdout_truncated,
        stderr_truncated,
        ..Default::default()
    };

    let Some(status) = status else {
        // The process could not be reaped. Not `Failed`: it may well have done
        // its work, and `Failed` is the answer that invites doing it again.
        return ExecutionReport {
            reason: Some(reason::OUTCOME_UNOBSERVED.into()),
            ..base
        };
    };

    // A command the runner killed is reported by WHY it was killed, not by the
    // signal it died of. The exit code is deliberately absent: the process did
    // not choose an outcome, and attaching one would assert something nobody
    // observed.
    if let Some(ended_by) = ended_by {
        return ExecutionReport {
            state: if ended_by == reason::CANCELLED {
                RunnerState::Cancelled
            } else {
                RunnerState::TimedOut
            },
            reason: Some(ended_by.to_string()),
            ..base
        };
    }

    match (status.code(), status.signal()) {
        (Some(0), _) => ExecutionReport {
            state: RunnerState::Succeeded,
            exit_code: Some(0),
            reason: Some(reason::COMPLETED.into()),
            ..base
        },
        (Some(code), _) => ExecutionReport {
            state: RunnerState::Failed,
            exit_code: Some(code),
            reason: Some(reason::COMPLETED.into()),
            ..base
        },
        // Killed by something that is not the runner — an OOM kill, an
        // administrator, the workload's own supervisor. It definitely ran and
        // definitely did not finish, which is a failure and not an unknown; the
        // signal is reported instead of an exit code the process never chose.
        (None, Some(signal)) => ExecutionReport {
            state: RunnerState::Failed,
            signal: Some(signal),
            reason: Some(reason::SIGNALLED.into()),
            ..base
        },
        (None, None) => ExecutionReport {
            reason: Some(reason::OUTCOME_UNOBSERVED.into()),
            ..base
        },
    }
}

/// Take the command's stdin off this process's own, exactly.
///
/// `read_exact` rather than "read to EOF" for the same reason the request
/// itself is one line: the number of bytes is known in advance, so waiting for
/// an EOF is waiting for something a writer is not obliged to deliver promptly.
/// It is also what turns a partial handover into an error instead of a silently
/// shorter secret — a short read here is a lost credential, not an empty one.
fn read_stdin(
    stdin_bytes: Option<usize>,
    mut source: impl Read,
) -> std::io::Result<Option<Vec<u8>>> {
    let Some(length) = stdin_bytes else {
        return Ok(None);
    };
    if length > MAX_STDIN_BYTES {
        // The same ceiling Kobe and `start` enforce. A supervisor is only ever
        // launched by `start`, so reaching this means the argv was tampered
        // with — and allocating whatever it asked for is not the response.
        return Err(std::io::Error::other("stdin length exceeds the bound"));
    }
    let mut bytes = vec![0u8; length];
    source.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

/// Start one of the supervisor's helper threads, or say that it could not.
///
/// `std::thread::Builder` rather than `std::thread::spawn`, because
/// `thread::spawn` **panics** when the OS refuses a thread — and this is the
/// one process where that panic is not an option. Every helper is started
/// *after* the command has been spawned into a session of its own, and
/// dropping Rust's [`Child`] does not kill anything: unwinding out of
/// [`supervise`] would leave a command with no deadline, no cancellation and
/// nobody to reap it, still charging the lease that paid for it.
///
/// The refusal is not hypothetical. The runner lives inside a tenant's
/// container under a PID cgroup, and the command it just spawned is itself a
/// consumer of that budget — so "the child started and the helper cannot" is
/// exactly the shape thread exhaustion takes here.
///
/// The handle is dropped on purpose: these threads are detached and observed
/// through the spool and the pipes, never joined.
fn spawn_helper(body: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
    #[cfg(test)]
    if tests::helper_thread_is_refused() {
        return Err(std::io::Error::from_raw_os_error(libc::EAGAIN));
    }
    std::thread::Builder::new().spawn(body).map(drop)
}

/// Hand the bytes to the process, then close its stdin.
///
/// On a thread, because the command is under no obligation to read: anything
/// larger than a pipe buffer would otherwise block the supervisor's wait loop,
/// and a supervisor that is not looping cannot cancel, time out, or drain
/// output.
///
/// Closing is the half that makes this useful at all. `gh auth login
/// --with-token` reads its token until EOF; a stdin that was written and left
/// open would leave it waiting for the timeout to kill it. Dropping the handle
/// — on every path, including a write that failed because the command already
/// exited — is what delivers that EOF.
///
/// Returns the OS's refusal instead of panicking on it; see [`spawn_helper`]
/// for why that distinction is load-bearing, and [`supervise`] for what is
/// done with it. The bytes are dropped along with the failed closure, which is
/// the correct disposal for them: nothing else in this process wants a
/// credential it can no longer deliver.
fn feed(sink: Option<std::process::ChildStdin>, bytes: Option<Vec<u8>>) -> std::io::Result<()> {
    let (Some(mut sink), Some(bytes)) = (sink, bytes) else {
        return Ok(());
    };
    spawn_helper(move || {
        // A command that exits without reading gives EPIPE here. That is its
        // choice, not a fault of the execution, and its own exit status is the
        // outcome that gets reported.
        let _ = sink.write_all(&bytes);
        let _ = sink.flush();
        drop(sink);
    })
}

/// Start the command, in a session of its own.
///
/// `with_stdin` decides between a pipe this supervisor feeds and `/dev/null`.
/// The distinction is the caller's to make: a command handed an immediately
/// closed pipe and one handed `/dev/null` both see EOF, but only the first is
/// something somebody asked for.
fn spawn(request: &StartRequest, with_stdin: bool) -> std::io::Result<Child> {
    let mut command = Command::new(&request.argv[0]);
    command.args(&request.argv[1..]);
    if let Some(cwd) = &request.cwd {
        // `chdir`, applied by the kernel at exec. Never `cd X && ...`: a shell
        // there would make quoting the security boundary, and the boundary is a
        // tenant's own untrusted input.
        command.current_dir(cwd);
    }
    // Never the supervisor's own stdin, and never an inherited terminal: a
    // detached command has no connection to read from, and a terminal would let
    // it stop on SIGTTIN and look like a hang. Either a pipe carrying exactly
    // what the caller supplied, or nothing at all.
    command.stdin(if with_stdin {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    // SAFETY: `setsid` is async-signal-safe and is the only thing called
    // between fork and exec. It puts the command in its own session, so
    // cancelling it kills the whole group without killing this supervisor.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn()
}

/// Make orphaned descendants reapable by this supervisor on Linux.
///
/// The runner is designed for containers, whose PID 1 is not guaranteed to
/// reap. Becoming a subreaper before the command is spawned makes descendants
/// that outlive their leader children of this process, so group absence can be
/// proved instead of inferred from the leader's exit.
#[cfg(target_os = "linux")]
fn enable_child_subreaper() -> std::io::Result<()> {
    // SAFETY: `PR_SET_CHILD_SUBREAPER` changes only this process's child-reaping
    // behavior and requires no pointer arguments or privileges.
    let result = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
fn enable_child_subreaper() -> std::io::Result<()> {
    Ok(())
}

/// Terminate the process group and prove that it is empty.
///
/// A leader exiting is not proof: a descendant may ignore SIGTERM and keep
/// consuming the lease. The return value is therefore the leader's observed
/// status only when the whole group is absent. `None` means teardown could not
/// be proven within the bounded TERM/KILL windows.
fn terminate_group(group: i32, child: &mut Child) -> Option<std::process::ExitStatus> {
    terminate_group_with_status(group, child, None)
}

/// Terminate the process group while preserving an already-observed leader
/// status when natural completion won the race with cancellation or timeout.
fn terminate_group_with_status(
    group: i32,
    child: &mut Child,
    mut leader_status: Option<std::process::ExitStatus>,
) -> Option<std::process::ExitStatus> {
    // SAFETY: a plain `kill(2)`. The negative pid addresses the group, which is
    // the point — the leader alone leaves its children running on CPU the lease
    // is paying for.
    unsafe { libc::kill(-group, libc::SIGTERM) };

    if drain_process_group(group, child, &mut leader_status) {
        return leader_status;
    }

    // Asked politely, then not. A command that traps SIGTERM and declines to
    // exit still has to stop: the lease that pays for it is ending either way.
    unsafe { libc::kill(-group, libc::SIGKILL) };

    if drain_process_group(group, child, &mut leader_status) {
        leader_status
    } else {
        None
    }
}

/// Reap the leader and adopted descendants until the group is absent or the
/// bounded termination window expires.
fn drain_process_group(
    group: i32,
    child: &mut Child,
    leader_status: &mut Option<std::process::ExitStatus>,
) -> bool {
    let deadline = Instant::now() + TERMINATION_GRACE;
    loop {
        if leader_status.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => *leader_status = Some(status),
                Ok(None) => {}
                // Reaping the leader failed, so no honest terminal outcome can
                // be recorded even if the kernel later drops the group.
                Err(_) => return false,
            }
        }

        // Never use raw waitpid before Child has reaped the leader: doing so
        // could steal the status that std::process owns.
        if leader_status.is_some() {
            reap_adopted_group_members(group);
        }

        if leader_status.is_some() && !process_group_exists(group) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(target_os = "linux")]
fn reap_adopted_group_members(group: i32) {
    loop {
        let mut status = 0;
        // SAFETY: after the direct child has been reaped through Child, this
        // non-blocking wait can only collect descendants adopted because this
        // supervisor enabled subreaping.
        let waited = unsafe { libc::waitpid(-group, &mut status, libc::WNOHANG) };
        if waited <= 0 {
            return;
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn reap_adopted_group_members(_group: i32) {}

fn process_group_exists(group: i32) -> bool {
    // SAFETY: signal zero performs existence/permission checking only.
    if unsafe { libc::kill(-group, 0) } == 0 {
        return true;
    }

    // EPERM still proves that a member exists. Any unexpected error fails
    // closed; only ESRCH proves the group is absent.
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// A stream being copied to disk, with a cap.
struct Pump {
    truncated: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
}

impl Pump {
    fn truncated(&self) -> bool {
        self.truncated.load(Ordering::SeqCst)
    }

    fn finished(&self) -> bool {
        self.finished.load(Ordering::SeqCst)
    }
}

/// Copy one stream to its file, stopping at the cap but never stopping reading.
///
/// The "never stopping reading" half is the one that matters: a pipe nobody
/// drains fills, and a command blocked writing to a full pipe hangs until the
/// timeout kills it. A caller would see a command that printed too much
/// reported as a timeout, which is a wrong answer rather than a bounded one.
///
/// A source that is absent, or a stream file that cannot be named, yields a
/// `Pump` that is already finished — the output is lost but the command is not,
/// and the wait loop still runs. Only the OS refusing the thread is an `Err`,
/// because that is the case where the loop would not run at all; see
/// [`spawn_helper`].
fn pump<R: Read + Send + 'static>(
    source: Option<R>,
    spool: &Spool,
    id: &str,
    stream: LogStream,
    cap: u64,
) -> std::io::Result<Pump> {
    let truncated = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let pump = Pump {
        truncated: Arc::clone(&truncated),
        finished: Arc::clone(&finished),
    };

    let Some(mut source) = source else {
        finished.store(true, Ordering::SeqCst);
        return Ok(pump);
    };
    let Ok(path) = spool.stream_path(id, stream) else {
        finished.store(true, Ordering::SeqCst);
        return Ok(pump);
    };

    spawn_helper(move || {
        let mut written: u64 = 0;
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).ok();
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = match source.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            let room = cap.saturating_sub(written);
            if room == 0 {
                truncated.store(true, Ordering::SeqCst);
                // Read on regardless. Discarding is what keeps the command
                // running; refusing to read is what hangs it.
                continue;
            }
            let take = (read as u64).min(room) as usize;
            if take < read {
                truncated.store(true, Ordering::SeqCst);
            }
            if let Some(file) = file.as_mut()
                && file.write_all(&buffer[..take]).is_err()
            {
                // The output is gone, but the command must not be.
                truncated.store(true, Ordering::SeqCst);
            }
            written += take as u64;
        }
        if let Some(file) = file.as_mut() {
            let _ = file.flush();
        }
        finished.store(true, Ordering::SeqCst);
    })?;

    Ok(pump)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::ExitStatus;

    thread_local! {
        /// Which helper thread this supervisor is to be refused, if any.
        ///
        /// Thread-local rather than global so the injection cannot leak into
        /// tests running in parallel in the same binary: only the thread
        /// calling [`supervise`] consults it, and that is the test's own.
        static REFUSE_HELPER_AT: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
        static HELPERS_STARTED: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    /// Whether [`spawn_helper`] should behave as an OS out of threads.
    pub(super) fn helper_thread_is_refused() -> bool {
        let index = HELPERS_STARTED.with(|started| {
            let index = started.get();
            started.set(index + 1);
            index
        });
        REFUSE_HELPER_AT.with(|at| at.get()) == Some(index)
    }

    /// Refuse the `index`-th helper thread this thread's supervisor starts.
    ///
    /// Real thread exhaustion cannot be provoked from a test without putting
    /// the whole test binary under the same PID pressure, which would break
    /// every other test in it. This reproduces the one thing that matters —
    /// the refusal reaching the supervisor after the command is already
    /// running — at exactly the call site the OS would refuse.
    fn refuse_helper_thread(index: u32) {
        REFUSE_HELPER_AT.with(|at| at.set(Some(index)));
        HELPERS_STARTED.with(|started| started.set(0));
    }

    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "kobe-supervisor-test-{}-{}-{}",
                std::process::id(),
                now_unix_ms(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A command that outlives the supervisor is never left running.
    ///
    /// The child is spawned before any helper thread exists, in a session of
    /// its own, and dropping Rust's `Child` does not kill it. So a supervisor
    /// that dies between those two points — which is what an OS refusing a
    /// thread used to do — leaves a command with no deadline, no cancellation
    /// and nobody to reap it, on CPU a lease is still paying for. The marker
    /// file is the proof: it is written after this test has finished waiting,
    /// so it can only exist if the command survived.
    #[test]
    fn a_refused_helper_thread_never_leaves_the_command_running() {
        // The feeder is helper 0; the stdout and stderr pumps are 1 and 2. All
        // three run after the spawn, so all three have to be covered.
        for refused in [0u32, 1, 2] {
            let scratch = Scratch::new();
            let spool = Spool::new(scratch.0.clone());
            let id = "sbxe-refused";
            let marker = scratch.0.join(format!("outlived-{refused}"));

            let request = StartRequest {
                protocol: crate::protocol::PROTOCOL_VERSION,
                id: id.into(),
                argv: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    format!("sleep 3; : > {}", marker.display()),
                ],
                cwd: None,
                timeout_seconds: 60,
                max_output_bytes: 4096,
                stdin_base64: None,
            };
            spool.reserve(&request).unwrap();

            let secret = b"ghp_the_supervisor_holds_this".to_vec();
            refuse_helper_thread(refused);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                supervise(&spool, id, Some(secret.len()), secret.as_slice());
            }));
            REFUSE_HELPER_AT.with(|at| at.set(None));

            assert!(
                outcome.is_ok(),
                "helper {refused} being refused unwound out of the supervisor"
            );

            // Terminal, and honest about which end it came from: the command
            // may well have done work before it was torn down, so `Unknown` is
            // the only state that does not invite a blind retry.
            let report = spool.read_report(id).unwrap();
            assert_eq!(
                report.state,
                RunnerState::Unknown,
                "helper {refused}: {report:?}"
            );
            assert_eq!(
                report.reason.as_deref(),
                Some(reason::SUPERVISOR_SETUP_FAILED),
                "helper {refused}: {report:?}"
            );

            // Past the command's own 3 seconds. If it was still running, this
            // is where it would have written the marker.
            std::thread::sleep(Duration::from_secs(4));
            assert!(
                !marker.exists(),
                "helper {refused} being refused left the command running to completion"
            );
        }
    }

    /// An outcome nobody observed is `Unknown`, never `Failed`.
    ///
    /// `Failed` reads as "it ran and said no", which tells a caller their retry
    /// is safe. If the runner could not reap the process, the command may have
    /// done all of its work — and running it again is precisely the damage this
    /// whole design exists to prevent.
    #[test]
    fn an_unobserved_outcome_is_unknown_rather_than_failed() {
        let report = settle_report("sbxe-1", 1, None, None, false, false);
        assert_eq!(report.state, RunnerState::Unknown);
        assert_eq!(report.exit_code, None);
        assert_eq!(report.signal, None);
        assert_eq!(report.reason.as_deref(), Some(reason::OUTCOME_UNOBSERVED));
    }

    /// A command the runner killed is reported by why, and carries no exit
    /// code.
    ///
    /// The process did not choose an outcome — the runner imposed one. An exit
    /// code here would assert something nobody observed, and 128+SIGKILL is
    /// indistinguishable from a command that deliberately exited 137.
    #[test]
    fn a_command_the_runner_killed_reports_why_and_not_an_exit_code() {
        for (ended_by, expected) in [
            (reason::CANCELLED, RunnerState::Cancelled),
            (reason::TIMED_OUT, RunnerState::TimedOut),
        ] {
            let report = settle_report(
                "sbxe-1",
                1,
                Some(ExitStatus::from_raw(9)),
                Some(ended_by),
                false,
                false,
            );
            assert_eq!(report.state, expected);
            assert_eq!(report.exit_code, None, "{ended_by} must not carry a code");
            assert_eq!(report.reason.as_deref(), Some(ended_by));
        }
    }

    /// An exit code is only ever the one the process chose.
    ///
    /// Zero is a success and anything else is a command that ran and said no —
    /// a caller's own failing test, not an infrastructure fault, and emphatically
    /// not something to retry on their behalf.
    #[test]
    fn an_exit_code_is_reported_exactly_as_the_process_gave_it() {
        // `from_raw` takes a wait status: the code sits in the high byte.
        let exited = |code: i32| ExitStatus::from_raw(code << 8);

        let success = settle_report("sbxe-1", 1, Some(exited(0)), None, false, false);
        assert_eq!(success.state, RunnerState::Succeeded);
        assert_eq!(success.exit_code, Some(0));

        for code in [1, 2, 127, 137, 255] {
            let report = settle_report("sbxe-1", 1, Some(exited(code)), None, false, false);
            assert_eq!(report.state, RunnerState::Failed, "exit {code}");
            assert_eq!(report.exit_code, Some(code));
            assert_eq!(report.signal, None);
        }
    }

    /// A process killed by something else is a failure that says which signal.
    ///
    /// An OOM kill definitely ran and definitely did not finish. Reporting it
    /// as exit code 137 would make it indistinguishable from a command that
    /// deliberately exited 137, which is a different thing that needs a
    /// different response.
    #[test]
    fn a_foreign_signal_is_a_failure_that_names_the_signal() {
        let report = settle_report(
            "sbxe-1",
            1,
            Some(ExitStatus::from_raw(libc::SIGKILL)),
            None,
            false,
            false,
        );
        assert_eq!(report.state, RunnerState::Failed);
        assert_eq!(report.exit_code, None, "no code was ever chosen");
        assert_eq!(report.signal, Some(libc::SIGKILL));
        assert_eq!(report.reason.as_deref(), Some(reason::SIGNALLED));
    }

    /// Truncation survives into the outcome.
    ///
    /// The report is the only place a caller can learn that output was capped;
    /// a flag that were dropped here would turn a bounded read into a silently
    /// wrong one.
    #[test]
    fn a_capped_stream_is_still_capped_in_the_outcome() {
        let report = settle_report(
            "sbxe-1",
            1,
            Some(ExitStatus::from_raw(0)),
            None,
            true,
            false,
        );
        assert!(report.stdout_truncated);
        assert!(!report.stderr_truncated);
    }

    /// Every reason a report can carry is a short, fixed code.
    ///
    /// Kobe persists this value into a Kubernetes object. A message built from
    /// anything inside the container — a path, an error string, a line of the
    /// command's own output — would put tenant data somewhere the tenant cannot
    /// see and cannot redact.
    #[test]
    fn every_reason_is_a_short_fixed_code() {
        for code in [
            reason::COMPLETED,
            reason::TIMED_OUT,
            reason::CANCELLED,
            reason::SIGNALLED,
            reason::SPAWN_FAILED,
            reason::OUTCOME_UNOBSERVED,
        ] {
            assert!(code.len() <= 64, "{code} is too long for a status field");
            assert!(
                code.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "{code} is not a bounded reason code"
            );
        }
    }
}
