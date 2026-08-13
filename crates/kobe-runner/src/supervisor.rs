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

use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::protocol::{ExecutionReport, LogStream, RunnerState, StartRequest};
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

/// Reason codes. A closed set, because Kobe persists these.
mod reason {
    pub const COMPLETED: &str = "completed";
    pub const TIMED_OUT: &str = "timed_out";
    pub const CANCELLED: &str = "cancelled_by_caller";
    pub const SIGNALLED: &str = "signalled";
    pub const SPAWN_FAILED: &str = "spawn_failed";
    pub const OUTCOME_UNOBSERVED: &str = "outcome_unobserved";
}

/// Supervise one reserved execution until it settles, then exit.
pub fn supervise(spool: &Spool, id: &str) {
    let request = match spool.read_request(id) {
        Ok(request) => request,
        Err(_) => {
            // Nothing to supervise and nothing to record it against. Writing a
            // report for an id whose request cannot be read would be inventing
            // one.
            return;
        }
    };

    let started_at = now_unix_ms();
    let mut child = match spawn(&request) {
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

    let stdout = pump(
        child.stdout.take(),
        spool,
        id,
        LogStream::Stdout,
        request.max_output_bytes,
    );
    let stderr = pump(
        child.stderr.take(),
        spool,
        id,
        LogStream::Stderr,
        request.max_output_bytes,
    );

    let deadline = Instant::now() + Duration::from_secs(request.timeout_seconds);
    let mut ended_by: Option<&'static str> = None;
    // Set once the group has been killed. A process that will not die even
    // after SIGKILL — blocked in an uninterruptible syscall against a wedged
    // filesystem — must not keep this supervisor polling forever, because a
    // supervisor that never exits is one that never records an outcome.
    let mut give_up_at: Option<Instant> = None;

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
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
                terminate_group(group, &mut child);
                give_up_at = Some(Instant::now() + TERMINATION_GRACE);
            }
        }
        if give_up_at.is_some_and(|at| Instant::now() >= at) {
            break None;
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

/// Start the command, in a session of its own.
fn spawn(request: &StartRequest) -> std::io::Result<Child> {
    let mut command = Command::new(&request.argv[0]);
    command.args(&request.argv[1..]);
    if let Some(cwd) = &request.cwd {
        // `chdir`, applied by the kernel at exec. Never `cd X && ...`: a shell
        // there would make quoting the security boundary, and the boundary is a
        // tenant's own untrusted input.
        command.current_dir(cwd);
    }
    // No stdin at all. A detached command has no connection to read from, and
    // an inherited terminal would let it stop on SIGTTIN and look like a hang.
    command.stdin(Stdio::null());
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

/// Terminate the process group and reap what is left.
fn terminate_group(group: i32, child: &mut Child) {
    // SAFETY: a plain `kill(2)`. The negative pid addresses the group, which is
    // the point — the leader alone leaves its children running on CPU the lease
    // is paying for.
    unsafe { libc::kill(-group, libc::SIGTERM) };

    let deadline = Instant::now() + TERMINATION_GRACE;
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
            return;
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    // Asked politely, then not. A command that traps SIGTERM and declines to
    // exit still has to stop: the lease that pays for it is ending either way.
    unsafe { libc::kill(-group, libc::SIGKILL) };
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
fn pump<R: Read + Send + 'static>(
    source: Option<R>,
    spool: &Spool,
    id: &str,
    stream: LogStream,
    cap: u64,
) -> Pump {
    let truncated = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let pump = Pump {
        truncated: Arc::clone(&truncated),
        finished: Arc::clone(&finished),
    };

    let Some(mut source) = source else {
        finished.store(true, Ordering::SeqCst);
        return pump;
    };
    let Ok(path) = spool.stream_path(id, stream) else {
        finished.store(true, Ordering::SeqCst);
        return pump;
    };

    std::thread::spawn(move || {
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
    });

    pump
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::ExitStatus;

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
