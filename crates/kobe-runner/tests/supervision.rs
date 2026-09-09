//! What the runner promises, exercised against the real binary.
//!
//! These drive `kobe-runner` as a subprocess — the same way Kobe drives it over
//! an exec — because every property that matters here is a property of
//! *processes*: sessions, process groups, signals, and a supervisor that has to
//! still be there after its parent is gone. None of that can be asserted about
//! a function call.
//!
//! What they cannot cover is the exec transport itself. A container is required
//! to show that the supervisor survives the *kubelet* tearing down an exec, as
//! opposed to surviving its parent exiting. The mechanism is the same — a
//! session of its own — but the demonstration is not.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kobe_runner::protocol::{Envelope, ExecutionReport, PROTOCOL_VERSION, Reply, RunnerState};

/// A scratch directory that cleans itself up.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "kobe-runner-it-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn runner(scratch: &Scratch, arguments: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kobe-runner"));
    command
        .arg("--state-dir")
        .arg(scratch.path().join("spool"))
        .args(arguments);
    command
}

fn reply(output: std::process::Output) -> Reply {
    let stdout = String::from_utf8(output.stdout).expect("a reply is valid UTF-8");
    let envelope: Envelope = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|error| panic!("unparseable reply {stdout:?}: {error}"));
    assert_eq!(envelope.protocol, PROTOCOL_VERSION);
    envelope.reply
}

fn start(scratch: &Scratch, id: &str, argv: &[&str], timeout: u64, cap: u64) -> Reply {
    start_in(scratch, id, argv, None, timeout, cap)
}

fn start_in(
    scratch: &Scratch,
    id: &str,
    argv: &[&str],
    cwd: Option<&str>,
    timeout: u64,
    cap: u64,
) -> Reply {
    reply(start_output(
        scratch,
        &["start"],
        id,
        argv,
        cwd,
        timeout,
        cap,
    ))
}

/// Start a command with bytes for its own stdin.
///
/// Kept apart from [`start`] so the ordinary path keeps sending exactly the
/// request a released runner would accept: with nobody asking for stdin, the
/// key must be absent rather than null.
fn start_with_stdin(
    scratch: &Scratch,
    id: &str,
    argv: &[&str],
    stdin: &[u8],
    timeout: u64,
    cap: u64,
) -> Reply {
    use base64::Engine;

    reply(start_output_with_stdin(
        scratch,
        &["start"],
        id,
        argv,
        None,
        timeout,
        cap,
        Some(base64::engine::general_purpose::STANDARD.encode(stdin)),
    ))
}

fn start_output(
    scratch: &Scratch,
    runner_arguments: &[&str],
    id: &str,
    argv: &[&str],
    cwd: Option<&str>,
    timeout: u64,
    cap: u64,
) -> std::process::Output {
    start_output_with_stdin(scratch, runner_arguments, id, argv, cwd, timeout, cap, None)
}

#[allow(clippy::too_many_arguments)]
fn start_output_with_stdin(
    scratch: &Scratch,
    runner_arguments: &[&str],
    id: &str,
    argv: &[&str],
    cwd: Option<&str>,
    timeout: u64,
    cap: u64,
    stdin_base64: Option<String>,
) -> std::process::Output {
    use std::io::Write;

    let request = serde_json::json!({
        "protocol": PROTOCOL_VERSION,
        "id": id,
        "argv": argv,
        "cwd": cwd,
        "timeoutSeconds": timeout,
        "maxOutputBytes": cap,
    });
    // `cwd: null` is not the same as an absent key for a `deny_unknown_fields`
    // struct with an Option — serde accepts both, and this keeps the helper
    // honest about which one it sends.
    let mut request = request;
    if cwd.is_none() {
        request.as_object_mut().unwrap().remove("cwd");
    }
    // Absent when unused, for the same reason: this is the shape an older
    // runner has to keep accepting.
    if let Some(stdin_base64) = stdin_base64 {
        request
            .as_object_mut()
            .unwrap()
            .insert("stdinBase64".into(), stdin_base64.into());
    }

    let mut child = runner(scratch, runner_arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = request.to_string();
    line.push('\n');
    child
        .stdin
        .take()
        .unwrap()
        .write_all(line.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn status(scratch: &Scratch, id: &str) -> Reply {
    reply(runner(scratch, &["status", "--id", id]).output().unwrap())
}

fn report_of(reply: Reply) -> ExecutionReport {
    match reply {
        Reply::Started { report } | Reply::State { report } => report,
        other => panic!("expected a report, got {other:?}"),
    }
}

/// Poll until the execution settles, or give up.
fn settled(scratch: &Scratch, id: &str, within: Duration) -> ExecutionReport {
    let deadline = Instant::now() + within;
    loop {
        let report = report_of(status(scratch, id));
        if report.state.is_terminal() {
            return report;
        }
        assert!(
            Instant::now() < deadline,
            "execution {id} never settled: {report:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn read_stream(scratch: &Scratch, id: &str, stream: &str) -> Vec<u8> {
    use base64::Engine;

    let mut collected = Vec::new();
    let mut offset = 0u64;
    loop {
        let reply = reply(
            runner(
                scratch,
                &[
                    "logs",
                    "--id",
                    id,
                    "--stream",
                    stream,
                    "--offset",
                    &offset.to_string(),
                ],
            )
            .output()
            .unwrap(),
        );
        let Reply::Logs { chunk } = reply else {
            panic!("expected a log chunk, got {reply:?}");
        };
        collected.extend(
            base64::engine::general_purpose::STANDARD
                .decode(&chunk.data_base64)
                .unwrap(),
        );
        if !chunk.more {
            return collected;
        }
        offset = chunk.next_offset;
    }
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 checks existence and permission without delivering
    // anything.
    if unsafe { libc::kill(pid, 0) != 0 } {
        return false;
    }
    // Nothing in a CI container reaps orphans, so a SIGKILLed process can
    // linger as a zombie that kill(2) still acknowledges. A zombie runs
    // nothing: treat it as gone, exactly like the runner's own liveness check.
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            stat.rsplit_once(')')
                .and_then(|(_, rest)| rest.trim_start().chars().next())
                != Some('Z')
        }
        Err(_) => true,
    }
}

fn wait_for_pid(pidfile: &Path) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(raw) = std::fs::read_to_string(pidfile)
            && let Ok(pid) = raw.trim().parse::<i32>()
        {
            return pid;
        }
        assert!(Instant::now() < deadline, "the descendant never started");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn assert_process_gone(pid: i32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while alive(pid) {
        assert!(
            Instant::now() < deadline,
            "descendant {pid} survived process-group termination"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The command outlives the process that started it.
///
/// This is the entire point of the runner. A "detached" execution that dies
/// with the connection that launched it is worse than none at all: the caller
/// has already built on a guarantee that was never there, and will discover it
/// only from the work that did not happen.
#[test]
fn a_started_command_outlives_the_process_that_started_it() {
    let scratch = Scratch::new();
    let marker = scratch.path().join("finished");
    let release = scratch.path().join("allow-finish");

    let report = report_of(start(
        &scratch,
        "sbxe-detached",
        &[
            "/bin/sh",
            "-c",
            &format!(
                "while [ ! -f {} ]; do sleep 0.05; done; touch {}",
                release.display(),
                marker.display()
            ),
        ],
        30,
        4096,
    ));
    // The caller chose to run a shell. Kobe never inserts one — that is the
    // difference this contract keeps.
    assert_eq!(report.state, RunnerState::Running);

    // `start` has already exited by the time we get here: the command has not.
    assert!(!marker.exists(), "the command must not have finished yet");
    std::fs::write(release, b"finish").unwrap();

    let settled = settled(&scratch, "sbxe-detached", Duration::from_secs(20));
    assert_eq!(settled.state, RunnerState::Succeeded);
    assert!(marker.exists(), "the command must have run to completion");
}

/// stdout and stderr stay apart, and the exit code is the process's own.
///
/// A caller that cannot separate a tool's diagnostics from its output cannot
/// parse either, and an exit code that Kobe synthesised would be
/// indistinguishable from one the command chose.
#[test]
fn the_two_streams_and_the_exact_exit_code_survive_the_round_trip() {
    let scratch = Scratch::new();
    start(
        &scratch,
        "sbxe-streams",
        &[
            "/bin/sh",
            "-c",
            "echo to-stdout; echo to-stderr >&2; exit 7",
        ],
        30,
        4096,
    );

    let report = settled(&scratch, "sbxe-streams", Duration::from_secs(20));
    assert_eq!(report.state, RunnerState::Failed);
    assert_eq!(report.exit_code, Some(7), "the exact code, not a synonym");
    assert_eq!(report.signal, None);

    assert_eq!(
        read_stream(&scratch, "sbxe-streams", "stdout"),
        b"to-stdout\n"
    );
    assert_eq!(
        read_stream(&scratch, "sbxe-streams", "stderr"),
        b"to-stderr\n"
    );
}

/// One id runs one command, however many times it is started.
///
/// A retried `start` is the normal consequence of a dropped connection. If the
/// second one spawned, every disconnect during a `terraform apply` would apply
/// it twice — which is the failure the whole reserve-then-spawn design exists
/// to prevent, and it has to hold on the runner's side of the boundary too.
#[test]
fn one_id_runs_one_command_however_often_it_is_started() {
    let scratch = Scratch::new();
    let ledger = scratch.path().join("ledger");
    let argv = [
        "/bin/sh",
        "-c",
        &format!("echo ran >> {}", ledger.display()),
    ];
    let argv: Vec<&str> = argv.to_vec();

    for _ in 0..3 {
        let report = report_of(start(&scratch, "sbxe-once", &argv, 30, 4096));
        assert_eq!(report.id, "sbxe-once");
    }
    settled(&scratch, "sbxe-once", Duration::from_secs(20));
    // Give any (wrongly) duplicated spawn time to append as well.
    std::thread::sleep(Duration::from_millis(300));

    let ledger = std::fs::read_to_string(&ledger).unwrap_or_default();
    assert_eq!(
        ledger.lines().count(),
        1,
        "the command ran more than once: {ledger:?}"
    );
}

/// A hard exit after the target-side reservation but before spawn releases the
/// reservation owner lock. The first exact retry settles the original runner
/// record Unknown; later retries return that byte-for-byte report and no retry
/// ever manufactures the command.
#[test]
fn a_reserved_command_whose_starter_crashed_is_never_spawned() {
    let scratch = Scratch::new();
    let ledger = scratch.path().join("before-spawn-ledger");
    let script = format!("echo ran >> {}", ledger.display());
    let argv = ["/bin/sh", "-c", script.as_str()];
    let output = start_output(
        &scratch,
        &["start", kobe_runner::protocol::TEST_EXIT_BEFORE_SPAWN_FLAG],
        "sbxe-before-spawn",
        &argv,
        None,
        30,
        4096,
    );
    assert_eq!(
        output.status.code(),
        Some(kobe_runner::protocol::TEST_EXECUTION_CRASH_EXIT_CODE)
    );
    assert!(
        output.stdout.is_empty(),
        "the crash wrote an acknowledgement"
    );

    let first = report_of(start(&scratch, "sbxe-before-spawn", &argv, 30, 4096));
    assert_eq!(first.state, RunnerState::Unknown);
    assert_eq!(
        first.reason.as_deref(),
        Some(kobe_runner::protocol::reason::SUPERVISOR_NOT_STARTED)
    );
    let second = report_of(start(&scratch, "sbxe-before-spawn", &argv, 30, 4096));
    assert_eq!(second, first, "the recovered Unknown must be stable");
    assert!(!ledger.exists(), "the pre-spawn command ran");
}

/// The injected lost-ack window occurs after the runner's durable reservation
/// and supervisor spawn, but before one reply byte. Retrying the ordinary start
/// must observe that same process rather than spawning the side effect again.
#[test]
fn a_lost_start_acknowledgement_still_spawns_exactly_once() {
    let scratch = Scratch::new();
    let ledger = scratch.path().join("lost-ack-ledger");
    let script = format!("echo ran >> {}; sleep 1", ledger.display());
    let argv = ["/bin/sh", "-c", script.as_str()];
    let output = start_output(
        &scratch,
        &[
            "start",
            kobe_runner::protocol::TEST_EXIT_AFTER_SPAWN_BEFORE_ACK_FLAG,
        ],
        "sbxe-lost-ack",
        &argv,
        None,
        30,
        4096,
    );
    assert_eq!(
        output.status.code(),
        Some(kobe_runner::protocol::TEST_EXECUTION_CRASH_EXIT_CODE)
    );
    assert!(
        output.stdout.is_empty(),
        "the lost acknowledgement wrote bytes"
    );

    let retried = report_of(start(&scratch, "sbxe-lost-ack", &argv, 30, 4096));
    assert_eq!(retried.id, "sbxe-lost-ack");
    let terminal = settled(&scratch, "sbxe-lost-ack", Duration::from_secs(20));
    let repeated = report_of(start(&scratch, "sbxe-lost-ack", &argv, 30, 4096));
    assert_eq!(repeated, terminal, "the retained outcome must be stable");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        std::fs::read_to_string(ledger)
            .unwrap_or_default()
            .lines()
            .count(),
        1
    );
}

/// A killed supervisor leaves the verdict Unknown and does not manufacture
/// process-absence proof. Lease teardown must preserve this report until
/// destroying the exact target supplies that proof.
#[test]
fn a_lost_supervisor_is_unknown_without_process_absence_proof() {
    let scratch = Scratch::new();
    let command_pidfile = scratch.path().join("lost-supervisor-command.pid");
    let script = format!("echo $$ > {}; sleep 60", command_pidfile.display());
    let report = report_of(start(
        &scratch,
        "sbxe-lost-supervisor",
        &["/bin/sh", "-c", &script],
        60,
        4096,
    ));
    assert_eq!(report.state, RunnerState::Running);
    let command_pid = wait_for_pid(&command_pidfile);
    let supervisor_pid = wait_for_pid(
        &scratch
            .path()
            .join("spool/sbxe-lost-supervisor/supervisor.pid"),
    );

    // SAFETY: both pids came from this test's private spool/process. SIGKILL is
    // intentional failure injection; the command group is cleaned below.
    assert_eq!(unsafe { libc::kill(supervisor_pid, libc::SIGKILL) }, 0);
    let deadline = Instant::now() + Duration::from_secs(10);
    while alive(supervisor_pid) {
        assert!(
            Instant::now() < deadline,
            "the supervisor never disappeared"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let unknown = report_of(status(&scratch, "sbxe-lost-supervisor"));
    assert_eq!(unknown.state, RunnerState::Unknown);
    assert_eq!(
        unknown.reason.as_deref(),
        Some(kobe_runner::protocol::reason::SUPERVISOR_LOST)
    );
    assert!(
        alive(command_pid),
        "Unknown must not claim the command vanished"
    );

    // SAFETY: the command is its own session/process-group leader by contract.
    unsafe { libc::kill(-command_pid, libc::SIGKILL) };
    assert_process_gone(command_pid);
}

/// The workload UID can make a live execution look absent.
///
/// This is why Kobe must never translate runner `NotFound` into fresh spawn
/// authority after its own Running checkpoint. The process and side effect
/// remain while both an unlinked state file and a renamed reservation make the
/// control verb unable to observe them.
#[test]
fn unlinking_and_renaming_spool_never_make_a_live_process_absent() {
    let scratch = Scratch::new();
    let ledger = scratch.path().join("tamper-missing-ledger");
    let pidfile = scratch.path().join("tamper-missing.pid");
    let script = format!(
        "echo ran >> {}; echo $$ > {}; sleep 60",
        ledger.display(),
        pidfile.display()
    );
    let report = report_of(start(
        &scratch,
        "sbxe-tamper-missing",
        &["/bin/sh", "-c", &script],
        60,
        4096,
    ));
    assert_eq!(report.state, RunnerState::Running);
    let command_pid = wait_for_pid(&pidfile);
    let spool = scratch.path().join("spool/sbxe-tamper-missing");

    std::fs::remove_file(spool.join("state.json")).unwrap();
    assert!(matches!(
        status(&scratch, "sbxe-tamper-missing"),
        Reply::Error {
            code: kobe_runner::protocol::RunnerErrorCode::NotFound
        }
    ));
    assert!(
        alive(command_pid),
        "unlinking state did not stop the command"
    );

    std::fs::rename(&spool, scratch.path().join("spool/hidden-by-workload")).unwrap();
    assert!(matches!(
        status(&scratch, "sbxe-tamper-missing"),
        Reply::Error {
            code: kobe_runner::protocol::RunnerErrorCode::NotFound
        }
    ));
    assert!(
        alive(command_pid),
        "NotFound coexists with the live command"
    );
    assert_eq!(
        std::fs::read_to_string(&ledger)
            .unwrap_or_default()
            .lines()
            .count(),
        1,
        "observation of missing state must not manufacture another spawn"
    );

    // SAFETY: the pid came from this test's private command session.
    unsafe { libc::kill(-command_pid, libc::SIGKILL) };
    assert_process_gone(command_pid);
}

/// Request, state, logs, locks, and cancellation are all workload-writable.
///
/// A forged terminal reply can coexist with the original live process. The
/// runner still honours a forged cancel marker because it shares this control
/// directory, but Kobe must treat neither observation as process-absence proof;
/// only destruction of the exact target has that authority.
#[test]
fn forged_spool_terminal_and_cancel_can_coexist_with_the_original_process() {
    let scratch = Scratch::new();
    let ledger = scratch.path().join("tamper-forged-ledger");
    let pidfile = scratch.path().join("tamper-forged.pid");
    let script = format!(
        "echo ran >> {}; echo $$ > {}; sleep 60",
        ledger.display(),
        pidfile.display()
    );
    report_of(start(
        &scratch,
        "sbxe-tamper-forged",
        &["/bin/sh", "-c", &script],
        60,
        4096,
    ));
    let command_pid = wait_for_pid(&pidfile);
    let spool = scratch.path().join("spool/sbxe-tamper-forged");

    std::fs::write(
        spool.join("request.json"),
        br#"{"protocol":1,"id":"sbxe-tamper-forged","argv":["/bin/false"],"timeoutSeconds":1,"maxOutputBytes":1}"#,
    )
    .unwrap();
    std::fs::remove_file(spool.join("state.lock")).unwrap();
    std::fs::File::create(spool.join("state.lock")).unwrap();
    std::fs::write(
        spool.join("state.json"),
        serde_json::to_vec(&ExecutionReport {
            id: "sbxe-tamper-forged".into(),
            state: RunnerState::Succeeded,
            exit_code: Some(0),
            reason: Some(kobe_runner::protocol::reason::COMPLETED.into()),
            ..Default::default()
        })
        .unwrap(),
    )
    .unwrap();
    std::fs::write(spool.join("stdout.log"), b"forged-output\n").unwrap();

    let forged = report_of(status(&scratch, "sbxe-tamper-forged"));
    assert_eq!(forged.state, RunnerState::Succeeded);
    assert_eq!(forged.exit_code, Some(0));
    assert_eq!(
        read_stream(&scratch, "sbxe-tamper-forged", "stdout"),
        b"forged-output\n"
    );
    assert!(
        alive(command_pid),
        "a forged terminal report is not process absence"
    );

    std::fs::File::create(spool.join("cancel")).unwrap();
    assert_process_gone(command_pid);
    let retained = report_of(status(&scratch, "sbxe-tamper-forged"));
    assert_eq!(
        retained, forged,
        "the workload-forged terminal remains indistinguishable from a runner outcome"
    );
    assert_eq!(
        std::fs::read_to_string(ledger)
            .unwrap_or_default()
            .lines()
            .count(),
        1
    );
}

/// A different command under a used id is refused, never run.
///
/// Running it would give the caller two commands where they asked for one, and
/// returning the first one's result would answer a question they did not ask.
#[test]
fn a_reused_id_with_a_different_command_is_refused() {
    let scratch = Scratch::new();
    start(
        &scratch,
        "sbxe-taken",
        &["/bin/sh", "-c", "exit 0"],
        30,
        4096,
    );

    let reply = start(
        &scratch,
        "sbxe-taken",
        &["/bin/sh", "-c", "exit 1"],
        30,
        4096,
    );
    assert!(
        matches!(
            reply,
            Reply::Error {
                code: kobe_runner::protocol::RunnerErrorCode::Conflict
            }
        ),
        "expected a conflict, got {reply:?}"
    );
}

/// Cancelling kills the process group, not just the process.
///
/// A build script that spawned four compilers and exited leaves those compilers
/// running — on CPU the lease is paying for, inside a Pod that is being torn
/// down. Signalling the leader alone would report a clean cancellation while
/// the actual work carried on.
#[test]
fn cancelling_kills_the_whole_process_group() {
    let scratch = Scratch::new();
    let pidfile = scratch.path().join("grandchild.pid");
    let script = format!("sleep 60 & echo $! > {}; wait", pidfile.display());
    start(
        &scratch,
        "sbxe-group",
        &["/bin/sh", "-c", &script],
        60,
        4096,
    );

    // Wait for the grandchild to exist before cancelling anything.
    let grandchild = wait_for_pid(&pidfile);
    assert!(alive(grandchild), "the grandchild must be running");

    let report = report_of(reply(
        runner(&scratch, &["cancel", "--id", "sbxe-group"])
            .output()
            .unwrap(),
    ));
    assert_eq!(report.state, RunnerState::Cancelled);
    assert_eq!(
        report.exit_code, None,
        "a cancelled command chose no outcome"
    );

    // The descendant that nobody signalled directly is gone too.
    assert_process_gone(grandchild);
}

/// A successful leader exit is not successful group completion.
///
/// Build scripts commonly background workers. The leader's zero exit status
/// is retained, but the execution must not settle until those workers are gone.
#[test]
fn successful_leader_exit_drains_the_whole_process_group() {
    let scratch = Scratch::new();
    let pidfile = scratch.path().join("successful-background-child.pid");
    let script = format!(
        "sh -c 'trap \"\" TERM HUP; echo $$ > {}; while :; do sleep 60; done' & while [ ! -s {} ]; do sleep 0.05; done; exit 0",
        pidfile.display(),
        pidfile.display()
    );
    start(
        &scratch,
        "sbxe-successful-group-drain",
        &["/bin/sh", "-c", &script],
        60,
        4096,
    );

    let descendant = wait_for_pid(&pidfile);
    let report = settled(
        &scratch,
        "sbxe-successful-group-drain",
        Duration::from_secs(20),
    );
    assert_eq!(report.state, RunnerState::Succeeded);
    assert_eq!(report.exit_code, Some(0));
    assert_eq!(report.reason.as_deref(), Some("completed"));
    assert_process_gone(descendant);
}

/// Cancellation escalates even when the leader exits before its descendant.
///
/// The inner shell deliberately ignores SIGTERM. The outer session leader
/// exits on SIGTERM, reproducing the case where treating leader exit as group
/// exit leaked the remaining command.
#[test]
fn cancelling_escalates_after_the_leader_exits_first() {
    let scratch = Scratch::new();
    let pidfile = scratch.path().join("term-ignoring-child.pid");
    let script = format!(
        "sh -c 'trap \"\" TERM; echo $$ > {}; while :; do sleep 60; done' & trap 'exit 0' TERM; wait",
        pidfile.display()
    );
    start(
        &scratch,
        "sbxe-group-escalate",
        &["/bin/sh", "-c", &script],
        60,
        4096,
    );

    let descendant = wait_for_pid(&pidfile);
    assert!(alive(descendant), "the descendant must be running");

    let _ = reply(
        runner(&scratch, &["cancel", "--id", "sbxe-group-escalate"])
            .output()
            .unwrap(),
    );
    let report = settled(&scratch, "sbxe-group-escalate", Duration::from_secs(20));
    assert_eq!(report.state, RunnerState::Cancelled);
    assert_eq!(report.reason.as_deref(), Some("cancelled_by_caller"));
    assert_process_gone(descendant);
}

/// Timeout uses the same proven process-group teardown as cancellation.
#[test]
fn timeout_escalates_after_the_leader_exits_first() {
    let scratch = Scratch::new();
    let pidfile = scratch.path().join("timed-out-child.pid");
    let script = format!(
        "sh -c 'trap \"\" TERM; echo $$ > {}; while :; do sleep 60; done' & trap 'exit 0' TERM; wait",
        pidfile.display()
    );
    start(
        &scratch,
        "sbxe-timeout-escalate",
        &["/bin/sh", "-c", &script],
        1,
        4096,
    );

    let descendant = wait_for_pid(&pidfile);
    assert!(alive(descendant), "the descendant must be running");

    let report = settled(&scratch, "sbxe-timeout-escalate", Duration::from_secs(20));
    assert_eq!(report.state, RunnerState::TimedOut);
    assert_eq!(report.reason.as_deref(), Some("timed_out"));
    assert_process_gone(descendant);
}

/// A command that outruns its bound is stopped, and says so.
///
/// `TimedOut` and not `Failed`: the command did not decide anything, and a
/// caller reading `Failed` would take it as their own program's verdict.
#[test]
fn a_command_that_outruns_its_bound_is_terminated_and_reported() {
    let scratch = Scratch::new();
    start(&scratch, "sbxe-timeout", &["/bin/sleep", "60"], 1, 4096);

    let report = settled(&scratch, "sbxe-timeout", Duration::from_secs(30));
    assert_eq!(report.state, RunnerState::TimedOut);
    assert_eq!(report.exit_code, None, "nothing chose an exit code");
    assert_eq!(report.reason.as_deref(), Some("timed_out"));
}

/// Output is capped, the cap is reported, and the command still finishes.
///
/// The second half is the one that is easy to get wrong: a runner that stops
/// reading a full pipe leaves the command blocked in `write`, so a command that
/// merely printed too much would be reported as a timeout — a wrong answer
/// rather than a bounded one.
#[test]
fn output_past_the_cap_is_dropped_reported_and_not_fatal() {
    let scratch = Scratch::new();
    let cap = 4096u64;
    start(
        &scratch,
        "sbxe-loud",
        &[
            "/bin/sh",
            "-c",
            "i=0; while [ $i -lt 4000 ]; do echo 0123456789012345678901234567890123456789; i=$((i+1)); done",
        ],
        60,
        cap,
    );

    let report = settled(&scratch, "sbxe-loud", Duration::from_secs(30));
    assert_eq!(
        report.state,
        RunnerState::Succeeded,
        "printing too much must not stop the command finishing: {report:?}"
    );
    assert!(
        report.stdout_truncated,
        "the caller must be told output was dropped"
    );
    assert!(!report.stderr_truncated, "stderr printed nothing");

    let retained = read_stream(&scratch, "sbxe-loud", "stdout");
    assert_eq!(retained.len() as u64, cap, "retention must stop at the cap");
}

/// `cwd` is a `chdir`, and there is no shell anywhere in the contract.
///
/// Implementing it as `cd X && ...` would make quoting the security boundary —
/// against input chosen by the occupant of a sandbox that exists precisely
/// because they are not trusted.
#[test]
fn a_working_directory_is_applied_as_a_chdir() {
    let scratch = Scratch::new();
    let workdir = std::fs::canonicalize(scratch.path()).unwrap();

    start_in(
        &scratch,
        "sbxe-cwd",
        // No shell: `pwd` is executed directly, and the directory comes from
        // the kernel rather than from a string somebody concatenated.
        &["/bin/pwd"],
        Some(workdir.to_str().unwrap()),
        30,
        4096,
    );

    let report = settled(&scratch, "sbxe-cwd", Duration::from_secs(20));
    assert_eq!(report.state, RunnerState::Succeeded);
    assert_eq!(
        String::from_utf8(read_stream(&scratch, "sbxe-cwd", "stdout"))
            .unwrap()
            .trim(),
        workdir.to_str().unwrap()
    );
}

/// Output survives the command, and is still readable by offset afterwards.
///
/// A detached execution whose output vanished at exit would be unusable for its
/// only purpose: the caller is, by definition, not connected while it runs.
#[test]
fn output_is_retained_after_the_command_has_finished() {
    let scratch = Scratch::new();
    start(
        &scratch,
        "sbxe-retained",
        &["/bin/sh", "-c", "echo first; echo second"],
        30,
        4096,
    );
    settled(&scratch, "sbxe-retained", Duration::from_secs(20));

    assert_eq!(
        read_stream(&scratch, "sbxe-retained", "stdout"),
        b"first\nsecond\n"
    );
    // And again: reading does not consume.
    assert_eq!(
        read_stream(&scratch, "sbxe-retained", "stdout"),
        b"first\nsecond\n"
    );
}

/// An execution nobody started is not found — never "succeeded".
#[test]
fn an_unknown_execution_is_not_found() {
    let scratch = Scratch::new();
    let reply = status(&scratch, "sbxe-never");
    assert!(
        matches!(
            reply,
            Reply::Error {
                code: kobe_runner::protocol::RunnerErrorCode::NotFound
            }
        ),
        "expected not found, got {reply:?}"
    );
}

/// A secret reaches the process on stdin, and its stdin is then closed.
///
/// Both halves in one exercise, because `cat` proves both and neither alone is
/// the feature. If the bytes never arrive, stdout is empty. If the descriptor
/// is left open, `cat` never sees EOF, never exits, and the execution ends as a
/// timeout instead of a success — which is exactly how a caller running
/// `gh auth login --with-token` would discover a half-implemented forward.
#[test]
fn stdin_reaches_the_process_and_is_then_closed() {
    let scratch = Scratch::new();
    let secret = b"ghp_a-token-that-must-never-be-an-argument\n";

    start_with_stdin(&scratch, "sbxe-stdin", &["/bin/cat"], secret, 20, 4096);

    let report = settled(&scratch, "sbxe-stdin", Duration::from_secs(20));
    assert_eq!(
        report.state,
        RunnerState::Succeeded,
        "a process waiting on EOF must not hang: {report:?}"
    );
    assert_eq!(report.exit_code, Some(0));
    assert_eq!(read_stream(&scratch, "sbxe-stdin", "stdout"), secret);
}

/// Exact bytes, including the ones that are not text.
///
/// A credential is not required to be UTF-8. A lossy conversion anywhere on
/// this path would corrupt one in a way that surfaces as an authentication
/// failure a long way from the cause.
#[test]
fn stdin_bytes_arrive_exactly_as_they_were_sent() {
    let scratch = Scratch::new();
    let raw: Vec<u8> = (0u8..=255).collect();

    start_with_stdin(&scratch, "sbxe-stdin-bytes", &["/bin/cat"], &raw, 20, 4096);

    let report = settled(&scratch, "sbxe-stdin-bytes", Duration::from_secs(20));
    assert_eq!(report.state, RunnerState::Succeeded);
    assert_eq!(read_stream(&scratch, "sbxe-stdin-bytes", "stdout"), raw);
}

/// A maximal payload survives the whole handover intact.
///
/// The bytes cross two pipes — `start` to the supervisor, supervisor to the
/// command — and the first read is exact rather than "until EOF". A payload at
/// the documented ceiling is where a short read or a partial write would
/// actually show up, and where it would show up as a corrupted credential
/// rather than an obvious failure.
#[test]
fn a_maximal_stdin_payload_arrives_whole() {
    let scratch = Scratch::new();
    // Non-repeating, so a duplicated or dropped block cannot pass unnoticed.
    let payload: Vec<u8> = (0..kobe_runner::protocol::MAX_STDIN_BYTES)
        .map(|index| (index % 251) as u8)
        .collect();

    start_with_stdin(
        &scratch,
        "sbxe-stdin-max",
        &["/bin/cat"],
        &payload,
        30,
        1 << 20,
    );

    let report = settled(&scratch, "sbxe-stdin-max", Duration::from_secs(30));
    assert_eq!(report.state, RunnerState::Succeeded, "{report:?}");
    assert!(!report.stdout_truncated);
    assert_eq!(read_stream(&scratch, "sbxe-stdin-max", "stdout"), payload);
}

/// A command that ignores its stdin still finishes, however much was sent.
///
/// The bytes are written on a thread precisely so this cannot deadlock: a
/// payload larger than a pipe buffer, handed to a process that never reads,
/// would otherwise block the supervisor's own wait loop — and a supervisor that
/// is not looping cannot cancel, time out, or drain output.
#[test]
fn stdin_nobody_reads_never_blocks_the_supervisor() {
    let scratch = Scratch::new();
    let bulk = vec![b'x'; kobe_runner::protocol::MAX_STDIN_BYTES];

    start_with_stdin(
        &scratch,
        "sbxe-stdin-ignored",
        &["/bin/sh", "-c", "echo done"],
        &bulk,
        20,
        4096,
    );

    let report = settled(&scratch, "sbxe-stdin-ignored", Duration::from_secs(20));
    assert_eq!(report.state, RunnerState::Succeeded, "{report:?}");
    assert_eq!(
        read_stream(&scratch, "sbxe-stdin-ignored", "stdout"),
        b"done\n"
    );
}

/// Sending no stdin still means `/dev/null`, exactly as before.
///
/// The forwarding path must not change what an ordinary execution gets. A
/// command that reads stdin and was given none has to see EOF immediately, not
/// wait for a writer that will never appear.
#[test]
fn an_execution_with_no_stdin_still_reads_nothing_and_exits() {
    let scratch = Scratch::new();

    start(&scratch, "sbxe-no-stdin", &["/bin/cat"], 20, 4096);

    let report = settled(&scratch, "sbxe-no-stdin", Duration::from_secs(20));
    assert_eq!(report.state, RunnerState::Succeeded, "{report:?}");
    assert!(read_stream(&scratch, "sbxe-no-stdin", "stdout").is_empty());
}

/// The secret is never written anywhere under the spool.
///
/// This is the property the whole design exists for. stdin carries a token so
/// that it does not appear in an argv the apiserver audit-logs; writing it to a
/// filesystem the tenant's workload shares — and which outlives the command —
/// would trade one durable copy for another.
#[test]
fn stdin_is_never_written_to_the_spool() {
    let scratch = Scratch::new();
    let secret = b"ghp_never-on-disk-anywhere";

    start_with_stdin(
        &scratch,
        "sbxe-stdin-secret",
        &["/bin/sh", "-c", "exit 0"],
        secret,
        20,
        4096,
    );
    settled(&scratch, "sbxe-stdin-secret", Duration::from_secs(20));

    let encoded = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(secret.as_slice())
    };
    let mut inspected = 0usize;
    let mut pending = vec![scratch.path().to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            inspected += 1;
            let bytes = std::fs::read(&path).unwrap();
            assert!(
                !bytes.windows(secret.len()).any(|window| window == secret),
                "{} holds the raw stdin",
                path.display()
            );
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&encoded),
                "{} holds the encoded stdin",
                path.display()
            );
        }
    }
    assert!(inspected > 0, "the execution wrote nothing at all");
}

/// Stdin past the documented bound is refused, and reserves nothing.
///
/// Refused rather than trimmed: half a token is still a secret, and a command
/// that received half of its input would fail somewhere a long way from the
/// request that caused it. Refusing before the reservation is what keeps the
/// caller's id reusable.
#[test]
fn oversized_stdin_is_refused_before_anything_is_reserved() {
    let scratch = Scratch::new();
    let too_much = vec![b'x'; kobe_runner::protocol::MAX_STDIN_BYTES + 1];

    let reply = start_with_stdin(
        &scratch,
        "sbxe-stdin-too-big",
        &["/bin/cat"],
        &too_much,
        20,
        4096,
    );
    assert!(
        matches!(
            reply,
            Reply::Error {
                code: kobe_runner::protocol::RunnerErrorCode::InvalidRequest
            }
        ),
        "expected an invalid request, got {reply:?}"
    );

    // Nothing was reserved, so the id is still free rather than occupied by a
    // command that could never have run.
    let reply = status(&scratch, "sbxe-stdin-too-big");
    assert!(
        matches!(
            reply,
            Reply::Error {
                code: kobe_runner::protocol::RunnerErrorCode::NotFound
            }
        ),
        "expected not found, got {reply:?}"
    );
}
