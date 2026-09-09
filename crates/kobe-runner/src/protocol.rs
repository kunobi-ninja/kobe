//! The wire contract between Kobe and the runner (#82).
//!
//! # Why this lives in a crate both sides compile
//!
//! Kobe writes these structures and the runner reads them, in different
//! processes, in different images, released on different schedules. Two
//! hand-maintained copies of a wire format drift, and the drift shows up as a
//! *misread* reply rather than a broken one — a caller told their command
//! succeeded because a field moved. One definition, compiled into both halves,
//! is what makes that impossible.
//!
//! # Why every reply carries a version
//!
//! A Sandbox image is built by an administrator and can be months older than
//! the Kobe that talks to it. A reply from an unrecognised protocol is refused
//! outright rather than parsed on a best-effort basis: guessing at an older
//! shape is how "running" gets read as "succeeded".
//!
//! # Why there is no protocol for "the output"
//!
//! Output is fetched in bounded chunks by offset, never returned whole. The
//! runner holds a tenant's output on the tenant's own disk, and Kobe reads as
//! much of it as one response may carry. An "all of it" verb would make the
//! operator's memory a function of what somebody else's command printed.

use serde::{Deserialize, Serialize};

/// The version both sides must agree on.
///
/// Bumped for every wire-shape change. Requests deliberately deny unknown
/// fields, so even an additive optional field would make a newer Kobe unable to
/// start commands through an older runner unless a new version were negotiated.
pub const PROTOCOL_VERSION: u32 = 1;

/// Longest an execution id may be, and the only shape one may take.
///
/// The id becomes a directory name under the spool root, so anything that can
/// traverse — `..`, a slash, a nul — is refused before it is ever joined onto a
/// path. Kobe's ids are `sbxe-<hex>` and fit comfortably.
pub const MAX_ID_LEN: usize = 64;

/// Longest a supervised command may be allowed to run.
///
/// Matches Kobe's own ceiling. Enforced on both sides because they fail
/// differently: Kobe's bound protects the lease, and the runner's protects a
/// container from a supervisor that outlives whatever asked for it.
pub const MAX_TIMEOUT_SECONDS: u64 = 3600;

/// Most output the runner retains, per stream.
///
/// The spool is on the ephemeral disk the whole Pod shares, and the caller
/// chooses what they run, so they choose how much it prints. Past this, output
/// is discarded and the discarding is reported.
pub const MAX_RETENTION_BYTES: u64 = 8 * 1024 * 1024;

/// Most output one log reply may carry.
///
/// A window rather than a file: the reply crosses an exec connection and is
/// buffered by the operator, so its size must be a Kobe decision rather than a
/// consequence of how much somebody's command printed.
pub const MAX_LOG_CHUNK_BYTES: usize = 256 * 1024;

/// Largest encoded start request, including its terminating newline.
///
/// Kobe validates this before spending an execution reservation, and the
/// runner enforces the same value while reading stdin. Keeping the bound in the
/// shared wire crate prevents a rollout from accepting an execution that the
/// installed runner can only reject after its idempotency key is durable.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Most stdin one execution may carry to its process.
///
/// This is a channel for **secrets and small inputs** — a token for
/// `gh auth login --with-token`, a password, a short configuration document. It
/// is emphatically not file transfer: the bytes travel base64-encoded inside
/// the single start request that [`MAX_REQUEST_BYTES`] bounds as a whole, and
/// both Kobe and the runner hold them in memory for the duration of the spawn.
///
/// Sixteen KiB encodes to just under 22 KiB of base64, which leaves the argv,
/// the cwd and the JSON scaffolding comfortable room inside the 64 KiB request.
/// A caller who exceeds it is **refused**, never truncated: half a token is
/// still a secret, and a command that read half its input and then saw EOF
/// would fail somewhere a long way from the cause.
pub const MAX_STDIN_BYTES: usize = 16 * 1024;

/// Hidden runner flag used only by the administrator-driven #82 live gate.
///
/// The process exits after its target-side reservation is durable, but before
/// any supervisor or command process is spawned.
pub const TEST_EXIT_BEFORE_SPAWN_FLAG: &str = "--test-exit-before-spawn";

/// Hidden runner flag used only by the administrator-driven #82 live gate.
///
/// It is shared by Kobe and the runner so the failure injection cannot
/// silently stop landing on the intended boundary after one binary changes.
/// The public execution API never accepts or forwards this value.
pub const TEST_EXIT_AFTER_SPAWN_BEFORE_ACK_FLAG: &str = "--test-exit-after-spawn-before-ack";

/// Distinct hard-exit status shared by both injected runner and operator
/// crashes, so the harness can prove the intended fault actually occurred.
pub const TEST_EXECUTION_CRASH_EXIT_CODE: i32 = 86;

/// Closed runner reason codes that carry process-lifecycle meaning.
///
/// These are shared because lease cleanup may release an `Unknown` execution's
/// capacity only when the runner's exact report proves no process group can
/// remain. A string copied independently on the two sides could silently turn
/// a safety proof into an unrecognised message after an upgrade.
pub mod reason {
    pub const COMPLETED: &str = "completed";
    pub const TIMED_OUT: &str = "timed_out";
    pub const CANCELLED: &str = "cancelled_by_caller";
    pub const SIGNALLED: &str = "signalled";
    pub const SPAWN_FAILED: &str = "spawn_failed";
    pub const SUPERVISOR_NOT_STARTED: &str = "supervisor_not_started";
    pub const SUPERVISOR_SETUP_FAILED: &str = "supervisor_setup_failed";
    pub const SUPERVISOR_LOST: &str = "supervisor_lost";
    pub const OUTCOME_UNOBSERVED: &str = "outcome_unobserved";
}

/// Whether an id may name a spool directory.
///
/// Restrictive on purpose: a permissive check here is a path traversal with
/// extra steps, and the runner runs inside the tenant's own container where
/// escaping the spool means writing anywhere the workload can.
pub fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// One command, as Kobe asks for it.
///
/// Sent on the runner's **stdin**, never as command-line arguments. A tenant's
/// argv routinely carries secrets — a token in a flag, a connection string in
/// an argument — and the exec request's argv is a URL that the target
/// apiserver's audit log records verbatim. stdin is the only channel into the
/// container that nothing on the way logs.
///
/// [`StartRequest::stdin_base64`] extends that same channel one hop further, to
/// the supervised process itself, so a command that reads a credential from
/// stdin no longer has to be given one in a flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartRequest {
    pub protocol: u32,
    /// Kobe's own execution id. The runner treats it as an opaque key and
    /// never as a path fragment until [`is_valid_id`] has accepted it.
    pub id: String,
    /// Executed directly. There is no shell anywhere in this contract: a shell
    /// would make quoting the security boundary, and the boundary is a tenant's
    /// own untrusted input.
    pub argv: Vec<String>,
    /// Applied with `chdir`, never with `cd X && ...`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Wall-clock bound the runner enforces on its own, so a command outlives
    /// neither the connection that started it nor its lease.
    pub timeout_seconds: u64,
    /// Per-stream retention cap. Output past it is discarded and the fact is
    /// reported — never silently dropped.
    pub max_output_bytes: u64,
    /// Bytes to write to the process's stdin, base64, then close.
    ///
    /// The whole point of the field: a Sandbox has no other way to receive a
    /// secret. Everything else a caller can say about a command ends up in
    /// argv, and the exec request's argv is a URL the target apiserver
    /// audit-logs verbatim — so `gh auth login --with-token`, which reads its
    /// token from stdin, was previously only expressible by putting the token
    /// somewhere it would be recorded. This is the other half of the intent
    /// that already puts the request itself on the runner's stdin.
    ///
    /// Bounded by [`MAX_STDIN_BYTES`], and for secrets rather than files — see
    /// that constant for why the bound is what it is. Base64 so exact bytes
    /// survive the JSON: a token is not required to be UTF-8, and a lossy
    /// conversion here would corrupt a credential in a way nothing downstream
    /// could diagnose.
    ///
    /// **Absent when unused, and that is load-bearing.** A request that carries
    /// no stdin serialises byte-for-byte as it did before this field existed,
    /// so a released runner that denies unknown fields still accepts it. A
    /// request that *does* carry stdin is refused outright by such a runner —
    /// loudly, before anything is reserved — which is the correct failure for a
    /// Sandbox image too old to honour it. Silently dropping the field would
    /// run the command with no stdin at all and report success.
    ///
    /// Never persisted. The runner keeps it out of its spool and Kobe keeps it
    /// out of the `SandboxExecution` record; only a digest of it is durable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin_base64: Option<String>,
}

impl StartRequest {
    /// Whether two requests are the same command.
    ///
    /// Compares everything that identifies what runs, and deliberately excludes
    /// the id — a retry carries the same id anyway. Timeout remains part of the
    /// v1 identity: changing it would require either a negotiated protocol or a
    /// second authority that an older runner understands.
    ///
    /// stdin is excluded, and not by oversight. The comparison runs against the
    /// request the runner kept in its spool, and the spool deliberately does
    /// not keep the stdin bytes — see [`StartRequest::without_stdin`]. Nor
    /// could a digest stored there stand in: the spool shares a UID with the
    /// tenant's workload, which can forge every file in it. The authority that
    /// two same-key requests are the same command is Kobe's own request digest,
    /// which *does* cover stdin and is checked in the API server before this
    /// runner is ever reached.
    pub fn same_command(&self, other: &Self) -> bool {
        self.argv == other.argv
            && self.cwd == other.cwd
            && self.timeout_seconds == other.timeout_seconds
            && self.max_output_bytes == other.max_output_bytes
    }

    /// The same request with the stdin bytes removed.
    ///
    /// What the runner writes to its spool. The spool lives on a filesystem the
    /// tenant's workload shares, survives the command that needed the secret,
    /// and is read back by a separate process on every `status` and `cancel` —
    /// none of which has any use for the bytes. A secret that only ever exists
    /// in memory cannot be read out of a file later.
    pub fn without_stdin(&self) -> Self {
        Self {
            stdin_base64: None,
            ..self.clone()
        }
    }

    /// The decoded stdin bytes, or why they are unusable.
    ///
    /// `Ok(None)` means the caller asked for no stdin at all, which is not the
    /// same as asking for an empty one: the first leaves the process reading
    /// `/dev/null`, the second hands it a pipe that is immediately closed. Both
    /// see EOF, but only the second is a statement the caller made.
    ///
    /// The bound is checked on the decoded bytes rather than the encoding, so
    /// the error a caller gets names the size they actually sent.
    pub fn stdin_bytes(&self) -> Result<Option<Vec<u8>>, StdinRejected> {
        use base64::Engine;

        let Some(encoded) = self.stdin_base64.as_deref() else {
            return Ok(None);
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| StdinRejected::NotBase64)?;
        if bytes.len() > MAX_STDIN_BYTES {
            return Err(StdinRejected::TooLarge);
        }
        Ok(Some(bytes))
    }
}

/// Why stdin could not be accepted.
///
/// Two distinct reasons rather than one, because they are two different
/// mistakes: a client that encoded badly and a client that sent too much need
/// to look in different places. Neither is ever repaired by truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdinRejected {
    NotBase64,
    /// More than [`MAX_STDIN_BYTES`] once decoded.
    TooLarge,
}

/// Where one supervised command is.
///
/// Deliberately smaller than Kobe's own state machine: the runner reports only
/// what it observed, and Kobe maps that onto the record a caller reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum RunnerState {
    Running,
    /// Exited zero.
    Succeeded,
    /// Ran and exited non-zero, or was killed by something other than the
    /// runner. Emphatically not an infrastructure fault.
    Failed,
    /// The runner terminated the process group because Kobe asked it to.
    Cancelled,
    /// The runner terminated the process group because its own bound elapsed.
    TimedOut,
    /// The runner cannot establish what happened. Never `Failed`, which invites
    /// a retry of something that may have run; never `Succeeded`, which would
    /// be a lie. Also the default, so a report that lost its state says so
    /// rather than asserting an outcome nobody observed.
    #[default]
    Unknown,
}

impl RunnerState {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Running)
    }
}

/// Everything the runner knows about one execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionReport {
    pub id: String,
    /// Absent means `Unknown`: a report that lost its state must not be able to
    /// assert an outcome by omission.
    #[serde(default)]
    pub state: RunnerState,
    /// The process's exact exit code. Absent unless it actually exited — a
    /// synthesised zero would be indistinguishable from a real success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// The signal that killed it, when one did. Carried separately from
    /// `exitCode` so a death by SIGKILL can never be mistaken for a command
    /// that chose to exit 137.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    /// Milliseconds since the Unix epoch. Not a formatted timestamp: the runner
    /// has no timezone database and no business owning a date format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at_unix_ms: Option<u64>,
    /// A short code from a closed set. Never a message, never any part of the
    /// command's own output — this value is the one thing from the runner that
    /// Kobe persists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether stdout hit the retention cap. Reported rather than silently
    /// applied: a caller parsing partial output as complete is how a cap
    /// becomes a wrong answer instead of an obvious one.
    #[serde(default)]
    pub stdout_truncated: bool,
    #[serde(default)]
    pub stderr_truncated: bool,
}

/// Which stream a log read addresses.
///
/// Separate, always. A caller that cannot tell a tool's diagnostics from its
/// output cannot reliably parse either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LogStream {
    Stdout,
    Stderr,
}

impl LogStream {
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Stdout => "stdout.log",
            Self::Stderr => "stderr.log",
        }
    }
}

impl std::str::FromStr for LogStream {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "stdout" => Ok(Self::Stdout),
            "stderr" => Ok(Self::Stderr),
            _ => Err(()),
        }
    }
}

/// One bounded window of one stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogChunk {
    pub id: String,
    pub stream: LogStream,
    /// Byte offset this window starts at.
    pub offset: u64,
    /// Where the next read should start. A caller that polls with this value
    /// gets each byte exactly once, which is what makes tailing a detached
    /// execution reconnectable at all.
    pub next_offset: u64,
    /// Base64, so exact bytes survive the JSON. A command's output is arbitrary
    /// bytes, and a lossy conversion at this layer would corrupt output that a
    /// later, larger read would have shown correctly.
    pub data_base64: String,
    /// Whether the RUNNER dropped output at the retention cap. Distinct from
    /// `more`: this one is unrecoverable.
    pub truncated: bool,
    /// Whether bytes are already waiting past `next_offset`.
    pub more: bool,
}

/// Why a request could not be served.
///
/// A closed set, because Kobe persists the code and a free-form message from
/// inside a tenant's container is not something that should reach an operator's
/// records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerErrorCode {
    /// No such execution in this container.
    NotFound,
    /// The id is taken by a different command.
    Conflict,
    /// The request itself is not runnable.
    InvalidRequest,
    /// The runner failed at something that is its own job.
    Internal,
}

/// One reply. Exactly one JSON document, on stdout, and nothing else.
///
/// The runner writes diagnostics to stderr precisely so that stdout stays a
/// single parseable document: a stray line printed by a library would otherwise
/// turn every reply into a parse failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "reply")]
pub enum Reply {
    /// The command is now supervised. Returned by `start`, including when
    /// `start` found the id already reserved by the identical request.
    Started {
        report: ExecutionReport,
    },
    /// A poll.
    State {
        report: ExecutionReport,
    },
    Logs {
        chunk: Box<LogChunk>,
    },
    Error {
        code: RunnerErrorCode,
    },
}

/// A reply with the version that decides whether it may be read at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub protocol: u32,
    #[serde(flatten)]
    pub reply: Reply,
}

impl Envelope {
    pub fn new(reply: Reply) -> Self {
        Self {
            protocol: PROTOCOL_VERSION,
            reply,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An id can never name anything outside the spool.
    ///
    /// The id is joined onto a path inside the tenant's own container. A
    /// permissive check here is a path traversal with extra steps: `..` would
    /// let one execution read or overwrite another's state, and a slash would
    /// let it write anywhere the workload can.
    #[test]
    fn an_execution_id_can_never_escape_the_spool_directory() {
        assert!(is_valid_id("sbxe-0123456789abcdef"));
        assert!(is_valid_id("a"));
        assert!(is_valid_id(&"a".repeat(MAX_ID_LEN)));

        for hostile in [
            "",
            "..",
            "../etc",
            "a/b",
            "a\\b",
            "a\0b",
            "A",
            "a b",
            ".",
            "a.b",
            "~",
            "$HOME",
            &"a".repeat(MAX_ID_LEN + 1),
        ] {
            assert!(!is_valid_id(hostile), "id {hostile:?} must be refused");
        }
    }

    /// A reply from a protocol nobody agreed on is refused, not guessed at.
    ///
    /// A Sandbox image can be months older than the Kobe talking to it.
    /// Best-effort parsing of an unrecognised shape is how "running" ends up
    /// being read as "succeeded".
    #[test]
    fn a_reply_carries_the_version_that_decides_whether_it_may_be_read() {
        let envelope = Envelope::new(Reply::State {
            report: ExecutionReport {
                id: "sbxe-1".into(),
                state: RunnerState::Running,
                ..Default::default()
            },
        });
        let encoded = serde_json::to_string(&envelope).unwrap();
        assert!(
            encoded.contains("\"protocol\":1"),
            "every reply must state its protocol: {encoded}"
        );

        let decoded: Envelope = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.protocol, PROTOCOL_VERSION);
    }

    /// A report that lost its state says so, rather than asserting an outcome.
    ///
    /// A truncated or corrupt state file is exactly the case where a default of
    /// `Succeeded` — or even `Failed` — would put a claim in front of a caller
    /// that nothing ever observed.
    #[test]
    fn a_report_with_no_readable_state_is_unknown() {
        assert_eq!(RunnerState::default(), RunnerState::Unknown);
        let report: ExecutionReport = serde_json::from_str(r#"{"id":"sbxe-1"}"#).unwrap();
        assert_eq!(report.state, RunnerState::Unknown);
        assert_eq!(report.exit_code, None);
    }

    /// Two requests are the same command only if everything that changes what
    /// runs agrees.
    ///
    /// This is the runner's half of idempotency: it is what stops a second
    /// `start` under one id from launching a different command inside a
    /// container Kobe has already recorded as busy with the first.
    #[test]
    fn two_requests_are_the_same_command_only_if_every_input_agrees() {
        let base = StartRequest {
            protocol: PROTOCOL_VERSION,
            id: "sbxe-1".into(),
            argv: vec!["/agent".into(), "run".into()],
            cwd: Some("/work".into()),
            timeout_seconds: 60,
            max_output_bytes: 1024,
            stdin_base64: None,
        };
        assert!(base.same_command(&base.clone()));

        // The id is not part of the comparison: a retry carries the same one,
        // so including it would make this check a tautology.
        let mut renamed = base.clone();
        renamed.id = "sbxe-2".into();
        assert!(base.same_command(&renamed));

        for mutate in [
            (|r: &mut StartRequest| r.argv = vec!["/agent".into()]) as fn(&mut StartRequest),
            |r: &mut StartRequest| r.argv.push("--force".into()),
            |r: &mut StartRequest| r.cwd = None,
            |r: &mut StartRequest| r.cwd = Some("/other".into()),
            |r: &mut StartRequest| r.timeout_seconds = 61,
            |r: &mut StartRequest| r.max_output_bytes = 2048,
        ] {
            let mut other = base.clone();
            mutate(&mut other);
            assert!(
                !base.same_command(&other),
                "{other:?} must not count as the same command"
            );
        }
    }

    /// stdout and stderr never share a file.
    ///
    /// Merging them is the one irreversible mistake in output capture: a caller
    /// that cannot separate a tool's diagnostics from its output cannot
    /// reliably parse either, and nothing downstream can undo the interleave.
    #[test]
    fn the_two_streams_are_never_stored_together() {
        assert_ne!(
            LogStream::Stdout.file_name(),
            LogStream::Stderr.file_name(),
            "the streams must not share a file"
        );
        assert_eq!("stdout".parse(), Ok(LogStream::Stdout));
        assert_eq!("stderr".parse(), Ok(LogStream::Stderr));
        assert_eq!("".parse::<LogStream>(), Err(()));
        assert_eq!("both".parse::<LogStream>(), Err(()));
    }

    /// A start request is never expressible as command-line arguments.
    ///
    /// The tenant's argv travels on stdin because the exec request's own argv
    /// is a URL the target apiserver audit-logs verbatim. If this type ever
    /// grew a `Display`/`to_argv`, that guarantee would quietly become
    /// optional.
    #[test]
    fn a_start_request_is_serialised_as_one_json_document() {
        let request = StartRequest {
            protocol: PROTOCOL_VERSION,
            id: "sbxe-1".into(),
            argv: vec!["/agent".into(), "--token".into(), "s3cret".into()],
            cwd: None,
            timeout_seconds: 5,
            max_output_bytes: 16,
            stdin_base64: None,
        };
        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: StartRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, request);

        // Unknown fields are refused rather than ignored: a newer Kobe sending
        // a field this runner does not implement must fail loudly, not run the
        // command with the field silently dropped.
        assert!(
            serde_json::from_str::<StartRequest>(
                r#"{"protocol":1,"id":"a","argv":["x"],"timeoutSeconds":1,"maxOutputBytes":1,"env":{"A":"B"}}"#
            )
            .is_err(),
            "an unrecognised field must not be ignored"
        );
    }

    /// Protocol v1 is byte-shape compatible in both rollout directions.
    ///
    /// The frozen peer below deliberately denies unknown fields, just as the
    /// released runner does. This catches the tempting but incompatible change
    /// of adding an optional field that a new Kobe would always emit.
    #[test]
    fn protocol_v1_start_requests_are_old_new_compatible() {
        #[derive(Debug, serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct ReleasedV1StartRequest {
            protocol: u32,
            id: String,
            argv: Vec<String>,
            #[serde(default)]
            cwd: Option<String>,
            timeout_seconds: u64,
            max_output_bytes: u64,
        }

        let current = StartRequest {
            protocol: PROTOCOL_VERSION,
            id: "sbxe-compatible".into(),
            argv: vec!["/agent".into(), "run".into()],
            cwd: Some("/work".into()),
            timeout_seconds: 60,
            max_output_bytes: 1024,
            stdin_base64: None,
        };
        let emitted = serde_json::to_string(&current).unwrap();
        let released: ReleasedV1StartRequest = serde_json::from_str(&emitted)
            .expect("a released deny-unknown-fields v1 runner must accept new Kobe JSON");
        assert_eq!(released.protocol, PROTOCOL_VERSION);
        assert_eq!(released.id, current.id);
        assert_eq!(released.argv, current.argv);
        assert_eq!(released.cwd, current.cwd);
        assert_eq!(released.timeout_seconds, current.timeout_seconds);
        assert_eq!(released.max_output_bytes, current.max_output_bytes);

        let released_json = r#"{"protocol":1,"id":"sbxe-compatible","argv":["/agent","run"],"cwd":"/work","timeoutSeconds":60,"maxOutputBytes":1024}"#;
        let read_by_current: StartRequest = serde_json::from_str(released_json)
            .expect("the current runner must accept released v1 Kobe JSON");
        assert_eq!(read_by_current, current);
        assert!(
            !emitted.contains("requestDigest"),
            "v1 must not grow a field an older strict runner rejects: {emitted}"
        );
        assert!(
            !emitted.contains("stdin"),
            "a request with no stdin must be byte-identical to the released shape: {emitted}"
        );

        // A request that DOES carry stdin is refused by the released runner
        // rather than run without it. Loud is the correct behaviour here: a
        // Sandbox image too old to forward stdin would otherwise start the
        // command with an empty one and report success, which for
        // `gh auth login --with-token` means an unauthenticated agent and no
        // indication why.
        let with_stdin = StartRequest {
            stdin_base64: Some("dG9rZW4=".into()),
            ..current
        };
        let emitted = serde_json::to_string(&with_stdin).unwrap();
        assert!(
            serde_json::from_str::<ReleasedV1StartRequest>(&emitted).is_err(),
            "an older strict runner must refuse stdin rather than silently drop it"
        );
    }

    /// stdin is bounded, and the boundary refuses rather than truncates.
    ///
    /// Truncation is the failure mode that must never exist here: half a token
    /// is still a secret, and the command that received it would fail
    /// somewhere a long way from the request that caused it.
    #[test]
    fn oversized_stdin_is_refused_at_the_documented_boundary() {
        use base64::Engine;
        let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);

        let mut request = StartRequest {
            protocol: PROTOCOL_VERSION,
            id: "sbxe-1".into(),
            argv: vec!["/agent".into()],
            cwd: None,
            timeout_seconds: 60,
            max_output_bytes: 1024,
            stdin_base64: None,
        };
        assert_eq!(request.stdin_bytes(), Ok(None));

        // Absent and present-but-empty are different requests. The first leaves
        // the process reading /dev/null; the second is a caller deliberately
        // handing it an immediately-closed pipe.
        request.stdin_base64 = Some(String::new());
        assert_eq!(request.stdin_bytes(), Ok(Some(Vec::new())));

        request.stdin_base64 = Some(encode(&vec![b'x'; MAX_STDIN_BYTES]));
        assert_eq!(
            request.stdin_bytes().unwrap().unwrap().len(),
            MAX_STDIN_BYTES,
            "exactly the bound is accepted"
        );

        request.stdin_base64 = Some(encode(&vec![b'x'; MAX_STDIN_BYTES + 1]));
        assert_eq!(request.stdin_bytes(), Err(StdinRejected::TooLarge));

        request.stdin_base64 = Some("not base64!!".into());
        assert_eq!(request.stdin_bytes(), Err(StdinRejected::NotBase64));

        // The encoded request still has to fit the whole-request bound, so the
        // stdin ceiling must leave room for a command beside it.
        let encoded_ceiling = MAX_STDIN_BYTES.div_ceil(3) * 4;
        assert!(
            encoded_ceiling + 1024 < MAX_REQUEST_BYTES,
            "the stdin bound must leave room for argv inside MAX_REQUEST_BYTES"
        );
    }

    /// Exact bytes survive, including the ones that are not text.
    ///
    /// A credential is not required to be UTF-8, and a lossy conversion at this
    /// layer would corrupt it in a way nothing downstream could diagnose.
    #[test]
    fn stdin_bytes_survive_the_wire_exactly() {
        use base64::Engine;

        let raw: Vec<u8> = (0u8..=255).collect();
        let request = StartRequest {
            protocol: PROTOCOL_VERSION,
            id: "sbxe-1".into(),
            argv: vec!["/agent".into()],
            cwd: None,
            timeout_seconds: 60,
            max_output_bytes: 1024,
            stdin_base64: Some(base64::engine::general_purpose::STANDARD.encode(&raw)),
        };
        let decoded: StartRequest =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        assert_eq!(decoded.stdin_bytes().unwrap().unwrap(), raw);
    }

    /// The runner's own copy of a request never carries the secret.
    ///
    /// `without_stdin` is what reaches the spool, which shares a filesystem
    /// with the tenant's workload and outlives the command that needed the
    /// secret. Everything else about the request is preserved, because the
    /// supervisor still has to run it.
    #[test]
    fn a_request_stripped_for_the_spool_keeps_everything_but_the_secret() {
        let request = StartRequest {
            protocol: PROTOCOL_VERSION,
            id: "sbxe-1".into(),
            argv: vec!["/agent".into(), "run".into()],
            cwd: Some("/work".into()),
            timeout_seconds: 60,
            max_output_bytes: 1024,
            stdin_base64: Some("czNjcmV0".into()),
        };
        let stripped = request.without_stdin();
        assert_eq!(stripped.stdin_base64, None);
        assert_eq!(
            stripped,
            StartRequest {
                stdin_base64: None,
                ..request.clone()
            }
        );

        let encoded = serde_json::to_string(&stripped).unwrap();
        assert!(
            !encoded.contains("czNjcmV0"),
            "the spool copy leaked: {encoded}"
        );
        assert!(
            !encoded.contains("stdin"),
            "the spool copy leaked: {encoded}"
        );

        // And a retry still recognises it as the same command, even though the
        // stored copy can no longer prove anything about stdin.
        assert!(stripped.same_command(&request));
        assert!(request.same_command(&stripped));
    }
}
