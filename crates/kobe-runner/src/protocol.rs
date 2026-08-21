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
/// Bumped only for a change that an older peer would MISREAD — a removed
/// field, a re-used name with new meaning. Additive optional fields do not bump
/// it, because an older peer ignoring a field it never knew about is safe.
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
}

impl StartRequest {
    /// Whether two requests are the same command.
    ///
    /// Compares everything that changes what runs, and deliberately excludes
    /// the id — a retry of the same request carries the same id anyway, and
    /// including it would make this a tautology.
    pub fn same_command(&self, other: &Self) -> bool {
        self.argv == other.argv
            && self.cwd == other.cwd
            && self.timeout_seconds == other.timeout_seconds
            && self.max_output_bytes == other.max_output_bytes
    }
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
}
