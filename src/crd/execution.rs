//! Durable, idempotent Sandbox command executions (#82).
//!
//! # Why plain `exec` is not enough
//!
//! A Kubernetes exec is a connection. If it drops, or the process serving it
//! restarts, there is no way to answer the only question that matters on a
//! retry: *did my command already run?* An agent that retries a `terraform
//! apply` because its connection blipped has done something much worse than
//! fail.
//!
//! So an execution is an **object**, reserved before anything is spawned. The
//! reservation is what makes "already ran" answerable, and the record is what
//! makes the answer survive a restart.
//!
//! # What is deliberately not stored
//!
//! Not the argv, not stdin, not the environment, not the output. A command line
//! carries secrets routinely — a token in a flag, a connection string in an
//! argument — and Kubernetes object status is readable by anyone with `get` on
//! the type, replicated to every etcd member, and included in backups.
//!
//! What is stored is a **digest** of the request. That is enough to answer "is
//! this the same command as last time?" without ever holding the command.
//!
//! # Unknown is a real outcome
//!
//! If Kobe cannot establish what happened — it crashed between spawning and
//! recording, or the target stopped answering — the execution becomes
//! `Unknown`. Not failed, which invites a retry; not succeeded, which is a lie.
//! `Unknown` is the state that tells a caller they must decide, and it exists
//! precisely because the alternative is a silent duplicate spawn.

use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One command's durable record.
///
/// Owner-referenced to its `SandboxLease`, so it cannot outlive the lease it
/// belongs to: #82 requires history to end with the Sandbox, and an execution
/// record that survived would describe a workload nobody can inspect.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, KubeSchema, PartialEq, Eq)]
#[kube(
    group = "kobe.kunobi.ninja",
    version = "v1alpha1",
    kind = "SandboxExecution",
    plural = "sandboxexecutions",
    shortname = "sbxe",
    status = "SandboxExecutionStatus",
    namespaced,
    printcolumn = r#"{"name":"State","type":"string","jsonPath":".status.state"}"#,
    printcolumn = r#"{"name":"Exit","type":"integer","jsonPath":".status.exitCode"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxExecutionSpec {
    /// The lease this ran under, by UID. An execution never outlives its exact
    /// lease: a same-named successor is a different Sandbox, and answering its
    /// caller with this record would describe somebody else's command.
    #[schemars(length(min = 1))]
    pub lease_uid: String,

    /// The Pod it ran in, by UID. Recorded so a replaced Pod invalidates the
    /// record rather than silently re-pointing it.
    #[schemars(length(min = 1))]
    pub pod_uid: String,

    /// Caller-supplied key. Two requests with this key are the same request.
    #[schemars(length(min = 1, max = 253))]
    pub idempotency_key: String,

    /// SHA-256 over the canonical request. Never the request itself: a command
    /// line routinely carries secrets, and object status is readable by anyone
    /// with `get`, replicated to every etcd member, and included in backups.
    #[schemars(length(min = 64, max = 64))]
    pub request_digest: String,

    /// Wall-clock bound the runner enforces.
    #[schemars(length(min = 1))]
    pub timeout: String,

    /// Whether the caller requested a detached handle instead of waiting for
    /// the result. This controls response timing, not runner supervision.
    #[serde(default)]
    pub detached: bool,

    /// Whether `kobe-runner` supervises this execution and cancellation must
    /// therefore be confirmed by that runner.
    ///
    /// Optional for upgrade compatibility. Records created before wait mode
    /// moved to the runner omit it; for those, only detached executions were
    /// runner-managed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_managed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SandboxExecutionStatus {
    #[serde(default)]
    pub state: ExecutionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "date-time"))]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "date-time"))]
    pub finished_at: Option<String>,
    /// The remote process's exact exit code. Absent unless the command actually
    /// ran to completion — a synthesised zero would be indistinguishable from
    /// a real success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Bounded reason code. Never a raw backend message, and never any part of
    /// the command's own output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64))]
    pub reason: Option<String>,
    /// Deadline after which a still-`Running` execution becomes `Unknown`.
    ///
    /// Persisted rather than derived, so a restarted controller reaches the
    /// same verdict as the one that started it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "date-time"))]
    pub verdict_deadline: Option<String>,
}

/// Where an execution is.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
pub enum ExecutionState {
    /// Reserved, not yet spawned. The state that makes a retry answerable.
    #[default]
    Queued,
    Running,
    Succeeded,
    /// Ran and exited non-zero.
    Failed,
    /// Cancelled by the caller, or by the lease ending.
    Cancelled,
    /// The runner's own bound elapsed.
    TimedOut,
    /// Kobe cannot establish what happened.
    ///
    /// Not `Failed`, which invites a retry of something that may have run; not
    /// `Succeeded`, which would be a lie. This is the state that tells a caller
    /// the decision is theirs.
    Unknown,
}

impl std::fmt::Display for ExecutionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// `crdgen` and the reaper binary import this module for its schemas without
// evaluating lifecycle, so these are unused in those builds.
#[allow(dead_code)]
impl ExecutionState {
    /// Whether the outcome is settled.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut | Self::Unknown
        )
    }

    /// Whether this state means the command definitely did not run.
    ///
    /// Only `Queued` does. Everything else — including `Unknown` — may have
    /// side effects, and that distinction is the whole reason a caller cannot
    /// safely retry on their own.
    pub fn definitely_did_not_run(self) -> bool {
        self == Self::Queued
    }
}

/// Why a state change was refused.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionTransitionError {
    #[error("an execution in {from} is already settled and cannot become {to}")]
    AlreadyTerminal {
        from: ExecutionState,
        to: ExecutionState,
    },
    #[error("{from} cannot become {to}")]
    Invalid {
        from: ExecutionState,
        to: ExecutionState,
    },
    #[error("{state} requires an exit code")]
    ExitCodeRequired { state: ExecutionState },
    #[error("{state} must not carry an exit code")]
    ExitCodeForbidden { state: ExecutionState },
}

/// Validate one execution state change.
///
/// Terminal is terminal. A settled execution that could move again would make
/// every answer Kobe has already given about it provisional — including the
/// ones a caller acted on.
#[allow(dead_code)]
pub fn transition_execution(
    from: ExecutionState,
    to: ExecutionState,
    exit_code: Option<i32>,
) -> Result<ExecutionState, ExecutionTransitionError> {
    use ExecutionState::*;

    if from == to {
        return Ok(from);
    }
    if from.is_terminal() {
        return Err(ExecutionTransitionError::AlreadyTerminal { from, to });
    }

    let allowed = matches!(
        (from, to),
        (Queued, Running)
            // Cancelled before it ever ran, and timed out while still queued,
            // are both real: a caller can cancel during the spawn, and a
            // spawn that never completes still has to end somewhere.
            | (Queued, Cancelled)
            | (Queued, TimedOut)
            | (Queued, Unknown)
            | (Running, Succeeded)
            | (Running, Failed)
            | (Running, Cancelled)
            | (Running, TimedOut)
            | (Running, Unknown)
    );
    if !allowed {
        return Err(ExecutionTransitionError::Invalid { from, to });
    }

    // An exit code is a claim that the process ran to completion. Attaching one
    // to a cancelled or unknown execution asserts something nobody observed.
    match to {
        Succeeded | Failed if exit_code.is_none() => {
            return Err(ExecutionTransitionError::ExitCodeRequired { state: to });
        }
        Cancelled | TimedOut | Unknown | Running | Queued if exit_code.is_some() => {
            return Err(ExecutionTransitionError::ExitCodeForbidden { state: to });
        }
        _ => {}
    }
    Ok(to)
}

/// The terminal state implied by an exit code.
///
/// Zero is success; anything else is a command that ran and said no. A
/// non-zero exit is emphatically not a Kobe failure, and conflating them would
/// make a caller's own failing test look like an infrastructure fault.
#[allow(dead_code)]
pub fn state_for_exit_code(exit_code: i32) -> ExecutionState {
    if exit_code == 0 {
        ExecutionState::Succeeded
    } else {
        ExecutionState::Failed
    }
}

/// Canonical digest of one execution request.
///
/// Covers everything that changes what runs. Two requests sharing an
/// idempotency key must agree on all of it — otherwise the second is a
/// different command wearing the first one's name, and returning the first
/// one's result would be a wrong answer rather than a cached one.
#[allow(dead_code)]
pub fn request_digest(argv: &[String], cwd: Option<&str>, timeout: &str, detached: bool) -> String {
    request_digest_with_mode(argv, cwd, timeout, Some(detached))
}

/// Digest emitted before lifecycle mode became part of the request identity.
///
/// Kept only to recognise exact live records across a rolling upgrade. New
/// reservations always use [`request_digest`], and callers must also match the
/// legacy record's explicit `detached` field before this digest is accepted.
#[allow(dead_code)]
pub fn legacy_request_digest(argv: &[String], cwd: Option<&str>, timeout: &str) -> String {
    request_digest_with_mode(argv, cwd, timeout, None)
}

fn request_digest_with_mode(
    argv: &[String],
    cwd: Option<&str>,
    timeout: &str,
    detached: Option<bool>,
) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    // Length-prefixed, so ["a","bc"] and ["ab","c"] cannot collide — an
    // ambiguity here would let a caller substitute a different command under
    // the same key.
    hasher.update((argv.len() as u64).to_be_bytes());
    for argument in argv {
        hasher.update((argument.len() as u64).to_be_bytes());
        hasher.update(argument.as_bytes());
    }
    match cwd {
        Some(cwd) => {
            hasher.update([1u8]);
            hasher.update((cwd.len() as u64).to_be_bytes());
            hasher.update(cwd.as_bytes());
        }
        None => hasher.update([0u8]),
    }
    hasher.update((timeout.len() as u64).to_be_bytes());
    hasher.update(timeout.as_bytes());
    if let Some(detached) = detached {
        // Wait and detached mode have different lifecycle semantics. Treating
        // them as one request could return a wait-mode record to a caller that
        // asked for a reconnectable execution, or vice versa.
        hasher.update([u8::from(detached)]);
    }
    format!("{:x}", hasher.finalize())
}

/// Whether an existing record answers this request.
///
/// Same key and same digest: the caller is retrying, and gets the original.
/// Same key, different digest: a different command under a reused key, which
/// is a conflict rather than a new execution — silently running it would give
/// the caller two commands where they asked for one.
#[allow(dead_code)]
pub fn reuse_verdict(
    existing: &SandboxExecutionSpec,
    lease_uid: &str,
    request_digest: &str,
) -> ReuseVerdict {
    if existing.lease_uid != lease_uid {
        // A key from another lease is not this caller's to reuse or conflict
        // with; it is simply not found here.
        return ReuseVerdict::Foreign;
    }
    if existing.request_digest == request_digest {
        ReuseVerdict::SameRequest
    } else {
        ReuseVerdict::Conflict
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReuseVerdict {
    /// Return the original execution.
    SameRequest,
    /// Refuse: the key is taken by a different command.
    Conflict,
    /// Belongs to another lease entirely.
    Foreign,
}

/// The execution object's name, derived from lease UID and idempotency key.
///
/// Derived so the reservation is a `create`, and a `create` is atomic: two
/// concurrent retries of the same request race for one name and exactly one
/// wins. A generated name would need a read-then-write, which is precisely the
/// pattern that produces duplicate spawns under concurrency.
///
/// Hashed rather than concatenated because an idempotency key is caller-
/// supplied: it can be long, contain characters a Kubernetes name forbids, or
/// be chosen to collide with another lease's.
#[allow(dead_code)]
pub fn execution_name(lease_uid: &str, idempotency_key: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update((lease_uid.len() as u64).to_be_bytes());
    hasher.update(lease_uid.as_bytes());
    hasher.update(idempotency_key.as_bytes());
    // 128 bits of a SHA-256, which is not a collision anyone can arrange.
    format!("sbxe-{:x}", hasher.finalize())[..37].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ExecutionState::*;

    fn spec(lease_uid: &str, digest: &str) -> SandboxExecutionSpec {
        SandboxExecutionSpec {
            lease_uid: lease_uid.into(),
            pod_uid: "pod-uid".into(),
            idempotency_key: "key-1".into(),
            request_digest: digest.into(),
            timeout: "60s".into(),
            detached: false,
            runner_managed: None,
        }
    }

    /// A settled execution never moves again.
    ///
    /// Every answer Kobe has already given about it — to a poll, to a retry —
    /// would otherwise be provisional, including the ones a caller acted on.
    #[test]
    fn terminal_states_are_terminal() {
        for terminal in [Succeeded, Failed, Cancelled, TimedOut, Unknown] {
            assert!(terminal.is_terminal());
            for to in [Running, Succeeded, Failed, Cancelled, TimedOut, Unknown] {
                if to == terminal {
                    // Idempotent: re-recording the same outcome is not a
                    // change, and a controller may well do it after a restart.
                    assert_eq!(transition_execution(terminal, to, None).unwrap(), terminal);
                    continue;
                }
                assert!(
                    matches!(
                        transition_execution(terminal, to, None),
                        Err(ExecutionTransitionError::AlreadyTerminal { .. })
                    ),
                    "{terminal} must not become {to}"
                );
            }
        }
    }

    /// An exit code is a claim that the process ran to completion.
    ///
    /// Requiring one for Succeeded/Failed stops a synthesised zero from being
    /// indistinguishable from a real success; forbidding it elsewhere stops a
    /// cancelled or unknown execution from asserting an outcome nobody saw.
    #[test]
    fn an_exit_code_is_only_ever_an_observed_one() {
        assert_eq!(
            transition_execution(Running, Succeeded, Some(0)).unwrap(),
            Succeeded
        );
        assert_eq!(
            transition_execution(Running, Failed, Some(1)).unwrap(),
            Failed
        );

        for state in [Succeeded, Failed] {
            assert!(matches!(
                transition_execution(Running, state, None),
                Err(ExecutionTransitionError::ExitCodeRequired { .. })
            ));
        }
        for state in [Cancelled, TimedOut, Unknown] {
            assert!(
                matches!(
                    transition_execution(Running, state, Some(0)),
                    Err(ExecutionTransitionError::ExitCodeForbidden { .. })
                ),
                "{state} must not carry an exit code"
            );
            assert!(transition_execution(Running, state, None).is_ok());
        }
    }

    /// A non-zero exit is the caller's result, not Kobe's failure.
    ///
    /// Conflating them makes somebody's own failing test look like an
    /// infrastructure fault — and, worse, look retryable.
    #[test]
    fn a_non_zero_exit_is_a_result_not_a_fault() {
        assert_eq!(state_for_exit_code(0), Succeeded);
        for code in [1, 2, 127, 130, 255, -1, i32::MAX, i32::MIN] {
            assert_eq!(state_for_exit_code(code), Failed, "exit {code}");
        }
    }

    /// Only `Queued` proves a command did not run.
    ///
    /// This is the distinction a caller needs to decide whether retrying is
    /// safe, and it is why `Unknown` exists at all: everything but `Queued`
    /// may have had side effects.
    #[test]
    fn only_a_queued_execution_definitely_did_not_run() {
        assert!(Queued.definitely_did_not_run());
        for state in [Running, Succeeded, Failed, Cancelled, TimedOut, Unknown] {
            assert!(
                !state.definitely_did_not_run(),
                "{state} may have had side effects"
            );
        }
    }

    /// A reused key with different content is a conflict, not a new command.
    ///
    /// Running it would give the caller two commands where they asked for one
    /// — and returning the first one's result would answer a question they did
    /// not ask.
    #[test]
    fn a_reused_key_with_different_content_conflicts() {
        let original = spec("lease-a", "digest-1");

        assert_eq!(
            reuse_verdict(&original, "lease-a", "digest-1"),
            ReuseVerdict::SameRequest
        );
        assert_eq!(
            reuse_verdict(&original, "lease-a", "digest-2"),
            ReuseVerdict::Conflict
        );
        // Another lease's key is not this caller's to reuse OR to conflict
        // with; leaking the conflict would confirm the other lease exists.
        assert_eq!(
            reuse_verdict(&original, "lease-b", "digest-1"),
            ReuseVerdict::Foreign
        );
    }

    /// Runner supervision provenance is additive across an in-place CRD
    /// upgrade. Legacy records omit it; new records can state it explicitly
    /// without changing the meaning of `detached`.
    #[test]
    fn runner_management_provenance_preserves_legacy_wire_records() {
        let legacy = serde_json::to_value(spec("lease-a", "digest-1")).unwrap();
        assert!(legacy.get("runnerManaged").is_none());
        let decoded: SandboxExecutionSpec = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.runner_managed, None);

        let current = SandboxExecutionSpec {
            runner_managed: Some(true),
            ..spec("lease-a", "digest-1")
        };
        let encoded = serde_json::to_value(current).unwrap();
        assert_eq!(encoded["runnerManaged"], true);
        assert_eq!(encoded["detached"], false);
    }

    /// The digest covers everything that changes what runs, unambiguously.
    ///
    /// Length-prefixing matters: without it `["a","bc"]` and `["ab","c"]`
    /// hash alike, which would let a caller substitute a different command
    /// under a key whose first use they already got a result for.
    #[test]
    fn the_request_digest_cannot_be_made_to_collide() {
        let base = request_digest(&["/agent".into(), "run".into()], None, "60s", false);

        assert_eq!(
            base,
            request_digest(&["/agent".into(), "run".into()], None, "60s", false),
            "the same request must digest identically"
        );

        // Argument boundaries.
        assert_ne!(
            base,
            request_digest(&["/agentrun".into()], None, "60s", false)
        );
        assert_ne!(
            request_digest(&["a".into(), "bc".into()], None, "60s", false),
            request_digest(&["ab".into(), "c".into()], None, "60s", false)
        );
        // Order.
        assert_ne!(
            base,
            request_digest(&["run".into(), "/agent".into()], None, "60s", false)
        );
        // Working directory, including present-but-empty versus absent.
        assert_ne!(
            base,
            request_digest(
                &["/agent".into(), "run".into()],
                Some("/work"),
                "60s",
                false
            )
        );
        assert_ne!(
            base,
            request_digest(&["/agent".into(), "run".into()], Some(""), "60s", false)
        );
        // Timeout: the same command with a different bound is a different
        // request, because its outcome can differ.
        assert_ne!(
            base,
            request_digest(&["/agent".into(), "run".into()], None, "600s", false)
        );
        // Lifecycle mode is part of the request. Returning a wait-mode result
        // for a detached retry would silently remove its reconnectability.
        assert_ne!(
            base,
            request_digest(&["/agent".into(), "run".into()], None, "60s", true)
        );

        assert_eq!(base.len(), 64);
    }

    /// Names are derived and fenced, so the reservation can be a `create`.
    ///
    /// A generated name would need read-then-write, which is exactly the
    /// pattern that produces duplicate spawns under concurrent retries.
    #[test]
    fn execution_names_are_derived_fenced_and_valid() {
        let name = execution_name("lease-uid-1", "key-1");
        assert_eq!(name, execution_name("lease-uid-1", "key-1"));

        // One lease's key cannot name another's execution.
        assert_ne!(name, execution_name("lease-uid-2", "key-1"));
        assert_ne!(name, execution_name("lease-uid-1", "key-2"));

        // A caller-supplied key can be long, oddly cased, or full of
        // characters a Kubernetes name forbids. None of that reaches the name.
        for hostile in [
            "../../etc/passwd",
            "UPPER",
            &"x".repeat(4096),
            "with spaces",
            "with/slash",
            "",
        ] {
            let name = execution_name("lease-uid-1", hostile);
            assert!(name.len() <= 253, "{name} is too long");
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{name} is not a valid object name"
            );
            assert!(name.starts_with("sbxe-"));
        }

        // Concatenation would let one lease's key collide with another's by
        // moving the boundary; the length prefix prevents it.
        assert_ne!(
            execution_name("ab", "c"),
            execution_name("a", "bc"),
            "the lease/key boundary must be unambiguous"
        );
    }
}
