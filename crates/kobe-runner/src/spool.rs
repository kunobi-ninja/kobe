//! The runner's durable half: one directory per execution.
//!
//! # Why a directory, created by `rename`
//!
//! Reserving an execution has to be atomic against a second `start` for the
//! same id — Kobe retries, and a retry that arrives while the first is still
//! writing must not be able to observe a half-built reservation and conclude
//! there is none. So the directory is assembled somewhere else and moved into
//! place in one step: after the `rename` it is complete, and before it there is
//! nothing to find.
//!
//! `rename` onto an existing directory fails rather than replacing it, which is
//! exactly the mutual exclusion this needs. A `create_dir` followed by writes
//! would leave a window where the directory exists and its request does not,
//! and the loser of that race would have to guess.
//!
//! # Why the spool is ephemeral
//!
//! It lives on the container's own filesystem and dies with the Sandbox. #82
//! ends history with the lease: output that outlived its Pod would describe a
//! workload nobody can inspect, from a filesystem nobody is cleaning up.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::protocol::{ExecutionReport, LogChunk, LogStream, StartRequest, is_valid_id};

/// Where executions live when nobody says otherwise.
///
/// Under `/var/run` because it must not survive the container: retaining a
/// tenant's output past the Sandbox is the one thing #82 explicitly does not
/// offer.
pub const DEFAULT_STATE_DIR: &str = "/var/run/kobe/executions";

const REQUEST_FILE: &str = "request.json";
const STATE_FILE: &str = "state.json";
const CANCEL_FILE: &str = "cancel";
const SUPERVISOR_PID_FILE: &str = "supervisor.pid";

#[derive(Debug)]
pub enum SpoolError {
    NotFound,
    /// The id is taken by a different command.
    Conflict(Box<StartRequest>),
    Io(std::io::Error),
    /// A file exists but does not parse. Distinct from `NotFound`, because the
    /// honest answer to "what happened" differs: absent means never started,
    /// corrupt means nobody can say.
    Corrupt,
}

impl From<std::io::Error> for SpoolError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// The outcome of reserving one id.
pub enum Reservation {
    /// This call created it. It may now spawn a supervisor — and nothing else
    /// will.
    Created,
    /// The identical request already reserved it. Report what it is doing;
    /// spawn nothing.
    AlreadyReserved,
}

pub struct Spool {
    root: PathBuf,
}

impl Spool {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory one execution owns.
    ///
    /// Every caller goes through here, and every caller has had the id
    /// validated first — the runner writes inside a tenant's container, where
    /// an id that escapes the spool can overwrite anything the workload can.
    fn dir(&self, id: &str) -> Result<PathBuf, SpoolError> {
        if !is_valid_id(id) {
            return Err(SpoolError::NotFound);
        }
        Ok(self.root.join(id))
    }

    /// Reserve one id, atomically, before anything is spawned.
    ///
    /// The same request twice is a retry and reserves nothing new. A different
    /// request under the same id is a conflict rather than a second execution:
    /// silently running it would give the caller two commands where they asked
    /// for one.
    pub fn reserve(&self, request: &StartRequest) -> Result<Reservation, SpoolError> {
        let target = self.dir(&request.id)?;
        std::fs::create_dir_all(&self.root)?;

        // Assembled out of the way, then moved in one step. A directory that
        // appeared before its request.json would let a concurrent `start`
        // observe a reservation it cannot read.
        let staging = self
            .root
            .join(format!(".staging-{}-{}", std::process::id(), now_unix_ms()));
        // A leftover staging directory from a killed `start` must not fail the
        // next one.
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::create_dir_all(&staging)?;

        let assemble = || -> Result<(), SpoolError> {
            std::fs::write(
                staging.join(REQUEST_FILE),
                serde_json::to_vec(request).map_err(|_| SpoolError::Corrupt)?,
            )?;
            // Written before the supervisor exists, so a poll that arrives
            // between the reservation and the spawn finds a state rather than
            // an empty directory it would have to interpret.
            std::fs::write(
                staging.join(STATE_FILE),
                serde_json::to_vec(&ExecutionReport {
                    id: request.id.clone(),
                    state: crate::protocol::RunnerState::Running,
                    started_at_unix_ms: Some(now_unix_ms()),
                    ..Default::default()
                })
                .map_err(|_| SpoolError::Corrupt)?,
            )?;
            std::fs::File::create(staging.join(LogStream::Stdout.file_name()))?;
            std::fs::File::create(staging.join(LogStream::Stderr.file_name()))?;
            Ok(())
        };
        if let Err(error) = assemble() {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(error);
        }

        match std::fs::rename(&staging, &target) {
            Ok(()) => Ok(Reservation::Created),
            Err(_) => {
                // Somebody reserved it first — possibly this same caller
                // retrying. The existing request decides, never the clock.
                let _ = std::fs::remove_dir_all(&staging);
                let existing = self.read_request(&request.id)?;
                if existing.same_command(request) {
                    Ok(Reservation::AlreadyReserved)
                } else {
                    Err(SpoolError::Conflict(Box::new(existing)))
                }
            }
        }
    }

    pub fn read_request(&self, id: &str) -> Result<StartRequest, SpoolError> {
        let path = self.dir(id)?.join(REQUEST_FILE);
        let bytes = read_existing(&path)?;
        serde_json::from_slice(&bytes).map_err(|_| SpoolError::Corrupt)
    }

    pub fn read_report(&self, id: &str) -> Result<ExecutionReport, SpoolError> {
        let path = self.dir(id)?.join(STATE_FILE);
        let bytes = read_existing(&path)?;
        serde_json::from_slice(&bytes).map_err(|_| SpoolError::Corrupt)
    }

    /// Replace the report, atomically.
    ///
    /// Written to a temporary file and renamed, because a poll can arrive at
    /// any instant: a reader that caught a partial write would parse a
    /// truncated document, and a report that does not parse is one nobody can
    /// act on.
    pub fn write_report(&self, report: &ExecutionReport) -> Result<(), SpoolError> {
        let dir = self.dir(&report.id)?;
        let temporary = dir.join(".state.json.tmp");
        std::fs::write(
            &temporary,
            serde_json::to_vec(report).map_err(|_| SpoolError::Corrupt)?,
        )?;
        std::fs::rename(&temporary, dir.join(STATE_FILE))?;
        Ok(())
    }

    /// Ask the supervisor to terminate the process group.
    ///
    /// A marker file rather than a signal from this process, and that is the
    /// whole point: `cancel` runs in a short-lived process that knows a pid
    /// only from a file it read. Signalling that pid directly races with the
    /// process exiting and the kernel reusing the number — killing whatever now
    /// holds it, inside a container where that could be the tenant's agent. The
    /// supervisor has not reaped its child, so only the supervisor can know the
    /// pid still means what it meant.
    pub fn request_cancel(&self, id: &str) -> Result<(), SpoolError> {
        let dir = self.dir(id)?;
        if !dir.join(STATE_FILE).exists() {
            return Err(SpoolError::NotFound);
        }
        std::fs::write(dir.join(CANCEL_FILE), b"1")?;
        Ok(())
    }

    pub fn cancel_requested(&self, id: &str) -> bool {
        self.dir(id)
            .map(|dir| dir.join(CANCEL_FILE).exists())
            .unwrap_or(false)
    }

    /// Record which process is supervising this execution.
    ///
    /// Kept out of the protocol: a pid is a fact about the inside of somebody
    /// else's container, and Kobe has no use for one. It exists so a later
    /// `status` can tell "still running" from "the supervisor is gone and
    /// nobody will ever record an outcome".
    pub fn write_supervisor_pid(&self, id: &str, pid: u32) -> Result<(), SpoolError> {
        std::fs::write(self.dir(id)?.join(SUPERVISOR_PID_FILE), pid.to_string())?;
        Ok(())
    }

    pub fn read_supervisor_pid(&self, id: &str) -> Option<i32> {
        let path = self.dir(id).ok()?.join(SUPERVISOR_PID_FILE);
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    pub fn stream_path(&self, id: &str, stream: LogStream) -> Result<PathBuf, SpoolError> {
        Ok(self.dir(id)?.join(stream.file_name()))
    }

    /// Read one bounded window of one stream.
    ///
    /// By offset, so a caller polling a detached execution sees every byte
    /// exactly once and can resume after a disconnect — the property that makes
    /// detached output reconnectable rather than merely present.
    pub fn read_chunk(
        &self,
        id: &str,
        stream: LogStream,
        offset: u64,
        max_bytes: usize,
    ) -> Result<LogChunk, SpoolError> {
        use base64::Engine;

        // The report is the authority on truncation: the file's own length
        // cannot distinguish "the command printed exactly this much" from "the
        // runner stopped writing here".
        let report = self.read_report(id)?;
        let path = self.stream_path(id, stream)?;
        let mut file = std::fs::File::open(&path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => SpoolError::NotFound,
            _ => SpoolError::Io(error),
        })?;
        let length = file.metadata()?.len();
        // A caller that asks past the end gets an empty window rather than an
        // error: they are tailing something that has not printed yet.
        let offset = offset.min(length);
        file.seek(SeekFrom::Start(offset))?;

        let mut data = Vec::new();
        file.take(max_bytes as u64).read_to_end(&mut data)?;
        let next_offset = offset + data.len() as u64;

        Ok(LogChunk {
            id: id.to_string(),
            stream,
            offset,
            next_offset,
            data_base64: base64::engine::general_purpose::STANDARD.encode(&data),
            truncated: match stream {
                LogStream::Stdout => report.stdout_truncated,
                LogStream::Stderr => report.stderr_truncated,
            },
            more: next_offset < length,
        })
    }
}

fn read_existing(path: &Path) -> Result<Vec<u8>, SpoolError> {
    std::fs::read(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => SpoolError::NotFound,
        _ => SpoolError::Io(error),
    })
}

/// Milliseconds since the Unix epoch.
///
/// A clock that reads before the epoch is not a timestamp anyone should
/// publish, so it becomes zero rather than a negative number cast into a
/// nonsense one.
pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{PROTOCOL_VERSION, RunnerState};

    fn request(id: &str, argv: &[&str]) -> StartRequest {
        StartRequest {
            protocol: PROTOCOL_VERSION,
            id: id.into(),
            argv: argv.iter().map(|argument| argument.to_string()).collect(),
            cwd: None,
            timeout_seconds: 60,
            max_output_bytes: 1024,
        }
    }

    /// One id reserves at most one command, whoever asks second.
    ///
    /// This is the runner's half of idempotency. Without it, a retried `start`
    /// — which is the normal consequence of a dropped connection — launches the
    /// command a second time inside a container Kobe has already recorded as
    /// busy with the first.
    #[test]
    fn one_id_can_only_ever_reserve_one_command() {
        let root = tempdir();
        let spool = Spool::new(root.path());

        assert!(matches!(
            spool
                .reserve(&request("sbxe-1", &["/agent", "run"]))
                .unwrap(),
            Reservation::Created
        ));
        // The same request is a retry, not a second command.
        assert!(matches!(
            spool
                .reserve(&request("sbxe-1", &["/agent", "run"]))
                .unwrap(),
            Reservation::AlreadyReserved
        ));
        // A different command under the same id is refused outright.
        assert!(matches!(
            spool.reserve(&request("sbxe-1", &["/agent", "destroy"])),
            Err(SpoolError::Conflict(_))
        ));
    }

    /// A reservation is never observable half-built.
    ///
    /// A concurrent `start` that found the directory but not its request would
    /// have to guess whether it had lost the race — and the safe guess (assume
    /// not) is a duplicate spawn.
    #[test]
    fn a_reservation_appears_complete_or_not_at_all() {
        let root = tempdir();
        let spool = Spool::new(root.path());
        spool.reserve(&request("sbxe-1", &["/agent"])).unwrap();

        let dir = root.path().join("sbxe-1");
        for required in [REQUEST_FILE, STATE_FILE, "stdout.log", "stderr.log"] {
            assert!(
                dir.join(required).exists(),
                "{required} must exist the moment the directory does"
            );
        }
        // Nothing is left lying around for the next reservation to trip over.
        let staging: Vec<_> = std::fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".staging"))
            .collect();
        assert!(staging.is_empty(), "staging directories must not survive");
    }

    /// An id that is not a plain name resolves to nothing at all.
    ///
    /// The runner writes inside the tenant's own container: an id that escapes
    /// the spool can read another execution's output or overwrite anything the
    /// workload can.
    #[test]
    fn a_hostile_id_reaches_no_file() {
        let root = tempdir();
        let spool = Spool::new(root.path());

        // A real neighbour to try to reach.
        spool.reserve(&request("sbxe-1", &["/agent"])).unwrap();

        for hostile in ["../sbxe-1", "..", "sbxe-1/../sbxe-1", "/etc/passwd", ""] {
            assert!(
                matches!(spool.read_report(hostile), Err(SpoolError::NotFound)),
                "id {hostile:?} must not resolve"
            );
            assert!(
                matches!(spool.request_cancel(hostile), Err(SpoolError::NotFound)),
                "id {hostile:?} must not be cancellable"
            );
            assert!(!spool.cancel_requested(hostile));
        }
    }

    /// Output is read by offset, so every byte is seen exactly once.
    ///
    /// This is what makes a detached execution's output reconnectable: a caller
    /// whose connection dropped resumes where they were, instead of re-reading
    /// what they already had or skipping what they did not.
    #[test]
    fn output_is_read_by_offset_and_never_twice() {
        use base64::Engine;

        let root = tempdir();
        let spool = Spool::new(root.path());
        spool.reserve(&request("sbxe-1", &["/agent"])).unwrap();
        std::fs::write(root.path().join("sbxe-1/stdout.log"), b"hello world").unwrap();

        let first = spool.read_chunk("sbxe-1", LogStream::Stdout, 0, 5).unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&first.data_base64)
                .unwrap(),
            b"hello"
        );
        assert_eq!(first.next_offset, 5);
        assert!(first.more, "the caller must know there is more waiting");

        let second = spool
            .read_chunk("sbxe-1", LogStream::Stdout, first.next_offset, 1024)
            .unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&second.data_base64)
                .unwrap(),
            b" world"
        );
        assert_eq!(second.next_offset, 11);
        assert!(!second.more);

        // Reading past the end is a caller tailing something that has not
        // printed yet, not an error.
        let past = spool
            .read_chunk("sbxe-1", LogStream::Stdout, 9_000, 1024)
            .unwrap();
        assert_eq!(past.data_base64, "");
        assert_eq!(past.next_offset, 11);
        assert!(!past.more);
    }

    /// The two streams are read from two files, always.
    ///
    /// Nothing downstream can undo an interleave, so the separation has to
    /// exist at the point of capture rather than be reconstructed later.
    #[test]
    fn stdout_and_stderr_are_read_separately() {
        let root = tempdir();
        let spool = Spool::new(root.path());
        spool.reserve(&request("sbxe-1", &["/agent"])).unwrap();
        std::fs::write(root.path().join("sbxe-1/stdout.log"), b"out").unwrap();
        std::fs::write(root.path().join("sbxe-1/stderr.log"), b"err").unwrap();

        use base64::Engine;
        let decode = |chunk: LogChunk| {
            String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(&chunk.data_base64)
                    .unwrap(),
            )
            .unwrap()
        };
        assert_eq!(
            decode(
                spool
                    .read_chunk("sbxe-1", LogStream::Stdout, 0, 64)
                    .unwrap()
            ),
            "out"
        );
        assert_eq!(
            decode(
                spool
                    .read_chunk("sbxe-1", LogStream::Stderr, 0, 64)
                    .unwrap()
            ),
            "err"
        );
    }

    /// Truncation is reported from the report, not inferred from a file size.
    ///
    /// A file that is exactly the cap long is indistinguishable from output
    /// that happened to end there — and a caller who reads a capped stream as
    /// complete gets a wrong answer rather than an obviously partial one.
    #[test]
    fn truncation_is_reported_rather_than_inferred() {
        let root = tempdir();
        let spool = Spool::new(root.path());
        spool.reserve(&request("sbxe-1", &["/agent"])).unwrap();
        std::fs::write(root.path().join("sbxe-1/stdout.log"), b"xxxx").unwrap();

        assert!(
            !spool
                .read_chunk("sbxe-1", LogStream::Stdout, 0, 64)
                .unwrap()
                .truncated
        );

        spool
            .write_report(&ExecutionReport {
                id: "sbxe-1".into(),
                state: RunnerState::Succeeded,
                exit_code: Some(0),
                stdout_truncated: true,
                ..Default::default()
            })
            .unwrap();

        let chunk = spool
            .read_chunk("sbxe-1", LogStream::Stdout, 0, 64)
            .unwrap();
        assert!(chunk.truncated, "a capped stream must say so");
        // The OTHER stream was not capped, and must not inherit the flag.
        assert!(
            !spool
                .read_chunk("sbxe-1", LogStream::Stderr, 0, 64)
                .unwrap()
                .truncated
        );
    }

    /// Cancelling something that was never started is not a cancellation.
    ///
    /// Answering "cancelled" for an unknown id would let a caller believe they
    /// stopped a command that is, in fact, running somewhere they mistyped.
    #[test]
    fn cancelling_an_unknown_execution_reports_not_found() {
        let root = tempdir();
        let spool = Spool::new(root.path());
        assert!(matches!(
            spool.request_cancel("sbxe-missing"),
            Err(SpoolError::NotFound)
        ));
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A scratch directory, without a dependency the Sandbox image would carry.
    ///
    /// The runner ships inside somebody else's container, so its dependency
    /// list is a security surface — a test-only crate is still one more thing
    /// to audit and to build for musl. The counter matters: two tests entering
    /// the same millisecond would otherwise share a spool and each would see
    /// the other's reservations.
    fn tempdir() -> TempDir {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "kobe-runner-test-{}-{}-{}",
            std::process::id(),
            now_unix_ms(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }
}
