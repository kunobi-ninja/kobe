//! Persistent terminal sessions: a shell that outlives the connection that
//! attached to it, and a screen a reconnect can redraw.
//!
//! # Two processes
//!
//! ```text
//! kobe attach ──exec tty──▶ kobe-runner session attach ──unix socket──▶ kobe-runner session serve ──pty──▶ shell
//! ```
//!
//! `serve` owns the pseudo-terminal and the shell. It runs in a session of its
//! own, reparented to the container's init, so the exec that started it can
//! end — a dropped laptop, an operator restart, a stream limit — without
//! taking the shell along. `attach` is the only part that belongs to the exec:
//! it bridges the exec's terminal to the server and dies with it.
//!
//! # Why the server keeps a screen
//!
//! Replaying raw output on reconnect is either unbounded or wrong: a bounded
//! tail starts in the middle of an escape sequence and a full-screen program's
//! state is spread over everything it ever printed. The server instead feeds
//! every byte through a terminal emulator and, on attach, sends the escape
//! codes that reproduce the current screen. While a client is attached the
//! bytes pass through untouched, so the caller's own terminal keeps its
//! scrollback.
//!
//! # One client at a time
//!
//! A new attach displaces the previous one, which is told why before its
//! socket is closed. Two clients typing into one shell is a feature for pair
//! programming and a hazard for everybody else; a reconnect after a silent
//! network drop is the common case, and it must not wait for the dead client
//! to time out.
//!
//! # Trust boundary
//!
//! The socket sits on the container's own filesystem under the workload's UID,
//! so the workload can connect to it. That grants nothing the workload does
//! not already have: the shell behind it runs as the same user in the same
//! container. Authentication and revocation stay with the exec Kobe fences.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};

use crate::protocol::is_valid_id;

/// Where session sockets live when nobody says otherwise.
///
/// Beside the execution spool and for the same reason: under `/var/run`, so
/// nothing about a session outlives the container.
pub const DEFAULT_SESSIONS_DIR: &str = "/var/run/kobe/sessions";

/// Most sessions one container may hold.
///
/// Each one is a shell and a screen buffer that nothing reaps until it exits
/// or the Sandbox ends. A loop that attaches under fresh names would otherwise
/// fill the Pod's memory one idle shell at a time.
pub const MAX_SESSIONS: usize = 16;

/// Largest frame either side sends or accepts.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Scrollback the server's emulator keeps. None: the redraw reproduces the
/// visible screen, and older lines already live in the caller's terminal.
const SCROLLBACK_ROWS: usize = 0;

const DEFAULT_SIZE: WindowSize = WindowSize { rows: 24, cols: 80 };

/// How long a fresh server may take to accept its first connection.
const SERVER_START_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a client may take to say hello before it is dropped.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a write to a client may block before the client is dropped.
///
/// The server writes output while holding the screen lock. A client that
/// stopped reading must not be able to stall the shell, or the next attach.
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the server waits, after the shell exits, for its last output.
const EXIT_DRAIN: Duration = Duration::from_millis(500);

/// How often `attach` re-reads the terminal size. Polled rather than taken
/// from `SIGWINCH`, so no signal handler has to be installed in a process that
/// is otherwise plain blocking I/O.
const RESIZE_POLL_MS: libc::c_int = 250;

const KIND_HELLO: u8 = 1;
const KIND_INPUT: u8 = 2;
const KIND_RESIZE: u8 = 3;
const KIND_OUTPUT: u8 = 4;
const KIND_EXIT: u8 = 5;
const KIND_DETACHED: u8 = 6;

/// A terminal size, rows first as the kernel orders them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowSize {
    pub rows: u16,
    pub cols: u16,
}

/// One message between `attach` and `serve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// attach → serve, first and only once: the caller's terminal size.
    Hello(WindowSize),
    /// attach → serve: keystrokes.
    Input(Vec<u8>),
    /// attach → serve: the caller's terminal changed size.
    Resize(WindowSize),
    /// serve → attach: terminal output, redraw included.
    Output(Vec<u8>),
    /// serve → attach: the shell exited with this status, `128 + signal` for
    /// a signal, as a shell would report it.
    Exit(i32),
    /// serve → attach: another client attached, so this one is closed.
    Detached,
}

/// Why a byte stream is not a sequence of frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Oversized,
    UnknownKind(u8),
    Malformed,
}

impl From<FrameError> for io::Error {
    fn from(error: FrameError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, format!("{error:?}"))
    }
}

impl Frame {
    /// `[kind][length: u32 big-endian][payload]`.
    pub fn encode(&self) -> Vec<u8> {
        let (kind, payload): (u8, Vec<u8>) = match self {
            Self::Hello(size) => (KIND_HELLO, encode_size(*size)),
            Self::Input(bytes) => (KIND_INPUT, bytes.clone()),
            Self::Resize(size) => (KIND_RESIZE, encode_size(*size)),
            Self::Output(bytes) => (KIND_OUTPUT, bytes.clone()),
            Self::Exit(code) => (KIND_EXIT, code.to_be_bytes().to_vec()),
            Self::Detached => (KIND_DETACHED, Vec::new()),
        };
        let mut encoded = Vec::with_capacity(5 + payload.len());
        encoded.push(kind);
        encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&payload);
        encoded
    }
}

fn encode_size(size: WindowSize) -> Vec<u8> {
    let mut payload = size.rows.to_be_bytes().to_vec();
    payload.extend_from_slice(&size.cols.to_be_bytes());
    payload
}

fn decode_size(payload: &[u8]) -> Result<WindowSize, FrameError> {
    let [r0, r1, c0, c1] = payload else {
        return Err(FrameError::Malformed);
    };
    let size = WindowSize {
        rows: u16::from_be_bytes([*r0, *r1]),
        cols: u16::from_be_bytes([*c0, *c1]),
    };
    // A zero dimension is not a terminal, and handing one to the kernel makes
    // every program in the session lay itself out into nothing.
    if size.rows == 0 || size.cols == 0 {
        return Err(FrameError::Malformed);
    }
    Ok(size)
}

/// Reassembles frames from reads that split them anywhere.
#[derive(Debug, Default)]
pub struct FrameReader {
    buffer: Vec<u8>,
}

impl FrameReader {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// The next complete frame, or `None` until more bytes arrive.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        let Some(header) = self.buffer.get(..5) else {
            return Ok(None);
        };
        let kind = header[0];
        let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        // Checked before waiting for the body, so a hostile length cannot make
        // this buffer grow towards it.
        if length > MAX_FRAME_BYTES {
            return Err(FrameError::Oversized);
        }
        if self.buffer.len() < 5 + length {
            return Ok(None);
        }
        let payload: Vec<u8> = self.buffer.drain(..5 + length).skip(5).collect();
        let frame = match kind {
            KIND_HELLO => Frame::Hello(decode_size(&payload)?),
            KIND_INPUT => Frame::Input(payload),
            KIND_RESIZE => Frame::Resize(decode_size(&payload)?),
            KIND_OUTPUT => Frame::Output(payload),
            KIND_EXIT => {
                let code: [u8; 4] = payload.try_into().map_err(|_| FrameError::Malformed)?;
                Frame::Exit(i32::from_be_bytes(code))
            }
            KIND_DETACHED if payload.is_empty() => Frame::Detached,
            KIND_DETACHED => return Err(FrameError::Malformed),
            other => return Err(FrameError::UnknownKind(other)),
        };
        Ok(Some(frame))
    }
}

fn write_frame(stream: &mut impl Write, frame: &Frame) -> io::Result<()> {
    stream.write_all(&frame.encode())
}

/// Output of any size, cut into frames the reader will accept.
fn write_output(stream: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    for chunk in bytes.chunks(MAX_FRAME_BYTES) {
        write_frame(stream, &Frame::Output(chunk.to_vec()))?;
    }
    Ok(())
}

/// Block until one whole frame arrives. `None` is a clean EOF.
fn read_frame(stream: &mut impl Read, reader: &mut FrameReader) -> io::Result<Option<Frame>> {
    let mut buffer = [0u8; 8 * 1024];
    loop {
        if let Some(frame) = reader.next_frame()? {
            return Ok(Some(frame));
        }
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(None),
            Ok(read) => reader.push(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

pub fn socket_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.sock"))
}

fn lock_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.lock"))
}

fn invalid_name(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("session name {name:?} must be lowercase letters, digits and '-'"),
    )
}

/// The sessions directory, private to the workload's user.
fn ensure_dir(dir: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Names of the sessions whose server answers.
///
/// A connection is the liveness check: a socket file outlives a server killed
/// with SIGKILL, and a stale one must not be reported as a shell somebody can
/// attach to. The probe never sends a hello, so the server drops it unseen.
pub fn list(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let file = entry.file_name().into_string().ok()?;
            let name = file.strip_suffix(".sock")?.to_string();
            (is_valid_id(&name) && UnixStream::connect(entry.path()).is_ok()).then_some(name)
        })
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// attach
// ---------------------------------------------------------------------------

/// Attach this process's terminal to session `name`, starting it with `argv`
/// if it does not exist yet. Returns the exit status to leave with.
pub fn attach(dir: &Path, name: &str, argv: &[String]) -> i32 {
    match attach_inner(dir, name, argv) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("kobe-runner: session {name}: {error}");
            1
        }
    }
}

fn attach_inner(dir: &Path, name: &str, argv: &[String]) -> io::Result<i32> {
    if !is_valid_id(name) {
        return Err(invalid_name(name));
    }
    ensure_dir(dir)?;
    let (stream, mut server) = connect_or_start(dir, name, argv)?;
    let code = bridge(stream);
    // Reap the server if it was our child and has already exited, so a
    // container whose init never reaps does not collect zombies from it.
    if let Some(server) = server.as_mut() {
        let _ = server.try_wait();
    }
    code
}

fn connect_or_start(
    dir: &Path,
    name: &str,
    argv: &[String],
) -> io::Result<(UnixStream, Option<Child>)> {
    let socket = socket_path(dir, name);
    if let Ok(stream) = UnixStream::connect(&socket) {
        return Ok((stream, None));
    }
    if list(dir).len() >= MAX_SESSIONS {
        return Err(io::Error::other(format!(
            "this sandbox already holds {MAX_SESSIONS} sessions"
        )));
    }
    let server = spawn_server(dir, name, argv)?;
    let deadline = Instant::now() + SERVER_START_TIMEOUT;
    loop {
        match UnixStream::connect(&socket) {
            Ok(stream) => return Ok((stream, Some(server))),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("the session server did not start: {error}"),
                ));
            }
        }
    }
}

/// Re-exec this binary as the server, in a session of its own.
///
/// The same shape as the execution supervisor, for the same reason: the exec
/// that runs `attach` is torn down with the caller's connection, and a server
/// in its session would go with it.
fn spawn_server(dir: &Path, name: &str, argv: &[String]) -> io::Result<Child> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("session")
        .arg("--dir")
        .arg(dir)
        .arg("serve")
        .arg("--name")
        .arg(name)
        .arg("--")
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: `setsid` is async-signal-safe and the only call between fork and
    // exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn()
}

/// Copy between this process's terminal and the server until the shell
/// exits, another client takes over, or the terminal goes away.
fn bridge(mut stream: UnixStream) -> io::Result<i32> {
    const STDIN: RawFd = libc::STDIN_FILENO;
    let _raw = RawTerminal::enter(STDIN);
    // SAFETY: fd 1 stays open for the life of the process; `ManuallyDrop`
    // keeps this handle from closing it.
    let mut stdout = std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(libc::STDOUT_FILENO) });

    let mut size = window_size(STDIN).unwrap_or(DEFAULT_SIZE);
    write_frame(&mut stream, &Frame::Hello(size))?;

    let mut reader = FrameReader::default();
    let mut stdin_open = true;
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let mut fds = [
            libc::pollfd {
                // A negative fd is skipped by poll(2): stdin at EOF must stop
                // waking the loop, while output keeps flowing.
                fd: if stdin_open { STDIN } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: `fds` is a valid array of two pollfd structs for the call.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, RESIZE_POLL_MS) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }

        if let Some(now) = window_size(STDIN)
            && now != size
        {
            size = now;
            write_frame(&mut stream, &Frame::Resize(size))?;
        }

        let ready = libc::POLLIN | libc::POLLHUP | libc::POLLERR;
        if fds[0].revents & ready != 0 {
            match read_fd(STDIN, &mut buffer)? {
                0 => stdin_open = false,
                read => write_frame(&mut stream, &Frame::Input(buffer[..read].to_vec()))?,
            }
        }
        if fds[1].revents & ready != 0 {
            let read = match stream.read(&mut buffer) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            if read == 0 {
                return Err(io::Error::other("the session server went away"));
            }
            reader.push(&buffer[..read]);
            while let Some(frame) = reader.next_frame()? {
                match frame {
                    Frame::Output(bytes) => {
                        stdout.write_all(&bytes)?;
                        stdout.flush()?;
                    }
                    Frame::Exit(code) => return Ok(code),
                    Frame::Detached => {
                        eprint!("\r\n[kobe-runner: session attached elsewhere]\r\n");
                        return Ok(0);
                    }
                    Frame::Hello(_) | Frame::Input(_) | Frame::Resize(_) => {
                        return Err(FrameError::Malformed.into());
                    }
                }
            }
        }
    }
}

fn read_fd(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `buffer` is valid for `buffer.len()` bytes of writes.
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read >= 0 {
            return Ok(read as usize);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn window_size(fd: RawFd) -> Option<WindowSize> {
    // SAFETY: an all-zero winsize is a valid value to be overwritten.
    let mut winsize: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ writes one winsize through the pointer.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ as _, &mut winsize) } != 0 {
        return None;
    }
    (winsize.ws_row > 0 && winsize.ws_col > 0).then_some(WindowSize {
        rows: winsize.ws_row,
        cols: winsize.ws_col,
    })
}

fn set_window_size(fd: RawFd, size: WindowSize) -> io::Result<()> {
    let winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads one winsize through the pointer. The kernel
    // signals the terminal's foreground group with SIGWINCH.
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ as _, &winsize) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The exec's terminal in raw mode, restored on drop.
///
/// The exec's pty starts cooked: it would echo every keystroke a second time
/// and hold input until Enter. The caller's own terminal is already raw, so
/// this end has to pass bytes through untouched too.
struct RawTerminal {
    fd: RawFd,
    saved: Option<libc::termios>,
}

impl RawTerminal {
    fn enter(fd: RawFd) -> Self {
        // SAFETY: an all-zero termios is a valid value to be overwritten.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: tcgetattr writes one termios through the pointer; it fails
        // harmlessly when `fd` is not a terminal.
        if unsafe { libc::isatty(fd) } != 1 || unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Self { fd, saved: None };
        }
        let mut raw = saved;
        // SAFETY: both calls only read and write the termios passed to them.
        unsafe {
            libc::cfmakeraw(&mut raw);
            libc::tcsetattr(fd, libc::TCSANOW, &raw);
        }
        Self {
            fd,
            saved: Some(saved),
        }
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        if let Some(saved) = self.saved {
            // SAFETY: restores the termios read in `enter`.
            unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &saved) };
        }
    }
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

/// Own session `name`: start `argv` on a fresh pty and serve attaches until it
/// exits. Returns the shell's exit status.
///
/// Returns `Ok(0)` without starting anything when another server already
/// holds the session, which is how two racing first attaches end up sharing
/// one shell instead of starting two.
pub fn serve(dir: &Path, name: &str, argv: &[String]) -> io::Result<i32> {
    if !is_valid_id(name) {
        return Err(invalid_name(name));
    }
    ensure_dir(dir)?;
    let Some(_lock) = SessionLock::acquire(dir, name)? else {
        return Ok(0);
    };

    // Holding the lock proves no live server owns this socket, so a file left
    // by one that was SIGKILLed is removed rather than refused.
    let socket = socket_path(dir, name);
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    let _socket_file = RemoveOnDrop(socket.clone());

    let (master, slave) = open_pty(DEFAULT_SIZE)?;
    let mut child = spawn_shell(name, argv, &slave)?;
    // Only the shell may hold the slave. A copy kept here would stop the
    // master from ever reading EOF.
    drop(slave);

    let master = File::from(master);
    let session = Arc::new(Session {
        state: Mutex::new(State {
            parser: vt100::Parser::new(DEFAULT_SIZE.rows, DEFAULT_SIZE.cols, SCROLLBACK_ROWS),
            size: DEFAULT_SIZE,
            client: None,
            generation: 0,
        }),
        writer: Mutex::new(master.try_clone()?),
    });

    let (drained, drained_signal) = mpsc::channel();
    {
        let session = session.clone();
        let mut reader = master;
        std::thread::spawn(move || {
            let mut buffer = [0u8; 32 * 1024];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => session.output(&buffer[..read]),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    // EIO is how Linux reports a pty whose last slave closed.
                    Err(_) => break,
                }
            }
            let _ = drained.send(());
        });
    }

    let done = Arc::new(AtomicBool::new(false));
    {
        let session = session.clone();
        let done = done.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if done.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let session = session.clone();
                // A client's hello is read on its own thread, so one that
                // connects and says nothing cannot hold up the next attach.
                std::thread::spawn(move || session.serve_client(stream));
            }
        });
    }

    let status = child.wait()?;
    // Background jobs can keep the slave open past the shell's exit, so the
    // reader's EOF is waited for, not required.
    let _ = drained_signal.recv_timeout(EXIT_DRAIN);
    let code = exit_code(status);
    session.finish(code);

    // Wake the accept loop so it sees `done` and returns.
    done.store(true, Ordering::SeqCst);
    let _ = UnixStream::connect(&socket);
    Ok(code)
}

struct Session {
    state: Mutex<State>,
    /// The pty master, for input and resizes. Locked after `state` whenever
    /// both are held.
    writer: Mutex<File>,
}

struct State {
    parser: vt100::Parser,
    size: WindowSize,
    client: Option<UnixStream>,
    /// Bumped per attach, so a displaced client's thread cannot clear the
    /// client that replaced it.
    generation: u64,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A thread that panicked mid-write leaves a screen that is at worst
    // slightly wrong; refusing every later attach over it would be worse.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Session {
    /// Feed pty output through the screen and on to the attached client.
    fn output(&self, bytes: &[u8]) {
        let mut state = lock(&self.state);
        state.parser.process(bytes);
        if let Some(client) = state.client.as_mut()
            && write_output(client, bytes).is_err()
        {
            state.client = None;
        }
    }

    fn resize(&self, state: &mut State, size: WindowSize) {
        if state.size == size {
            return;
        }
        if set_window_size(lock(&self.writer).as_raw_fd(), size).is_ok() {
            state.size = size;
            state.parser.set_size(size.rows, size.cols);
        }
    }

    fn serve_client(&self, mut stream: UnixStream) {
        let mut reader = FrameReader::default();
        if stream.set_read_timeout(Some(HELLO_TIMEOUT)).is_err() {
            return;
        }
        let Ok(Some(Frame::Hello(size))) = read_frame(&mut stream, &mut reader) else {
            return;
        };
        if stream.set_read_timeout(None).is_err()
            || stream
                .set_write_timeout(Some(CLIENT_WRITE_TIMEOUT))
                .is_err()
        {
            return;
        }
        let Ok(mut writer) = stream.try_clone() else {
            return;
        };

        let generation = {
            let mut state = lock(&self.state);
            self.resize(&mut state, size);
            if let Some(mut previous) = state.client.take() {
                let _ = write_frame(&mut previous, &Frame::Detached);
                let _ = previous.shutdown(std::net::Shutdown::Both);
            }
            // Under the same lock the pty reader takes, so no output lands
            // between the redraw and the live stream, and none twice.
            if write_output(&mut writer, &redraw(state.parser.screen())).is_err() {
                return;
            }
            state.generation += 1;
            state.client = Some(writer);
            state.generation
        };

        loop {
            match read_frame(&mut stream, &mut reader) {
                Ok(Some(Frame::Input(bytes))) => {
                    if lock(&self.writer).write_all(&bytes).is_err() {
                        break;
                    }
                }
                Ok(Some(Frame::Resize(size))) => {
                    let mut state = lock(&self.state);
                    if state.generation == generation {
                        self.resize(&mut state, size);
                    }
                }
                // EOF, an error, or a frame only the server sends.
                _ => break,
            }
        }

        let mut state = lock(&self.state);
        if state.generation == generation {
            state.client = None;
        }
    }

    /// Tell the attached client the shell's status and close it.
    fn finish(&self, code: i32) {
        let mut state = lock(&self.state);
        if let Some(mut client) = state.client.take() {
            let _ = write_frame(&mut client, &Frame::Exit(code));
            let _ = client.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// Escape codes that turn a blank terminal into this screen.
///
/// `state_formatted` covers contents, cursor and input modes but not which
/// buffer is showing, so the alternate screen is switched explicitly: a
/// full-screen program redrawn onto the primary buffer would leave its frame
/// in the caller's scrollback when it exits.
fn redraw(screen: &vt100::Screen) -> Vec<u8> {
    let mut bytes = if screen.alternate_screen() {
        b"\x1b[?1049h".to_vec()
    } else {
        b"\x1b[?1049l".to_vec()
    };
    bytes.extend_from_slice(&screen.state_formatted());
    bytes
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

fn open_pty(size: WindowSize) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let mut winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty writes two descriptors through the first two pointers
    // and reads the winsize; the name and termios pointers may be null.
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut winsize,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openpty succeeded, so both are open descriptors this process owns.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    // openpty does not set close-on-exec. A shell that inherited the master
    // would keep its own pty alive after every other holder let go.
    for fd in [&master, &slave] {
        // SAFETY: F_SETFD on a descriptor this process owns.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((master, slave))
}

/// Start the session's program on the pty slave, as its controlling terminal.
///
/// No `argv` means the user's login shell: `$SHELL`, else `/bin/sh`.
fn spawn_shell(name: &str, argv: &[String], slave: &OwnedFd) -> io::Result<Child> {
    let mut command = match argv.split_first() {
        Some((program, arguments)) => {
            let mut command = Command::new(program);
            command.args(arguments);
            command
        }
        None => {
            let shell = std::env::var("SHELL")
                .ok()
                .filter(|shell| shell.starts_with('/'))
                .unwrap_or_else(|| "/bin/sh".to_string());
            let mut command = Command::new(&shell);
            command.arg("-l");
            command
        }
    };
    // An exec does not set TERM, and without it a shell falls back to a
    // terminal that cannot move the cursor.
    if std::env::var_os("TERM").is_none() {
        command.env("TERM", "xterm-256color");
    }
    command
        .env("KOBE_SESSION", name)
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave.try_clone()?));
    // SAFETY: `setsid` and `ioctl` are async-signal-safe and the only calls
    // between fork and exec. The new session gets the slave (already dup'ed to
    // fd 0) as its controlling terminal, so job control and ^C work.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn()
}

/// An exclusive `flock` on the session's lock file, held for the server's life.
///
/// The kernel drops it when the process dies, however it dies, so it cannot go
/// stale the way a pid file or the socket itself can.
struct SessionLock {
    _file: File,
    path: PathBuf,
}

impl SessionLock {
    fn acquire(dir: &Path, name: &str) -> io::Result<Option<Self>> {
        let path = lock_path(dir, name);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)?;
        // SAFETY: flock on a descriptor this process owns.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(error)
            };
        }
        Ok(Some(Self { _file: file, path }))
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(bytes: &[u8]) -> Vec<Frame> {
        let mut reader = FrameReader::default();
        reader.push(bytes);
        std::iter::from_fn(|| reader.next_frame().unwrap()).collect()
    }

    /// Every frame survives the wire, however the reads split it.
    #[test]
    fn frames_round_trip_across_arbitrary_read_boundaries() {
        let sent = vec![
            Frame::Hello(WindowSize {
                rows: 40,
                cols: 120,
            }),
            Frame::Input(b"ls\r".to_vec()),
            Frame::Resize(WindowSize {
                rows: 50,
                cols: 200,
            }),
            Frame::Output(Vec::new()),
            Frame::Output((0u8..=255).collect()),
            Frame::Exit(-1),
            Frame::Exit(130),
            Frame::Detached,
        ];
        let wire: Vec<u8> = sent.iter().flat_map(Frame::encode).collect();
        assert_eq!(frames(&wire), sent);

        // One byte at a time: the worst split a stream socket can produce.
        let mut reader = FrameReader::default();
        let mut received = Vec::new();
        for byte in &wire {
            reader.push(std::slice::from_ref(byte));
            while let Some(frame) = reader.next_frame().unwrap() {
                received.push(frame);
            }
        }
        assert_eq!(received, sent);
    }

    /// A length past the bound is refused before its body is buffered.
    #[test]
    fn an_oversized_frame_is_refused_from_its_header() {
        let mut reader = FrameReader::default();
        let mut header = vec![KIND_OUTPUT];
        header.extend_from_slice(&((MAX_FRAME_BYTES + 1) as u32).to_be_bytes());
        reader.push(&header);
        assert_eq!(reader.next_frame(), Err(FrameError::Oversized));
    }

    /// Frames nobody defined, and sizes that are not terminals, are errors.
    #[test]
    fn unknown_and_malformed_frames_are_refused() {
        let mut reader = FrameReader::default();
        reader.push(&[99, 0, 0, 0, 0]);
        assert_eq!(reader.next_frame(), Err(FrameError::UnknownKind(99)));

        for payload in [&[0u8, 0, 0, 80][..], &[0, 24, 0, 0], &[0, 24, 0], &[]] {
            let mut reader = FrameReader::default();
            reader.push(&[KIND_RESIZE, 0, 0, 0, payload.len() as u8]);
            reader.push(payload);
            assert_eq!(
                reader.next_frame(),
                Err(FrameError::Malformed),
                "{payload:?}"
            );
        }
    }

    /// Output larger than a frame is split, never refused or truncated.
    #[test]
    fn large_output_is_split_into_acceptable_frames() {
        let bytes: Vec<u8> = (0..MAX_FRAME_BYTES * 2 + 7).map(|i| i as u8).collect();
        let mut wire = Vec::new();
        write_output(&mut wire, &bytes).unwrap();
        let received: Vec<u8> = frames(&wire)
            .into_iter()
            .flat_map(|frame| match frame {
                Frame::Output(chunk) => chunk,
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        assert_eq!(received, bytes);
    }

    /// The redraw selects the buffer the program is drawing on.
    #[test]
    fn the_redraw_restores_the_alternate_screen() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        parser.process(b"prompt$ ");
        let primary = redraw(parser.screen());
        assert!(primary.starts_with(b"\x1b[?1049l"));
        assert!(primary.windows(7).any(|w| w == b"prompt$"));

        parser.process(b"\x1b[?1049hEDITOR");
        let alternate = redraw(parser.screen());
        assert!(alternate.starts_with(b"\x1b[?1049h"));
        assert!(alternate.windows(6).any(|w| w == b"EDITOR"));
    }

    // -- a live server --------------------------------------------------

    struct Client {
        stream: UnixStream,
        reader: FrameReader,
    }

    impl Client {
        fn attach(dir: &Path, name: &str) -> Self {
            let deadline = Instant::now() + SERVER_START_TIMEOUT;
            let stream = loop {
                match UnixStream::connect(socket_path(dir, name)) {
                    Ok(stream) => break stream,
                    Err(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    Err(error) => panic!("server never listened: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut client = Self {
                stream,
                reader: FrameReader::default(),
            };
            client.send(Frame::Hello(WindowSize { rows: 24, cols: 80 }));
            client
        }

        fn send(&mut self, frame: Frame) {
            write_frame(&mut self.stream, &frame).unwrap();
        }

        /// Read until the accumulated output contains `needle`, or a
        /// non-output frame arrives.
        fn output_until(&mut self, needle: &str) -> (String, Option<Frame>) {
            let mut output = Vec::new();
            loop {
                let frame = read_frame(&mut self.stream, &mut self.reader)
                    .expect("read")
                    .expect("server closed the stream");
                match frame {
                    Frame::Output(bytes) => {
                        output.extend_from_slice(&bytes);
                        if String::from_utf8_lossy(&output).contains(needle) {
                            return (String::from_utf8_lossy(&output).into_owned(), None);
                        }
                    }
                    other => return (String::from_utf8_lossy(&output).into_owned(), Some(other)),
                }
            }
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        // Short: a unix socket path is limited to about a hundred bytes.
        let dir = std::env::temp_dir().join(format!("kr-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// The whole point: output survives a disconnect, and the next attach
    /// sees the screen as it was.
    #[test]
    fn a_reattach_redraws_the_screen_the_shell_left() {
        let dir = temp_dir("redraw");
        let server = {
            let dir = dir.clone();
            std::thread::spawn(move || serve(&dir, "main", &["/bin/sh".to_string()]).unwrap())
        };

        let mut first = Client::attach(&dir, "main");
        // The arithmetic keeps the echoed command line from matching.
        first.send(Frame::Input(b"echo kobe-$((40 + 2))\n".to_vec()));
        first.output_until("kobe-42");
        drop(first);

        let mut second = Client::attach(&dir, "main");
        let (redrawn, _) = second.output_until("kobe-42");
        assert!(
            redrawn.starts_with("\x1b[?1049l"),
            "the reattach must begin with a redraw: {redrawn:?}"
        );
        assert_eq!(list(&dir), vec!["main".to_string()]);

        second.send(Frame::Input(b"exit 7\n".to_vec()));
        let (_, end) = second.output_until("\u{0}never");
        assert_eq!(end, Some(Frame::Exit(7)));
        assert_eq!(server.join().unwrap(), 7);
        assert!(list(&dir).is_empty(), "the socket must go with the server");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A second attach takes over, and the first is told why.
    #[test]
    fn a_new_attach_displaces_the_previous_one() {
        let dir = temp_dir("displace");
        let server = {
            let dir = dir.clone();
            std::thread::spawn(move || serve(&dir, "main", &["/bin/sh".to_string()]).unwrap())
        };

        let mut first = Client::attach(&dir, "main");
        first.send(Frame::Input(b"echo ready-$((1 + 1))\n".to_vec()));
        first.output_until("ready-2");

        let mut second = Client::attach(&dir, "main");
        second.output_until("ready-2");
        let (_, end) = first.output_until("\u{0}never");
        assert_eq!(end, Some(Frame::Detached));

        // A second server for the same name defers to the first.
        assert_eq!(serve(&dir, "main", &["/bin/sh".to_string()]).unwrap(), 0);

        second.send(Frame::Input(b"exit\n".to_vec()));
        let (_, end) = second.output_until("\u{0}never");
        assert_eq!(end, Some(Frame::Exit(0)));
        assert_eq!(server.join().unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A name that could leave the sessions directory is refused.
    #[test]
    fn a_session_name_cannot_escape_the_directory() {
        let dir = temp_dir("names");
        for hostile in ["../x", "a/b", "", "A"] {
            assert_eq!(
                serve(&dir, hostile, &[]).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(attach(&dir, hostile, &[]), 1);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
