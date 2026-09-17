//! `kobe attach` and `port-forward` — the executable-resource client half (#84).
//!
//! # Framing
//!
//! Binary frames with a leading channel byte, matching what the server speaks
//! (#83) and Kubernetes' own `v4` convention:
//!
//! ```text
//! 0 stdin (out)  1 stdout (in)  2 stderr (in)  3 error (in)  4 resize (out)
//! ```
//!
//! # Raw mode is a promise to restore it
//!
//! `attach` puts the terminal in raw mode so keystrokes reach the workload
//! rather than the shell. Every exit path has to undo that — including a
//! panic, because a process that dies in raw mode leaves the user with a
//! terminal that does not echo, and their next instinct is to close the window
//! rather than type `reset`. The guard here restores on drop, and a panic hook
//! restores before the message is printed.
//!
//! # A local listener is a commitment too
//!
//! `port-forward` binds locally and forwards a bounded number of connections.
//! never binds a wildcard address by default: a forward reachable from the
//! network turns "a port on my machine" into "a port on the office LAN", and
//! the sandbox behind it belongs to one caller.

use std::io::{IsTerminal, Write};
use std::sync::Arc;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use super::config::{CliConfig, ResolvedConfig};
use super::{
    OutputFormat, Reaching, authed_client, get_auth_header, get_auth_header_for_output,
    get_auth_header_noninteractive, with_auth,
};

pub const CHANNEL_STDIN: u8 = 0;
pub const CHANNEL_STDOUT: u8 = 1;
pub const CHANNEL_STDERR: u8 = 2;
pub const CHANNEL_ERROR: u8 = 3;
pub const CHANNEL_RESIZE: u8 = 4;

/// Browsers need several connections at once for an application shell, its
/// assets, and an upgraded WebSocket. Keep the local listener bounded so a
/// single forward cannot create an unbounded number of upstream streams.
const MAX_CONCURRENT_PORT_FORWARD_CONNECTIONS: usize = 16;

/// Frame one outbound chunk.
pub fn client_frame(channel: u8, payload: &[u8]) -> Message {
    let mut framed = Vec::with_capacity(payload.len() + 1);
    framed.push(channel);
    framed.extend_from_slice(payload);
    Message::Binary(framed.into())
}

/// A terminal resize, as the server expects it.
///
/// A newly allocated or minimized pseudo-terminal may temporarily report a
/// zero dimension. The server correctly refuses that as not being a terminal,
/// so the client must wait for the next usable size instead of ending its own
/// session with a protocol violation.
pub fn resize_frame(width: u16, height: u16) -> Option<Message> {
    if width == 0 || height == 0 {
        return None;
    }
    Some(client_frame(
        CHANNEL_RESIZE,
        format!(r#"{{"width":{width},"height":{height}}}"#).as_bytes(),
    ))
}

/// What an inbound frame turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerFrame {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    /// The server ended the stream, with its reason code.
    Ended {
        reason: String,
    },
    /// A frame this client does not understand.
    ///
    /// Ignored rather than fatal: the server may add channels, and a client
    /// that died on an unknown one would break on a server upgrade it did not
    /// need to care about. The reverse — the server ignoring an unknown frame
    /// from a client — is not symmetric, because there the client believes it
    /// sent something.
    Unknown,
}

/// Parse one server frame.
pub fn parse_server_frame(message: &Message) -> Option<ServerFrame> {
    let payload = match message {
        Message::Binary(payload) => payload.as_ref(),
        Message::Close(_) => {
            return Some(ServerFrame::Ended {
                reason: "closed".to_string(),
            });
        }
        _ => return None,
    };
    parse_server_payload(payload)
}

fn parse_server_payload(payload: &[u8]) -> Option<ServerFrame> {
    let (&channel, body) = payload.split_first()?;
    Some(match channel {
        CHANNEL_STDOUT => ServerFrame::Stdout(body.to_vec()),
        CHANNEL_STDERR => ServerFrame::Stderr(body.to_vec()),
        CHANNEL_ERROR => ServerFrame::Ended {
            reason: parse_end_reason(body),
        },
        _ => ServerFrame::Unknown,
    })
}

/// Pull the bounded reason code out of an error frame.
///
/// Falls back to the raw text rather than to a generic message: a reason this
/// client does not recognise is still more useful to whoever reads it than
/// "the stream ended".
fn parse_end_reason(body: &[u8]) -> String {
    #[derive(serde::Deserialize)]
    struct End {
        reason: String,
    }
    serde_json::from_slice::<End>(body)
        .map(|end| end.reason)
        .unwrap_or_else(|_| String::from_utf8_lossy(body).into_owned())
}

/// Whether the CLI should exit non-zero for this end reason.
///
/// A stream the caller closed, or one whose command simply finished, is a
/// success. A revoked lease or a limit is not — an unattended caller has to be
/// able to tell "your session ended normally" from "your session was cut off",
/// because only one of those means the work did not finish.
pub fn end_is_failure(reason: &str) -> bool {
    !matches!(reason, "completed" | "closed")
}

/// Turn an `https://` endpoint into the `wss://` origin for a stream.
///
/// Explicitly, rather than by string replacement of `http`: a substitution
/// would rewrite the first `http` anywhere in the URL, including in a path or
/// query. A caller pointed at a host with `http` in its name deserves better
/// than a silently mangled endpoint.
pub fn websocket_url(endpoint: &str, path: &str) -> Result<String> {
    let mut url = url::Url::parse(endpoint).context("endpoint is not a valid URL")?;
    let scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        other => anyhow::bail!("cannot open a stream over {other}"),
    };
    url.set_scheme(scheme)
        .map_err(|()| anyhow::anyhow!("could not switch the endpoint to {scheme}"))?;
    let joined = url.join(path).context("could not build the stream URL")?;
    Ok(joined.to_string())
}

/// Restores the terminal when it goes out of scope.
///
/// On drop, and from a panic hook. A process that dies in raw mode leaves a
/// terminal that does not echo, and the user's next instinct is to close the
/// window rather than to type `reset` blind.
struct RawModeGuard {
    restore: bool,
}

impl RawModeGuard {
    fn enter() -> Result<Self> {
        if !std::io::stdin().is_terminal() {
            // Not a terminal — piped input, or CI. Raw mode would be
            // meaningless and `disable_raw_mode` on exit could disturb whatever
            // the parent process is doing.
            return Ok(Self { restore: false });
        }
        crossterm::terminal::enable_raw_mode().context("could not put the terminal in raw mode")?;

        let existing = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // Restore FIRST: a panic message printed in raw mode arrives as a
            // staircase, which is exactly when it is least readable.
            let _ = crossterm::terminal::disable_raw_mode();
            existing(info);
        }));
        Ok(Self { restore: true })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.restore {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

/// Attach an interactive session to a sandbox.
pub async fn attach(
    lease: &str,
    command: &[String],
    container: Option<&str>,
    tty: bool,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<i32> {
    if output == OutputFormat::Json {
        anyhow::bail!("sandbox attach is interactive and does not support --output json");
    }
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;

    if lease_uses_iroh(&config, lease, output).await {
        return attach_iroh(&config, lease, command, container, tty).await;
    }

    let mut path = format!("/v1/sandbox-leases/{lease}/attach?tty={tty}");
    if let Some(container) = container {
        path.push_str(&format!("&container={container}"));
    }
    for argument in command {
        path.push_str(&format!("&command={}", urlencoding_minimal(argument)));
    }

    let mut socket = open_stream(&config, &path, OutputFormat::Text).await?;
    let _raw = if tty {
        Some(RawModeGuard::enter()?)
    } else {
        None
    };

    // The initial size, before anything is typed: a shell that starts thinking
    // the terminal is 80x24 renders its first prompt wrong, and no later
    // resize event will arrive to correct it if the window never changes.
    if tty
        && let Ok((width, height)) = crossterm::terminal::size()
        && let Some(frame) = resize_frame(width, height)
    {
        socket.send(frame).await.ok();
    }

    let reason = pump_terminal(&mut socket, tty).await?;
    if end_is_failure(&reason) {
        eprintln!("kobe: session ended: {reason}");
        return Ok(super::sandbox::CLI_FAILURE_EXIT);
    }
    Ok(0)
}

/// Where `kobe attach --session` finds `kobe-runner` when not told otherwise:
/// the path the Kobe workspace images ship it at, and set as `runnerPath`.
pub const DEFAULT_RUNNER_PATH: &str = "/kobe-runner";

/// End reason for a stream the caller left with `~.`. Hyphenated so it cannot
/// collide with a server reason, which are snake_case.
const LOCAL_DETACH: &str = "local-detach";

/// A connection that lasted this long was a success, and resets the backoff.
const SESSION_STABLE_AFTER: std::time::Duration = std::time::Duration::from_secs(10);

/// Consecutive failed reconnects before giving up: about five minutes.
const MAX_SESSION_RECONNECTS: u32 = 30;

const MAX_RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(10);

/// Whether `name` can name a runner session: the runner's own id rule,
/// lowercase letters, digits and `-`, at most 64 bytes.
pub fn is_session_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Split `dev.main` into the lease selector `dev` and the session `main`.
///
/// On the last dot, so a selector that itself contains dots (a pool name may)
/// keeps them. The caller tries the whole selector first; this is only the
/// reading it falls back to.
pub fn split_session_selector(selector: &str) -> Option<(&str, &str)> {
    let (lease, session) = selector.rsplit_once('.')?;
    (!lease.is_empty() && is_session_name(session)).then_some((lease, session))
}

/// Argv that attaches to runner session `name`, creating it with `command`.
pub fn session_command(runner_path: &str, name: &str, command: &[String]) -> Vec<String> {
    let mut argv = vec![
        runner_path.to_string(),
        "session".to_string(),
        "attach".to_string(),
        "--name".to_string(),
        name.to_string(),
    ];
    if !command.is_empty() {
        argv.push("--".to_string());
        argv.extend(command.iter().cloned());
    }
    argv
}

/// Whether a stream that ended for `reason` leaves a session to reconnect to.
///
/// The shell lives in the runner, not in the stream, so a limit that ends the
/// stream ends only this connection. `completed` means the runner itself
/// exited: the shell did, or another attach took the session over. A revoked
/// lease refuses the next attach too, and a protocol violation would repeat.
fn session_reconnects_after(reason: &str) -> bool {
    !matches!(
        reason,
        "completed" | "revoked" | "protocol_violation" | LOCAL_DETACH
    )
}

fn reconnect_delay(failures: u32) -> std::time::Duration {
    let exponent = failures.saturating_sub(1).min(4);
    std::time::Duration::from_secs(1 << exponent).min(MAX_RECONNECT_DELAY)
}

/// A stream Kobe refused to open, as opposed to one it could not be reached
/// for. Retrying a refusal only repeats it.
fn is_refusal(error: &anyhow::Error) -> bool {
    let status = error.chain().find_map(|cause| {
        if let Some(tokio_tungstenite::tungstenite::Error::Http(response)) = cause.downcast_ref() {
            return Some(response.status().as_u16());
        }
        cause
            .downcast_ref::<IrohSessionRefused>()
            .map(|refused| refused.0)
    });
    matches!(status, Some(code) if (400..500).contains(&code) && code != 408 && code != 429)
}

/// ssh's escape sequence: `~.` typed at the start of a line detaches.
///
/// Only at the start of a line, so a `~` in a path or a word is sent at once.
/// `~~` sends one `~`, and a held `~` followed by anything else sends both.
#[derive(Debug, Default)]
pub struct EscapeFilter {
    mid_line: bool,
    holding: bool,
}

impl EscapeFilter {
    /// The bytes to forward, and whether the caller asked to detach. Bytes
    /// after the escape are dropped: they were typed to a session that is
    /// being left.
    pub fn filter(&mut self, input: &[u8]) -> (Vec<u8>, bool) {
        let mut forward = Vec::with_capacity(input.len() + 1);
        for &byte in input {
            if self.holding {
                self.holding = false;
                match byte {
                    b'.' => return (forward, true),
                    b'~' => {
                        forward.push(b'~');
                        self.mid_line = true;
                        continue;
                    }
                    _ => forward.push(b'~'),
                }
            } else if !self.mid_line && byte == b'~' {
                self.holding = true;
                continue;
            }
            forward.push(byte);
            self.mid_line = !matches!(byte, b'\r' | b'\n');
        }
        (forward, false)
    }
}

/// `kobe attach --session`: a terminal that survives its connection.
///
/// The shell runs under `kobe-runner session` in the sandbox, detached from
/// the exec, so this side only has to reconnect. Any end the runner did not
/// choose (a dropped network, an operator restart, the stream's idle or
/// duration bound) is followed by a reconnect, and the runner redraws the
/// screen. `~.` at the start of a line detaches and leaves the shell running.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
pub async fn attach_session(
    lease: &str,
    name: &str,
    runner_path: &str,
    command: &[String],
    container: Option<&str>,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<i32> {
    use super::sandbox::CLI_FAILURE_EXIT;

    if output == OutputFormat::Json {
        anyhow::bail!("sandbox attach is interactive and does not support --output json");
    }
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("--session needs an interactive terminal");
    }
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;
    let argv = session_command(runner_path, name, command);
    let iroh = lease_uses_iroh(&config, lease, output).await;

    let _raw = RawModeGuard::enter()?;
    let mut input = spawn_stdin_reader();
    let mut escape = EscapeFilter::default();
    let detached = || {
        eprint!("\r\n[kobe: detached; `kobe attach {lease} --session {name}` resumes]\r\n");
        Ok(0)
    };
    let mut failures = 0u32;
    loop {
        let started = tokio::time::Instant::now();
        let outcome = session_once(
            &config,
            lease,
            &argv,
            container,
            iroh,
            &mut input,
            &mut escape,
        )
        .await;
        if started.elapsed() >= SESSION_STABLE_AFTER {
            failures = 0;
        }
        let why = match outcome {
            Ok(reason) if reason == LOCAL_DETACH => return detached(),
            Ok(reason) if reason == "completed" => return Ok(0),
            Ok(reason) if !session_reconnects_after(&reason) => {
                eprint!("\r\nkobe: session ended: {reason}\r\n");
                return Ok(CLI_FAILURE_EXIT);
            }
            Ok(reason) => reason,
            Err(error) if is_refusal(&error) => {
                eprint!("\r\nkobe: {error:#}\r\n");
                return Ok(CLI_FAILURE_EXIT);
            }
            Err(error) => format!("{error:#}"),
        };

        failures += 1;
        if failures > MAX_SESSION_RECONNECTS {
            eprint!("\r\nkobe: giving up after {MAX_SESSION_RECONNECTS} reconnects: {why}\r\n");
            return Ok(CLI_FAILURE_EXIT);
        }
        let delay = reconnect_delay(failures);
        eprint!(
            "\r\n[kobe: connection lost ({why}); reconnecting in {}s, ~. to stop]\r\n",
            delay.as_secs()
        );
        if wait_or_detach(delay, &mut input, &mut escape).await {
            return detached();
        }
    }
}

#[cfg(not(unix))]
#[allow(clippy::too_many_arguments)]
pub async fn attach_session(
    _lease: &str,
    _name: &str,
    _runner_path: &str,
    _command: &[String],
    _container: Option<&str>,
    _target_override: Option<&str>,
    _endpoint_override: Option<&str>,
    _output: OutputFormat,
) -> Result<i32> {
    anyhow::bail!("--session is supported only on unix terminals")
}

/// One connection to the session, until it ends for any reason.
#[cfg(unix)]
async fn session_once(
    config: &ResolvedConfig,
    lease: &str,
    argv: &[String],
    container: Option<&str>,
    iroh: bool,
    input: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    escape: &mut EscapeFilter,
) -> Result<String> {
    // The initial size on every connection: the runner resizes the shell to
    // whichever terminal attached last.
    let size = crossterm::terminal::size()
        .ok()
        .and_then(|(width, height)| resize_frame(width, height));
    if iroh {
        let mut body = serde_json::json!({
            "operation": "attach",
            "tty": true,
            "command": argv,
        });
        if let Some(container) = container {
            body["container"] = serde_json::json!(container);
        }
        let mut link = dial_iroh_session(config, lease, OutputFormat::Text, body).await?;
        if let Some(Message::Binary(frame)) = size {
            write_blob(&mut link.send, &frame).await.ok();
        }
        pump_raw_iroh(&mut link, input, Some(escape)).await
    } else {
        let mut path = format!("/v1/sandbox-leases/{lease}/attach?tty=true");
        if let Some(container) = container {
            path.push_str(&format!("&container={container}"));
        }
        for argument in argv {
            path.push_str(&format!("&command={}", urlencoding_minimal(argument)));
        }
        let mut socket = open_stream(config, &path, OutputFormat::Text).await?;
        if let Some(frame) = size {
            socket.send(frame).await.ok();
        }
        pump_raw(&mut socket, input, Some(escape)).await
    }
}

/// Sleep out a reconnect delay, unless the caller detaches first.
///
/// Keystrokes typed while disconnected are dropped rather than queued: the
/// caller cannot see what they would land on, and a queued `rm` reaching a
/// shell after an unseen screen change is worse than retyping.
#[cfg(unix)]
async fn wait_or_detach(
    delay: std::time::Duration,
    input: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    escape: &mut EscapeFilter,
) -> bool {
    let sleep = tokio::time::sleep(delay);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            _ = &mut sleep => return false,
            bytes = input.recv() => {
                let Some(bytes) = bytes else {
                    (&mut sleep).await;
                    return false;
                };
                // Ctrl-C has no shell to reach while disconnected, so it
                // stops the reconnecting instead.
                if escape.filter(&bytes).1 || bytes.contains(&0x03) {
                    return true;
                }
            }
        }
    }
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn open_stream(config: &ResolvedConfig, path: &str, output: OutputFormat) -> Result<Socket> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let url = websocket_url(config.endpoint.as_str(), path)?;
    let token = match output {
        OutputFormat::Text => get_auth_header(config, "GET", path, b"").await?,
        OutputFormat::Json => get_auth_header_noninteractive(config, "GET", path, b"").await?,
    };

    let mut request = url
        .as_str()
        .into_client_request()
        .context("could not build the stream request")?;
    if let Some(token) = token {
        request.headers_mut().insert(
            "Authorization",
            token.parse().context("authorization header is not valid")?,
        );
    }

    let (socket, response) = tokio_tungstenite::connect_async(request)
        .await
        .context("could not open the stream")?;
    // A non-101 cannot reach here — `connect_async` fails first — but the
    // status is worth checking rather than assumed, because a proxy that
    // upgraded something else would otherwise look like success.
    if response.status().as_u16() != 101 {
        anyhow::bail!("stream was not upgraded (HTTP {})", response.status());
    }
    Ok(socket)
}

/// Copy between this terminal and the stream until one of them ends.
/// Write one server frame to the local terminal.
///
/// Returns the end reason once the session is over, so both input paths share
/// one definition of "the stream said we are done".
fn apply_server_frame(message: &Message) -> Option<String> {
    match parse_server_frame(message) {
        Some(ServerFrame::Stdout(bytes)) => {
            let mut out = std::io::stdout();
            out.write_all(&bytes).ok();
            out.flush().ok();
            None
        }
        Some(ServerFrame::Stderr(bytes)) => {
            let mut err = std::io::stderr();
            err.write_all(&bytes).ok();
            err.flush().ok();
            None
        }
        Some(ServerFrame::Ended { reason }) => Some(reason),
        // A channel this client does not know. Ignored so a server that adds
        // one does not break a client that never needed it.
        Some(ServerFrame::Unknown) | None => None,
    }
}

async fn pump_terminal(socket: &mut Socket, tty: bool) -> Result<String> {
    if !tty {
        return pump_pipe(socket).await;
    }
    #[cfg(unix)]
    {
        pump_raw(socket, &mut spawn_stdin_reader(), None).await
    }
    #[cfg(not(unix))]
    {
        pump_key_events(socket).await
    }
}

/// Forward stdin and stdout as opaque bytes, with no terminal in the loop.
///
/// This is `--no-tty`: the caller is a pipe, not a person. An `ssh` running
/// `kobe ssh-proxy` as its ProxyCommand speaks the SSH protocol over these two
/// descriptors, and any interpretation of the bytes — decoding keystrokes,
/// raw mode, a resize watcher that opens the controlling terminal — either
/// corrupts the stream or, with no terminal at all, aborts the process.
/// crossterm's event reader is the latter case: it panics when it cannot open
/// one, which is exactly the situation here.
async fn pump_pipe(socket: &mut Socket) -> Result<String> {
    let mut receiver = spawn_stdin_reader();
    loop {
        tokio::select! {
            inbound = socket.next() => {
                let Some(message) = inbound else {
                    return Ok("closed".to_string());
                };
                let message = message.context("stream failed")?;
                if let Some(reason) = apply_server_frame(&message) {
                    return Ok(reason);
                }
            }
            outbound = receiver.recv() => {
                // stdin at EOF is not the end of the session: the workload may
                // still be writing. Stop forwarding and keep rendering.
                let Some(bytes) = outbound else { continue };
                socket.send(client_frame(CHANNEL_STDIN, &bytes)).await?;
            }
        }
    }
}

/// Read this process's stdin on its own thread and hand the bytes to a channel.
///
/// A dedicated thread rather than `tokio::io::stdin()`: a read cancelled by
/// `select!` can lose whatever it had already taken from the fd, and the
/// bytes it would lose are the user's keystrokes. Handing them to a channel
/// makes the branch cancel-safe, because a receive that loses the race
/// leaves the message queued. The channel closes at EOF.
///
/// One per stdin, not one per stream. The thread holds the stdin lock while
/// it blocks in `read`, so a second reader started on reconnect would wait for
/// the first to wake up, and the keystroke that woke it would be lost.
fn spawn_stdin_reader() -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin().lock();
        let mut buffer = [0u8; 4096];
        loop {
            match stdin.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    if sender.blocking_send(buffer[..read].to_vec()).is_err() {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });
    receiver
}

/// Forward stdin byte for byte, interpreting nothing.
///
/// A full-screen program on the far side — zellij, tmux, vim — negotiates its
/// own input modes by writing escape sequences that reach the real terminal,
/// which then answers on stdin. Mouse reporting, bracketed paste, focus events
/// and the kitty keyboard protocol all work that way. A client that decodes
/// keystrokes and re-encodes them cannot participate: it drops every sequence
/// its own key table has no name for, so the remote program enables a mode and
/// then never hears from it. Copying the bytes through is both simpler and
/// strictly more capable.
///
/// The cost is that resizes no longer arrive as decoded events, because
/// nothing is decoding. `SIGWINCH` carries them instead.
///
/// With an `escape` filter, `~.` at the start of a line ends the pump with
/// [`LOCAL_DETACH`] instead of reaching the workload.
#[cfg(unix)]
async fn pump_raw(
    socket: &mut Socket,
    input: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut escape: Option<&mut EscapeFilter>,
) -> Result<String> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut resized =
        signal(SignalKind::window_change()).context("could not watch for terminal resizes")?;
    let mut input_open = true;

    loop {
        tokio::select! {
            inbound = socket.next() => {
                let Some(message) = inbound else {
                    return Ok("closed".to_string());
                };
                let message = message.context("stream failed")?;
                if let Some(reason) = apply_server_frame(&message) {
                    return Ok(reason);
                }
            }
            outbound = input.recv(), if input_open => {
                // stdin at EOF is not the end of the session: the workload may
                // still be writing. Stop forwarding and keep rendering.
                let Some(bytes) = outbound else {
                    input_open = false;
                    continue;
                };
                let (bytes, detach) = match escape.as_deref_mut() {
                    Some(filter) => filter.filter(&bytes),
                    None => (bytes, false),
                };
                if !bytes.is_empty() {
                    socket.send(client_frame(CHANNEL_STDIN, &bytes)).await?;
                }
                if detach {
                    return Ok(LOCAL_DETACH.to_string());
                }
            }
            _ = resized.recv() => {
                if let Ok((width, height)) = crossterm::terminal::size()
                    && let Some(frame) = resize_frame(width, height) {
                    socket.send(frame).await?;
                }
            }
        }
    }
}

/// Decode key events and re-encode them as bytes.
///
/// The fallback where no `SIGWINCH` exists. Lossy by construction — see
/// [`key_to_bytes`] — so it is only reached off Unix, and only with a terminal:
/// a pipe goes through [`pump_pipe`], because the event reader needs a
/// terminal to open and aborts the process without one.
#[cfg(not(unix))]
async fn pump_key_events(socket: &mut Socket) -> Result<String> {
    use crossterm::event::{Event, EventStream};

    let mut events = EventStream::new();
    loop {
        tokio::select! {
            inbound = socket.next() => {
                let Some(message) = inbound else {
                    return Ok("closed".to_string());
                };
                let message = message.context("stream failed")?;
                if let Some(reason) = apply_server_frame(&message) {
                    return Ok(reason);
                }
            }
            event = events.next() => {
                let Some(event) = event else { continue };
                match event.context("terminal input failed")? {
                    Event::Key(key) => {
                        if let Some(bytes) = key_to_bytes(&key) {
                            socket.send(client_frame(CHANNEL_STDIN, &bytes)).await?;
                        }
                    }
                    // Forwarded so the workload's own rendering follows the
                    // window. Without it, resizing mid-session leaves a shell
                    // drawing to a width that no longer exists.
                    Event::Resize(width, height) => {
                        if let Some(frame) = resize_frame(width, height) {
                            socket.send(frame).await?;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Encode one key event as the bytes a terminal would have sent.
///
/// Only what a shell actually needs. An incomplete mapping is honest — the key
/// simply does nothing — where a wrong one sends a byte the workload acts on.
pub fn key_to_bytes(key: &crossterm::event::KeyEvent) -> Option<Vec<u8>> {
    use crossterm::event::{KeyCode, KeyModifiers};

    // Control characters first: Ctrl-C has to reach the workload rather than
    // killing the CLI, which is the whole reason raw mode is on.
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && let KeyCode::Char(character) = key.code
    {
        let lower = character.to_ascii_lowercase();
        if lower.is_ascii_lowercase() {
            return Some(vec![(lower as u8) - b'a' + 1]);
        }
    }

    Some(match key.code {
        KeyCode::Char(character) => character.to_string().into_bytes(),
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Esc => vec![0x1b],
        KeyCode::Up => b"\x1b[A".to_vec(),
        KeyCode::Down => b"\x1b[B".to_vec(),
        KeyCode::Right => b"\x1b[C".to_vec(),
        KeyCode::Left => b"\x1b[D".to_vec(),
        KeyCode::Home => b"\x1b[H".to_vec(),
        KeyCode::End => b"\x1b[F".to_vec(),
        KeyCode::Delete => b"\x1b[3~".to_vec(),
        KeyCode::PageUp => b"\x1b[5~".to_vec(),
        KeyCode::PageDown => b"\x1b[6~".to_vec(),
        _ => return None,
    })
}

/// Percent-encode the few characters that cannot appear in a query value.
///
/// Deliberately minimal and explicit rather than pulled from a crate: the only
/// job is to stop an argument from ending the query or introducing a parameter.
fn urlencoding_minimal(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// Forward a declared sandbox port to a local address.
///
/// Binds `127.0.0.1` unless asked otherwise. A forward reachable from the
/// network turns "a port on my machine" into "a port on the office LAN", and
/// the sandbox behind it belongs to one caller.
pub async fn port_forward(
    lease: &str,
    local_port: u16,
    remote: &str,
    bind: &str,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<i32> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;

    let listener = tokio::net::TcpListener::bind((bind, local_port))
        .await
        .with_context(|| format!("could not bind {bind}:{local_port}"))?;
    let bound = listener.local_addr()?;

    match output {
        OutputFormat::Json => emit_port_forward_json(&serde_json::json!({
            "apiVersion": super::sandbox::SANDBOX_CLI_API_VERSION,
            "event": "listening",
            "lease": lease,
            "listening": bound.to_string(),
            "remote": remote,
        }))?,
        OutputFormat::Text => {
            println!("Forwarding {bound} -> {lease}:{remote}");
        }
    }

    let path = format!(
        "/v1/sandbox-leases/{lease}/port-forward?port={}",
        urlencoding_minimal(remote)
    );
    let iroh = lease_uses_iroh(&config, lease, output).await;

    // A browser opens parallel connections for an HTML shell, JavaScript, CSS,
    // and the upgraded WebSocket. Serving only the first connection left those
    // later requests queued behind an HTTP keep-alive connection, which makes
    // browser clients such as noVNC appear to load forever. Bound the fan-out
    // so the forward remains a local, resource-limited convenience rather than
    // an unbounded stream factory.
    let permits = Arc::new(tokio::sync::Semaphore::new(
        MAX_CONCURRENT_PORT_FORWARD_CONNECTIONS,
    ));
    loop {
        let (local, peer) = listener.accept().await.context("accept failed")?;
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .context("port-forward connection limiter closed")?;
        let config = config.clone();
        let lease = lease.to_owned();
        let remote = remote.to_owned();
        let path = path.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut local = local;
            let result =
                forward_connection(&mut local, &config, &lease, &remote, &path, iroh, output).await;
            if let Err(error) = result {
                let _ = report_port_forward_error(output, &lease, peer, &format!("{error:#}"));
            }
        });
    }
}

pub(crate) async fn forward_connection(
    local: &mut tokio::net::TcpStream,
    config: &ResolvedConfig,
    lease: &str,
    remote: &str,
    path: &str,
    iroh: bool,
    output: OutputFormat,
) -> Result<()> {
    if iroh {
        let mut link = dial_iroh_session(
            config,
            lease,
            output,
            serde_json::json!({
                "operation": "port-forward",
                "port": remote,
            }),
        )
        .await?;
        pump_connection_iroh(local, &mut link).await
    } else {
        let mut socket = open_stream(config, path, output).await?;
        pump_connection(local, &mut socket).await
    }
}

/// Report long-lived forward failures without contaminating machine stderr.
///
/// JSON mode is an event stream because the listener remains alive across
/// individual connection failures. Every event is one flushed NDJSON record.
fn report_port_forward_error(
    output: OutputFormat,
    lease: &str,
    peer: std::net::SocketAddr,
    error: &str,
) -> Result<()> {
    match output {
        OutputFormat::Json => emit_port_forward_json(&serde_json::json!({
            "apiVersion": super::sandbox::SANDBOX_CLI_API_VERSION,
            "event": "connectionError",
            "lease": lease,
            "peer": peer.to_string(),
            "error": error,
        })),
        OutputFormat::Text => {
            eprintln!("kobe: {peer} could not be forwarded: {error}");
            Ok(())
        }
    }
}

fn emit_port_forward_json(value: &serde_json::Value) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

async fn pump_connection(local: &mut tokio::net::TcpStream, socket: &mut Socket) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            read = local.read(&mut buffer) => {
                match read? {
                    0 => return Ok(()),
                    count => {
                        socket
                            .send(client_frame(CHANNEL_STDIN, &buffer[..count]))
                            .await?;
                    }
                }
            }
            inbound = socket.next() => {
                let Some(message) = inbound else { return Ok(()) };
                match parse_server_frame(&message?) {
                    Some(ServerFrame::Stdout(bytes)) | Some(ServerFrame::Stderr(bytes)) => {
                        local.write_all(&bytes).await?;
                    }
                    Some(ServerFrame::Ended { reason }) => {
                        if end_is_failure(&reason) {
                            anyhow::bail!("forward ended: {reason}");
                        }
                        return Ok(());
                    }
                    Some(ServerFrame::Unknown) | None => {}
                }
            }
        }
    }
}

/// ALPN must match the operator's `kobe-sandbox/1`. Duplicated rather than
/// shared: this crate cannot depend on the operator binary.
const KOBE_SANDBOX_ALPN: &[u8] = b"kobe-sandbox/1";
const MAX_BLOB_BYTES: usize = 1024 * 1024;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct IrohSessionOffer {
    node_id: String,
    ticket: String,
    #[serde(default)]
    relay: String,
}

#[derive(Debug, serde::Deserialize)]
struct LeaseTransportView {
    #[serde(default)]
    transport: Option<String>,
}

pub(crate) async fn lease_uses_iroh(
    config: &ResolvedConfig,
    lease: &str,
    output: OutputFormat,
) -> bool {
    let path = format!("/v1/sandbox-leases/{lease}");
    let token = match get_auth_header_for_output(config, "GET", &path, b"", output).await {
        Ok(token) => token,
        Err(_) => return false,
    };
    let response = match with_auth(
        authed_client().get(format!("{}{path}", config.endpoint.as_str())),
        &token,
    )
    .send()
    .await
    {
        Ok(response) => response,
        Err(_) => return false,
    };
    if !response.status().is_success() {
        return false;
    }
    match response.json::<LeaseTransportView>().await {
        Ok(body) => body.transport.as_deref() == Some("iroh"),
        Err(_) => false,
    }
}

async fn request_iroh_session(
    config: &ResolvedConfig,
    lease: &str,
    output: OutputFormat,
    body: serde_json::Value,
) -> Result<IrohSessionOffer> {
    let path = format!("/v1/sandbox-leases/{lease}/session");
    let encoded = serde_json::to_vec(&body).context("session body")?;
    // SSH signatures are verified against an empty body on this API.
    let token = get_auth_header_for_output(config, "POST", &path, b"", output).await?;
    let response = with_auth(
        authed_client()
            .post(format!("{}{path}", config.endpoint.as_str()))
            .header("content-type", "application/json")
            .body(encoded),
        &token,
    )
    .send()
    .await
    .reaching(config)?;
    if !response.status().is_success() {
        return Err(IrohSessionRefused(response.status().as_u16()).into());
    }
    response.json().await.context("iroh session offer")
}

/// The operator answered the iroh session request with a non-success status.
#[derive(Debug)]
struct IrohSessionRefused(u16);

impl std::fmt::Display for IrohSessionRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "iroh session was refused (HTTP {})", self.0)
    }
}

impl std::error::Error for IrohSessionRefused {}

async fn write_blob<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> std::io::Result<()> {
    if data.len() > MAX_BLOB_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "iroh blob exceeds MAX_BLOB_BYTES",
        ));
    }
    let len = u32::try_from(data.len()).expect("len fits u32");
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await
}

async fn read_blob<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_BLOB_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "iroh blob length is not a usable frame",
        ));
    }
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    Ok(Some(data))
}

fn decode_hex(input: &str) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        anyhow::bail!("ticket is not hex");
    }
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).context("ticket is not hex"))
        .collect()
}

fn relay_mode(configured: &str) -> Result<iroh::RelayMode> {
    match configured.trim().to_ascii_lowercase().as_str() {
        "" | "public" => Ok(iroh::RelayMode::Default),
        "disabled" => Ok(iroh::RelayMode::Disabled),
        urls => {
            let map = iroh::RelayMap::empty();
            for url in urls
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
            {
                let parsed: iroh::RelayUrl = url
                    .parse()
                    .with_context(|| format!("invalid iroh relay URL: {url}"))?;
                let cfg = std::sync::Arc::new(iroh::RelayConfig::new(parsed.clone(), None));
                map.insert(parsed, cfg);
            }
            Ok(iroh::RelayMode::Custom(map))
        }
    }
}

struct IrohLink {
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    _conn: iroh::endpoint::Connection,
    _endpoint: iroh::Endpoint,
}

async fn dial_iroh_session(
    config: &ResolvedConfig,
    lease: &str,
    output: OutputFormat,
    body: serde_json::Value,
) -> Result<IrohLink> {
    let offer = request_iroh_session(config, lease, output, body).await?;
    let node: iroh::EndpointId = offer
        .node_id
        .parse()
        .context("iroh node id from the session offer is not valid")?;
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
        .relay_mode(relay_mode(&offer.relay)?)
        .bind()
        .await
        .context("bind local iroh endpoint")?;
    if offer.relay != "disabled" {
        tokio::time::timeout(std::time::Duration::from_secs(30), endpoint.online())
            .await
            .context("local iroh endpoint did not come online")?;
    }
    let conn = endpoint
        .connect(node, KOBE_SANDBOX_ALPN)
        .await
        .context("dial operator iroh endpoint")?;
    let (mut send, recv) = conn.open_bi().await.context("open iroh stream")?;
    let ticket = decode_hex(&offer.ticket)?;
    write_blob(&mut send, &ticket)
        .await
        .context("send iroh session ticket")?;
    Ok(IrohLink {
        send,
        recv,
        _conn: conn,
        _endpoint: endpoint,
    })
}

async fn attach_iroh(
    config: &ResolvedConfig,
    lease: &str,
    command: &[String],
    container: Option<&str>,
    tty: bool,
) -> Result<i32> {
    let mut body = serde_json::json!({
        "operation": "attach",
        "tty": tty,
    });
    if !command.is_empty() {
        body["command"] = serde_json::json!(command);
    }
    if let Some(container) = container {
        body["container"] = serde_json::json!(container);
    }
    let mut link = dial_iroh_session(config, lease, OutputFormat::Text, body).await?;
    let _raw = if tty {
        Some(RawModeGuard::enter()?)
    } else {
        None
    };
    if tty
        && let Ok((width, height)) = crossterm::terminal::size()
        && width > 0
        && height > 0
    {
        let payload = format!(r#"{{"width":{width},"height":{height}}}"#);
        let mut frame = Vec::with_capacity(payload.len() + 1);
        frame.push(CHANNEL_RESIZE);
        frame.extend_from_slice(payload.as_bytes());
        write_blob(&mut link.send, &frame).await.ok();
    }
    let reason = pump_terminal_iroh(&mut link, tty).await?;
    if end_is_failure(&reason) {
        eprintln!("kobe: session ended: {reason}");
        return Ok(super::sandbox::CLI_FAILURE_EXIT);
    }
    Ok(0)
}

fn apply_server_blob(payload: &[u8]) -> Option<String> {
    match parse_server_payload(payload) {
        Some(ServerFrame::Stdout(bytes)) => {
            let mut out = std::io::stdout();
            out.write_all(&bytes).ok();
            out.flush().ok();
            None
        }
        Some(ServerFrame::Stderr(bytes)) => {
            let mut err = std::io::stderr();
            err.write_all(&bytes).ok();
            err.flush().ok();
            None
        }
        Some(ServerFrame::Ended { reason }) => Some(reason),
        Some(ServerFrame::Unknown) | None => None,
    }
}

async fn pump_terminal_iroh(link: &mut IrohLink, tty: bool) -> Result<String> {
    #[cfg(unix)]
    if tty {
        return pump_raw_iroh(link, &mut spawn_stdin_reader(), None).await;
    }
    pump_key_events_iroh(link).await
}

/// [`pump_raw`] over an iroh stream.
#[cfg(unix)]
async fn pump_raw_iroh(
    link: &mut IrohLink,
    input: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut escape: Option<&mut EscapeFilter>,
) -> Result<String> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut resized =
        signal(SignalKind::window_change()).context("could not watch for terminal resizes")?;
    let mut input_open = true;

    loop {
        tokio::select! {
            inbound = read_blob(&mut link.recv) => {
                let Some(payload) = inbound.context("iroh stream failed")? else {
                    return Ok("closed".to_string());
                };
                if let Some(reason) = apply_server_blob(&payload) {
                    return Ok(reason);
                }
            }
            outbound = input.recv(), if input_open => {
                let Some(bytes) = outbound else {
                    input_open = false;
                    continue;
                };
                let (bytes, detach) = match escape.as_deref_mut() {
                    Some(filter) => filter.filter(&bytes),
                    None => (bytes, false),
                };
                if !bytes.is_empty() {
                    let mut frame = Vec::with_capacity(bytes.len() + 1);
                    frame.push(CHANNEL_STDIN);
                    frame.extend_from_slice(&bytes);
                    write_blob(&mut link.send, &frame).await?;
                }
                if detach {
                    return Ok(LOCAL_DETACH.to_string());
                }
            }
            _ = resized.recv() => {
                if let Ok((width, height)) = crossterm::terminal::size()
                    && width > 0
                    && height > 0
                {
                    let payload = format!(r#"{{"width":{width},"height":{height}}}"#);
                    let mut frame = Vec::with_capacity(payload.len() + 1);
                    frame.push(CHANNEL_RESIZE);
                    frame.extend_from_slice(payload.as_bytes());
                    write_blob(&mut link.send, &frame).await?;
                }
            }
        }
    }
}

async fn pump_key_events_iroh(link: &mut IrohLink) -> Result<String> {
    use crossterm::event::{Event, EventStream};
    use futures_util::StreamExt;

    let mut events = EventStream::new();
    loop {
        tokio::select! {
            inbound = read_blob(&mut link.recv) => {
                let Some(payload) = inbound.context("iroh stream failed")? else {
                    return Ok("closed".to_string());
                };
                if let Some(reason) = apply_server_blob(&payload) {
                    return Ok(reason);
                }
            }
            event = events.next() => {
                let Some(event) = event else { continue };
                let Event::Key(key) = event.context("keyboard")? else { continue };
                if let Some(bytes) = key_to_bytes(&key) {
                    let mut frame = Vec::with_capacity(bytes.len() + 1);
                    frame.push(CHANNEL_STDIN);
                    frame.extend_from_slice(&bytes);
                    write_blob(&mut link.send, &frame).await?;
                }
            }
        }
    }
}

async fn pump_connection_iroh(
    local: &mut tokio::net::TcpStream,
    link: &mut IrohLink,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            read = local.read(&mut buffer) => {
                match read? {
                    0 => return Ok(()),
                    count => {
                        let mut frame = Vec::with_capacity(count + 1);
                        frame.push(CHANNEL_STDIN);
                        frame.extend_from_slice(&buffer[..count]);
                        write_blob(&mut link.send, &frame).await?;
                    }
                }
            }
            inbound = read_blob(&mut link.recv) => {
                let Some(payload) = inbound? else { return Ok(()) };
                match parse_server_payload(&payload) {
                    Some(ServerFrame::Stdout(bytes)) | Some(ServerFrame::Stderr(bytes)) => {
                        local.write_all(&bytes).await?;
                    }
                    Some(ServerFrame::Ended { reason }) => {
                        if end_is_failure(&reason) {
                            anyhow::bail!("forward ended: {reason}");
                        }
                        return Ok(());
                    }
                    Some(ServerFrame::Unknown) | None => {}
                }
            }
        }
    }
}

/// Split `LOCAL:REMOTE` into its parts.
///
/// The remote half stays a string: it may be a pool-declared *name*, and the
/// server resolves it. Parsing it as a number here would refuse `8080:http`,
/// which is the form an administrator publishing named ports intends people to
/// use.
pub fn split_forward_spec(spec: &str) -> Result<(u16, String)> {
    let (local, remote) = spec
        .split_once(':')
        .context("expected LOCAL:REMOTE, for example 8080:http or 8080:3000")?;
    let local: u16 = local
        .parse()
        .with_context(|| format!("{local} is not a local port"))?;
    if remote.is_empty() {
        anyhow::bail!("a remote port or declared port name is required");
    }
    Ok((local, remote.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    /// Frames carry their channel and nothing else is prepended.
    #[test]
    fn client_frames_are_channel_prefixed() {
        let Message::Binary(framed) = client_frame(CHANNEL_STDIN, b"hi") else {
            panic!("frames are binary");
        };
        assert_eq!(framed.as_ref(), &[CHANNEL_STDIN, b'h', b'i']);

        let Some(Message::Binary(resize)) = resize_frame(120, 40) else {
            panic!("frames are binary");
        };
        assert_eq!(resize[0], CHANNEL_RESIZE);
        assert_eq!(&resize[1..], br#"{"width":120,"height":40}"#);
    }

    /// A transient zero-sized PTY must not make the client send a frame the
    /// server is required to reject.
    #[test]
    fn zero_terminal_dimensions_are_not_sent() {
        assert!(resize_frame(0, 24).is_none());
        assert!(resize_frame(80, 0).is_none());
        assert!(resize_frame(0, 0).is_none());
    }

    /// The client tolerates channels it does not know; the server does not.
    ///
    /// The asymmetry is deliberate. A server that adds a channel must not break
    /// clients that never needed it. But a *server* ignoring an unknown frame
    /// from a client would leave that client believing it sent something —
    /// a resize, a keystroke — that never arrived.
    #[test]
    fn unknown_server_channels_are_ignored_not_fatal() {
        assert_eq!(
            parse_server_frame(&Message::Binary(vec![CHANNEL_STDOUT, b'o'].into())),
            Some(ServerFrame::Stdout(b"o".to_vec()))
        );
        assert_eq!(
            parse_server_frame(&Message::Binary(vec![CHANNEL_STDERR, b'e'].into())),
            Some(ServerFrame::Stderr(b"e".to_vec()))
        );
        for unknown in [5u8, 42, 255] {
            assert_eq!(
                parse_server_frame(&Message::Binary(vec![unknown, b'x'].into())),
                Some(ServerFrame::Unknown),
                "channel {unknown} must not be fatal"
            );
        }
        // An empty frame carries no channel.
        assert_eq!(parse_server_frame(&Message::Binary(vec![].into())), None);
    }

    /// A cut-off session must not look like a clean one.
    ///
    /// An unattended caller has to tell "your session ended normally" from
    /// "your session was cut off", because only one of those means the work did
    /// not finish.
    #[test]
    fn only_a_clean_end_exits_zero() {
        for clean in ["completed", "closed"] {
            assert!(!end_is_failure(clean));
        }
        for cut_off in [
            "revoked",
            "idle_timeout",
            "duration_exceeded",
            "byte_limit_exceeded",
            "protocol_violation",
            "target_error",
            // A reason from a newer server. Unknown means "not one of the
            // clean ones", which is the safe reading.
            "something_new",
        ] {
            assert!(end_is_failure(cut_off), "{cut_off} must exit non-zero");
        }
    }

    /// The end reason survives, even one this client does not recognise.
    #[test]
    fn the_end_reason_is_reported_verbatim() {
        assert_eq!(
            parse_server_frame(&Message::Binary(
                [vec![CHANNEL_ERROR], br#"{"reason":"revoked"}"#.to_vec()]
                    .concat()
                    .into()
            )),
            Some(ServerFrame::Ended {
                reason: "revoked".to_string()
            })
        );
        // Malformed: better to show whatever arrived than to replace it with
        // "the stream ended", which tells the reader nothing.
        assert_eq!(
            parse_server_frame(&Message::Binary(
                [vec![CHANNEL_ERROR], b"not json".to_vec()].concat().into()
            )),
            Some(ServerFrame::Ended {
                reason: "not json".to_string()
            })
        );
    }

    /// The scheme is switched, never substituted.
    ///
    /// A string replacement of `http` would rewrite the first occurrence
    /// anywhere in the URL — a host called `http-gw.internal`, a path, a query
    /// value — and silently point the caller somewhere else.
    #[test]
    fn the_stream_url_is_derived_without_string_substitution() {
        assert_eq!(
            websocket_url("https://kobe.example", "/v1/sandbox-leases/x/attach").unwrap(),
            "wss://kobe.example/v1/sandbox-leases/x/attach"
        );
        assert_eq!(
            websocket_url("http://localhost:8080", "/v1/x").unwrap(),
            "ws://localhost:8080/v1/x"
        );

        // A host whose NAME contains the scheme must survive intact.
        let url = websocket_url("https://http-gateway.example", "/v1/x").unwrap();
        assert!(url.starts_with("wss://http-gateway.example"), "{url}");

        assert!(websocket_url("ftp://example", "/v1/x").is_err());
        assert!(websocket_url("not a url", "/v1/x").is_err());
    }

    /// Both input paths end the session on the same frame.
    ///
    /// The raw and key-event loops used to carry their own copy of this match;
    /// a reason recognised by one and not the other would have left a caller
    /// attached to a session the server considered finished.
    #[test]
    fn only_an_end_frame_ends_the_session() {
        // A malformed error payload still ends the session, carrying the raw
        // text: a reason this client cannot parse is more useful to whoever
        // reads it than silently staying attached to a finished session.
        assert_eq!(
            apply_server_frame(&Message::Binary(vec![CHANNEL_ERROR, b'{'].into())),
            Some("{".to_string())
        );
        assert_eq!(
            apply_server_frame(&Message::Close(None)),
            Some("closed".to_string())
        );
        assert_eq!(
            apply_server_frame(&Message::Binary(
                [&[CHANNEL_ERROR][..], br#"{"reason":"completed"}"#]
                    .concat()
                    .into()
            )),
            Some("completed".to_string())
        );
        // Output is written through, never treated as terminal.
        assert_eq!(
            apply_server_frame(&Message::Binary(vec![CHANNEL_STDOUT, b'h'].into())),
            None
        );
        assert_eq!(
            apply_server_frame(&Message::Binary(vec![CHANNEL_STDERR, b'h'].into())),
            None
        );
        // A channel this client has never heard of must not end the session.
        assert_eq!(
            apply_server_frame(&Message::Binary(vec![99, b'x'].into())),
            None
        );
    }

    /// Ctrl-C reaches the workload rather than killing the CLI.
    ///
    /// That is the entire reason raw mode is on: in cooked mode the terminal
    /// would deliver SIGINT here, and the caller could never interrupt a
    /// process inside their sandbox.
    #[test]
    fn control_keys_are_forwarded_as_control_bytes() {
        let control = |character: char| {
            key_to_bytes(&KeyEvent::new(
                KeyCode::Char(character),
                KeyModifiers::CONTROL,
            ))
        };
        assert_eq!(control('c'), Some(vec![0x03]));
        assert_eq!(control('d'), Some(vec![0x04]));
        assert_eq!(control('z'), Some(vec![0x1a]));
        // Case is not a different key.
        assert_eq!(control('C'), Some(vec![0x03]));

        // Ordinary keys are themselves.
        assert_eq!(
            key_to_bytes(&KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE)),
            Some(b"a".to_vec())
        );
        assert_eq!(
            key_to_bytes(&KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            Some(vec![b'\r'])
        );
        // Arrows are the escape sequences a terminal would have sent.
        assert_eq!(
            key_to_bytes(&KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)),
            Some(b"\x1b[A".to_vec())
        );

        // An unmapped key sends nothing rather than something wrong. Doing
        // nothing is a visible non-event; sending the wrong byte is one the
        // workload acts on.
        assert_eq!(
            key_to_bytes(&KeyEvent::new(KeyCode::F(13), KeyModifiers::NONE)),
            None
        );
    }

    /// `~.` detaches only where ssh's escape would: at the start of a line.
    #[test]
    fn the_escape_detaches_only_at_the_start_of_a_line() {
        let run = |chunks: &[&[u8]]| {
            let mut filter = EscapeFilter::default();
            let mut forwarded = Vec::new();
            for chunk in chunks {
                let (bytes, detach) = filter.filter(chunk);
                forwarded.extend(bytes);
                if detach {
                    return (forwarded, true);
                }
            }
            (forwarded, false)
        };

        // At the very start, after Enter, and split across reads.
        assert_eq!(run(&[b"~."]), (vec![], true));
        assert_eq!(run(&[b"ls\r~."]), (b"ls\r".to_vec(), true));
        assert_eq!(run(&[b"ls\r~", b"."]), (b"ls\r".to_vec(), true));
        // Anything after the escape was typed to a session being left.
        assert_eq!(run(&[b"~.rm -rf\r"]), (vec![], true));

        // Mid-line, a tilde is just a tilde.
        assert_eq!(run(&[b"cd ~/src\r"]), (b"cd ~/src\r".to_vec(), false));
        assert_eq!(run(&[b"a~."]), (b"a~.".to_vec(), false));
        // `~~` sends one, and a held tilde followed by anything else sends both.
        assert_eq!(run(&[b"~~."]), (b"~.".to_vec(), false));
        assert_eq!(run(&[b"~/x"]), (b"~/x".to_vec(), false));
        assert_eq!(run(&[b"~", b"\r"]), (b"~\r".to_vec(), false));
    }

    /// `dev.main` reads as a lease and a session; anything else stays whole.
    #[test]
    fn a_selector_splits_on_its_last_dot_into_a_session() {
        assert_eq!(split_session_selector("dev.main"), Some(("dev", "main")));
        assert_eq!(
            split_session_selector("kobe-dev.build-2"),
            Some(("kobe-dev", "build-2"))
        );
        // A dotted selector keeps its dots; only the last segment can be a
        // session.
        assert_eq!(
            split_session_selector("ci.gpu.main"),
            Some(("ci.gpu", "main"))
        );

        for whole in ["dev", "dev.", ".main", "dev.Main", "dev.a_b", "dev.a/b"] {
            assert_eq!(split_session_selector(whole), None, "{whole}");
        }
        assert!(is_session_name(&"a".repeat(64)));
        assert!(!is_session_name(&"a".repeat(65)));
    }

    /// The session command reaches the runner, and a program only when given.
    #[test]
    fn the_session_command_names_the_runner_and_the_session() {
        assert_eq!(
            session_command("/kobe-runner", "main", &[]),
            ["/kobe-runner", "session", "attach", "--name", "main"]
        );
        assert_eq!(
            session_command("/opt/r", "work", &["zsh".to_string()]),
            ["/opt/r", "session", "attach", "--name", "work", "--", "zsh"]
        );
    }

    /// Limits end the connection, not the session; only a final end stops.
    #[test]
    fn only_a_final_end_stops_the_reconnect_loop() {
        for again in [
            "closed",
            "idle_timeout",
            "duration_exceeded",
            "byte_limit_exceeded",
            "target_error",
            "something_new",
        ] {
            assert!(session_reconnects_after(again), "{again}");
        }
        for fin in ["completed", "revoked", "protocol_violation", LOCAL_DETACH] {
            assert!(!session_reconnects_after(fin), "{fin}");
        }
    }

    #[test]
    fn the_reconnect_delay_backs_off_to_a_ceiling() {
        let delays: Vec<u64> = (1..=7).map(|n| reconnect_delay(n).as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 10, 10, 10]);
    }

    /// A refusal is final; a network failure or an overloaded server is not.
    #[test]
    fn a_refused_stream_is_not_retried() {
        use tokio_tungstenite::tungstenite::{Error, http::Response};

        let http = |status: u16| {
            anyhow::Error::new(Error::Http(Box::new(
                Response::builder().status(status).body(None).unwrap(),
            )))
            .context("could not open the stream")
        };
        assert!(is_refusal(&http(403)));
        assert!(is_refusal(&http(404)));
        assert!(is_refusal(&anyhow::Error::new(IrohSessionRefused(409))));

        assert!(!is_refusal(&http(429)));
        assert!(!is_refusal(&http(503)));
        assert!(!is_refusal(&anyhow::anyhow!("connection reset")));
    }

    /// A forward spec keeps its remote half as a string.
    ///
    /// The remote may be a pool-declared *name*. Parsing it as a number here
    /// would refuse `8080:http`, which is the form an administrator publishing
    /// named ports intends people to use.
    #[test]
    fn a_forward_spec_accepts_named_remote_ports() {
        assert_eq!(
            split_forward_spec("8080:http").unwrap(),
            (8080, "http".into())
        );
        assert_eq!(
            split_forward_spec("8080:3000").unwrap(),
            (8080, "3000".into())
        );
        assert_eq!(split_forward_spec("0:http").unwrap(), (0, "http".into()));

        for bad in ["8080", "", ":3000", "8080:", "notaport:http", "99999:http"] {
            assert!(split_forward_spec(bad).is_err(), "{bad:?} must be refused");
        }
    }

    /// A query value cannot end the query or add a parameter.
    #[test]
    fn query_values_are_escaped() {
        assert_eq!(urlencoding_minimal("http"), "http");
        assert_eq!(urlencoding_minimal("a b"), "a%20b");
        assert_eq!(
            urlencoding_minimal("&container=other"),
            "%26container%3Dother"
        );
        assert_eq!(urlencoding_minimal("a#b?c"), "a%23b%3Fc");
        // Unreserved characters stay readable.
        assert_eq!(urlencoding_minimal("a-b_c.d~e"), "a-b_c.d~e");
    }
}
