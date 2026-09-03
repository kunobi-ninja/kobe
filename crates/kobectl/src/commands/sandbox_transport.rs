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
//! `port-forward` binds locally and forwards one connection at a time. It
//! never binds a wildcard address by default: a forward reachable from the
//! network turns "a port on my machine" into "a port on the office LAN", and
//! the sandbox behind it belongs to one caller.

use std::io::{IsTerminal, Write};

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

use super::config::{CliConfig, ResolvedConfig};
use super::{OutputFormat, get_auth_header, get_auth_header_noninteractive};

pub const CHANNEL_STDIN: u8 = 0;
pub const CHANNEL_STDOUT: u8 = 1;
pub const CHANNEL_STDERR: u8 = 2;
pub const CHANNEL_ERROR: u8 = 3;
pub const CHANNEL_RESIZE: u8 = 4;

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
    #[cfg(unix)]
    if tty {
        return pump_raw(socket).await;
    }
    pump_key_events(socket, tty).await
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
#[cfg(unix)]
async fn pump_raw(socket: &mut Socket) -> Result<String> {
    use tokio::signal::unix::{SignalKind, signal};

    // A dedicated thread rather than `tokio::io::stdin()`: a read cancelled by
    // `select!` can lose whatever it had already taken from the fd, and the
    // bytes it would lose are the user's keystrokes. Handing them to a channel
    // makes the branch cancel-safe, because a receive that loses the race
    // leaves the message queued.
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
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

    let mut resized =
        signal(SignalKind::window_change()).context("could not watch for terminal resizes")?;

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
/// [`key_to_bytes`] — so it is only reached off Unix, or when there is no tty
/// to put in raw mode.
async fn pump_key_events(socket: &mut Socket, tty: bool) -> Result<String> {
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
            event = events.next(), if tty => {
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

    // One connection at a time, on purpose. Concurrency here would need one
    // upstream stream per local connection, and each of those counts against
    // the lease's own concurrency limit — a browser opening six sockets would
    // exhaust it and the failures would look like the sandbox misbehaving.
    loop {
        let (mut local, peer) = listener.accept().await.context("accept failed")?;
        let mut socket = match open_stream(&config, &path, output).await {
            Ok(socket) => socket,
            Err(error) => {
                report_port_forward_error(output, lease, peer, &format!("{error:#}"))?;
                continue;
            }
        };
        if let Err(error) = pump_connection(&mut local, &mut socket).await {
            report_port_forward_error(output, lease, peer, &format!("{error:#}"))?;
        }
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
