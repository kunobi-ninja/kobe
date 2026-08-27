//! Bounded interactive transport for Sandbox operations (#83).
//!
//! Two things a caller can want that a request/response API cannot give them:
//! a terminal, and a TCP connection to a declared port. Both need a stream, and
//! a stream needs limits, a framing, and a way to be closed by somebody other
//! than the caller.
//!
//! # Not a Kubernetes proxy
//!
//! The caller's WebSocket never reaches the API server. Kobe terminates it,
//! resolves the target through #81, opens a *separate* connection with a
//! credential scoped to one Pod, and copies bytes between the two. Nothing the
//! caller sends becomes part of a Kubernetes request: not a path, not a header,
//! not a protocol negotiation. That is the difference between "exec into your
//! Sandbox" and "an authenticated tunnel to the API server".
//!
//! # Framing
//!
//! Binary frames, first byte a channel, matching Kubernetes' own `v4` channel
//! convention so tooling written against one reads naturally against the other:
//!
//! ```text
//! 0  stdin      caller -> sandbox
//! 1  stdout     sandbox -> caller
//! 2  stderr     sandbox -> caller
//! 3  error      sandbox -> caller   (a bounded reason, never a raw response)
//! 4  resize     caller -> sandbox   ({"width":N,"height":N})
//! ```
//!
//! An unknown channel from the caller is refused rather than ignored. Ignoring
//! it means a client that believes it sent a resize, or a signal, and was
//! silently disregarded.
//!
//! # Limits are not optional
//!
//! Every one of these exists because the caller controls the workload:
//!
//! * **idle timeout** — an abandoned terminal holds a connection to the target
//!   cluster indefinitely, and nobody notices because nothing is wrong.
//! * **maximum duration** — an *active* stream would otherwise outlive any
//!   sensible bound simply by staying busy.
//! * **byte ceiling** — `yes` is a one-word denial-of-service.
//! * **concurrency** — enforced before upgrade, from #83's registry.
//!
//! A stream is also cancelled the moment its lease stops permitting access.
//! Kubernetes authenticates an upgraded connection once; nothing but an
//! explicit cancel closes it.

use std::future::Future;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// Channel bytes, matching Kubernetes' `v4` convention.
pub const CHANNEL_STDIN: u8 = 0;
pub const CHANNEL_STDOUT: u8 = 1;
pub const CHANNEL_STDERR: u8 = 2;
pub const CHANNEL_ERROR: u8 = 3;
pub const CHANNEL_RESIZE: u8 = 4;

/// Closed after this long with nothing in either direction.
///
/// An abandoned terminal is the common case — somebody closes a laptop — and it
/// holds a connection to the target cluster with nothing to signal that
/// anything is wrong.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Closed after this long regardless of activity.
///
/// The idle timeout does not bound an *active* stream: a session that stays
/// busy would otherwise live as long as the lease, which defeats having a
/// separate transport bound at all.
pub const MAX_STREAM_DURATION: Duration = Duration::from_secs(4 * 60 * 60);

/// Most bytes carried across both directions before the stream is closed.
///
/// `yes > /dev/null` is a one-word way to make the operator relay unbounded
/// traffic from inside a sandbox whose occupant is, by construction, not
/// trusted. Counting both directions also prevents a caller from receiving the
/// full bound and then sending another full bound back.
pub const MAX_STREAM_BYTES: u64 = 512 * 1024 * 1024;

/// Longest an upgraded operation may spend opening its exact target stream.
///
/// Stream limits cannot protect a handler that never reaches the pump. Pod
/// identity reads, exec negotiation and port-forward setup are therefore
/// bounded separately and remain revocable while the target API is stalled.
pub const STREAM_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound one target-setup future by both lease revocation and setup timeout.
pub async fn bounded_setup<T, F>(operation: F, revoked: &CancellationToken) -> Result<T, StreamEnd>
where
    F: Future<Output = T>,
{
    tokio::select! {
        biased;
        _ = revoked.cancelled() => Err(StreamEnd::Revoked),
        result = tokio::time::timeout(STREAM_SETUP_TIMEOUT, operation) => {
            result.map_err(|_| StreamEnd::TargetError)
        }
    }
}

/// Why a stream ended.
///
/// Reported to the caller on the error channel as a bounded code, so a client
/// can distinguish "your lease ended" from "you hit a limit" from "the workload
/// exited" without ever seeing a raw backend response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEnd {
    /// The workload closed it. The ordinary case.
    Completed,
    /// The lease stopped permitting access.
    Revoked,
    IdleTimeout,
    DurationExceeded,
    ByteLimitExceeded,
    /// The caller sent something this protocol does not define.
    ProtocolViolation,
    /// The target connection failed.
    TargetError,
}

impl StreamEnd {
    pub fn code(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Revoked => "revoked",
            Self::IdleTimeout => "idle_timeout",
            Self::DurationExceeded => "duration_exceeded",
            Self::ByteLimitExceeded => "byte_limit_exceeded",
            Self::ProtocolViolation => "protocol_violation",
            Self::TargetError => "target_error",
        }
    }

    /// Whether the caller could have prevented it. Used only for logging, so an
    /// operator can separate their own faults from callers' behaviour.
    pub fn is_caller_fault(self) -> bool {
        matches!(
            self,
            Self::IdleTimeout
                | Self::DurationExceeded
                | Self::ByteLimitExceeded
                | Self::ProtocolViolation
        )
    }
}

/// A caller frame, once validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerFrame {
    Stdin(Vec<u8>),
    Resize {
        width: u16,
        height: u16,
    },
    /// The caller closed the stream.
    Close,
}

/// Parse one inbound frame.
///
/// Everything a caller may send is enumerated here. Anything else is a
/// violation rather than a no-op: silently dropping a frame leaves a client
/// believing it resized a terminal, or sent input, that never arrived.
pub fn parse_caller_frame(message: &Message) -> Result<CallerFrame, StreamEnd> {
    let payload = match message {
        Message::Binary(payload) => payload.as_ref(),
        Message::Close(_) => return Ok(CallerFrame::Close),
        // Ping/pong are the transport's own; they never carry a channel.
        Message::Ping(_) | Message::Pong(_) => return Ok(CallerFrame::Stdin(Vec::new())),
        // Text frames are not part of this protocol. Accepting them would mean
        // two encodings for stdin, and a client that guessed wrong would send
        // silently-mangled bytes to a shell.
        Message::Text(_) => return Err(StreamEnd::ProtocolViolation),
    };

    let Some((&channel, body)) = payload.split_first() else {
        // An empty frame has no channel, so there is no way to know what the
        // caller meant by it.
        return Err(StreamEnd::ProtocolViolation);
    };

    match channel {
        CHANNEL_STDIN => Ok(CallerFrame::Stdin(body.to_vec())),
        CHANNEL_RESIZE => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Resize {
                width: u16,
                height: u16,
            }
            let resize: Resize =
                serde_json::from_slice(body).map_err(|_| StreamEnd::ProtocolViolation)?;
            // A zero dimension is not a terminal. Passing it through makes the
            // workload's own tty handling the thing that has to cope.
            if resize.width == 0 || resize.height == 0 {
                return Err(StreamEnd::ProtocolViolation);
            }
            Ok(CallerFrame::Resize {
                width: resize.width,
                height: resize.height,
            })
        }
        // stdout, stderr and error are outbound only. A caller sending one is
        // either confused or trying something; neither is a reason to guess.
        _ => Err(StreamEnd::ProtocolViolation),
    }
}

/// Frame one outbound chunk.
pub fn server_frame(channel: u8, payload: &[u8]) -> Message {
    let mut framed = Vec::with_capacity(payload.len() + 1);
    framed.push(channel);
    framed.extend_from_slice(payload);
    Message::Binary(framed.into())
}

/// Tracks the limits that end a stream.
///
/// Separated from the copying so the rules are testable without a socket, and
/// because these bounds are the reason the transport is safe to expose at all.
#[derive(Debug)]
pub struct StreamLimits {
    started: tokio::time::Instant,
    last_activity: tokio::time::Instant,
    bytes: u64,
    idle_timeout: Duration,
    max_duration: Duration,
    max_bytes: u64,
}

impl StreamLimits {
    pub fn new(idle_timeout: Duration, max_duration: Duration, max_bytes: u64) -> Self {
        Self::starting_at(
            tokio::time::Instant::now(),
            idle_timeout,
            max_duration,
            max_bytes,
        )
    }

    /// The start instant is a parameter so every bound is decided by arithmetic
    /// on values the caller supplies. A type that read the clock internally
    /// could only be tested against the clock, which is how limit bugs stay
    /// hidden until production.
    pub fn starting_at(
        now: tokio::time::Instant,
        idle_timeout: Duration,
        max_duration: Duration,
        max_bytes: u64,
    ) -> Self {
        Self {
            started: now,
            last_activity: now,
            bytes: 0,
            idle_timeout,
            max_duration,
            max_bytes,
        }
    }

    /// Record traffic in either direction and re-check every bound.
    pub fn record(&mut self, bytes: usize, now: tokio::time::Instant) -> Result<(), StreamEnd> {
        self.last_activity = now;
        self.bytes = self.bytes.saturating_add(bytes as u64);
        if self.bytes > self.max_bytes {
            return Err(StreamEnd::ByteLimitExceeded);
        }
        self.check(now)
    }

    /// Re-check the time-based bounds without any traffic.
    pub fn check(&self, now: tokio::time::Instant) -> Result<(), StreamEnd> {
        if now.duration_since(self.started) >= self.max_duration {
            return Err(StreamEnd::DurationExceeded);
        }
        if now.duration_since(self.last_activity) >= self.idle_timeout {
            return Err(StreamEnd::IdleTimeout);
        }
        Ok(())
    }

    /// How long until the next bound would fire, so the loop can wake exactly
    /// then rather than polling.
    pub fn next_deadline(&self, now: tokio::time::Instant) -> Duration {
        let until_idle = self
            .idle_timeout
            .saturating_sub(now.duration_since(self.last_activity));
        let until_max = self
            .max_duration
            .saturating_sub(now.duration_since(self.started));
        until_idle.min(until_max)
    }
}

/// Await one already-authorized I/O operation without stepping outside the
/// stream's revocation and time bounds.
///
/// The outer pump `select!` protects reads while they are pending. Writes and
/// sink sends happen after a branch wins; awaiting them directly would let a
/// stalled target or slow caller ignore release and every timeout forever.
async fn bounded_io<T, E, F>(
    operation: F,
    limits: &StreamLimits,
    revoked: &CancellationToken,
    failure: StreamEnd,
) -> Result<T, StreamEnd>
where
    F: Future<Output = Result<T, E>>,
{
    let now = tokio::time::Instant::now();
    limits.check(now)?;
    let deadline = limits.next_deadline(now);
    tokio::select! {
        biased;
        _ = revoked.cancelled() => Err(StreamEnd::Revoked),
        _ = tokio::time::sleep(deadline) => {
            Err(limits
                .check(tokio::time::Instant::now())
                .err()
                .unwrap_or(StreamEnd::IdleTimeout))
        }
        result = operation => result.map_err(|_| failure),
    }
}

/// Copy bytes between the caller's WebSocket and one duplex target stream.
///
/// Used for port-forward, where both sides are opaque byte streams. Exec has
/// three channels and is handled separately.
///
/// The stream ends on the first of: the caller closing it, the target closing
/// it, any limit, or revocation. Revocation is checked in the same `select` as
/// the traffic so a cancelled lease closes the socket immediately rather than
/// on the next byte — which for an idle terminal could be never.
pub async fn pump_duplex<S>(
    socket: &mut WebSocket,
    target: &mut S,
    limits: &mut StreamLimits,
    revoked: CancellationToken,
) -> StreamEnd
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        let now = tokio::time::Instant::now();
        if let Err(end) = limits.check(now) {
            return end;
        }
        let deadline = limits.next_deadline(now);

        tokio::select! {
            _ = revoked.cancelled() => return StreamEnd::Revoked,
            _ = tokio::time::sleep(deadline) => {
                // A bound came due. `check` decides which, so the reported
                // reason always matches the rule that actually fired.
                return limits
                    .check(tokio::time::Instant::now())
                    .err()
                    .unwrap_or(StreamEnd::IdleTimeout);
            }
            inbound = socket.next() => {
                match inbound {
                    Some(Ok(message)) => {
                        let frame = match parse_caller_frame(&message) {
                            Ok(frame) => frame,
                            Err(end) => return end,
                        };
                        match frame {
                            CallerFrame::Close => return StreamEnd::Completed,
                            // A forwarded port has no terminal to resize.
                            CallerFrame::Resize { .. } => return StreamEnd::ProtocolViolation,
                            CallerFrame::Stdin(bytes) => {
                                if bytes.is_empty() {
                                    continue;
                                }
                                if let Err(end) = limits.record(bytes.len(), tokio::time::Instant::now()) {
                                    return end;
                                }
                                if let Err(end) = bounded_io(
                                    target.write_all(&bytes),
                                    limits,
                                    &revoked,
                                    StreamEnd::TargetError,
                                )
                                .await
                                {
                                    return end;
                                }
                            }
                        }
                    }
                    Some(Err(_)) | None => return StreamEnd::Completed,
                }
            }
            read = target.read(&mut buffer) => {
                match read {
                    // The workload closed its side.
                    Ok(0) => return StreamEnd::Completed,
                    Ok(count) => {
                        if let Err(end) = limits.record(count, tokio::time::Instant::now()) {
                            return end;
                        }
                        if let Err(end) = bounded_io(
                            socket.send(server_frame(CHANNEL_STDOUT, &buffer[..count])),
                            limits,
                            &revoked,
                            StreamEnd::Completed,
                        )
                        .await
                        {
                            return end;
                        }
                    }
                    Err(_) => return StreamEnd::TargetError,
                }
            }
        }
    }
}

/// Tell the caller why their stream ended, then close it.
///
/// A bounded code on the error channel, never a backend message: those can
/// carry namespaces, node names, and other people's object names.
pub async fn close_with(socket: &mut WebSocket, end: StreamEnd) {
    debug!(reason = end.code(), "closing Sandbox stream");
    // A peer that stopped reading must not retain its registry guard forever
    // merely because the courtesy reason/close frames are backpressured.
    let close = async {
        let _ = socket
            .send(server_frame(
                CHANNEL_ERROR,
                format!(r#"{{"reason":"{}"}}"#, end.code()).as_bytes(),
            ))
            .await;
        let _ = socket.send(Message::Close(None)).await;
    };
    let _ = tokio::time::timeout(Duration::from_secs(1), close).await;
}

/// Copy between the caller's WebSocket and a three-channel exec/attach session.
///
/// Distinct from [`pump_duplex`] because exec has stdout and stderr as separate
/// streams and a resize channel. Merging them would lose the distinction the
/// caller's terminal needs — a client cannot colour stderr it cannot identify.
pub async fn pump_attached(
    socket: &mut WebSocket,
    attached: &mut kube::api::AttachedProcess,
    limits: &mut StreamLimits,
    revoked: CancellationToken,
) -> StreamEnd {
    let mut stdin = attached.stdin();
    let mut stdout = attached.stdout();
    let mut stderr = attached.stderr();
    let mut resize = attached.terminal_size();

    let mut out_buffer = vec![0u8; 32 * 1024];
    let mut err_buffer = vec![0u8; 32 * 1024];

    loop {
        let now = tokio::time::Instant::now();
        if let Err(end) = limits.check(now) {
            return end;
        }
        let deadline = limits.next_deadline(now);

        // `read` on an `Option<impl AsyncRead>` needs a concrete future each
        // pass; `futures::future::OptionFuture` keeps a closed channel from
        // completing instantly and spinning the loop.
        let stdout_read = async {
            match stdout.as_mut() {
                Some(stream) => Some(stream.read(&mut out_buffer).await),
                None => std::future::pending().await,
            }
        };
        let stderr_read = async {
            match stderr.as_mut() {
                Some(stream) => Some(stream.read(&mut err_buffer).await),
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            _ = revoked.cancelled() => return StreamEnd::Revoked,
            _ = tokio::time::sleep(deadline) => {
                return limits
                    .check(tokio::time::Instant::now())
                    .err()
                    .unwrap_or(StreamEnd::IdleTimeout);
            }
            inbound = socket.next() => {
                match inbound {
                    Some(Ok(message)) => {
                        let frame = match parse_caller_frame(&message) {
                            Ok(frame) => frame,
                            Err(end) => return end,
                        };
                        match frame {
                            CallerFrame::Close => return StreamEnd::Completed,
                            CallerFrame::Stdin(bytes) => {
                                if bytes.is_empty() {
                                    continue;
                                }
                                if let Err(end) =
                                    limits.record(bytes.len(), tokio::time::Instant::now())
                                {
                                    return end;
                                }
                                let Some(stdin) = stdin.as_mut() else {
                                    // The caller sent input to a session that
                                    // has no stdin. Refusing beats discarding:
                                    // silently dropping keystrokes is the kind
                                    // of bug that gets blamed on the workload.
                                    return StreamEnd::ProtocolViolation;
                                };
                                if let Err(end) = bounded_io(
                                    stdin.write_all(&bytes),
                                    limits,
                                    &revoked,
                                    StreamEnd::TargetError,
                                )
                                .await
                                {
                                    return end;
                                }
                            }
                            CallerFrame::Resize { width, height } => {
                                let Some(resize) = resize.as_mut() else {
                                    // Explicitly unsupported rather than
                                    // ignored: #83 requires resize to fail
                                    // loudly where the session has no terminal.
                                    return StreamEnd::ProtocolViolation;
                                };
                                if let Err(end) = bounded_io(
                                    resize.send(kube::api::TerminalSize { width, height }),
                                    limits,
                                    &revoked,
                                    StreamEnd::TargetError,
                                )
                                .await
                                {
                                    return end;
                                }
                            }
                        }
                    }
                    Some(Err(_)) | None => return StreamEnd::Completed,
                }
            }
            read = stdout_read => {
                match read {
                    Some(Ok(0)) | None => {
                        // Closed. Stop selecting on it, and let the session end
                        // when stderr closes too.
                        stdout = None;
                        if stderr.is_none() {
                            return StreamEnd::Completed;
                        }
                    }
                    Some(Ok(count)) => {
                        if let Err(end) = limits.record(count, tokio::time::Instant::now()) {
                            return end;
                        }
                        if let Err(end) = bounded_io(
                            socket.send(server_frame(CHANNEL_STDOUT, &out_buffer[..count])),
                            limits,
                            &revoked,
                            StreamEnd::Completed,
                        )
                        .await
                        {
                            return end;
                        }
                    }
                    Some(Err(_)) => return StreamEnd::TargetError,
                }
            }
            read = stderr_read => {
                match read {
                    Some(Ok(0)) | None => {
                        stderr = None;
                        if stdout.is_none() {
                            return StreamEnd::Completed;
                        }
                    }
                    Some(Ok(count)) => {
                        if let Err(end) = limits.record(count, tokio::time::Instant::now()) {
                            return end;
                        }
                        if let Err(end) = bounded_io(
                            socket.send(server_frame(CHANNEL_STDERR, &err_buffer[..count])),
                            limits,
                            &revoked,
                            StreamEnd::Completed,
                        )
                        .await
                        {
                            return end;
                        }
                    }
                    Some(Err(_)) => return StreamEnd::TargetError,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binary(bytes: Vec<u8>) -> Message {
        Message::Binary(bytes.into())
    }

    /// Everything a caller may send is enumerated; anything else ends the
    /// stream.
    ///
    /// Silently ignoring an unknown frame is the failure that matters: a client
    /// believes it resized a terminal, or sent input, and it never arrived. A
    /// caller writing to stdout or the error channel is either confused or
    /// probing, and neither is a reason to guess.
    #[test]
    fn only_defined_inbound_channels_are_accepted() {
        assert_eq!(
            parse_caller_frame(&binary(vec![CHANNEL_STDIN, b'h', b'i'])).unwrap(),
            CallerFrame::Stdin(b"hi".to_vec())
        );
        assert_eq!(
            parse_caller_frame(&binary(
                [
                    vec![CHANNEL_RESIZE],
                    br#"{"width":120,"height":40}"#.to_vec()
                ]
                .concat()
            ))
            .unwrap(),
            CallerFrame::Resize {
                width: 120,
                height: 40
            }
        );

        // Outbound-only channels, and anything undefined.
        for channel in [CHANNEL_STDOUT, CHANNEL_STDERR, CHANNEL_ERROR, 5, 200, 255] {
            assert_eq!(
                parse_caller_frame(&binary(vec![channel, b'x'])).unwrap_err(),
                StreamEnd::ProtocolViolation,
                "channel {channel} must be refused"
            );
        }

        // An empty frame has no channel, so there is no way to know what was
        // meant by it.
        assert_eq!(
            parse_caller_frame(&binary(vec![])).unwrap_err(),
            StreamEnd::ProtocolViolation
        );

        // Text frames would be a second encoding for stdin; a client that
        // guessed wrong would send silently-mangled bytes to a shell.
        assert_eq!(
            parse_caller_frame(&Message::Text("hi".into())).unwrap_err(),
            StreamEnd::ProtocolViolation
        );
    }

    /// A malformed or nonsensical resize is refused, not forwarded.
    ///
    /// Passing a zero dimension through makes the workload's own tty handling
    /// the thing that has to cope with it — which is exactly the sort of input
    /// a sandboxed process should never receive from the platform itself.
    #[test]
    fn a_nonsensical_resize_is_refused() {
        let resize = |body: &str| {
            parse_caller_frame(&binary(
                [vec![CHANNEL_RESIZE], body.as_bytes().to_vec()].concat(),
            ))
        };

        assert!(resize(r#"{"width":80,"height":24}"#).is_ok());

        for bad in [
            r#"{"width":0,"height":24}"#,
            r#"{"width":80,"height":0}"#,
            r#"{"width":0,"height":0}"#,
            r#"{"width":80}"#,
            r#"{"width":80,"height":24,"cols":1}"#,
            r#"{"width":-1,"height":24}"#,
            r#"{"width":99999999,"height":24}"#,
            "not json",
            "",
        ] {
            assert_eq!(
                resize(bad).unwrap_err(),
                StreamEnd::ProtocolViolation,
                "resize {bad:?} must be refused"
            );
        }
    }

    /// Every bound actually binds, and reports the rule that fired.
    ///
    /// Reporting matters: a client that cannot tell "you were idle" from "your
    /// lease ended" cannot decide whether reconnecting is sensible.
    #[test]
    fn each_limit_ends_the_stream_for_its_own_reason() {
        let start = tokio::time::Instant::now();

        // Bytes.
        let mut limits =
            StreamLimits::starting_at(start, Duration::from_secs(60), Duration::from_secs(600), 10);
        assert!(limits.record(10, start).is_ok());
        assert_eq!(
            limits.record(1, start).unwrap_err(),
            StreamEnd::ByteLimitExceeded
        );

        // Idle: quiet for long enough, even though the total duration is fine.
        let limits = StreamLimits::starting_at(
            start,
            Duration::from_secs(60),
            Duration::from_secs(600),
            1024,
        );
        assert!(limits.check(start + Duration::from_secs(59)).is_ok());
        assert_eq!(
            limits.check(start + Duration::from_secs(60)).unwrap_err(),
            StreamEnd::IdleTimeout
        );

        // Duration: busy throughout, so never idle — this is the bound the idle
        // timeout cannot supply.
        let mut limits = StreamLimits::starting_at(
            start,
            Duration::from_secs(60),
            Duration::from_secs(600),
            1_000_000,
        );
        for second in 1..600 {
            assert!(
                limits
                    .record(1, start + Duration::from_secs(second))
                    .is_ok(),
                "an active stream must not trip the idle bound at {second}s"
            );
        }
        assert_eq!(
            limits
                .record(1, start + Duration::from_secs(600))
                .unwrap_err(),
            StreamEnd::DurationExceeded
        );
    }

    /// The loop sleeps until the next bound rather than polling.
    ///
    /// A poll loop on an idle terminal is a busy wait per open stream; the
    /// deadline is what makes an abandoned session cost nothing until it is
    /// closed.
    #[test]
    fn the_next_deadline_is_the_nearest_bound() {
        let start = tokio::time::Instant::now();
        let limits = StreamLimits::starting_at(
            start,
            Duration::from_secs(60),
            Duration::from_secs(600),
            1024,
        );

        assert_eq!(limits.next_deadline(start), Duration::from_secs(60));
        assert_eq!(
            limits.next_deadline(start + Duration::from_secs(30)),
            Duration::from_secs(30)
        );

        // Late in a long-running stream the total duration is nearer than the
        // idle window, and the deadline has to follow whichever is closer.
        let limits = StreamLimits::starting_at(
            start,
            Duration::from_secs(600),
            Duration::from_secs(60),
            1024,
        );
        assert_eq!(limits.next_deadline(start), Duration::from_secs(60));

        // Never negative: a bound already passed wakes immediately.
        assert_eq!(
            limits.next_deadline(start + Duration::from_secs(9999)),
            Duration::ZERO
        );
    }

    /// Target negotiation is part of a live operation and cannot ignore a
    /// release merely because the Kubernetes request has not answered yet.
    #[tokio::test]
    async fn a_blocked_setup_is_preempted_by_revocation() {
        let revoked = CancellationToken::new();
        revoked.cancel();

        assert_eq!(
            bounded_setup(std::future::pending::<()>(), &revoked)
                .await
                .unwrap_err(),
            StreamEnd::Revoked
        );
    }

    /// Once a pump branch starts writing, the same duration bound still owns
    /// that await; a backpressured peer cannot turn it into an unbounded wait.
    #[tokio::test]
    async fn a_blocked_io_cannot_outlive_the_stream_deadline() {
        let now = tokio::time::Instant::now();
        let limits = StreamLimits::starting_at(now, Duration::from_secs(60), Duration::ZERO, 1024);
        let revoked = CancellationToken::new();

        assert_eq!(
            bounded_io(
                std::future::pending::<Result<(), ()>>(),
                &limits,
                &revoked,
                StreamEnd::TargetError,
            )
            .await
            .unwrap_err(),
            StreamEnd::DurationExceeded
        );
    }

    /// Outbound frames carry their channel, and nothing else is prepended.
    #[test]
    fn server_frames_are_channel_prefixed() {
        let Message::Binary(framed) = server_frame(CHANNEL_STDOUT, b"out") else {
            panic!("server frames are binary");
        };
        assert_eq!(framed.as_ref(), &[CHANNEL_STDOUT, b'o', b'u', b't']);

        let Message::Binary(empty) = server_frame(CHANNEL_STDERR, b"") else {
            panic!("server frames are binary");
        };
        assert_eq!(empty.as_ref(), &[CHANNEL_STDERR]);
    }

    /// Every end reason is distinguishable and non-empty.
    ///
    /// The code is all the caller gets — a backend message could carry
    /// namespaces, node names, or other tenants' object names — so it has to
    /// carry the whole distinction on its own.
    #[test]
    fn every_end_reason_is_a_distinct_bounded_code() {
        let ends = [
            StreamEnd::Completed,
            StreamEnd::Revoked,
            StreamEnd::IdleTimeout,
            StreamEnd::DurationExceeded,
            StreamEnd::ByteLimitExceeded,
            StreamEnd::ProtocolViolation,
            StreamEnd::TargetError,
        ];
        let mut codes: Vec<&str> = ends.iter().map(|end| end.code()).collect();
        codes.sort_unstable();
        let unique = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), unique, "end reasons must be distinguishable");
        assert!(codes.iter().all(|code| !code.is_empty()));

        // Revocation is not the caller's fault; a limit is. The distinction
        // drives whether an operator should be looking at their own service.
        assert!(!StreamEnd::Revoked.is_caller_fault());
        assert!(!StreamEnd::TargetError.is_caller_fault());
        assert!(StreamEnd::IdleTimeout.is_caller_fault());
        assert!(StreamEnd::ByteLimitExceeded.is_caller_fault());
    }
}
