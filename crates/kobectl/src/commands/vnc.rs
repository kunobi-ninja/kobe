//! A headless VNC client, so an agent can see and drive a Sandbox desktop.
//!
//! # Why this lives in the CLI
//!
//! The workspace image runs Xvfb, a window manager and x11vnc, and until now
//! the only way to see any of it was a human opening noVNC in a browser
//! through a port-forward. For an image whose purpose is agent sessions that
//! is backwards: the agent is the one that needs to look, and then to act.
//!
//! Capturing inside the Sandbox and copying the file out is not an
//! alternative. `kobe exec` cannot carry binary on stdout — 2048 random bytes
//! come back as 3676 with a different hash, because the bytes are converted
//! lossily to text. Reading the framebuffer here means the image never passes
//! through stdout at all.
//!
//! # Transport
//!
//! No new authentication and no new exposure. A loopback listener is bound on
//! an ephemeral port and one accepted connection is forwarded to the
//! Sandbox's VNC port by exactly the code `kobe port-forward` uses, so this
//! inherits the same authenticated stream, the same iroh-or-WebSocket choice,
//! and the same admission checks.
//!
//! # Headless
//!
//! Nothing here opens a window. No winit, no softbuffer, no X11 client
//! libraries: those are what would grow the binary and complicate
//! cross-compiling to six targets. This is protocol bytes and a PNG encoder.

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::config::CliConfig;
use super::{OutputFormat, print_json};

/// Refuse a framebuffer larger than this many pixels.
///
/// A malicious or broken server can announce any geometry, and a raw-encoded
/// rectangle is width × height × 4 bytes that this process would allocate on
/// its word alone. 64 megapixels is far beyond any desktop the image starts
/// and still bounds the allocation at a quarter of a gigabyte.
const MAX_FRAMEBUFFER_PIXELS: u64 = 64 * 1024 * 1024;

/// What the server said about itself during the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServerInit {
    pub width: u16,
    pub height: u16,
    pub format: PixelFormat,
}

/// The server's pixel layout, as sent in ServerInit.
///
/// Kept as the server sent it rather than forcing our own with
/// SetPixelFormat: x11vnc already offers 32-bit true colour, and converting
/// on this side is less code than negotiating and then still having to handle
/// whatever the server actually agreed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PixelFormat {
    pub bits_per_pixel: u8,
    pub big_endian: bool,
    pub true_colour: bool,
    pub red_max: u16,
    pub green_max: u16,
    pub blue_max: u16,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
}

impl PixelFormat {
    pub(crate) fn parse(raw: &[u8; 16]) -> Self {
        Self {
            bits_per_pixel: raw[0],
            big_endian: raw[2] != 0,
            true_colour: raw[3] != 0,
            red_max: u16::from_be_bytes([raw[4], raw[5]]),
            green_max: u16::from_be_bytes([raw[6], raw[7]]),
            blue_max: u16::from_be_bytes([raw[8], raw[9]]),
            red_shift: raw[10],
            green_shift: raw[11],
            blue_shift: raw[12],
        }
    }

    pub(crate) fn bytes_per_pixel(&self) -> usize {
        usize::from(self.bits_per_pixel) / 8
    }

    /// Convert one pixel to 8-bit RGB.
    ///
    /// The maxima are scaled rather than assumed: a server offering 5-6-5
    /// would otherwise produce a dark, wrong image instead of an obviously
    /// unsupported one.
    pub(crate) fn to_rgb(self, raw: &[u8]) -> [u8; 3] {
        let mut value: u32 = 0;
        if self.big_endian {
            for byte in raw {
                value = (value << 8) | u32::from(*byte);
            }
        } else {
            for byte in raw.iter().rev() {
                value = (value << 8) | u32::from(*byte);
            }
        }
        let channel = |max: u16, shift: u8| -> u8 {
            if max == 0 {
                return 0;
            }
            let raw = (value >> shift) & u32::from(max);
            ((raw * 255) / u32::from(max)) as u8
        };
        [
            channel(self.red_max, self.red_shift),
            channel(self.green_max, self.green_shift),
            channel(self.blue_max, self.blue_shift),
        ]
    }
}

/// Complete the RFB handshake and return what the server announced.
///
/// Only the `None` security type is accepted. The image's x11vnc runs
/// `-nopw` on loopback inside the Sandbox, where the authenticated stream is
/// the boundary; a server asking for VNC authentication here would mean the
/// far end is not the one this command was aimed at, which is worth refusing
/// rather than prompting for a password nobody set.
pub(crate) async fn handshake<S>(socket: &mut S) -> Result<ServerInit>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut version = [0u8; 12];
    socket
        .read_exact(&mut version)
        .await
        .context("the server closed before sending its RFB version")?;
    if !version.starts_with(b"RFB ") {
        bail!(
            "not an RFB server: it opened with {:?}",
            String::from_utf8_lossy(&version)
        );
    }
    // Answer 3.8 regardless of a higher offer: it is the last version with a
    // stable handshake, and every server that speaks more also speaks it.
    socket.write_all(b"RFB 003.008\n").await?;
    socket.flush().await?;

    let mut count = [0u8; 1];
    socket.read_exact(&mut count).await?;
    if count[0] == 0 {
        // A zero count is followed by a reason string, which is the only
        // place the server explains a refusal.
        let mut length = [0u8; 4];
        socket.read_exact(&mut length).await?;
        let mut reason = vec![0u8; u32::from_be_bytes(length) as usize];
        socket.read_exact(&mut reason).await?;
        bail!(
            "the VNC server refused the connection: {}",
            String::from_utf8_lossy(&reason)
        );
    }
    let mut types = vec![0u8; usize::from(count[0])];
    socket.read_exact(&mut types).await?;
    if !types.contains(&1) {
        bail!(
            "the VNC server offers no unauthenticated security type (offered {types:?}); \
             kobe reaches it over an already-authenticated stream and does not hold a VNC password"
        );
    }
    socket.write_all(&[1]).await?;
    socket.flush().await?;

    let mut result = [0u8; 4];
    socket.read_exact(&mut result).await?;
    if u32::from_be_bytes(result) != 0 {
        bail!("the VNC server rejected the security handshake");
    }

    // Shared: never disconnect another viewer. A screenshot must not evict a
    // human who is watching the same desktop.
    socket.write_all(&[1]).await?;
    socket.flush().await?;

    let mut init = [0u8; 20];
    socket.read_exact(&mut init).await?;
    let width = u16::from_be_bytes([init[0], init[1]]);
    let height = u16::from_be_bytes([init[2], init[3]]);
    let mut format_bytes = [0u8; 16];
    format_bytes.copy_from_slice(&init[4..20]);
    let format = PixelFormat::parse(&format_bytes);

    let mut name_length = [0u8; 4];
    socket.read_exact(&mut name_length).await?;
    let mut name = vec![0u8; u32::from_be_bytes(name_length) as usize];
    socket.read_exact(&mut name).await?;

    if !format.true_colour {
        bail!("the VNC server offers a colour-map format, which kobe does not read");
    }
    if !matches!(format.bits_per_pixel, 8 | 16 | 32) {
        bail!(
            "unsupported pixel size: {} bits per pixel",
            format.bits_per_pixel
        );
    }
    let pixels = u64::from(width) * u64::from(height);
    if pixels == 0 {
        bail!("the VNC server announced an empty framebuffer ({width}x{height})");
    }
    if pixels > MAX_FRAMEBUFFER_PIXELS {
        bail!("the VNC server announced {width}x{height}, which kobe refuses to allocate");
    }

    Ok(ServerInit {
        width,
        height,
        format,
    })
}

/// Ask for the whole framebuffer and decode the raw-encoded answer to RGB.
///
/// Raw is requested on purpose. Tight and ZRLE would move fewer bytes over a
/// loopback forward that is already fast, and each is a decoder to maintain
/// and get wrong; raw is a memcpy with a pixel conversion.
pub(crate) async fn capture<S>(socket: &mut S, server: ServerInit) -> Result<Vec<u8>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // SetEncodings: raw only.
    socket.write_all(&[2, 0, 0, 1]).await?;
    socket.write_all(&0i32.to_be_bytes()).await?;

    // FramebufferUpdateRequest, non-incremental so the server sends every
    // pixel rather than what changed since a previous frame we never saw.
    let mut request = vec![3u8, 0];
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&0u16.to_be_bytes());
    request.extend_from_slice(&server.width.to_be_bytes());
    request.extend_from_slice(&server.height.to_be_bytes());
    socket.write_all(&request).await?;
    socket.flush().await?;

    let width = usize::from(server.width);
    let height = usize::from(server.height);
    let mut image = vec![0u8; width * height * 3];
    let bytes_per_pixel = server.format.bytes_per_pixel();

    loop {
        let mut header = [0u8; 1];
        socket.read_exact(&mut header).await?;
        match header[0] {
            0 => {}
            // Bell, cut-text and colour-map messages can arrive before the
            // update. Skipping them keeps a chatty server from derailing a
            // capture, and each has a length we can read past.
            2 => continue,
            3 => {
                let mut rest = [0u8; 7];
                socket.read_exact(&mut rest).await?;
                let length = u32::from_be_bytes([rest[3], rest[4], rest[5], rest[6]]) as usize;
                let mut text = vec![0u8; length];
                socket.read_exact(&mut text).await?;
                continue;
            }
            other => bail!("unexpected RFB message type {other} while waiting for a frame"),
        }

        let mut rest = [0u8; 3];
        socket.read_exact(&mut rest).await?;
        let rectangles = u16::from_be_bytes([rest[1], rest[2]]);
        for _ in 0..rectangles {
            let mut head = [0u8; 12];
            socket.read_exact(&mut head).await?;
            let x = usize::from(u16::from_be_bytes([head[0], head[1]]));
            let y = usize::from(u16::from_be_bytes([head[2], head[3]]));
            let w = usize::from(u16::from_be_bytes([head[4], head[5]]));
            let h = usize::from(u16::from_be_bytes([head[6], head[7]]));
            let encoding = i32::from_be_bytes([head[8], head[9], head[10], head[11]]);
            if encoding != 0 {
                bail!("the server sent encoding {encoding} after we asked for raw only");
            }
            if x + w > width || y + h > height {
                bail!("the server sent a rectangle outside the framebuffer it announced");
            }
            let mut row = vec![0u8; w * bytes_per_pixel];
            for line in 0..h {
                socket.read_exact(&mut row).await?;
                for column in 0..w {
                    let pixel = &row[column * bytes_per_pixel..(column + 1) * bytes_per_pixel];
                    let rgb = server.format.to_rgb(pixel);
                    let at = ((y + line) * width + (x + column)) * 3;
                    image[at..at + 3].copy_from_slice(&rgb);
                }
            }
        }
        return Ok(image);
    }
}

/// Which mouse button an event carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Button {
    Left,
    Middle,
    Right,
}

impl Button {
    pub(crate) fn mask(self) -> u8 {
        match self {
            Self::Left => 1,
            Self::Middle => 1 << 1,
            Self::Right => 1 << 2,
        }
    }

    pub(crate) fn parse(name: &str) -> Result<Self> {
        match name {
            "left" => Ok(Self::Left),
            "middle" => Ok(Self::Middle),
            "right" => Ok(Self::Right),
            other => bail!("unknown button {other}; use left, middle or right"),
        }
    }
}

/// One RFB PointerEvent: six bytes, and the whole of "move the mouse".
pub(crate) fn pointer_event(buttons: u8, x: u16, y: u16) -> [u8; 6] {
    let x = x.to_be_bytes();
    let y = y.to_be_bytes();
    [5, buttons, x[0], x[1], y[0], y[1]]
}

/// One RFB KeyEvent: eight bytes, carrying an X11 keysym.
pub(crate) fn key_event(down: bool, keysym: u32) -> [u8; 8] {
    let key = keysym.to_be_bytes();
    [4, u8::from(down), 0, 0, key[0], key[1], key[2], key[3]]
}

/// The X11 keysym for a character, and whether Shift must be held.
///
/// Printable ASCII maps onto keysyms one-to-one, which is why typing ordinary
/// text needs no table. Anything outside it is refused rather than guessed:
/// an accent silently typed as the wrong character is worse than an error
/// saying kobe cannot type it, and a real fix is a layout-aware table rather
/// than a wider guess.
pub(crate) fn keysym_for(character: char) -> Result<(u32, bool)> {
    let shifted = character.is_ascii_uppercase()
        || matches!(
            character,
            '!' | '@'
                | '#'
                | '$'
                | '%'
                | '^'
                | '&'
                | '*'
                | '('
                | ')'
                | '_'
                | '+'
                | '{'
                | '}'
                | '|'
                | ':'
                | '"'
                | '<'
                | '>'
                | '?'
                | '~'
        );
    match character {
        '\n' => Ok((0xff0d, false)),
        '\t' => Ok((0xff09, false)),
        ' '..='~' => Ok((character as u32, shifted)),
        other => bail!(
            "kobe cannot type {other:?}: only printable ASCII, tab and newline map to keysyms \
             without a layout-aware table"
        ),
    }
}

/// A named non-printing key, for `kobe vnc key`.
pub(crate) fn named_keysym(name: &str) -> Result<u32> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "return" | "enter" => 0xff0d,
        "tab" => 0xff09,
        "escape" | "esc" => 0xff1b,
        "backspace" => 0xff08,
        "delete" | "del" => 0xffff,
        "home" => 0xff50,
        "end" => 0xff57,
        "pageup" => 0xff55,
        "pagedown" => 0xff56,
        "left" => 0xff51,
        "up" => 0xff52,
        "right" => 0xff53,
        "down" => 0xff54,
        "space" => 0x20,
        other => bail!("unknown key {other}; try return, tab, escape, or an arrow"),
    })
}

/// Hold Shift around a keysym when the character needs it.
pub(crate) fn typed_key_events(keysym: u32, shifted: bool) -> Vec<u8> {
    const SHIFT_L: u32 = 0xffe1;
    let mut bytes = Vec::new();
    if shifted {
        bytes.extend_from_slice(&key_event(true, SHIFT_L));
    }
    bytes.extend_from_slice(&key_event(true, keysym));
    bytes.extend_from_slice(&key_event(false, keysym));
    if shifted {
        bytes.extend_from_slice(&key_event(false, SHIFT_L));
    }
    bytes
}

/// What `kobe vnc` was asked to do once it is connected.
pub(crate) enum VncAction {
    Screenshot { path: std::path::PathBuf },
    Click { x: u16, y: u16, button: Button },
    Move { x: u16, y: u16 },
    Type { text: String },
    Key { name: String },
}

/// Open a VNC session to the lease and run one action.
///
/// The forward is deliberately a single connection on an ephemeral loopback
/// port rather than a long-lived listener: the port exists for the length of
/// this command and nothing else can find it.
pub(crate) async fn run(
    lease: &str,
    port: u16,
    action: VncAction,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<i32> {
    let config = CliConfig::load()?;
    let config = config.resolve(target_override, endpoint_override)?;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("could not bind a local port for the VNC forward")?;
    let bound = listener.local_addr()?;

    let remote = port.to_string();
    let forwarding = {
        let config = config.clone();
        let lease = lease.to_owned();
        let remote = remote.clone();
        tokio::spawn(async move {
            let path = format!("/v1/sandbox-leases/{lease}/port-forward?port={remote}");
            let iroh = super::sandbox_transport::lease_uses_iroh(&config, &lease, output).await;
            let (mut local, _) = listener.accept().await?;
            super::sandbox_transport::forward_connection(
                &mut local, &config, &lease, &remote, &path, iroh, output,
            )
            .await
        })
    };

    let mut socket = tokio::net::TcpStream::connect(bound)
        .await
        .context("could not reach the local end of the VNC forward")?;
    socket.set_nodelay(true).ok();

    let result = drive(&mut socket, action, lease, output).await;

    // The forward ends with this connection; a failure there explains a
    // failure here better than a bare read error does.
    drop(socket);
    match forwarding.await {
        Ok(Err(error)) if result.is_ok() => {
            return Err(error).context("the VNC forward failed");
        }
        _ => {}
    }
    result
}

async fn drive(
    socket: &mut tokio::net::TcpStream,
    action: VncAction,
    lease: &str,
    output: OutputFormat,
) -> Result<i32> {
    let server = handshake(socket).await?;
    match action {
        VncAction::Screenshot { path } => {
            let pixels = capture(socket, server).await?;
            write_png(&path, server.width, server.height, &pixels)
                .with_context(|| format!("could not write {}", path.display()))?;
            match output {
                OutputFormat::Json => print_json(&serde_json::json!({
                    "apiVersion": super::sandbox::SANDBOX_CLI_API_VERSION,
                    "lease": lease,
                    "path": path.display().to_string(),
                    "width": server.width,
                    "height": server.height,
                }))?,
                OutputFormat::Text => println!(
                    "Wrote {} ({}x{})",
                    path.display(),
                    server.width,
                    server.height
                ),
            }
        }
        VncAction::Move { x, y } => {
            bounds_check(server, x, y)?;
            socket.write_all(&pointer_event(0, x, y)).await?;
            socket.flush().await?;
        }
        VncAction::Click { x, y, button } => {
            bounds_check(server, x, y)?;
            // Move first: a server that never saw the pointer arrive can
            // deliver the press at the old position.
            socket.write_all(&pointer_event(0, x, y)).await?;
            socket
                .write_all(&pointer_event(button.mask(), x, y))
                .await?;
            socket.write_all(&pointer_event(0, x, y)).await?;
            socket.flush().await?;
        }
        VncAction::Type { text } => {
            let mut bytes = Vec::new();
            for character in text.chars() {
                let (keysym, shifted) = keysym_for(character)?;
                bytes.extend_from_slice(&typed_key_events(keysym, shifted));
            }
            socket.write_all(&bytes).await?;
            socket.flush().await?;
        }
        VncAction::Key { name } => {
            let keysym = named_keysym(&name)?;
            socket.write_all(&key_event(true, keysym)).await?;
            socket.write_all(&key_event(false, keysym)).await?;
            socket.flush().await?;
        }
    }
    Ok(0)
}

fn bounds_check(server: ServerInit, x: u16, y: u16) -> Result<()> {
    if x >= server.width || y >= server.height {
        bail!(
            "({x},{y}) is outside the {}x{} desktop",
            server.width,
            server.height
        );
    }
    Ok(())
}

fn write_png(path: &std::path::Path, width: u16, height: u16, rgb: &[u8]) -> Result<()> {
    let file = std::fs::File::create(path)?;
    let mut encoder = png::Encoder::new(
        std::io::BufWriter::new(file),
        u32::from(width),
        u32::from(height),
    );
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.write_header()?.write_image_data(rgb)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format_32bpp_little_endian() -> PixelFormat {
        PixelFormat::parse(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0])
    }

    /// The wire is what the server reads, so the bytes are the contract.
    /// A PointerEvent is six bytes and a click is two of them.
    #[test]
    fn pointer_events_are_six_bytes_on_the_wire() {
        assert_eq!(pointer_event(0, 640, 480), [5, 0, 2, 128, 1, 224]);
        assert_eq!(
            pointer_event(Button::Left.mask(), 640, 480),
            [5, 1, 2, 128, 1, 224]
        );
        assert_eq!(Button::Right.mask(), 4, "right is bit 2, not button 3");
    }

    /// A KeyEvent is eight bytes and carries an X11 keysym, not a scancode.
    #[test]
    fn key_events_carry_a_keysym() {
        assert_eq!(key_event(true, 0xff0d), [4, 1, 0, 0, 0, 0, 0xff, 0x0d]);
        assert_eq!(key_event(false, 0x61), [4, 0, 0, 0, 0, 0, 0, 0x61]);
    }

    /// Printable ASCII is keysym-identical, which is why typing needs no
    /// table. Uppercase and shifted symbols must hold Shift or they arrive as
    /// the wrong character rather than as an error.
    #[test]
    fn ascii_maps_to_keysyms_and_knows_when_shift_is_needed() {
        assert_eq!(keysym_for('a').unwrap(), (0x61, false));
        assert_eq!(keysym_for('A').unwrap(), (0x41, true));
        assert_eq!(keysym_for('/').unwrap(), (0x2f, false));
        assert_eq!(keysym_for('?').unwrap(), (0x3f, true));
        assert_eq!(keysym_for('\n').unwrap(), (0xff0d, false));
    }

    /// An accent silently typed as the wrong character is worse than a
    /// refusal, so anything needing a layout-aware table is refused by name.
    #[test]
    fn a_character_without_a_keysym_is_refused_rather_than_guessed() {
        let error = keysym_for('ñ').unwrap_err().to_string();
        assert!(error.contains("cannot type"), "{error}");
        assert!(error.contains("layout-aware"), "{error}");
    }

    /// Shift wraps the keystroke and is released afterwards: a left-over
    /// Shift would capitalise everything typed next.
    #[test]
    fn shift_is_pressed_and_released_around_the_key() {
        let plain = typed_key_events(0x61, false);
        assert_eq!(plain.len(), 16, "two key events");

        let shifted = typed_key_events(0x41, true);
        assert_eq!(shifted.len(), 32, "shift down, key down, key up, shift up");
        assert_eq!(&shifted[0..8], &key_event(true, 0xffe1));
        assert_eq!(&shifted[24..32], &key_event(false, 0xffe1));
    }

    /// Pixels are scaled from the server's maxima rather than assumed to be
    /// eight bits: a 5-6-5 server would otherwise produce a dark, wrong image.
    #[test]
    fn pixels_convert_through_the_servers_own_maxima() {
        let format = format_32bpp_little_endian();
        assert_eq!(format.bytes_per_pixel(), 4);
        // Little-endian BGRX: blue, green, red, pad.
        assert_eq!(format.to_rgb(&[0, 0, 255, 0]), [255, 0, 0], "red");
        assert_eq!(format.to_rgb(&[255, 0, 0, 0]), [0, 0, 255], "blue");
        assert_eq!(format.to_rgb(&[0, 0, 0, 0]), [0, 0, 0], "black");

        let five_six_five = PixelFormat {
            bits_per_pixel: 16,
            big_endian: false,
            true_colour: true,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
        };
        // Full red in 5-6-5 must reach 255, not 31.
        assert_eq!(five_six_five.to_rgb(&[0x00, 0xf8]), [255, 0, 0]);
    }

    /// Unknown key names are rejected with a hint rather than sent as zero,
    /// which the server would accept and silently do nothing with.
    #[test]
    fn named_keys_resolve_or_explain() {
        assert_eq!(named_keysym("Return").unwrap(), 0xff0d);
        assert_eq!(named_keysym("esc").unwrap(), 0xff1b);
        assert!(
            named_keysym("hyperspace")
                .unwrap_err()
                .to_string()
                .contains("unknown key")
        );
    }

    /// A click outside the announced desktop is a caller error worth naming,
    /// not something to send and have silently ignored.
    #[test]
    fn coordinates_outside_the_desktop_are_refused() {
        let server = ServerInit {
            width: 800,
            height: 600,
            format: format_32bpp_little_endian(),
        };
        assert!(bounds_check(server, 799, 599).is_ok());
        let error = bounds_check(server, 800, 0).unwrap_err().to_string();
        assert!(error.contains("800x600"), "{error}");
    }
}
