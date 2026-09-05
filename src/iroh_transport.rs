//! Optional P2P data-plane transport for Sandbox operations (#197).
//!
//! The control plane stays where it is: REST over axum, admission through the
//! API server, scoped credentials through #81. Iroh only carries the *bytes*
//! of attach/port-forward sessions, and later the dial to child-cluster
//! apiservers, where direct L3 connectivity cannot reach (NATs).
//!
//! # Always compiled, activated per pool
//!
//! The binary always contains iroh (plain dependency, no Cargo feature). Whether
//! a session uses it is decided at runtime by `SandboxPool.spec.transport`
//! (`direct` by default). Asking for `iroh` where the operator did not enable
//! it is rejected at admission — never silently downgraded to WebSocket.
//!
//! # Session handshake
//!
//! A caller that wants bytes on an `iroh` pool first hits REST
//! (`POST /v1/sandbox-leases/{id}/session`). That path does the same
//! authorization and stream registration as the WebSocket upgrade, then
//! returns a one-shot ticket plus this replica's node ID. The client dials
//! iroh, writes the ticket as the first length-prefixed blob, and from then
//! on the wire is the same channel-framed protocol as the WebSocket path.
//! An unknown or reused ticket is dropped; it is never served over
//! WebSocket instead.
//!
//! # Relay
//!
//! Default is the public n0 relay ([`RelayMode::Default`]); traffic is
//! end-to-end encrypted QUIC, so a relay observes metadata only (addresses,
//! timing), never session bytes. A self-hosted relay is a config change
//! ([`RelayMode::Custom`]), not a protocol change.
//!
//! # Identity
//!
//! The operator endpoint keeps an ephemeral [`SecretKey`] for the spike. A
//! stable identity persisted in a Secret is follow-up work: without it, every
//! operator restart changes the node ID peers dial. Session tickets are
//! replica-local and die with [`TICKET_TTL`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use iroh::endpoint::{Incoming, RecvStream, SendStream};
use iroh::{Endpoint, RelayMode, SecretKey, endpoint::presets::N0};
use rand::Rng;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tracing::warn;

/// ALPN negotiated on every kobe↔sandbox iroh connection.
///
/// Versioned so a future wire change fails at the handshake instead of
/// misreading a stream.
pub const KOBE_SANDBOX_ALPN: &[u8] = b"kobe-sandbox/1";

/// Longest to wait for the endpoint to come online (home relay selected)
/// before a session attempt fails explicitly rather than hanging.
#[allow(dead_code)] // used by callers that dial after bind (CLI, future session helpers)
pub const ENDPOINT_ONLINE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a minted ticket is valid before the accept loop drops it.
///
/// Matches [`crate::api::sandbox_transport::STREAM_SETUP_TIMEOUT`]: a caller
/// that cannot dial in that window has already lost the same race the
/// WebSocket path would have lost opening the target stream.
pub const TICKET_TTL: Duration = Duration::from_secs(30);

/// Raw ticket size. The JSON offer hex-encodes these bytes.
pub const TICKET_BYTES: usize = 32;

/// Largest length-prefixed blob accepted on an iroh stream.
///
/// A WebSocket message is already bounded by the HTTP stack. QUIC is a byte
/// stream, so this is the equivalent: a caller that announces a multi-megabyte
/// frame is probing, not resizing a terminal.
pub const MAX_BLOB_BYTES: usize = 1024 * 1024;

/// How the operator endpoint reaches the relay network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RelayConfig {
    /// Public n0 relays. The current default (#197: relay público por ahora).
    #[default]
    Public,
    /// Operator-run relays, by URL.
    Custom(Vec<String>),
    /// No relays: direct UDP only. Fails behind NAT by construction.
    Disabled,
}

impl RelayConfig {
    fn relay_mode(&self) -> Result<RelayMode> {
        match self {
            RelayConfig::Public => Ok(RelayMode::Default),
            RelayConfig::Disabled => Ok(RelayMode::Disabled),
            RelayConfig::Custom(urls) => {
                let map = iroh::RelayMap::empty();
                for url in urls {
                    let url: iroh::RelayUrl = url
                        .parse()
                        .with_context(|| format!("invalid iroh relay URL: {url}"))?;
                    let cfg = std::sync::Arc::new(iroh::RelayConfig::new(url.clone(), None));
                    map.insert(url, cfg);
                }
                Ok(RelayMode::Custom(map))
            }
        }
    }
}

/// Configuration for the operator-side iroh endpoint.
#[derive(Debug, Clone, Default)]
pub struct IrohTransportConfig {
    /// Relay selection. Default is the public relay.
    pub relay: RelayConfig,
    /// Stable identity. `None` generates an ephemeral key (spike behavior);
    /// production should load this from a Secret so restarts keep the node ID.
    pub secret_key: Option<SecretKey>,
}

/// Operator-side iroh enablement, parsed from `KOBE_IROH_RELAY`.
///
/// Fail-closed like [`crate::sandbox_runtime::parse_mode`]: an unrecognised
/// value refuses startup rather than running an operator whose relays are not
/// what the administrator wrote down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrohOperatorConfig {
    /// No endpoint is bound. Pools requesting `iroh` transport are rejected
    /// at admission — never silently served over WebSocket.
    Disabled,
    /// Bind the endpoint with these relays.
    Enabled(RelayConfig),
}

/// Parse the configured relay selection without silently degrading bad input.
///
/// - `""` / `"public"` → public n0 relays (current default, #197).
/// - `"disabled"` → no endpoint; `iroh` pools are refused.
/// - anything else → comma-separated relay URLs for a self-hosted relay map.
pub fn parse_operator_config(configured: &str) -> Result<IrohOperatorConfig, String> {
    match configured.trim().to_ascii_lowercase().as_str() {
        "" | "public" => Ok(IrohOperatorConfig::Enabled(RelayConfig::Public)),
        "disabled" => Ok(IrohOperatorConfig::Disabled),
        urls => {
            let urls: Vec<String> = urls
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect();
            if urls.is_empty() {
                return Err(format!("invalid KOBE_IROH_RELAY value: {configured:?}"));
            }
            // Validate eagerly so a typo fails startup, not the first session.
            for url in &urls {
                url.parse::<iroh::RelayUrl>()
                    .map_err(|_| format!("invalid iroh relay URL in KOBE_IROH_RELAY: {url:?}"))?;
            }
            Ok(IrohOperatorConfig::Enabled(RelayConfig::Custom(urls)))
        }
    }
}

/// Read the operator iroh configuration. Absence defaults to the public relay.
pub fn operator_config_from_env() -> Result<IrohOperatorConfig, String> {
    parse_operator_config(&std::env::var("KOBE_IROH_RELAY").unwrap_or_default())
}

/// Admission gate for `iroh` pools: the pool may only use the P2P transport
/// when the operator actually bound an endpoint. Pure so both the HTTP path
/// and tests share one decision.
pub fn require_iroh_available(
    transport: crate::crd::SandboxTransport,
    endpoint_present: bool,
) -> Result<(), &'static str> {
    if transport == crate::crd::SandboxTransport::Iroh && !endpoint_present {
        return Err(
            "pool requests iroh transport but the operator has it disabled (KOBE_IROH_RELAY=disabled)",
        );
    }
    Ok(())
}

/// Bind the operator endpoint: N0 preset, kobe ALPN, configured relays.
///
/// Returns once bound; callers that need a home relay before accepting
/// sessions should additionally await [`wait_online`].
pub async fn bind_endpoint(config: &IrohTransportConfig) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(N0)
        .alpns(vec![KOBE_SANDBOX_ALPN.to_vec()])
        .relay_mode(config.relay.relay_mode()?);
    if let Some(key) = &config.secret_key {
        builder = builder.secret_key(key.clone());
    }
    builder.bind().await.context("bind iroh operator endpoint")
}

/// Wait until the endpoint is online (usable for dial/accept), or time out.
///
/// An endpoint that never comes online must fail the session explicitly —
/// the failure contract for admission (#101) has no room for a hang.
#[allow(dead_code)] // CLI dials wait on its own endpoint; operator accept does not.
pub async fn wait_online(endpoint: &Endpoint) -> Result<()> {
    tokio::time::timeout(ENDPOINT_ONLINE_TIMEOUT, endpoint.online())
        .await
        .context("iroh endpoint did not come online in time")?;
    Ok(())
}

impl IrohOperatorConfig {
    /// Canonical relay string put in a session offer so the client builds the
    /// same [`RelayMode`] the operator is using.
    pub fn as_offer_string(&self) -> String {
        match self {
            Self::Disabled => "disabled".into(),
            Self::Enabled(RelayConfig::Public) => "public".into(),
            Self::Enabled(RelayConfig::Disabled) => "disabled".into(),
            Self::Enabled(RelayConfig::Custom(urls)) => urls.join(","),
        }
    }
}

/// How a caller reaches this replica's iroh endpoint.
///
/// Shown on lease list/get so `kobe status` can print the node ID without
/// opening a session. The node ID is replica-local: another replica has a
/// different one, and a restart currently mints a new key.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IrohDial {
    pub node_id: String,
    pub relay: String,
}

impl IrohDial {
    pub fn from_endpoint(endpoint: &Endpoint, relay: String) -> Self {
        Self {
            node_id: endpoint.id().to_string(),
            relay,
        }
    }
}

/// What REST returns after minting a ticket. The client dials `node_id` with
/// `alpn` and writes the decoded ticket as the first blob.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IrohSessionOffer {
    pub transport: &'static str,
    pub node_id: String,
    pub ticket: String,
    pub alpn: String,
    pub relay: String,
}

impl IrohSessionOffer {
    pub fn new(endpoint: &Endpoint, ticket: String, relay: String) -> Self {
        Self {
            transport: "iroh",
            node_id: endpoint.id().to_string(),
            ticket,
            alpn: String::from_utf8_lossy(KOBE_SANDBOX_ALPN).into_owned(),
            relay,
        }
    }
}

/// One accepted iroh stream, handed from the accept loop to the REST waiter.
pub struct IrohLink {
    pub send: SendStream,
    pub recv: RecvStream,
}

struct PendingTicket {
    tx: oneshot::Sender<IrohLink>,
    inserted: Instant,
}

/// Replica-local ticket map. Tickets never leave this process: another replica
/// has a different node ID, so a ticket minted here is useless there.
#[derive(Clone, Default)]
pub struct IrohSessionHub {
    inner: Arc<Mutex<HashMap<String, PendingTicket>>>,
}

impl IrohSessionHub {
    /// Mint a single-use ticket. The receiver completes when the accept loop
    /// claims it, or when [`TICKET_TTL`] elapses and the sender is dropped.
    pub fn mint(&self) -> (String, oneshot::Receiver<IrohLink>) {
        let mut bytes = [0u8; TICKET_BYTES];
        rand::rng().fill(&mut bytes);
        let ticket = hex::encode(bytes);
        let (tx, rx) = oneshot::channel();
        let mut map = self.inner.lock().expect("iroh session hub lock");
        Self::gc_locked(&mut map);
        map.insert(
            ticket.clone(),
            PendingTicket {
                tx,
                inserted: Instant::now(),
            },
        );
        (ticket, rx)
    }

    /// Take the waiter for `ticket`, if it is still pending and unexpired.
    pub fn claim(&self, ticket: &str) -> Option<oneshot::Sender<IrohLink>> {
        let mut map = self.inner.lock().expect("iroh session hub lock");
        Self::gc_locked(&mut map);
        map.remove(ticket).map(|pending| pending.tx)
    }

    fn gc_locked(map: &mut HashMap<String, PendingTicket>) {
        let now = Instant::now();
        map.retain(|_, pending| now.duration_since(pending.inserted) < TICKET_TTL);
    }
}

/// Write one length-prefixed blob. First blob on a session is the raw ticket;
/// later blobs are `[channel][payload]` matching the WebSocket frames.
pub async fn write_blob<W: AsyncWriteExt + Unpin>(
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

/// Read one length-prefixed blob, or `None` on a clean EOF before any bytes.
pub async fn read_blob<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, std::io::Error> {
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

/// Write the raw ticket bytes as the first blob on a newly opened stream.
pub async fn write_ticket<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    ticket_hex: &str,
) -> Result<(), String> {
    let bytes = hex::decode(ticket_hex).map_err(|_| "ticket is not hex".to_string())?;
    if bytes.len() != TICKET_BYTES {
        return Err("ticket has the wrong length".into());
    }
    write_blob(writer, &bytes)
        .await
        .map_err(|err| err.to_string())
}

/// Accept incoming iroh connections until the endpoint closes.
///
/// Each connection is expected to open one bi-stream and write a ticket as
/// the first blob. Unknown tickets are dropped rather than mapped onto the
/// WebSocket path.
pub async fn accept_loop(endpoint: Endpoint, sessions: IrohSessionHub) {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            break;
        };
        let sessions = sessions.clone();
        tokio::spawn(async move {
            if let Err(err) = accept_one(incoming, &sessions).await {
                warn!(error = %err, "iroh accept failed");
            }
        });
    }
}

async fn accept_one(incoming: Incoming, sessions: &IrohSessionHub) -> Result<()> {
    let conn = incoming.await.context("iroh handshake failed")?;
    let (send, mut recv) = conn.accept_bi().await.context("iroh accept_bi failed")?;
    let Some(blob) = read_blob(&mut recv).await.context("read iroh ticket")? else {
        return Ok(());
    };
    if blob.len() != TICKET_BYTES {
        anyhow::bail!("iroh ticket blob has the wrong length");
    }
    let ticket = hex::encode(&blob);
    match sessions.claim(&ticket) {
        Some(tx) => {
            let _ = tx.send(IrohLink { send, recv });
        }
        None => {
            warn!("iroh connection presented an unknown or expired ticket");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_relay_is_default() {
        assert!(matches!(
            IrohTransportConfig::default().relay,
            RelayConfig::Public
        ));
    }

    #[test]
    fn disabled_maps_to_disabled_mode() {
        let mode = RelayConfig::Disabled.relay_mode().unwrap();
        assert!(matches!(mode, RelayMode::Disabled));
    }

    #[test]
    fn custom_relay_rejects_garbage_url() {
        let cfg = RelayConfig::Custom(vec!["not a url at all !!!".to_string()]);
        assert!(cfg.relay_mode().is_err());
    }

    #[test]
    fn alpn_is_versioned() {
        assert!(KOBE_SANDBOX_ALPN.ends_with(b"/1"));
    }

    #[test]
    fn operator_config_defaults_to_public_relay() {
        assert_eq!(
            parse_operator_config("").unwrap(),
            IrohOperatorConfig::Enabled(RelayConfig::Public)
        );
        assert_eq!(
            parse_operator_config("public").unwrap(),
            IrohOperatorConfig::Enabled(RelayConfig::Public)
        );
        assert_eq!(
            parse_operator_config("disabled").unwrap(),
            IrohOperatorConfig::Disabled
        );
    }

    #[test]
    fn operator_config_accepts_custom_relays_and_rejects_garbage() {
        let parsed =
            parse_operator_config("https://relay.example.com, https://relay2.example.com").unwrap();
        assert!(matches!(
            parsed,
            IrohOperatorConfig::Enabled(RelayConfig::Custom(_))
        ));
        assert!(parse_operator_config("https://relay.example.com, !!!").is_err());
        assert!(parse_operator_config(",,,").is_err());
    }

    #[test]
    fn iroh_pool_requires_a_bound_endpoint() {
        use crate::crd::SandboxTransport;
        assert!(require_iroh_available(SandboxTransport::Direct, false).is_ok());
        assert!(require_iroh_available(SandboxTransport::Direct, true).is_ok());
        assert!(require_iroh_available(SandboxTransport::Iroh, true).is_ok());
        assert!(require_iroh_available(SandboxTransport::Iroh, false).is_err());
    }

    #[test]
    fn a_ticket_is_claimed_once_and_unknown_tickets_are_dropped() {
        let hub = IrohSessionHub::default();
        let (ticket, mut rx) = hub.mint();
        assert!(hub.claim("not-a-ticket").is_none());
        let tx = hub.claim(&ticket).expect("fresh ticket is claimable");
        assert!(hub.claim(&ticket).is_none(), "a ticket is single-use");
        drop(tx);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn length_prefixed_blobs_round_trip() {
        let (mut writer, mut reader) = tokio::io::duplex(128);
        write_blob(&mut writer, b"hello").await.unwrap();
        let got = read_blob(&mut reader).await.unwrap().unwrap();
        assert_eq!(got, b"hello");
    }

    /// Two endpoints on this host, no relay: a minted ticket becomes a live
    /// stream the waiter can read.
    #[tokio::test]
    async fn a_ticket_opens_an_iroh_stream_between_two_endpoints() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = IrohTransportConfig {
            relay: RelayConfig::Disabled,
            secret_key: None,
        };
        let server = bind_endpoint(&config).await.expect("bind server");
        let client = bind_endpoint(&config).await.expect("bind client");
        let hub = IrohSessionHub::default();
        let (ticket, rx) = hub.mint();

        let accept = tokio::spawn(accept_loop(server.clone(), hub));
        let conn = client
            .connect(server.addr(), KOBE_SANDBOX_ALPN)
            .await
            .expect("dial");
        let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
        write_ticket(&mut send, &ticket)
            .await
            .expect("write ticket");

        let mut link = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("ticket claimed in time")
            .expect("sender still live");
        write_blob(&mut send, &[1, b'x']).await.expect("frame");
        let got = tokio::time::timeout(Duration::from_secs(5), read_blob(&mut link.recv))
            .await
            .expect("frame arrived")
            .expect("readable")
            .expect("not eof");
        assert_eq!(got, vec![1, b'x']);

        client.close().await;
        server.close().await;
        let _ = accept.await;
    }
}
