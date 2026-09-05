//! Optional P2P data-plane transport for Sandbox operations (#197).
//!
//! The control plane stays where it is: REST over axum, admission through the
//! API server, scoped credentials through #81. Iroh only carries the *bytes*
//! of attach/exec/port-forward sessions, and later the dial to child-cluster
//! apiservers, where direct L3 connectivity cannot reach (NATs).
//!
//! # Always compiled, activated per pool
//!
//! The binary always contains iroh (plain dependency, no Cargo feature). Whether
//! a session uses it is decided at runtime by `SandboxPool.spec.transport`
//! (`direct` by default). Asking for `iroh` where the operator did not enable
//! it is rejected at admission — never silently downgraded to WebSocket.
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
//! operator restart changes the node ID peers dial. Lease-scoped peer IDs are
//! exchanged through the existing scoped-credential path (#81) and die with
//! the lease TTL.

use std::time::Duration;

use anyhow::{Context, Result};
use iroh::{Endpoint, RelayMode, SecretKey, endpoint::presets::N0};

/// ALPN negotiated on every kobe↔sandbox iroh connection.
///
/// Versioned so a future wire change fails at the handshake instead of
/// misreading a stream.
pub const KOBE_SANDBOX_ALPN: &[u8] = b"kobe-sandbox/1";

/// Longest to wait for the endpoint to come online (home relay selected)
/// before a session attempt fails explicitly rather than hanging.
pub const ENDPOINT_ONLINE_TIMEOUT: Duration = Duration::from_secs(30);

/// How the operator endpoint reaches the relay network.
#[derive(Debug, Clone, Default)]
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
pub async fn wait_online(endpoint: &Endpoint) -> Result<()> {
    tokio::time::timeout(ENDPOINT_ONLINE_TIMEOUT, endpoint.online())
        .await
        .context("iroh endpoint did not come online in time")?;
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
}
