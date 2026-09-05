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
#[allow(dead_code)] // consumed by the session path (step 4, #197)
pub const ENDPOINT_ONLINE_TIMEOUT: Duration = Duration::from_secs(30);

/// How the operator endpoint reaches the relay network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RelayConfig {
    /// Public n0 relays. The current default (#197: relay público por ahora).
    #[default]
    Public,
    /// Operator-run relays, by URL.
    Custom(Vec<String>),
    /// No relays: direct UDP only. Fails behind NAT by construction.
    #[allow(dead_code)] // constructed via KOBE_IROH_RELAY parsing follow-ups (step 4, #197)
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
#[allow(dead_code)] // consumed by the session path (step 4, #197)
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
}
