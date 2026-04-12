mod config;
mod config_tui;
mod lease_create;
mod leases;
mod login;
mod pools;
mod release;
mod state;
mod status;
mod version;

use clap::ValueEnum;
use serde::Serialize;

pub use config::{
    config_current_target, config_list_targets, config_set_target, config_show, config_use_target,
};
pub use config_tui::run_config_tui as config_interactive;
pub use lease_create::lease_create;
pub use login::{login, logout};
pub use release::release;
pub use status::status;
pub use version::version;

use config::{AuthMode, ResolvedConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

pub(crate) fn cli_version() -> &'static str {
    option_env!("BUILD_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

pub(crate) fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Get a valid auth header value based on the configured auth mode.
/// Returns None for no-auth mode, Some(header) for token/oidc/ssh.
pub(crate) async fn get_auth_header(
    config: &ResolvedConfig,
    method: &str,
    path: &str,
    body: &[u8],
) -> anyhow::Result<Option<String>> {
    match &config.auth {
        AuthMode::None => Ok(None),
        AuthMode::Token => match &config.token {
            Some(t) => Ok(Some(format!("Bearer {t}"))),
            None => {
                anyhow::bail!("Auth mode is 'token' but no token configured. Run: kobe config edit")
            }
        },
        AuthMode::Oidc => {
            let service_config =
                kunobi_auth::client::ServiceConfig::discover(&config.endpoint).await?;
            let client = kunobi_auth::client::AuthClient::new(service_config)?;
            Ok(Some(format!("Bearer {}", client.token().await?)))
        }
        AuthMode::Ssh => {
            let client = kunobi_auth::client::AuthClient::with_ssh(config.ssh_fingerprint.clone())?;
            // Discover audience from /v1/status — retry once if server hasn't loaded policies yet
            let audience = discover_ssh_audience(&config.endpoint).await?;
            tofu_check(&config.endpoint, &audience).await?;
            let header = client.authorize(&audience, method, path, body).await?;
            Ok(Some(header))
        }
    }
}

async fn discover_ssh_audience(endpoint: &str) -> anyhow::Result<String> {
    // Try twice — the server may not have loaded policies on first attempt
    for attempt in 0..2 {
        let resp: serde_json::Value = reqwest::get(format!("{endpoint}/v1/status"))
            .await?
            .json()
            .await?;
        if let Some(methods) = resp["auth"]["methods"].as_array() {
            for method in methods {
                if method["type"].as_str() == Some("ssh") {
                    if let Some(audience) = method["audience"].as_str() {
                        return Ok(audience.to_string());
                    }
                }
            }
        }
        if attempt == 0 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    anyhow::bail!(
        "Server at {endpoint} has no SSH auth method configured. \
         Check that an AccessPolicy with ssh auth exists in the cluster."
    )
}

async fn tofu_check(endpoint: &str, audience: &str) -> anyhow::Result<()> {
    let store = kunobi_auth::client::TofuStore::new()?;
    match store.verify(endpoint, audience)? {
        kunobi_auth::client::TofuResult::Trusted => Ok(()),
        kunobi_auth::client::TofuResult::FirstConnect { endpoint, audience } => {
            eprintln!();
            eprintln!("Connecting to {endpoint}");
            eprintln!("  Audience: {audience}");
            eprintln!();
            eprint!("Trust this service? [y/N] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim().eq_ignore_ascii_case("y") {
                store.trust(&endpoint, &audience)?;
                Ok(())
            } else {
                anyhow::bail!("Connection refused by user")
            }
        }
        kunobi_auth::client::TofuResult::AudienceChanged {
            endpoint,
            previous,
            current,
        } => {
            eprintln!();
            eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            eprintln!("@    WARNING: SERVICE AUDIENCE HAS CHANGED!       @");
            eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            eprintln!("The audience for {endpoint} changed:");
            eprintln!("  Previous: {previous}");
            eprintln!("  Current:  {current}");
            eprintln!("This could mean the service was reconfigured, or it");
            eprintln!("could indicate a man-in-the-middle attack.");
            eprint!("Continue? [y/N] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim().eq_ignore_ascii_case("y") {
                store.trust(&endpoint, &current)?;
                Ok(())
            } else {
                anyhow::bail!("Connection refused by user")
            }
        }
    }
}

/// Build an HTTP request with optional auth.
pub(crate) fn authed_client() -> reqwest::Client {
    reqwest::Client::new()
}

/// Add auth header to a request builder if available.
pub(crate) fn with_auth(
    builder: reqwest::RequestBuilder,
    auth_header: &Option<String>,
) -> reqwest::RequestBuilder {
    match auth_header {
        Some(h) => builder.header("Authorization", h),
        None => builder,
    }
}
