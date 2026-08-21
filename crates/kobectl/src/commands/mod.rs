mod config;
mod config_tui;
mod extend;
mod keepalive;
mod lease_create;
mod leases;
mod login;
mod picker;
mod pools;
mod purge;
mod release;
pub(crate) mod sandbox;
pub(crate) mod sandbox_transport;
mod select;
pub(crate) mod session;
mod state;
mod status;
mod version;
mod with_lease;

use clap::ValueEnum;
use serde::Serialize;

pub use config::{
    config_current_target, config_export, config_import, config_list_targets, config_set_target,
    config_show, config_use_target,
};
pub use config_tui::run_config_tui as config_interactive;
pub use extend::extend;
pub use lease_create::{LeaseCreateCommand, lease_create};
pub use login::{login, logout};
pub use purge::purge;
pub use release::release;
pub use status::status;
pub use version::version;
pub use with_lease::{WithLeaseCommand, with_lease};

use config::{AuthMode, ResolvedConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthInteraction {
    Interactive,
    NonInteractive,
}

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
    get_auth_header_with_interaction(config, method, path, body, AuthInteraction::Interactive).await
}

/// Build authorization without ever prompting or writing a trust warning.
///
/// Machine-output commands use this path so stdout remains their only output
/// channel. An SSH first-connect or audience change becomes structured command
/// failure; the caller can rerun a text-mode command to review it interactively.
pub(crate) async fn get_auth_header_noninteractive(
    config: &ResolvedConfig,
    method: &str,
    path: &str,
    body: &[u8],
) -> anyhow::Result<Option<String>> {
    get_auth_header_with_interaction(config, method, path, body, AuthInteraction::NonInteractive)
        .await
}

async fn get_auth_header_with_interaction(
    config: &ResolvedConfig,
    method: &str,
    path: &str,
    body: &[u8],
    interaction: AuthInteraction,
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
            let token = match interaction {
                AuthInteraction::Interactive => {
                    kunobi_auth::client::AuthClient::new(service_config)?
                        .token()
                        .await?
                }
                AuthInteraction::NonInteractive => {
                    oidc_token_noninteractive(&service_config).await?
                }
            };
            Ok(Some(format!("Bearer {token}")))
        }
        AuthMode::Ssh => {
            let client = kunobi_auth::client::AuthClient::with_ssh(config.ssh_fingerprint.clone())?;
            // Discover audience from /v1/status — retry once if server hasn't loaded policies yet
            let audience = discover_ssh_audience(&config.endpoint).await?;
            tofu_check(&config.endpoint, &audience, interaction).await?;
            let header = client.authorize(&audience, method, path, body).await?;
            Ok(Some(header))
        }
    }
}

/// Load or refresh OIDC credentials without falling back to browser login.
///
/// `AuthClient::token()` deliberately becomes interactive when neither path is
/// usable. Machine output cannot permit that fallback because browser-login
/// writes prompts to stdout. This mirrors its cache/refresh path and fails
/// before any user interaction would begin.
async fn oidc_token_noninteractive(
    config: &kunobi_auth::client::ServiceConfig,
) -> anyhow::Result<String> {
    use kunobi_auth::client::TokenStore;

    let store = TokenStore::new()?;
    let Some(stored) = store.load(&config.issuer)? else {
        anyhow::bail!("OIDC login is required; run `kobe login` before using --output json")
    };
    if !stored.is_expired() {
        return Ok(stored.id_token);
    }
    let Some(refresh_token) = stored.refresh_token.as_deref() else {
        anyhow::bail!(
            "OIDC credentials expired without a refresh token; run `kobe login` before using --output json"
        )
    };
    let mut refreshed = kunobi_auth::client::oidc::refresh(
        &config.issuer,
        &config.client_id,
        &config.redirect_uri,
        refresh_token,
    )
    .await
    .map_err(|error| {
        anyhow::anyhow!(
            "OIDC refresh failed without interactive fallback ({error}); run `kobe login`"
        )
    })?;
    refreshed.extra = stored.extra;
    let token = refreshed.id_token.clone();
    store.save(&refreshed)?;
    Ok(token)
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
                if method["type"].as_str() == Some("ssh")
                    && let Some(audience) = method["audience"].as_str()
                {
                    return Ok(audience.to_string());
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

/// Verify SSH trust off the async worker thread.
///
/// The interactive path reads stdin synchronously. Running it in Tokio's
/// blocking pool means an enclosing request deadline or signal `select!` can
/// still make progress instead of being trapped inside one future poll.
async fn tofu_check(
    endpoint: &str,
    audience: &str,
    interaction: AuthInteraction,
) -> anyhow::Result<()> {
    let endpoint = endpoint.to_string();
    let audience = audience.to_string();
    tokio::task::spawn_blocking(move || tofu_check_blocking(&endpoint, &audience, interaction))
        .await
        .map_err(|error| anyhow::anyhow!("SSH trust check task failed: {error}"))?
}

fn tofu_check_blocking(
    endpoint: &str,
    audience: &str,
    interaction: AuthInteraction,
) -> anyhow::Result<()> {
    let store = kunobi_auth::client::TofuStore::new()?;
    apply_tofu_result(&store, store.verify(endpoint, audience)?, interaction)
}

fn apply_tofu_result(
    store: &kunobi_auth::client::TofuStore,
    result: kunobi_auth::client::TofuResult,
    interaction: AuthInteraction,
) -> anyhow::Result<()> {
    // The SSH auth path has no OIDC issuer (status reports issuer=None for ssh,
    // and SSH identities are stamped issuer="ssh"), so pin the endpoint under
    // the "ssh" sentinel for the issuer slot that TofuStore::trust requires.
    let pinned_issuer = "ssh";
    match result {
        kunobi_auth::client::TofuResult::Trusted => Ok(()),
        kunobi_auth::client::TofuResult::FirstConnect { endpoint, audience }
            if interaction == AuthInteraction::NonInteractive =>
        {
            anyhow::bail!(
                "SSH trust is not established for {endpoint} (audience {audience}); rerun in text mode to review it"
            )
        }
        kunobi_auth::client::TofuResult::FirstConnect { endpoint, audience } => {
            eprintln!();
            eprintln!("Connecting to {endpoint}");
            eprintln!("  Audience: {audience}");
            eprintln!();
            eprint!("Trust this service? [y/N] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim().eq_ignore_ascii_case("y") {
                store.trust(&endpoint, pinned_issuer, &audience)?;
                Ok(())
            } else {
                anyhow::bail!("Connection refused by user")
            }
        }
        kunobi_auth::client::TofuResult::AudienceChanged {
            endpoint,
            previous,
            current,
        } if interaction == AuthInteraction::NonInteractive => {
            anyhow::bail!(
                "SSH audience changed for {endpoint} from {previous} to {current}; rerun in text mode to review it"
            )
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
                store.trust(&endpoint, pinned_issuer, &current)?;
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

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn noninteractive_tofu_never_accepts_a_promptable_decision() {
        let directory = tempfile::tempdir().unwrap();
        let store = kunobi_auth::client::TofuStore::with_path(directory.path().join("known.json"));
        let first = kunobi_auth::client::TofuResult::FirstConnect {
            endpoint: "https://kobe.example".into(),
            audience: "kobe".into(),
        };
        assert!(
            apply_tofu_result(&store, first, AuthInteraction::NonInteractive)
                .unwrap_err()
                .to_string()
                .contains("rerun in text mode")
        );

        let changed = kunobi_auth::client::TofuResult::AudienceChanged {
            endpoint: "https://kobe.example".into(),
            previous: "old".into(),
            current: "new".into(),
        };
        assert!(
            apply_tofu_result(&store, changed, AuthInteraction::NonInteractive)
                .unwrap_err()
                .to_string()
                .contains("rerun in text mode")
        );
        apply_tofu_result(
            &store,
            kunobi_auth::client::TofuResult::Trusted,
            AuthInteraction::NonInteractive,
        )
        .unwrap();
    }
}
