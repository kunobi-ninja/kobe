mod claim;
mod config;
mod leases;
mod login;
mod pools;
mod release;

pub use claim::claim;
pub use config::{config_interactive, config_set, config_show};
pub use leases::leases;
pub use login::{login, logout};
pub use pools::pools;
pub use release::release;

use config::{AuthMode, CliConfig};

/// Get a valid auth token based on the configured auth mode.
/// Returns None for no-auth mode, Some(token) for token/oidc.
pub(crate) async fn get_auth_header(endpoint: &str) -> anyhow::Result<Option<String>> {
    let config = CliConfig::load()?;

    match config.auth {
        AuthMode::None => Ok(None),
        AuthMode::Token => match &config.token {
            Some(t) => Ok(Some(t.clone())),
            None => anyhow::bail!(
                "Auth mode is 'token' but no token configured. Run: kobe config set token <value>"
            ),
        },
        AuthMode::Oidc => {
            let service_config = kunobi_oidc::ServiceConfig::discover(endpoint).await?;
            let client = kunobi_oidc::AuthClient::new(service_config)?;
            Ok(Some(client.token().await?))
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
    token: &Option<String>,
) -> reqwest::RequestBuilder {
    match token {
        Some(t) => builder.bearer_auth(t),
        None => builder,
    }
}
