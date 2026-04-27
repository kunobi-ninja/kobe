use anyhow::Result;
use kunobi_auth::client::{AuthClient, ServiceConfig};

use super::config::{AuthMode, CliConfig};

/// Default OAuth scope for the device-grant flow. Mirrors what
/// `browser_login` uses internally — every Kunobi IdP we test against
/// (Dex, Auth0, Keycloak) accepts `openid profile email`. If a
/// product needs a tighter scope it can be made configurable later.
const DEVICE_GRANT_SCOPE: &str = "openid profile email offline_access";

/// Authenticate with the kobe service.
///
/// `device` selects RFC 8628 Device Authorization Grant: the CLI prints
/// a verification URL + user code and polls the IdP while the user
/// completes authorization in any browser (typically on a phone or
/// laptop). Useful when running kobe over SSH on a headless box,
/// inside a CI runner, or anywhere a browser can't open locally.
///
/// Without `device`, falls back to the standard browser-redirect flow
/// — opens the system browser, listens on a localhost callback URL,
/// completes the OAuth dance.
pub async fn login(
    context_override: Option<&str>,
    endpoint_override: Option<&str>,
    device: bool,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(context_override, endpoint_override)?;
    let endpoint = config.endpoint.as_str();
    if config.auth != AuthMode::Oidc {
        println!(
            "Context uses auth={}. Browser/device login is only needed for auth=oidc.",
            config.auth
        );
        return Ok(());
    }

    println!("Discovering auth configuration from {endpoint}...");
    let service_config = ServiceConfig::discover(endpoint).await?;
    let client = AuthClient::new(service_config)?;

    if device {
        println!("Starting device authorization flow...");
        client
            .device_login(DEVICE_GRANT_SCOPE, |prompt| {
                eprintln!();
                if let Some(complete) = &prompt.verification_uri_complete {
                    eprintln!("  Open this URL on any browser:");
                    eprintln!("    {complete}");
                    eprintln!();
                    eprintln!(
                        "  Or visit {} and enter code: {}",
                        prompt.verification_uri, prompt.user_code
                    );
                } else {
                    eprintln!("  Open this URL on any browser:");
                    eprintln!("    {}", prompt.verification_uri);
                    eprintln!();
                    eprintln!("  Then enter code: {}", prompt.user_code);
                }
                eprintln!();
                eprintln!(
                    "  Code expires in {} seconds. Polling…",
                    prompt.expires_in.as_secs()
                );
                eprintln!();
            })
            .await?;
    } else {
        println!("Opening browser for authentication...");
        client.login().await?;
    }

    println!("Authenticated successfully!");
    Ok(())
}

/// Sign out of the kobe service.
///
/// Now uses `logout_async`: in addition to deleting the locally cached
/// token, attempts to **revoke** the refresh + access tokens at the
/// IdP via RFC 7009. Closes the leaked-laptop window where a stolen
/// refresh token would otherwise stay valid until natural expiry. If
/// the IdP doesn't advertise a revocation endpoint or the request
/// fails, the local cleanup still happens and the error is logged
/// (best-effort semantics).
pub async fn logout(context_override: Option<&str>, endpoint_override: Option<&str>) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(context_override, endpoint_override)?;
    let endpoint = config.endpoint.as_str();
    if config.auth != AuthMode::Oidc {
        println!(
            "Context uses auth={}. Browser logout is only needed for auth=oidc.",
            config.auth
        );
        return Ok(());
    }

    let service_config = ServiceConfig::discover(endpoint).await?;
    let client = AuthClient::new(service_config)?;
    client.logout_async().await?;

    println!("Logged out (token revoked at IdP).");
    Ok(())
}
