use anyhow::Result;
use kunobi_auth::client::{AuthClient, ServiceConfig};

use super::config::{AuthMode, CliConfig};

pub async fn login(context_override: Option<&str>, endpoint_override: Option<&str>) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(context_override, endpoint_override)?;
    let endpoint = config.endpoint.as_str();
    if config.auth != AuthMode::Oidc {
        println!(
            "Context uses auth={}. Browser login is only needed for auth=oidc.",
            config.auth
        );
        return Ok(());
    }

    println!("Discovering auth configuration from {endpoint}...");
    let service_config = ServiceConfig::discover(endpoint).await?;
    let client = AuthClient::new(service_config)?;

    println!("Opening browser for authentication...");
    client.login().await?;

    println!("Authenticated successfully!");
    Ok(())
}

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
    client.logout()?;

    println!("Logged out.");
    Ok(())
}
