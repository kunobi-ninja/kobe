use anyhow::Result;
use kunobi_auth::client::{AuthClient, ServiceConfig};

use super::config::CliConfig;

pub async fn login() -> Result<()> {
    let config = CliConfig::load()?;
    let endpoint = config.endpoint();

    println!("Discovering auth configuration from {endpoint}...");
    let service_config = ServiceConfig::discover(endpoint).await?;
    let client = AuthClient::new(service_config)?;

    println!("Opening browser for authentication...");
    client.login().await?;

    println!("Authenticated successfully!");
    Ok(())
}

pub async fn logout() -> Result<()> {
    let config = CliConfig::load()?;
    let endpoint = config.endpoint();

    let service_config = ServiceConfig::discover(endpoint).await?;
    let client = AuthClient::new(service_config)?;
    client.logout()?;

    println!("Logged out.");
    Ok(())
}
