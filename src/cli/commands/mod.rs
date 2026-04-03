mod claim;
mod config;
mod leases;
mod login;
mod pools;
mod release;

pub use claim::claim;
pub use config::{config_set, config_show};
pub use leases::leases;
pub use login::{login, logout};
pub use pools::pools;
pub use release::release;

pub(crate) async fn get_token(endpoint: &str) -> anyhow::Result<String> {
    let service_config = kunobi_oidc::ServiceConfig::discover(endpoint).await?;
    let client = kunobi_oidc::AuthClient::new(service_config)?;
    client.token().await
}
