use anyhow::Result;

use super::config::CliConfig;
use super::{authed_client, get_auth_header, with_auth};

pub async fn release(
    lease_id: &str,
    context_override: Option<&str>,
    endpoint_override: Option<&str>,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(context_override, endpoint_override)?;
    let endpoint = config.endpoint.as_str();
    let path = format!("/v1/leases/{lease_id}");
    let token = get_auth_header(&config, "DELETE", &path, b"").await?;

    let client = authed_client();
    let response = with_auth(
        client.delete(format!("{endpoint}/v1/leases/{lease_id}")),
        &token,
    )
    .send()
    .await?;

    if response.status().is_success() {
        println!("Released lease {lease_id}");
    } else if response.status().as_u16() == 404 {
        println!("Lease {lease_id} not found (already released or expired)");
    } else {
        anyhow::bail!("Failed to release lease (HTTP {})", response.status());
    }

    Ok(())
}
