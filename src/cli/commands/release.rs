use anyhow::Result;

use super::config::CliConfig;

pub async fn release(lease_id: &str) -> Result<()> {
    let config = CliConfig::load()?;
    let endpoint = config.endpoint();
    let token = crate::commands::get_token(endpoint).await?;

    let client = reqwest::Client::new();
    let response = client
        .delete(format!("{endpoint}/v1/leases/{lease_id}"))
        .bearer_auth(&token)
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
