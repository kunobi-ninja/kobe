use anyhow::Result;
use std::path::PathBuf;

use super::config::CliConfig;

pub async fn claim(pool: &str, ttl: &str, output: Option<&str>) -> Result<()> {
    let config = CliConfig::load()?;
    let endpoint = config.endpoint();
    let token = crate::commands::get_token(endpoint).await?;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{endpoint}/v1/leases"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "pool": pool,
            "ttl": ttl,
        }))
        .send()
        .await?;

    let status = response.status();
    let body: serde_json::Value = response.json().await?;

    if !status.is_success() {
        let msg = body["error"]
            .as_str()
            .or(body["message"].as_str())
            .unwrap_or("Unknown error");
        anyhow::bail!("Failed to claim cluster (HTTP {status}): {msg}");
    }

    let lease_id = body["id"].as_str().unwrap_or("unknown");
    let cluster_name = body["clusterName"]
        .as_str()
        .or(body["cluster_name"].as_str())
        .unwrap_or("pending");
    let kubeconfig = body["kubeconfig"].as_str();

    if let Some(kc) = kubeconfig {
        let path = match output {
            Some(p) => PathBuf::from(p),
            None => dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".kube")
                .join(format!("kobe-{lease_id}")),
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, kc)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        println!("Cluster: {cluster_name}");
        println!("Lease:   {lease_id}");
        println!("Config:  {}", path.display());
        println!();
        println!("export KUBECONFIG={}", path.display());
    } else {
        println!("Cluster: {cluster_name}");
        println!("Lease:   {lease_id}");
        println!("Status:  Pending (waiting for cluster assignment)");
    }

    Ok(())
}
