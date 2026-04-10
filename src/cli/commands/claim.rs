use anyhow::Result;
use std::path::PathBuf;

use super::config::CliConfig;
use super::{authed_client, get_auth_header, with_auth};

pub async fn claim(
    pool: &str,
    ttl: &str,
    output: Option<&str>,
    context_override: Option<&str>,
    endpoint_override: Option<&str>,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(context_override, endpoint_override)?;
    let endpoint = config.endpoint.as_str();
    let body_json = serde_json::json!({
        "profile": pool,
        "ttl": ttl,
    });
    let body_bytes = serde_json::to_vec(&body_json)?;
    // Body signing not yet supported server-side (extractor doesn't have body access).
    // Sign with empty body for now.
    let token = get_auth_header(&config, "POST", "/v1/leases", b"").await?;

    let client = authed_client();
    let response = with_auth(client.post(format!("{endpoint}/v1/leases")), &token)
        .header("Content-Type", "application/json")
        .body(body_bytes)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        let msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v["error"].as_str().map(|s| s.to_string()))
            .unwrap_or(text);
        anyhow::bail!("Failed to claim cluster (HTTP {status}): {msg}");
    }
    let body: serde_json::Value = response.json().await?;

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
