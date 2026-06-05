//! `kobe with-lease` (#107 P3) — run a command while holding a lease, releasing
//! it on exit (success, failure, or signal). The lease is heartbeat-extended for
//! the command's lifetime so a long task never races its own TTL deadline.

use std::path::PathBuf;

use anyhow::{Context, Result};
use tokio::sync::oneshot;

use super::OutputFormat;
use super::config::{CliConfig, ResolvedConfig};
use super::keepalive::heartbeat_until;
use super::lease_create::{create_lease_request, wait_for_usable_lease};
use super::release::release_lease;

pub struct WithLeaseCommand<'a> {
    pub pool: Option<&'a str>,
    pub ttl: &'a str,
    pub cmd: &'a [String],
    pub target_override: Option<&'a str>,
    pub endpoint_override: Option<&'a str>,
    pub output: OutputFormat,
}

/// Removes a file on drop — guarantees the ephemeral kubeconfig is cleaned up
/// even on an early return or panic.
struct TempFile(PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub async fn with_lease(command: WithLeaseCommand<'_>) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(command.target_override, command.endpoint_override)?;
    let verbose = command.output == OutputFormat::Text;

    // with-lease is non-interactive (it wraps a command), so the pool must be
    // explicit rather than prompted.
    let pool = command
        .pool
        .context("with-lease requires a pool: kobe with-lease <pool> --ttl 1h -- <cmd>")?;
    if command.cmd.is_empty() {
        anyhow::bail!("with-lease requires a command after `--`");
    }

    if verbose {
        eprintln!("Leasing '{pool}' for the wrapped command...");
    }
    let accepted = create_lease_request(&config, pool, command.ttl, None).await?;
    let lease_id = accepted.id.clone();

    // Everything past creation must release the lease, even on error.
    let outcome = run_wrapped(
        &config,
        &lease_id,
        accepted.effective_ttl.clone(),
        command.ttl,
        command.cmd,
        verbose,
    )
    .await;

    if let Err(e) = release_lease(&config, &lease_id).await {
        eprintln!("Warning: failed to release lease {lease_id}: {e}");
    } else if verbose {
        eprintln!("Released lease {lease_id}");
    }

    outcome
}

async fn run_wrapped(
    config: &ResolvedConfig,
    lease_id: &str,
    effective_ttl: Option<String>,
    ttl: &str,
    cmd: &[String],
    verbose: bool,
) -> Result<()> {
    let ready = wait_for_usable_lease(config, lease_id, effective_ttl, None).await?;
    let kubeconfig = ready
        .kubeconfig
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Lease {lease_id} became bound without kubeconfig"))?;

    // Ephemeral kubeconfig in the temp dir, not the standard ~/.kube path — it
    // lives only for the wrapped command.
    let kpath = std::env::temp_dir().join(format!("kobe-{lease_id}.yaml"));
    std::fs::write(&kpath, kubeconfig)
        .with_context(|| format!("writing kubeconfig to {}", kpath.display()))?;
    let _tmp = TempFile(kpath.clone());

    if verbose {
        eprintln!(
            "Running `{}` with KUBECONFIG={}",
            cmd.join(" "),
            kpath.display()
        );
    }

    let mut child = tokio::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .env("KUBECONFIG", &kpath)
        .spawn()
        .with_context(|| format!("failed to spawn '{}'", cmd[0]))?;

    // Heartbeat-extend in the background until the child exits.
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let hb = tokio::spawn({
        let config = config.clone();
        let lease_id = lease_id.to_string();
        let ttl = ttl.to_string();
        async move {
            let stop = async {
                let _ = stop_rx.await;
            };
            let _ = heartbeat_until(&config, &lease_id, &ttl, stop, verbose).await;
        }
    });

    let status = child.wait().await.context("waiting for wrapped command")?;
    let _ = stop_tx.send(());
    let _ = hb.await;

    if !status.success() {
        // Surface non-zero exit as an error so `kobe with-lease` itself fails
        // (after releasing the lease above).
        anyhow::bail!("command exited with status {}", status.code().unwrap_or(1));
    }
    Ok(())
}
