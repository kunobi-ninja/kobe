//! Maintains the `kobe-system/kobe-live-instances` ConfigMap containing
//! one newline-delimited `ClusterInstance.metadata.name` per line.
//!
//! Consumed by the `kobe-host-reaper` DaemonSet via a mounted ConfigMap
//! volume to decide which lease-root subdirectories are stale.
//!
//! Runs only on the elected leader (see `src/main.rs` leader_election).

use anyhow::Result;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::{Client, api::Api};
use std::collections::BTreeSet;
use tracing::debug;

pub const CONFIGMAP_NAME: &str = "kobe-live-instances";
pub const CONFIGMAP_KEY: &str = "instances";
pub const UPDATED_AT_ANNOTATION: &str = "kobe.kunobi.ninja/updated-at";

pub fn render_instances(names: &BTreeSet<String>) -> String {
    names.iter().cloned().collect::<Vec<_>>().join("\n")
}

pub async fn write_live_set(
    cms: &Api<ConfigMap>,
    namespace: &str,
    names: &BTreeSet<String>,
    now_rfc3339: &str,
) -> Result<()> {
    use kube::api::{Patch, PatchParams};
    use serde_json::json;

    let body = json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": CONFIGMAP_NAME,
            "namespace": namespace,
            "annotations": { UPDATED_AT_ANNOTATION: now_rfc3339 }
        },
        "data": { CONFIGMAP_KEY: render_instances(names) }
    });
    let pp = PatchParams::apply("kobe-operator").force();
    cms.patch(CONFIGMAP_NAME, &pp, &Patch::Apply(&body)).await?;
    debug!(count = names.len(), "wrote kobe-live-instances ConfigMap");
    Ok(())
}

use crate::crd::ClusterInstance;
use futures::FutureExt;
use futures::StreamExt;
use kube::runtime::watcher::{Config, watcher};
use tokio::sync::Notify;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Run the live-set reconciler until the cancellation token fires.
/// Caller is responsible for ensuring this only runs on the leader.
pub async fn run_live_set_controller(client: Client, namespace: &str, shutdown: CancellationToken) {
    info!("Starting live-set controller (writes kobe-live-instances CM)");
    let cms: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let cis: Api<ClusterInstance> = Api::all(client.clone());

    if let Err(e) = relist_and_write(&cis, &cms, namespace).await {
        warn!(error = %e, "initial live-set write failed; will retry from watch loop");
    }

    let notify = std::sync::Arc::new(Notify::new());
    let notify_clone = notify.clone();
    let cis_clone = cis.clone();

    let watch_shutdown = shutdown.clone();
    let watch_handle = tokio::spawn(async move {
        let mut stream = Box::pin(watcher(cis_clone, Config::default()));
        loop {
            tokio::select! {
                _ = watch_shutdown.cancelled() => break,
                ev = stream.next() => match ev {
                    Some(Ok(_)) => {
                        notify_clone.notify_one();
                    }
                    Some(Err(e)) => warn!(error = %e, "live_set watch error"),
                    None => break,
                }
            }
        }
    });

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = notify.notified() => {
                sleep(Duration::from_secs(1)).await;
                while notify.notified().now_or_never().is_some() {}
                if let Err(e) = relist_and_write(&cis, &cms, namespace).await {
                    warn!(error = %e, "live-set write failed (will retry on next event)");
                }
            }
        }
    }

    watch_handle.abort();
    info!("live-set controller stopped");
}

async fn relist_and_write(
    cis: &Api<ClusterInstance>,
    cms: &Api<ConfigMap>,
    namespace: &str,
) -> Result<()> {
    use kube::api::ListParams;
    let list = cis.list(&ListParams::default()).await?;
    let mut names = BTreeSet::new();
    for ci in list.items {
        if let Some(n) = ci.metadata.name {
            names.insert(n);
        }
    }
    let now = chrono::Utc::now().to_rfc3339();
    write_live_set(cms, namespace, &names, &now).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_instances_sorted_newline_delimited_no_trailing() {
        let mut s = BTreeSet::new();
        s.insert("b".into());
        s.insert("a".into());
        s.insert("c".into());
        assert_eq!(render_instances(&s), "a\nb\nc");
    }

    #[test]
    fn render_instances_empty_is_empty_string() {
        let s = BTreeSet::new();
        assert_eq!(render_instances(&s), "");
    }

    #[test]
    fn render_instances_single_no_newline() {
        let mut s = BTreeSet::new();
        s.insert("only".into());
        assert_eq!(render_instances(&s), "only");
    }
}
