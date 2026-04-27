use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Serialize, Deserialize)]
struct CliState {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    lease_artifacts: BTreeMap<String, LeaseArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeaseArtifact {
    kubeconfig_path: String,
}

impl CliState {
    fn load() -> Result<Self> {
        let path = state_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&data)?)
    }

    fn save(&self) -> Result<()> {
        let path = state_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

pub(crate) fn record_kubeconfig(endpoint: &str, lease_id: &str, path: &Path) -> Result<()> {
    let mut state = CliState::load()?;
    state.lease_artifacts.insert(
        lease_key(endpoint, lease_id),
        LeaseArtifact {
            kubeconfig_path: path.display().to_string(),
        },
    );
    state.save()
}

pub(crate) fn forget_kubeconfig(endpoint: &str, lease_id: &str) -> Result<()> {
    let mut state = CliState::load()?;
    if state
        .lease_artifacts
        .remove(&lease_key(endpoint, lease_id))
        .is_some()
    {
        state.save()?;
    }
    Ok(())
}

pub(crate) fn remove_kubeconfig(endpoint: &str, lease_id: &str) -> Result<Option<PathBuf>> {
    let recorded = if let Ok(state) = CliState::load() {
        state
            .lease_artifacts
            .get(&lease_key(endpoint, lease_id))
            .map(|artifact| PathBuf::from(&artifact.kubeconfig_path))
    } else {
        None
    };

    forget_kubeconfig(endpoint, lease_id)?;

    let path = recorded.unwrap_or_else(|| default_kubeconfig_path(lease_id));
    if path.exists() {
        std::fs::remove_file(&path)?;
        return Ok(Some(path));
    }

    Ok(None)
}

pub(crate) fn endpoint_kubeconfigs(endpoint: &str) -> Result<Vec<PathBuf>> {
    let state = CliState::load()?;
    let prefix = format!("{endpoint}::");
    Ok(state
        .lease_artifacts
        .iter()
        .filter(|(key, _)| key.starts_with(&prefix))
        .map(|(_, artifact)| PathBuf::from(&artifact.kubeconfig_path))
        .collect())
}

/// State-tracked kubeconfigs whose lease is not in the supplied active set.
///
/// Conservative: only considers entries we recorded ourselves (`record_kubeconfig`).
/// Freestanding `~/.kube/kobe-*.yaml` files we never tracked are left alone — we
/// cannot prove they correspond to an expired lease without parsing the filename
/// and risking a false positive on an unrelated user-managed file.
pub(crate) fn find_orphan_kubeconfigs(
    endpoint: &str,
    active_lease_ids: &BTreeSet<String>,
) -> Result<Vec<OrphanKubeconfig>> {
    let state = CliState::load()?;
    let prefix = format!("{endpoint}::");
    let mut orphans = Vec::new();
    for (key, artifact) in &state.lease_artifacts {
        let Some(lease_id) = key.strip_prefix(&prefix) else {
            continue;
        };
        if active_lease_ids.contains(lease_id) {
            continue;
        }
        let path = PathBuf::from(&artifact.kubeconfig_path);
        if !path.exists() {
            continue;
        }
        orphans.push(OrphanKubeconfig {
            lease_id: lease_id.to_string(),
            path,
        });
    }
    Ok(orphans)
}

#[derive(Debug, Clone)]
pub(crate) struct OrphanKubeconfig {
    pub lease_id: String,
    pub path: PathBuf,
}

pub(crate) fn forget_endpoint_kubeconfigs(endpoint: &str) -> Result<()> {
    let mut state = CliState::load()?;
    let prefix = format!("{endpoint}::");
    state
        .lease_artifacts
        .retain(|key, _| !key.starts_with(&prefix));
    state.save()?;
    Ok(())
}

pub(crate) fn local_kubeconfig_candidates() -> Result<Vec<PathBuf>> {
    let kube_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".kube");
    if !kube_dir.exists() {
        return Ok(Vec::new());
    }

    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(&kube_dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        let is_current_style = name.starts_with("kobe-") && name.ends_with(".yaml");
        let is_legacy_style = name.starts_with("kobe-lease-");
        if !(is_current_style || is_legacy_style) {
            continue;
        }
        candidates.push(path);
    }

    Ok(candidates)
}

pub(crate) fn resolve_kubeconfig_path(endpoint: &str, lease_id: &str) -> Option<String> {
    if let Ok(state) = CliState::load()
        && let Some(artifact) = state.lease_artifacts.get(&lease_key(endpoint, lease_id))
        && Path::new(&artifact.kubeconfig_path).exists()
    {
        return Some(artifact.kubeconfig_path.clone());
    }

    let default = default_kubeconfig_path(lease_id);
    if default.exists() {
        return Some(default.display().to_string());
    }

    None
}

pub(crate) fn default_kubeconfig_path(lease_id: &str) -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".kube")
        .join(format!("kobe-{lease_id}"))
}

fn lease_key(endpoint: &str, lease_id: &str) -> String {
    format!("{endpoint}::{lease_id}")
}

fn state_path() -> Result<PathBuf> {
    let dir =
        dirs::config_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?;
    Ok(dir.join("kobe").join("state.json"))
}
