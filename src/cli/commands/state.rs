use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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

pub(crate) fn resolve_kubeconfig_path(endpoint: &str, lease_id: &str) -> Option<String> {
    if let Ok(state) = CliState::load() {
        if let Some(artifact) = state.lease_artifacts.get(&lease_key(endpoint, lease_id)) {
            if Path::new(&artifact.kubeconfig_path).exists() {
                return Some(artifact.kubeconfig_path.clone());
            }
        }
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
