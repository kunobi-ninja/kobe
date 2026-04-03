use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Authentication mode.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// No authentication (local dev / port-forward)
    None,
    /// Static bearer token
    Token,
    /// OIDC browser login (default)
    #[default]
    Oidc,
}

impl std::fmt::Display for AuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMode::None => write!(f, "none"),
            AuthMode::Token => write!(f, "token"),
            AuthMode::Oidc => write!(f, "oidc"),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CliConfig {
    /// Kobe API endpoint.
    #[serde(default)]
    pub endpoint: Option<String>,

    /// Authentication mode.
    #[serde(default)]
    pub auth: AuthMode,

    /// Static bearer token (when auth = token).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

const DEFAULT_ENDPOINT: &str = "https://kobe.kunobi.ninja";

impl CliConfig {
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&data)?)
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path()?;
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

    pub fn endpoint(&self) -> &str {
        self.endpoint.as_deref().unwrap_or(DEFAULT_ENDPOINT)
    }
}

fn config_path() -> Result<PathBuf> {
    let dir =
        dirs::config_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?;
    Ok(dir.join("kobe").join("config.json"))
}

/// Set a config value via CLI.
pub async fn config_set(key: &str, value: &str) -> Result<()> {
    let mut config = CliConfig::load()?;
    match key {
        "endpoint" => config.endpoint = Some(value.to_string()),
        "auth" => {
            config.auth = match value {
                "none" => AuthMode::None,
                "token" => AuthMode::Token,
                "oidc" => AuthMode::Oidc,
                _ => anyhow::bail!("Invalid auth mode: {value}. Valid: none, token, oidc"),
            }
        }
        "token" => {
            config.token = Some(value.to_string());
            config.auth = AuthMode::Token;
        }
        _ => anyhow::bail!("Unknown key: {key}. Valid: endpoint, auth, token"),
    }
    config.save()?;
    println!("Set {key} = {value}");
    Ok(())
}

/// Show current config.
pub async fn config_show() -> Result<()> {
    let config = CliConfig::load()?;
    print_config(&config);
    Ok(())
}

fn print_config(config: &CliConfig) {
    println!("endpoint: {}", config.endpoint());
    println!("auth:     {}", config.auth);
    if config.auth == AuthMode::Token {
        let masked = config
            .token
            .as_deref()
            .map(|t| {
                if t.len() > 8 {
                    format!("{}...{}", &t[..4], &t[t.len() - 4..])
                } else {
                    "****".to_string()
                }
            })
            .unwrap_or_else(|| "(not set)".to_string());
        println!("token:    {masked}");
    }
}
