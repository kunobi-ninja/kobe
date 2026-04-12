use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

use super::{OutputFormat, print_json};

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
    /// SSH key signing (SSHSIG)
    Ssh,
}

impl std::fmt::Display for AuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMode::None => write!(f, "none"),
            AuthMode::Token => write!(f, "token"),
            AuthMode::Oidc => write!(f, "oidc"),
            AuthMode::Ssh => write!(f, "ssh"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KobeTarget {
    /// Kobe API endpoint.
    pub endpoint: String,

    /// Authentication mode.
    #[serde(default)]
    pub auth: AuthMode,

    /// Static bearer token (when auth = token).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// SSH key fingerprint (when auth = ssh). If None, first Ed25519 key is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub target: Option<String>,
    pub endpoint: String,
    pub auth: AuthMode,
    pub token: Option<String>,
    pub ssh_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigLegacyOutput<'a> {
    endpoint: Option<&'a str>,
    auth: &'a AuthMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_fingerprint: Option<&'a str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigTargetOutput<'a> {
    endpoint: &'a str,
    auth: &'a AuthMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_fingerprint: Option<&'a str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigViewOutput<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    current_target: Option<&'a str>,
    targets: BTreeMap<&'a str, ConfigTargetOutput<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    legacy: Option<ConfigLegacyOutput<'a>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigListEntry<'a> {
    name: &'a str,
    current: bool,
    endpoint: &'a str,
    auth: &'a AuthMode,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CurrentTargetOutput<'a> {
    name: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetMutationOutput<'a> {
    name: &'a str,
    current: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CliConfig {
    /// Current named target.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "current_context"
    )]
    pub current_target: Option<String>,

    /// Named endpoint/auth configurations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty", alias = "contexts")]
    pub targets: BTreeMap<String, KobeTarget>,

    /// Kobe API endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Authentication mode.
    #[serde(default, skip_serializing_if = "is_default_auth")]
    pub auth: AuthMode,

    /// Static bearer token (when auth = token).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// SSH key fingerprint (when auth = ssh). If None, first Ed25519 key is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_fingerprint: Option<String>,
}

const DEFAULT_ENDPOINT: &str = "https://kobe.kunobi.ninja";

fn is_default_auth(auth: &AuthMode) -> bool {
    auth == &AuthMode::default()
}

impl CliConfig {
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(&path)?;
        let mut config: Self = serde_json::from_str(&data)?;
        if config.migrate_legacy_to_default_target() {
            config.save()?;
        }
        Ok(config)
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

    fn migrate_legacy_to_default_target(&mut self) -> bool {
        if !self.targets.is_empty() || self.current_target.is_some() {
            return false;
        }

        let has_legacy = self.endpoint.is_some()
            || self.auth != AuthMode::default()
            || self.token.is_some()
            || self.ssh_fingerprint.is_some();

        if !has_legacy {
            return false;
        }

        self.targets.insert(
            "default".to_string(),
            KobeTarget {
                endpoint: self
                    .endpoint
                    .clone()
                    .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string()),
                auth: self.auth.clone(),
                token: self.token.clone(),
                ssh_fingerprint: self.ssh_fingerprint.clone(),
            },
        );
        self.current_target = Some("default".to_string());
        self.endpoint = None;
        self.auth = AuthMode::default();
        self.token = None;
        self.ssh_fingerprint = None;
        true
    }

    pub fn resolve(
        &self,
        target_override: Option<&str>,
        endpoint_override: Option<&str>,
    ) -> Result<ResolvedConfig> {
        let target_name = target_override.or(self.current_target.as_deref());

        if let Some(name) = target_name {
            let target = self.targets.get(name).ok_or_else(|| {
                anyhow::anyhow!("Unknown target '{name}'. Run: kobe config list")
            })?;

            return Ok(ResolvedConfig {
                target: Some(name.to_string()),
                endpoint: endpoint_override.unwrap_or(&target.endpoint).to_string(),
                auth: target.auth.clone(),
                token: target.token.clone(),
                ssh_fingerprint: target.ssh_fingerprint.clone(),
            });
        }

        Ok(ResolvedConfig {
            target: None,
            endpoint: endpoint_override
                .map(str::to_string)
                .unwrap_or_else(|| self.endpoint().to_string()),
            auth: self.auth.clone(),
            token: self.token.clone(),
            ssh_fingerprint: self.ssh_fingerprint.clone(),
        })
    }
}

fn config_path() -> Result<PathBuf> {
    let dir =
        dirs::config_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?;
    Ok(dir.join("kobe").join("config.json"))
}

/// Show current config.
pub async fn config_show(target_override: Option<&str>, output: OutputFormat) -> Result<()> {
    let config = CliConfig::load()?;
    match output {
        OutputFormat::Text => print_config(&config, target_override)?,
        OutputFormat::Json => print_json(&config_view_output(&config))?,
    }
    Ok(())
}

pub async fn config_set_target(
    name: &str,
    endpoint: &str,
    auth: Option<&str>,
    token: Option<&str>,
    ssh_fingerprint: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    let mut config = CliConfig::load()?;
    let auth = match auth {
        Some(auth) => parse_auth_mode(auth)?,
        None if token.is_some() => AuthMode::Token,
        None if ssh_fingerprint.is_some() => AuthMode::Ssh,
        None => AuthMode::Oidc,
    };

    if auth == AuthMode::Token && token.is_none() {
        anyhow::bail!("Token targets require --token <value>");
    }

    config.targets.insert(
        name.to_string(),
        KobeTarget {
            endpoint: endpoint.to_string(),
            auth,
            token: token.map(str::to_string),
            ssh_fingerprint: ssh_fingerprint.map(str::to_string),
        },
    );
    config.current_target = Some(name.to_string());
    config.save()?;

    match output {
        OutputFormat::Text => {
            println!("Set target {name}");
            println!("Current target: {name}");
        }
        OutputFormat::Json => print_json(&TargetMutationOutput {
            name,
            current: true,
        })?,
    }
    Ok(())
}

pub async fn config_use_target(name: &str, output: OutputFormat) -> Result<()> {
    let mut config = CliConfig::load()?;
    if !config.targets.contains_key(name) {
        anyhow::bail!("Unknown target '{name}'. Run: kobe config list");
    }
    config.current_target = Some(name.to_string());
    config.save()?;

    match output {
        OutputFormat::Text => println!("Current target: {name}"),
        OutputFormat::Json => print_json(&TargetMutationOutput {
            name,
            current: true,
        })?,
    }
    Ok(())
}

pub async fn config_current_target(output: OutputFormat) -> Result<()> {
    let config = CliConfig::load()?;
    let Some(current_target) = config.current_target else {
        anyhow::bail!("Current target is not set. Run: kobe config list");
    };

    if !config.targets.contains_key(&current_target) {
        anyhow::bail!(
            "Current target '{current_target}' does not exist. Run: kobe config list"
        );
    }

    match output {
        OutputFormat::Text => println!("{current_target}"),
        OutputFormat::Json => print_json(&CurrentTargetOutput {
            name: &current_target,
        })?,
    }
    Ok(())
}

pub async fn config_list_targets(output: OutputFormat) -> Result<()> {
    let config = CliConfig::load()?;
    match output {
        OutputFormat::Text => {
            if config.targets.is_empty() {
                println!("No targets configured.");
                return Ok(());
            }

            for (name, target) in &config.targets {
                let marker = if config.current_target.as_deref() == Some(name) {
                    "*"
                } else {
                    " "
                };
                println!("{marker} {name}  {}  auth={}", target.endpoint, target.auth);
            }
        }
        OutputFormat::Json => {
            let targets = config
                .targets
                .iter()
                .map(|(name, target)| ConfigListEntry {
                    name,
                    current: config.current_target.as_deref() == Some(name.as_str()),
                    endpoint: &target.endpoint,
                    auth: &target.auth,
                })
                .collect::<Vec<_>>();
            print_json(&targets)?;
        }
    }
    Ok(())
}

fn config_view_output<'a>(config: &'a CliConfig) -> ConfigViewOutput<'a> {
    ConfigViewOutput {
        current_target: config.current_target.as_deref(),
        targets: config
            .targets
            .iter()
            .map(|(name, target)| {
                (
                    name.as_str(),
                    ConfigTargetOutput {
                        endpoint: &target.endpoint,
                        auth: &target.auth,
                        token: target.token.as_deref(),
                        ssh_fingerprint: target.ssh_fingerprint.as_deref(),
                    },
                )
            })
            .collect(),
        legacy: legacy_output(config),
    }
}

fn legacy_output(config: &CliConfig) -> Option<ConfigLegacyOutput<'_>> {
    let has_legacy = config.endpoint.is_some()
        || config.auth != AuthMode::default()
        || config.token.is_some()
        || config.ssh_fingerprint.is_some();
    if !has_legacy {
        return None;
    }

    Some(ConfigLegacyOutput {
        endpoint: config.endpoint.as_deref(),
        auth: &config.auth,
        token: config.token.as_deref(),
        ssh_fingerprint: config.ssh_fingerprint.as_deref(),
    })
}

fn print_config(config: &CliConfig, target_override: Option<&str>) -> Result<()> {
    let resolved = config.resolve(target_override, None)?;
    if let Some(target) = &resolved.target {
        println!("target:   {target}");
    }
    println!("endpoint: {}", resolved.endpoint);
    print_auth(
        &resolved.auth,
        resolved.token.as_deref(),
        resolved.ssh_fingerprint.as_deref(),
    );

    if !config.targets.is_empty() {
        println!();
        println!("targets:");
        for (name, target) in &config.targets {
            let marker = if config.current_target.as_deref() == Some(name) {
                "*"
            } else {
                " "
            };
            println!(
                "  {marker} {name}  {}  auth={}",
                target.endpoint, target.auth
            );
        }
    }

    Ok(())
}

fn print_auth(auth: &AuthMode, token: Option<&str>, ssh_fingerprint: Option<&str>) {
    println!("auth:     {auth}");
    if auth == &AuthMode::Token {
        let masked = token
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
    if auth == &AuthMode::Ssh {
        let fp = ssh_fingerprint.unwrap_or("(not set — will use ~/.ssh/id_ed25519)");
        println!("ssh-fingerprint: {fp}");
    }
}

pub fn parse_auth_mode(value: &str) -> Result<AuthMode> {
    match value {
        "none" => Ok(AuthMode::None),
        "token" => Ok(AuthMode::Token),
        "oidc" => Ok(AuthMode::Oidc),
        "ssh" => Ok(AuthMode::Ssh),
        _ => anyhow::bail!("Invalid auth mode: {value}. Valid: none, token, oidc, ssh"),
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthMode, CliConfig};

    #[test]
    fn migrates_legacy_flat_config_into_default_target() {
        let mut config = CliConfig {
            endpoint: Some("https://example.test".to_string()),
            auth: AuthMode::Ssh,
            token: None,
            ssh_fingerprint: Some("SHA256:test".to_string()),
            ..CliConfig::default()
        };

        assert!(config.migrate_legacy_to_default_target());
        assert_eq!(config.current_target.as_deref(), Some("default"));
        let target = config.targets.get("default").expect("default target");
        assert_eq!(target.endpoint, "https://example.test");
        assert_eq!(target.auth, AuthMode::Ssh);
        assert_eq!(target.ssh_fingerprint.as_deref(), Some("SHA256:test"));
        assert!(config.endpoint.is_none());
        assert_eq!(config.auth, AuthMode::Oidc);
        assert!(config.token.is_none());
        assert!(config.ssh_fingerprint.is_none());
    }

    #[test]
    fn does_not_migrate_when_targets_already_exist() {
        let mut config = CliConfig::default();
        config.targets.insert(
            "prod".to_string(),
            super::KobeTarget {
                endpoint: "https://prod.example.test".to_string(),
                auth: AuthMode::Oidc,
                token: None,
                ssh_fingerprint: None,
            },
        );
        config.endpoint = Some("https://legacy.example.test".to_string());

        assert!(!config.migrate_legacy_to_default_target());
        assert!(config.targets.contains_key("prod"));
        assert_eq!(
            config.endpoint.as_deref(),
            Some("https://legacy.example.test")
        );
    }
}
