use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
pub struct KobeContext {
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
    pub context: Option<String>,
    pub endpoint: String,
    pub auth: AuthMode,
    pub token: Option<String>,
    pub ssh_fingerprint: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CliConfig {
    /// Current named context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_context: Option<String>,

    /// Named endpoint/auth configurations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub contexts: BTreeMap<String, KobeContext>,

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

    pub fn resolve(
        &self,
        context_override: Option<&str>,
        endpoint_override: Option<&str>,
    ) -> Result<ResolvedConfig> {
        let context_name = context_override.or(self.current_context.as_deref());

        if let Some(name) = context_name {
            let context = self.contexts.get(name).ok_or_else(|| {
                anyhow::anyhow!("Unknown context '{name}'. Run: kobe config get-contexts")
            })?;

            return Ok(ResolvedConfig {
                context: Some(name.to_string()),
                endpoint: endpoint_override.unwrap_or(&context.endpoint).to_string(),
                auth: context.auth.clone(),
                token: context.token.clone(),
                ssh_fingerprint: context.ssh_fingerprint.clone(),
            });
        }

        Ok(ResolvedConfig {
            context: None,
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

/// Set a config value via CLI.
pub async fn config_set(key: &str, value: &str) -> Result<()> {
    let mut config = CliConfig::load()?;
    if let Some(current_context) = config.current_context.clone() {
        if let Some(context) = config.contexts.get_mut(&current_context) {
            match key {
                "endpoint" => context.endpoint = value.to_string(),
                "auth" => {
                    context.auth = parse_auth_mode(value)?;
                }
                "token" => {
                    context.token = Some(value.to_string());
                    context.auth = AuthMode::Token;
                }
                "ssh-fingerprint" => {
                    context.ssh_fingerprint = Some(value.to_string());
                    context.auth = AuthMode::Ssh;
                }
                _ => anyhow::bail!(
                    "Unknown key: {key}. Valid: endpoint, auth, token, ssh-fingerprint"
                ),
            }
            config.save()?;
            println!("Set {key} for context {current_context} = {value}");
            return Ok(());
        }
    }

    match key {
        "endpoint" => config.endpoint = Some(value.to_string()),
        "auth" => {
            config.auth = parse_auth_mode(value)?;
        }
        "token" => {
            config.token = Some(value.to_string());
            config.auth = AuthMode::Token;
        }
        "ssh-fingerprint" => {
            config.ssh_fingerprint = Some(value.to_string());
            config.auth = AuthMode::Ssh;
        }
        _ => anyhow::bail!("Unknown key: {key}. Valid: endpoint, auth, token, ssh-fingerprint"),
    }
    config.save()?;
    println!("Set {key} = {value}");
    Ok(())
}

/// Show current config.
pub async fn config_show(context_override: Option<&str>) -> Result<()> {
    let config = CliConfig::load()?;
    print_config(&config, context_override)?;
    Ok(())
}

pub async fn config_set_context(
    name: &str,
    endpoint: &str,
    auth: Option<&str>,
    token: Option<&str>,
    ssh_fingerprint: Option<&str>,
) -> Result<()> {
    let mut config = CliConfig::load()?;
    let auth = match auth {
        Some(auth) => parse_auth_mode(auth)?,
        None if token.is_some() => AuthMode::Token,
        None if ssh_fingerprint.is_some() => AuthMode::Ssh,
        None => AuthMode::Oidc,
    };

    if auth == AuthMode::Token && token.is_none() {
        anyhow::bail!("Token contexts require --token <value>");
    }

    config.contexts.insert(
        name.to_string(),
        KobeContext {
            endpoint: endpoint.to_string(),
            auth,
            token: token.map(str::to_string),
            ssh_fingerprint: ssh_fingerprint.map(str::to_string),
        },
    );
    config.current_context = Some(name.to_string());
    config.save()?;

    println!("Set context {name}");
    println!("Current context: {name}");
    Ok(())
}

pub async fn config_use_context(name: &str) -> Result<()> {
    let mut config = CliConfig::load()?;
    if !config.contexts.contains_key(name) {
        anyhow::bail!("Unknown context '{name}'. Run: kobe config get-contexts");
    }
    config.current_context = Some(name.to_string());
    config.save()?;

    println!("Current context: {name}");
    Ok(())
}

pub async fn config_current_context() -> Result<()> {
    let config = CliConfig::load()?;
    let Some(current_context) = config.current_context else {
        anyhow::bail!("Current context is not set. Run: kobe config get-contexts");
    };

    if !config.contexts.contains_key(&current_context) {
        anyhow::bail!(
            "Current context '{current_context}' does not exist. Run: kobe config get-contexts"
        );
    }

    println!("{current_context}");
    Ok(())
}

pub async fn config_contexts() -> Result<()> {
    let config = CliConfig::load()?;
    if config.contexts.is_empty() {
        println!("No contexts configured.");
        return Ok(());
    }

    for (name, context) in &config.contexts {
        let marker = if config.current_context.as_deref() == Some(name) {
            "*"
        } else {
            " "
        };
        println!(
            "{marker} {name}  {}  auth={}",
            context.endpoint, context.auth
        );
    }
    Ok(())
}

fn print_config(config: &CliConfig, context_override: Option<&str>) -> Result<()> {
    let resolved = config.resolve(context_override, None)?;
    if let Some(context) = &resolved.context {
        println!("context:  {context}");
    }
    println!("endpoint: {}", resolved.endpoint);
    print_auth(
        &resolved.auth,
        resolved.token.as_deref(),
        resolved.ssh_fingerprint.as_deref(),
    );

    if !config.contexts.is_empty() {
        println!();
        println!("contexts:");
        for (name, context) in &config.contexts {
            let marker = if config.current_context.as_deref() == Some(name) {
                "*"
            } else {
                " "
            };
            println!(
                "  {marker} {name}  {}  auth={}",
                context.endpoint, context.auth
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
