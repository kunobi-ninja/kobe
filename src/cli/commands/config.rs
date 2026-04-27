use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;

use super::session;
use super::{OutputFormat, print_json};

/// Where a target definition lives. Computed during `CliConfig::load`
/// based on which file each target appears in. Not serialized — pure
/// runtime metadata for `kobe config list` / `current` UX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Defined only in the global config (`~/.config/kobe/config.json`).
    Global,
    /// Defined only in the local project config (`./.kobe.toml`).
    Local,
    /// Defined in BOTH global and local. The local definition wins
    /// when resolving (overlay order). `kobe config list` flags these
    /// so users see the conflict instead of being silently surprised.
    Both,
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scope::Global => write!(f, "global"),
            Scope::Local => write!(f, "local"),
            Scope::Both => write!(f, "both"),
        }
    }
}

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
struct ConfigLegacyOutput {
    endpoint: Option<String>,
    auth: AuthMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigTargetOutput {
    endpoint: String,
    auth: AuthMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigViewOutput {
    path: String,
    exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved: Option<ResolvedConfigOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_target: Option<String>,
    targets: BTreeMap<String, ConfigTargetOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    legacy: Option<ConfigLegacyOutput>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResolvedConfigOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    endpoint: String,
    auth: AuthMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigListEntry<'a> {
    name: &'a str,
    current: bool,
    endpoint: &'a str,
    auth: &'a AuthMode,
    /// Where this target is defined (global / local / both). Pre-1.0
    /// shape — clients that parse this JSON should expect the field to
    /// be present from v0.12 onward.
    scope: Scope,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TargetMutationOutput<'a> {
    name: &'a str,
    current: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CliConfig {
    /// Current named target. **Legacy** — historically lived alongside
    /// the targets map; today the per-shell session file is the source
    /// of truth (see `session.rs`). We still parse this field for
    /// backward compat with old configs and the `kobe config import`
    /// payload, but writes go to the session file instead.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "current_context"
    )]
    pub current_target: Option<String>,

    /// Named endpoint/auth configurations.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        alias = "contexts"
    )]
    pub targets: BTreeMap<String, KobeTarget>,

    /// Per-target scope (Global/Local/Both). Populated during
    /// `load()` and used by `config list` / `config current`. Not
    /// serialized — pure runtime metadata.
    #[serde(skip)]
    pub target_scopes: BTreeMap<String, Scope>,

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

fn is_default_auth(auth: &AuthMode) -> bool {
    auth == &AuthMode::default()
}

impl CliConfig {
    pub fn load() -> Result<Self> {
        let mut config = Self::load_global()?;
        // Tag every target seen in the global file as Global. The
        // overlay step below promotes any name that ALSO appears in
        // local to `Both`.
        for name in config.targets.keys() {
            config.target_scopes.insert(name.clone(), Scope::Global);
        }
        if let Some(local) = Self::load_local()? {
            config.overlay(local);
        }
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let path = global_config_path()?;
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

    pub(crate) fn load_global() -> Result<Self> {
        let path = global_config_path()?;
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

    fn load_local() -> Result<Option<Self>> {
        let Some(path) = local_config_path()? else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(&path)?;
        let mut config: Self = toml::from_str(&data)?;
        config.migrate_legacy_to_default_target();
        Ok(Some(config))
    }

    fn overlay(&mut self, local: Self) {
        if local.current_target.is_some() {
            self.current_target = local.current_target;
        }

        for (name, target) in local.targets {
            // Scope bookkeeping: anything that was already Global
            // becomes Both; anything new is Local.
            let scope = match self.target_scopes.get(&name) {
                Some(Scope::Global) => Scope::Both,
                _ => Scope::Local,
            };
            self.target_scopes.insert(name.clone(), scope);
            self.targets.insert(name, target);
        }

        if local.endpoint.is_some() {
            self.endpoint = local.endpoint;
        }
        if local.auth != AuthMode::default() {
            self.auth = local.auth;
        }
        if local.token.is_some() {
            self.token = local.token;
        }
        if local.ssh_fingerprint.is_some() {
            self.ssh_fingerprint = local.ssh_fingerprint;
        }
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
                endpoint: match self.endpoint.clone() {
                    Some(endpoint) => endpoint,
                    None => return false,
                },
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

    /// Resolve the active target for the current invocation.
    ///
    /// Priority order:
    ///
    /// 1. `--target <name>` flag (one-shot, no persistence).
    /// 2. **Per-shell session file** at `<cache>/sessions/<ppid>.json`
    ///    (set by `kobe config use <name>`). Different terminal
    ///    windows resolve independently because their parent shells
    ///    have distinct PIDs. See `session.rs`.
    /// 3. Legacy `current_target` field in the config file (kept for
    ///    backward compat with configs from before per-shell sessions
    ///    existed and with `kobe config import` payloads).
    /// 4. Legacy flat `endpoint` (pre-targets configs).
    ///
    /// `endpoint_override` lets `kobe -e https://...` flag short-circuit
    /// the endpoint without touching auth (auth still comes from the
    /// resolved target).
    pub fn resolve(
        &self,
        target_override: Option<&str>,
        endpoint_override: Option<&str>,
    ) -> Result<ResolvedConfig> {
        let session_target = session::load()
            .ok()
            .and_then(|opt| opt.map(|(state, _, _)| state.current_target));

        if let Some(endpoint) = endpoint_override {
            let target_name = target_override
                .map(|s| s.to_string())
                .or_else(|| session_target.clone())
                .or_else(|| self.current_target.clone());
            if let Some(name) = target_name {
                let target = self.targets.get(&name).ok_or_else(|| {
                    anyhow::anyhow!("Unknown target '{name}'. Run: kobe config list")
                })?;
                return Ok(ResolvedConfig {
                    target: Some(name),
                    endpoint: endpoint.to_string(),
                    auth: target.auth.clone(),
                    token: target.token.clone(),
                    ssh_fingerprint: target.ssh_fingerprint.clone(),
                });
            }

            return Ok(ResolvedConfig {
                target: None,
                endpoint: endpoint.to_string(),
                auth: self.auth.clone(),
                token: self.token.clone(),
                ssh_fingerprint: self.ssh_fingerprint.clone(),
            });
        }

        let target_name = target_override
            .map(|s| s.to_string())
            .or(session_target)
            .or_else(|| self.current_target.clone());

        if let Some(name) = target_name {
            let target = self
                .targets
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("Unknown target '{name}'. Run: kobe config list"))?;

            return Ok(ResolvedConfig {
                target: Some(name),
                endpoint: endpoint_override.unwrap_or(&target.endpoint).to_string(),
                auth: target.auth.clone(),
                token: target.token.clone(),
                ssh_fingerprint: target.ssh_fingerprint.clone(),
            });
        }

        if let Some(endpoint) = self.endpoint.as_deref() {
            return Ok(ResolvedConfig {
                target: None,
                endpoint: endpoint.to_string(),
                auth: self.auth.clone(),
                token: self.token.clone(),
                ssh_fingerprint: self.ssh_fingerprint.clone(),
            });
        }

        if !self.targets.is_empty() {
            anyhow::bail!(
                "No current target configured for this shell. \
                 Run: kobe config use <name> (active for this terminal only) \
                 or pass --target <name>. \
                 Available targets: kobe config list."
            );
        }

        anyhow::bail!(
            "No endpoint configured. Run: kobe config set <name> --endpoint <url> ..., use kobe config import, or pass --endpoint <url>"
        )
    }
}

fn global_config_path() -> Result<PathBuf> {
    let dir =
        dirs::config_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?;
    Ok(dir.join("kobe").join("config.json"))
}

fn local_config_path() -> Result<Option<PathBuf>> {
    let cwd = std::env::current_dir()
        .map_err(|e| anyhow::anyhow!("Cannot determine current directory: {e}"))?;
    Ok(Some(cwd.join(".kobe.toml")))
}

/// Show current config.
pub async fn config_show(target_override: Option<&str>, output: OutputFormat) -> Result<()> {
    let config = CliConfig::load()?;
    match output {
        OutputFormat::Text => print_config(&config, target_override)?,
        OutputFormat::Json => print_json(&config_view_output(&config, target_override))?,
    }
    Ok(())
}

pub async fn config_export(path: Option<&str>, output: OutputFormat) -> Result<()> {
    let config = CliConfig::load()?;
    let serialized = serde_json::to_string_pretty(&config)?;

    match path {
        Some("-") => {
            println!("{serialized}");
        }
        Some(path) => {
            std::fs::write(path, format!("{serialized}\n"))?;
            match output {
                OutputFormat::Text => println!("Exported config to {path}"),
                OutputFormat::Json => print_json(&serde_json::json!({ "path": path }))?,
            }
        }
        None => match output {
            OutputFormat::Text => println!("{serialized}"),
            OutputFormat::Json => print_json(&config_view_output(&config, None))?,
        },
    }

    Ok(())
}

pub async fn config_import(path: Option<&str>, output: OutputFormat) -> Result<()> {
    let source = path.unwrap_or("-");
    let mut input = String::new();

    if source == "-" {
        std::io::stdin().read_to_string(&mut input)?;
    } else {
        input = std::fs::read_to_string(source)?;
    }

    let mut config: CliConfig = serde_json::from_str(&input)?;
    if let Some(current) = config.current_target.as_deref()
        && !config.targets.contains_key(current)
    {
        anyhow::bail!("Imported config references unknown current_target '{current}'");
    }
    if config.migrate_legacy_to_default_target() {
        // Preserve migration behavior for older exported configs.
    }
    config.save()?;

    match output {
        OutputFormat::Text => println!("Imported config into {}", global_config_path()?.display()),
        OutputFormat::Json => print_json(&config_view_output(&config, None))?,
    }

    Ok(())
}

/// Define or update a target.
///
/// By default writes to **local** `./.kobe.toml` so the definition
/// follows the project (and can be committed to the repo if the
/// endpoint is non-secret). Pass `global = true` to write to the
/// global library at `~/.config/kobe/config.json` instead — useful for
/// endpoints you reuse across many projects.
///
/// Does NOT touch the active-target session file. Defining a target
/// and switching to it are separate operations; run `kobe config use
/// <name>` afterwards to make it active for this shell.
pub async fn config_set_target(
    name: &str,
    endpoint: &str,
    auth: Option<&str>,
    token: Option<&str>,
    ssh_fingerprint: Option<&str>,
    global: bool,
    output: OutputFormat,
) -> Result<()> {
    let auth = match auth {
        Some(auth) => parse_auth_mode(auth)?,
        None if token.is_some() => AuthMode::Token,
        None if ssh_fingerprint.is_some() => AuthMode::Ssh,
        None => AuthMode::Oidc,
    };

    if auth == AuthMode::Token && token.is_none() {
        anyhow::bail!("Token targets require --token <value>");
    }

    let target = KobeTarget {
        endpoint: endpoint.to_string(),
        auth,
        token: token.map(str::to_string),
        ssh_fingerprint: ssh_fingerprint.map(str::to_string),
    };

    let written_path = if global {
        let mut config = CliConfig::load_global()?;
        config.targets.insert(name.to_string(), target);
        config.save()?;
        global_config_path()?
    } else {
        write_target_to_local(name, target)?
    };

    match output {
        OutputFormat::Text => {
            println!("Set target {name}");
            println!("Wrote: {}", written_path.display());
            println!("(use this target now: kobe config use {name})");
        }
        OutputFormat::Json => print_json(&TargetMutationOutput {
            name,
            current: false,
        })?,
    }
    Ok(())
}

/// Insert/update a target in the local `./.kobe.toml`, creating the
/// file if it doesn't exist. Returns the absolute path written.
fn write_target_to_local(name: &str, target: KobeTarget) -> Result<PathBuf> {
    let path = local_config_path()?
        .ok_or_else(|| anyhow::anyhow!("Cannot determine current directory for .kobe.toml"))?;

    let mut local: CliConfig = if path.exists() {
        let raw = std::fs::read_to_string(&path)?;
        toml::from_str(&raw)?
    } else {
        CliConfig::default()
    };

    local.targets.insert(name.to_string(), target);

    let toml_str = toml::to_string_pretty(&local)?;
    std::fs::write(&path, toml_str)
        .map_err(|e| anyhow::anyhow!("Failed to write {}: {e}", path.display()))?;
    Ok(path)
}

/// Make `<name>` the active target for **this terminal window only**.
///
/// Writes the choice to `<cache>/sessions/<ppid>.json`, keyed by the
/// parent shell's PID. Other windows have different parent PIDs and
/// keep whatever they had. The session file is reaped automatically
/// when the parent shell exits (see `session::gc_dead_sessions`).
///
/// Validates that the target exists in the merged config (global +
/// local) before writing.
pub async fn config_use_target(name: &str, output: OutputFormat) -> Result<()> {
    let config = CliConfig::load()?;
    if !config.targets.contains_key(name) {
        anyhow::bail!(
            "Unknown target '{name}'. Run: kobe config list (or define one with: kobe config set {name} --endpoint <url>)"
        );
    }

    let saved_path = session::save(&session::SessionState {
        current_target: name.to_string(),
    })?;

    match output {
        OutputFormat::Text => {
            println!("Active target for this shell: {name}");
            println!("State: {}", saved_path.display());
        }
        OutputFormat::Json => print_json(&TargetMutationOutput {
            name,
            current: true,
        })?,
    }
    Ok(())
}

/// Print the active target for this shell, plus where the answer came
/// from. Helps users debug "why is kobe pointing at X?" without
/// needing to know the resolution rules by heart.
pub async fn config_current_target(output: OutputFormat) -> Result<()> {
    let config = CliConfig::load()?;
    let session = session::load()?;

    let (current_target, source) = match session {
        Some((state, path, ppid)) => (state.current_target.clone(), Some((path, ppid))),
        None => match config.current_target.clone() {
            Some(t) => (t, None),
            None => {
                anyhow::bail!(
                    "No active target set for this shell. \
                     Run: kobe config use <name>. \
                     Available targets: kobe config list."
                )
            }
        },
    };

    if !config.targets.contains_key(&current_target) {
        anyhow::bail!(
            "Active target '{current_target}' is not defined. Run: kobe config list (or remove the stale state with: kobe config use <other>)."
        );
    }

    match output {
        OutputFormat::Text => match source {
            Some((path, ppid)) => println!(
                "{current_target}\n  source: session file (ppid={ppid}, {})",
                path.display()
            ),
            None => println!(
                "{current_target}\n  source: legacy config file (consider running: kobe config use {current_target})"
            ),
        },
        OutputFormat::Json => {
            let scope = config
                .target_scopes
                .get(&current_target)
                .map(|s| s.to_string());
            let source_str = source
                .as_ref()
                .map(|(p, ppid)| format!("session-file:{}:{}", ppid, p.display()))
                .unwrap_or_else(|| "config-file".to_string());
            print_json(&serde_json::json!({
                "name": current_target,
                "source": source_str,
                "scope": scope,
            }))?
        }
    }
    Ok(())
}

pub async fn config_list_targets(output: OutputFormat) -> Result<()> {
    let config = CliConfig::load()?;
    let session = session::load().ok().flatten();
    let active = session
        .as_ref()
        .map(|(state, _, _)| state.current_target.clone())
        .or_else(|| config.current_target.clone());

    match output {
        OutputFormat::Text => {
            if config.targets.is_empty() {
                println!("No targets configured.");
                return Ok(());
            }

            // Compute column widths so the table looks tidy on real
            // terminals (long endpoints don't push the SCOPE column off
            // the screen).
            let name_w = config
                .targets
                .keys()
                .map(|s| s.len())
                .max()
                .unwrap_or(4)
                .max(4);
            let endpoint_w = config
                .targets
                .values()
                .map(|t| t.endpoint.len())
                .max()
                .unwrap_or(8)
                .max(8);

            println!(
                "{:<8}{:<width_n$}  {:<width_e$}  {:<6}  SCOPE",
                "ACTIVE",
                "NAME",
                "ENDPOINT",
                "AUTH",
                width_n = name_w,
                width_e = endpoint_w,
            );
            let mut overlap_targets: Vec<&str> = Vec::new();
            for (name, target) in &config.targets {
                let marker = if active.as_deref() == Some(name) {
                    "  *  "
                } else {
                    "     "
                };
                let scope = config
                    .target_scopes
                    .get(name)
                    .copied()
                    .unwrap_or(Scope::Global);
                if scope == Scope::Both {
                    overlap_targets.push(name);
                }
                println!(
                    "{:<8}{:<width_n$}  {:<width_e$}  {:<6}  {}",
                    marker,
                    name,
                    target.endpoint,
                    target.auth.to_string(),
                    scope,
                    width_n = name_w,
                    width_e = endpoint_w,
                );
            }
            if !overlap_targets.is_empty() {
                eprintln!();
                eprintln!(
                    "warning: {} target{} defined in BOTH global and local — local wins:",
                    overlap_targets.len(),
                    if overlap_targets.len() == 1 { "" } else { "s" }
                );
                for n in &overlap_targets {
                    eprintln!("  - {n}");
                }
                eprintln!("  to inspect: cat ~/.config/kobe/config.json and ./.kobe.toml");
            }
        }
        OutputFormat::Json => {
            let targets = config
                .targets
                .iter()
                .map(|(name, target)| {
                    let scope = config
                        .target_scopes
                        .get(name)
                        .copied()
                        .unwrap_or(Scope::Global);
                    ConfigListEntry {
                        name,
                        current: active.as_deref() == Some(name.as_str()),
                        endpoint: &target.endpoint,
                        auth: &target.auth,
                        scope,
                    }
                })
                .collect::<Vec<_>>();
            print_json(&targets)?;
        }
    }
    Ok(())
}

fn config_view_output(config: &CliConfig, target_override: Option<&str>) -> ConfigViewOutput {
    let path = global_config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "(unknown)".to_string());
    let exists = global_config_path().map(|p| p.exists()).unwrap_or(false);
    let resolved =
        config
            .resolve(target_override, None)
            .ok()
            .map(|resolved| ResolvedConfigOutput {
                target: resolved.target,
                endpoint: resolved.endpoint,
                auth: resolved.auth,
                token: resolved.token,
                ssh_fingerprint: resolved.ssh_fingerprint,
            });

    ConfigViewOutput {
        path,
        exists,
        resolved,
        current_target: config.current_target.clone(),
        targets: config
            .targets
            .iter()
            .map(|(name, target)| {
                (
                    name.clone(),
                    ConfigTargetOutput {
                        endpoint: target.endpoint.clone(),
                        auth: target.auth.clone(),
                        token: target.token.clone(),
                        ssh_fingerprint: target.ssh_fingerprint.clone(),
                    },
                )
            })
            .collect(),
        legacy: legacy_output(config),
    }
}

fn legacy_output(config: &CliConfig) -> Option<ConfigLegacyOutput> {
    let has_legacy = config.endpoint.is_some()
        || config.auth != AuthMode::default()
        || config.token.is_some()
        || config.ssh_fingerprint.is_some();
    if !has_legacy {
        return None;
    }

    Some(ConfigLegacyOutput {
        endpoint: config.endpoint.clone(),
        auth: config.auth.clone(),
        token: config.token.clone(),
        ssh_fingerprint: config.ssh_fingerprint.clone(),
    })
}

fn print_config(config: &CliConfig, target_override: Option<&str>) -> Result<()> {
    let path = global_config_path()?;
    let exists = path.exists();

    println!("config:   {}", path.display());
    println!("exists:   {}", if exists { "yes" } else { "no" });

    let resolved = config.resolve(target_override, None);

    if !exists {
        println!();
        println!("No saved config found.");
        if let Ok(resolved) = resolved {
            println!("resolved-endpoint: {}", resolved.endpoint);
            print_auth(
                &resolved.auth,
                resolved.token.as_deref(),
                resolved.ssh_fingerprint.as_deref(),
            );
        } else {
            println!("resolved: none");
            println!(
                "hint:     run 'kobe config set <name> --endpoint <url> ...' or pass --endpoint"
            );
        }
        return Ok(());
    }

    let resolved = resolved?;

    if let Some(target) = &resolved.target {
        println!("current-target: {target}");
        println!("endpoint: {}", resolved.endpoint);
        print_auth(
            &resolved.auth,
            resolved.token.as_deref(),
            resolved.ssh_fingerprint.as_deref(),
        );
    } else if config.targets.is_empty() {
        println!("mode:     legacy");
        println!("endpoint: {}", resolved.endpoint);
        print_auth(
            &resolved.auth,
            resolved.token.as_deref(),
            resolved.ssh_fingerprint.as_deref(),
        );
    }

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
    } else if exists {
        println!();
        println!("targets:  (none)");
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
