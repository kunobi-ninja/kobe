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

    /// When true, a local `.kobe.toml` `current_target` replaces a global
    /// one. Default false: project files may register extra targets, but
    /// `cd` into a repo must not steal an already-set active target.
    /// A local value is still used when the global file has none (legacy
    /// endpoint-only project files migrate to `current_target = "default"`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub override_current_target: bool,

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
        if local.current_target.is_some()
            && (local.override_current_target || self.current_target.is_none())
        {
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

/// Render a bearer token for display, never revealing enough of it to
/// be usable.
///
/// Tokens longer than 8 characters keep a 4-char head and tail so a user
/// can tell *which* token is configured; anything shorter is replaced
/// wholesale, because a 4+4 elision of an 8-char secret would print the
/// entire value. `None` renders as `(not set)`.
fn mask_token(token: Option<&str>) -> String {
    match token {
        Some(t) if t.len() > 8 => format!("{}...{}", &t[..4], &t[t.len() - 4..]),
        Some(_) => "****".to_string(),
        None => "(not set)".to_string(),
    }
}

fn print_auth(auth: &AuthMode, token: Option<&str>, ssh_fingerprint: Option<&str>) {
    println!("auth:     {auth}");
    if auth == &AuthMode::Token {
        let masked = mask_token(token);
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
    use super::{AuthMode, CliConfig, KobeTarget, Scope, mask_token, parse_auth_mode};
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn target(endpoint: &str) -> KobeTarget {
        KobeTarget {
            endpoint: endpoint.to_string(),
            auth: AuthMode::Oidc,
            token: None,
            ssh_fingerprint: None,
        }
    }

    fn config_with(targets: &[(&str, &str)]) -> CliConfig {
        let mut c = CliConfig::default();
        for (name, endpoint) in targets {
            c.targets.insert(name.to_string(), target(endpoint));
            c.target_scopes.insert(name.to_string(), Scope::Global);
        }
        c
    }

    // ── Session isolation ─────────────────────────────────────────────
    //
    // `CliConfig::resolve` consults the per-shell session file, so the
    // resolve tests must not read (or write) the developer's real one.
    // `KUNOBI_SESSIONS_DIR` redirects it; the mutex serializes the tests
    // that touch that process-global.

    struct SessionSandbox {
        _lock: MutexGuard<'static, ()>,
        previous: Option<std::ffi::OsString>,
        dir: PathBuf,
    }

    impl SessionSandbox {
        /// Point session storage at a fresh empty directory. Nothing in
        /// it, so `session::load()` reports "no active target".
        fn new(tag: &str) -> Self {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let lock = LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .unwrap_or_else(|e| e.into_inner());

            let dir = std::env::temp_dir().join(format!("kobe-cfg-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let previous = std::env::var_os("KUNOBI_SESSIONS_DIR");
            // SAFETY: the mutex above guarantees no other test in this
            // binary reads or writes this variable concurrently, and
            // nothing else in kobectl touches it.
            unsafe { std::env::set_var("KUNOBI_SESSIONS_DIR", &dir) };
            Self {
                _lock: lock,
                previous,
                dir,
            }
        }
    }

    impl Drop for SessionSandbox {
        fn drop(&mut self) {
            // SAFETY: same as in `new` — still holding the lock.
            unsafe {
                match self.previous.take() {
                    Some(v) => std::env::set_var("KUNOBI_SESSIONS_DIR", v),
                    None => std::env::remove_var("KUNOBI_SESSIONS_DIR"),
                }
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    // ── overlay: local `.kobe.toml` on top of the global library ──────

    /// A target defined in both files resolves to the **local**
    /// definition and is flagged `Both`, which is what makes `kobe
    /// config list` warn about the shadowing instead of silently
    /// pointing at a different cluster than the user's global config
    /// says.
    #[test]
    fn overlay_local_target_shadows_the_global_one_and_is_marked_both() {
        let mut global = config_with(&[("prod", "https://global.test")]);
        let mut local = CliConfig::default();
        local
            .targets
            .insert("prod".to_string(), target("https://local.test"));

        global.overlay(local);

        assert_eq!(global.targets["prod"].endpoint, "https://local.test");
        assert_eq!(global.target_scopes["prod"], Scope::Both);
    }

    /// A target that only the project file defines is `Local`, and one
    /// that only the global library defines stays `Global`. These three
    /// scopes are the entire contract of the SCOPE column.
    #[test]
    fn overlay_tags_local_only_and_global_only_targets_distinctly() {
        let mut global = config_with(&[("prod", "https://global.test")]);
        let mut local = CliConfig::default();
        local
            .targets
            .insert("staging".to_string(), target("https://staging.test"));

        global.overlay(local);

        assert_eq!(global.target_scopes["prod"], Scope::Global);
        assert_eq!(global.target_scopes["staging"], Scope::Local);
        assert_eq!(global.targets.len(), 2);
    }

    /// Local values only override when they are actually set. An
    /// endpoint-only `.kobe.toml` must not blank out a token that lives
    /// in the global config.
    #[test]
    fn overlay_only_applies_local_fields_that_are_set() {
        let mut global = CliConfig {
            current_target: Some("prod".to_string()),
            endpoint: Some("https://global.test".to_string()),
            token: Some("global-token".to_string()),
            ssh_fingerprint: Some("SHA256:global".to_string()),
            ..CliConfig::default()
        };

        global.overlay(CliConfig::default());

        assert_eq!(global.current_target.as_deref(), Some("prod"));
        assert_eq!(global.endpoint.as_deref(), Some("https://global.test"));
        assert_eq!(global.token.as_deref(), Some("global-token"));
        assert_eq!(global.ssh_fingerprint.as_deref(), Some("SHA256:global"));
    }

    /// Local `current_target` does not steal a global active target.
    /// Register extra targets from `.kobe.toml`; opt in with
    /// `override_current_target` to pin the repo's default. A local value
    /// still applies when the global file has no current target, so a
    /// legacy endpoint-only project file keeps working.
    #[test]
    fn overlay_ignores_local_current_target_unless_opted_in() {
        let mut global = CliConfig {
            current_target: Some("prod".to_string()),
            ..CliConfig::default()
        };
        let local = CliConfig {
            current_target: Some("e2e".to_string()),
            ..CliConfig::default()
        };
        global.overlay(local);
        assert_eq!(global.current_target.as_deref(), Some("prod"));

        let mut global = CliConfig {
            current_target: Some("prod".to_string()),
            ..CliConfig::default()
        };
        let local = CliConfig {
            current_target: Some("e2e".to_string()),
            override_current_target: true,
            ..CliConfig::default()
        };
        global.overlay(local);
        assert_eq!(global.current_target.as_deref(), Some("e2e"));

        let mut global = CliConfig::default();
        let local = CliConfig {
            current_target: Some("default".to_string()),
            ..CliConfig::default()
        };
        global.overlay(local);
        assert_eq!(global.current_target.as_deref(), Some("default"));
    }

    /// …and when they *are* set, local wins for every legacy field. The
    /// active-target name is not stolen without `override_current_target`.
    #[test]
    fn overlay_local_values_win_when_present() {
        let mut global = CliConfig {
            current_target: Some("prod".to_string()),
            endpoint: Some("https://global.test".to_string()),
            auth: AuthMode::Oidc,
            token: Some("global-token".to_string()),
            ssh_fingerprint: Some("SHA256:global".to_string()),
            ..CliConfig::default()
        };
        let local = CliConfig {
            current_target: Some("staging".to_string()),
            endpoint: Some("https://local.test".to_string()),
            auth: AuthMode::Token,
            token: Some("local-token".to_string()),
            ssh_fingerprint: Some("SHA256:local".to_string()),
            ..CliConfig::default()
        };

        global.overlay(local);

        assert_eq!(global.current_target.as_deref(), Some("prod"));
        assert_eq!(global.endpoint.as_deref(), Some("https://local.test"));
        assert_eq!(global.auth, AuthMode::Token);
        assert_eq!(global.token.as_deref(), Some("local-token"));
        assert_eq!(global.ssh_fingerprint.as_deref(), Some("SHA256:local"));
    }

    /// Documented asymmetry: `auth` is overlaid only when the local
    /// value differs from the default (`oidc`), because TOML cannot tell
    /// "absent" from "explicitly oidc". A project file that spells out
    /// `auth = "oidc"` therefore cannot pull a global `token` target
    /// back to OIDC. Pinned so the limitation is a decision, not a
    /// surprise.
    #[test]
    fn overlay_cannot_reset_auth_to_the_default_mode() {
        let mut global = CliConfig {
            auth: AuthMode::Token,
            ..CliConfig::default()
        };
        let local = CliConfig {
            auth: AuthMode::Oidc,
            ..CliConfig::default()
        };

        global.overlay(local);

        assert_eq!(global.auth, AuthMode::Token);
    }

    // ── legacy migration ──────────────────────────────────────────────

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

    /// A config that already names a current target has been through the
    /// migration (or was written by a modern kobe). Re-running it would
    /// clobber that choice with a synthesised `default`.
    #[test]
    fn does_not_migrate_when_a_current_target_is_already_set() {
        let mut config = CliConfig {
            current_target: Some("prod".to_string()),
            endpoint: Some("https://legacy.example.test".to_string()),
            ..CliConfig::default()
        };

        assert!(!config.migrate_legacy_to_default_target());
        assert!(config.targets.is_empty());
        assert_eq!(config.current_target.as_deref(), Some("prod"));
    }

    /// A pristine config has nothing to migrate, and `save()` must not
    /// be triggered — `load_global` writes the file back whenever this
    /// returns true, so a spurious `true` would rewrite (and re-chmod)
    /// the user's config on every single command.
    #[test]
    fn does_not_migrate_an_empty_config() {
        let mut config = CliConfig::default();
        assert!(!config.migrate_legacy_to_default_target());
        assert!(config.targets.is_empty());
        assert!(config.current_target.is_none());
    }

    /// A legacy config with credentials but no endpoint cannot become a
    /// target (a target requires an endpoint). It must be left exactly
    /// as it was — in particular *not* half-migrated with the flat
    /// fields cleared, which would silently destroy the user's token.
    #[test]
    fn does_not_migrate_a_legacy_config_that_has_no_endpoint() {
        let mut config = CliConfig {
            endpoint: None,
            auth: AuthMode::Token,
            token: Some("secret-token".to_string()),
            ..CliConfig::default()
        };

        assert!(!config.migrate_legacy_to_default_target());
        assert!(config.targets.is_empty());
        assert!(config.current_target.is_none());
        assert_eq!(config.auth, AuthMode::Token);
        assert_eq!(config.token.as_deref(), Some("secret-token"));
    }

    // ── resolve: which endpoint does this invocation talk to? ─────────

    /// `--target` beats the per-shell session *and* the legacy
    /// `current_target`. It is the documented one-shot escape hatch, so
    /// it has to sit at the top of the precedence chain.
    #[test]
    fn resolve_prefers_the_explicit_target_override() {
        let _sandbox = SessionSandbox::new("override");
        let mut config = config_with(&[("prod", "https://prod.test"), ("dev", "https://dev.test")]);
        config.current_target = Some("prod".to_string());
        super::session::save(&super::session::SessionState {
            current_target: "prod".to_string(),
        })
        .ok();

        let resolved = config.resolve(Some("dev"), None).unwrap();
        assert_eq!(resolved.target.as_deref(), Some("dev"));
        assert_eq!(resolved.endpoint, "https://dev.test");
    }

    /// With no `--target`, the per-shell session file wins over the
    /// legacy `current_target` in the config. That is the whole point of
    /// per-shell sessions: two terminals pointing at different clusters
    /// while sharing one config file.
    #[test]
    fn resolve_prefers_the_session_target_over_the_config_field() {
        let sandbox = SessionSandbox::new("session-wins");
        if super::session::save(&super::session::SessionState {
            current_target: "dev".to_string(),
        })
        .is_err()
        {
            // Parent PID unavailable (no shell parent) — per-shell state
            // is genuinely unusable here, nothing to assert.
            drop(sandbox);
            return;
        }

        let mut config = config_with(&[("prod", "https://prod.test"), ("dev", "https://dev.test")]);
        config.current_target = Some("prod".to_string());

        let resolved = config.resolve(None, None).unwrap();
        assert_eq!(resolved.target.as_deref(), Some("dev"));
        assert_eq!(resolved.endpoint, "https://dev.test");
    }

    /// Without a session file the legacy `current_target` still works —
    /// configs written before per-shell sessions existed (and `kobe
    /// config import` payloads) must keep resolving.
    #[test]
    fn resolve_falls_back_to_the_legacy_current_target() {
        let _sandbox = SessionSandbox::new("legacy-current");
        let mut config = config_with(&[("prod", "https://prod.test")]);
        config.current_target = Some("prod".to_string());

        let resolved = config.resolve(None, None).unwrap();
        assert_eq!(resolved.target.as_deref(), Some("prod"));
        assert_eq!(resolved.endpoint, "https://prod.test");
    }

    /// The pre-targets flat config still resolves, with no target name.
    #[test]
    fn resolve_falls_back_to_the_flat_legacy_endpoint() {
        let _sandbox = SessionSandbox::new("flat");
        let config = CliConfig {
            endpoint: Some("https://legacy.test".to_string()),
            auth: AuthMode::Token,
            token: Some("t".to_string()),
            ..CliConfig::default()
        };

        let resolved = config.resolve(None, None).unwrap();
        assert!(resolved.target.is_none());
        assert_eq!(resolved.endpoint, "https://legacy.test");
        assert_eq!(resolved.auth, AuthMode::Token);
        assert_eq!(resolved.token.as_deref(), Some("t"));
    }

    /// A name that isn't defined is an error, not a silent fallback to
    /// some other target — pointing a CI job at the wrong cluster is far
    /// worse than failing.
    #[test]
    fn resolve_rejects_an_unknown_target_name() {
        let _sandbox = SessionSandbox::new("unknown");
        let config = config_with(&[("prod", "https://prod.test")]);

        let err = config.resolve(Some("nope"), None).unwrap_err().to_string();
        assert!(err.contains("Unknown target 'nope'"), "got: {err}");
    }

    /// `-e/--endpoint` overrides only the URL: auth mode, token and SSH
    /// fingerprint still come from the resolved target. Dropping the
    /// auth would silently downgrade an authenticated call to anonymous.
    #[test]
    fn resolve_endpoint_override_keeps_the_targets_credentials() {
        let _sandbox = SessionSandbox::new("endpoint-override");
        let mut config = CliConfig::default();
        config.targets.insert(
            "prod".to_string(),
            KobeTarget {
                endpoint: "https://prod.test".to_string(),
                auth: AuthMode::Token,
                token: Some("prod-token".to_string()),
                ssh_fingerprint: None,
            },
        );
        config.current_target = Some("prod".to_string());

        let resolved = config.resolve(None, Some("http://127.0.0.1:8080")).unwrap();
        assert_eq!(resolved.endpoint, "http://127.0.0.1:8080");
        assert_eq!(resolved.target.as_deref(), Some("prod"));
        assert_eq!(resolved.auth, AuthMode::Token);
        assert_eq!(resolved.token.as_deref(), Some("prod-token"));
    }

    /// `--endpoint` with no target at all resolves anonymously against
    /// the legacy top-level auth — this is the `kobe -e http://localhost`
    /// port-forward path, which must work on a machine with no config.
    #[test]
    fn resolve_endpoint_override_works_with_no_target_configured() {
        let _sandbox = SessionSandbox::new("endpoint-only");
        let config = CliConfig::default();

        let resolved = config.resolve(None, Some("http://127.0.0.1:8080")).unwrap();
        assert_eq!(resolved.endpoint, "http://127.0.0.1:8080");
        assert!(resolved.target.is_none());
        assert_eq!(resolved.auth, AuthMode::Oidc);
    }

    /// The two "nothing resolved" failures give different advice:
    /// with targets defined the user needs `kobe config use`, without
    /// them they need `kobe config set`. Pin both, because the message
    /// *is* the UX for a first-run user.
    #[test]
    fn resolve_error_distinguishes_no_active_target_from_no_config_at_all() {
        let _sandbox = SessionSandbox::new("errors");

        let with_targets = config_with(&[("prod", "https://prod.test")]);
        let err = with_targets.resolve(None, None).unwrap_err().to_string();
        assert!(err.contains("kobe config use <name>"), "got: {err}");

        let empty = CliConfig::default();
        let err = empty.resolve(None, None).unwrap_err().to_string();
        assert!(err.contains("kobe config set <name>"), "got: {err}");
        assert!(
            !err.contains("kobe config use"),
            "must not suggest selecting among zero targets: {err}"
        );
    }

    // ── Serde: on-disk compatibility of the config file ───────────────

    /// `contexts` / `current_context` are the pre-rename field names.
    /// Configs written by those versions are still on developers' disks;
    /// dropping the aliases would silently present them with an empty
    /// target list.
    #[test]
    fn config_still_reads_the_pre_rename_context_field_names() {
        let config: CliConfig = serde_json::from_str(
            r#"{
                "current_context": "prod",
                "contexts": {
                    "prod": { "endpoint": "https://prod.test", "auth": "token", "token": "t" }
                }
            }"#,
        )
        .unwrap();

        assert_eq!(config.current_target.as_deref(), Some("prod"));
        assert_eq!(config.targets["prod"].endpoint, "https://prod.test");
        assert_eq!(config.targets["prod"].auth, AuthMode::Token);
    }

    /// A target with no `auth` key predates the auth modes and must
    /// default to OIDC — the same default a freshly created target gets.
    #[test]
    fn target_without_an_auth_key_defaults_to_oidc() {
        let t: KobeTarget = serde_json::from_str(r#"{ "endpoint": "https://x.test" }"#).unwrap();
        assert_eq!(t.auth, AuthMode::Oidc);
        assert!(t.token.is_none());
        assert!(t.ssh_fingerprint.is_none());
    }

    /// The saved file stays minimal: the default auth mode, an empty
    /// target map and unset secrets are all omitted. `target_scopes` is
    /// runtime-only metadata and must never be written — round-tripping
    /// it would make a *local* target look global on the next load.
    #[test]
    fn saved_config_omits_defaults_and_runtime_only_metadata() {
        let mut config = config_with(&[("prod", "https://prod.test")]);
        config.target_scopes.insert("prod".into(), Scope::Local);

        let v: serde_json::Value = serde_json::to_value(&config).unwrap();
        assert!(v.get("auth").is_none(), "default auth must be omitted: {v}");
        assert!(v.get("endpoint").is_none(), "unset endpoint omitted: {v}");
        assert!(v.get("token").is_none(), "unset token omitted: {v}");
        assert!(
            v.get("target_scopes").is_none() && v.get("targetScopes").is_none(),
            "runtime-only scope metadata must never be persisted: {v}"
        );
        assert!(v["targets"]["prod"].get("token").is_none());

        let empty = serde_json::to_value(CliConfig::default()).unwrap();
        assert_eq!(empty, serde_json::json!({}), "a pristine config is `{{}}`");
    }

    /// Serialized configs round-trip through the JSON the `config
    /// export` / `config import` pair uses.
    #[test]
    fn config_round_trips_through_export_import_json() {
        let mut config = CliConfig {
            current_target: Some("prod".to_string()),
            ..CliConfig::default()
        };
        config.targets.insert(
            "prod".to_string(),
            KobeTarget {
                endpoint: "https://prod.test".to_string(),
                auth: AuthMode::Ssh,
                token: None,
                ssh_fingerprint: Some("SHA256:abc".to_string()),
            },
        );

        let json = serde_json::to_string(&config).unwrap();
        let back: CliConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(back.current_target.as_deref(), Some("prod"));
        assert_eq!(back.targets["prod"].auth, AuthMode::Ssh);
        assert_eq!(
            back.targets["prod"].ssh_fingerprint.as_deref(),
            Some("SHA256:abc")
        );
        assert!(
            back.target_scopes.is_empty(),
            "scopes are recomputed on load, never read from the file"
        );
    }

    /// The local project file is TOML. A target defined there must
    /// survive `toml::to_string_pretty` → `toml::from_str`, which is
    /// exactly what `write_target_to_local` does on every
    /// `kobe config set`.
    #[test]
    fn local_target_round_trips_through_toml() {
        let mut local = CliConfig::default();
        local.targets.insert(
            "ci".to_string(),
            KobeTarget {
                endpoint: "https://ci.test".to_string(),
                auth: AuthMode::Token,
                token: Some("ci-token".to_string()),
                ssh_fingerprint: None,
            },
        );

        let rendered = toml::to_string_pretty(&local).expect("local config must serialize to TOML");
        let back: CliConfig = toml::from_str(&rendered).unwrap();
        assert_eq!(back.targets["ci"].endpoint, "https://ci.test");
        assert_eq!(back.targets["ci"].auth, AuthMode::Token);
        assert_eq!(back.targets["ci"].token.as_deref(), Some("ci-token"));
    }

    /// `write_target_to_local` re-serializes whatever is already in
    /// `./.kobe.toml` before adding the new target. If that file still
    /// carries pre-targets flat keys (`endpoint`, `token`, …), the
    /// struct now holds a scalar *after* a table — the classic TOML
    /// "values must be emitted before tables" hazard. `kobe config set`
    /// must not blow up on such a file.
    #[test]
    fn local_config_with_both_flat_legacy_keys_and_targets_still_serializes() {
        let mut local = CliConfig {
            endpoint: Some("https://legacy.test".to_string()),
            auth: AuthMode::Token,
            token: Some("legacy-token".to_string()),
            ..CliConfig::default()
        };
        local
            .targets
            .insert("ci".to_string(), target("https://ci.test"));

        let rendered = toml::to_string_pretty(&local)
            .expect("a legacy-plus-targets local config must still serialize");
        let back: CliConfig = toml::from_str(&rendered).unwrap();
        assert_eq!(back.endpoint.as_deref(), Some("https://legacy.test"));
        assert_eq!(back.token.as_deref(), Some("legacy-token"));
        assert_eq!(back.targets["ci"].endpoint, "https://ci.test");
    }

    // ── Auth mode + scope vocabulary ──────────────────────────────────

    /// The four accepted `--auth` spellings, and the exact set. A typo
    /// must be rejected with a message that lists the valid values
    /// rather than silently falling back to OIDC.
    #[test]
    fn parse_auth_mode_accepts_exactly_the_four_documented_modes() {
        assert_eq!(parse_auth_mode("none").unwrap(), AuthMode::None);
        assert_eq!(parse_auth_mode("token").unwrap(), AuthMode::Token);
        assert_eq!(parse_auth_mode("oidc").unwrap(), AuthMode::Oidc);
        assert_eq!(parse_auth_mode("ssh").unwrap(), AuthMode::Ssh);

        for bad in ["OIDC", "bearer", "", "oidc "] {
            let err = parse_auth_mode(bad).unwrap_err().to_string();
            assert!(
                err.contains("Valid: none, token, oidc, ssh"),
                "`{bad}` must be rejected with the valid list; got: {err}"
            );
        }
    }

    /// `AuthMode`'s `Display` (used in `config list`'s AUTH column) and
    /// its serde form (written to disk and to `--output json`) must
    /// agree — otherwise the value a user copies out of the table is not
    /// the value `--auth` accepts back.
    #[test]
    fn auth_mode_display_matches_its_serde_form() {
        for mode in [
            AuthMode::None,
            AuthMode::Token,
            AuthMode::Oidc,
            AuthMode::Ssh,
        ] {
            let wire = serde_json::to_value(&mode).unwrap();
            assert_eq!(wire, serde_json::json!(mode.to_string()));
            assert_eq!(parse_auth_mode(&mode.to_string()).unwrap(), mode);
        }
        assert_eq!(AuthMode::default(), AuthMode::Oidc);
    }

    /// Same contract for `Scope`, which appears both in the text table
    /// and in the `config list --output json` payload.
    #[test]
    fn scope_display_matches_its_serde_form() {
        for scope in [Scope::Global, Scope::Local, Scope::Both] {
            assert_eq!(
                serde_json::to_value(scope).unwrap(),
                serde_json::json!(scope.to_string())
            );
        }
        assert_eq!(Scope::Global.to_string(), "global");
        assert_eq!(Scope::Local.to_string(), "local");
        assert_eq!(Scope::Both.to_string(), "both");
    }

    // ── Secret handling ───────────────────────────────────────────────

    /// `kobe config show` prints the configured bearer token. It must
    /// never print enough of it to be reusable: short tokens are fully
    /// elided, and long ones keep only a 4+4 fingerprint. A regression
    /// here leaks a credential into terminal scrollback and CI logs.
    #[test]
    fn token_display_never_reveals_a_usable_secret() {
        assert_eq!(mask_token(None), "(not set)");
        // 8 chars or fewer: a 4+4 elision would print the whole thing.
        assert_eq!(mask_token(Some("")), "****");
        assert_eq!(mask_token(Some("short")), "****");
        assert_eq!(mask_token(Some("12345678")), "****");
        // 9+ chars: head and tail only, and never the middle.
        assert_eq!(mask_token(Some("123456789")), "1234...6789");
        let secret = "kobe_live_ABCDEFGHIJKLMNOP";
        let masked = mask_token(Some(secret));
        assert_eq!(masked, "kobe...MNOP");
        assert!(
            !masked.contains("live_ABCDEFGHIJKL"),
            "the body of the token must not appear: {masked}"
        );
    }

    // ── JSON output shapes ────────────────────────────────────────────

    /// The `legacy` block in `config show --output json` exists only to
    /// tell a user they still have a pre-targets config. It must be
    /// absent for a modern config so scripts can use its presence as the
    /// "needs migration" signal.
    #[test]
    fn legacy_json_block_appears_only_for_pre_targets_configs() {
        assert!(super::legacy_output(&config_with(&[("prod", "https://p.test")])).is_none());
        assert!(super::legacy_output(&CliConfig::default()).is_none());

        let legacy = CliConfig {
            endpoint: Some("https://legacy.test".to_string()),
            ..CliConfig::default()
        };
        let out = super::legacy_output(&legacy).expect("legacy block expected");
        assert_eq!(out.endpoint.as_deref(), Some("https://legacy.test"));

        // A non-default auth alone is enough to count as legacy.
        let auth_only = CliConfig {
            auth: AuthMode::Token,
            ..CliConfig::default()
        };
        assert!(super::legacy_output(&auth_only).is_some());
    }

    /// `config show --output json` is a scripted surface: keys are
    /// camelCase, absent optionals are omitted (not null), and the
    /// resolved block reflects the same precedence `resolve` applies.
    #[test]
    fn config_view_json_uses_camel_case_and_omits_absent_optionals() {
        let _sandbox = SessionSandbox::new("view");
        let mut config = CliConfig::default();
        config.targets.insert(
            "prod".to_string(),
            KobeTarget {
                endpoint: "https://prod.test".to_string(),
                auth: AuthMode::Ssh,
                token: None,
                ssh_fingerprint: Some("SHA256:abc".to_string()),
            },
        );
        config.current_target = Some("prod".to_string());

        let v = serde_json::to_value(super::config_view_output(&config, None)).unwrap();

        assert_eq!(v["currentTarget"], "prod");
        assert_eq!(v["targets"]["prod"]["sshFingerprint"], "SHA256:abc");
        assert!(
            v["targets"]["prod"].get("token").is_none(),
            "an unset token must be omitted, not null: {v}"
        );
        assert!(v.get("legacy").is_none(), "no legacy block expected: {v}");
        assert_eq!(v["resolved"]["target"], "prod");
        assert_eq!(v["resolved"]["endpoint"], "https://prod.test");
        assert_eq!(v["resolved"]["auth"], "ssh");
    }

    /// When nothing resolves, the `resolved` key is omitted entirely
    /// rather than emitted as null — `config show --output json` on a
    /// fresh machine must still be valid, parseable output.
    #[test]
    fn config_view_json_omits_resolved_when_nothing_is_configured() {
        let _sandbox = SessionSandbox::new("view-empty");
        let v =
            serde_json::to_value(super::config_view_output(&CliConfig::default(), None)).unwrap();

        assert!(v.get("resolved").is_none(), "got: {v}");
        assert!(v.get("currentTarget").is_none(), "got: {v}");
        assert_eq!(v["targets"], serde_json::json!({}));
        assert!(v["path"].is_string());
        assert!(v["exists"].is_boolean());
    }

    /// Guard against `BTreeMap` being swapped for a `HashMap`: the
    /// targets map is rendered directly into `config list`, so a
    /// non-deterministic order would reshuffle the table (and the JSON)
    /// on every invocation.
    #[test]
    fn targets_iterate_in_stable_alphabetical_order() {
        let config = config_with(&[
            ("zeta", "https://z.test"),
            ("alpha", "https://a.test"),
            ("mid", "https://m.test"),
        ]);
        let names: Vec<&str> = config.targets.keys().map(String::as_str).collect();
        assert_eq!(names, vec!["alpha", "mid", "zeta"]);
    }
}
