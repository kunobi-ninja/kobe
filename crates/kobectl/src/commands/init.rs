//! `kobe init`: make `ssh kobe-<pool>-<name>` work on this machine.
//!
//! Each step checks before it acts and is skipped when already done, so
//! running `init` twice is cheap and running it after `doctor` repairs what
//! `doctor` reported:
//!
//! 1. target: with `--endpoint`, write (or replace) a named target and make
//!    it current for this shell; otherwise use the current target.
//! 2. session: authorization must work without prompts, because that is what
//!    `ssh-proxy` gets. The first-connect trust question (ssh auth) or the
//!    browser login (oidc) happens here, once, in the user's terminal.
//! 3. default pool: chosen from the pools that can serve SSH (Sandbox, with
//!    `attach` and `exec`), then saved on the target.
//! 4. public key: found, or generated on request.
//! 5. `ssh_config`: Kobe's file written and included from `~/.ssh/config`.
//! 6. proof: `ssh -G kobe-<probe>` must resolve to `kobe ssh-proxy`.
//!
//! Non-interactive runs (`--yes`, no terminal, or `--output json`) never
//! prompt: a step that would need an answer fails with the command that
//! supplies it.

use std::io::IsTerminal;
use std::process::Command;

use anyhow::{Context, Result};
use serde::Serialize;

use super::config::{AuthMode, CliConfig, KobeTarget, ResolvedConfig, Scope};
use super::{OutputFormat, login, pools, print_json, session, ssh_proxy, ssh_setup};

pub struct InitCommand<'a> {
    /// Create or replace a target at this endpoint.
    pub endpoint: Option<&'a str>,
    /// Name of the target `--endpoint` writes. Defaults to `default`.
    pub name: Option<&'a str>,
    /// Auth mode for `--endpoint`. Discovered from the endpoint when unset.
    pub auth: Option<&'a str>,
    /// Bearer token for `--auth token`.
    pub token: Option<&'a str>,
    /// Pool `ssh-proxy` uses when the host does not name one.
    pub default_pool: Option<&'a str>,
    /// Public key file to authorize in sandboxes; remembered in the config.
    pub public_key: Option<&'a str>,
    /// Answer every question with its default and never prompt.
    pub yes: bool,
    pub target_override: Option<&'a str>,
    pub endpoint_override: Option<&'a str>,
    pub output: OutputFormat,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InitOutput {
    target: String,
    endpoint: String,
    auth: String,
    default_pool: Option<String>,
    public_key: String,
    ssh_config: String,
    include: String,
    try_host: String,
}

/// Rewrite `$HOME/x` as `~/x`. `init` reports four paths and three of them
/// live under the home directory, where the prefix is the longest and least
/// informative part of the line.
///
/// Takes the home directory rather than reading the environment so the
/// rewrite can be tested without one.
fn shorten_home(path: &str, home: Option<&str>) -> String {
    let Some(home) = home.filter(|home| !home.is_empty()) else {
        return path.to_string();
    };
    let home = home.strip_suffix('/').unwrap_or(home);
    match path.strip_prefix(home) {
        Some("") => "~".to_string(),
        Some(rest) if rest.starts_with('/') => format!("~{rest}"),
        _ => path.to_string(),
    }
}

fn home_path(path: &std::path::Path) -> String {
    shorten_home(
        &path.display().to_string(),
        std::env::var("HOME").ok().as_deref(),
    )
}

struct Reporter {
    output: OutputFormat,
    /// Escapes are for a person watching, so they are off whenever stdout is
    /// redirected or `NO_COLOR` is set. Decided once: a report whose lines are
    /// styled inconsistently is worse than one with no styling at all.
    color: bool,
}

impl Reporter {
    fn new(output: OutputFormat) -> Self {
        let color = output == OutputFormat::Text
            && std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none();
        Self { output, color }
    }

    /// Explanatory prose under the report. Dimmed, because it is there for
    /// the first run and should not compete with the result on later ones.
    fn note(&self, body: impl AsRef<str>) {
        if self.output != OutputFormat::Text {
            return;
        }
        for line in body.as_ref().lines() {
            if self.color {
                println!("  \x1b[2m{line}\x1b[0m");
            } else {
                println!("  {line}");
            }
        }
    }

    fn step(&self, name: &str, detail: impl AsRef<str>) {
        if self.output != OutputFormat::Text {
            return;
        }
        let detail = detail.as_ref();
        if self.color {
            println!("  \x1b[32m✓\x1b[0m \x1b[2m{name:<12}\x1b[0m {detail}");
        } else {
            println!("  ✓ {name:<12} {detail}");
        }
    }
}

pub async fn init(command: InitCommand<'_>) -> Result<()> {
    let interactive = !command.yes
        && command.output == OutputFormat::Text
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal();
    let report = Reporter::new(command.output);

    // 1. target
    let target_name = match command.endpoint {
        Some(endpoint) => {
            let name = command.name.unwrap_or("default");
            let auth = match command.auth {
                Some(auth) => super::config::parse_auth_mode(auth)?,
                None => discover_auth_mode(endpoint).await?,
            };
            if auth == AuthMode::Token
                && command.token.is_none()
                && std::env::var_os("KOBE_TOKEN").is_none()
            {
                anyhow::bail!("auth=token needs --token <value> or KOBE_TOKEN");
            }
            let mut global = CliConfig::load_global()?;
            let previous = global.targets.get(name);
            let target = KobeTarget {
                endpoint: endpoint.trim_end_matches('/').to_string(),
                auth: auth.clone(),
                token: command.token.map(str::to_string),
                ssh_fingerprint: previous.and_then(|t| t.ssh_fingerprint.clone()),
                default_pool: previous.and_then(|t| t.default_pool.clone()),
            };
            global.targets.insert(name.to_string(), target);
            global.save()?;
            session::save(&session::SessionState {
                current_target: name.to_string(),
            })?;
            report.step(
                "target",
                format!("{name} → {endpoint} (auth {auth}), current for this shell"),
            );
            Some(name.to_string())
        }
        None => None,
    };
    let config = CliConfig::load()?;
    let resolved = config
        .resolve(
            target_name.as_deref().or(command.target_override),
            command.endpoint_override,
        )
        .context("no target to set up; pass --endpoint <url>")?;
    let target_name = resolved.target.clone();
    if command.endpoint.is_none() {
        report.step(
            "target",
            format!(
                "{} → {} (auth {})",
                target_name.as_deref().unwrap_or("endpoint override"),
                resolved.endpoint,
                resolved.auth
            ),
        );
    }

    // 2. session
    ensure_session(&resolved, interactive, &report).await?;

    // 3. default pool
    let default_pool =
        choose_default_pool(&resolved, command.default_pool, interactive, &report).await?;
    if let (Some(name), Some(pool)) = (target_name.as_deref(), default_pool.as_deref())
        && resolved.default_pool.as_deref() != Some(pool)
    {
        save_default_pool(&config, name, pool)?;
    }

    // 4. public key
    let public_key = ensure_public_key(&config, command.public_key, interactive, &report)?;

    // 5. ssh_config
    let executable = std::env::current_exe().context("could not resolve the kobe executable")?;
    let kobe_config = ssh_setup::kobe_ssh_config_path()?;
    let user_config = ssh_setup::user_ssh_config_path()?;
    let block = ssh_proxy::render_ssh_config(&executable, command.target_override);
    let change = ssh_setup::install(&kobe_config, &block)?;
    report.step("ssh config", format!("wrote {}", home_path(&kobe_config)));
    report.step(
        "include",
        match change {
            ssh_setup::IncludeChange::AlreadyPresent => {
                format!("{} already includes it", home_path(&user_config))
            }
            ssh_setup::IncludeChange::Added => {
                format!("added to the top of {}", home_path(&user_config))
            }
            ssh_setup::IncludeChange::AddedAboveScoped { scoped_line } => format!(
                "added to the top of {}; the Include on line {scoped_line} is inside a Host block and can be removed",
                user_config.display()
            ),
        },
    );

    // 6. proof
    let probe = format!("{}init-probe", ssh_proxy::HOST_PREFIX);
    match ssh_setup::resolved_proxy_command(&user_config, &probe)? {
        Some(proxy) if proxy.contains("ssh-proxy") => {
            report.step(
                "ssh resolve",
                format!(
                    "ssh -G {probe} → {}",
                    shorten_home(&proxy, std::env::var("HOME").ok().as_deref())
                ),
            );
        }
        Some(proxy) => anyhow::bail!(
            "ssh -G {probe} resolves to `{proxy}`, not kobe ssh-proxy: another Host block in {} matches kobe-* first",
            user_config.display()
        ),
        None => anyhow::bail!(
            "ssh -G {probe} resolves without a ProxyCommand although {} includes {}",
            user_config.display(),
            kobe_config.display()
        ),
    }

    let try_host = format!(
        "{}{}1",
        ssh_proxy::HOST_PREFIX,
        default_pool
            .as_deref()
            .map(|pool| format!("{pool}-"))
            .unwrap_or_default()
    );
    match command.output {
        OutputFormat::Text => {
            println!();
            if report.color {
                println!("  Ready.  \x1b[1mssh {try_host}\x1b[0m");
            } else {
                println!("  Ready.  ssh {try_host}");
            }
            // The trailing `1` reads like an index into something. It is not:
            // it is a name the caller invents, and inventing another one is
            // how you get a second sandbox. Nothing else in the output says
            // so, and getting it wrong is the difference between returning to
            // your work and silently leasing a new machine.
            println!();
            report.note(
                "The host is kobe-<pool>-<name>, and the name is yours. The first\n\
                 connection leases a sandbox and later ones return to it, so a\n\
                 different name is a different sandbox.",
            );
            report.note(format!(
                "Append .<session>, as in {try_host}.main, for a shell that\n\
                 outlives a dropped connection."
            ));
        }
        OutputFormat::Json => print_json(&InitOutput {
            target: target_name.unwrap_or_default(),
            endpoint: resolved.endpoint.clone(),
            auth: resolved.auth.to_string(),
            default_pool,
            public_key,
            ssh_config: kobe_config.display().to_string(),
            include: user_config.display().to_string(),
            try_host,
        })?,
    }
    Ok(())
}

/// Pick the auth mode a new target should use from what the endpoint
/// advertises: ssh needs no secret and no browser, so it comes first.
async fn discover_auth_mode(endpoint: &str) -> Result<AuthMode> {
    let url = format!("{}/v1/status", endpoint.trim_end_matches('/'));
    let response = super::authed_client()
        .get(&url)
        .send()
        .await
        .with_context(|| format!("could not reach {url}"))?;
    if !response.status().is_success() {
        anyhow::bail!("{url} answered HTTP {}", response.status());
    }
    let body: serde_json::Value = response
        .json()
        .await
        .context("could not parse /v1/status")?;
    let methods: Vec<&str> = body["auth"]["methods"]
        .as_array()
        .map(|methods| methods.iter().filter_map(|m| m.as_str()).collect())
        .unwrap_or_default();
    for (name, mode) in [
        ("ssh", AuthMode::Ssh),
        ("oidc", AuthMode::Oidc),
        ("token", AuthMode::Token),
    ] {
        if methods.contains(&name) {
            return Ok(mode);
        }
    }
    if methods.is_empty() {
        return Ok(AuthMode::None);
    }
    anyhow::bail!(
        "{endpoint} advertises auth methods {}, none of which this CLI supports; pass --auth",
        methods.join(", ")
    )
}

async fn ensure_session(
    config: &ResolvedConfig,
    interactive: bool,
    report: &Reporter,
) -> Result<()> {
    if super::get_auth_header_noninteractive(config, "GET", "/v1/pools", b"")
        .await
        .is_ok()
    {
        report.step("session", format!("{} authorization ready", config.auth));
        return Ok(());
    }
    match config.auth {
        AuthMode::Ssh if interactive => {
            // The interactive path asks the one-time trust question on the
            // terminal and pins the endpoint; after it, the non-interactive
            // path succeeds for every later command.
            super::get_auth_header(config, "GET", "/v1/pools", b"")
                .await
                .context("SSH authorization failed")?;
        }
        AuthMode::Oidc if interactive => {
            login::login(config.target.as_deref(), Some(&config.endpoint), false).await?;
        }
        AuthMode::Ssh => anyhow::bail!(
            "SSH authorization needs a one-time trust answer; run `kobe init` in a terminal, or `kobe status`"
        ),
        AuthMode::Oidc => anyhow::bail!("OIDC login is required; run `kobe login`"),
        AuthMode::Token => anyhow::bail!("token authorization failed; check --token or KOBE_TOKEN"),
        AuthMode::None => anyhow::bail!("the endpoint rejected unauthenticated requests"),
    }
    super::get_auth_header_noninteractive(config, "GET", "/v1/pools", b"")
        .await
        .context("authorization still needs a prompt after login")?;
    report.step("session", format!("{} authorization ready", config.auth));
    Ok(())
}

async fn choose_default_pool(
    config: &ResolvedConfig,
    requested: Option<&str>,
    interactive: bool,
    report: &Reporter,
) -> Result<Option<String>> {
    let pools = pools::fetch_pools_for_config_with_output(config, OutputFormat::Json).await?;
    let capable_pools: Vec<&pools::PoolSummary> = pools
        .iter()
        .filter(|pool| pool.is_sandbox() && pool.supports("attach") && pool.supports("exec"))
        .collect();
    let capable: Vec<String> = capable_pools.iter().map(|pool| pool.name.clone()).collect();
    if capable.is_empty() {
        anyhow::bail!(
            "no pool can serve SSH ({} visible); a SandboxPool with runnerPath and an image that ships kobe-sshd is needed",
            pools.len()
        );
    }
    let chosen = if let Some(requested) = requested {
        if !capable.iter().any(|name| name == requested) {
            anyhow::bail!(
                "pool {requested} cannot serve SSH; ssh-capable pools: {}",
                capable.join(", ")
            );
        }
        Some(requested.to_string())
    } else if let Some(current) = config
        .default_pool
        .as_deref()
        .filter(|current| capable.iter().any(|name| name == current))
    {
        Some(current.to_string())
    } else if capable.len() == 1 {
        Some(capable[0].clone())
    } else if interactive {
        let items: Vec<super::picker::PickerItem> = capable_pools
            .iter()
            .map(|pool| pool_picker_item(pool))
            .collect();
        let index = super::picker::run_picker(
            "Default pool for ssh kobe-<name>",
            "Hosts named kobe-<pool>-<name> can still pick any pool.",
            &items,
        )?;
        Some(capable[index].clone())
    } else {
        None
    };
    match &chosen {
        Some(pool) => report.step(
            "default pool",
            format!("{pool} (ssh-capable: {})", capable.join(", ")),
        ),
        None => report.step(
            "default pool",
            format!(
                "none; hosts must name one: kobe-<pool>-<name> (ssh-capable: {})",
                capable.join(", ")
            ),
        ),
    }
    Ok(chosen)
}

/// One picker row per ssh-capable pool: what is available now, what a lease
/// costs, and what it can do. The same counts and policy line `kobe status`
/// prints, so the picker and the status table never disagree.
fn pool_picker_item(pool: &pools::PoolSummary) -> super::picker::PickerItem {
    let phase = pool
        .phase
        .as_deref()
        .filter(|phase| !phase.is_empty())
        .unwrap_or("Ready");
    let mut secondary = vec![format!("{phase}  {}", pools::format_pool_counts(pool))];
    if let Some(policy) = pools::format_policy(pool) {
        secondary.push(policy);
    }
    if !pool.capabilities.is_empty() {
        secondary.push(pool.capabilities.join(", "));
    }
    super::picker::PickerItem {
        primary: pool.name.clone(),
        secondary: secondary.join("   "),
    }
}

/// Persist the default pool on whichever file defines the target.
fn save_default_pool(config: &CliConfig, target: &str, pool: &str) -> Result<()> {
    match config.target_scopes.get(target) {
        Some(Scope::Local) => {
            let mut entry = config
                .targets
                .get(target)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unknown target {target}"))?;
            entry.default_pool = Some(pool.to_string());
            super::config::write_target_to_local(target, entry)?;
        }
        _ => {
            let mut global = CliConfig::load_global()?;
            let entry = global
                .targets
                .get_mut(target)
                .ok_or_else(|| anyhow::anyhow!("target {target} is not in the global config"))?;
            entry.default_pool = Some(pool.to_string());
            global.save()?;
        }
    }
    Ok(())
}

fn ensure_public_key(
    config: &CliConfig,
    requested: Option<&str>,
    interactive: bool,
    report: &Reporter,
) -> Result<String> {
    if let Some(path) = requested {
        let key = ssh_proxy::resolve_public_key(Some(path), None)?;
        let mut global = CliConfig::load_global()?;
        if global.ssh_public_key.as_deref() != Some(path) {
            global.ssh_public_key = Some(path.to_string());
            global.save()?;
        }
        report.step(
            "public key",
            format!("{path} (remembered in the kobe config)"),
        );
        return Ok(key);
    }
    match ssh_proxy::resolve_public_key(None, config.ssh_public_key.as_deref()) {
        Ok(key) => {
            let mut words = key.split_whitespace();
            let kind = words.next().unwrap_or("");
            let comment = words.nth(1).unwrap_or("");
            report.step("public key", format!("{kind} {comment}").trim());
            Ok(key)
        }
        Err(error) if interactive => {
            eprintln!("{error}");
            eprint!("Generate ~/.ssh/id_ed25519 now? [y/N] ");
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if !answer.trim().eq_ignore_ascii_case("y") {
                anyhow::bail!("no public key to authorize");
            }
            let home = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("cannot determine the home directory"))?;
            let key_path = home.join(".ssh").join("id_ed25519");
            let status = Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-f"])
                .arg(&key_path)
                .status()
                .context("could not run ssh-keygen")?;
            if !status.success() {
                anyhow::bail!("ssh-keygen failed");
            }
            let key = ssh_proxy::resolve_public_key(None, None)?;
            report.step(
                "public key",
                format!("generated {}.pub", key_path.display()),
            );
            Ok(key)
        }
        Err(error) => {
            Err(error).context("pass --public-key <path>, or run `ssh-keygen -t ed25519`")
        }
    }
}

#[cfg(test)]
mod tests {

    /// `init` prints four paths and three sit under the home directory, so the
    /// prefix is the longest and least useful part of each line.
    #[test]
    fn home_is_shortened_to_a_tilde_only_at_a_path_boundary() {
        assert_eq!(
            shorten_home("/Users/lenij/.ssh/config", Some("/Users/lenij")),
            "~/.ssh/config"
        );
        assert_eq!(shorten_home("/Users/lenij", Some("/Users/lenij")), "~");
        // A trailing slash on HOME must not produce "~//.ssh/config".
        assert_eq!(
            shorten_home("/Users/lenij/.ssh/config", Some("/Users/lenij/")),
            "~/.ssh/config"
        );
    }

    /// A different account whose name merely starts with ours keeps its path:
    /// rewriting `/Users/lenija` to `~a` would be worse than not rewriting.
    #[test]
    fn a_sibling_directory_sharing_the_prefix_is_left_alone() {
        assert_eq!(
            shorten_home("/Users/lenija/.ssh/config", Some("/Users/lenij")),
            "/Users/lenija/.ssh/config"
        );
        assert_eq!(
            shorten_home("/etc/ssh/config", Some("/Users/lenij")),
            "/etc/ssh/config"
        );
    }

    /// No HOME, no rewrite. The report still has to be printable.
    #[test]
    fn without_a_home_the_path_is_printed_as_it_is() {
        assert_eq!(shorten_home("/Users/lenij/x", None), "/Users/lenij/x");
        assert_eq!(shorten_home("/Users/lenij/x", Some("")), "/Users/lenij/x");
    }
    use super::*;

    #[test]
    fn pool_picker_row_shows_availability_policy_and_capabilities() {
        let pool: pools::PoolSummary = serde_json::from_value(serde_json::json!({
            "name": "agent-workspace",
            "resourceKind": "Sandbox",
            "capabilities": ["exec", "logs", "attach", "port-forward"],
            "phase": "Ready",
            "ready": 2,
            "leased": 1,
            "creating": 0,
            "policy": { "mode": "fixed", "ttl": "30m", "warmTarget": 2 }
        }))
        .unwrap();
        let item = pool_picker_item(&pool);
        assert_eq!(item.primary, "agent-workspace");
        assert_eq!(
            item.secondary,
            "Ready  ready 2  leased 1   ttl 30m  warm 2 fixed   exec, logs, attach, port-forward"
        );
    }

    #[test]
    fn pool_picker_row_without_policy_or_phase_still_reads() {
        let pool: pools::PoolSummary = serde_json::from_value(serde_json::json!({
            "name": "small",
            "resourceKind": "Sandbox",
            "ready": 0
        }))
        .unwrap();
        assert_eq!(pool_picker_item(&pool).secondary, "Ready  ready 0");
    }
}
