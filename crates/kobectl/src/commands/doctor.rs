//! `kobe doctor`: read-only checks of everything `ssh kobe-<pool>-<name>`
//! depends on, from this machine outward.
//!
//! Every check is independent and reported even when an earlier one fails,
//! so one run shows the whole picture: someone who says "it does not
//! connect" gets the binary, the target, the session, the pools, the key and
//! the `ssh_config` on one screen. Nothing here prompts and nothing is
//! written; `kobe init` is the command that repairs what `doctor` reports.
//!
//! The exit status is 0 when nothing failed. Warnings do not fail the run.

use anyhow::Result;
use serde::Serialize;

use super::config::{AuthMode, CliConfig, ResolvedConfig};
use super::{OutputFormat, leases, pools, print_json, ssh_proxy, ssh_setup};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warn,
    Fail,
    Skip,
}

impl Status {
    fn glyph(self) -> &'static str {
        match self {
            Status::Ok => "✓",
            Status::Warn => "!",
            Status::Fail => "✗",
            Status::Skip => "·",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    /// What to do about a warning or failure. Empty when nothing is needed.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fix: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DoctorOutput {
    healthy: bool,
    checks: Vec<Check>,
}

fn ok(name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name,
        status: Status::Ok,
        detail: detail.into(),
        fix: String::new(),
    }
}

fn warn(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Check {
    Check {
        name,
        status: Status::Warn,
        detail: detail.into(),
        fix: fix.into(),
    }
}

fn fail(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Check {
    Check {
        name,
        status: Status::Fail,
        detail: detail.into(),
        fix: fix.into(),
    }
}

fn skip(name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name,
        status: Status::Skip,
        detail: detail.into(),
        fix: String::new(),
    }
}

/// Run every check. Returns whether all of them passed.
pub async fn doctor(
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> Result<bool> {
    let checks = collect(target_override, endpoint_override).await;
    let healthy = checks.iter().all(|check| check.status != Status::Fail);
    match output {
        OutputFormat::Json => print_json(&DoctorOutput { healthy, checks })?,
        OutputFormat::Text => {
            for check in &checks {
                println!(
                    "{} {:<12} {}",
                    check.status.glyph(),
                    check.name,
                    check.detail
                );
                if !check.fix.is_empty() {
                    println!("  {:<12} → {}", "", check.fix);
                }
            }
            if !healthy {
                println!();
                println!("Some checks failed. `kobe init` repairs the local ones.");
            }
        }
    }
    Ok(healthy)
}

async fn collect(target_override: Option<&str>, endpoint_override: Option<&str>) -> Vec<Check> {
    let mut checks = Vec::new();

    let executable = std::env::current_exe().ok();
    checks.push(match &executable {
        Some(path) => ok(
            "binary",
            format!("{} {}", path.display(), super::cli_version()),
        ),
        None => warn(
            "binary",
            format!("kobe {} (path unknown)", super::cli_version()),
            "",
        ),
    });

    let loaded = CliConfig::load();
    let (config, resolved) = match loaded {
        Ok(config) => match config.resolve(target_override, endpoint_override) {
            Ok(resolved) => (Some(config), Some(resolved)),
            Err(error) => {
                checks.push(fail(
                    "target",
                    error.to_string(),
                    "kobe init --endpoint <url>, or kobe config use <name>",
                ));
                (Some(config), None)
            }
        },
        Err(error) => {
            checks.push(fail(
                "config",
                error.to_string(),
                "kobe init --endpoint <url>",
            ));
            (None, None)
        }
    };

    let Some(resolved) = resolved else {
        checks.push(skip("endpoint", "no target"));
        checks.push(skip("session", "no target"));
        checks.push(skip("pools", "no target"));
        checks.push(public_key_check(config.as_ref()));
        checks.extend(ssh_config_checks(executable.as_deref()));
        return checks;
    };
    checks.push(ok(
        "target",
        format!(
            "{} → {} (auth {})",
            resolved.target.as_deref().unwrap_or("endpoint override"),
            resolved.endpoint,
            resolved.auth
        ),
    ));

    checks.push(endpoint_check(&resolved).await);

    let session = session_check(&resolved).await;
    let session_ok = session.status == Status::Ok;
    checks.push(session);

    if session_ok {
        checks.push(pools_check(&resolved).await);
        checks.push(leases_check(&resolved).await);
    } else {
        checks.push(skip("pools", "no session"));
        checks.push(skip("leases", "no session"));
    }

    checks.push(public_key_check(config.as_ref()));
    checks.extend(ssh_config_checks(executable.as_deref()));
    checks
}

async fn endpoint_check(config: &ResolvedConfig) -> Check {
    let url = format!("{}/v1/status", config.endpoint);
    match super::authed_client().get(&url).send().await {
        Ok(response) if response.status().is_success() => {
            let body: serde_json::Value = response.json().await.unwrap_or_default();
            let version = body["version"].as_str().unwrap_or("?");
            let methods = body["auth"]["methods"]
                .as_array()
                .map(|methods| {
                    methods
                        .iter()
                        .filter_map(|method| method.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let detail = if methods.is_empty() {
                format!("api {version}")
            } else {
                format!("api {version}, auth methods: {methods}")
            };
            let advertised = body["auth"]["methods"]
                .as_array()
                .map(|methods| {
                    methods
                        .iter()
                        .any(|method| method.as_str() == Some(&config.auth.to_string()))
                })
                .unwrap_or(true);
            if advertised || config.auth == AuthMode::None {
                ok("endpoint", detail)
            } else {
                warn(
                    "endpoint",
                    format!("{detail}; target uses auth {}", config.auth),
                    "kobe config set <target> --auth <one of the advertised methods>",
                )
            }
        }
        Ok(response) => fail(
            "endpoint",
            format!("{url} answered HTTP {}", response.status()),
            "check the endpoint URL with kobe config view",
        ),
        Err(error) => fail(
            "endpoint",
            super::classify_unreachable(&error).summary().to_string(),
            super::classify_unreachable(&error).hint().to_string(),
        ),
    }
}

/// Authorization must work without a prompt: that is what `ssh-proxy` needs.
async fn session_check(config: &ResolvedConfig) -> Check {
    match super::get_auth_header_noninteractive(config, "GET", "/v1/pools", b"").await {
        Ok(_) => ok(
            "session",
            format!("{} authorization ready without prompts", config.auth),
        ),
        Err(error) => {
            let text = error.to_string();
            let fix = match config.auth {
                AuthMode::Oidc => "kobe login",
                AuthMode::Ssh if text.contains("trust") => {
                    "kobe status (answers the one-time trust prompt)"
                }
                AuthMode::Ssh => {
                    "ssh-add your Ed25519 key, or kobe config set <target> --ssh-fingerprint <fp>"
                }
                AuthMode::Token => "set KOBE_TOKEN or kobe config set <target> --token <token>",
                AuthMode::None => "",
            };
            fail("session", text, fix)
        }
    }
}

async fn pools_check(config: &ResolvedConfig) -> Check {
    let pools = match pools::fetch_pools_for_config_with_output(config, OutputFormat::Json).await {
        Ok(pools) => pools,
        Err(error) => return fail("pools", error.to_string(), ""),
    };
    let ssh_capable: Vec<&str> = pools
        .iter()
        .filter(|pool| pool.is_sandbox() && pool.supports("attach") && pool.supports("exec"))
        .map(|pool| pool.name.as_str())
        .collect();
    if ssh_capable.is_empty() {
        return fail(
            "pools",
            format!(
                "{} pool(s) visible, none is a Sandbox pool with attach and exec",
                pools.len()
            ),
            "ask the administrator for a SandboxPool with runnerPath and an image that ships kobe-sshd",
        );
    }
    match config.default_pool.as_deref() {
        Some(default) if ssh_capable.contains(&default) => ok(
            "pools",
            format!("ssh-capable: {}; default {default}", ssh_capable.join(", ")),
        ),
        Some(default) => warn(
            "pools",
            format!(
                "default pool {default} is not ssh-capable; ssh-capable: {}",
                ssh_capable.join(", ")
            ),
            "kobe config set <target> --default-pool <pool>",
        ),
        None => warn(
            "pools",
            format!(
                "ssh-capable: {}; no default pool, so hosts must name one (kobe-<pool>-<name>)",
                ssh_capable.join(", ")
            ),
            "kobe init, or kobe config set <target> --default-pool <pool>",
        ),
    }
}

async fn leases_check(config: &ResolvedConfig) -> Check {
    let all = match leases::fetch_all_leases_with_output(config, OutputFormat::Json).await {
        Ok(all) => all,
        Err(error) => return warn("leases", error.to_string(), ""),
    };
    let mut live: Vec<String> = all
        .iter()
        .filter(|lease| lease.is_sandbox() && !leases::is_terminal_phase(&lease.phase))
        .map(|lease| {
            let name = lease.alias.clone().unwrap_or_else(|| lease.id.clone());
            match &lease.expires_at {
                Some(expires) => format!("{name} ({}, until {expires})", lease.phase),
                None => format!("{name} ({})", lease.phase),
            }
        })
        .collect();
    live.sort();
    if live.is_empty() {
        ok("leases", "no active sandboxes")
    } else {
        ok(
            "leases",
            format!("{} active: {}", live.len(), live.join("; ")),
        )
    }
}

fn public_key_check(config: Option<&CliConfig>) -> Check {
    let configured = config.and_then(|config| config.ssh_public_key.as_deref());
    match ssh_proxy::resolve_public_key(None, configured) {
        Ok(key) => {
            let mut words = key.split_whitespace();
            let kind = words.next().unwrap_or("?");
            let comment = words.nth(1).unwrap_or("");
            ok("public key", format!("{kind} {comment}").trim().to_string())
        }
        Err(error) => fail(
            "public key",
            error.to_string(),
            "ssh-keygen -t ed25519, or kobe init --public-key <path>",
        ),
    }
}

fn ssh_config_checks(executable: Option<&std::path::Path>) -> Vec<Check> {
    let mut checks = Vec::new();
    let kobe_config = match ssh_setup::kobe_ssh_config_path() {
        Ok(path) => path,
        Err(error) => {
            checks.push(fail("ssh config", error.to_string(), ""));
            return checks;
        }
    };
    let user_config = match ssh_setup::user_ssh_config_path() {
        Ok(path) => path,
        Err(error) => {
            checks.push(fail("ssh config", error.to_string(), ""));
            return checks;
        }
    };

    if !kobe_config.is_file() {
        checks.push(fail(
            "ssh config",
            format!("{} does not exist", kobe_config.display()),
            "kobe init",
        ));
    } else {
        let text = std::fs::read_to_string(&user_config).unwrap_or_default();
        checks.push(match ssh_setup::include_state(&text, &kobe_config) {
            ssh_setup::IncludeState::Global => ok(
                "ssh config",
                format!(
                    "{} includes {}",
                    user_config.display(),
                    kobe_config.display()
                ),
            ),
            ssh_setup::IncludeState::Missing => fail(
                "ssh config",
                format!(
                    "{} does not include {}",
                    user_config.display(),
                    kobe_config.display()
                ),
                "kobe init",
            ),
            ssh_setup::IncludeState::Scoped {
                include_line,
                host_line,
            } => fail(
                "ssh config",
                format!(
                    "Include on line {include_line} of {} comes after the Host block on line {host_line}, so it applies to that host only",
                    user_config.display()
                ),
                "kobe init moves it above the first Host",
            ),
        });
    }

    let probe = format!("{}doctor-probe", ssh_proxy::HOST_PREFIX);
    checks.push(
        match ssh_setup::resolved_proxy_command(&user_config, &probe) {
            Ok(Some(command)) if command.contains("ssh-proxy") => {
                let same_binary = executable
                    .map(|path| command.contains(&path.display().to_string()))
                    .unwrap_or(true);
                if same_binary {
                    ok("ssh resolve", format!("ssh -G {probe} → {command}"))
                } else {
                    warn(
                        "ssh resolve",
                        format!("ssh -G {probe} → {command}, which is not this binary"),
                        "kobe init rewrites the block for this binary",
                    )
                }
            }
            Ok(Some(command)) => fail(
                "ssh resolve",
                format!("ssh -G {probe} → {command}, which is not kobe ssh-proxy"),
                "another Host block matches kobe-* first; move Kobe's Include above it",
            ),
            Ok(None) => fail(
                "ssh resolve",
                format!("ssh -G {probe} resolves without a ProxyCommand"),
                "kobe init",
            ),
            Err(error) => fail("ssh resolve", error.to_string(), "install OpenSSH"),
        },
    );
    checks
}
