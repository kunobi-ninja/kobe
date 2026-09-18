//! `kobe ssh-proxy` and `kobe ssh-config`: reach a sandbox with an ordinary
//! SSH client.
//!
//! An SSH client configured with
//!
//! ```text
//! Host kobe-*
//!     ProxyCommand kobe ssh-proxy %n
//! ```
//!
//! runs this command instead of opening a TCP connection, and speaks the SSH
//! protocol over its stdin and stdout. The command resolves the host name to
//! one of the caller's sandboxes, creating it when the name is new, authorizes
//! the caller's public key inside it, and then hands the stream to
//! [`super::sandbox_transport::attach`] running `kobe-sshd` in the sandbox.
//! From there the bytes are SSH end to end; Kobe carries them without reading
//! them.
//!
//! One SSH connection is one Kobe operation, however many sessions the client
//! multiplexes over it. That is what keeps a multiplexing client (a terminal
//! that opens many panes on one host) inside the per-sandbox operation limit.
//!
//! # Host names
//!
//! `kobe-<pool>-<name>` selects the pool by name; `kobe-<name>` uses the
//! target's `default_pool`. A sandbox created here is aliased to the whole
//! host name, lowercased, so `kobe-small-1` and `kobe-small-2` are two
//! sandboxes and another user's `kobe-small-1` is a third: aliases are scoped
//! to the caller.
//!
//! Connecting tries that whole-host alias first and then `<name>` on its own
//! within the named pool, because `kobe lease --name dev` aliases its lease
//! `dev` — which is also what `kobe attach dev` answers to. Without the second
//! attempt a lease visible in `kobe status` had no host that reached it, and
//! since a miss creates, the failure surfaced as a concurrency error about a
//! sandbox nobody asked for.
//!
//! A dot adds a persistent session: `kobe-dev.main` is sandbox `kobe-dev`,
//! with interactive logins landing in `kobe-runner` session `main`, whose
//! shell outlives the connection. Aliases are DNS labels, so the dot can never
//! be part of one.
//!
//! # stdout is the transport
//!
//! Nothing here may print to stdout. Progress and errors go to stderr, which
//! `ssh` relays to the user. Authorization runs non-interactively for the same
//! reason: a trust prompt would read its answer from bytes that belong to the
//! SSH client. Establish trust once with `kobe status` before the first
//! connection.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;

use super::config::{CliConfig, ResolvedConfig};
use super::{OutputFormat, leases, pools, sandbox, sandbox_transport};

/// Where `kobe-sshd` lives in the workspace images. Passed as attach argv, so
/// the pool's `attachCommand` (typically a multiplexer) is not involved.
const REMOTE_SSHD: &str = "/usr/local/bin/kobe-sshd";

/// The account sshd serves inside the workspace images.
pub const REMOTE_USER: &str = "nonroot";

/// Host-name prefix an SSH client routes here.
pub const HOST_PREFIX: &str = "kobe-";

/// Bound on waiting for a fresh sandbox. `ssh` has no timeout of its own for
/// a ProxyCommand, so this is the only thing standing between a cold pool and
/// a client that hangs forever.
const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Public keys tried, in order, when neither `--public-key` nor the config
/// names one. Ed25519 first because `kobe login` prefers it too.
const DEFAULT_PUBLIC_KEYS: &[&str] = &["id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"];

/// Exit status of [`AUTHORIZE_KEY_SCRIPT`] when the image has no `kobe-sshd`.
///
/// Checked before the attach because the attach cannot report it: a command
/// that does not exist ends the stream, and `ssh` only sees a connection
/// closed before the banner.
const EXIT_NO_SSHD: i32 = 3;

/// Appends the caller's key to `authorized_keys` once, after checking that
/// the image can serve SSH at all. Run with `sh -c`, the key arriving on stdin
/// so it never appears in an argv that the target cluster's audit log records.
const AUTHORIZE_KEY_SCRIPT: &str = r#"[ -x /usr/local/bin/kobe-sshd ] || exit 3
umask 077
mkdir -p "$HOME/.ssh"
file="$HOME/.ssh/authorized_keys"
key="$(cat)"
[ -n "$key" ] || { echo "kobe ssh-proxy: empty public key" >&2; exit 2; }
touch "$file"
grep -qxF -- "$key" "$file" || printf '%s\n' "$key" >> "$file"
"#;

pub struct SshProxyCommand<'a> {
    /// The host name as the SSH client supplied it (`%n`).
    pub host: &'a str,
    /// Pool for a new sandbox. Overrides both the host name and the target's
    /// `default_pool`.
    pub pool: Option<&'a str>,
    /// TTL for a new sandbox. Pool default when unset.
    pub ttl: Option<&'a str>,
    /// Bound on waiting for a new sandbox to become ready.
    pub wait_timeout: Option<&'a str>,
    /// Connect only; never create a sandbox.
    pub no_create: bool,
    /// Public key file to authorize. Config or `~/.ssh` defaults when unset.
    pub public_key: Option<&'a str>,
    pub target_override: Option<&'a str>,
    pub endpoint_override: Option<&'a str>,
}

/// How a host name maps to a sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSpec {
    /// Pool named inside the host, when one of `known_pools` matched.
    pub pool: Option<String>,
    /// The lease alias: the host name up to its first dot, lowercased.
    pub alias: String,
    /// The name after the pool, when the host carries one.
    ///
    /// `kobe-sandbox-dev`, with a `sandbox` pool, parses to
    /// `Some("dev")`. That is what `kobe lease --name` and `kobe attach` call
    /// the lease, so it is the second thing to try when nothing is aliased to
    /// the whole host. Without it a lease the caller can see in `kobe status`
    /// has no SSH host that reaches it, and the miss silently becomes a
    /// create.
    pub name: Option<String>,
    /// The persistent session named after the dot, when there is one.
    pub session: Option<String>,
}

/// Parse `kobe-<pool>-<name>` / `kobe-<name>`.
///
/// The prefix is optional so `kobe ssh-proxy small-1` works by hand, and the
/// alias always keeps the prefix so that leases made by hand and leases made
/// through `ssh` share one namespace. The pool is the longest known pool name
/// that the remainder starts with, so a pool named `ci` and one named
/// `ci-gpu` are both addressable. An unknown pool is not an error here: the
/// caller falls back to the target default, and a genuinely wrong name is
/// diagnosed with the list of pools that exist.
///
/// Everything after the first dot names a session: `kobe-dev.main`.
pub fn parse_host(host: &str, known_pools: &[String]) -> Result<HostSpec> {
    let host = host.trim().to_ascii_lowercase();
    let (host, session) = match host.split_once('.') {
        Some((name, session)) => {
            if !sandbox_transport::is_session_name(session) {
                anyhow::bail!(
                    "session '{session}' in host '{host}' must be lowercase letters, digits and '-', at most 64 characters"
                );
            }
            (name.to_string(), Some(session.to_string()))
        }
        None => (host, None),
    };
    let alias = if host.starts_with(HOST_PREFIX) {
        host.clone()
    } else {
        format!("{HOST_PREFIX}{host}")
    };
    let rest = &alias[HOST_PREFIX.len()..];
    if rest.is_empty() {
        anyhow::bail!("host name must be kobe-<pool>-<name> or kobe-<name>, got '{host}'");
    }
    if alias.len() > 63
        || !alias
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || alias.ends_with('-')
    {
        anyhow::bail!(
            "host name '{host}' is not a valid lease alias: lowercase letters, digits and '-', at most 63 characters, not ending in '-'"
        );
    }
    let mut pool: Option<&String> = None;
    for candidate in known_pools {
        let matches = rest == candidate
            || rest
                .strip_prefix(candidate.as_str())
                .is_some_and(|tail| tail.starts_with('-'));
        if matches && pool.is_none_or(|best| candidate.len() > best.len()) {
            pool = Some(candidate);
        }
    }
    // Whatever follows the matched pool, minus the separating '-'. A host that
    // is only a pool name carries no name, so there is nothing to look up.
    let name = match pool {
        Some(matched) if rest.len() > matched.len() => Some(rest[matched.len() + 1..].to_string()),
        Some(_) => None,
        None => Some(rest.to_string()),
    };
    Ok(HostSpec {
        pool: pool.cloned(),
        alias,
        name,
        session,
    })
}

/// Serve one SSH connection to the sandbox named by `command.host`.
///
/// Returns the exit code for the process: the attach outcome, or Kobe's own
/// failure code when the sandbox could not be resolved or prepared.
pub async fn ssh_proxy(command: SshProxyCommand<'_>) -> Result<i32> {
    if std::io::stdout().is_terminal() {
        anyhow::bail!(
            "ssh-proxy speaks SSH on stdout and is meant to run as an ssh ProxyCommand; \
             run `kobe ssh-config` to install it, then `ssh {}`",
            command.host
        );
    }
    let config = CliConfig::load()?;
    let public_key = resolve_public_key(command.public_key, config.ssh_public_key.as_deref())?;
    let config = config.resolve(command.target_override, command.endpoint_override)?;

    let quiet = OutputFormat::Json;
    let known_pools: Vec<String> = if command.pool.is_some() {
        Vec::new()
    } else {
        pools::fetch_pools_for_config_with_output(&config, quiet)
            .await?
            .into_iter()
            .map(|pool| pool.name)
            .collect()
    };
    let spec = parse_host(command.host, &known_pools)?;

    let ready_timeout = match command.wait_timeout {
        Some(value) => super::lease_create::parse_cli_duration(value)
            .ok_or_else(|| anyhow::anyhow!("Invalid --wait-timeout '{value}'"))?,
        None => DEFAULT_READY_TIMEOUT,
    };

    // Two ways to name the same sandbox. `ssh kobe-<pool>-<name>` aliases the
    // lease to the whole host, while `kobe lease --name <name>` aliases it to
    // the name alone — and `kobe attach <name>` accepts that one. Trying only
    // the first left a lease the caller can see in `kobe status` with no host
    // that reaches it, and because a miss creates, the failure arrived as a
    // concurrency error about a sandbox nobody asked for.
    //
    // The whole host still wins, so a sandbox created through SSH keeps its
    // own alias even if some other lease answers to the bare name.
    let all_leases = leases::fetch_all_leases_with_output(&config, quiet).await?;
    let live = |lease: &leases::LeaseSummary| !leases::is_terminal_phase(&lease.phase);
    let existing = all_leases
        .iter()
        .find(|lease| live(lease) && lease.alias.as_deref() == Some(spec.alias.as_str()))
        .or_else(|| {
            let name = spec.name.as_deref()?;
            all_leases.iter().find(|lease| {
                live(lease)
                    && lease.alias.as_deref() == Some(name)
                    // Only within the pool the host named. Without this, two
                    // pools holding a `dev` each would answer the same host.
                    && spec.pool.as_deref().is_none_or(|pool| lease.profile == pool)
            })
        })
        .cloned();

    let lease_id = match existing {
        Some(lease) if !lease.is_sandbox() => anyhow::bail!(
            "{} is a {} lease, which cannot serve SSH",
            spec.alias,
            lease.resource_kind
        ),
        Some(lease) => {
            if !lease.phase.eq_ignore_ascii_case("ready") {
                eprintln!("kobe: waiting for {} ({})...", spec.alias, lease.id);
                sandbox::wait_ready_quiet(&config, &lease.id, ready_timeout).await?;
            }
            lease.id
        }
        None if command.no_create => anyhow::bail!(
            "no active sandbox named {}; create one with `kobe lease <pool> --name {}`",
            spec.alias,
            spec.alias
        ),
        None => {
            let pool = match command.pool.or(spec.pool.as_deref()) {
                Some(pool) => pool.to_string(),
                None => config.default_pool.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "{} names no pool and the target has no default pool; use kobe-<pool>-<name> \
                         (pools: {}) or set one with `kobe init --default-pool <pool>`",
                        spec.alias,
                        if known_pools.is_empty() {
                            "none visible".to_string()
                        } else {
                            known_pools.join(", ")
                        }
                    )
                })?,
            };
            eprintln!("kobe: creating {} in pool {pool}...", spec.alias);
            let lease = sandbox::create_ready_lease(
                &config,
                &pool,
                command.ttl,
                Some(&spec.alias),
                ready_timeout,
            )
            .await?;
            eprintln!(
                "kobe: {} is ready ({}); release with `kobe release {}`",
                spec.alias, lease.id, spec.alias
            );
            lease.id
        }
    };

    authorize_key(&config, &lease_id, &public_key).await?;

    // With a session, sshd sends interactive logins to it; see `kobe-sshd`.
    let mut remote = vec![REMOTE_SSHD.to_string()];
    if let Some(session) = &spec.session {
        remote.extend(["--session".to_string(), session.clone()]);
    }
    sandbox_transport::attach(
        &lease_id,
        &remote,
        None,
        false,
        command.target_override,
        command.endpoint_override,
        OutputFormat::Text,
    )
    .await
}

/// Put the caller's public key in the sandbox's `authorized_keys`.
///
/// Idempotent, so every connection can afford it: the alternative, remembering
/// which sandbox already has the key, would go stale the moment a lease under
/// the same name is recreated.
async fn authorize_key(config: &ResolvedConfig, lease_id: &str, public_key: &str) -> Result<()> {
    let stdin = base64::engine::general_purpose::STANDARD.encode(format!("{public_key}\n"));
    let argv = [
        "/bin/sh".to_string(),
        "-c".to_string(),
        AUTHORIZE_KEY_SCRIPT.to_string(),
    ];
    let result = sandbox::exec_once(
        config,
        lease_id,
        &argv,
        None,
        Some("30s"),
        Some(&stdin),
        &sandbox::new_idempotency_key(),
        // The key must be in place before the attach, so this one waits.
        false,
        OutputFormat::Json,
    )
    .await
    .with_context(|| {
        format!(
            "could not authorize the public key in {lease_id}; the pool must declare `runnerPath` \
             so `kobe exec` is available"
        )
    })?;
    if result.exit_code == Some(EXIT_NO_SSHD) {
        anyhow::bail!(
            "{lease_id} runs an image without {REMOTE_SSHD}; the pool needs \
             zondax/kobe-sandbox v0.45.0 or newer (release this sandbox with \
             `kobe release {lease_id}` once the pool image is updated)"
        );
    }
    if result.exit_code != Some(0) {
        anyhow::bail!(
            "authorizing the public key in {lease_id} failed ({}): {}",
            result.state,
            result.stderr.unwrap_or_default().trim()
        );
    }
    Ok(())
}

/// Pick the public key file and read it.
///
/// Order: `--public-key`, the config's `ssh_public_key`, then the first of
/// [`DEFAULT_PUBLIC_KEYS`] under `~/.ssh`. A key that is present but not a
/// public key (someone pointed at the private half) is refused rather than
/// sent anywhere.
pub(crate) fn resolve_public_key(flag: Option<&str>, configured: Option<&str>) -> Result<String> {
    let path = match flag.or(configured) {
        Some(explicit) => expand_home(explicit),
        None => {
            let ssh_dir = dirs::home_dir()
                .ok_or_else(|| anyhow::anyhow!("cannot determine the home directory"))?
                .join(".ssh");
            DEFAULT_PUBLIC_KEYS
                .iter()
                .map(|name| ssh_dir.join(name))
                .find(|candidate| candidate.is_file())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no public key found under {}; pass --public-key <path> or set ssh_public_key in the kobe config",
                        ssh_dir.display()
                    )
                })?
        }
    };
    read_public_key(&path)
}

fn read_public_key(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read public key {}", path.display()))?;
    let key = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .unwrap_or_default();
    let is_public = key.split_whitespace().next().is_some_and(|kind| {
        kind.starts_with("ssh-") || kind.starts_with("ecdsa-") || kind.starts_with("sk-")
    });
    if !is_public {
        anyhow::bail!(
            "{} does not look like an OpenSSH public key (expected `ssh-ed25519 AAAA... comment`)",
            path.display()
        );
    }
    Ok(key.to_string())
}

fn expand_home(path: &str) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => dirs::home_dir()
            .map(|home| home.join(rest))
            .unwrap_or_else(|| PathBuf::from(path)),
        None => PathBuf::from(path),
    }
}

/// The `ssh_config` block that routes `kobe-*` through this binary.
///
/// The executable is spelled out in full because `ssh` runs a ProxyCommand
/// through `$SHELL -c` without a login profile, where `kobe` may not be on
/// `PATH`. Host keys are not checked: a recreated lease under the same name
/// has a fresh key, and the far end is already authenticated by Kobe, which
/// only ever attaches this caller to a sandbox this caller owns.
pub fn render_ssh_config(executable: &Path, target: Option<&str>) -> String {
    let mut proxy = format!(
        "{} ssh-proxy",
        shell_quote(&executable.display().to_string())
    );
    if let Some(target) = target {
        proxy.push_str(&format!(" --target {}", shell_quote(target)));
    }
    proxy.push_str(" %n");
    format!(
        "# Kobe sandboxes over SSH. Generated by `kobe ssh-config`.\n\
         # `ssh kobe-<pool>-<name>` leases the sandbox on first use and reuses it after.\n\
         # `ssh kobe-<name>.<session>` logs in to a session that survives disconnects.\n\
         Host {HOST_PREFIX}*\n\
         \x20   User {REMOTE_USER}\n\
         \x20   ProxyCommand {proxy}\n\
         \x20   StrictHostKeyChecking no\n\
         \x20   UserKnownHostsFile /dev/null\n\
         \x20   LogLevel ERROR\n\
         \x20   ServerAliveInterval 30\n\
         \x20   ServerAliveCountMax 4\n"
    )
}

/// Print the `ssh_config` block for the running binary.
pub fn ssh_config(target_override: Option<&str>) -> Result<()> {
    let executable = std::env::current_exe().context("could not resolve the kobe executable")?;
    print!("{}", render_ssh_config(&executable, target_override));
    Ok(())
}

fn shell_quote(value: &str) -> String {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/._-+:@%".contains(&byte))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pools(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn host_names_the_pool_and_keeps_the_prefix_in_the_alias() {
        let spec = parse_host("kobe-small-1", &pools(&["small", "gpu"])).unwrap();
        assert_eq!(spec.pool.as_deref(), Some("small"));
        assert_eq!(spec.alias, "kobe-small-1");
    }

    #[test]
    fn host_without_prefix_gets_the_prefix_back() {
        let spec = parse_host("small-1", &pools(&["small"])).unwrap();
        assert_eq!(spec.alias, "kobe-small-1");
        assert_eq!(spec.pool.as_deref(), Some("small"));
    }

    #[test]
    fn longest_pool_name_wins() {
        let spec = parse_host("kobe-ci-gpu-2", &pools(&["ci", "ci-gpu"])).unwrap();
        assert_eq!(spec.pool.as_deref(), Some("ci-gpu"));
    }

    /// The name after the pool is what `kobe lease --name` and `kobe attach`
    /// call the lease, and the SSH path needs it to reach one they created.
    #[test]
    fn host_carries_the_name_after_the_pool() {
        let spec = parse_host(
            "kobe-sandbox-kache-mutants-m2",
            &pools(&["sandbox"]),
        )
        .unwrap();
        assert_eq!(spec.pool.as_deref(), Some("sandbox"));
        assert_eq!(spec.alias, "kobe-sandbox-kache-mutants-m2");
        assert_eq!(
            spec.name.as_deref(),
            Some("kache-mutants-m2"),
            "the name must survive hyphens, or a lease called kache-mutants-m2 stays unreachable"
        );
    }

    /// A host that is only a pool name has no name to look up, and must not
    /// invent one by stripping the pool off itself.
    #[test]
    fn host_that_is_only_a_pool_carries_no_name() {
        let spec = parse_host("kobe-sandbox", &pools(&["sandbox"])).unwrap();
        assert_eq!(spec.pool.as_deref(), Some("sandbox"));
        assert_eq!(spec.name, None);
    }

    /// With no pool in the host, everything after the prefix is the name, so
    /// `kobe-dev` can still find a lease aliased `dev` in the default pool.
    #[test]
    fn host_without_a_known_pool_is_all_name() {
        let spec = parse_host("kobe-dev", &pools(&["small"])).unwrap();
        assert_eq!(spec.pool, None);
        assert_eq!(spec.name.as_deref(), Some("dev"));
    }

    /// The session suffix belongs to the session, never to the name.
    #[test]
    fn a_session_suffix_does_not_leak_into_the_name() {
        let spec = parse_host("kobe-small-dev.main", &pools(&["small"])).unwrap();
        assert_eq!(spec.name.as_deref(), Some("dev"));
        assert_eq!(spec.session.as_deref(), Some("main"));
        assert_eq!(spec.alias, "kobe-small-dev");
    }

    #[test]
    fn pool_must_be_a_whole_segment() {
        let spec = parse_host("kobe-smallish-1", &pools(&["small"])).unwrap();
        assert_eq!(spec.pool, None);
        assert_eq!(spec.alias, "kobe-smallish-1");
    }

    #[test]
    fn bare_pool_name_is_its_own_alias() {
        let spec = parse_host("kobe-small", &pools(&["small"])).unwrap();
        assert_eq!(spec.pool.as_deref(), Some("small"));
        assert_eq!(spec.alias, "kobe-small");
    }

    #[test]
    fn unknown_pool_is_left_to_the_default() {
        let spec = parse_host("kobe-dev", &pools(&["small"])).unwrap();
        assert_eq!(spec.pool, None);
        assert_eq!(spec.alias, "kobe-dev");
    }

    #[test]
    fn host_is_lowercased() {
        let spec = parse_host("Kobe-Small-1", &pools(&["small"])).unwrap();
        assert_eq!(spec.alias, "kobe-small-1");
        assert_eq!(spec.pool.as_deref(), Some("small"));
    }

    #[test]
    fn invalid_aliases_are_refused() {
        assert!(parse_host("kobe-", &[]).is_err());
        assert!(parse_host("kobe-a_b", &[]).is_err());
        assert!(parse_host("kobe-trailing-", &[]).is_err());
        assert!(parse_host(&format!("kobe-{}", "x".repeat(60)), &[]).is_err());
    }

    /// `kobe-dev.main` is sandbox `kobe-dev`, session `main`.
    #[test]
    fn a_dot_names_a_session_in_the_same_sandbox() {
        let spec = parse_host("kobe-small-1.main", &pools(&["small"])).unwrap();
        assert_eq!(spec.alias, "kobe-small-1");
        assert_eq!(spec.pool.as_deref(), Some("small"));
        assert_eq!(spec.session.as_deref(), Some("main"));

        let plain = parse_host("kobe-small-1", &pools(&["small"])).unwrap();
        assert_eq!(plain.alias, spec.alias, "both reach one sandbox");
        assert_eq!(plain.session, None);

        assert_eq!(
            parse_host("Kobe-Dev.Build-2", &[])
                .unwrap()
                .session
                .as_deref(),
            Some("build-2")
        );
        for bad in ["kobe-a.", "kobe-a.b.c", "kobe-a.b_c", ".main"] {
            assert!(parse_host(bad, &[]).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn public_key_file_is_validated() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("id_ed25519.pub");
        std::fs::write(&good, "ssh-ed25519 AAAAC3Nza test@host\n").unwrap();
        assert_eq!(
            read_public_key(&good).unwrap(),
            "ssh-ed25519 AAAAC3Nza test@host"
        );

        let private = dir.path().join("id_ed25519");
        std::fs::write(&private, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        let error = read_public_key(&private).unwrap_err().to_string();
        assert!(
            error.contains("does not look like an OpenSSH public key"),
            "{error}"
        );
    }

    #[test]
    fn ssh_config_routes_the_prefix_through_the_absolute_executable() {
        let rendered = render_ssh_config(Path::new("/opt/homebrew/bin/kobe"), None);
        assert!(rendered.contains("Host kobe-*\n"));
        assert!(rendered.contains("    ProxyCommand /opt/homebrew/bin/kobe ssh-proxy %n\n"));
        assert!(rendered.contains("    User nonroot\n"));
        assert!(!rendered.contains("--target"));
    }

    #[test]
    fn ssh_config_quotes_paths_and_carries_the_target() {
        let rendered = render_ssh_config(Path::new("/Users/me/my tools/kobe"), Some("work"));
        assert!(
            rendered
                .contains("ProxyCommand '/Users/me/my tools/kobe' ssh-proxy --target work %n\n"),
            "{rendered}"
        );
    }
}
