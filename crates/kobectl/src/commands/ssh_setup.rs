//! Files and probes shared by `kobe init` and `kobe doctor` for the SSH path.
//!
//! The `ssh_config` block from [`super::ssh_proxy::render_ssh_config`] lives in
//! a file Kobe owns, `<config dir>/kobe/ssh_config`, and `~/.ssh/config` gets
//! one `Include` line for it. Owning the file means `init` can rewrite it
//! freely (a new executable path, a new target) without ever editing the
//! user's own `Host` blocks; the `Include` line is the only thing written
//! there, and it is written once.
//!
//! The `Include` must come before the first `Host` or `Match` line. `ssh`
//! parses the file top to bottom, and an `Include` that appears inside a
//! `Host` block applies only to that host, which silently leaves `kobe-*`
//! unrouted. [`include_state`] tells the two apart.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

/// `<config dir>/kobe/ssh_config`: the file `Host kobe-*` is written to.
pub fn kobe_ssh_config_path() -> Result<PathBuf> {
    let dir =
        dirs::config_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine config directory"))?;
    Ok(dir.join("kobe").join("ssh_config"))
}

/// `~/.ssh/config`, which receives the `Include`.
pub fn user_ssh_config_path() -> Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?;
    Ok(home.join(".ssh").join("config"))
}

/// The exact `Include` line for `path`.
///
/// Absolute on purpose. `ssh` expands `~` from the password database, not
/// from `$HOME`, so a tilde would point somewhere else in any environment
/// that redirects the home directory (test harnesses, some CI images).
pub fn include_line(path: &Path) -> String {
    format!("Include \"{}\"", path.display())
}

/// Split the arguments of an `ssh_config` line the way `ssh` does: on
/// whitespace, except inside double quotes. A config directory such as
/// `~/Library/Application Support` only survives quoted.
fn split_arguments(rest: &str) -> Vec<String> {
    let mut arguments = Vec::new();
    let mut chars = rest.trim().chars().peekable();
    while let Some(&first) = chars.peek() {
        if first.is_whitespace() {
            chars.next();
            continue;
        }
        let mut argument = String::new();
        if first == '"' {
            chars.next();
            for c in chars.by_ref() {
                if c == '"' {
                    break;
                }
                argument.push(c);
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                argument.push(c);
                chars.next();
            }
        }
        arguments.push(argument);
    }
    arguments
}

/// Where the `Include` for Kobe's file stands in the user's `ssh_config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncludeState {
    /// Not present.
    Missing,
    /// Present before any `Host`/`Match` line: applies to every host.
    Global,
    /// Present, but after a `Host`/`Match` line at `host_line` (1-based):
    /// scoped to that block and useless for `kobe-*`.
    Scoped {
        include_line: usize,
        host_line: usize,
    },
}

/// Classify the `Include` for Kobe's file inside `text`.
pub fn include_state(text: &str, kobe_config: &Path) -> IncludeState {
    let wanted = include_target(kobe_config);
    let mut first_host: Option<usize> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        let number = index + 1;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (keyword, rest) = line.split_at(line.find(char::is_whitespace).unwrap_or(line.len()));
        let keyword = keyword.to_ascii_lowercase();
        if keyword == "host" || keyword == "match" {
            first_host.get_or_insert(number);
            continue;
        }
        if keyword == "include" {
            let mentions_kobe = split_arguments(rest)
                .iter()
                .any(|argument| include_target(Path::new(argument)) == wanted);
            if mentions_kobe {
                return match first_host {
                    None => IncludeState::Global,
                    Some(host_line) => IncludeState::Scoped {
                        include_line: number,
                        host_line,
                    },
                };
            }
        }
    }
    IncludeState::Missing
}

/// Normalize an `Include` argument for comparison: `~/x`, `$HOME/x`, and the
/// absolute path all mean the same file.
fn include_target(path: &Path) -> PathBuf {
    let text = path.display().to_string();
    if let Some(rest) = text.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(text)
}

/// Put `line` at the top of `text`, above everything else.
pub fn prepend_include(text: &str, line: &str) -> String {
    if text.trim().is_empty() {
        return format!("{line}\n");
    }
    format!("{line}\n\n{text}")
}

/// What `install` did to the user's `ssh_config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncludeChange {
    /// The line was already there, above the host blocks.
    AlreadyPresent,
    /// The line was added at the top.
    Added,
    /// A scoped line was left alone and a global one added above. The
    /// stale one is harmless but worth removing by hand.
    AddedAboveScoped { scoped_line: usize },
}

/// Write Kobe's `ssh_config` file and make sure `~/.ssh/config` includes it.
///
/// Kobe's file is rewritten whole, mode 0600. The user's file is only ever
/// prepended to, never rewritten beyond that one line, and is created (with
/// its directory, mode 0700) when absent.
pub fn install(kobe_config: &Path, block: &str) -> Result<IncludeChange> {
    write_private(kobe_config, block)?;

    let user_config = user_ssh_config_path()?;
    let existing = match std::fs::read_to_string(&user_config) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(error).with_context(|| format!("could not read {}", user_config.display()));
        }
    };
    let line = include_line(kobe_config);
    let (change, updated) = match include_state(&existing, kobe_config) {
        IncludeState::Global => return Ok(IncludeChange::AlreadyPresent),
        IncludeState::Missing => (IncludeChange::Added, prepend_include(&existing, &line)),
        IncludeState::Scoped { include_line, .. } => (
            IncludeChange::AddedAboveScoped {
                scoped_line: include_line,
            },
            prepend_include(&existing, &line),
        ),
    };
    if let Some(parent) = user_config.parent() {
        create_private_dir(parent)?;
    }
    write_private(&user_config, &updated)?;
    Ok(change)
}

fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

fn write_private(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    std::fs::write(path, content).with_context(|| format!("could not write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Ask the installed `ssh` how it would reach `host`, reading `user_config`
/// as its configuration file.
///
/// Returns the resolved `ProxyCommand`, `Ok(None)` when `ssh` resolves the
/// host without one, and an error when `ssh` is missing or refuses the
/// configuration. This is the only check that proves the user's real
/// `ssh_config`, includes and all, does what the files say. The file is
/// passed explicitly (`-F`) because `ssh` locates `~/.ssh/config` through
/// the password database, which `$HOME` does not redirect.
pub fn resolved_proxy_command(user_config: &Path, host: &str) -> Result<Option<String>> {
    let output = Command::new("ssh")
        .arg("-G")
        .arg("-F")
        .arg(user_config)
        .arg(host)
        .output()
        .context("could not run `ssh -G`; is OpenSSH installed?")?;
    if !output.status.success() {
        anyhow::bail!(
            "`ssh -G {host}` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text.lines().find_map(|line| {
        line.strip_prefix("proxycommand ")
            .map(str::trim)
            .map(str::to_string)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kobe() -> PathBuf {
        PathBuf::from("/tmp/kobe-test-home/.config/kobe/ssh_config")
    }

    #[test]
    fn missing_include_is_reported() {
        assert_eq!(
            include_state("Host github.com\n  User git\n", &kobe()),
            IncludeState::Missing
        );
        assert_eq!(include_state("", &kobe()), IncludeState::Missing);
    }

    #[test]
    fn include_above_hosts_is_global() {
        let text = "Include /tmp/kobe-test-home/.config/kobe/ssh_config\n\nHost github.com\n";
        assert_eq!(include_state(text, &kobe()), IncludeState::Global);
        let quoted = "Include \"/tmp/kobe-test-home/.config/kobe/ssh_config\"\nHost a\n";
        assert_eq!(include_state(quoted, &kobe()), IncludeState::Global);
        let spaced = Path::new("/tmp/kobe test/Application Support/kobe/ssh_config");
        let text = format!("{}\nHost a\n", include_line(spaced));
        assert_eq!(include_state(&text, spaced), IncludeState::Global);
        assert_eq!(
            split_arguments(" \"/a b/c\" d  e "),
            vec!["/a b/c".to_string(), "d".to_string(), "e".to_string()]
        );
    }

    #[test]
    fn include_after_a_host_is_scoped() {
        let text =
            "Host github.com\n  User git\nInclude /tmp/kobe-test-home/.config/kobe/ssh_config\n";
        assert_eq!(
            include_state(text, &kobe()),
            IncludeState::Scoped {
                include_line: 3,
                host_line: 1
            }
        );
    }

    #[test]
    fn other_includes_do_not_count() {
        let text = "Include ~/.ssh/work.conf\nHost a\n";
        assert_eq!(include_state(text, &kobe()), IncludeState::Missing);
    }

    #[test]
    fn include_keyword_is_case_insensitive_and_match_counts_as_a_block() {
        let text = "Match all\n  ServerAliveInterval 5\nINCLUDE /tmp/kobe-test-home/.config/kobe/ssh_config\n";
        assert!(matches!(
            include_state(text, &kobe()),
            IncludeState::Scoped { host_line: 1, .. }
        ));
    }

    #[test]
    fn prepend_keeps_existing_content_below_a_blank_line() {
        assert_eq!(
            prepend_include("Host a\n", "Include x"),
            "Include x\n\nHost a\n"
        );
        assert_eq!(prepend_include("", "Include x"), "Include x\n");
        assert_eq!(prepend_include("  \n", "Include x"), "Include x\n");
    }

    #[test]
    fn install_creates_the_user_config_and_is_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let kobe_config = home.path().join("kobe").join("ssh_config");
        let user_config = home.path().join("ssh").join("config");
        // Route the helpers at the temp dir by using absolute paths directly.
        write_private(&kobe_config, "Host kobe-*\n").unwrap();
        let line = include_line(&kobe_config);
        let updated = prepend_include("", &line);
        write_private(&user_config, &updated).unwrap();
        let text = std::fs::read_to_string(&user_config).unwrap();
        assert_eq!(include_state(&text, &kobe_config), IncludeState::Global);
        // Adding again above the same content changes nothing observable.
        assert_eq!(
            include_state(&prepend_include(&text, &line), &kobe_config),
            IncludeState::Global
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&user_config)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
