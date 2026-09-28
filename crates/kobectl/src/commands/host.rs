//! `kobe host`: machines reached over plain SSH, such as a self-hosted CI Mac.
//!
//! A host is not a lease. Nothing is created, reserved or recycled; the
//! machine is always there and may be busy with other work. Every verb runs
//! the system `ssh`, so a host is reachable exactly when `ssh <dest>` is, with
//! the user's own `~/.ssh/config`, agent and keys.
//!
//! `kobe vnc --host` carries the RFB stream over `ssh -W`, so no local port is
//! opened and nothing on the host changes: macOS Screen Sharing is the server,
//! and [`super::vnc::handshake`] logs in with Apple's security type 30.

use anyhow::{Context, Result, bail};
use std::process::Stdio;
use tokio::process::Command;

use super::OutputFormat;
use super::config::{CliConfig, KobeHost, remove_host, write_host};
use super::print_json;
use super::vnc::{Credentials, VncAction, drive};

/// Screen Sharing's port.
const DEFAULT_VNC_PORT: u16 = 5900;

/// Look a host up in the merged global and local config.
pub(crate) fn lookup(name: &str) -> Result<KobeHost> {
    let config = CliConfig::load()?;
    config.hosts.get(name).cloned().ok_or_else(|| {
        let known: Vec<_> = config.hosts.keys().cloned().collect();
        if known.is_empty() {
            anyhow::anyhow!(
                "no host named {name}; add one with: kobe host set {name} --ssh USER@ADDR"
            )
        } else {
            anyhow::anyhow!("no host named {name}; known hosts: {}", known.join(", "))
        }
    })
}

/// How a secret reference is read. Kept separate from running it so the
/// parsing is testable without 1Password or a keychain.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SecretSource {
    /// `op://vault/item/field`, read with `op read`.
    OnePassword(String),
    /// `keychain:<service>`, read with `security find-generic-password -w -s`.
    Keychain(String),
    /// `env:<VAR>`.
    Env(String),
    /// `cmd:<shell command>`, whose trimmed stdout is the secret.
    Command(String),
}

impl SecretSource {
    pub(crate) fn parse(reference: &str) -> Result<Self> {
        if reference.starts_with("op://") {
            return Ok(Self::OnePassword(reference.to_string()));
        }
        let (scheme, rest) = reference.split_once(':').unwrap_or(("", reference));
        let rest = rest.to_string();
        match scheme {
            "keychain" if !rest.is_empty() => Ok(Self::Keychain(rest)),
            "env" if !rest.is_empty() => Ok(Self::Env(rest)),
            "cmd" if !rest.is_empty() => Ok(Self::Command(rest)),
            _ => bail!(
                "vnc_password must be a reference, not a password: op://vault/item/field, \
                 keychain:<service>, env:<VAR> or cmd:<command>"
            ),
        }
    }
}

/// Read the secret a reference points at. Nothing is cached or written.
pub(crate) async fn resolve_secret(reference: &str) -> Result<String> {
    let (program, args): (&str, Vec<String>) = match SecretSource::parse(reference)? {
        SecretSource::Env(var) => {
            return std::env::var(&var).with_context(|| format!("{var} is not set"));
        }
        SecretSource::OnePassword(uri) => ("op", vec!["read".into(), uri]),
        SecretSource::Keychain(service) => (
            "security",
            vec![
                "find-generic-password".into(),
                "-w".into(),
                "-s".into(),
                service,
            ],
        ),
        SecretSource::Command(command) => ("sh", vec!["-c".into(), command]),
    };
    let result = Command::new(program)
        .args(&args)
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .await
        .with_context(|| format!("could not run {program} to read the VNC password"))?;
    if !result.status.success() {
        bail!(
            "{program} could not read the VNC password ({})",
            result.status
        );
    }
    let secret = String::from_utf8(result.stdout)
        .context("the VNC password is not UTF-8")?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    if secret.is_empty() {
        bail!("{program} returned an empty VNC password");
    }
    Ok(secret)
}

/// The Screen Sharing account: `vnc_user`, else the user in the SSH
/// destination, else the local user.
pub(crate) fn vnc_user(host: &KobeHost) -> Option<String> {
    if let Some(user) = &host.vnc_user {
        return Some(user.clone());
    }
    if let Some((user, _)) = host.ssh.split_once('@') {
        return Some(user.to_string());
    }
    std::env::var("USER").ok()
}

/// `ssh` arguments that pipe one TCP connection to `127.0.0.1:<port>` on the
/// host through the SSH session's stdin and stdout.
pub(crate) fn stream_args(host: &KobeHost, port: u16) -> Vec<String> {
    vec![
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-W".into(),
        format!("127.0.0.1:{port}"),
        host.ssh.clone(),
    ]
}

/// `ssh` arguments that run `command` on the host. `--` keeps the command's
/// own flags away from ssh.
pub(crate) fn exec_args(host: &KobeHost, command: &[String]) -> Vec<String> {
    let mut args = vec![host.ssh.clone(), "--".into()];
    args.extend(command.iter().cloned());
    args
}

/// `ssh` arguments that listen on `bind:local` and forward to `remote` on the
/// host's loopback.
pub(crate) fn forward_args(host: &KobeHost, bind: &str, spec: &str) -> Result<Vec<String>> {
    let (local, remote) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("port-forward takes LOCAL:REMOTE, e.g. 5901:5900"))?;
    let local: u16 = local.parse().context("LOCAL must be a port number")?;
    let remote: u16 = remote.parse().context("REMOTE must be a port number")?;
    Ok(vec![
        "-N".into(),
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-L".into(),
        format!("{bind}:{local}:127.0.0.1:{remote}"),
        host.ssh.clone(),
    ])
}

async fn run_ssh(args: Vec<String>) -> Result<i32> {
    let status = Command::new("ssh")
        .args(&args)
        .status()
        .await
        .context("could not run ssh")?;
    Ok(status.code().unwrap_or(255))
}

/// `kobe host exec <name> -- <command>`: the remote exit code, or 255 when
/// ssh itself failed, as ssh reports it.
pub(crate) async fn exec(name: &str, command: &[String]) -> Result<i32> {
    let host = lookup(name)?;
    run_ssh(exec_args(&host, command)).await
}

/// `kobe host port-forward <name> LOCAL:REMOTE`, until interrupted.
pub(crate) async fn port_forward(name: &str, spec: &str, bind: &str) -> Result<i32> {
    let host = lookup(name)?;
    let args = forward_args(&host, bind, spec)?;
    eprintln!("Forwarding {bind}:{spec} to {name}; Ctrl-C stops it");
    run_ssh(args).await
}

/// `kobe host ssh <name>`: an interactive shell.
pub(crate) async fn shell(name: &str) -> Result<i32> {
    let host = lookup(name)?;
    run_ssh(vec![host.ssh]).await
}

/// `kobe vnc <action> --host <name>`: log in to Screen Sharing over
/// `ssh -W` and run one action.
pub(crate) async fn vnc(
    name: &str,
    port: Option<u16>,
    action: VncAction,
    output: OutputFormat,
) -> Result<i32> {
    let host = lookup(name)?;
    let reference = host.vnc_password.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "host {name} has no vnc_password; set one with: kobe host set {name} --ssh {} \
             --vnc-password op://VAULT/ITEM/password",
            host.ssh
        )
    })?;
    let user = vnc_user(&host)
        .ok_or_else(|| anyhow::anyhow!("host {name} has no vnc_user and USER is not set"))?;
    let credentials = Credentials {
        user,
        password: resolve_secret(reference).await?,
    };
    let port = port.or(host.vnc_port).unwrap_or(DEFAULT_VNC_PORT);

    let mut child = Command::new("ssh")
        .args(stream_args(&host, port))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("could not run ssh")?;
    let reader = child.stdout.take().expect("stdout is piped");
    let writer = child.stdin.take().expect("stdin is piped");
    let mut stream = tokio::io::join(reader, writer);

    let result = drive(&mut stream, Some(&credentials), action, name, output).await;
    drop(stream);
    let _ = child.kill().await;
    result.with_context(|| format!("VNC to {name} ({}) failed", host.ssh))
}

/// `kobe vnc open --host <name>`: forward Screen Sharing to a local port and
/// open it in the system VNC viewer (Screen Sharing on macOS), which asks for
/// the account itself. Runs until interrupted.
pub(crate) async fn open_vnc(
    name: &str,
    port: Option<u16>,
    local_port: u16,
    launch_viewer: bool,
) -> Result<i32> {
    let host = lookup(name)?;
    let remote = port.or(host.vnc_port).unwrap_or(DEFAULT_VNC_PORT);
    let local = if local_port == 0 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        listener.local_addr()?.port()
    } else {
        local_port
    };
    let mut forward = Command::new("ssh")
        .args(forward_args(
            &host,
            "127.0.0.1",
            &format!("{local}:{remote}"),
        )?)
        .kill_on_drop(true)
        .spawn()
        .context("could not run ssh")?;
    let url = format!("vnc://127.0.0.1:{local}");
    // Give ssh a moment to bind before the viewer connects.
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", local)).is_ok() {
            break;
        }
        if let Some(status) = forward.try_wait()? {
            bail!("ssh exited before the forward was up ({status})");
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    println!("{name} Screen Sharing at {url}; Ctrl-C stops it");
    if launch_viewer {
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        let _ = std::process::Command::new(opener).arg(&url).status();
    }
    let status = forward.wait().await?;
    Ok(status.code().unwrap_or(0))
}

/// Arguments of `kobe host set`.
pub struct SetHostCommand<'a> {
    pub name: &'a str,
    pub ssh: &'a str,
    pub vnc_user: Option<&'a str>,
    pub vnc_password: Option<&'a str>,
    pub vnc_port: Option<u16>,
    pub local: bool,
    pub output: OutputFormat,
}

pub async fn set(command: SetHostCommand<'_>) -> Result<()> {
    if let Some(reference) = command.vnc_password {
        // Refuse a literal password before it reaches a file.
        SecretSource::parse(reference)?;
    }
    let host = KobeHost {
        ssh: command.ssh.to_string(),
        vnc_user: command.vnc_user.map(str::to_string),
        vnc_password: command.vnc_password.map(str::to_string),
        vnc_port: command.vnc_port,
    };
    let path = write_host(command.name, host.clone(), command.local)?;
    match command.output {
        OutputFormat::Text => {
            println!("Set host {}", command.name);
            println!("Wrote: {}", super::home_path(&path));
        }
        OutputFormat::Json => print_json(&serde_json::json!({
            "name": command.name,
            "host": host,
            "path": path.display().to_string(),
        }))?,
    }
    Ok(())
}

pub async fn list(output: OutputFormat) -> Result<()> {
    let config = CliConfig::load()?;
    match output {
        OutputFormat::Json => print_json(&config.hosts)?,
        OutputFormat::Text if config.hosts.is_empty() => {
            println!("No hosts. Add one with: kobe host set NAME --ssh USER@ADDR");
        }
        OutputFormat::Text => {
            for (name, host) in &config.hosts {
                let vnc = match &host.vnc_password {
                    Some(_) => format!(
                        "vnc {}@:{}",
                        vnc_user(host).unwrap_or_default(),
                        host.vnc_port.unwrap_or(DEFAULT_VNC_PORT)
                    ),
                    None => "no vnc".to_string(),
                };
                println!("{name}\t{}\t{vnc}", host.ssh);
            }
        }
    }
    Ok(())
}

pub async fn remove(name: &str, local: bool, output: OutputFormat) -> Result<()> {
    let removed = remove_host(name, local)?;
    if !removed {
        bail!(
            "no host named {name} in the {} config",
            if local { "local" } else { "global" }
        );
    }
    match output {
        OutputFormat::Text => println!("Removed host {name}"),
        OutputFormat::Json => print_json(&serde_json::json!({ "name": name, "removed": true }))?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(ssh: &str) -> KobeHost {
        KobeHost {
            ssh: ssh.into(),
            vnc_user: None,
            vnc_password: None,
            vnc_port: None,
        }
    }

    #[test]
    fn references_parse_and_a_literal_password_is_refused() {
        assert_eq!(
            SecretSource::parse("op://Zondax/macos ci/password").unwrap(),
            SecretSource::OnePassword("op://Zondax/macos ci/password".into())
        );
        assert_eq!(
            SecretSource::parse("keychain:ci-mac").unwrap(),
            SecretSource::Keychain("ci-mac".into())
        );
        assert_eq!(
            SecretSource::parse("env:PW").unwrap(),
            SecretSource::Env("PW".into())
        );
        assert_eq!(
            SecretSource::parse("cmd:pass show ci").unwrap(),
            SecretSource::Command("pass show ci".into())
        );
        for literal in ["hunter2", "keychain:", "env:", "http://x"] {
            assert!(SecretSource::parse(literal).is_err(), "{literal}");
        }
    }

    #[tokio::test]
    async fn a_command_reference_yields_its_trimmed_stdout() {
        assert_eq!(resolve_secret("cmd:printf 'pw\\n'").await.unwrap(), "pw");
        assert!(
            resolve_secret("cmd:true").await.is_err(),
            "empty is refused"
        );
        assert!(resolve_secret("cmd:exit 3").await.is_err());
    }

    #[test]
    fn the_vnc_user_defaults_to_the_ssh_user() {
        assert_eq!(vnc_user(&host("ci@mac")).as_deref(), Some("ci"));
        let named = KobeHost {
            vnc_user: Some("admin".into()),
            ..host("ci@mac")
        };
        assert_eq!(vnc_user(&named).as_deref(), Some("admin"));
    }

    #[test]
    fn ssh_arguments_keep_the_remote_side_on_loopback() {
        let mac = host("ci@192.168.64.10");
        assert_eq!(
            stream_args(&mac, 5900),
            [
                "-o",
                "ExitOnForwardFailure=yes",
                "-W",
                "127.0.0.1:5900",
                "ci@192.168.64.10"
            ]
        );
        assert_eq!(
            forward_args(&mac, "127.0.0.1", "5901:5900").unwrap(),
            [
                "-N",
                "-o",
                "ExitOnForwardFailure=yes",
                "-L",
                "127.0.0.1:5901:127.0.0.1:5900",
                "ci@192.168.64.10"
            ]
        );
        assert!(forward_args(&mac, "127.0.0.1", "5900").is_err());
        assert_eq!(
            exec_args(&mac, &["uname".into(), "-a".into()]),
            ["ci@192.168.64.10", "--", "uname", "-a"]
        );
    }
}
