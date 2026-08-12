mod commands;

use clap::{CommandFactory, Parser, Subcommand};
use commands::OutputFormat;

#[derive(Parser)]
#[command(
    name = "kobe",
    about = "Kubernetes cluster pool manager",
    version = commands::cli_version()
)]
struct Cli {
    /// One-off endpoint override using the selected target's auth.
    #[arg(long, global = true, value_name = "URL")]
    endpoint: Option<String>,

    /// Named CLI target to use.
    #[arg(long = "target", alias = "context", global = true, value_name = "NAME")]
    target: Option<String>,

    /// Output format.
    #[arg(long, short = 'o', global = true, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show status overview
    Status,
    /// Show CLI and endpoint versions
    Version,
    /// Authenticate with the Kobe service.
    ///
    /// Default flow opens the system browser and listens on a localhost
    /// callback. With --device, prints a verification URL + user code
    /// for completing auth on any device with a browser — useful over
    /// SSH, in CI, or on headless hosts.
    Login {
        /// Use the RFC 8628 Device Authorization Grant flow instead of
        /// opening a local browser. Prints a URL + code for the user
        /// to complete on a phone/laptop.
        #[arg(long)]
        device: bool,
    },
    /// Sandbox operations: run commands in a leased agent environment.
    Sandbox {
        #[command(subcommand)]
        action: SandboxAction,
    },
    /// Remove stored credentials. Also revokes the refresh + access
    /// tokens at the IdP (RFC 7009) so a leaked token can't outlive
    /// `kobe logout`.
    Logout,
    /// Lease a cluster from a pool and wait until it is ready
    Lease {
        /// Pool name (e.g. ci-small)
        pool: Option<String>,
        /// Lease TTL
        #[arg(long, default_value = "1h")]
        ttl: String,
        /// Return immediately after creating the lease request
        #[arg(long)]
        no_wait: bool,
        /// Maximum time to wait for the lease to become usable (e.g. 30s, 5m, 1h)
        #[arg(long, value_name = "DURATION", conflicts_with = "no_wait")]
        wait_timeout: Option<String>,
        /// Write kubeconfig to this path (default: ~/.kube/kobe-{pool}-{short-lease}.yaml)
        #[arg(long = "kubeconfig", value_name = "PATH")]
        kubeconfig: Option<String>,
        /// Name this lease (#107 P2). Unique among your active leases, so you can
        /// reference it by name later: `kobe extend pr-106 30m`.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Idempotent (#107 P3): with --name, reuse the existing active lease of
        /// that name (extending its TTL) instead of failing on the duplicate —
        /// "lease again means renew". Safe to call unconditionally at job start.
        #[arg(long, requires = "name")]
        ensure: bool,
        /// Heartbeat-extend the lease until interrupted (#107 P3). Re-extends by
        /// `--ttl` at half-TTL intervals until Ctrl-C or the server ceiling.
        #[arg(long, conflicts_with = "no_wait")]
        keepalive: bool,
    },
    /// Run a command while holding a lease, auto-releasing on exit (#107 P3).
    ///
    /// Creates a lease, heartbeat-extends it for the command's lifetime, then
    /// releases it (even on failure/signal). `kobe with-lease --ttl 1h -- kubectl get pods`.
    WithLease {
        /// Pool name (e.g. ci-small)
        pool: Option<String>,
        /// Lease TTL / heartbeat window
        #[arg(long, default_value = "1h")]
        ttl: String,
        /// Command to run (after `--`), with the lease kubeconfig in KUBECONFIG.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Extend the TTL of an active lease
    ///
    /// TARGET selects the lease by id or pool. When omitted: if you hold a
    /// single active lease it is used; otherwise you are prompted to pick one
    /// (or, with `--output json`, the command errors and lists candidates).
    Extend {
        /// Lease id or pool to extend (optional when you hold one lease)
        target: Option<String>,
        /// Duration to add to the current expiry (e.g. 30m, 1h)
        #[arg(long, default_value = "30m")]
        ttl: String,
    },
    /// Release a cluster lease
    Release {
        /// Lease ID
        lease_id: Option<String>,
    },
    /// Release all active leases and remove local Kobe lease kubeconfigs
    Purge {
        /// Skip the confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,
        /// Only remove kubeconfigs whose lease no longer exists server-side
        /// (phase Released or Expired, or absent from the server entirely).
        /// Active leases are not released. Files in `~/.kube/kobe-*.yaml`
        /// that Kobe never recorded itself are not touched. Use this to clean
        /// up files left behind by TTL expiry.
        #[arg(long)]
        orphans_only: bool,
    },
    /// Manage CLI configuration
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
}

/// Sandbox operations.
///
/// Separate from cluster leases on purpose: a Sandbox is one agent
/// environment, not a cluster, and nothing here can produce a kubeconfig or a
/// credential for the cluster underneath it.
#[derive(Subcommand)]
enum SandboxAction {
    /// Run a command in an existing sandbox and return its exact exit code.
    ///
    /// argv is sent as-is — no shell, so no quoting rules of Kobe's own.
    Exec {
        /// Sandbox lease id.
        lease: String,
        /// Working directory inside the sandbox.
        #[arg(long)]
        cwd: Option<String>,
        /// Wall-clock bound for the command (e.g. `30s`, `5m`).
        #[arg(long)]
        timeout: Option<String>,
        /// The command. Everything after `--`.
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Create a sandbox, run one command in it, and release it.
    ///
    /// The release is attempted on every terminal path, and its failure is
    /// reported separately from the command's result.
    Run {
        /// Sandbox pool.
        pool: String,
        /// Lease TTL (e.g. `2h`).
        #[arg(long)]
        ttl: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        timeout: Option<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Read a bounded tail of the sandbox's output.
    Logs {
        lease: String,
        /// Lines from the end.
        #[arg(long)]
        tail: Option<i64>,
    },
    /// Cancel a running execution.
    Cancel {
        lease: String,
        /// Execution id, as returned by `exec`.
        #[arg(long)]
        execution: String,
    },
    /// Open an interactive session in a sandbox.
    ///
    /// With no command, attaches to the container's existing process.
    Attach {
        lease: String,
        #[arg(long)]
        container: Option<String>,
        /// Run without a terminal. Useful when piping input, where raw mode
        /// would be meaningless.
        #[arg(long)]
        no_tty: bool,
        /// Command to run instead of attaching. Everything after `--`.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Forward a pool-declared sandbox port to a local one.
    ///
    /// `LOCAL:REMOTE`, where REMOTE is a declared port name or number.
    PortForward {
        lease: String,
        /// e.g. `8080:http` or `8080:3000`.
        spec: String,
        /// Local bind address. Defaults to loopback: a forward reachable from
        /// the network turns a port on your machine into a port on the LAN.
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Show current configuration
    View,
    /// Export the saved configuration as JSON
    Export {
        /// Destination path, or '-' for stdout
        path: Option<String>,
    },
    /// Import configuration from JSON
    Import {
        /// Source path, or '-' for stdin
        path: Option<String>,
    },
    /// Edit configuration in the TUI
    Edit {
        /// Target name to edit (defaults to current target, else legacy config)
        name: Option<String>,
    },
    /// List named targets
    List,
    /// Show the current named target
    Current,
    /// Select the current named target
    Use {
        /// Target name
        name: String,
    },
    /// Create or replace a named target. By default writes to the
    /// local `./.kobe.toml` so the definition follows the project;
    /// pass `--global` to write to `~/.config/kobe/config.json`
    /// instead (use this for endpoints you want available from any
    /// directory).
    Set {
        /// Target name
        name: String,
        /// Kobe API endpoint
        #[arg(long)]
        endpoint: String,
        /// Auth mode (none, token, oidc, ssh)
        #[arg(long)]
        auth: Option<String>,
        /// Static bearer token for auth=token
        #[arg(long)]
        token: Option<String>,
        /// SSH key fingerprint for auth=ssh
        #[arg(long = "ssh-fingerprint")]
        ssh_fingerprint: Option<String>,
        /// Write to the global config file (`~/.config/kobe/config.json`)
        /// instead of the local `./.kobe.toml`. Use for endpoints you
        /// reuse across many projects.
        #[arg(long)]
        global: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Two rustls crypto providers are compiled in — ring via reqwest, aws-lc-rs
    // via the WebSocket client's TLS feature — and rustls refuses to choose
    // between them, panicking on the first TLS connection. Installing one here
    // makes that choice deterministic. Ignoring the error is correct: it only
    // fails if a provider is already installed, which is the desired state.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Reap session files whose parent shell has exited. Cheap (one
    // readdir + a process-existence check per file) and idempotent;
    // running it on every invocation keeps the cache directory tidy
    // without needing a daemon or cron job.
    commands::session::gc_dead_sessions();

    let cli = Cli::parse();
    let target = cli.target.as_deref();
    let endpoint = cli.endpoint.as_deref();
    let output = cli.output;

    match cli.command {
        Commands::Status => commands::status(target, endpoint, output).await,
        Commands::Version => commands::version(target, endpoint, output).await,
        Commands::Login { device } => commands::login(target, endpoint, device).await,
        Commands::Logout => commands::logout(target, endpoint).await,
        Commands::Lease {
            pool,
            ttl,
            no_wait,
            wait_timeout,
            kubeconfig,
            name,
            ensure,
            keepalive,
        } => {
            commands::lease_create(commands::LeaseCreateCommand {
                pool: pool.as_deref(),
                ttl: &ttl,
                no_wait,
                wait_timeout: wait_timeout.as_deref(),
                kubeconfig_path: kubeconfig.as_deref(),
                name: name.as_deref(),
                ensure,
                keepalive,
                target_override: target,
                endpoint_override: endpoint,
                output,
            })
            .await
        }
        Commands::WithLease { pool, ttl, cmd } => {
            commands::with_lease(commands::WithLeaseCommand {
                pool: pool.as_deref(),
                ttl: &ttl,
                cmd: &cmd,
                target_override: target,
                endpoint_override: endpoint,
                output,
            })
            .await
        }
        Commands::Extend { target: lease, ttl } => {
            commands::extend(lease.as_deref(), &ttl, target, endpoint, output).await
        }
        // These return the REMOTE command's exit code, so the process exits
        // with it rather than with a generic success. `set -e` in a caller's
        // script depends on exactly this.
        Commands::Sandbox { action } => {
            let code = match action {
                SandboxAction::Exec {
                    lease,
                    cwd,
                    timeout,
                    command,
                } => {
                    commands::sandbox::exec(
                        &lease,
                        &command,
                        cwd.as_deref(),
                        timeout.as_deref(),
                        target,
                        endpoint,
                        output,
                    )
                    .await
                }
                SandboxAction::Run {
                    pool,
                    ttl,
                    cwd,
                    timeout,
                    command,
                } => {
                    commands::sandbox::run(commands::sandbox::RunCommand {
                        pool: &pool,
                        ttl: ttl.as_deref(),
                        argv: &command,
                        cwd: cwd.as_deref(),
                        timeout: timeout.as_deref(),
                        target_override: target,
                        endpoint_override: endpoint,
                        output,
                    })
                    .await
                }
                SandboxAction::Logs { lease, tail } => {
                    commands::sandbox::logs(&lease, tail, target, endpoint, output)
                        .await
                        .map(|()| 0)
                }
                SandboxAction::Cancel { lease, execution } => {
                    commands::sandbox::cancel(&lease, &execution, target, endpoint, output)
                        .await
                        .map(|()| 0)
                }
                SandboxAction::Attach {
                    lease,
                    container,
                    no_tty,
                    command,
                } => {
                    commands::sandbox_transport::attach(
                        &lease,
                        &command,
                        container.as_deref(),
                        !no_tty,
                        target,
                        endpoint,
                    )
                    .await
                }
                SandboxAction::PortForward { lease, spec, bind } => {
                    match commands::sandbox_transport::split_forward_spec(&spec) {
                        Ok((local, remote)) => {
                            commands::sandbox_transport::port_forward(
                                &lease, local, &remote, &bind, target, endpoint, output,
                            )
                            .await
                        }
                        Err(error) => Err(error),
                    }
                }
            };
            match code {
                Ok(0) => Ok(()),
                Ok(code) => std::process::exit(code),
                Err(error) => {
                    eprintln!("kobe: {error:#}");
                    std::process::exit(commands::sandbox::CLI_FAILURE_EXIT)
                }
            }
        }
        Commands::Release { lease_id } => {
            commands::release(lease_id.as_deref(), target, endpoint, output).await
        }
        Commands::Purge { yes, orphans_only } => {
            commands::purge(target, endpoint, output, yes, orphans_only).await
        }
        Commands::Config { action } => match action {
            Some(ConfigAction::View) => commands::config_show(target, output).await,
            Some(ConfigAction::Export { path }) => {
                commands::config_export(path.as_deref(), output).await
            }
            Some(ConfigAction::Import { path }) => {
                commands::config_import(path.as_deref(), output).await
            }
            Some(ConfigAction::Edit { name }) => {
                if let (Some(flag), Some(arg)) = (target, name.as_deref())
                    && flag != arg
                {
                    anyhow::bail!("Specify either --target {flag} or config edit {arg}, not both");
                }
                commands::config_interactive(name.as_deref().or(target))
            }
            Some(ConfigAction::List) => commands::config_list_targets(output).await,
            Some(ConfigAction::Current) => commands::config_current_target(output).await,
            Some(ConfigAction::Use { name }) => commands::config_use_target(&name, output).await,
            Some(ConfigAction::Set {
                name,
                endpoint,
                auth,
                token,
                ssh_fingerprint,
                global,
            }) => {
                commands::config_set_target(
                    &name,
                    &endpoint,
                    auth.as_deref(),
                    token.as_deref(),
                    ssh_fingerprint.as_deref(),
                    global,
                    output,
                )
                .await
            }
            None => print_config_help(),
        },
    }
}

fn print_config_help() -> anyhow::Result<()> {
    let mut cmd = Cli::command();
    let config_cmd = cmd
        .find_subcommand_mut("config")
        .ok_or_else(|| anyhow::anyhow!("config command is not available"))?;
    config_cmd.print_help()?;
    println!();
    Ok(())
}
