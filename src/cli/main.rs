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
        } => {
            commands::lease_create(commands::LeaseCreateCommand {
                pool: pool.as_deref(),
                ttl: &ttl,
                no_wait,
                wait_timeout: wait_timeout.as_deref(),
                kubeconfig_path: kubeconfig.as_deref(),
                target_override: target,
                endpoint_override: endpoint,
                output,
            })
            .await
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
