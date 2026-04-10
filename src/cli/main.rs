mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "kobe",
    about = "Kubernetes cluster pool manager",
    version = commands::cli_version()
)]
struct Cli {
    /// One-off endpoint override using the selected context's auth.
    #[arg(long, global = true, value_name = "URL")]
    endpoint: Option<String>,

    /// Named CLI context to use.
    #[arg(long, global = true, value_name = "NAME")]
    context: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show status overview (server, pools, leases)
    Status,
    /// Show CLI and endpoint versions
    Version,
    /// Authenticate with the Kobe service
    Login,
    /// Remove stored credentials
    Logout,
    /// List available cluster pools
    Pools,
    /// Manage cluster leases
    Lease {
        #[command(subcommand)]
        action: LeaseAction,
    },
    /// Manage CLI configuration (interactive if no subcommand)
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
}

#[derive(Subcommand)]
enum LeaseAction {
    /// Create a new lease (claim a cluster from a pool)
    Create {
        /// Pool name (e.g. ci-small)
        pool: String,
        /// Lease TTL
        #[arg(long, default_value = "1h")]
        ttl: String,
        /// Write kubeconfig to this path (default: ~/.kube/kobe-{lease-id})
        #[arg(long, short)]
        output: Option<String>,
    },
    /// List your active leases
    List,
    /// Release a cluster lease
    Release {
        /// Lease ID
        lease_id: String,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Set a configuration value
    Set {
        /// Key (endpoint, auth, token, ssh-fingerprint)
        key: String,
        /// Value
        value: String,
    },
    /// Show current configuration
    View,
    /// List named contexts
    GetContexts,
    /// Show the current named context
    CurrentContext,
    /// Select the current named context
    UseContext {
        /// Context name
        name: String,
    },
    /// Create or replace a named context
    SetContext {
        /// Context name
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
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let context = cli.context.as_deref();
    let endpoint = cli.endpoint.as_deref();

    match cli.command {
        Commands::Status => commands::status(context, endpoint).await,
        Commands::Version => commands::version(context, endpoint).await,
        Commands::Login => commands::login(context, endpoint).await,
        Commands::Logout => commands::logout(context, endpoint).await,
        Commands::Pools => commands::pools(context, endpoint).await,
        Commands::Lease { action } => match action {
            LeaseAction::Create { pool, ttl, output } => {
                commands::claim(&pool, &ttl, output.as_deref(), context, endpoint).await
            }
            LeaseAction::List => commands::leases(context, endpoint).await,
            LeaseAction::Release { lease_id } => {
                commands::release(&lease_id, context, endpoint).await
            }
        },
        Commands::Config { action } => match action {
            Some(ConfigAction::Set { key, value }) => commands::config_set(&key, &value).await,
            Some(ConfigAction::View) => commands::config_show(context).await,
            Some(ConfigAction::GetContexts) => commands::config_contexts().await,
            Some(ConfigAction::CurrentContext) => commands::config_current_context().await,
            Some(ConfigAction::UseContext { name }) => commands::config_use_context(&name).await,
            Some(ConfigAction::SetContext {
                name,
                endpoint,
                auth,
                token,
                ssh_fingerprint,
            }) => {
                commands::config_set_context(
                    &name,
                    &endpoint,
                    auth.as_deref(),
                    token.as_deref(),
                    ssh_fingerprint.as_deref(),
                )
                .await
            }
            None => commands::config_interactive(),
        },
    }
}
