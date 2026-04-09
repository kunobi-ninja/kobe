mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kobe", about = "Kubernetes cluster pool manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show status overview (server, pools, leases)
    Status,
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
    Show,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => commands::status().await,
        Commands::Login => commands::login().await,
        Commands::Logout => commands::logout().await,
        Commands::Pools => commands::pools().await,
        Commands::Lease { action } => match action {
            LeaseAction::Create { pool, ttl, output } => {
                commands::claim(&pool, &ttl, output.as_deref()).await
            }
            LeaseAction::List => commands::leases().await,
            LeaseAction::Release { lease_id } => commands::release(&lease_id).await,
        },
        Commands::Config { action } => match action {
            Some(ConfigAction::Set { key, value }) => commands::config_set(&key, &value).await,
            Some(ConfigAction::Show) => commands::config_show().await,
            None => commands::config_interactive(),
        },
    }
}
