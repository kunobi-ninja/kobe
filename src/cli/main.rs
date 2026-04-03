mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kobe", about = "Claim Kubernetes clusters from Kobe pools")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate with the Kobe service
    Login,
    /// Remove stored credentials
    Logout,
    /// List available cluster pools
    Pools,
    /// Claim a cluster from a pool
    Claim {
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
    Leases,
    /// Release a cluster lease
    Release {
        /// Lease ID
        lease_id: String,
    },
    /// Manage CLI configuration (interactive if no subcommand)
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Set a configuration value
    Set {
        /// Key (endpoint, auth, token)
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
        Commands::Login => commands::login().await,
        Commands::Logout => commands::logout().await,
        Commands::Pools => commands::pools().await,
        Commands::Claim { pool, ttl, output } => {
            commands::claim(&pool, &ttl, output.as_deref()).await
        }
        Commands::Leases => commands::leases().await,
        Commands::Release { lease_id } => commands::release(&lease_id).await,
        Commands::Config { action } => match action {
            Some(ConfigAction::Set { key, value }) => commands::config_set(&key, &value).await,
            Some(ConfigAction::Show) => commands::config_show().await,
            None => commands::config_interactive(),
        },
    }
}
