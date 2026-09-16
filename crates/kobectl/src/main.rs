mod commands;

use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{CommandFactory, Parser, Subcommand, error::ErrorKind};
use commands::OutputFormat;
use std::io::IsTerminal;

/// Help colors, the palette cargo uses. clap strips them when the output is
/// not a terminal, so piped help stays plain text.
const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default())
    .error(AnsiColor::Red.on_default().effects(Effects::BOLD))
    .valid(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .invalid(AnsiColor::Yellow.on_default().effects(Effects::BOLD));

/// Heading for the options every command accepts. Keeping them apart stops
/// them from interleaving with a command's own flags in its help.
const GLOBAL_OPTIONS: &str = "Global options";

#[derive(Parser)]
#[command(
    name = "kobe",
    about = "Lease clusters and sandboxes from Kobe pools",
    version = commands::cli_version(),
    styles = STYLES
)]
struct Cli {
    /// Use this endpoint with the selected target's auth
    #[arg(long, global = true, value_name = "URL", help_heading = GLOBAL_OPTIONS)]
    endpoint: Option<String>,

    /// Use this named target instead of the current one
    #[arg(
        long = "target",
        alias = "context",
        global = true,
        value_name = "NAME",
        help_heading = GLOBAL_OPTIONS
    )]
    target: Option<String>,

    /// Output format
    #[arg(
        long,
        short = 'o',
        global = true,
        value_enum,
        default_value_t = OutputFormat::Text,
        help_heading = GLOBAL_OPTIONS
    )]
    output: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show your leases, the pools you can use, and who you are signed in as
    Status {
        /// Include released and expired leases
        ///
        /// Text and JSON both hide them by default, so the two views agree.
        #[arg(long)]
        all: bool,
    },
    /// Show the CLI and server versions
    Version,
    /// Sign in to the Kobe server
    ///
    /// Opens the system browser and listens on a localhost callback. With
    /// --device, prints a URL and a code to finish sign-in on any device with
    /// a browser instead: over SSH, in CI, or on a headless host.
    Login {
        /// Sign in on another device (RFC 8628 device authorization)
        #[arg(long)]
        device: bool,
    },
    /// Lease a sandbox, run one command in it, and release it
    Run {
        /// Pool to lease from
        pool: String,
        /// Lease TTL, e.g. 2h (pool default when omitted)
        #[arg(long)]
        ttl: Option<String>,
        /// Working directory for the command
        #[arg(long, value_name = "DIR")]
        cwd: Option<String>,
        /// Stop the command after this long, e.g. 30s or 5m
        #[arg(long, value_name = "DURATION")]
        timeout: Option<String>,
        /// The command to run, after `--`
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Run a command in a lease and exit with its exit code
    Exec {
        /// Lease id, name, or pool
        lease: String,
        /// Working directory for the command
        #[arg(long, value_name = "DIR")]
        cwd: Option<String>,
        /// Stop the command after this long, e.g. 30s or 5m
        #[arg(long, value_name = "DURATION")]
        timeout: Option<String>,
        /// Send this process's stdin to the command, then close it
        ///
        /// Use it to pass a secret without putting it on the command line. The
        /// exec argv becomes a URL that the target apiserver audit-logs
        /// verbatim, so `--token s3cret` records the token and
        /// `printf %s "$TOKEN" | kobe exec ... --stdin -- gh auth login
        /// --with-token` does not.
        #[arg(long)]
        stdin: bool,
        /// The command to run, after `--`
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Read a lease's logs, or the output of one execution
    Logs {
        /// Lease id, name, or pool
        lease: String,
        /// Read the output of this execution instead of the lease's logs
        #[arg(long, value_name = "ID", conflicts_with = "tail")]
        execution: Option<String>,
        /// Keep reading until the execution finishes
        #[arg(long, requires = "execution")]
        follow: bool,
        /// Show only the last N lines
        #[arg(long, value_name = "N", conflicts_with = "execution")]
        tail: Option<i64>,
    },
    /// Cancel a running execution
    Cancel {
        /// Lease id, name, or pool
        lease: String,
        /// Execution id, as printed by `kobe exec`
        #[arg(long, value_name = "ID")]
        execution: String,
    },
    /// Open a terminal in a lease
    ///
    /// With no lease, uses the only one you can attach to, or asks you to
    /// pick. With --session, the shell survives disconnects: `~.` at the start
    /// of a line detaches, and attaching again resumes it.
    Attach {
        /// Lease id, name, or pool. `LEASE.NAME` is `LEASE --session NAME`
        lease: Option<String>,
        /// Container to attach to
        #[arg(long)]
        container: Option<String>,
        /// Run without allocating a terminal
        #[arg(long)]
        no_tty: bool,
        /// Attach to a persistent session, creating it on first use
        #[arg(long, value_name = "NAME", conflicts_with = "no_tty")]
        session: Option<String>,
        /// Path of `kobe-runner` in the sandbox, for --session
        #[arg(long, value_name = "PATH", requires = "session")]
        runner_path: Option<String>,
        /// Command to run instead of the default shell, after `--`
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Forward a local port to a port the pool declares
    PortForward {
        /// Lease id, name, or pool
        lease: String,
        /// LOCAL:REMOTE, where REMOTE is a port name or number (8080:http)
        spec: String,
        /// Local address to listen on
        ///
        /// Loopback by default. Binding to a network address exposes the
        /// forwarded port to your LAN.
        #[arg(long, value_name = "ADDR", default_value = "127.0.0.1")]
        bind: String,
    },
    /// Carry an SSH connection to a sandbox (used as the ssh ProxyCommand)
    ///
    /// `ssh kobe-<pool>-<name>` resolves the host name to one of your
    /// sandboxes, creating it on first use, authorizes your public key in it,
    /// and runs the sandbox's sshd over `kobe attach`. Install the ssh_config
    /// block with `kobe ssh-config`. Not meant to be run by hand.
    #[command(hide = true)]
    SshProxy {
        /// Host name as ssh passes it (`%n`): kobe-<pool>-<name> or kobe-<name>,
        /// optionally followed by `.<session>`
        host: String,
        /// Pool for a new sandbox. Overrides the host name and the target's default pool
        #[arg(long)]
        pool: Option<String>,
        /// TTL for a new sandbox (pool default when omitted)
        #[arg(long)]
        ttl: Option<String>,
        /// How long to wait for a new sandbox to become ready, e.g. 30s or 5m
        #[arg(long, value_name = "DURATION")]
        wait_timeout: Option<String>,
        /// Connect to an existing sandbox only; never create one
        #[arg(long)]
        no_create: bool,
        /// Public key file to authorize inside the sandbox
        #[arg(long, value_name = "PATH")]
        public_key: Option<String>,
    },
    /// Set up this machine: target, sign-in, default pool, and ssh
    ///
    /// Writes a target with --endpoint (or uses the current one), signs in or
    /// records the one-time trust answer, picks a default pool, finds your
    /// public key, installs the ssh_config block, and checks that `ssh -G`
    /// resolves it. Steps that are already done are skipped.
    Init {
        /// Create or replace a target at this endpoint and make it current
        #[arg(long, value_name = "URL")]
        endpoint: Option<String>,
        /// Name for the target written by --endpoint [default: default]
        #[arg(long, value_name = "NAME", requires = "endpoint")]
        name: Option<String>,
        /// Auth mode for --endpoint: none, token, oidc, or ssh (discovered when omitted)
        #[arg(long, value_name = "MODE", requires = "endpoint")]
        auth: Option<String>,
        /// Bearer token for --auth token
        #[arg(long, requires = "endpoint")]
        token: Option<String>,
        /// Pool that `ssh kobe-<name>` uses when the host name does not name one
        #[arg(long = "default-pool", value_name = "POOL")]
        default_pool: Option<String>,
        /// Public key file to authorize inside sandboxes (saved to the config)
        #[arg(long, value_name = "PATH")]
        public_key: Option<String>,
        /// Never prompt; accept every default
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Check the ssh setup without changing anything
    ///
    /// Checks the target, endpoint, sign-in, pools, public key, and the
    /// ssh_config block that `ssh kobe-<pool>-<name>` depends on.
    Doctor,
    /// Print the ssh_config block for `ssh kobe-<pool>-<name>`
    ///
    /// Append it to `~/.ssh/config` or a file it includes. The block uses the
    /// absolute path of this executable, and carries `--target` when one is
    /// given.
    SshConfig,
    /// Deprecated compatibility namespace for the original Sandbox CLI.
    #[command(hide = true)]
    Sandbox {
        #[command(subcommand)]
        action: SandboxAction,
    },
    /// Sign out and revoke your tokens
    ///
    /// Removes stored credentials and revokes the refresh and access tokens at
    /// the identity provider (RFC 7009), so a leaked token stops working too.
    Logout,
    /// Lease a resource from a pool and wait until it is ready
    Lease {
        /// Pool to lease from, e.g. ci-small or agents
        pool: Option<String>,
        /// How long the lease lasts
        #[arg(long, default_value = "1h")]
        ttl: String,
        /// Return as soon as the lease is requested
        #[arg(long)]
        no_wait: bool,
        /// How long to wait for the lease to become ready, e.g. 30s, 5m, 1h
        #[arg(long, value_name = "DURATION", conflicts_with = "no_wait")]
        wait_timeout: Option<String>,
        /// Write the cluster's kubeconfig to this path (clusters only)
        #[arg(long = "kubeconfig", value_name = "PATH")]
        kubeconfig: Option<String>,
        /// Name the lease so other commands can refer to it
        ///
        /// Names are unique among your active leases: `kobe lease ci --name
        /// pr-106`, then `kobe extend pr-106`.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Attach a JSON object to the lease: inline JSON or @path
        ///
        /// Metadata is descriptive only; Kobe does not act on it.
        #[arg(long, value_name = "JSON|@PATH")]
        metadata_json: Option<String>,
        /// Reuse your active lease with --name, extending it, instead of failing
        ///
        /// Makes `kobe lease` safe to call unconditionally at job start: a
        /// second call renews the lease. A reused lease keeps its original
        /// metadata.
        #[arg(long, requires = "name")]
        ensure: bool,
        /// Keep extending the lease until interrupted
        ///
        /// Extends by --ttl at half-TTL intervals until Ctrl-C or the server's
        /// maximum lease time.
        #[arg(long, conflicts_with = "no_wait")]
        keepalive: bool,
    },
    /// Lease a cluster, run a command with its kubeconfig, then release it
    ///
    /// The lease is kept alive while the command runs and released when it
    /// exits, including on failure or a signal. The command sees the lease's
    /// kubeconfig in KUBECONFIG: `kobe with-lease ci-small -- kubectl get
    /// pods`.
    WithLease {
        /// Pool to lease from, e.g. ci-small
        pool: Option<String>,
        /// Lease TTL, also the keepalive window
        #[arg(long, default_value = "1h")]
        ttl: String,
        /// Attach a JSON object to the lease: inline JSON or @path
        ///
        /// Metadata is descriptive only; Kobe does not act on it.
        #[arg(long, value_name = "JSON|@PATH")]
        metadata_json: Option<String>,
        /// The command to run, after `--`
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Add time to an active lease
    ///
    /// With no lease, extends the only one you hold, or asks you to pick. With
    /// `--output json` and several leases it fails and lists them instead.
    Extend {
        /// Lease id, name, or pool (optional when you hold one lease)
        #[arg(id = "lease_selector", value_name = "LEASE")]
        target: Option<String>,
        /// Time to add to the current expiry, e.g. 30m or 1h
        #[arg(long, default_value = "30m")]
        ttl: String,
    },
    /// Release a lease
    ///
    /// With no lease, releases the only one you hold, or asks you to pick.
    /// With `--output json` and several leases it releases the first active
    /// one.
    Release {
        /// Lease id, name, or pool
        #[arg(value_name = "LEASE")]
        lease_id: Option<String>,
    },
    /// Release all your leases and remove their kubeconfigs
    Purge {
        /// Do not ask for confirmation
        #[arg(long, short = 'y')]
        yes: bool,
        /// Only remove kubeconfigs of leases that are gone; release nothing
        ///
        /// Removes kubeconfigs whose lease was released, expired, or no longer
        /// exists on the server. Active leases are left alone, and files in
        /// `~/.kube/kobe-*.yaml` that kobe did not record are not touched. Use
        /// it to clean up after leases that expired.
        #[arg(long)]
        orphans_only: bool,
    },
    /// Edit the CLI configuration
    ///
    /// With no subcommand, opens the editor in a terminal.
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
}

/// Kind-specific adapters retained behind the hidden compatibility namespace.
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
        /// Forward this process's stdin to the remote command, then close it.
        ///
        /// For secrets and small inputs. The command sees EOF once the bytes
        /// are delivered, so anything that reads until EOF — `gh auth login
        /// --with-token` — completes rather than waiting for its timeout.
        #[arg(long)]
        stdin: bool,
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
    /// Read a bounded tail of the sandbox or one durable execution.
    Logs {
        lease: String,
        /// Durable execution id. Reads reconnectable stdout/stderr windows.
        #[arg(long, conflicts_with = "tail")]
        execution: Option<String>,
        /// Continue from returned offsets until the execution is terminal.
        /// With `--output json`, emits one JSON object per line (NDJSON).
        #[arg(long, requires = "execution")]
        follow: bool,
        /// Lines from the end of the sandbox's own output.
        #[arg(long, conflicts_with = "execution")]
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
        lease: Option<String>,
        #[arg(long)]
        container: Option<String>,
        /// Run without allocating a terminal.
        #[arg(long)]
        no_tty: bool,
        /// Attach to a persistent session in the sandbox's `kobe-runner`,
        /// creating it on first use. The shell outlives the connection:
        /// dropped connections and stream limits reconnect on their own, and
        /// `~.` at the start of a line detaches. The command after `--`
        /// starts a new session; the login shell when there is none.
        /// `LEASE.NAME` is the same as `LEASE --session NAME`.
        #[arg(long, value_name = "NAME", conflicts_with = "no_tty")]
        session: Option<String>,
        /// Where `kobe-runner` lives in the sandbox, for `--session`.
        /// Defaults to `/kobe-runner`.
        #[arg(long, requires = "session")]
        runner_path: Option<String>,
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
    /// Show the resolved configuration and where each value comes from
    View,
    /// Export the saved configuration as JSON
    Export {
        /// Destination file, or `-` for stdout
        path: Option<String>,
    },
    /// Import a configuration exported with `kobe config export`
    Import {
        /// Source file, or `-` for stdin
        path: Option<String>,
    },
    /// Edit a target in the terminal editor
    Edit {
        /// Target to edit [default: the current target]
        name: Option<String>,
    },
    /// List named targets
    List,
    /// Show the current target and where it was selected
    Current,
    /// Switch the current target for this shell
    Use {
        /// Target name
        name: String,
    },
    /// Create or replace a named target
    ///
    /// Writes to `./.kobe.toml` so the target follows the project. Pass
    /// --global to write to `~/.config/kobe/config.json` instead, for
    /// endpoints you use from any directory.
    Set {
        /// Target name
        name: String,
        /// Kobe server URL
        #[arg(long, value_name = "URL")]
        endpoint: String,
        /// Auth mode: none, token, oidc, or ssh
        #[arg(long, value_name = "MODE")]
        auth: Option<String>,
        /// Bearer token for --auth token
        #[arg(long)]
        token: Option<String>,
        /// SSH key fingerprint for --auth ssh
        #[arg(long = "ssh-fingerprint", value_name = "FINGERPRINT")]
        ssh_fingerprint: Option<String>,
        /// Pool that `ssh kobe-<name>` uses when the host name does not name one
        #[arg(long = "default-pool", value_name = "POOL")]
        default_pool: Option<String>,
        /// Write to `~/.config/kobe/config.json` instead of `./.kobe.toml`
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

    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            error.exit()
        }
        Err(error) if requests_resource_json(&args) => {
            let code = error.exit_code();
            commands::sandbox::emit_cli_parse_error(&error.to_string(), code)?;
            std::process::exit(code)
        }
        Err(error) => error.exit(),
    };
    let target = cli.target.as_deref();
    let endpoint = cli.endpoint.as_deref();
    let output = cli.output;

    let result = match cli.command {
        Commands::Status { all } => commands::status(target, endpoint, output, all).await,
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
            metadata_json,
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
                metadata_json: metadata_json.as_deref(),
                ensure,
                keepalive,
                target_override: target,
                endpoint_override: endpoint,
                output,
            })
            .await
        }
        Commands::WithLease {
            pool,
            ttl,
            metadata_json,
            cmd,
        } => {
            commands::with_lease(commands::WithLeaseCommand {
                pool: pool.as_deref(),
                ttl: &ttl,
                metadata_json: metadata_json.as_deref(),
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
        Commands::Run {
            pool,
            ttl,
            cwd,
            timeout,
            command,
        } => {
            if let Err(error) =
                commands::require_pool_capability(&pool, "exec", target, endpoint, output).await
            {
                exit_resource_error(error, output);
            }
            dispatch_resource_action(
                SandboxAction::Run {
                    pool,
                    ttl,
                    cwd,
                    timeout,
                    command,
                },
                target,
                endpoint,
                output,
            )
            .await
        }
        Commands::Exec {
            lease,
            cwd,
            timeout,
            stdin,
            command,
        } => {
            let lease =
                commands::require_lease_capability(&lease, "exec", target, endpoint, output)
                    .await
                    .unwrap_or_else(|error| exit_resource_error(error, output));
            dispatch_resource_action(
                SandboxAction::Exec {
                    lease,
                    cwd,
                    timeout,
                    stdin,
                    command,
                },
                target,
                endpoint,
                output,
            )
            .await
        }
        Commands::Logs {
            lease,
            execution,
            follow,
            tail,
        } => {
            let lease =
                commands::require_lease_capability(&lease, "logs", target, endpoint, output)
                    .await
                    .unwrap_or_else(|error| exit_resource_error(error, output));
            dispatch_resource_action(
                SandboxAction::Logs {
                    lease,
                    execution,
                    follow,
                    tail,
                },
                target,
                endpoint,
                output,
            )
            .await
        }
        Commands::Cancel { lease, execution } => {
            let lease =
                commands::require_lease_capability(&lease, "cancel", target, endpoint, output)
                    .await
                    .unwrap_or_else(|error| exit_resource_error(error, output));
            dispatch_resource_action(
                SandboxAction::Cancel { lease, execution },
                target,
                endpoint,
                output,
            )
            .await
        }
        Commands::Attach {
            lease,
            container,
            no_tty,
            session,
            runner_path,
            command,
        } => {
            dispatch_resource_action(
                SandboxAction::Attach {
                    lease,
                    container,
                    no_tty,
                    session,
                    runner_path,
                    command,
                },
                target,
                endpoint,
                output,
            )
            .await
        }
        Commands::PortForward { lease, spec, bind } => {
            let lease = commands::require_lease_capability(
                &lease,
                "port-forward",
                target,
                endpoint,
                output,
            )
            .await
            .unwrap_or_else(|error| exit_resource_error(error, output));
            dispatch_resource_action(
                SandboxAction::PortForward { lease, spec, bind },
                target,
                endpoint,
                output,
            )
            .await
        }
        Commands::SshProxy {
            host,
            pool,
            ttl,
            wait_timeout,
            no_create,
            public_key,
        } => {
            // stdout is the SSH transport, so the outcome is an exit code and
            // stderr text, never a JSON envelope on stdout.
            match commands::ssh_proxy(commands::SshProxyCommand {
                host: &host,
                pool: pool.as_deref(),
                ttl: ttl.as_deref(),
                wait_timeout: wait_timeout.as_deref(),
                no_create,
                public_key: public_key.as_deref(),
                target_override: target,
                endpoint_override: endpoint,
            })
            .await
            {
                Ok(0) => Ok(()),
                Ok(code) => std::process::exit(code),
                Err(error) => exit_resource_error(error, OutputFormat::Text),
            }
        }
        Commands::Init {
            endpoint: new_endpoint,
            name,
            auth,
            token: new_token,
            default_pool,
            public_key,
            yes,
        } => {
            commands::init(commands::InitCommand {
                endpoint: new_endpoint.as_deref(),
                name: name.as_deref(),
                auth: auth.as_deref(),
                token: new_token.as_deref(),
                default_pool: default_pool.as_deref(),
                public_key: public_key.as_deref(),
                yes,
                target_override: target,
                endpoint_override: endpoint,
                output,
            })
            .await
        }
        Commands::Doctor => match commands::doctor(target, endpoint, output).await {
            Ok(true) => Ok(()),
            Ok(false) => std::process::exit(1),
            Err(error) => Err(error),
        },
        Commands::SshConfig => commands::ssh_config(target),
        Commands::Sandbox { action } => {
            dispatch_resource_action(action, target, endpoint, output).await
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
            // Bare `kobe config` opens the editor when a person is at the
            // keyboard. Scripts and `-o json` get the subcommand list instead,
            // because a raw-mode editor would hang a pipe.
            None if output == OutputFormat::Text
                && std::io::stdin().is_terminal()
                && std::io::stdout().is_terminal() =>
            {
                commands::config_interactive(target)
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
                default_pool,
                global,
            }) => {
                commands::config_set_target(commands::SetTargetCommand {
                    name: &name,
                    endpoint: &endpoint,
                    auth: auth.as_deref(),
                    token: token.as_deref(),
                    ssh_fingerprint: ssh_fingerprint.as_deref(),
                    default_pool: default_pool.as_deref(),
                    global,
                    output,
                })
                .await
            }
            None => exit_with_config_help(),
        },
    };
    // One place decides how a failure reaches the caller: every command
    // prints the same `kobe:` prefix in text mode and the same structured
    // body under `--output json`. Returning the error to `main` instead
    // printed anyhow's own `Error:` for everything except the sandbox
    // actions, which routed through here already.
    match result {
        Ok(()) => Ok(()),
        Err(error) => exit_resource_error(error, output),
    }
}

/// Dispatch one capability-specific resource action. Kind-specific API routes
/// stay behind this boundary; the public command hierarchy remains flat.
async fn dispatch_resource_action(
    action: SandboxAction,
    target: Option<&str>,
    endpoint: Option<&str>,
    output: OutputFormat,
) -> anyhow::Result<()> {
    // These return the REMOTE command's exit code, so the process exits with
    // it rather than with generic success. `set -e` depends on exactly this.
    let code = match action {
        SandboxAction::Exec {
            lease,
            cwd,
            timeout,
            stdin,
            command,
        } => {
            commands::sandbox::exec(
                &lease,
                &command,
                cwd.as_deref(),
                timeout.as_deref(),
                stdin,
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
        SandboxAction::Logs {
            lease,
            execution,
            follow,
            tail,
        } => commands::sandbox::logs(
            &lease,
            tail,
            execution.as_deref(),
            follow,
            target,
            endpoint,
            output,
        )
        .await
        .map(|()| 0),
        SandboxAction::Cancel { lease, execution } => {
            commands::sandbox::cancel(&lease, &execution, target, endpoint, output)
                .await
                .map(|()| 0)
        }
        SandboxAction::Attach {
            lease,
            container,
            no_tty,
            session,
            runner_path,
            command,
        } => {
            // One resolution point for both spellings: a named lease must
            // advertise `attach`, and an unnamed one opens the picker over
            // the leases that do.
            let (lease, session) = match lease {
                Some(selector) => {
                    // `dev.main` is `dev --session main`. The whole selector is
                    // tried first: a pool name may contain dots, and a selector
                    // that already names a lease keeps meaning that lease.
                    let whole = commands::require_lease_capability(
                        &selector, "attach", target, endpoint, output,
                    )
                    .await;
                    match (
                        whole,
                        commands::sandbox_transport::split_session_selector(&selector),
                    ) {
                        (Ok(lease), _) => Ok((lease, session)),
                        (Err(_), Some((lease, name))) if session.is_none() => {
                            commands::require_lease_capability(
                                lease, "attach", target, endpoint, output,
                            )
                            .await
                            .map(|lease| (lease, Some(name.to_string())))
                        }
                        (Err(error), _) => Err(error),
                    }
                }
                None => commands::pick_lease_with_capability("attach", target, endpoint, output)
                    .await
                    .map(|lease| (lease, session)),
            }
            .unwrap_or_else(|error| exit_resource_error(error, output));
            match session {
                Some(name) => {
                    commands::sandbox_transport::attach_session(
                        &lease,
                        &name,
                        runner_path
                            .as_deref()
                            .unwrap_or(commands::sandbox_transport::DEFAULT_RUNNER_PATH),
                        &command,
                        container.as_deref(),
                        target,
                        endpoint,
                        output,
                    )
                    .await
                }
                None => {
                    commands::sandbox_transport::attach(
                        &lease,
                        &command,
                        container.as_deref(),
                        !no_tty,
                        target,
                        endpoint,
                        output,
                    )
                    .await
                }
            }
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
        Err(error) => exit_resource_error(error, output),
    }
}

fn exit_resource_error(error: anyhow::Error, output: OutputFormat) -> ! {
    if output == OutputFormat::Json {
        let _ = commands::sandbox::emit_cli_error(&error);
    } else {
        eprintln!("kobe: {error:#}");
    }
    std::process::exit(commands::sandbox::CLI_FAILURE_EXIT)
}

fn requests_resource_json(args: &[std::ffi::OsString]) -> bool {
    let args: Vec<_> = args
        .iter()
        .map(|argument| argument.to_string_lossy())
        .collect();
    let end = args
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(args.len());
    let arguments = args.get(1..end).unwrap_or_default();
    let json = arguments.iter().enumerate().any(|(index, argument)| {
        argument == "--output=json"
            || argument == "-o=json"
            || argument == "-ojson"
            || ((argument == "--output" || argument == "-o")
                && arguments
                    .get(index + 1)
                    .is_some_and(|value| value == "json"))
    });
    if !json {
        return false;
    }

    // Find the first positional while skipping the values of known global
    // options. A target literally named `sandbox`, or `--output json` passed
    // to the remote command after `--`, must not change Clap's error channel.
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if matches!(
            argument.as_ref(),
            "--endpoint" | "--target" | "--context" | "--output" | "-o"
        ) {
            index += 2;
            continue;
        }
        if argument.starts_with("--endpoint=")
            || argument.starts_with("--target=")
            || argument.starts_with("--context=")
            || argument.starts_with("--output=")
            || argument.starts_with("-o")
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') {
            index += 1;
            continue;
        }
        return matches!(
            argument.as_ref(),
            "sandbox" | "run" | "exec" | "logs" | "cancel" | "attach" | "port-forward"
        );
    }
    false
}

/// Print `kobe config`'s help to stderr and exit 2, like any other missing
/// subcommand. Rendering from the built root keeps the usage line reading
/// `kobe config` instead of a bare `config`.
fn exit_with_config_help() -> ! {
    let mut cli = Cli::command();
    cli.build();
    if let Some(config) = cli.find_subcommand_mut("config") {
        let help = config.render_help();
        if std::io::stderr().is_terminal() {
            eprintln!("{}", help.ansi());
        } else {
            eprintln!("{help}");
        }
    }
    std::process::exit(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_json_parse_errors_are_detected_before_clap_exits() {
        for args in [
            vec!["kobe", "run", "agents", "--output", "json"],
            vec!["kobe", "--output=json", "exec", "lease-1"],
            vec!["kobe", "sandbox", "run", "agents", "--output", "json"],
            vec!["kobe", "--output=json", "sandbox", "run", "agents"],
            vec!["kobe", "sandbox", "run", "agents", "-o=json"],
            vec!["kobe", "sandbox", "run", "agents", "-ojson"],
        ] {
            let args: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
            assert!(requests_resource_json(&args));
        }
        let text: Vec<std::ffi::OsString> = ["kobe", "sandbox", "run", "agents"]
            .into_iter()
            .map(Into::into)
            .collect();
        assert!(!requests_resource_json(&text));
        for args in [
            vec!["kobe", "--target", "sandbox", "status", "--output", "json"],
            vec![
                "kobe", "sandbox", "run", "agents", "--", "tool", "--output", "json",
            ],
        ] {
            let args: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
            assert!(!requests_resource_json(&args));
        }
    }

    /// The public #84 shape reaches the durable execution-log route with follow
    /// enabled; these flags must not be mistaken for global or sandbox options.
    #[test]
    fn execution_logs_accept_execution_and_follow_options() {
        let cli = Cli::try_parse_from([
            "kobe",
            "logs",
            "sandbox-1",
            "--execution",
            "sbxe-1",
            "--follow",
        ])
        .unwrap();

        let Commands::Logs {
            lease,
            execution,
            follow,
            tail,
        } = cli.command
        else {
            panic!("expected resource logs")
        };
        assert_eq!(lease, "sandbox-1");
        assert_eq!(execution.as_deref(), Some("sbxe-1"));
        assert!(follow);
        assert_eq!(tail, None);
    }

    /// Sandbox-tail and execution-window modes are distinct server routes.
    /// Rejecting a mixed invocation prevents silently ignoring one bound.
    #[test]
    fn execution_logs_reject_tail_and_follow_requires_execution() {
        assert!(
            Cli::try_parse_from([
                "kobe",
                "logs",
                "sandbox-1",
                "--execution",
                "sbxe-1",
                "--tail",
                "10",
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["kobe", "logs", "sandbox-1", "--follow"]).is_err());
    }

    /// Forwarding stdin is opt-in, and the flag belongs to kobe rather than to
    /// the remote command.
    ///
    /// Opt-in because a `kobe exec` in a pipeline must not silently start
    /// consuming the script's own stdin. Before `--` because everything after
    /// it is the tenant's argv — the argv this feature exists to keep secrets
    /// out of — so `cat --stdin` has to stay a request to run `cat --stdin`.
    #[test]
    fn exec_forwards_stdin_only_when_asked() {
        let cli = Cli::try_parse_from(["kobe", "exec", "sandbox-1", "--", "true"]).unwrap();
        assert!(
            matches!(cli.command, Commands::Exec { stdin: false, .. }),
            "forwarding stdin must be opt-in: an ordinary exec sends none"
        );

        // Before `--`, so it cannot be confused with an argument of the remote
        // command — which is exactly what `--stdin` exists to avoid needing.
        let cli = Cli::try_parse_from([
            "kobe",
            "exec",
            "sandbox-1",
            "--stdin",
            "--",
            "gh",
            "auth",
            "login",
            "--with-token",
        ])
        .unwrap();
        let Commands::Exec { stdin, command, .. } = cli.command else {
            panic!("expected exec");
        };
        assert!(stdin);
        assert_eq!(command, ["gh", "auth", "login", "--with-token"]);

        // A `--stdin` after `--` belongs to the remote command, not to kobe.
        let cli =
            Cli::try_parse_from(["kobe", "exec", "sandbox-1", "--", "cat", "--stdin"]).unwrap();
        let Commands::Exec { stdin, command, .. } = cli.command else {
            panic!("expected exec");
        };
        assert!(!stdin);
        assert_eq!(command, ["cat", "--stdin"]);
    }

    #[test]
    fn legacy_sandbox_namespace_remains_parseable_but_hidden() {
        let cli =
            Cli::try_parse_from(["kobe", "sandbox", "exec", "sandbox-1", "--", "true"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Sandbox {
                action: SandboxAction::Exec { .. }
            }
        ));
    }

    #[test]
    fn extend_selector_is_distinct_from_the_global_target() {
        let cli = Cli::try_parse_from([
            "kobe",
            "--target",
            "production",
            "extend",
            "dev",
            "--ttl",
            "30m",
        ])
        .unwrap();
        assert_eq!(cli.target.as_deref(), Some("production"));
        let Commands::Extend { target, ttl } = cli.command else {
            panic!("expected extend")
        };
        assert_eq!(target.as_deref(), Some("dev"));
        assert_eq!(ttl, "30m");
    }
}
