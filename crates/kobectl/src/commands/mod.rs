mod config;
mod config_tui;
mod doctor;
mod extend;
mod init;
mod keepalive;
mod lease_create;
mod leases;
mod login;
mod picker;
mod pools;
mod purge;
mod release;
pub(crate) mod sandbox;
pub(crate) mod sandbox_transport;
mod select;
pub(crate) mod session;
mod ssh_proxy;
mod ssh_setup;
mod state;
mod status;
mod version;
pub(crate) mod vnc;
mod with_lease;

use clap::ValueEnum;
use serde::Serialize;

pub use config::{
    SetTargetCommand, config_current_target, config_export, config_import, config_list_targets,
    config_set_target, config_show, config_use_target,
};
pub use config_tui::run_config_tui as config_interactive;
pub use doctor::doctor;
pub use extend::extend;
pub use init::{InitCommand, init};
pub use lease_create::{LeaseCreateCommand, lease_create};
pub use login::{login, logout};
pub use purge::purge;
pub use release::release;
pub use ssh_proxy::{SshProxyCommand, ssh_config, ssh_proxy};
pub use status::status;
pub use version::version;
pub use with_lease::{WithLeaseCommand, with_lease};

/// Resolve a pool before any mutating shortcut and verify that the selected
/// resource kind exposes the requested operation.
pub async fn require_pool_capability(
    pool: &str,
    capability: &str,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let config = config::CliConfig::load()?.resolve(target_override, endpoint_override)?;
    let pool = pools::fetch_pool_for_config_with_output(&config, pool, output).await?;
    if !pool.supports(capability) {
        anyhow::bail!(
            "pool {} allocates {} resources, which do not support {capability}; available capabilities: {}",
            pool.name,
            pool.resource_kind,
            pool.capabilities.join(", ")
        );
    }
    Ok(())
}

/// Resolve an exact ID, alias, or unique pool selector and reject an
/// incompatible operation before it reaches a kind-specific route.
/// Resolve a lease for a capability when the caller named none.
///
/// `kobe attach` with no argument: one attachable lease is taken, several open
/// the picker, none is an error naming the verb. Kept beside
/// [`require_lease_capability`] so a named lease and an unnamed one answer the
/// same question about what the lease can serve.
pub async fn pick_lease_with_capability(
    capability: &str,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> anyhow::Result<String> {
    let config = config::CliConfig::load()?.resolve(target_override, endpoint_override)?;
    select::resolve_lease_for_capability(&config, capability, output).await
}

pub async fn require_lease_capability(
    selector: &str,
    capability: &str,
    target_override: Option<&str>,
    endpoint_override: Option<&str>,
    output: OutputFormat,
) -> anyhow::Result<String> {
    let config = config::CliConfig::load()?.resolve(target_override, endpoint_override)?;
    let leases = leases::fetch_all_leases_with_output(&config, output).await?;
    let by_id: Vec<_> = leases.iter().filter(|lease| lease.id == selector).collect();
    let by_alias: Vec<_> = leases
        .iter()
        .filter(|lease| lease.alias.as_deref() == Some(selector))
        .collect();
    let by_pool: Vec<_> = leases
        .iter()
        .filter(|lease| lease.profile == selector)
        .collect();
    let matches = if !by_id.is_empty() {
        by_id
    } else if !by_alias.is_empty() {
        by_alias
    } else {
        by_pool
    };
    let lease = match matches.as_slice() {
        [lease] => lease,
        [] => anyhow::bail!("no lease matches '{selector}'"),
        many => anyhow::bail!(
            "'{selector}' matches multiple leases: {}",
            many.iter()
                .map(|lease| lease.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    if !lease
        .capabilities
        .iter()
        .any(|candidate| candidate == capability)
    {
        anyhow::bail!(
            "lease {} is a {} resource and does not support {capability}; available capabilities: {}",
            lease.id,
            lease.resource_kind,
            lease.capabilities.join(", ")
        );
    }
    Ok(lease.id.clone())
}

use config::{AuthMode, ResolvedConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthInteraction {
    Interactive,
    NonInteractive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

pub(crate) fn cli_version() -> &'static str {
    option_env!("BUILD_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

pub(crate) fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Get a valid auth header value based on the configured auth mode.
/// Returns None for no-auth mode, Some(header) for token/oidc/ssh.
pub(crate) async fn get_auth_header(
    config: &ResolvedConfig,
    method: &str,
    path: &str,
    body: &[u8],
) -> anyhow::Result<Option<String>> {
    get_auth_header_with_interaction(config, method, path, body, AuthInteraction::Interactive).await
}

/// Build authorization without ever prompting or writing a trust warning.
///
/// Machine-output commands use this path so stdout remains their only output
/// channel. An SSH first-connect or audience change becomes structured command
/// failure; the caller can rerun a text-mode command to review it interactively.
pub(crate) async fn get_auth_header_noninteractive(
    config: &ResolvedConfig,
    method: &str,
    path: &str,
    body: &[u8],
) -> anyhow::Result<Option<String>> {
    get_auth_header_with_interaction(config, method, path, body, AuthInteraction::NonInteractive)
        .await
}

pub(crate) async fn get_auth_header_for_output(
    config: &ResolvedConfig,
    method: &str,
    path: &str,
    body: &[u8],
    output: OutputFormat,
) -> anyhow::Result<Option<String>> {
    match output {
        OutputFormat::Text => get_auth_header(config, method, path, body).await,
        OutputFormat::Json => get_auth_header_noninteractive(config, method, path, body).await,
    }
}

async fn get_auth_header_with_interaction(
    config: &ResolvedConfig,
    method: &str,
    path: &str,
    body: &[u8],
    interaction: AuthInteraction,
) -> anyhow::Result<Option<String>> {
    match &config.auth {
        AuthMode::None => Ok(None),
        AuthMode::Token => match &config.token {
            Some(t) => Ok(Some(format!("Bearer {t}"))),
            None => {
                anyhow::bail!("Auth mode is 'token' but no token configured. Run: kobe config edit")
            }
        },
        AuthMode::Oidc => {
            let service_config = login::discover_pinned(&config.endpoint).await?;
            let token = match interaction {
                AuthInteraction::Interactive => {
                    kunobi_auth::client::AuthClient::new(service_config)?
                        .token()
                        .await?
                }
                AuthInteraction::NonInteractive => {
                    oidc_token_noninteractive(&service_config).await?
                }
            };
            Ok(Some(format!("Bearer {token}")))
        }
        AuthMode::Ssh => {
            let client = kunobi_auth::client::AuthClient::with_ssh(config.ssh_fingerprint.clone())?;
            // Discover audience from /v1/status — retry once if server hasn't loaded policies yet
            let audience = discover_ssh_audience(config).await?;
            tofu_check(&config.endpoint, &audience, interaction).await?;
            let header = client.authorize(&audience, method, path, body).await?;
            Ok(Some(header))
        }
    }
}

/// Load or refresh OIDC credentials without falling back to browser login.
///
/// `AuthClient::token()` deliberately becomes interactive when neither path is
/// usable. Machine output cannot permit that fallback because browser-login
/// writes prompts to stdout. This mirrors its cache/refresh path and fails
/// before any user interaction would begin.
async fn oidc_token_noninteractive(
    config: &kunobi_auth::client::ServiceConfig,
) -> anyhow::Result<String> {
    use kunobi_auth::client::TokenStore;

    let store = TokenStore::new()?;
    let Some(stored) = store.load(&config.issuer)? else {
        anyhow::bail!("OIDC login is required; run `kobe login` before using --output json")
    };
    if !stored.is_expired() {
        return Ok(stored.id_token);
    }
    let Some(refresh_token) = stored.refresh_token.as_deref() else {
        anyhow::bail!(
            "OIDC credentials expired without a refresh token; run `kobe login` before using --output json"
        )
    };
    let mut refreshed = kunobi_auth::client::oidc::refresh(
        &config.issuer,
        &config.client_id,
        &config.redirect_uri,
        refresh_token,
    )
    .await
    .map_err(|error| {
        anyhow::anyhow!(
            "OIDC refresh failed without interactive fallback ({error}); run `kobe login`"
        )
    })?;
    refreshed.extra = stored.extra;
    let token = refreshed.id_token.clone();
    store.save(&refreshed)?;
    Ok(token)
}

/// The SSH audience an endpoint advertises, discovered once per process.
///
/// Every authorized request needs the audience, and every request signs its
/// own `(method, path, body)`, so a command that makes several requests used
/// to re-fetch `/v1/status` for each one. An endpoint does not change its
/// audience underneath a running command; a stale entry cannot outlive the
/// process.
fn audience_cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

async fn discover_ssh_audience(config: &ResolvedConfig) -> anyhow::Result<String> {
    let endpoint = config.endpoint.as_str();
    // The guard is dropped before any await, so the lock never spans one.
    if let Ok(cache) = audience_cache().lock()
        && let Some(hit) = cache.get(endpoint)
    {
        return Ok(hit.clone());
    }

    // Try twice — the server may not have loaded policies on first attempt
    for attempt in 0..2 {
        let resp: serde_json::Value = authed_client()
            .get(format!("{endpoint}/v1/status"))
            .send()
            .await
            .reaching(config)?
            .json()
            .await?;
        if let Some(methods) = resp["auth"]["methods"].as_array() {
            for method in methods {
                if method["type"].as_str() == Some("ssh")
                    && let Some(audience) = method["audience"].as_str()
                {
                    if let Ok(mut cache) = audience_cache().lock() {
                        cache.insert(endpoint.to_string(), audience.to_string());
                    }
                    return Ok(audience.to_string());
                }
            }
        }
        if attempt == 0 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    anyhow::bail!(
        "Server at {endpoint} has no SSH auth method configured. \
         Check that an AccessPolicy with ssh auth exists in the cluster."
    )
}

/// The SSH auth path has no OIDC issuer (status reports issuer=None for ssh, and SSH
/// identities are stamped issuer="ssh"), so the endpoint is pinned under this sentinel
/// in the issuer slot that `TofuStore` verifies and stores.
const SSH_PINNED_ISSUER: &str = "ssh";

/// Verify SSH trust off the async worker thread.
///
/// The interactive path reads stdin synchronously. Running it in Tokio's
/// blocking pool means an enclosing request deadline or signal `select!` can
/// still make progress instead of being trapped inside one future poll.
async fn tofu_check(
    endpoint: &str,
    audience: &str,
    interaction: AuthInteraction,
) -> anyhow::Result<()> {
    let endpoint = endpoint.to_string();
    let audience = audience.to_string();
    tokio::task::spawn_blocking(move || tofu_check_blocking(&endpoint, &audience, interaction))
        .await
        .map_err(|error| anyhow::anyhow!("SSH trust check task failed: {error}"))?
}

fn tofu_check_blocking(
    endpoint: &str,
    audience: &str,
    interaction: AuthInteraction,
) -> anyhow::Result<()> {
    let store = kunobi_auth::client::TofuStore::new()?;
    apply_tofu_result(
        &store,
        store.verify(endpoint, SSH_PINNED_ISSUER, audience)?,
        interaction,
    )
}

fn apply_tofu_result(
    store: &kunobi_auth::client::TofuStore,
    result: kunobi_auth::client::TofuResult,
    interaction: AuthInteraction,
) -> anyhow::Result<()> {
    match result {
        kunobi_auth::client::TofuResult::Trusted => Ok(()),
        kunobi_auth::client::TofuResult::FirstConnect { endpoint, audience }
            if interaction == AuthInteraction::NonInteractive =>
        {
            anyhow::bail!(
                "SSH trust is not established for {endpoint} (audience {audience}); rerun in text mode to review it"
            )
        }
        kunobi_auth::client::TofuResult::FirstConnect { endpoint, audience } => {
            eprintln!();
            eprintln!("Connecting to {endpoint}");
            eprintln!("  Audience: {audience}");
            eprintln!();
            eprint!("Trust this service? [y/N] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim().eq_ignore_ascii_case("y") {
                store.trust(&endpoint, SSH_PINNED_ISSUER, &audience)?;
                Ok(())
            } else {
                anyhow::bail!("Connection refused by user")
            }
        }
        kunobi_auth::client::TofuResult::AudienceChanged {
            endpoint,
            previous,
            current,
        } if interaction == AuthInteraction::NonInteractive => {
            anyhow::bail!(
                "SSH audience changed for {endpoint} from {previous} to {current}; rerun in text mode to review it"
            )
        }
        kunobi_auth::client::TofuResult::AudienceChanged {
            endpoint,
            previous,
            current,
        } => {
            eprintln!();
            eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            eprintln!("@    WARNING: SERVICE AUDIENCE HAS CHANGED!       @");
            eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            eprintln!("The audience for {endpoint} changed:");
            eprintln!("  Previous: {previous}");
            eprintln!("  Current:  {current}");
            eprintln!("This could mean the service was reconfigured, or it");
            eprintln!("could indicate a man-in-the-middle attack.");
            eprint!("Continue? [y/N] ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim().eq_ignore_ascii_case("y") {
                store.trust(&endpoint, SSH_PINNED_ISSUER, &current)?;
                Ok(())
            } else {
                anyhow::bail!("Connection refused by user")
            }
        }
        // The SSH path always pins the "ssh" sentinel, so a different issuer means the
        // endpoint was pinned by another auth path or by someone else. Refuse either
        // way: unlike an audience change, there is no answer the user can give here
        // that makes the new issuer trustworthy.
        kunobi_auth::client::TofuResult::IssuerChanged {
            endpoint,
            previous,
            current,
        } => {
            anyhow::bail!(
                "SSH trust for {endpoint} is pinned to issuer {previous}, but the service now \
                 presents {current}. Remove the pin for {endpoint} from the trust store only if \
                 you know why it changed."
            )
        }
        other => anyhow::bail!("Unhandled SSH trust result: {other:?}"),
    }
}

/// Build an HTTP request with optional auth.
/// Why a request never reached the server, in terms the caller can act on.
///
/// `reqwest` errors arrive as a chain — request, then connect, then the
/// operating system's resolver text — and printing the chain gives the caller
/// three clauses of plumbing and no idea what to do. Nothing below the top
/// layer is theirs to fix; what is theirs is the endpoint, the VPN, and
/// whether the server is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unreachable {
    Dns,
    Refused,
    TimedOut,
    Tls,
    Other,
}

impl Unreachable {
    pub(crate) fn summary(self) -> &'static str {
        match self {
            Self::Dns => "the host name does not resolve",
            Self::Refused => "nothing is listening there",
            Self::TimedOut => "the connection timed out",
            Self::Tls => "the TLS handshake failed",
            Self::Other => "the connection failed",
        }
    }

    pub(crate) fn hint(self) -> &'static str {
        match self {
            Self::Dns => {
                "A private cluster resolves only from its network: connect the VPN, or check the endpoint for a typo."
            }
            Self::Refused => {
                "The name resolves, so the address is reachable but nothing answered. Check that the kobe ingress is up."
            }
            Self::TimedOut => {
                "The address is routable but silent, which usually means a firewall or a missing VPN route."
            }
            Self::Tls => {
                "The server's certificate was rejected. Check that the endpoint host matches the certificate."
            }
            Self::Other => "Check the endpoint and that the kobe server is reachable from here.",
        }
    }
}

/// Classify a transport failure.
///
/// The typed predicates carry the bucket; the resolver's own words are the
/// only place DNS is distinguishable from a refused connection, because both
/// surface as `is_connect`. Matching that text is unlovely but it is the
/// difference between "connect the VPN" and "the server is down", which is
/// the entire value of the message.
pub(crate) fn classify_unreachable(error: &reqwest::Error) -> Unreachable {
    if error.is_timeout() {
        return Unreachable::TimedOut;
    }

    let mut chain = String::new();
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        chain.push_str(&current.to_string().to_ascii_lowercase());
        chain.push(' ');
        source = current.source();
    }

    if chain.contains("dns error") || chain.contains("failed to lookup address") {
        Unreachable::Dns
    } else if chain.contains("connection refused") {
        Unreachable::Refused
    } else if chain.contains("timed out") {
        Unreachable::TimedOut
    } else if chain.contains("certificate") || chain.contains("tls") {
        Unreachable::Tls
    } else {
        // Including `is_connect` with no recognisable cause: the bucket is
        // the same, and a hint that guesses would be worse than a general one.
        Unreachable::Other
    }
}

/// Render the message a caller sees when kobe cannot be reached.
pub(crate) fn unreachable_message(
    endpoint: &str,
    target: Option<&str>,
    kind: Unreachable,
) -> String {
    let host = endpoint
        .split_once("://")
        .map_or(endpoint, |(_, rest)| rest)
        .split('/')
        .next()
        .unwrap_or(endpoint);
    let origin = match target {
        Some(target) => format!("target    {target}"),
        None => "target    (none: endpoint given directly)".to_string(),
    };
    format!(
        "cannot reach kobe at {host}: {summary}\n\n  endpoint  {endpoint}\n  {origin}\n\n  {hint}\n  `kobe config view` shows where this endpoint came from.",
        summary = kind.summary(),
        hint = kind.hint(),
    )
}

/// Attach the reachability explanation to a failed request.
pub(crate) trait Reaching<T> {
    fn reaching(self, config: &ResolvedConfig) -> anyhow::Result<T>;
}

impl<T> Reaching<T> for Result<T, reqwest::Error> {
    fn reaching(self, config: &ResolvedConfig) -> anyhow::Result<T> {
        self.map_err(|error| {
            if error.is_builder() || error.is_body() || error.is_decode() {
                // Not a reachability problem; the caller's own message is
                // better than a story about the network.
                return anyhow::Error::new(error);
            }
            anyhow::anyhow!(unreachable_message(
                &config.endpoint,
                config.target.as_deref(),
                classify_unreachable(&error),
            ))
        })
    }
}

/// Whether human output on stdout may carry terminal styles.
///
/// Off when stdout is redirected or `NO_COLOR` is set, so `kobe status | grep`
/// and saved logs stay plain text. Decided once per process.
pub(crate) fn stdout_color() -> bool {
    static COLOR: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *COLOR.get_or_init(|| {
        std::io::IsTerminal::is_terminal(&std::io::stdout())
            && std::env::var_os("NO_COLOR").is_none()
    })
}

/// `text` wrapped in the SGR style `sgr` (`"1"` bold, `"33"` yellow) when
/// [`stdout_color`] allows it, and unchanged otherwise.
pub(crate) fn styled(sgr: &str, text: impl std::fmt::Display) -> String {
    if stdout_color() {
        format!("\x1b[{sgr}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// The process-wide HTTP client.
///
/// `reqwest::Client` owns a connection pool, so building a fresh one per
/// request threw that pool away and paid a new TCP and TLS handshake for every
/// call. One client lets the commands that make several requests reuse a
/// single kept-alive connection. Cloning is cheap and shares the pool.
pub(crate) fn authed_client() -> reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new).clone()
}

/// Add auth header to a request builder if available.
pub(crate) fn with_auth(
    builder: reqwest::RequestBuilder,
    auth_header: &Option<String>,
) -> reqwest::RequestBuilder {
    match auth_header {
        Some(h) => builder.header("Authorization", h),
        None => builder,
    }
}

/// Paths one lease operation is tried on, in order.
///
/// `/v1/leases/{id}` serves both kinds since server v0.41.0. A server before
/// that routes it to Cluster leases only and answers a Sandbox id with 404, so
/// a Sandbox id keeps `/v1/sandbox-leases/{id}` as a fallback.
pub(crate) fn lease_request_paths(lease_id: &str) -> Vec<String> {
    let mut paths = vec![format!("/v1/leases/{lease_id}")];
    if extend::is_sandbox_lease(lease_id) {
        paths.push(format!("/v1/sandbox-leases/{lease_id}"));
    }
    paths
}

/// Send `method` for one lease on its canonical path, falling back as
/// [`lease_request_paths`] describes when the server answers 404.
///
/// Each attempt is signed for its own path. A JSON `body`, when given, is sent
/// with every attempt.
pub(crate) async fn send_lease_request(
    config: &ResolvedConfig,
    method: reqwest::Method,
    lease_id: &str,
    body: Option<&[u8]>,
) -> anyhow::Result<reqwest::Response> {
    let paths = lease_request_paths(lease_id);
    let client = authed_client();
    let mut attempts = paths.iter().peekable();
    loop {
        let path = attempts.next().expect("at least one lease path");
        // Body signing is not yet supported server-side; sign with an empty
        // body (matches `lease_create`).
        let token = get_auth_header(config, method.as_str(), path, b"").await?;
        let mut request = with_auth(
            client.request(method.clone(), format!("{}{path}", config.endpoint)),
            &token,
        );
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(body.to_vec());
        }
        let response = request.send().await.reaching(config)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND && attempts.peek().is_some() {
            continue;
        }
        return Ok(response);
    }
}

/// The auth method types a `/v1/status` body advertises, in order and without
/// repeats. `None` when the body has no method list at all.
///
/// Each method is an object whose `type` names it (`AuthMethodInfo` on the
/// server), and one type can appear once per provider: two OIDC issuers are
/// two `oidc` entries.
pub(crate) fn advertised_auth_methods(status: &serde_json::Value) -> Option<Vec<String>> {
    let methods = status["auth"]["methods"].as_array()?;
    let mut types: Vec<String> = Vec::new();
    for method in methods {
        if let Some(kind) = method["type"].as_str()
            && !types.iter().any(|seen| seen == kind)
        {
            types.push(kind.to_string());
        }
    }
    Some(types)
}

#[cfg(test)]
mod auth_method_tests {
    use super::advertised_auth_methods;
    use serde_json::json;

    /// The shape zur1-worker1 serves: two OIDC providers. Reading the entries
    /// as strings found nothing, so `doctor` warned that `oidc` was not
    /// advertised and `init` chose no auth at all.
    #[test]
    fn methods_are_read_from_each_entrys_type() {
        let status = json!({"auth": {"methods": [
            {"type": "oidc", "issuer": "https://token.actions.githubusercontent.com", "description": "github-actions"},
            {"type": "oidc", "issuer": "https://clerk.kunobi.com", "clientId": "abc", "description": "kunobi-oauth"},
            {"type": "ssh", "audience": "kobe"},
        ]}});
        assert_eq!(
            advertised_auth_methods(&status),
            Some(vec!["oidc".to_string(), "ssh".to_string()])
        );
    }

    /// No list is different from an empty one: `doctor` does not second-guess
    /// a server that does not say, and `init` treats both as no auth.
    #[test]
    fn a_missing_list_is_none_and_an_empty_one_is_empty() {
        assert_eq!(advertised_auth_methods(&json!({})), None);
        assert_eq!(
            advertised_auth_methods(&json!({"auth": {"methods": []}})),
            Some(vec![])
        );
    }

    /// An entry without a string `type` names no method and is skipped.
    #[test]
    fn entries_without_a_type_are_skipped() {
        let status =
            json!({"auth": {"methods": [{"issuer": "x"}, "oidc", {"type": 3}, {"type": "token"}]}});
        assert_eq!(
            advertised_auth_methods(&status),
            Some(vec!["token".to_string()])
        );
    }
}

#[cfg(test)]
mod reachability_tests {
    use super::*;

    /// The message names the host, what failed, and where the endpoint came
    /// from. A caller who sees it should not have to run anything to know
    /// which of their machines is wrong.
    #[test]
    fn an_unreachable_message_names_the_host_target_and_remedy() {
        let message = unreachable_message(
            "https://kobe.zur1-worker1.int-pro.zondax.io",
            Some("int-pro"),
            Unreachable::Dns,
        );
        assert!(
            message.starts_with("cannot reach kobe at kobe.zur1-worker1.int-pro.zondax.io: "),
            "{message}"
        );
        assert!(
            message.contains("the host name does not resolve"),
            "{message}"
        );
        assert!(message.contains("int-pro"), "{message}");
        assert!(message.contains("VPN"), "{message}");
        // The operating system's resolver text is exactly what this replaces.
        assert!(!message.contains("nodename"), "{message}");
        assert!(!message.contains("servname"), "{message}");

        // An endpoint passed directly has no target to name, and must say so
        // rather than printing an empty field.
        let direct = unreachable_message("http://127.0.0.1:8080", None, Unreachable::Refused);
        assert!(direct.contains("endpoint given directly"), "{direct}");
        assert!(direct.contains("nothing is listening there"), "{direct}");
        // Host extraction keeps the port and drops the scheme and path.
        assert!(direct.contains("at 127.0.0.1:8080:"), "{direct}");
    }

    /// DNS and a refused connection both arrive as `is_connect`, and they ask
    /// the caller to do completely different things. Distinguishing them is
    /// the whole point of classifying.
    #[test]
    fn resolver_and_refusal_are_told_apart() {
        assert_eq!(Unreachable::Dns.summary(), "the host name does not resolve");
        assert_eq!(Unreachable::Refused.summary(), "nothing is listening there");
        assert_ne!(Unreachable::Dns.hint(), Unreachable::Refused.hint());
        // Every bucket offers something to do next.
        for kind in [
            Unreachable::Dns,
            Unreachable::Refused,
            Unreachable::TimedOut,
            Unreachable::Tls,
            Unreachable::Other,
        ] {
            assert!(!kind.hint().is_empty(), "{kind:?} has no hint");
            assert!(!kind.summary().is_empty(), "{kind:?} has no summary");
        }
    }
}

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn noninteractive_tofu_never_accepts_a_promptable_decision() {
        let directory = tempfile::tempdir().unwrap();
        let store = kunobi_auth::client::TofuStore::with_path(directory.path().join("known.json"));
        let first = kunobi_auth::client::TofuResult::FirstConnect {
            endpoint: "https://kobe.example".into(),
            audience: "kobe".into(),
        };
        assert!(
            apply_tofu_result(&store, first, AuthInteraction::NonInteractive)
                .unwrap_err()
                .to_string()
                .contains("rerun in text mode")
        );

        let changed = kunobi_auth::client::TofuResult::AudienceChanged {
            endpoint: "https://kobe.example".into(),
            previous: "old".into(),
            current: "new".into(),
        };
        assert!(
            apply_tofu_result(&store, changed, AuthInteraction::NonInteractive)
                .unwrap_err()
                .to_string()
                .contains("rerun in text mode")
        );
        apply_tofu_result(
            &store,
            kunobi_auth::client::TofuResult::Trusted,
            AuthInteraction::NonInteractive,
        )
        .unwrap();
    }
}
