use anyhow::Result;
use kunobi_auth::client::{AuthClient, ServiceConfig, TofuResult, TofuStore};

use super::config::{AuthMode, CliConfig};

/// Default OAuth scope for the device-grant flow. Mirrors what
/// `browser_login` uses internally — every Kunobi IdP we test against
/// (Dex, Auth0, Keycloak) accepts `openid profile email`. If a
/// product needs a tighter scope it can be made configurable later.
const DEVICE_GRANT_SCOPE: &str = "openid profile email offline_access";

/// Authenticate with the kobe service.
///
/// `device` selects RFC 8628 Device Authorization Grant: the CLI prints
/// a verification URL + user code and polls the IdP while the user
/// completes authorization in any browser (typically on a phone or
/// laptop). Useful when running kobe over SSH on a headless box,
/// inside a CI runner, or anywhere a browser can't open locally.
///
/// Without `device`, falls back to the standard browser-redirect flow
/// — opens the system browser, listens on a localhost callback URL,
/// completes the OAuth dance.
///
/// `retrust` re-pins the endpoint's advertised issuer and audience when they
/// no longer match the trusted pin (see [`retrust_pin`]). Without it the
/// pinned discovery refuses a change, as every other command does.
pub async fn login(
    context_override: Option<&str>,
    endpoint_override: Option<&str>,
    device: bool,
    retrust: bool,
) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(context_override, endpoint_override)?;
    let endpoint = config.endpoint.as_str();
    if config.auth != AuthMode::Oidc {
        println!(
            "Context uses auth={}. Browser/device login is only needed for auth=oidc.",
            config.auth
        );
        return Ok(());
    }

    println!("Discovering auth configuration from {endpoint}...");
    let service_config = if retrust {
        let service_config = kunobi_auth::client::discover_unpinned(endpoint).await?;
        if let Some(change) = retrust_pin(&TofuStore::new()?, &service_config)? {
            eprintln!("{change}");
        }
        service_config
    } else {
        discover_pinned(endpoint).await?
    };
    let client = AuthClient::new(service_config)?;

    if device {
        println!("Starting device authorization flow...");
        client
            .device_login(DEVICE_GRANT_SCOPE, |prompt| {
                eprintln!();
                if let Some(complete) = &prompt.verification_uri_complete {
                    eprintln!("  Open this URL on any browser:");
                    eprintln!("    {complete}");
                    eprintln!();
                    eprintln!(
                        "  Or visit {} and enter code: {}",
                        prompt.verification_uri, prompt.user_code
                    );
                } else {
                    eprintln!("  Open this URL on any browser:");
                    eprintln!("    {}", prompt.verification_uri);
                    eprintln!();
                    eprintln!("  Then enter code: {}", prompt.user_code);
                }
                eprintln!();
                eprintln!(
                    "  Code expires in {} seconds. Polling…",
                    prompt.expires_in.as_secs()
                );
                eprintln!();
            })
            .await?;
    } else {
        println!("Opening browser for authentication...");
        client.login().await?;
    }

    println!("Authenticated successfully!");
    Ok(())
}

/// Sign out of the kobe service.
///
/// Now uses `logout_async`: in addition to deleting the locally cached
/// token, attempts to **revoke** the refresh + access tokens at the
/// IdP via RFC 7009. Closes the leaked-laptop window where a stolen
/// refresh token would otherwise stay valid until natural expiry. If
/// the IdP doesn't advertise a revocation endpoint or the request
/// fails, the local cleanup still happens and the error is logged
/// (best-effort semantics).
pub async fn logout(context_override: Option<&str>, endpoint_override: Option<&str>) -> Result<()> {
    let config = CliConfig::load()?;
    let config = config.resolve(context_override, endpoint_override)?;
    let endpoint = config.endpoint.as_str();
    if config.auth != AuthMode::Oidc {
        println!(
            "Context uses auth={}. Browser logout is only needed for auth=oidc.",
            config.auth
        );
        return Ok(());
    }

    let service_config = discover_pinned(endpoint).await?;
    let client = AuthClient::new(service_config)?;
    client.logout_async().await?;

    println!("Logged out (token revoked at IdP).");
    Ok(())
}

/// Pin `service_config`'s issuer and audience for its endpoint, which the
/// user asked for explicitly with `kobe login --retrust`.
///
/// The pinned discovery used everywhere else refuses any change, so an
/// endpoint that moved from SSH auth (pinned under the `ssh` issuer sentinel)
/// to OIDC, or whose advertised audience changed, stays unusable until trust
/// is re-established. Returns a description of the change when the pin moved,
/// so the caller can show the user what they accepted.
fn retrust_pin(store: &TofuStore, service_config: &ServiceConfig) -> Result<Option<String>> {
    let endpoint = &service_config.endpoint;
    let issuer = &service_config.issuer;
    let audience = service_config.audience.as_deref().unwrap_or("");
    let change = match store.verify(endpoint, issuer, audience)? {
        TofuResult::Trusted => return Ok(None),
        TofuResult::FirstConnect { .. } => None,
        TofuResult::IssuerChanged {
            previous, current, ..
        } => Some(format!(
            "Re-pinned the auth issuer for {endpoint}: {previous:?} -> {current:?} \
             (audience now {audience:?})"
        )),
        TofuResult::AudienceChanged {
            previous, current, ..
        } => Some(format!(
            "Re-pinned the auth audience for {endpoint}: {previous:?} -> {current:?}"
        )),
        other => anyhow::bail!("unexpected TOFU result for {endpoint}: {other:?}"),
    };
    store.trust(endpoint, issuer, audience)?;
    Ok(change)
}

/// Discover `endpoint`'s auth configuration, checked against the trusted pin.
///
/// Every OIDC command goes through here, so a pin mismatch reads the same from
/// `kobe status` as from `kobe login`.
pub(crate) async fn discover_pinned(endpoint: &str) -> Result<ServiceConfig> {
    ServiceConfig::discover(endpoint)
        .await
        .map_err(retrust_hint)
}

/// Replace kunobi-auth's pin-mismatch hint with the command that fixes it.
///
/// The library ends its TOFU errors by pointing at its own `trust()` function,
/// which a CLI user cannot call. Keep what changed, drop that hint, and name
/// `kobe login --retrust`. Any other error passes through unchanged.
fn retrust_hint(error: anyhow::Error) -> anyhow::Error {
    let message = error.to_string();
    let Some(detail) = message.strip_prefix("TOFU: ") else {
        return error;
    };
    let detail = [
        ". If this change is expected",
        "; call trust()",
        "; re-run trust()",
    ]
    .iter()
    .find_map(|hint| detail.split_once(hint).map(|(kept, _)| kept))
    .unwrap_or(detail);
    anyhow::anyhow!(
        "{detail}. If the server's auth changed on purpose, for example from SSH keys to OIDC, \
         run `kobe login --retrust`"
    )
}

#[cfg(test)]
mod tests {
    /// Every kunobi-auth TOFU message loses its `trust()` hint and names the
    /// command a user can run.
    #[test]
    fn a_pin_mismatch_names_kobe_login_retrust_instead_of_trust() {
        for (library, kept) in [
            (
                "TOFU: audience changed for https://kobe.example (possible MITM): pinned \"kobe-system\", presented \"\". If this change is expected, re-establish trust explicitly with trust()",
                "audience changed for https://kobe.example (possible MITM): pinned \"kobe-system\", presented \"\"",
            ),
            (
                "TOFU: issuer changed for https://kobe.example (possible MITM): pinned \"ssh\", presented \"https://clerk.example\". If this change is expected, re-establish trust explicitly with trust()",
                "issuer changed for https://kobe.example (possible MITM): pinned \"ssh\", presented \"https://clerk.example\"",
            ),
            (
                "TOFU: refusing to trust unpinned service https://kobe.example; call trust() to establish first-use trust",
                "refusing to trust unpinned service https://kobe.example",
            ),
        ] {
            let message = super::retrust_hint(anyhow::anyhow!(library)).to_string();
            assert!(message.starts_with(kept), "{message}");
            assert!(message.ends_with("run `kobe login --retrust`"), "{message}");
            assert!(!message.contains("trust()"), "{message}");
        }
    }

    #[test]
    fn other_errors_pass_through_unchanged() {
        let message = super::retrust_hint(anyhow::anyhow!("connection refused")).to_string();
        assert_eq!(message, "connection refused");
    }

    use super::*;

    fn oidc_config(audience: Option<&str>) -> ServiceConfig {
        let mut config = ServiceConfig::new("https://kobe.example", "https://idp.example", "cli");
        config.audience = audience.map(str::to_string);
        config
    }

    fn store(directory: &tempfile::TempDir) -> TofuStore {
        TofuStore::with_path(directory.path().join("known.json"))
    }

    #[test]
    fn retrust_moves_an_ssh_pin_to_the_oidc_issuer() {
        let directory = tempfile::tempdir().unwrap();
        let store = store(&directory);
        store
            .trust("https://kobe.example", "ssh", "kobe-system")
            .unwrap();
        let config = oidc_config(None);

        // Without --retrust the pinned discovery refuses the new issuer.
        assert!(
            store
                .check_and_pin("https://kobe.example", "https://idp.example", "")
                .is_err()
        );

        let change = retrust_pin(&store, &config).unwrap().unwrap();
        assert!(
            change.contains("\"ssh\" -> \"https://idp.example\""),
            "{change}"
        );
        // Once re-pinned, every later pinned discovery accepts it.
        store
            .check_and_pin("https://kobe.example", "https://idp.example", "")
            .unwrap();
    }

    #[test]
    fn retrust_moves_a_changed_audience() {
        let directory = tempfile::tempdir().unwrap();
        let store = store(&directory);
        store
            .trust("https://kobe.example", "https://idp.example", "cli")
            .unwrap();

        let change = retrust_pin(&store, &oidc_config(None)).unwrap().unwrap();
        assert!(change.contains("audience"), "{change}");
        store
            .check_and_pin("https://kobe.example", "https://idp.example", "")
            .unwrap();
    }

    #[test]
    fn retrust_is_silent_when_the_pin_already_matches_or_is_new() {
        let directory = tempfile::tempdir().unwrap();
        let store = store(&directory);
        assert_eq!(
            retrust_pin(&store, &oidc_config(Some("kobe"))).unwrap(),
            None
        );
        assert_eq!(
            retrust_pin(&store, &oidc_config(Some("kobe"))).unwrap(),
            None
        );
        store
            .check_and_pin("https://kobe.example", "https://idp.example", "kobe")
            .unwrap();
    }
}
