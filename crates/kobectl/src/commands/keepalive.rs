//! #107 P3 — heartbeat-extend a lease for the lifetime of some activity: a
//! foreground `kobe lease --keepalive`, or a `with-lease` wrapped command.

use std::future::Future;
use std::time::Duration;

use anyhow::Result;

use super::config::ResolvedConfig;
use super::extend::extend_lease;
use super::lease_create::parse_cli_duration;

/// Don't hammer the API for very short TTLs.
const MIN_INTERVAL: Duration = Duration::from_secs(15);
/// Used when the TTL string can't be parsed (the extend still passes it
/// verbatim to the server, which is the source of truth).
const DEFAULT_INTERVAL: Duration = Duration::from_secs(1800);

/// Half the TTL, floored at [`MIN_INTERVAL`] — re-extend well before expiry so a
/// slow request can't let the lease lapse.
pub(crate) fn heartbeat_interval(ttl: &str) -> Duration {
    parse_cli_duration(ttl)
        .map(|d| d / 2)
        .unwrap_or(DEFAULT_INTERVAL)
        .max(MIN_INTERVAL)
}

/// Re-extend `lease_id` by `ttl` every [`heartbeat_interval`] until `stop`
/// completes (Ctrl-C, or a wrapped command exiting) or the server refuses the
/// extension (the `max_extensions` / `max_ttl` ceiling). Ceiling/transport
/// errors stop the loop and are reported but not propagated — the caller still
/// wants to release the lease and report the wrapped command's own result.
pub(crate) async fn heartbeat_until<F: Future<Output = ()>>(
    config: &ResolvedConfig,
    lease_id: &str,
    ttl: &str,
    stop: F,
    verbose: bool,
) -> Result<()> {
    let interval = heartbeat_interval(ttl);
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = &mut stop => break,
            _ = tokio::time::sleep(interval) => {
                match extend_lease(config, lease_id, ttl).await {
                    Ok(expires_at) => {
                        if verbose {
                            eprintln!("Heartbeat: extended {lease_id} (expires {expires_at})");
                        }
                    }
                    Err(e) => {
                        eprintln!("Heartbeat stopped for {lease_id}: {e}");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_is_half_ttl_floored_at_min() {
        assert_eq!(heartbeat_interval("1h"), Duration::from_secs(1800));
        assert_eq!(heartbeat_interval("30m"), Duration::from_secs(900));
        // 10s/2 = 5s, floored at the 15s minimum.
        assert_eq!(heartbeat_interval("10s"), Duration::from_secs(15));
        // Unparseable -> default; the server still enforces the real TTL.
        assert_eq!(
            heartbeat_interval("not-a-duration"),
            Duration::from_secs(1800)
        );
    }
}
