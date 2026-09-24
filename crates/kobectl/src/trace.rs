//! Opt-in request tracing for the CLI.
//!
//! The CLI had no logging of any kind, which is why a stray `GET
//! /v1/pools/ci-small` in CI could not be attributed to a command: the only
//! evidence was a test server's view of the wire, and nothing on this side
//! said who asked or why. Turning it on prints one line per request and one
//! per response, to stderr, so a failure carries the sequence that produced
//! it.
//!
//! Deliberately not a logging framework. `kobectl` is published to crates.io
//! with a slim dependency tree, and this needs no filtering, no levels and no
//! subscriber — one environment variable and `eprintln!`.
//!
//! # Where it writes, and why that matters
//!
//! stderr, always. stdout carries `--output json`, and a trace line mixed into
//! it would break every machine consumer the moment someone turned this on to
//! debug one.
//!
//! # Turning it on
//!
//! ```text
//! KOBE_TRACE=1 kobe status
//! ```
//!
//! CI enables it for the integration tests that have flaked on unexplained
//! requests, so the next occurrence names the caller instead of leaving a
//! server-side path and no origin.

use std::sync::OnceLock;
use std::time::Instant;

/// Whether `KOBE_TRACE` asks for request tracing.
///
/// Read once: the environment cannot change under a CLI invocation, and a
/// per-request read would be the only syscall on an otherwise local path.
pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("KOBE_TRACE").is_some_and(|value| value != "0" && !value.is_empty())
    })
}

/// Send `builder`, tracing the request and what came back.
///
/// Takes the builder apart with `build_split` so the method and URL can be
/// named before anything is sent — including when the send fails, which is
/// exactly the case where knowing what was attempted matters most.
pub(crate) async fn send(builder: reqwest::RequestBuilder) -> reqwest::Result<reqwest::Response> {
    if !enabled() {
        return builder.send().await;
    }

    let (client, request) = builder.build_split();
    let request = match request {
        Ok(request) => request,
        Err(error) => {
            eprintln!("[kobe-trace] request could not be built: {error}");
            return Err(error);
        }
    };
    // The URL is printed whole. A query string is where a wrong id or a stale
    // cursor hides, and this output is already opt-in and local.
    let method = request.method().clone();
    let url = request.url().clone();
    eprintln!("[kobe-trace] -> {method} {url}");

    let started = Instant::now();
    let result = client.execute(request).await;
    let elapsed = started.elapsed();
    match &result {
        Ok(response) => eprintln!(
            "[kobe-trace] <- {} {method} {url} in {elapsed:?}",
            response.status().as_u16()
        ),
        Err(error) => eprintln!("[kobe-trace] <- ERR {method} {url} in {elapsed:?}: {error}"),
    }
    result
}

#[cfg(test)]
mod tests {
    /// `enabled` is cached, so these assert on the parsing rule rather than on
    /// the cached value — a test that set the variable would race every other
    /// test in the binary and win or lose depending on order.
    fn asks_for_tracing(value: Option<&str>) -> bool {
        value.is_some_and(|value| value != "0" && !value.is_empty())
    }

    #[test]
    fn only_a_meaningful_value_turns_tracing_on() {
        assert!(asks_for_tracing(Some("1")));
        assert!(asks_for_tracing(Some("true")));
        assert!(!asks_for_tracing(Some("0")), "0 is off, not 'set'");
        assert!(!asks_for_tracing(Some("")), "empty is off, not 'set'");
        assert!(!asks_for_tracing(None));
    }
}
