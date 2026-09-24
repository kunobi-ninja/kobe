//! Opt-in request tracing, behind `KOBE_TRACE`.
//!
//! The CLI had no logging of any kind, so a stray `GET /v1/pools/ci-small` in
//! CI could not be attributed: the only evidence was a test server's view of
//! the wire, with no origin. One line per request and one per response is
//! enough to name the caller.
//!
//! stderr, always — stdout carries `--output json`, and a trace line in it
//! would break every machine consumer the moment somebody debugged one.
//!
//! No logging framework: `kobectl` ships a slim dependency tree, and this
//! needs no levels, filtering or subscriber.

use std::sync::OnceLock;
use std::time::Instant;

/// Read once: the environment cannot change under a CLI invocation.
pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("KOBE_TRACE").is_some_and(|value| value != "0" && !value.is_empty())
    })
}

/// Send `builder`, tracing the request and what came back.
///
/// `build_split` names the request before it goes out, so a send that fails
/// still reports what was attempted — the case where it matters most.
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
