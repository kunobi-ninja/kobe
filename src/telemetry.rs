use anyhow::Result;
use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Log targets whose own diagnostics print the bytes on the wire.
///
/// `tungstenite` is the WebSocket implementation underneath `kube`'s exec
/// channel, and several of its `trace`/`debug` records are payload dumps: the
/// frame writer renders the complete frame — `payload: 0x…` — as hex, and the
/// client handshake logs the request verbatim.
///
/// That matters here more than it would in most services. A caller's stdin is
/// carried to a Sandbox as a binary WebSocket frame *specifically* so the
/// secret stays out of the argv the target apiserver audit-logs; a frame dump
/// puts it straight back into a durable log, and hex-decode → strip the channel
/// byte → base64-decode recovers it exactly. Kobe's own masking cannot help:
/// it is applied to what Kobe formats, and this record is formatted inside the
/// transport.
const PAYLOAD_DUMPING_TARGETS: &[&str] = &["tungstenite"];

/// Whether an event may be emitted at all, before any `RUST_LOG` is consulted.
///
/// The default filter already excludes [`PAYLOAD_DUMPING_TARGETS`], but
/// "excluded by default" is a configuration, not a property: `RUST_LOG=trace`,
/// or a `tungstenite=debug` directive added while chasing an unrelated
/// connection problem, re-enables the dump — and nothing would tell the
/// operator they had just started logging every forwarded credential.
///
/// `WARN` and above still pass. A WebSocket that is failing must be able to say
/// so; nothing tungstenite logs at that level carries a frame.
fn payload_is_never_dumped(metadata: &tracing::Metadata<'_>) -> bool {
    if *metadata.level() <= tracing::Level::WARN {
        return true;
    }
    let target = metadata.target();
    !PAYLOAD_DUMPING_TARGETS.iter().any(|dumping| {
        target
            .strip_prefix(dumping)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
    })
}

/// The suppression, as a layer of its own.
///
/// A *global* filter on the registry rather than another [`EnvFilter`]
/// directive: directive precedence is a property of the string an operator
/// supplied, so competing with it there would leave the guarantee depending on
/// what they wrote. A separate layer is consulted for every event whatever the
/// filter says — including events bridged in from the `log` crate, which is how
/// `tungstenite` (a `log` user, not a `tracing` one) actually reaches this
/// subscriber.
fn payload_dump_guard() -> tracing_subscriber::filter::FilterFn<fn(&tracing::Metadata<'_>) -> bool>
{
    tracing_subscriber::filter::filter_fn(
        payload_is_never_dumped as fn(&tracing::Metadata<'_>) -> bool,
    )
}

/// Initialize the tracing subscriber with optional OpenTelemetry export.
///
/// When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, spans are exported via OTLP gRPC.
/// The Helm chart exposes this through `telemetry.otlp`; `OTEL_SERVICE_NAME`
/// and standard OpenTelemetry resource attributes distinguish deployments in
/// a shared backend. When unset, only the fmt/JSON layer is active.
///
/// The operator's `RUST_LOG` is honoured for everything except
/// [`PAYLOAD_DUMPING_TARGETS`], which [`payload_dump_guard`] holds at `WARN`
/// unconditionally — see there for why that one exception is not negotiable.
///
/// Returns the tracer provider handle for graceful shutdown (flush on drop).
pub fn init() -> Result<Option<SdkTracerProvider>> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "kobe_operator=info,tower_http=info".into());

    let fmt_layer = tracing_subscriber::fmt::layer().json();

    let otel_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

    if let Some(_endpoint) = otel_endpoint {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .build()?;

        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(
                opentelemetry_sdk::Resource::builder()
                    .with_service_name(
                        std::env::var("OTEL_SERVICE_NAME")
                            .unwrap_or_else(|_| "kobe-operator".into()),
                    )
                    .build(),
            )
            .build();

        let tracer = provider.tracer("kobe-operator");
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(payload_dump_guard())
            .with(fmt_layer)
            .with(otel_layer)
            .init();

        Ok(Some(provider))
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(payload_dump_guard())
            .with(fmt_layer)
            .init();

        Ok(None)
    }
}

/// Gracefully shut down the OTel pipeline, flushing any pending spans.
pub fn shutdown(provider: Option<SdkTracerProvider>) {
    if let Some(provider) = provider
        && let Err(e) = provider.shutdown()
    {
        eprintln!("OpenTelemetry shutdown error: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A writer that keeps what the subscriber emitted.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("capture buffer")
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for Captured {
        type Writer = Captured;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    /// Emit through exactly the stack [`init`] installs, for one `RUST_LOG`.
    ///
    /// The spec is passed rather than read from the environment so a hostile
    /// operator setting can be exercised without a process-wide mutation that
    /// every other test in this binary would see.
    fn emitted_under(spec: &str, emit: impl FnOnce()) -> String {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::registry()
            .with(EnvFilter::new(spec))
            .with(payload_dump_guard())
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(captured.clone()),
            );
        tracing::subscriber::with_default(subscriber, emit);
        String::from_utf8(captured.0.lock().expect("capture buffer").clone())
            .expect("subscriber output is UTF-8")
    }

    /// No `RUST_LOG` can turn the WebSocket frame dump back on.
    ///
    /// A caller's stdin reaches the Sandbox as a binary WebSocket frame, which
    /// is the whole point: it keeps the secret out of the argv the target
    /// apiserver audit-logs. `tungstenite` renders that frame's complete
    /// payload as hex at `trace`, so an operator debugging an unrelated
    /// connection problem with `RUST_LOG=trace` would write every forwarded
    /// token into Kobe's own JSON logs, in a form a hex-then-base64 decode
    /// recovers exactly.
    #[test]
    fn no_rust_log_can_re_enable_the_websocket_payload_dump() {
        // The hex a frame carrying "hunter2" would print.
        let payload_hex = "68756e74657232";

        for hostile in [
            "trace",
            "tungstenite=trace",
            "tungstenite::protocol::frame=trace",
            "kobe_operator=info,tungstenite=debug",
        ] {
            let emitted = emitted_under(hostile, || {
                tracing::trace!(
                    target: "tungstenite::protocol::frame",
                    "writing frame <FRAME> payload: 0x{payload_hex}"
                );
                tracing::debug!(target: "tungstenite", "Sending frame: 0x{payload_hex}");
            });

            assert!(
                !emitted.contains(payload_hex),
                "RUST_LOG={hostile} put a frame payload in the logs: {emitted}"
            );
        }
    }

    /// The suppression is a level floor on one target, not a blanket mute.
    ///
    /// A guard that silenced the transport outright would trade a disclosure
    /// for a blind spot: a WebSocket that keeps resetting is exactly what an
    /// operator turns `RUST_LOG` up to diagnose, and nothing tungstenite emits
    /// at `WARN` or above carries a frame. Everything outside the guarded
    /// targets stays entirely the operator's decision.
    #[test]
    fn the_payload_guard_costs_no_diagnostics_above_warn() {
        let emitted = emitted_under("trace", || {
            tracing::warn!(target: "tungstenite", "connection reset by peer");
            tracing::error!(target: "tungstenite::protocol", "protocol violation");
            tracing::trace!(target: "kobe_operator::api", "execution started");
            tracing::trace!(target: "tungstenite_lookalike", "not a guarded target");
        });

        for surviving in [
            "connection reset by peer",
            "protocol violation",
            "execution started",
            "not a guarded target",
        ] {
            assert!(
                emitted.contains(surviving),
                "the guard swallowed {surviving:?}: {emitted}"
            );
        }
    }
}
