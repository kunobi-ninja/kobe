use anyhow::Result;
use opentelemetry::trace::TracerProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize the tracing subscriber with optional OpenTelemetry export.
///
/// When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, spans are exported via OTLP gRPC.
/// When unset, only the fmt/JSON layer is active (current behavior preserved).
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
            .with(fmt_layer)
            .with(otel_layer)
            .init();

        Ok(Some(provider))
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
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
