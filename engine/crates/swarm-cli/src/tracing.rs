use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Default)]
pub struct TracingGuard {
    tracer_provider: Option<SdkTracerProvider>,
}

impl Drop for TracingGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take()
            && let Err(error) = provider.shutdown()
        {
            eprintln!("failed to flush tracing provider: {error}");
        }
    }
}

pub fn init_tracing(
    service_name: &str,
    otlp_endpoint: Option<&str>,
) -> Result<TracingGuard, Box<dyn std::error::Error>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = fmt::layer()
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(false)
        .with_writer(std::io::stderr);

    if let Some(endpoint) = otlp_endpoint.filter(|value| !value.trim().is_empty()) {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .with_protocol(Protocol::HttpBinary)
            .build()?;
        let tracer_provider = SdkTracerProvider::builder()
            .with_resource(
                Resource::builder_empty()
                    .with_attributes([KeyValue::new("service.name", service_name.to_string())])
                    .build(),
            )
            .with_batch_exporter(exporter)
            .build();
        let tracer = tracer_provider.tracer(service_name.to_string());
        let telemetry = OpenTelemetryLayer::new(tracer);
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .with(telemetry)
            .try_init()?;
        Ok(TracingGuard {
            tracer_provider: Some(tracer_provider),
        })
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init()?;
        Ok(TracingGuard::default())
    }
}
