use opentelemetry::{KeyValue, trace::TracerProvider as _};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
	Resource,
	trace::{Sampler, SdkTracerProvider},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;

pub struct TelemetryGuard {
	tracer_provider: Option<SdkTracerProvider>,
}

impl Drop for TelemetryGuard {
	fn drop(&mut self) {
		if let Some(provider) = self.tracer_provider.take() {
			let _ = provider.shutdown();
		}
	}
}

pub fn init(config: &Config) -> Result<TelemetryGuard, String> {
	if !config.telemetry.enabled {
		if config.telemetry.console_logs {
			tracing_subscriber::registry()
				.with(tracing_subscriber::fmt::layer())
				.try_init()
				.map_err(|e| format!("tracing subscriber init failed: {e}"))?;
		}
		return Ok(TelemetryGuard {
			tracer_provider: None,
		});
	}

	let exporter = opentelemetry_otlp::SpanExporter::builder()
		.with_http()
		.with_endpoint(config.telemetry.otlp_endpoint.clone())
		.build()
		.map_err(|e| format!("OTLP span exporter init failed: {e}"))?;

	let sample_ratio = config.telemetry.sample_ratio.clamp(0.0, 1.0);
	let tracer_provider = SdkTracerProvider::builder()
		.with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
			sample_ratio,
		))))
		.with_resource(
			Resource::builder_empty()
				.with_attributes(vec![
					KeyValue::new("service.name", config.telemetry.service_name.clone()),
					KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
				])
				.build(),
		)
		.with_batch_exporter(exporter)
		.build();

	let tracer = tracer_provider.tracer(config.telemetry.service_name.clone());
	let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
	tracing_subscriber::registry()
		.with(config.telemetry.console_logs.then(tracing_subscriber::fmt::layer))
		.with(otel_layer)
		.try_init()
		.map_err(|e| format!("tracing subscriber init failed: {e}"))?;

	Ok(TelemetryGuard {
		tracer_provider: Some(tracer_provider),
	})
}
