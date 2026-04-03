use serde::{Deserialize, Serialize};

/// Top-level runtime configuration for the first Rust-only slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Whether adapters may execute live side effects.
    pub live_response_enabled: bool,
    /// Telemetry subjects or sources to subscribe to.
    pub telemetry_sources: Vec<TelemetrySourceConfig>,
    /// Maximum number of concurrent response executions.
    pub max_in_flight_actions: usize,
}

/// Describes a telemetry stream or bridge configured for the runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySourceConfig {
    pub name: String,
    pub subject: String,
}
