use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// A normalized telemetry event from the environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryEvent {
    pub source: String,
    pub event_id: String,
    pub timestamp: i64,
    pub host_id: Option<String>,
    pub payload: TelemetryPayload,
}

/// Normalized payload kinds shared across detectors and telemetry bridges.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryPayload {
    ProcessStart(ProcessStartEvent),
    NetworkConnect(NetworkConnectEvent),
    DnsQuery(DnsQueryEvent),
    RegistryAccess(RegistryAccessEvent),
    AuthenticationEvent(AuthenticationEventData),
}

/// Normalized process execution event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStartEvent {
    pub parent_process: String,
    pub process_name: String,
    pub command_line: String,
    pub user: Option<String>,
}

/// Normalized outbound network event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConnectEvent {
    pub process_name: String,
    pub destination_ip: String,
    pub destination_port: u16,
    pub protocol: String,
}

/// Normalized DNS query event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsQueryEvent {
    pub query_name: String,
    pub query_type: String,
    pub source_ip: Option<String>,
    pub process_name: Option<String>,
    pub response_code: Option<String>,
}

/// Normalized registry or protected-process access event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryAccessEvent {
    pub process_name: String,
    pub registry_path: String,
    pub access_type: String,
    pub target_process: Option<String>,
}

/// Normalized authentication or remote-access event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationEventData {
    pub auth_type: String,
    pub source_host: Option<String>,
    pub target_host: Option<String>,
    pub target_service: Option<String>,
    pub process_name: Option<String>,
    pub success: bool,
    pub user: Option<String>,
}

/// Shared bridge-health status surfaced by telemetry bridge implementations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BridgeHealth {
    pub source_id: String,
    pub ready: bool,
    pub events_processed: u64,
    pub error_count: u64,
    pub lag_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl BridgeHealth {
    pub fn new(source_id: impl Into<String>) -> Self {
        Self {
            source_id: source_id.into(),
            ready: false,
            events_processed: 0,
            error_count: 0,
            lag_seconds: None,
            last_error: None,
        }
    }

    pub fn record_event(&mut self, timestamp: i64) {
        self.ready = true;
        self.events_processed = self.events_processed.saturating_add(1);
        self.lag_seconds = current_unix_seconds()
            .checked_sub(timestamp)
            .map(|lag| lag.max(0) as f64);
        self.last_error = None;
    }

    pub fn record_error(&mut self, message: impl Into<String>) {
        self.ready = false;
        self.error_count = self.error_count.saturating_add(1);
        self.last_error = Some(message.into());
    }
}

/// Errors surfaced by telemetry bridge implementations.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryBridgeError {
    #[error("bridge connection failed: {0}")]
    Connection(String),

    #[error("bridge mapping failed: {0}")]
    Mapping(String),

    #[error("bridge schema validation failed: {0}")]
    Schema(String),

    #[error("bridge unavailable: {0}")]
    Unavailable(String),
}

pub type TelemetryBridgeResult<T> = std::result::Result<T, TelemetryBridgeError>;

/// Common contract for bridge adapters that normalize external telemetry into shared events.
#[async_trait]
pub trait TelemetryBridge: Send {
    fn source_id(&self) -> &str;

    async fn poll(&mut self) -> TelemetryBridgeResult<Vec<TelemetryEvent>>;

    fn validate_schema(&self, event: &TelemetryEvent) -> bool;

    fn health(&self) -> BridgeHealth;
}

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::BridgeHealth;

    #[test]
    fn bridge_health_tracks_events_and_errors() {
        let mut health = BridgeHealth::new("synthetic");
        assert!(!health.ready);
        assert_eq!(health.events_processed, 0);
        assert_eq!(health.error_count, 0);

        health.record_event(1_700_000_000);
        assert!(health.ready);
        assert_eq!(health.events_processed, 1);
        assert!(health.lag_seconds.is_some());
        assert_eq!(health.last_error, None);

        health.record_error("bridge disconnected");
        assert!(!health.ready);
        assert_eq!(health.error_count, 1);
        assert_eq!(health.last_error.as_deref(), Some("bridge disconnected"));
    }
}
