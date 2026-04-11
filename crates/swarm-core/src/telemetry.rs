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
    ProcessMemoryAccess(ProcessMemoryAccessEvent),
    NetworkConnect(NetworkConnectEvent),
    DnsQuery(DnsQueryEvent),
    RegistryAccess(RegistryAccessEvent),
    RegistryPersistence(RegistryPersistenceEvent),
    FilePersistence(FilePersistenceEvent),
    AuthenticationEvent(AuthenticationEventData),
    InfrastructureHealth(InfrastructureHealthEvent),
    ThermalAnomaly(ThermalAnomalyEvent),
    ResourceExhaustion(ResourceExhaustionEvent),
}

/// Normalized process execution event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStartEvent {
    pub parent_process: String,
    pub process_name: String,
    pub command_line: String,
    pub user: Option<String>,
    pub executable_path: Option<String>,
    pub signer: Option<String>,
    pub signature_valid: Option<bool>,
}

/// Normalized process memory access event for fileless and injection-style detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessMemoryAccessEvent {
    pub source_process: String,
    pub target_process: String,
    pub allocation_type: String,
    pub protection_flags: Vec<String>,
    pub region_size: u64,
    pub call_stack_hint: Option<String>,
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

/// Normalized registry-based persistence event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryPersistenceEvent {
    pub process_name: String,
    pub registry_path: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub access_type: String,
}

/// Normalized file-based persistence or side-loading artifact event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePersistenceEvent {
    pub file_path: String,
    pub operation: String,
    pub process_name: String,
    pub content_preview: Option<String>,
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

/// Infrastructure health snapshot from a node monitoring source such as Sentinel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureHealthEvent {
    pub node_name: String,
    pub cpu_usage_percent: f64,
    pub cpu_frequency_mhz: f64,
    pub load_average_1m: f64,
    pub load_average_5m: f64,
    pub load_average_15m: f64,
    pub memory_usage_percent: f64,
    pub memory_available_bytes: u64,
    pub disk_usage_percent: f64,
    pub disk_io_latency_ms: f64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub network_rx_errors: u64,
    pub network_tx_errors: u64,
    pub failure_probability: f64,
    pub prediction_confidence: f64,
    pub time_to_failure_secs: f64,
    pub collection_duration_ms: f64,
}

/// Thermal anomaly detected on a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThermalAnomalyEvent {
    pub node_name: String,
    pub temperature_celsius: f64,
    pub cpu_throttled: bool,
    pub trend_slope: f64,
    pub severity: ThermalSeverity,
    pub estimated_time_to_critical_secs: f64,
}

/// Severity classification for node thermal anomalies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThermalSeverity {
    Normal,
    Elevated,
    High,
    Critical,
}

/// Resource exhaustion event from node infrastructure telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceExhaustionEvent {
    pub node_name: String,
    pub resource_kind: ExhaustedResource,
    pub utilization_percent: f64,
    pub current_value: u64,
    pub capacity_value: u64,
    pub oom_kill_count: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    pub is_new: bool,
}

/// Classification of exhausted resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExhaustedResource {
    Memory,
    Disk,
    Cpu,
    Swap,
    NetworkBandwidth,
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
    use super::{
        BridgeHealth, ExhaustedResource, InfrastructureHealthEvent, ProcessMemoryAccessEvent,
        ResourceExhaustionEvent, TelemetryEvent, TelemetryPayload, ThermalAnomalyEvent,
        ThermalSeverity,
    };

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

    #[test]
    fn infrastructure_payload_variants_round_trip_with_expected_kind_tags() {
        let event = TelemetryEvent {
            source: "sentinel".to_string(),
            event_id: "sentinel:node-a:health:1700000000".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("node-a".to_string()),
            payload: TelemetryPayload::InfrastructureHealth(InfrastructureHealthEvent {
                node_name: "node-a".to_string(),
                cpu_usage_percent: 88.0,
                cpu_frequency_mhz: 3400.0,
                load_average_1m: 12.0,
                load_average_5m: 8.0,
                load_average_15m: 4.0,
                memory_usage_percent: 91.0,
                memory_available_bytes: 512,
                disk_usage_percent: 72.0,
                disk_io_latency_ms: 16.0,
                network_rx_bytes: 128,
                network_tx_bytes: 256,
                network_rx_errors: 0,
                network_tx_errors: 0,
                failure_probability: 0.72,
                prediction_confidence: 0.88,
                time_to_failure_secs: 120.0,
                collection_duration_ms: 9.0,
            }),
        };
        let thermal = TelemetryPayload::ThermalAnomaly(ThermalAnomalyEvent {
            node_name: "node-a".to_string(),
            temperature_celsius: 81.0,
            cpu_throttled: true,
            trend_slope: 6.0,
            severity: ThermalSeverity::High,
            estimated_time_to_critical_secs: 45.0,
        });
        let exhaustion = TelemetryPayload::ResourceExhaustion(ResourceExhaustionEvent {
            node_name: "node-a".to_string(),
            resource_kind: ExhaustedResource::Memory,
            utilization_percent: 93.0,
            current_value: 930,
            capacity_value: 1000,
            oom_kill_count: Some(1),
            swap_used_bytes: Some(2048),
            is_new: true,
        });

        let encoded = serde_json::to_value(&event).unwrap();
        assert_eq!(
            encoded.get("payload").and_then(|value| value.get("kind")),
            Some(&serde_json::Value::String(
                "infrastructure_health".to_string()
            ))
        );

        let thermal_encoded = serde_json::to_value(&thermal).unwrap();
        assert_eq!(
            thermal_encoded.get("kind"),
            Some(&serde_json::Value::String("thermal_anomaly".to_string()))
        );

        let exhaustion_encoded = serde_json::to_value(&exhaustion).unwrap();
        assert_eq!(
            exhaustion_encoded.get("kind"),
            Some(&serde_json::Value::String(
                "resource_exhaustion".to_string()
            ))
        );
    }

    #[test]
    fn process_memory_access_payload_round_trips_with_expected_kind_tag() {
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-memory-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-a".to_string()),
            payload: TelemetryPayload::ProcessMemoryAccess(ProcessMemoryAccessEvent {
                source_process: "powershell.exe".to_string(),
                target_process: "lsass.exe".to_string(),
                allocation_type: "private".to_string(),
                protection_flags: vec![
                    "PAGE_EXECUTE_READWRITE".to_string(),
                    "PAGE_READWRITE".to_string(),
                ],
                region_size: 16384,
                call_stack_hint: Some("NtWriteVirtualMemory -> HellsGate".to_string()),
            }),
        };

        let encoded = serde_json::to_value(&event).unwrap();
        assert_eq!(
            encoded.get("payload").and_then(|value| value.get("kind")),
            Some(&serde_json::Value::String(
                "process_memory_access".to_string()
            ))
        );
    }
}
