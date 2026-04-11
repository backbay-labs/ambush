use crate::client::{EventType, GetEventsResponse, TetragonClient, proto};
use crate::error::{Error, Result};
use crate::mapper::map_process_exec;
use async_trait::async_trait;
use std::sync::Mutex;
use swarm_core::{
    BridgeHealth, ProcessStartEvent, TelemetryBridge, TelemetryBridgeError, TelemetryBridgeResult,
    TelemetryEvent, TelemetryPayload,
};
use tokio::sync::mpsc::Sender;
use tokio::time::{Duration, sleep};
use tokio_stream::StreamExt;
use tracing::warn;

const SOURCE_ID: &str = "tetragon";

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub endpoint: String,
    pub reconnect_backoff_ms: u64,
    pub max_reconnect_backoff_ms: u64,
    pub event_timeout_secs: u64,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:54321".to_string(),
            reconnect_backoff_ms: 1_000,
            max_reconnect_backoff_ms: 30_000,
            event_timeout_secs: 30,
        }
    }
}

pub struct TetragonBridge {
    config: BridgeConfig,
    stream: Option<tonic::Streaming<GetEventsResponse>>,
    reconnect_attempts: u32,
    health: Mutex<BridgeHealth>,
}

impl TetragonBridge {
    pub fn new(config: BridgeConfig) -> Self {
        Self {
            config,
            stream: None,
            reconnect_attempts: 0,
            health: Mutex::new(BridgeHealth::new(SOURCE_ID)),
        }
    }

    pub async fn run(&mut self, tx: Sender<TelemetryEvent>) -> Result<()> {
        loop {
            let events = self.poll().await.map_err(Error::from)?;
            for event in events {
                tx.send(event).await.map_err(|_| Error::ChannelClosed)?;
            }
        }
    }

    pub async fn run_once(&mut self, tx: Sender<TelemetryEvent>) -> Result<()> {
        let events = self.poll().await.map_err(Error::from)?;
        for event in events {
            tx.send(event).await.map_err(|_| Error::ChannelClosed)?;
        }
        Ok(())
    }

    async fn connect_stream(&mut self) -> TelemetryBridgeResult<()> {
        if self.stream.is_some() {
            return Ok(());
        }

        let mut client = match TetragonClient::connect(&self.config.endpoint).await {
            Ok(client) => client,
            Err(error) => {
                let message = error.to_string();
                self.sleep_on_disconnect(message.clone()).await;
                return Err(TelemetryBridgeError::Connection(message));
            }
        };
        let stream = match client
            .get_events(vec![EventType::ProcessExec], Vec::new())
            .await
        {
            Ok(stream) => stream,
            Err(error) => {
                let message = error.to_string();
                self.sleep_on_disconnect(message.clone()).await;
                return Err(TelemetryBridgeError::Connection(message));
            }
        };

        self.stream = Some(stream);
        let mut guard = self
            .health
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        guard.ready = true;
        guard.last_error = None;
        Ok(())
    }

    fn map_response(
        &self,
        response: GetEventsResponse,
    ) -> TelemetryBridgeResult<Option<TelemetryEvent>> {
        match response.event {
            Some(proto::get_events_response::Event::ProcessExec(exec)) => {
                let event = map_process_exec(&exec, &response.node_name).ok_or_else(|| {
                    TelemetryBridgeError::Mapping(
                        "process_exec event missing process payload".to_string(),
                    )
                })?;
                Ok(Some(event))
            }
            Some(_) => Ok(None),
            None => Err(TelemetryBridgeError::Mapping(
                "gRPC response missing event payload".to_string(),
            )),
        }
    }

    async fn sleep_on_disconnect(&mut self, message: String) {
        self.record_error(&message);
        let backoff = self.reconnect_backoff(self.reconnect_attempts);
        warn!(
            endpoint = %self.config.endpoint,
            backoff_ms = backoff.as_millis() as u64,
            error = %message,
            "tetragon bridge lost gRPC connectivity; retrying"
        );
        self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
        sleep(backoff).await;
    }

    fn record_event(&self, event: &TelemetryEvent) {
        let mut guard = self
            .health
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        guard.record_event(event.timestamp);
    }

    fn record_error(&self, message: &str) {
        let mut guard = self
            .health
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        guard.record_error(message.to_string());
    }

    fn process_start_schema_valid(process: &ProcessStartEvent) -> bool {
        !process.process_name.trim().is_empty() && !process.command_line.trim().is_empty()
    }

    fn reconnect_backoff(&self, attempts: u32) -> Duration {
        let shift = attempts.min(20);
        let multiplier = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        let max_backoff = self
            .config
            .max_reconnect_backoff_ms
            .max(self.config.reconnect_backoff_ms);
        let delay_ms = self
            .config
            .reconnect_backoff_ms
            .saturating_mul(multiplier)
            .min(max_backoff);
        Duration::from_millis(delay_ms)
    }
}

#[async_trait]
impl TelemetryBridge for TetragonBridge {
    fn source_id(&self) -> &str {
        SOURCE_ID
    }

    async fn poll(&mut self) -> TelemetryBridgeResult<Vec<TelemetryEvent>> {
        loop {
            self.connect_stream().await?;

            let Some(stream) = self.stream.as_mut() else {
                continue;
            };

            let timeout_duration = Duration::from_secs(self.config.event_timeout_secs);
            match tokio::time::timeout(timeout_duration, stream.next()).await {
                Ok(Some(Ok(response))) => {
                    let Some(event) = self.map_response(response)? else {
                        continue;
                    };
                    if !self.validate_schema(&event) {
                        let message = format!(
                            "bridge `{}` produced invalid normalized telemetry for event `{}`",
                            self.source_id(),
                            event.event_id
                        );
                        self.record_error(&message);
                        return Err(TelemetryBridgeError::Schema(message));
                    }
                    self.reconnect_attempts = 0;
                    self.record_event(&event);
                    return Ok(vec![event]);
                }
                Ok(Some(Err(error))) => {
                    self.stream = None;
                    let message = format!("event stream failed: {error}");
                    self.sleep_on_disconnect(message.clone()).await;
                    return Err(TelemetryBridgeError::Connection(message));
                }
                Ok(None) => {
                    self.stream = None;
                    let message = "event stream closed".to_string();
                    self.sleep_on_disconnect(message.clone()).await;
                    return Err(TelemetryBridgeError::Connection(message));
                }
                Err(_elapsed) => {
                    self.stream = None;
                    let message = format!(
                        "event stream silent for {}s; triggering reconnect",
                        self.config.event_timeout_secs
                    );
                    self.sleep_on_disconnect(message.clone()).await;
                    return Err(TelemetryBridgeError::Connection(message));
                }
            }
        }
    }

    fn validate_schema(&self, event: &TelemetryEvent) -> bool {
        if event.source != self.source_id() {
            return false;
        }
        if event.event_id.trim().is_empty() || event.timestamp <= 0 {
            return false;
        }

        match &event.payload {
            TelemetryPayload::ProcessStart(process) => Self::process_start_schema_valid(process),
            TelemetryPayload::NetworkConnect(connect) => {
                !connect.process_name.trim().is_empty()
                    && !connect.destination_ip.trim().is_empty()
                    && !connect.protocol.trim().is_empty()
            }
            TelemetryPayload::DnsQuery(query) => {
                !query.query_name.trim().is_empty() && !query.query_type.trim().is_empty()
            }
            TelemetryPayload::RegistryAccess(access) => {
                !access.process_name.trim().is_empty()
                    && !access.registry_path.trim().is_empty()
                    && !access.access_type.trim().is_empty()
            }
            TelemetryPayload::RegistryPersistence(persistence) => {
                !persistence.process_name.trim().is_empty()
                    && !persistence.registry_path.trim().is_empty()
                    && !persistence.access_type.trim().is_empty()
            }
            TelemetryPayload::FilePersistence(file) => {
                !file.file_path.trim().is_empty()
                    && !file.operation.trim().is_empty()
                    && !file.process_name.trim().is_empty()
            }
            TelemetryPayload::AuthenticationEvent(auth) => !auth.auth_type.trim().is_empty(),
            TelemetryPayload::ProcessMemoryAccess(_) => false,
            TelemetryPayload::InfrastructureHealth(_)
            | TelemetryPayload::ThermalAnomaly(_)
            | TelemetryPayload::ResourceExhaustion(_) => false,
        }
    }

    fn health(&self) -> BridgeHealth {
        self.health
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{BridgeConfig, TetragonBridge};
    use crate::client::proto;
    use prost_types::Timestamp;
    use swarm_core::{TelemetryBridge, TelemetryBridgeError, TelemetryEvent, TelemetryPayload};
    use tokio::time::Duration;

    fn make_exec() -> proto::ProcessExec {
        proto::ProcessExec {
            process: Some(proto::Process {
                exec_id: "exec-1".to_string(),
                binary: "/usr/bin/bash".to_string(),
                arguments: "-lc whoami".to_string(),
                uid: Some(1000),
                start_time: Some(Timestamp {
                    seconds: 123,
                    nanos: 0,
                }),
                ..Default::default()
            }),
            parent: Some(proto::Process {
                binary: "/usr/bin/sshd".to_string(),
                ..Default::default()
            }),
            ancestors: Vec::new(),
        }
    }

    #[test]
    fn process_exec_response_maps_to_normalized_event() {
        let bridge = TetragonBridge::new(BridgeConfig::default());

        let event = bridge
            .map_response(proto::GetEventsResponse {
                event: Some(proto::get_events_response::Event::ProcessExec(make_exec())),
                node_name: "node-a".to_string(),
                ..Default::default()
            })
            .expect("mapping should succeed")
            .expect("process exec should yield one event");
        assert_eq!(event.event_id, "tetragon:node-a:exec-1");
        assert!(bridge.validate_schema(&event));
    }

    #[test]
    fn missing_event_payload_returns_mapping_error() {
        let bridge = TetragonBridge::new(BridgeConfig::default());

        let error = bridge
            .map_response(proto::GetEventsResponse::default())
            .expect_err("response should fail");
        assert!(matches!(error, TelemetryBridgeError::Mapping(_)));
    }

    #[tokio::test]
    async fn health_reports_processed_events() {
        let bridge = TetragonBridge::new(BridgeConfig::default());
        let event =
            crate::mapper::map_process_exec(&make_exec(), "node-a").expect("event should map");
        bridge.record_event(&event);

        let health = bridge.health();
        assert_eq!(health.source_id, "tetragon");
        assert_eq!(health.events_processed, 1);
        assert_eq!(health.error_count, 0);
        assert!(health.ready);
    }

    #[test]
    fn reconnect_backoff_grows_exponentially_and_caps() {
        let bridge = TetragonBridge::new(BridgeConfig {
            endpoint: "http://127.0.0.1:54321".to_string(),
            reconnect_backoff_ms: 500,
            max_reconnect_backoff_ms: 4_000,
            event_timeout_secs: 30,
        });

        assert_eq!(bridge.reconnect_backoff(0), Duration::from_millis(500));
        assert_eq!(bridge.reconnect_backoff(1), Duration::from_millis(1_000));
        assert_eq!(bridge.reconnect_backoff(2), Duration::from_millis(2_000));
        assert_eq!(bridge.reconnect_backoff(3), Duration::from_millis(4_000));
        assert_eq!(bridge.reconnect_backoff(4), Duration::from_millis(4_000));
    }

    #[test]
    fn validate_schema_rejects_empty_process_name() {
        let bridge = TetragonBridge::new(BridgeConfig::default());
        let event = TelemetryEvent {
            source: "tetragon".to_string(),
            event_id: "evt-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("node-a".to_string()),
            payload: TelemetryPayload::ProcessStart(swarm_core::ProcessStartEvent {
                parent_process: "sshd".to_string(),
                process_name: String::new(),
                command_line: "bash -lc whoami".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };

        assert!(!bridge.validate_schema(&event));
    }

    #[test]
    fn validate_schema_accepts_sentinel_parent_process() {
        let bridge = TetragonBridge::new(BridgeConfig::default());
        let event = TelemetryEvent {
            source: "tetragon".to_string(),
            event_id: "evt-sentinel".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("node-a".to_string()),
            payload: TelemetryPayload::ProcessStart(swarm_core::ProcessStartEvent {
                parent_process: "<none>".to_string(),
                process_name: "/usr/lib/systemd/systemd".to_string(),
                command_line: "/usr/lib/systemd/systemd --system".to_string(),
                user: Some("root".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        assert!(bridge.validate_schema(&event));
    }

    #[test]
    fn validate_schema_accepts_empty_parent_process() {
        let bridge = TetragonBridge::new(BridgeConfig::default());
        let event = TelemetryEvent {
            source: "tetragon".to_string(),
            event_id: "evt-empty-parent".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("node-a".to_string()),
            payload: TelemetryPayload::ProcessStart(swarm_core::ProcessStartEvent {
                parent_process: String::new(),
                process_name: "/sbin/init".to_string(),
                command_line: "/sbin/init".to_string(),
                user: Some("root".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };
        assert!(bridge.validate_schema(&event));
    }

    #[test]
    fn bridge_config_default_includes_event_timeout() {
        let config = BridgeConfig::default();
        assert_eq!(config.event_timeout_secs, 30);
    }
}
