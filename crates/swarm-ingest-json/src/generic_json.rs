use crate::{JsonBridgeConfigError, record_error, validate_event_schema};
use async_trait::async_trait;
use chrono::DateTime;
use serde_json::Value;
use swarm_core::config::{
    FieldMappingConfig, GenericJsonBridgeConfig, GenericJsonPayloadMappingConfig,
};
use swarm_core::{
    AuthenticationEventData, BridgeHealth, DnsQueryEvent, NetworkConnectEvent, ProcessStartEvent,
    RegistryAccessEvent, TelemetryBridge, TelemetryBridgeError, TelemetryBridgeResult,
    TelemetryEvent, TelemetryPayload,
};

use crate::source::JsonRecordSource;

const SOURCE_ID: &str = "generic_json";

#[derive(Debug)]
pub struct GenericJsonBridge {
    source: JsonRecordSource,
    mapping: FieldMappingConfig,
    health: BridgeHealth,
}

impl GenericJsonBridge {
    pub fn try_new(
        source: JsonRecordSource,
        mapping: FieldMappingConfig,
    ) -> TelemetryBridgeResult<Self> {
        mapping
            .validate()
            .map_err(|error| TelemetryBridgeError::Unavailable(error.to_string()))?;
        Ok(Self {
            source,
            mapping,
            health: BridgeHealth::new(SOURCE_ID),
        })
    }

    pub fn from_config(config: &GenericJsonBridgeConfig) -> Result<Self, JsonBridgeConfigError> {
        let source = JsonRecordSource::from_file_config(&config.source)?;
        Ok(Self::try_new(source, config.mapping.clone())?)
    }

    fn map_record(&mut self, record: &Value) -> TelemetryBridgeResult<TelemetryEvent> {
        let event_id = required_string(
            record,
            &self.mapping.event_id_path,
            "event_id_path",
            &mut self.health,
        )?;
        let timestamp = required_timestamp(
            record,
            &self.mapping.timestamp_path,
            "timestamp_path",
            &mut self.health,
        )?;
        let host_id = self
            .mapping
            .host_id_path
            .as_ref()
            .and_then(|pointer| optional_string(record, pointer));

        let payload = map_payload(record, &self.mapping.payload, &mut self.health)?;
        let event = TelemetryEvent {
            source: SOURCE_ID.to_string(),
            event_id,
            timestamp,
            host_id,
            payload,
        };

        if !validate_event_schema(&event, SOURCE_ID) {
            let message = format!(
                "bridge `{SOURCE_ID}` produced invalid normalized telemetry for `{}`",
                event.event_id
            );
            self.health.record_error(message.clone());
            return Err(TelemetryBridgeError::Schema(message));
        }

        Ok(event)
    }
}

#[async_trait]
impl TelemetryBridge for GenericJsonBridge {
    fn source_id(&self) -> &str {
        SOURCE_ID
    }

    async fn poll(&mut self) -> TelemetryBridgeResult<Vec<TelemetryEvent>> {
        let Some(record) = self.source.next_record() else {
            return Ok(Vec::new());
        };

        let event = self.map_record(&record)?;
        self.health.record_event(event.timestamp);
        Ok(vec![event])
    }

    fn validate_schema(&self, event: &TelemetryEvent) -> bool {
        validate_event_schema(event, SOURCE_ID)
    }

    fn health(&self) -> BridgeHealth {
        self.health.clone()
    }
}

fn map_payload(
    record: &Value,
    mapping: &GenericJsonPayloadMappingConfig,
    health: &mut BridgeHealth,
) -> TelemetryBridgeResult<TelemetryPayload> {
    match mapping {
        GenericJsonPayloadMappingConfig::ProcessStart {
            parent_process_path,
            process_name_path,
            command_line_path,
            user_path,
            executable_path_path,
            signer_path,
            signature_valid_path,
        } => Ok(TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: required_string(
                record,
                parent_process_path,
                "payload.parent_process_path",
                health,
            )?,
            process_name: required_string(
                record,
                process_name_path,
                "payload.process_name_path",
                health,
            )?,
            command_line: required_string(
                record,
                command_line_path,
                "payload.command_line_path",
                health,
            )?,
            user: user_path
                .as_ref()
                .and_then(|pointer| optional_string(record, pointer)),
            executable_path: executable_path_path
                .as_ref()
                .and_then(|pointer| optional_string(record, pointer)),
            signer: signer_path
                .as_ref()
                .and_then(|pointer| optional_string(record, pointer)),
            signature_valid: signature_valid_path
                .as_ref()
                .and_then(|pointer| optional_bool(record, pointer)),
        })),
        GenericJsonPayloadMappingConfig::NetworkConnect {
            process_name_path,
            destination_ip_path,
            destination_port_path,
            protocol_path,
        } => Ok(TelemetryPayload::NetworkConnect(NetworkConnectEvent {
            process_name: required_string(
                record,
                process_name_path,
                "payload.process_name_path",
                health,
            )?,
            destination_ip: required_string(
                record,
                destination_ip_path,
                "payload.destination_ip_path",
                health,
            )?,
            destination_port: required_u16(
                record,
                destination_port_path,
                "payload.destination_port_path",
                health,
            )?,
            protocol: required_string(record, protocol_path, "payload.protocol_path", health)?,
        })),
        GenericJsonPayloadMappingConfig::DnsQuery {
            query_name_path,
            query_type_path,
            source_ip_path,
            process_name_path,
            response_code_path,
        } => Ok(TelemetryPayload::DnsQuery(DnsQueryEvent {
            query_name: required_string(
                record,
                query_name_path,
                "payload.query_name_path",
                health,
            )?,
            query_type: required_string(
                record,
                query_type_path,
                "payload.query_type_path",
                health,
            )?,
            source_ip: source_ip_path
                .as_ref()
                .and_then(|pointer| optional_string(record, pointer)),
            process_name: process_name_path
                .as_ref()
                .and_then(|pointer| optional_string(record, pointer)),
            response_code: response_code_path
                .as_ref()
                .and_then(|pointer| optional_string(record, pointer)),
        })),
        GenericJsonPayloadMappingConfig::RegistryAccess {
            process_name_path,
            registry_path_path,
            access_type_path,
            target_process_path,
        } => Ok(TelemetryPayload::RegistryAccess(RegistryAccessEvent {
            process_name: required_string(
                record,
                process_name_path,
                "payload.process_name_path",
                health,
            )?,
            registry_path: required_string(
                record,
                registry_path_path,
                "payload.registry_path_path",
                health,
            )?,
            access_type: required_string(
                record,
                access_type_path,
                "payload.access_type_path",
                health,
            )?,
            target_process: target_process_path
                .as_ref()
                .and_then(|pointer| optional_string(record, pointer)),
        })),
        GenericJsonPayloadMappingConfig::RegistryPersistence {
            process_name_path,
            registry_path_path,
            access_type_path,
            value_name_path,
            value_data_path,
        } => Ok(TelemetryPayload::RegistryPersistence(
            swarm_core::RegistryPersistenceEvent {
                process_name: required_string(
                    record,
                    process_name_path,
                    "payload.process_name_path",
                    health,
                )?,
                registry_path: required_string(
                    record,
                    registry_path_path,
                    "payload.registry_path_path",
                    health,
                )?,
                value_name: value_name_path
                    .as_ref()
                    .and_then(|pointer| optional_string(record, pointer)),
                value_data: value_data_path
                    .as_ref()
                    .and_then(|pointer| optional_string(record, pointer)),
                access_type: required_string(
                    record,
                    access_type_path,
                    "payload.access_type_path",
                    health,
                )?,
            },
        )),
        GenericJsonPayloadMappingConfig::FilePersistence {
            file_path_path,
            operation_path,
            process_name_path,
            content_preview_path,
        } => Ok(TelemetryPayload::FilePersistence(
            swarm_core::FilePersistenceEvent {
                file_path: required_string(
                    record,
                    file_path_path,
                    "payload.file_path_path",
                    health,
                )?,
                operation: required_string(
                    record,
                    operation_path,
                    "payload.operation_path",
                    health,
                )?,
                process_name: required_string(
                    record,
                    process_name_path,
                    "payload.process_name_path",
                    health,
                )?,
                content_preview: content_preview_path
                    .as_ref()
                    .and_then(|pointer| optional_string(record, pointer)),
            },
        )),
        GenericJsonPayloadMappingConfig::AuthenticationEvent {
            auth_type_path,
            source_host_path,
            target_host_path,
            target_service_path,
            process_name_path,
            success_path,
            user_path,
        } => Ok(TelemetryPayload::AuthenticationEvent(
            AuthenticationEventData {
                auth_type: required_string(
                    record,
                    auth_type_path,
                    "payload.auth_type_path",
                    health,
                )?,
                source_host: source_host_path
                    .as_ref()
                    .and_then(|pointer| optional_string(record, pointer)),
                target_host: target_host_path
                    .as_ref()
                    .and_then(|pointer| optional_string(record, pointer)),
                target_service: target_service_path
                    .as_ref()
                    .and_then(|pointer| optional_string(record, pointer)),
                process_name: process_name_path
                    .as_ref()
                    .and_then(|pointer| optional_string(record, pointer)),
                success: required_bool(record, success_path, "payload.success_path", health)?,
                user: user_path
                    .as_ref()
                    .and_then(|pointer| optional_string(record, pointer)),
            },
        )),
    }
}

fn required_string(
    record: &Value,
    pointer: &str,
    field: &str,
    health: &mut BridgeHealth,
) -> TelemetryBridgeResult<String> {
    record
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| record_error(health, format!("mapped field `{field}` is required")))
}

fn optional_string(record: &Value, pointer: &str) -> Option<String> {
    record
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.trim().is_empty())
}

fn optional_bool(record: &Value, pointer: &str) -> Option<bool> {
    let value = record.pointer(pointer)?;
    match value {
        Value::Bool(boolean) => Some(*boolean),
        Value::String(raw) => raw.parse::<bool>().ok(),
        _ => None,
    }
}

fn required_u16(
    record: &Value,
    pointer: &str,
    field: &str,
    health: &mut BridgeHealth,
) -> TelemetryBridgeResult<u16> {
    let value = record
        .pointer(pointer)
        .ok_or_else(|| record_error(health, format!("mapped field `{field}` is required")))?;
    match value {
        Value::Number(number) => number
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| record_error(health, format!("mapped field `{field}` must fit in u16"))),
        Value::String(raw) => raw.parse::<u16>().map_err(|error| {
            record_error(
                health,
                format!("mapped field `{field}` must parse as u16: {error}"),
            )
        }),
        _ => Err(record_error(
            health,
            format!("mapped field `{field}` must be a string or number"),
        )),
    }
}

fn required_bool(
    record: &Value,
    pointer: &str,
    field: &str,
    health: &mut BridgeHealth,
) -> TelemetryBridgeResult<bool> {
    let value = record
        .pointer(pointer)
        .ok_or_else(|| record_error(health, format!("mapped field `{field}` is required")))?;
    match value {
        Value::Bool(value) => Ok(*value),
        Value::String(raw) => match raw.to_ascii_lowercase().as_str() {
            "true" | "success" | "ok" => Ok(true),
            "false" | "failure" | "error" => Ok(false),
            _ => Err(record_error(
                health,
                format!("mapped field `{field}` must parse as bool"),
            )),
        },
        _ => Err(record_error(
            health,
            format!("mapped field `{field}` must be a bool or string"),
        )),
    }
}

fn required_timestamp(
    record: &Value,
    pointer: &str,
    field: &str,
    health: &mut BridgeHealth,
) -> TelemetryBridgeResult<i64> {
    let value = record
        .pointer(pointer)
        .ok_or_else(|| record_error(health, format!("mapped field `{field}` is required")))?;
    match value {
        Value::Number(number) => number.as_i64().ok_or_else(|| {
            record_error(
                health,
                format!("mapped field `{field}` must be a signed integer timestamp"),
            )
        }),
        Value::String(raw) => {
            if let Ok(parsed) = raw.parse::<i64>() {
                return Ok(parsed);
            }
            DateTime::parse_from_rfc3339(raw)
                .map(|timestamp| timestamp.timestamp())
                .map_err(|error| {
                    record_error(
                        health,
                        format!("mapped field `{field}` must be unix seconds or RFC3339: {error}"),
                    )
                })
        }
        _ => Err(record_error(
            health,
            format!("mapped field `{field}` must be a string or number"),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::GenericJsonBridge;
    use crate::source::JsonRecordSource;
    use serde_json::json;
    use swarm_core::config::{FieldMappingConfig, GenericJsonPayloadMappingConfig};
    use swarm_core::{TelemetryBridge, TelemetryBridgeError, TelemetryPayload};

    fn process_start_mapping() -> FieldMappingConfig {
        FieldMappingConfig {
            event_id_path: "/meta/id".to_string(),
            timestamp_path: "/meta/timestamp".to_string(),
            host_id_path: Some("/meta/host".to_string()),
            payload: GenericJsonPayloadMappingConfig::ProcessStart {
                parent_process_path: "/proc/parent".to_string(),
                process_name_path: "/proc/name".to_string(),
                command_line_path: "/proc/cmd".to_string(),
                user_path: Some("/proc/user".to_string()),
                executable_path_path: None,
                signer_path: None,
                signature_valid_path: None,
            },
        }
    }

    #[tokio::test]
    async fn maps_process_start_payload_from_json_pointers() {
        let source = JsonRecordSource::new([json!({
            "meta": {
                "id": "evt-1",
                "timestamp": 1_712_665_600i64,
                "host": "host-a"
            },
            "proc": {
                "parent": "sshd",
                "name": "bash",
                "cmd": "bash -lc whoami",
                "user": "alice"
            }
        })]);
        let mut bridge =
            GenericJsonBridge::try_new(source, process_start_mapping()).expect("mapping is valid");

        let events = bridge.poll().await.expect("generic json event should map");
        let event = events.first().expect("one event should be returned");
        assert_eq!(event.source, "generic_json");
        assert_eq!(event.host_id.as_deref(), Some("host-a"));

        match &event.payload {
            TelemetryPayload::ProcessStart(process) => {
                assert_eq!(process.parent_process, "sshd");
                assert_eq!(process.process_name, "bash");
                assert_eq!(process.command_line, "bash -lc whoami");
                assert_eq!(process.user.as_deref(), Some("alice"));
            }
            _ => panic!("expected process start payload"),
        }
    }

    #[test]
    fn invalid_pointer_is_rejected_at_construction_time() {
        let mapping = FieldMappingConfig {
            event_id_path: "meta/id".to_string(),
            ..process_start_mapping()
        };
        let error = GenericJsonBridge::try_new(JsonRecordSource::default(), mapping)
            .expect_err("invalid pointer fails");
        assert!(matches!(error, TelemetryBridgeError::Unavailable(_)));
    }

    #[tokio::test]
    async fn missing_required_field_fails_closed() {
        let source = JsonRecordSource::new([json!({
            "meta": {
                "id": "evt-2",
                "timestamp": "2026-04-06T12:00:00Z"
            },
            "proc": {
                "parent": "sshd",
                "cmd": "bash -lc whoami"
            }
        })]);
        let mut bridge =
            GenericJsonBridge::try_new(source, process_start_mapping()).expect("mapping is valid");

        let error = bridge
            .poll()
            .await
            .expect_err("missing process name should fail");
        assert!(matches!(error, TelemetryBridgeError::Mapping(_)));
        assert_eq!(bridge.health().error_count, 1);
    }

    #[tokio::test]
    async fn schema_rejection_fails_closed() {
        let source = JsonRecordSource::new([json!({
            "meta": {
                "id": "evt-3",
                "timestamp": 0
            },
            "proc": {
                "parent": "sshd",
                "name": "bash",
                "cmd": "bash -lc whoami"
            }
        })]);
        let mut bridge =
            GenericJsonBridge::try_new(source, process_start_mapping()).expect("mapping is valid");

        let error = bridge
            .poll()
            .await
            .expect_err("empty process name should fail schema validation");
        assert!(matches!(error, TelemetryBridgeError::Schema(_)));
    }
}
