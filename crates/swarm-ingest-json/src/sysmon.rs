use crate::host_common::{
    event_root, first_bool, first_string, process_name_from_path, required_string,
    required_timestamp, required_u16, sanitize_optional_string, telemetry_event_id,
};
use crate::{JsonBridgeConfigError, validate_event_schema};
use async_trait::async_trait;
use serde_json::Value;
use swarm_core::config::SysmonBridgeConfig;
use swarm_core::{
    BridgeHealth, FilePersistenceEvent, NetworkConnectEvent, ProcessStartEvent, TelemetryBridge,
    TelemetryBridgeError, TelemetryBridgeResult, TelemetryEvent, TelemetryPayload,
};

use crate::source::JsonRecordSource;

const SOURCE_ID: &str = "sysmon";

#[derive(Debug)]
pub struct SysmonBridge {
    source: JsonRecordSource,
    health: BridgeHealth,
}

impl SysmonBridge {
    pub fn new(source: JsonRecordSource) -> Self {
        Self {
            source,
            health: BridgeHealth::new(SOURCE_ID),
        }
    }

    pub fn from_config(config: &SysmonBridgeConfig) -> Result<Self, JsonBridgeConfigError> {
        let source = JsonRecordSource::from_file_config(&config.source)?;
        Ok(Self::new(source))
    }

    fn map_record(&mut self, record: &Value) -> TelemetryBridgeResult<Option<TelemetryEvent>> {
        let record = event_root(record);
        let event_code = required_string(
            record,
            &["/System/EventID", "/System/EventId"],
            "System.EventID",
            &mut self.health,
            SOURCE_ID,
        )?;
        let timestamp = required_timestamp(
            record,
            &[
                "/System/TimeCreated/@SystemTime",
                "/System/TimeCreated/SystemTime",
                "/System/TimeCreated",
            ],
            "System.TimeCreated",
            &mut self.health,
            SOURCE_ID,
        )?;
        let host_id = sanitize_optional_string(first_string(record, &["/System/Computer"]));
        let record_id = first_string(record, &["/System/EventRecordID", "/System/RecordID"]);

        let payload = match event_code.as_str() {
            "1" => Some(self.map_process_start(record)?),
            "3" => Some(self.map_network_connect(record)?),
            "11" => Some(self.map_file_persistence(record)?),
            _ => None,
        };

        let Some(payload) = payload else {
            return Ok(None);
        };

        let event = TelemetryEvent {
            source: SOURCE_ID.to_string(),
            event_id: telemetry_event_id(SOURCE_ID, record_id, &event_code, timestamp),
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

        Ok(Some(event))
    }

    fn map_process_start(&mut self, record: &Value) -> TelemetryBridgeResult<TelemetryPayload> {
        let image = required_string(
            record,
            &["/EventData/Image"],
            "EventData.Image",
            &mut self.health,
            SOURCE_ID,
        )?;
        let parent = required_string(
            record,
            &["/EventData/ParentImage", "/EventData/ParentProcessName"],
            "EventData.ParentImage",
            &mut self.health,
            SOURCE_ID,
        )?;
        let command_line =
            sanitize_optional_string(first_string(record, &["/EventData/CommandLine"]))
                .unwrap_or_else(|| image.clone());
        let signer = sanitize_optional_string(first_string(
            record,
            &["/EventData/Signature", "/EventData/Company"],
        ));
        let signature_valid = first_bool(record, &["/EventData/Signed"]).or_else(|| {
            first_string(record, &["/EventData/SignatureStatus"]).map(|value| {
                value.eq_ignore_ascii_case("valid") || value.eq_ignore_ascii_case("trusted")
            })
        });

        Ok(TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: process_name_from_path(&parent),
            process_name: process_name_from_path(&image),
            command_line,
            user: sanitize_optional_string(first_string(record, &["/EventData/User"])),
            executable_path: Some(image),
            signer,
            signature_valid,
        }))
    }

    fn map_network_connect(&mut self, record: &Value) -> TelemetryBridgeResult<TelemetryPayload> {
        let image = required_string(
            record,
            &["/EventData/Image"],
            "EventData.Image",
            &mut self.health,
            SOURCE_ID,
        )?;

        Ok(TelemetryPayload::NetworkConnect(NetworkConnectEvent {
            process_name: process_name_from_path(&image),
            destination_ip: required_string(
                record,
                &["/EventData/DestinationIp", "/EventData/DestinationHostname"],
                "EventData.DestinationIp",
                &mut self.health,
                SOURCE_ID,
            )?,
            destination_port: required_u16(
                record,
                &["/EventData/DestinationPort"],
                "EventData.DestinationPort",
                &mut self.health,
                SOURCE_ID,
            )?,
            protocol: required_string(
                record,
                &["/EventData/Protocol"],
                "EventData.Protocol",
                &mut self.health,
                SOURCE_ID,
            )?
            .to_ascii_lowercase(),
        }))
    }

    fn map_file_persistence(&mut self, record: &Value) -> TelemetryBridgeResult<TelemetryPayload> {
        let image = required_string(
            record,
            &["/EventData/Image"],
            "EventData.Image",
            &mut self.health,
            SOURCE_ID,
        )?;

        Ok(TelemetryPayload::FilePersistence(FilePersistenceEvent {
            file_path: required_string(
                record,
                &["/EventData/TargetFilename"],
                "EventData.TargetFilename",
                &mut self.health,
                SOURCE_ID,
            )?,
            operation: "create".to_string(),
            process_name: process_name_from_path(&image),
            content_preview: sanitize_optional_string(first_string(
                record,
                &["/EventData/Contents", "/EventData/Hashes"],
            )),
        }))
    }
}

#[async_trait]
impl TelemetryBridge for SysmonBridge {
    fn source_id(&self) -> &str {
        SOURCE_ID
    }

    async fn poll(&mut self) -> TelemetryBridgeResult<Vec<TelemetryEvent>> {
        while let Some(record) = self.source.next_record() {
            if let Some(event) = self.map_record(&record)? {
                self.health.record_event(event.timestamp);
                return Ok(vec![event]);
            }
        }
        Ok(Vec::new())
    }

    fn validate_schema(&self, event: &TelemetryEvent) -> bool {
        validate_event_schema(event, SOURCE_ID)
    }

    fn health(&self) -> BridgeHealth {
        self.health.clone()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::SysmonBridge;
    use crate::source::JsonRecordSource;
    use serde_json::json;
    use swarm_core::{TelemetryBridge, TelemetryPayload};

    #[tokio::test]
    async fn process_create_maps_to_process_start() {
        let mut bridge = SysmonBridge::new(JsonRecordSource::new([json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "EventRecordID": 1001,
                    "TimeCreated": { "@SystemTime": "2026-04-13T15:10:00Z" },
                    "Computer": "win-host-02"
                },
                "EventData": {
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                    "CommandLine": "powershell.exe -enc SQBFAFgA",
                    "User": "ACME\\alice",
                    "Signature": "Microsoft Windows",
                    "Signed": "true"
                }
            }
        })]));

        let events = bridge
            .poll()
            .await
            .expect("sysmon process event should map");
        let event = events.first().expect("one event should be returned");

        match &event.payload {
            TelemetryPayload::ProcessStart(process) => {
                assert_eq!(process.parent_process, "WINWORD");
                assert_eq!(process.process_name, "powershell");
                assert_eq!(process.signer.as_deref(), Some("Microsoft Windows"));
                assert_eq!(process.signature_valid, Some(true));
            }
            _ => panic!("expected process_start payload"),
        }
    }

    #[tokio::test]
    async fn network_connect_maps_to_network_connect_payload() {
        let mut bridge = SysmonBridge::new(JsonRecordSource::new([json!({
            "Event": {
                "System": {
                    "EventID": 3,
                    "EventRecordID": 1002,
                    "TimeCreated": { "@SystemTime": "2026-04-13T15:10:05Z" },
                    "Computer": "win-host-02"
                },
                "EventData": {
                    "Image": "C:\\Windows\\System32\\curl.exe",
                    "DestinationIp": "203.0.113.40",
                    "DestinationPort": 443,
                    "Protocol": "tcp"
                }
            }
        })]));

        let events = bridge
            .poll()
            .await
            .expect("sysmon network event should map");
        let event = events.first().expect("one event should be returned");

        match &event.payload {
            TelemetryPayload::NetworkConnect(connect) => {
                assert_eq!(connect.process_name, "curl");
                assert_eq!(connect.destination_ip, "203.0.113.40");
                assert_eq!(connect.destination_port, 443);
                assert_eq!(connect.protocol, "tcp");
            }
            _ => panic!("expected network_connect payload"),
        }
    }

    #[tokio::test]
    async fn file_create_maps_to_file_persistence_payload() {
        let mut bridge = SysmonBridge::new(JsonRecordSource::new([json!({
            "Event": {
                "System": {
                    "EventID": 11,
                    "EventRecordID": 1003,
                    "TimeCreated": { "@SystemTime": "2026-04-13T15:10:10Z" },
                    "Computer": "win-host-02"
                },
                "EventData": {
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "TargetFilename": "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.cmd"
                }
            }
        })]));

        let events = bridge.poll().await.expect("sysmon file event should map");
        let event = events.first().expect("one event should be returned");

        match &event.payload {
            TelemetryPayload::FilePersistence(file) => {
                assert_eq!(
                    file.file_path,
                    "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.cmd"
                );
                assert_eq!(file.operation, "create");
                assert_eq!(file.process_name, "cmd");
            }
            _ => panic!("expected file_persistence payload"),
        }
    }
}
