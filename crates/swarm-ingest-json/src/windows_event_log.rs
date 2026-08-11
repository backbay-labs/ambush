use crate::host_common::{
    event_root, first_string, process_name_from_path, required_string, required_timestamp,
    sanitize_optional_string, telemetry_event_id,
};
use crate::{JsonBridgeConfigError, validate_event_schema};
use async_trait::async_trait;
use serde_json::Value;
use swarm_core::config::WindowsEventLogBridgeConfig;
use swarm_core::{
    AuthenticationEventData, BridgeHealth, ProcessStartEvent, TelemetryBridge,
    TelemetryBridgeError, TelemetryBridgeResult, TelemetryEvent, TelemetryPayload,
};

use crate::source::JsonRecordSource;

const SOURCE_ID: &str = "windows_event_log";

#[derive(Debug)]
pub struct WindowsEventLogBridge {
    source: JsonRecordSource,
    health: BridgeHealth,
}

impl WindowsEventLogBridge {
    pub fn new(source: JsonRecordSource) -> Self {
        Self {
            source,
            health: BridgeHealth::new(SOURCE_ID),
        }
    }

    pub fn from_config(
        config: &WindowsEventLogBridgeConfig,
    ) -> Result<Self, JsonBridgeConfigError> {
        let source = JsonRecordSource::from_file_config(&config.source)?;
        Ok(Self::new(source))
    }

    fn map_record(&mut self, record: &Value) -> TelemetryBridgeResult<Option<TelemetryEvent>> {
        let record = event_root(record);
        let event_code = required_string(
            record,
            &["/System/EventID", "/System/EventId", "/System/EventCode"],
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
        let record_id = first_string(
            record,
            &[
                "/System/EventRecordID",
                "/System/EventRecordId",
                "/System/Correlation/ActivityID",
            ],
        );

        let payload = match event_code.as_str() {
            "4624" | "4625" => {
                Some(self.map_authentication(record, &event_code, host_id.as_deref())?)
            }
            "4688" => Some(self.map_process_start(record)?),
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

    fn map_authentication(
        &mut self,
        record: &Value,
        event_code: &str,
        host_id: Option<&str>,
    ) -> TelemetryBridgeResult<TelemetryPayload> {
        let logon_type = first_string(record, &["/EventData/LogonType"]);
        let package = sanitize_optional_string(first_string(
            record,
            &[
                "/EventData/AuthenticationPackageName",
                "/EventData/LogonProcessName",
            ],
        ));
        let process_name = sanitize_optional_string(
            first_string(
                record,
                &["/EventData/ProcessName", "/EventData/CallerProcessName"],
            )
            .map(|value| process_name_from_path(&value)),
        );
        let auth_type = infer_auth_type(
            logon_type.as_deref(),
            package.as_deref(),
            process_name.as_deref(),
        );

        Ok(TelemetryPayload::AuthenticationEvent(
            AuthenticationEventData {
                auth_type,
                source_host: sanitize_optional_string(first_string(
                    record,
                    &["/EventData/IpAddress", "/EventData/WorkstationName"],
                )),
                target_host: host_id.map(str::to_string),
                target_service: package,
                process_name,
                success: event_code == "4624",
                user: sanitize_optional_string(first_string(
                    record,
                    &["/EventData/TargetUserName", "/EventData/SubjectUserName"],
                )),
            },
        ))
    }

    fn map_process_start(&mut self, record: &Value) -> TelemetryBridgeResult<TelemetryPayload> {
        let image = required_string(
            record,
            &["/EventData/NewProcessName", "/EventData/ProcessName"],
            "EventData.NewProcessName",
            &mut self.health,
            SOURCE_ID,
        )?;
        let parent = required_string(
            record,
            &[
                "/EventData/ParentProcessName",
                "/EventData/CreatorProcessName",
            ],
            "EventData.ParentProcessName",
            &mut self.health,
            SOURCE_ID,
        )?;
        let command_line = sanitize_optional_string(first_string(
            record,
            &["/EventData/CommandLine", "/EventData/ProcessCommandLine"],
        ))
        .unwrap_or_else(|| image.clone());

        Ok(TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: process_name_from_path(&parent),
            process_name: process_name_from_path(&image),
            command_line,
            user: sanitize_optional_string(first_string(
                record,
                &["/EventData/SubjectUserName", "/EventData/TargetUserName"],
            )),
            executable_path: Some(image),
            signer: None,
            signature_valid: None,
        }))
    }
}

#[async_trait]
impl TelemetryBridge for WindowsEventLogBridge {
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

fn infer_auth_type(
    logon_type: Option<&str>,
    package: Option<&str>,
    process_name: Option<&str>,
) -> String {
    if matches!(logon_type, Some("10")) {
        return "rdp".to_string();
    }
    if process_name.is_some_and(|value| value.to_ascii_lowercase().contains("winrm")) {
        return "winrm".to_string();
    }
    if package.is_some_and(|value| value.to_ascii_lowercase().contains("kerberos")) {
        return "kerberos".to_string();
    }
    if package.is_some_and(|value| value.to_ascii_lowercase().contains("ntlm")) {
        return "ntlm".to_string();
    }
    "windows_logon".to_string()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::WindowsEventLogBridge;
    use crate::source::JsonRecordSource;
    use serde_json::json;
    use swarm_core::{TelemetryBridge, TelemetryPayload};

    #[tokio::test]
    async fn failed_rdp_logon_maps_to_authentication_event() {
        let mut bridge = WindowsEventLogBridge::new(JsonRecordSource::new([json!({
            "Event": {
                "System": {
                    "EventID": 4625,
                    "EventRecordID": 9001,
                    "TimeCreated": { "@SystemTime": "2026-04-13T15:00:00Z" },
                    "Computer": "win-host-01"
                },
                "EventData": {
                    "LogonType": "10",
                    "AuthenticationPackageName": "Negotiate",
                    "IpAddress": "198.51.100.22",
                    "WorkstationName": "ws-22",
                    "ProcessName": "C:\\Windows\\System32\\winlogon.exe",
                    "TargetUserName": "alice"
                }
            }
        })]));

        let events = bridge.poll().await.expect("windows auth record should map");
        let event = events.first().expect("one event should be returned");
        assert_eq!(event.source, "windows_event_log");

        match &event.payload {
            TelemetryPayload::AuthenticationEvent(auth) => {
                assert_eq!(auth.auth_type, "rdp");
                assert_eq!(auth.source_host.as_deref(), Some("198.51.100.22"));
                assert_eq!(auth.target_host.as_deref(), Some("win-host-01"));
                assert_eq!(auth.process_name.as_deref(), Some("winlogon"));
                assert!(!auth.success);
                assert_eq!(auth.user.as_deref(), Some("alice"));
            }
            _ => panic!("expected authentication payload"),
        }
    }

    #[tokio::test]
    async fn process_creation_maps_to_process_start() {
        let mut bridge = WindowsEventLogBridge::new(JsonRecordSource::new([json!({
            "Event": {
                "System": {
                    "EventID": 4688,
                    "EventRecordID": 9002,
                    "TimeCreated": { "@SystemTime": "2026-04-13T15:00:05Z" },
                    "Computer": "win-host-01"
                },
                "EventData": {
                    "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                    "CommandLine": "powershell.exe -enc SQBFAFgA",
                    "SubjectUserName": "alice"
                }
            }
        })]));

        let events = bridge
            .poll()
            .await
            .expect("windows process-create record should map");
        let event = events.first().expect("one event should be returned");

        match &event.payload {
            TelemetryPayload::ProcessStart(process) => {
                assert_eq!(process.parent_process, "WINWORD");
                assert_eq!(process.process_name, "powershell");
                assert_eq!(process.command_line, "powershell.exe -enc SQBFAFgA");
                assert_eq!(process.user.as_deref(), Some("alice"));
                assert_eq!(
                    process.executable_path.as_deref(),
                    Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
                );
            }
            _ => panic!("expected process_start payload"),
        }
    }

    #[tokio::test]
    async fn unsupported_records_are_skipped() {
        let mut bridge = WindowsEventLogBridge::new(JsonRecordSource::new([
            json!({
                "Event": {
                    "System": {
                        "EventID": 4634,
                        "EventRecordID": 9000,
                        "TimeCreated": { "@SystemTime": "2026-04-13T14:59:59Z" },
                        "Computer": "win-host-01"
                    },
                    "EventData": {}
                }
            }),
            json!({
                "Event": {
                    "System": {
                        "EventID": 4688,
                        "EventRecordID": 9003,
                        "TimeCreated": { "@SystemTime": "2026-04-13T15:00:10Z" },
                        "Computer": "win-host-01"
                    },
                    "EventData": {
                        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                        "ParentProcessName": "C:\\Windows\\explorer.exe",
                        "CommandLine": "cmd.exe /c whoami"
                    }
                }
            }),
        ]));

        let events = bridge
            .poll()
            .await
            .expect("supported event should be found");
        assert_eq!(events.len(), 1);
        assert_eq!(bridge.health().events_processed, 1);
    }
}
