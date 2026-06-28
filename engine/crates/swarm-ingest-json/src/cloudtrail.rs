use crate::{JsonBridgeConfigError, record_error, validate_event_schema};
use async_trait::async_trait;
use chrono::DateTime;
use serde_json::Value;
use swarm_core::config::CloudTrailBridgeConfig;
use swarm_core::{
    AuthenticationEventData, BridgeHealth, NetworkConnectEvent, TelemetryBridge,
    TelemetryBridgeError, TelemetryBridgeResult, TelemetryEvent, TelemetryPayload,
};

use crate::source::JsonRecordSource;

const SOURCE_ID: &str = "cloudtrail";
const HTTPS_PORT: u16 = 443;

#[derive(Debug)]
pub struct CloudTrailBridge {
    source: JsonRecordSource,
    health: BridgeHealth,
}

impl CloudTrailBridge {
    pub fn new(source: JsonRecordSource) -> Self {
        Self {
            source,
            health: BridgeHealth::new(SOURCE_ID),
        }
    }

    pub fn from_config(config: &CloudTrailBridgeConfig) -> Result<Self, JsonBridgeConfigError> {
        let source = JsonRecordSource::from_file_config(&config.source)?;
        Ok(Self::new(source))
    }

    fn map_record(&mut self, record: &Value) -> TelemetryBridgeResult<TelemetryEvent> {
        let event_id = required_string(record, "/eventID", "eventID", &mut self.health)?;
        let event_name = required_string(record, "/eventName", "eventName", &mut self.health)?;
        let event_source =
            required_string(record, "/eventSource", "eventSource", &mut self.health)?;
        let timestamp = parse_timestamp(record, "/eventTime", &mut self.health)?;
        let host_id = optional_string(record, "/recipientAccountId");
        let source_ip = optional_string(record, "/sourceIPAddress");
        let user_agent = optional_string(record, "/userAgent");

        let payload = if is_auth_event(&event_source, &event_name) {
            TelemetryPayload::AuthenticationEvent(AuthenticationEventData {
                auth_type: event_name.clone(),
                source_host: source_ip.clone(),
                target_host: host_id.clone(),
                target_service: Some(event_source.clone()),
                process_name: user_agent,
                success: auth_success(record),
                user: cloudtrail_user(record),
            })
        } else {
            TelemetryPayload::NetworkConnect(NetworkConnectEvent {
                process_name: user_agent.unwrap_or_else(|| event_name.clone()),
                destination_ip: cloudtrail_endpoint(record, &event_source),
                destination_port: HTTPS_PORT,
                protocol: "aws_api".to_string(),
            })
        };

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
impl TelemetryBridge for CloudTrailBridge {
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
        .ok_or_else(|| record_error(health, format!("CloudTrail field `{field}` is required")))
}

fn optional_string(record: &Value, pointer: &str) -> Option<String> {
    record
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.trim().is_empty())
}

fn parse_timestamp(
    record: &Value,
    pointer: &str,
    health: &mut BridgeHealth,
) -> TelemetryBridgeResult<i64> {
    let raw = required_string(record, pointer, "eventTime", health)?;
    DateTime::parse_from_rfc3339(&raw)
        .map(|timestamp| timestamp.timestamp())
        .map_err(|error| record_error(health, format!("invalid CloudTrail eventTime: {error}")))
}

fn cloudtrail_user(record: &Value) -> Option<String> {
    optional_string(record, "/userIdentity/userName")
        .or_else(|| {
            optional_string(
                record,
                "/userIdentity/sessionContext/sessionIssuer/userName",
            )
        })
        .or_else(|| optional_string(record, "/userIdentity/arn"))
        .or_else(|| optional_string(record, "/userIdentity/principalId"))
}

fn auth_success(record: &Value) -> bool {
    if let Some(status) = optional_string(record, "/responseElements/ConsoleLogin") {
        return status.eq_ignore_ascii_case("success");
    }
    optional_string(record, "/errorCode").is_none()
        && optional_string(record, "/errorMessage").is_none()
}

fn is_auth_event(event_source: &str, event_name: &str) -> bool {
    matches!(
        event_source,
        "signin.amazonaws.com" | "sts.amazonaws.com" | "iam.amazonaws.com"
    ) || matches!(
        event_name,
        "ConsoleLogin"
            | "AssumeRole"
            | "AssumeRoleWithSAML"
            | "AssumeRoleWithWebIdentity"
            | "GetSessionToken"
    )
}

fn cloudtrail_endpoint(record: &Value, event_source: &str) -> String {
    optional_string(record, "/requestParameters/bucketName")
        .or_else(|| optional_string(record, "/requestParameters/host"))
        .unwrap_or_else(|| event_source.to_string())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::CloudTrailBridge;
    use crate::source::JsonRecordSource;
    use serde_json::json;
    use swarm_core::{TelemetryBridge, TelemetryPayload};

    #[tokio::test]
    async fn console_login_maps_to_authentication_event() {
        let mut bridge = CloudTrailBridge::new(JsonRecordSource::new([json!({
            "eventID": "evt-1",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "eventTime": "2026-04-06T12:00:00Z",
            "recipientAccountId": "123456789012",
            "sourceIPAddress": "198.51.100.10",
            "userAgent": "signin.amazonaws.com",
            "responseElements": { "ConsoleLogin": "Success" },
            "userIdentity": {
                "type": "IAMUser",
                "userName": "alice"
            }
        })]));

        let events = bridge
            .poll()
            .await
            .expect("cloudtrail auth event should map");
        let event = events.first().expect("one event should be returned");
        assert_eq!(event.source, "cloudtrail");

        match &event.payload {
            TelemetryPayload::AuthenticationEvent(auth) => {
                assert_eq!(auth.auth_type, "ConsoleLogin");
                assert_eq!(auth.user.as_deref(), Some("alice"));
                assert!(auth.success);
                assert_eq!(auth.target_service.as_deref(), Some("signin.amazonaws.com"));
            }
            _ => panic!("expected authentication payload"),
        }
    }

    #[tokio::test]
    async fn s3_access_maps_to_network_connect_event() {
        let mut bridge = CloudTrailBridge::new(JsonRecordSource::new([json!({
            "eventID": "evt-2",
            "eventName": "GetObject",
            "eventSource": "s3.amazonaws.com",
            "eventTime": "2026-04-06T12:01:00Z",
            "recipientAccountId": "123456789012",
            "sourceIPAddress": "198.51.100.11",
            "userAgent": "aws-cli/2.15.0",
            "requestParameters": {
                "bucketName": "incident-bucket"
            }
        })]));

        let events = bridge
            .poll()
            .await
            .expect("cloudtrail data event should map");
        let event = events.first().expect("one event should be returned");

        match &event.payload {
            TelemetryPayload::NetworkConnect(connect) => {
                assert_eq!(connect.process_name, "aws-cli/2.15.0");
                assert_eq!(connect.destination_ip, "incident-bucket");
                assert_eq!(connect.destination_port, 443);
                assert_eq!(connect.protocol, "aws_api");
            }
            _ => panic!("expected network connect payload"),
        }
    }

    #[tokio::test]
    async fn malformed_record_fails_closed() {
        let mut bridge = CloudTrailBridge::new(JsonRecordSource::new([json!({
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "eventTime": "2026-04-06T12:00:00Z"
        })]));

        let error = bridge
            .poll()
            .await
            .expect_err("missing event id should fail");
        assert!(matches!(
            error,
            swarm_core::TelemetryBridgeError::Mapping(_)
        ));
        assert_eq!(bridge.health().error_count, 1);
    }
}
