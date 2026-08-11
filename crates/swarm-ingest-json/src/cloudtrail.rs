use crate::{JsonBridgeConfigError, record_error, validate_event_schema};
use async_trait::async_trait;
use chrono::DateTime;
use serde_json::Value;
use swarm_core::config::CloudTrailBridgeConfig;
use swarm_core::{
    BridgeHealth, CloudTrailEvent, TelemetryBridge, TelemetryBridgeError, TelemetryBridgeResult,
    TelemetryEvent, TelemetryPayload,
};

use crate::source::JsonRecordSource;

const SOURCE_ID: &str = "cloudtrail";

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
        let aws_account_id = optional_string(record, "/recipientAccountId");

        let payload = TelemetryPayload::CloudTrail(CloudTrailEvent {
            event_name,
            event_source,
            aws_account_id: aws_account_id.clone(),
            principal_arn: optional_string(record, "/userIdentity/arn"),
            principal_id: optional_string(record, "/userIdentity/principalId"),
            principal_name: cloudtrail_user(record),
            principal_type: optional_string(record, "/userIdentity/type"),
            source_ip_address: optional_string(record, "/sourceIPAddress"),
            aws_region: optional_string(record, "/awsRegion"),
            user_agent: optional_string(record, "/userAgent"),
            mfa_authenticated: optional_bool(
                record,
                "/userIdentity/sessionContext/attributes/mfaAuthenticated",
            )
            .or_else(|| optional_yes_no(record, "/additionalEventData/MFAUsed")),
            request_parameters: object_or_default(record.pointer("/requestParameters")),
            response_elements: object_or_default(record.pointer("/responseElements")),
            error_code: optional_string(record, "/errorCode"),
            error_message: optional_string(record, "/errorMessage"),
        });

        let event = TelemetryEvent {
            source: SOURCE_ID.to_string(),
            event_id,
            timestamp,
            host_id: aws_account_id,
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

fn optional_bool(record: &Value, pointer: &str) -> Option<bool> {
    match record.pointer(pointer) {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("true") => Some(true),
        Some(Value::String(value)) if value.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn optional_yes_no(record: &Value, pointer: &str) -> Option<bool> {
    record.pointer(pointer).and_then(|value| match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "yes" | "true" | "1" => Some(true),
            "no" | "false" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

fn object_or_default(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Object(object)) => Value::Object(object.clone()),
        Some(Value::Null) | None => Value::Object(Default::default()),
        Some(other) => other.clone(),
    }
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::CloudTrailBridge;
    use crate::source::JsonRecordSource;
    use serde_json::json;
    use swarm_core::{TelemetryBridge, TelemetryPayload};

    #[tokio::test]
    async fn console_login_maps_to_cloudtrail_payload() {
        let mut bridge = CloudTrailBridge::new(JsonRecordSource::new([json!({
            "eventID": "evt-1",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "eventTime": "2026-04-06T12:00:00Z",
            "recipientAccountId": "123456789012",
            "sourceIPAddress": "198.51.100.10",
            "userAgent": "signin.amazonaws.com",
            "awsRegion": "us-east-1",
            "responseElements": { "ConsoleLogin": "Success" },
            "userIdentity": {
                "type": "IAMUser",
                "userName": "alice",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "principalId": "AIDAEXAMPLE",
                "sessionContext": {
                    "attributes": {
                        "mfaAuthenticated": "true"
                    }
                }
            }
        })]));

        let events = bridge
            .poll()
            .await
            .expect("cloudtrail auth event should map");
        let event = events.first().expect("one event should be returned");
        assert_eq!(event.source, "cloudtrail");

        match &event.payload {
            TelemetryPayload::CloudTrail(cloudtrail) => {
                assert_eq!(cloudtrail.event_name, "ConsoleLogin");
                assert_eq!(cloudtrail.event_source, "signin.amazonaws.com");
                assert_eq!(cloudtrail.aws_account_id.as_deref(), Some("123456789012"));
                assert_eq!(
                    cloudtrail.principal_arn.as_deref(),
                    Some("arn:aws:iam::123456789012:user/alice")
                );
                assert_eq!(cloudtrail.principal_name.as_deref(), Some("alice"));
                assert_eq!(
                    cloudtrail.source_ip_address.as_deref(),
                    Some("198.51.100.10")
                );
                assert_eq!(cloudtrail.aws_region.as_deref(), Some("us-east-1"));
                assert_eq!(cloudtrail.mfa_authenticated, Some(true));
            }
            _ => panic!("expected cloudtrail payload"),
        }
    }

    #[tokio::test]
    async fn request_and_response_elements_are_preserved() {
        let mut bridge = CloudTrailBridge::new(JsonRecordSource::new([json!({
            "eventID": "evt-2",
            "eventName": "RunInstances",
            "eventSource": "ec2.amazonaws.com",
            "eventTime": "2026-04-06T12:01:00Z",
            "recipientAccountId": "123456789012",
            "sourceIPAddress": "198.51.100.11",
            "requestParameters": {
                "imageId": "ami-evilminer",
                "instanceType": "p4d.24xlarge"
            },
            "responseElements": {
                "instancesSet": {
                    "items": [{"instanceId": "i-123"}]
                }
            }
        })]));

        let events = bridge
            .poll()
            .await
            .expect("cloudtrail data event should map");
        let event = events.first().expect("one event should be returned");

        match &event.payload {
            TelemetryPayload::CloudTrail(cloudtrail) => {
                assert_eq!(cloudtrail.event_name, "RunInstances");
                assert_eq!(cloudtrail.event_source, "ec2.amazonaws.com");
                assert_eq!(cloudtrail.request_parameters["imageId"], "ami-evilminer");
                assert_eq!(
                    cloudtrail.response_elements["instancesSet"]["items"][0]["instanceId"],
                    "i-123"
                );
            }
            _ => panic!("expected cloudtrail payload"),
        }
    }

    #[tokio::test]
    async fn console_login_falls_back_to_additional_event_data_mfa() {
        let mut bridge = CloudTrailBridge::new(JsonRecordSource::new([json!({
            "eventID": "evt-mfa-aed",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "eventTime": "2026-04-06T12:00:00Z",
            "recipientAccountId": "123456789012",
            "sourceIPAddress": "198.51.100.10",
            "userAgent": "signin.amazonaws.com",
            "awsRegion": "us-east-1",
            "responseElements": { "ConsoleLogin": "Success" },
            "additionalEventData": { "MFAUsed": "No" },
            "userIdentity": {
                "type": "IAMUser",
                "userName": "alice",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "principalId": "AIDAEXAMPLE"
            }
        })]));

        let event = bridge
            .poll()
            .await
            .expect("cloudtrail event should map")
            .pop()
            .expect("one event");
        match event.payload {
            TelemetryPayload::CloudTrail(cloudtrail) => {
                assert_eq!(cloudtrail.mfa_authenticated, Some(false));
            }
            _ => panic!("expected cloudtrail payload"),
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
