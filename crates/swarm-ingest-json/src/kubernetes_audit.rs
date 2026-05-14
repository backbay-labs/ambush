use crate::{JsonBridgeConfigError, record_error, validate_event_schema};
use async_trait::async_trait;
use chrono::DateTime;
use serde_json::Value;
use swarm_core::config::KubernetesAuditBridgeConfig;
use swarm_core::{
    BridgeHealth, KubernetesAuditEvent, TelemetryBridge, TelemetryBridgeError,
    TelemetryBridgeResult, TelemetryEvent, TelemetryPayload,
};

use crate::source::JsonRecordSource;

const SOURCE_ID: &str = "kubernetes_audit";

#[derive(Debug)]
pub struct KubernetesAuditBridge {
    source: JsonRecordSource,
    health: BridgeHealth,
}

impl KubernetesAuditBridge {
    pub fn new(source: JsonRecordSource) -> Self {
        Self {
            source,
            health: BridgeHealth::new(SOURCE_ID),
        }
    }

    pub fn from_config(
        config: &KubernetesAuditBridgeConfig,
    ) -> Result<Self, JsonBridgeConfigError> {
        let source = JsonRecordSource::from_file_config(&config.source)?;
        Ok(Self::new(source))
    }

    fn map_record(&mut self, record: &Value) -> TelemetryBridgeResult<TelemetryEvent> {
        let event_id = required_string(record, "/auditID", "auditID", &mut self.health)?;
        let timestamp = parse_timestamp(
            record,
            &["/stageTimestamp", "/requestReceivedTimestamp"],
            "stageTimestamp/requestReceivedTimestamp",
            &mut self.health,
        )?;
        let payload = TelemetryPayload::KubernetesAudit(KubernetesAuditEvent {
            verb: required_string(record, "/verb", "verb", &mut self.health)?,
            stage: optional_string(record, "/stage"),
            username: optional_string(record, "/user/username"),
            user_groups: string_array(record.pointer("/user/groups")),
            source_ips: string_array(record.pointer("/sourceIPs")),
            user_agent: optional_string(record, "/userAgent"),
            namespace: optional_string(record, "/objectRef/namespace"),
            resource: required_string(
                record,
                "/objectRef/resource",
                "objectRef.resource",
                &mut self.health,
            )?,
            subresource: optional_string(record, "/objectRef/subresource"),
            resource_name: optional_string(record, "/objectRef/name"),
            api_group: optional_string(record, "/objectRef/apiGroup"),
            response_code: record
                .pointer("/responseStatus/code")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok()),
            annotations: object_or_default(record.pointer("/annotations")),
            request_object: object_or_default(record.pointer("/requestObject")),
            impersonated_username: optional_string(record, "/impersonatedUser/username"),
        });

        let event = TelemetryEvent {
            source: SOURCE_ID.to_string(),
            event_id,
            timestamp,
            host_id: None,
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
impl TelemetryBridge for KubernetesAuditBridge {
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
        .ok_or_else(|| {
            record_error(
                health,
                format!("Kubernetes audit field `{field}` is required"),
            )
        })
}

fn optional_string(record: &Value, pointer: &str) -> Option<String> {
    record
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.trim().is_empty())
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.trim().is_empty())
        .collect()
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
    pointers: &[&str],
    field: &str,
    health: &mut BridgeHealth,
) -> TelemetryBridgeResult<i64> {
    let raw = pointers
        .iter()
        .find_map(|pointer| record.pointer(pointer).and_then(Value::as_str))
        .map(str::to_string)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            record_error(
                health,
                format!("Kubernetes audit field `{field}` is required"),
            )
        })?;
    DateTime::parse_from_rfc3339(&raw)
        .map(|timestamp| timestamp.timestamp())
        .map_err(|error| {
            record_error(
                health,
                format!("invalid Kubernetes audit timestamp: {error}"),
            )
        })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::KubernetesAuditBridge;
    use crate::source::JsonRecordSource;
    use serde_json::json;
    use swarm_core::{TelemetryBridge, TelemetryPayload};

    #[tokio::test]
    async fn maps_webhook_record_to_kubernetes_audit_payload() {
        let mut bridge = KubernetesAuditBridge::new(JsonRecordSource::new([json!({
            "auditID": "audit-1",
            "stageTimestamp": "2026-04-12T12:00:00Z",
            "verb": "create",
            "stage": "ResponseComplete",
            "user": {
                "username": "system:serviceaccount:prod:builder",
                "groups": ["system:serviceaccounts", "system:authenticated"]
            },
            "sourceIPs": ["203.0.113.10"],
            "userAgent": "kubectl/v1.30.0",
            "objectRef": {
                "resource": "pods",
                "namespace": "prod",
                "name": "escape-attempt",
                "apiGroup": ""
            },
            "responseStatus": {
                "code": 201
            },
            "annotations": {
                "authorization.k8s.io/decision": "allow"
            },
            "requestObject": {
                "spec": {
                    "hostPID": true
                }
            }
        })]));

        let events = bridge.poll().await.expect("kubernetes audit should map");
        let event = events.first().expect("one event should be returned");
        assert_eq!(event.source, "kubernetes_audit");

        match &event.payload {
            TelemetryPayload::KubernetesAudit(audit) => {
                assert_eq!(audit.verb, "create");
                assert_eq!(
                    audit.username.as_deref(),
                    Some("system:serviceaccount:prod:builder")
                );
                assert_eq!(audit.resource, "pods");
                assert_eq!(audit.namespace.as_deref(), Some("prod"));
                assert_eq!(audit.source_ips, vec!["203.0.113.10".to_string()]);
                assert_eq!(audit.response_code, Some(201));
                assert_eq!(audit.annotations["authorization.k8s.io/decision"], "allow");
                assert_eq!(audit.request_object["spec"]["hostPID"], true);
            }
            _ => panic!("expected kubernetes audit payload"),
        }
    }

    #[tokio::test]
    async fn malformed_record_fails_closed() {
        let mut bridge = KubernetesAuditBridge::new(JsonRecordSource::new([json!({
            "verb": "create",
            "stageTimestamp": "2026-04-12T12:00:00Z"
        })]));

        let error = bridge
            .poll()
            .await
            .expect_err("missing audit fields should fail");
        assert!(matches!(
            error,
            swarm_core::TelemetryBridgeError::Mapping(_)
        ));
        assert_eq!(bridge.health().error_count, 1);
    }
}
