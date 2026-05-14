use crate::detector::{
    DetectionFinding, DetectionStrategy, KubernetesAuditEvent, TelemetryEvent, TelemetryPayload,
};
use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesAuditProfile {
    #[serde(default = "default_privileged_role_fragments")]
    pub privileged_role_fragments: Vec<String>,
    #[serde(default = "default_escape_host_path_prefixes")]
    pub escape_host_path_prefixes: Vec<String>,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
}

impl Default for KubernetesAuditProfile {
    fn default() -> Self {
        Self {
            privileged_role_fragments: default_privileged_role_fragments(),
            escape_host_path_prefixes: default_escape_host_path_prefixes(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KubernetesAuditDetector {
    privileged_role_fragments: Vec<String>,
    escape_host_path_prefixes: Vec<String>,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
}

impl Default for KubernetesAuditDetector {
    fn default() -> Self {
        Self {
            privileged_role_fragments: default_privileged_role_fragments()
                .into_iter()
                .map(normalize)
                .collect(),
            escape_host_path_prefixes: default_escape_host_path_prefixes()
                .into_iter()
                .map(normalize)
                .collect(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

impl KubernetesAuditDetector {
    pub fn from_profile(profile: KubernetesAuditProfile) -> Result<Self, ProfileValidationError> {
        profile.validate()?;
        Ok(Self {
            privileged_role_fragments: profile
                .privileged_role_fragments
                .into_iter()
                .map(normalize)
                .collect(),
            escape_host_path_prefixes: profile
                .escape_host_path_prefixes
                .into_iter()
                .map(normalize)
                .collect(),
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
        })
    }

    pub fn profile(&self) -> KubernetesAuditProfile {
        KubernetesAuditProfile {
            privileged_role_fragments: self.privileged_role_fragments.clone(),
            escape_host_path_prefixes: self.escape_host_path_prefixes.clone(),
            high_confidence_threshold: self.high_confidence_threshold,
            medium_confidence_threshold: self.medium_confidence_threshold,
        }
    }

    fn evaluate_kubernetes(
        &self,
        event: &TelemetryEvent,
        audit: &KubernetesAuditEvent,
    ) -> Vec<DetectionFinding> {
        let mut findings = Vec::new();

        if self.role_binding_to_privileged_role(audit) {
            findings.push(self.finding(
                event,
                audit,
                "privileged_role_binding",
                Severity::High,
                self.high_confidence_threshold,
                "T1098",
                "Account Manipulation",
                "privilege-escalation",
                json!({
                    "role_ref_name": json_string_pointer(&audit.request_object, "/roleRef/name"),
                }),
            ));
        }

        if self.role_with_wildcard_permissions(audit) {
            findings.push(self.finding(
                event,
                audit,
                "wildcard_rbac_permissions",
                Severity::Critical,
                self.high_confidence_threshold,
                "T1098",
                "Account Manipulation",
                "privilege-escalation",
                json!({}),
            ));
        }

        if audit
            .impersonated_username
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            findings.push(self.finding(
                event,
                audit,
                "user_impersonation",
                Severity::Medium,
                self.medium_confidence_threshold.max(0.78),
                "T1134",
                "Access Token Manipulation",
                "privilege-escalation",
                json!({
                    "impersonated_username": audit.impersonated_username,
                }),
            ));
        }

        if self.container_escape_indicator(audit) {
            findings.push(self.finding(
                event,
                audit,
                "privileged_pod_spec",
                Severity::Critical,
                self.high_confidence_threshold,
                "T1611",
                "Escape to Host",
                "privilege-escalation",
                json!({}),
            ));
        }

        findings
    }

    fn finding(
        &self,
        event: &TelemetryEvent,
        audit: &KubernetesAuditEvent,
        mode: &str,
        severity: Severity,
        confidence: f64,
        technique_id: &str,
        technique_name: &str,
        kill_chain_stage: &str,
        extra: Value,
    ) -> DetectionFinding {
        let mut evidence = Map::new();
        evidence.insert("verb".to_string(), json!(audit.verb));
        evidence.insert("stage".to_string(), json!(audit.stage));
        evidence.insert("username".to_string(), json!(audit.username));
        evidence.insert("user_groups".to_string(), json!(audit.user_groups));
        evidence.insert("source_ips".to_string(), json!(audit.source_ips));
        evidence.insert("user_agent".to_string(), json!(audit.user_agent));
        evidence.insert("namespace".to_string(), json!(audit.namespace));
        evidence.insert("resource".to_string(), json!(audit.resource));
        evidence.insert("subresource".to_string(), json!(audit.subresource));
        evidence.insert("resource_name".to_string(), json!(audit.resource_name));
        evidence.insert("api_group".to_string(), json!(audit.api_group));
        evidence.insert("response_code".to_string(), json!(audit.response_code));
        evidence.insert("annotations".to_string(), audit.annotations.clone());
        evidence.insert("request_object".to_string(), audit.request_object.clone());
        evidence.insert("mode".to_string(), json!(mode));
        evidence.insert("mitre_technique_id".to_string(), json!(technique_id));
        evidence.insert(
            "attack_techniques".to_string(),
            json!([{
                "id": technique_id,
                "name": technique_name,
                "kill_chain_stage": kill_chain_stage,
            }]),
        );
        if let Value::Object(extra) = extra {
            evidence.extend(extra);
        }

        DetectionFinding {
            finding_id: format!("{}:{}", self.id(), event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::PrivilegeEscalation,
            severity,
            confidence,
            evidence: Value::Object(evidence),
            strategy_id: self.id().to_string(),
        }
    }

    fn role_binding_to_privileged_role(&self, audit: &KubernetesAuditEvent) -> bool {
        if !matches!(
            audit.resource.as_str(),
            "rolebindings" | "clusterrolebindings"
        ) {
            return false;
        }
        if !matches!(
            normalize(&audit.verb).as_str(),
            "create" | "update" | "patch"
        ) {
            return false;
        }
        let role_ref = json_string_pointer(&audit.request_object, "/roleRef/name")
            .map(|value| normalize(&value))
            .unwrap_or_default();
        self.privileged_role_fragments
            .iter()
            .any(|fragment| role_ref.contains(fragment))
            || json_tree_contains_string(&audit.request_object, "system:masters")
    }

    fn role_with_wildcard_permissions(&self, audit: &KubernetesAuditEvent) -> bool {
        if !matches!(audit.resource.as_str(), "roles" | "clusterroles") {
            return false;
        }
        if !matches!(
            normalize(&audit.verb).as_str(),
            "create" | "update" | "patch"
        ) {
            return false;
        }
        audit
            .request_object
            .pointer("/rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|rule| {
                ["/verbs", "/resources", "/apiGroups"]
                    .into_iter()
                    .any(|pointer| {
                        rule.pointer(pointer)
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .map(normalize)
                            .any(|value| value == "*" || value == "secrets")
                    })
            })
    }

    fn container_escape_indicator(&self, audit: &KubernetesAuditEvent) -> bool {
        if audit.resource != "pods" {
            return false;
        }
        if !matches!(
            normalize(&audit.verb).as_str(),
            "create" | "update" | "patch"
        ) {
            return false;
        }
        spec_roots(&audit.request_object).into_iter().any(|spec| {
            bool_pointer(spec, "/hostPID")
                || bool_pointer(spec, "/hostIPC")
                || bool_pointer(spec, "/hostNetwork")
                || privileged_container(spec)
                || host_path_escape(spec, &self.escape_host_path_prefixes)
        })
    }
}

impl KubernetesAuditProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        validate_confidence_thresholds(
            "kubernetes_audit",
            self.high_confidence_threshold,
            self.medium_confidence_threshold,
        )?;
        validate_entries(
            "kubernetes_audit",
            "privileged_role_fragments",
            &self.privileged_role_fragments,
        )?;
        validate_entries(
            "kubernetes_audit",
            "escape_host_path_prefixes",
            &self.escape_host_path_prefixes,
        )?;
        Ok(())
    }
}

impl DetectionStrategy for KubernetesAuditDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        "kubernetes_audit"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match &event.payload {
            TelemetryPayload::KubernetesAudit(audit) => self.evaluate_kubernetes(event, audit),
            TelemetryPayload::ProcessStart(_)
            | TelemetryPayload::ProcessMemoryAccess(_)
            | TelemetryPayload::NetworkConnect(_)
            | TelemetryPayload::DnsQuery(_)
            | TelemetryPayload::CloudTrail(_)
            | TelemetryPayload::RegistryAccess(_)
            | TelemetryPayload::RegistryPersistence(_)
            | TelemetryPayload::FilePersistence(_)
            | TelemetryPayload::AuthenticationEvent(_)
            | TelemetryPayload::InfrastructureHealth(_)
            | TelemetryPayload::ThermalAnomaly(_)
            | TelemetryPayload::ResourceExhaustion(_) => Vec::new(),
        }
    }
}

fn validate_entries(
    profile: &'static str,
    field: &'static str,
    values: &[String],
) -> Result<(), ProfileValidationError> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(ProfileValidationError {
            profile,
            field,
            reason: "must not contain empty entries".to_string(),
        });
    }
    Ok(())
}

fn spec_roots(request_object: &Value) -> Vec<&Value> {
    let mut specs = Vec::new();
    if let Some(spec) = request_object.pointer("/spec") {
        specs.push(spec);
    }
    if let Some(spec) = request_object.pointer("/spec/template/spec") {
        specs.push(spec);
    }
    specs
}

fn bool_pointer(root: &Value, pointer: &str) -> bool {
    root.pointer(pointer)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn privileged_container(spec: &Value) -> bool {
    ["/containers", "/initContainers", "/ephemeralContainers"]
        .into_iter()
        .any(|pointer| {
            spec.pointer(pointer)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|container| {
                    container
                        .pointer("/securityContext/privileged")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                })
        })
}

fn host_path_escape(spec: &Value, prefixes: &[String]) -> bool {
    spec.pointer("/volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|volume| volume.pointer("/hostPath/path").and_then(Value::as_str))
        .map(normalize)
        .any(|path| prefixes.iter().any(|prefix| path.starts_with(prefix)))
}

fn json_string_pointer(root: &Value, pointer: &str) -> Option<String> {
    match root.pointer(pointer) {
        Some(Value::String(value)) => Some(value.to_string()),
        Some(Value::Number(value)) => Some(value.to_string()),
        Some(Value::Bool(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn json_tree_contains_string(root: &Value, needle: &str) -> bool {
    let needle = normalize(needle);
    match root {
        Value::String(value) => normalize(value).contains(&needle),
        Value::Array(values) => values
            .iter()
            .any(|value| json_tree_contains_string(value, needle.as_str())),
        Value::Object(values) => values
            .values()
            .any(|value| json_tree_contains_string(value, needle.as_str())),
        _ => false,
    }
}

fn normalize(value: impl AsRef<str>) -> String {
    value.as_ref().trim().to_ascii_lowercase()
}

fn default_privileged_role_fragments() -> Vec<String> {
    vec![
        "cluster-admin".to_string(),
        "admin".to_string(),
        "system:masters".to_string(),
    ]
}

fn default_escape_host_path_prefixes() -> Vec<String> {
    vec![
        "/".to_string(),
        "/proc".to_string(),
        "/var/run/docker.sock".to_string(),
        "/run/containerd".to_string(),
    ]
}

fn default_high_confidence_threshold() -> f64 {
    0.95
}

fn default_medium_confidence_threshold() -> f64 {
    0.80
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::KubernetesAuditDetector;
    use crate::detector::{
        DetectionStrategy, KubernetesAuditEvent, TelemetryEvent, TelemetryPayload,
    };
    use serde_json::json;

    fn event(event_id: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "kubernetes_audit".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_760_000_000,
            host_id: None,
            payload: TelemetryPayload::KubernetesAudit(KubernetesAuditEvent {
                verb: "create".to_string(),
                stage: Some("ResponseComplete".to_string()),
                username: Some("system:serviceaccount:prod:builder".to_string()),
                user_groups: vec!["system:authenticated".to_string()],
                source_ips: vec!["203.0.113.20".to_string()],
                user_agent: Some("kubectl".to_string()),
                namespace: Some("prod".to_string()),
                resource: "pods".to_string(),
                subresource: None,
                resource_name: Some("escape-attempt".to_string()),
                api_group: Some("".to_string()),
                response_code: Some(201),
                annotations: json!({}),
                request_object: json!({}),
                impersonated_username: None,
            }),
        }
    }

    fn payload_mut(event: &mut TelemetryEvent) -> &mut KubernetesAuditEvent {
        match &mut event.payload {
            TelemetryPayload::KubernetesAudit(payload) => payload,
            _ => panic!("expected kubernetes audit payload"),
        }
    }

    #[test]
    fn privileged_role_binding_is_detected() {
        let detector = KubernetesAuditDetector::default();
        let mut event = event("evt-1");
        let payload = payload_mut(&mut event);
        payload.resource = "clusterrolebindings".to_string();
        payload.request_object = json!({
            "roleRef": { "name": "cluster-admin" },
            "subjects": [{ "kind": "ServiceAccount", "name": "builder" }]
        });

        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence["mode"], "privileged_role_binding");
    }

    #[test]
    fn wildcard_cluster_role_is_detected() {
        let detector = KubernetesAuditDetector::default();
        let mut event = event("evt-2");
        let payload = payload_mut(&mut event);
        payload.resource = "clusterroles".to_string();
        payload.request_object = json!({
            "rules": [{
                "apiGroups": ["*"],
                "resources": ["*"],
                "verbs": ["*"]
            }]
        });

        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence["mode"], "wildcard_rbac_permissions");
    }

    #[test]
    fn impersonation_is_detected() {
        let detector = KubernetesAuditDetector::default();
        let mut event = event("evt-3");
        payload_mut(&mut event).impersonated_username = Some("cluster-admin".to_string());

        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence["mode"], "user_impersonation");
    }

    #[test]
    fn privileged_pod_spec_is_detected() {
        let detector = KubernetesAuditDetector::default();
        let mut event = event("evt-4");
        payload_mut(&mut event).request_object = json!({
            "spec": {
                "hostPID": true,
                "volumes": [{
                    "name": "host-root",
                    "hostPath": { "path": "/" }
                }],
                "containers": [{
                    "name": "escape",
                    "securityContext": {
                        "privileged": true
                    }
                }]
            }
        });

        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence["mode"], "privileged_pod_spec");
    }
}
