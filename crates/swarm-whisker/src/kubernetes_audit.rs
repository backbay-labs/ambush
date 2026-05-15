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
        let stage = audit.stage.as_deref().unwrap_or_default();
        if !stage.eq_ignore_ascii_case("ResponseComplete") {
            return Vec::new();
        }
        // Fail closed when `responseStatus.code` is missing or unmapped at
        // ResponseComplete: malformed/partial audit records must not drive
        // privileged-pod or wildcard-RBAC findings without an explicit
        // success code. Detection requires the cluster to emit a 2xx response.
        let Some(code) = audit.response_code else {
            return Vec::new();
        };
        if !(200..300).contains(&code) {
            return Vec::new();
        }

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

    #[allow(clippy::too_many_arguments)]
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
            finding_id: format!("{}:{}:{}", self.id(), mode, event.event_id),
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
        if self
            .privileged_role_fragments
            .iter()
            .any(|fragment| role_ref.contains(fragment))
            || json_tree_contains_string(&audit.request_object, "system:masters")
        {
            return true;
        }
        // JSON Patch: a `replace /roleRef/name` op (or any add/replace whose
        // path or value mentions a privileged role name) updates an existing
        // binding to point at cluster-admin/admin. The walk in
        // `role_with_wildcard_permissions` doesn't apply here; check directly.
        if let Some(operations) = audit.request_object.as_array() {
            for op in operations {
                let kind = op.get("op").and_then(Value::as_str).unwrap_or_default();
                if !matches!(kind, "add" | "replace") {
                    continue;
                }
                let path = op.get("path").and_then(Value::as_str).unwrap_or_default();
                let Some(value) = op.get("value") else {
                    continue;
                };
                if path.contains("/roleRef") {
                    let candidate = match value {
                        Value::String(s) => normalize(s),
                        _ => json_string_pointer(value, "/name")
                            .map(|s| normalize(&s))
                            .unwrap_or_default(),
                    };
                    if !candidate.is_empty()
                        && self
                            .privileged_role_fragments
                            .iter()
                            .any(|fragment| candidate.contains(fragment))
                    {
                        return true;
                    }
                    if json_tree_contains_string(value, "system:masters") {
                        return true;
                    }
                }
            }
        }
        false
    }

    // KNOWN LIMITATION: a single audit event can build a wildcard rule via
    // multiple field-level patches (`add /rules/0/verbs ["*"]`,
    // `add /rules/0/resources ["*"]`, `add /rules/0/apiGroups ["*"]`). The
    // current detector only fires when a patch value is itself a complete rule
    // object/array. Combining sibling field patches into a synthetic rule
    // before evaluating wildcard membership is tracked as a follow-up.
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
        if audit
            .request_object
            .pointer("/rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(rule_is_wildcard)
        {
            return true;
        }
        // JSON Patch updates ship as `[{op, path, value}, ...]`. A patch like
        // `add /rules/-` with `{verbs:["*"], resources:["*"], apiGroups:["*"]}`
        // would otherwise miss the object walk above.
        if let Some(operations) = audit.request_object.as_array() {
            for op in operations {
                let kind = op.get("op").and_then(Value::as_str).unwrap_or_default();
                if !matches!(kind, "add" | "replace") {
                    continue;
                }
                let Some(value) = op.get("value") else {
                    continue;
                };
                let path = op.get("path").and_then(Value::as_str).unwrap_or_default();
                if path.contains("/rules") {
                    if let Some(rule_array) = value.as_array() {
                        if rule_array.iter().any(rule_is_wildcard) {
                            return true;
                        }
                    } else if rule_is_wildcard(value) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn container_escape_indicator(&self, audit: &KubernetesAuditEvent) -> bool {
        // Pods carry the spec inline; controller resources (Deployment, DaemonSet,
        // StatefulSet, ReplicaSet, Job, CronJob) wrap the same spec under
        // `spec.template.spec` (and CronJobs under `spec.jobTemplate.spec.template.spec`).
        // `spec_roots` walks both shapes — the outer-resource gate just needs to
        // accept the shapes that can carry a templated pod spec.
        if !matches!(
            audit.resource.as_str(),
            "pods"
                | "deployments"
                | "daemonsets"
                | "statefulsets"
                | "replicasets"
                | "jobs"
                | "cronjobs"
        ) {
            return false;
        }
        if !matches!(
            normalize(&audit.verb).as_str(),
            "create" | "update" | "patch"
        ) {
            return false;
        }
        if spec_roots(&audit.request_object).into_iter().any(|spec| {
            bool_pointer(spec, "/hostPID")
                || bool_pointer(spec, "/hostIPC")
                || bool_pointer(spec, "/hostNetwork")
                || privileged_container(spec)
                || host_path_escape(spec, &self.escape_host_path_prefixes)
        }) {
            return true;
        }
        // JSON Patch updates carry an array of `{op, path, value}` operations
        // instead of a full pod spec. A `patch` that adds `hostPID`,
        // `hostNetwork`, `securityContext.privileged`, or a hostPath volume to
        // an existing controller would otherwise miss the spec walk above.
        json_patch_escalates(&audit.request_object, &self.escape_host_path_prefixes)
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

fn rule_is_wildcard(rule: &Value) -> bool {
    ["/verbs", "/resources", "/apiGroups"]
        .into_iter()
        .all(|pointer| rule_field_contains_wildcard(rule, pointer))
}

fn rule_field_contains_wildcard(rule: &Value, pointer: &str) -> bool {
    let entries: Vec<&str> = rule
        .pointer(pointer)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .collect();
    if entries.contains(&"*") {
        return true;
    }
    // For apiGroups, an empty string is the Kubernetes core API group
    // (pods, secrets, configmaps, ...) — wildcarding verbs+resources within
    // it is still wildcard RBAC over the most sensitive surface.
    pointer == "/apiGroups" && entries.contains(&"")
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

fn json_patch_escalates(request_object: &Value, host_path_prefixes: &[String]) -> bool {
    let Some(operations) = request_object.as_array() else {
        return false;
    };
    operations
        .iter()
        .filter(|op| {
            op.get("op")
                .and_then(Value::as_str)
                .is_some_and(|kind| matches!(kind, "add" | "replace"))
        })
        .any(|op| {
            let path = op.get("path").and_then(Value::as_str).unwrap_or_default();
            let value = op.get("value");
            json_patch_target_escalates(path, value, host_path_prefixes)
        })
}

fn json_patch_target_escalates(
    path: &str,
    value: Option<&Value>,
    host_path_prefixes: &[String],
) -> bool {
    let Some(value) = value else {
        return false;
    };
    let normalized = path.trim_end_matches('/');
    if normalized.ends_with("/hostPID")
        || normalized.ends_with("/hostIPC")
        || normalized.ends_with("/hostNetwork")
    {
        return matches!(value, Value::Bool(true));
    }
    if normalized.ends_with("/securityContext/privileged") {
        return matches!(value, Value::Bool(true));
    }
    if normalized.contains("/securityContext") && privileged_container_value(value) {
        return true;
    }
    // Direct retarget of an existing volume's hostPath to an escape prefix:
    // `replace /spec/template/spec/volumes/0/hostPath/path` with `"/"`. The
    // value is a scalar string, so host_path_escape_value (which walks
    // arrays/objects looking for `/hostPath/path` pointers) can't see it.
    if normalized.ends_with("/hostPath/path")
        && let Some(scalar) = value.as_str()
        && host_path_prefixes
            .iter()
            .any(|prefix| scalar.starts_with(prefix.as_str()))
    {
        return true;
    }
    if normalized.contains("/volumes") && host_path_escape_value(value, host_path_prefixes) {
        return true;
    }
    // Patches that add/replace a whole container, container array, pod spec, or
    // pod template need a deep walk of the value because the escalation may be
    // any number of levels nested inside the patched subtree (e.g. add
    // `/spec/template/spec/containers/-` with a full container that includes
    // `securityContext.privileged: true`).
    if normalized.ends_with("/containers")
        || normalized.contains("/containers/")
        || normalized.ends_with("/initContainers")
        || normalized.contains("/initContainers/")
        || normalized.ends_with("/ephemeralContainers")
        || normalized.contains("/ephemeralContainers/")
        || normalized.ends_with("/spec")
        || normalized.ends_with("/template")
        || normalized.contains("/template/spec")
        || normalized.ends_with("/jobTemplate")
        || normalized.contains("/jobTemplate/spec")
    {
        return value_contains_pod_escalation(value, host_path_prefixes);
    }
    false
}

fn value_contains_pod_escalation(value: &Value, host_path_prefixes: &[String]) -> bool {
    match value {
        Value::Array(items) => items
            .iter()
            .any(|item| value_contains_pod_escalation(item, host_path_prefixes)),
        Value::Object(_) => {
            if bool_pointer(value, "/hostPID")
                || bool_pointer(value, "/hostIPC")
                || bool_pointer(value, "/hostNetwork")
                || privileged_container(value)
                || host_path_escape(value, host_path_prefixes)
                || privileged_container_value(value)
            {
                return true;
            }
            // Recurse one level to catch a single container value (no `/containers`
            // wrapper) whose `securityContext.privileged` lives at the root.
            value
                .as_object()
                .into_iter()
                .flat_map(|map| map.values())
                .any(|child| value_contains_pod_escalation(child, host_path_prefixes))
        }
        _ => false,
    }
}

fn privileged_container_value(value: &Value) -> bool {
    matches!(value.pointer("/privileged"), Some(Value::Bool(true)))
}

fn host_path_escape_value(value: &Value, prefixes: &[String]) -> bool {
    if let Some(items) = value.as_array() {
        // Whole-array patches: walk each element so a `replace /spec/template/spec/volumes`
        // with an inline hostPath volume still matches.
        return items
            .iter()
            .any(|item| host_path_escape_value(item, prefixes));
    }
    let path = value
        .pointer("/hostPath/path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    !path.is_empty()
        && prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix.as_str()))
}

fn spec_roots(request_object: &Value) -> Vec<&Value> {
    let mut specs = Vec::new();
    if let Some(spec) = request_object.pointer("/spec") {
        specs.push(spec);
    }
    if let Some(spec) = request_object.pointer("/spec/template/spec") {
        specs.push(spec);
    }
    // CronJob nests its pod template one level deeper.
    if let Some(spec) = request_object.pointer("/spec/jobTemplate/spec/template/spec") {
        specs.push(spec);
    }
    // The `pods/ephemeralcontainers` subresource update can carry the debug
    // containers at the top level (no `/spec` wrapper). Treat the request body
    // itself as a spec-equivalent root so `privileged_container` finds them.
    if request_object
        .pointer("/ephemeralContainers")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
    {
        specs.push(request_object);
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

    #[test]
    fn json_patch_retargeting_volume_hostpath_to_root_is_detected() {
        // Regression: a successful JSONPatch that directly retargets an
        // existing volume's hostPath to an escape prefix used to evade the
        // /volumes walk because the patched value was a scalar string.
        let detector = KubernetesAuditDetector::default();
        let mut event = event("evt-jsonpatch-volume");
        let payload = payload_mut(&mut event);
        payload.request_object = json!([
            {
                "op": "replace",
                "path": "/spec/template/spec/volumes/0/hostPath/path",
                "value": "/"
            }
        ]);
        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1, "scalar hostPath retarget must trigger");
        assert_eq!(findings[0].evidence["mode"], "privileged_pod_spec");
    }

    #[test]
    fn denied_response_is_not_treated_as_privilege_escalation() {
        let detector = KubernetesAuditDetector::default();
        let mut event = event("evt-deny");
        let payload = payload_mut(&mut event);
        payload.resource = "clusterrolebindings".to_string();
        payload.request_object = json!({
            "roleRef": { "name": "cluster-admin" },
            "subjects": [{ "kind": "ServiceAccount", "name": "builder" }]
        });
        payload.response_code = Some(403);
        assert!(detector.evaluate(&event).is_empty());

        payload_mut(&mut event).stage = Some("RequestReceived".to_string());
        payload_mut(&mut event).response_code = Some(201);
        assert!(detector.evaluate(&event).is_empty());
    }

    #[test]
    fn narrow_secrets_reader_role_is_not_wildcard_rbac() {
        let detector = KubernetesAuditDetector::default();
        let mut event = event("evt-narrow");
        let payload = payload_mut(&mut event);
        payload.resource = "roles".to_string();
        payload.request_object = json!({
            "rules": [{
                "verbs": ["get"],
                "resources": ["secrets"],
                "apiGroups": [""]
            }]
        });
        assert!(detector.evaluate(&event).is_empty());

        // Genuine wildcard requires ALL three fields to contain "*".
        payload_mut(&mut event).request_object = json!({
            "rules": [{
                "verbs": ["*"],
                "resources": ["*"],
                "apiGroups": ["*"]
            }]
        });
        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence["mode"], "wildcard_rbac_permissions");

        // Core API group is signalled by `apiGroups: [""]` — verbs+resources
        // wildcarded over the core group is still wildcard RBAC.
        payload_mut(&mut event).request_object = json!({
            "rules": [{
                "verbs": ["*"],
                "resources": ["*"],
                "apiGroups": [""]
            }]
        });
        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence["mode"], "wildcard_rbac_permissions");
    }

    #[test]
    fn missing_response_code_at_response_complete_fails_closed() {
        let detector = KubernetesAuditDetector::default();
        let mut event = event("evt-meta");
        let payload = payload_mut(&mut event);
        payload.resource = "clusterrolebindings".to_string();
        payload.request_object = json!({
            "roleRef": { "name": "cluster-admin" },
            "subjects": [{ "kind": "ServiceAccount", "name": "builder" }]
        });
        payload.response_code = None;
        assert!(
            detector.evaluate(&event).is_empty(),
            "missing response_code at ResponseComplete must fail closed"
        );

        // Restoring an explicit 2xx code lets the predicate fire.
        payload_mut(&mut event).response_code = Some(201);
        assert_eq!(detector.evaluate(&event).len(), 1);
    }
}
