use crate::TemporalEventWindow;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::fs;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;
use swarm_whisker::{
    DetectionFinding, DetectionStrategy, ProfileValidationError, TelemetryEvent,
    TelemetryEventPredicate, TelemetryPayload,
};

pub const KILL_CHAIN_SEQUENCE_STRATEGY_ID: &str = "kill_chain_sequence";
const MIN_PARTIAL_PREFIX_LEN: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillChainSequenceProfile {
    #[serde(default = "default_rules_path")]
    pub rules_path: String,
}

impl Default for KillChainSequenceProfile {
    fn default() -> Self {
        Self {
            rules_path: default_rules_path(),
        }
    }
}

impl KillChainSequenceProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        if self.rules_path.trim().is_empty() {
            return Err(ProfileValidationError {
                profile: "KillChainSequenceProfile",
                field: "rules_path",
                reason: "must not be empty".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KillChainSequenceDetectorError {
    #[error("failed to read kill-chain sequence rules `{path}`: {source}")]
    ReadRules {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse kill-chain sequence rules `{path}`: {source}")]
    ParseRules {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("invalid kill-chain sequence rules `{path}`: {reason}")]
    InvalidRules { path: String, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KillChainSequenceRuleSet {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    pub rules: Vec<KillChainSequenceRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KillChainSequenceRule {
    id: String,
    name: String,
    description: String,
    threat_class: ThreatClass,
    severity: Severity,
    confidence: f64,
    max_span_ms: i64,
    #[serde(default)]
    tags: Vec<String>,
    attack_chain: Vec<KillChainTechnique>,
    steps: Vec<KillChainSequenceStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KillChainTechnique {
    technique_id: String,
    name: String,
    kill_chain_stage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum KillChainStepKind {
    ProcessStart,
    NetworkConnect,
    RegistryPersistence,
    FilePersistence,
    AuthenticationEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KillChainSequenceStep {
    kind: KillChainStepKind,
    #[serde(default)]
    source_in: Vec<String>,
    #[serde(default)]
    process_name_in: Vec<String>,
    #[serde(default)]
    parent_process_in: Vec<String>,
    #[serde(default)]
    command_line_contains_any: Vec<String>,
    #[serde(default)]
    destination_port_in: Vec<u16>,
    #[serde(default)]
    destination_ip_in: Vec<String>,
    #[serde(default)]
    registry_path_contains_any: Vec<String>,
    #[serde(default)]
    access_type_in: Vec<String>,
    #[serde(default)]
    file_path_contains_any: Vec<String>,
    #[serde(default)]
    auth_type_in: Vec<String>,
    #[serde(default)]
    target_service_in: Vec<String>,
    #[serde(default)]
    success: Option<bool>,
}

impl KillChainSequenceStep {
    fn has_matcher(&self) -> bool {
        !self.source_in.is_empty()
            || !self.process_name_in.is_empty()
            || !self.parent_process_in.is_empty()
            || !self.command_line_contains_any.is_empty()
            || !self.destination_port_in.is_empty()
            || !self.destination_ip_in.is_empty()
            || !self.registry_path_contains_any.is_empty()
            || !self.access_type_in.is_empty()
            || !self.file_path_contains_any.is_empty()
            || !self.auth_type_in.is_empty()
            || !self.target_service_in.is_empty()
            || self.success.is_some()
    }

    fn matches(&self, event: &TelemetryEvent) -> bool {
        if !self.source_in.is_empty()
            && !self
                .source_in
                .iter()
                .any(|expected| event.source.eq_ignore_ascii_case(expected))
        {
            return false;
        }

        match (&self.kind, &event.payload) {
            (KillChainStepKind::ProcessStart, TelemetryPayload::ProcessStart(process)) => {
                matches_string_list(&self.parent_process_in, &process.parent_process)
                    && matches_string_list(&self.process_name_in, &process.process_name)
                    && matches_contains_any(
                        &self.command_line_contains_any,
                        process.command_line.as_str(),
                    )
            }
            (KillChainStepKind::NetworkConnect, TelemetryPayload::NetworkConnect(network)) => {
                matches_string_list(&self.process_name_in, &network.process_name)
                    && matches_u16_list(&self.destination_port_in, network.destination_port)
                    && matches_string_list(&self.destination_ip_in, &network.destination_ip)
            }
            (
                KillChainStepKind::RegistryPersistence,
                TelemetryPayload::RegistryPersistence(registry),
            ) => {
                matches_string_list(&self.process_name_in, &registry.process_name)
                    && matches_contains_any(
                        &self.registry_path_contains_any,
                        registry.registry_path.as_str(),
                    )
                    && matches_string_list(&self.access_type_in, &registry.access_type)
            }
            (KillChainStepKind::FilePersistence, TelemetryPayload::FilePersistence(file)) => {
                matches_string_list(&self.process_name_in, &file.process_name)
                    && matches_contains_any(&self.file_path_contains_any, file.file_path.as_str())
            }
            (
                KillChainStepKind::AuthenticationEvent,
                TelemetryPayload::AuthenticationEvent(auth),
            ) => {
                matches_string_list(&self.auth_type_in, &auth.auth_type)
                    && self
                        .success
                        .map(|expected| auth.success == expected)
                        .unwrap_or(true)
                    && match_optional_string_list(
                        &self.process_name_in,
                        auth.process_name.as_deref(),
                    )
                    && match_optional_string_list(
                        &self.target_service_in,
                        auth.target_service.as_deref(),
                    )
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KillChainSequenceDetector {
    strategy_id: String,
    rules: Vec<KillChainSequenceRule>,
    window: TemporalEventWindow,
}

impl KillChainSequenceDetector {
    pub fn from_profile(
        strategy_id: impl Into<String>,
        profile: KillChainSequenceProfile,
        window: TemporalEventWindow,
    ) -> Result<Self, KillChainSequenceDetectorError> {
        let strategy_id = strategy_id.into();
        let path = profile.rules_path.trim().to_string();
        let raw = fs::read_to_string(&path).map_err(|source| {
            KillChainSequenceDetectorError::ReadRules {
                path: path.clone(),
                source,
            }
        })?;
        let rule_set: KillChainSequenceRuleSet = serde_yaml::from_str(&raw).map_err(|source| {
            KillChainSequenceDetectorError::ParseRules {
                path: path.clone(),
                source,
            }
        })?;
        validate_rule_set(&rule_set, &path)?;
        Ok(Self {
            strategy_id,
            rules: rule_set.rules,
            window,
        })
    }
}

impl DetectionStrategy for KillChainSequenceDetector {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn id(&self) -> &str {
        self.strategy_id.as_str()
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        self.rules
            .iter()
            .filter_map(|rule| evaluate_rule(rule, &self.strategy_id, &self.window, event))
            .collect()
    }
}

fn evaluate_rule(
    rule: &KillChainSequenceRule,
    strategy_id: &str,
    window: &TemporalEventWindow,
    current_event: &TelemetryEvent,
) -> Option<DetectionFinding> {
    let max_prefix_len = rule
        .steps
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, step)| {
            if !step.matches(current_event) {
                return None;
            }
            let prefix_len = index + 1;
            if prefix_len < MIN_PARTIAL_PREFIX_LEN {
                return None;
            }

            let host_id = current_event.host_id.clone();
            let predicates = rule.steps[..prefix_len]
                .iter()
                .map(|step| {
                    let step = step.clone();
                    let host_id = host_id.clone();
                    let predicate = move |event: &TelemetryEvent| {
                        host_matches(host_id.as_deref(), event.host_id.as_deref())
                            && step.matches(event)
                    };
                    Box::new(predicate) as Box<dyn TelemetryEventPredicate>
                })
                .collect::<Vec<_>>();
            let predicate_refs = predicates
                .iter()
                .map(|predicate| predicate.as_ref())
                .collect::<Vec<_>>();
            let matched = window
                .match_ordered(&predicate_refs, Some(rule.max_span_ms))
                .ok()
                .flatten()?;
            if matched
                .matched_events
                .last()
                .is_some_and(|event| event.event_id == current_event.event_id)
            {
                Some((prefix_len, matched))
            } else {
                None
            }
        })?;

    let (prefix_len, matched) = max_prefix_len;
    let match_kind = if prefix_len == rule.steps.len() {
        "full"
    } else {
        "partial"
    };
    let severity = if match_kind == "full" {
        rule.severity
    } else {
        downgrade_severity(rule.severity)
    };
    let confidence = if match_kind == "full" {
        rule.confidence
    } else {
        partial_confidence(rule.confidence, prefix_len, rule.steps.len())
    };

    Some(DetectionFinding {
        finding_id: format!(
            "{strategy_id}:{}:{match_kind}:{}",
            rule.id, current_event.event_id
        ),
        event_id: current_event.event_id.clone(),
        threat_class: rule.threat_class.clone(),
        severity,
        confidence,
        evidence: serde_json::json!({
            "rule_id": rule.id,
            "rule_name": rule.name,
            "rule_description": rule.description,
            "match_kind": match_kind,
            "matched_prefix_len": prefix_len,
            "expected_steps": rule.steps.len(),
            "matched_event_ids": matched.matched_events.iter().map(|event| event.event_id.clone()).collect::<Vec<_>>(),
            "matched_events": matched.matched_events.iter().map(render_event_summary).collect::<Vec<_>>(),
            "attack_techniques": rule.attack_chain.iter().take(prefix_len).map(render_technique).collect::<Vec<_>>(),
            "kill_chain_stages": rule.attack_chain.iter().take(prefix_len).map(|technique| technique.kill_chain_stage.clone()).collect::<Vec<_>>(),
            "tags": rule.tags.clone(),
            "time_span_ms": matched.span_ms,
            "max_span_ms": rule.max_span_ms,
        }),
        strategy_id: strategy_id.to_string(),
    })
}

fn render_event_summary(event: &TelemetryEvent) -> serde_json::Value {
    serde_json::json!({
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "host_id": event.host_id,
        "payload_kind": payload_kind(&event.payload),
    })
}

fn render_technique(technique: &KillChainTechnique) -> serde_json::Value {
    serde_json::json!({
        "technique_id": technique.technique_id,
        "name": technique.name,
        "kill_chain_stage": technique.kill_chain_stage,
    })
}

fn payload_kind(payload: &TelemetryPayload) -> &'static str {
    match payload {
        TelemetryPayload::ProcessStart(_) => "process_start",
        TelemetryPayload::ProcessMemoryAccess(_) => "process_memory_access",
        TelemetryPayload::NetworkConnect(_) => "network_connect",
        TelemetryPayload::DnsQuery(_) => "dns_query",
        TelemetryPayload::RegistryAccess(_) => "registry_access",
        TelemetryPayload::RegistryPersistence(_) => "registry_persistence",
        TelemetryPayload::FilePersistence(_) => "file_persistence",
        TelemetryPayload::AuthenticationEvent(_) => "authentication_event",
        TelemetryPayload::InfrastructureHealth(_) => "infrastructure_health",
        TelemetryPayload::ThermalAnomaly(_) => "thermal_anomaly",
        TelemetryPayload::ResourceExhaustion(_) => "resource_exhaustion",
    }
}

fn validate_rule_set(
    rule_set: &KillChainSequenceRuleSet,
    path: &str,
) -> Result<(), KillChainSequenceDetectorError> {
    if rule_set.rules.is_empty() {
        return Err(KillChainSequenceDetectorError::InvalidRules {
            path: path.to_string(),
            reason: "must define at least one sequence rule".to_string(),
        });
    }

    for rule in &rule_set.rules {
        if rule.id.trim().is_empty() {
            return Err(KillChainSequenceDetectorError::InvalidRules {
                path: path.to_string(),
                reason: "rule id must not be empty".to_string(),
            });
        }
        if rule.name.trim().is_empty() {
            return Err(KillChainSequenceDetectorError::InvalidRules {
                path: path.to_string(),
                reason: format!("rule `{}` name must not be empty", rule.id),
            });
        }
        if rule.steps.len() < MIN_PARTIAL_PREFIX_LEN {
            return Err(KillChainSequenceDetectorError::InvalidRules {
                path: path.to_string(),
                reason: format!("rule `{}` must define at least two steps", rule.id),
            });
        }
        if rule.attack_chain.len() != rule.steps.len() {
            return Err(KillChainSequenceDetectorError::InvalidRules {
                path: path.to_string(),
                reason: format!(
                    "rule `{}` attack_chain length must match steps length",
                    rule.id
                ),
            });
        }
        if !rule.confidence.is_finite() || !(0.0..=1.0).contains(&rule.confidence) {
            return Err(KillChainSequenceDetectorError::InvalidRules {
                path: path.to_string(),
                reason: format!("rule `{}` confidence must be between 0.0 and 1.0", rule.id),
            });
        }
        if rule.max_span_ms <= 0 {
            return Err(KillChainSequenceDetectorError::InvalidRules {
                path: path.to_string(),
                reason: format!("rule `{}` max_span_ms must be greater than zero", rule.id),
            });
        }
        for (index, step) in rule.steps.iter().enumerate() {
            if !step.has_matcher() {
                return Err(KillChainSequenceDetectorError::InvalidRules {
                    path: path.to_string(),
                    reason: format!(
                        "rule `{}` step {} must define at least one matcher",
                        rule.id, index
                    ),
                });
            }
        }
        for technique in &rule.attack_chain {
            if technique.technique_id.trim().is_empty()
                || technique.name.trim().is_empty()
                || technique.kill_chain_stage.trim().is_empty()
            {
                return Err(KillChainSequenceDetectorError::InvalidRules {
                    path: path.to_string(),
                    reason: format!(
                        "rule `{}` attack_chain entries must define technique_id, name, and kill_chain_stage",
                        rule.id
                    ),
                });
            }
        }
    }

    Ok(())
}

fn default_rules_path() -> String {
    "sequences/kill-chain-v1.yaml".to_string()
}

fn matches_string_list(expected: &[String], actual: &str) -> bool {
    expected.is_empty()
        || expected
            .iter()
            .any(|value| actual.eq_ignore_ascii_case(value.as_str()))
}

fn match_optional_string_list(expected: &[String], actual: Option<&str>) -> bool {
    if expected.is_empty() {
        return true;
    }
    actual.is_some_and(|actual| matches_string_list(expected, actual))
}

fn matches_contains_any(expected: &[String], actual: &str) -> bool {
    expected.is_empty()
        || expected.iter().any(|value| {
            actual
                .to_ascii_lowercase()
                .contains(value.to_ascii_lowercase().as_str())
        })
}

fn matches_u16_list(expected: &[u16], actual: u16) -> bool {
    expected.is_empty() || expected.contains(&actual)
}

fn host_matches(expected: Option<&str>, actual: Option<&str>) -> bool {
    match expected {
        Some(expected) => actual.is_some_and(|actual| actual == expected),
        None => true,
    }
}

fn partial_confidence(confidence: f64, matched_steps: usize, total_steps: usize) -> f64 {
    let progress = matched_steps as f64 / total_steps as f64;
    (confidence * progress * 0.8).clamp(0.35, (confidence - 0.05).max(0.35))
}

fn downgrade_severity(severity: Severity) -> Severity {
    match severity {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Low,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        KILL_CHAIN_SEQUENCE_STRATEGY_ID, KillChainSequenceDetector, KillChainSequenceProfile,
    };
    use crate::{RuntimeMode, SwarmRuntime};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_policy::static_gate::StaticApprovalGate;
    use swarm_response::adapters::SandboxExecutor;
    use swarm_whisker::{DetectionStrategy, TelemetryEvent, TelemetryPayload};

    fn write_rules() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "swarm-sequence-rules-{}-{}.yaml",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::write(
            &path,
            r#"
version: 1
rules:
  - id: office_lolbin_download
    name: Office child process followed by outbound download
    description: Matches a benign-looking office macro execution chain that only becomes suspicious in sequence.
    threat_class: command_and_control
    severity: HIGH
    confidence: 0.9
    max_span_ms: 120000
    attack_chain:
      - technique_id: T1204.002
        name: Malicious File
        kill_chain_stage: execution
      - technique_id: T1059.001
        name: PowerShell
        kill_chain_stage: execution
      - technique_id: T1105
        name: Ingress Tool Transfer
        kill_chain_stage: command_and_control
    tags: [office, sequence]
    steps:
      - kind: process_start
        parent_process_in: [winword]
        process_name_in: [powershell]
      - kind: process_start
        parent_process_in: [powershell]
        process_name_in: [cmd]
      - kind: network_connect
        process_name_in: [cmd]
        destination_port_in: [443]
"#,
        )
        .unwrap();
        path
    }

    fn process_event(
        event_id: &str,
        timestamp: i64,
        parent_process: &str,
        process_name: &str,
    ) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(swarm_whisker::ProcessStartEvent {
                parent_process: parent_process.to_string(),
                process_name: process_name.to_string(),
                command_line: format!("{process_name}.exe"),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    fn network_event(event_id: &str, timestamp: i64, process_name: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::NetworkConnect(swarm_whisker::NetworkConnectEvent {
                process_name: process_name.to_string(),
                destination_ip: "198.51.100.10".to_string(),
                destination_port: 443,
                protocol: "tcp".to_string(),
            }),
        }
    }

    #[test]
    fn sequence_detector_emits_full_match_on_terminal_event() {
        let path = write_rules();
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            StaticApprovalGate::default(),
            SandboxExecutor,
        );
        let detector = KillChainSequenceDetector::from_profile(
            KILL_CHAIN_SEQUENCE_STRATEGY_ID,
            KillChainSequenceProfile {
                rules_path: path.display().to_string(),
            },
            runtime.temporal_event_window(),
        )
        .unwrap();

        runtime.record_temporal_event(&process_event(
            "evt-1",
            1_700_000_000,
            "winword",
            "powershell",
        ));
        runtime.record_temporal_event(&process_event("evt-2", 1_700_000_030, "powershell", "cmd"));
        let final_event = network_event("evt-3", 1_700_000_060, "cmd");
        runtime.record_temporal_event(&final_event);

        let findings = detector.evaluate(&final_event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].event_id, "evt-3");
        assert_eq!(findings[0].strategy_id, KILL_CHAIN_SEQUENCE_STRATEGY_ID);
        assert_eq!(findings[0].evidence["match_kind"], "full");
    }

    #[test]
    fn sequence_detector_emits_partial_match_before_terminal_event() {
        let path = write_rules();
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            StaticApprovalGate::default(),
            SandboxExecutor,
        );
        let detector = KillChainSequenceDetector::from_profile(
            KILL_CHAIN_SEQUENCE_STRATEGY_ID,
            KillChainSequenceProfile {
                rules_path: path.display().to_string(),
            },
            runtime.temporal_event_window(),
        )
        .unwrap();

        runtime.record_temporal_event(&process_event(
            "evt-1",
            1_700_000_000,
            "winword",
            "powershell",
        ));
        let current_event = process_event("evt-2", 1_700_000_030, "powershell", "cmd");
        runtime.record_temporal_event(&current_event);

        let findings = detector.evaluate(&current_event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence["match_kind"], "partial");
        assert_eq!(findings[0].event_id, "evt-2");
    }
}
