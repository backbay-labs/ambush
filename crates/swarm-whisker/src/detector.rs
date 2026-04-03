//! Detection strategies that Whiskers execute on each telemetry event.

use serde::{Deserialize, Serialize};
use serde_json::json;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

/// Trait for pluggable detection strategies.
///
/// Strategies must be fast, deterministic, and side-effect free.
pub trait DetectionStrategy: Send + Sync {
    /// Strategy identifier.
    fn id(&self) -> &str;

    /// Evaluate a single telemetry event. Returns findings (possibly empty).
    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding>;
}

/// A normalized telemetry event from the environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryEvent {
    pub source: String,
    pub event_id: String,
    pub timestamp: i64,
    pub host_id: Option<String>,
    pub payload: TelemetryPayload,
}

/// Normalized payload kinds handled by the first detector slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryPayload {
    ProcessStart(ProcessStartEvent),
    NetworkConnect(NetworkConnectEvent),
}

/// Normalized process execution event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStartEvent {
    pub parent_process: String,
    pub process_name: String,
    pub command_line: String,
    pub user: Option<String>,
}

/// Normalized outbound network event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConnectEvent {
    pub process_name: String,
    pub destination_ip: String,
    pub destination_port: u16,
    pub protocol: String,
}

/// A concrete structured finding produced by a detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionFinding {
    pub finding_id: String,
    pub event_id: String,
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub confidence: f64,
    pub evidence: serde_json::Value,
    pub strategy_id: String,
}

/// Detector for suspicious parent-child process trees.
#[derive(Debug, Clone)]
pub struct SuspiciousProcessTreeDetector {
    suspicious_parents: Vec<&'static str>,
    suspicious_children: Vec<&'static str>,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
}

impl Default for SuspiciousProcessTreeDetector {
    fn default() -> Self {
        Self {
            suspicious_parents: vec!["winword", "excel", "outlook", "acrord32", "teams"],
            suspicious_children: vec!["powershell", "pwsh", "cmd", "sh", "bash", "curl", "wget"],
            high_confidence_threshold: 0.9,
            medium_confidence_threshold: 0.7,
        }
    }
}

impl SuspiciousProcessTreeDetector {
    pub fn new(high_confidence_threshold: f64, medium_confidence_threshold: f64) -> Self {
        Self {
            high_confidence_threshold,
            medium_confidence_threshold,
            ..Self::default()
        }
    }

    fn process_match(
        &self,
        event: &TelemetryEvent,
        process: &ProcessStartEvent,
    ) -> Option<DetectionFinding> {
        let parent = process.parent_process.to_ascii_lowercase();
        let child = process.process_name.to_ascii_lowercase();
        let command_line = process.command_line.to_ascii_lowercase();

        if !self
            .suspicious_parents
            .iter()
            .any(|candidate| *candidate == parent)
        {
            return None;
        }
        if !self
            .suspicious_children
            .iter()
            .any(|candidate| *candidate == child)
        {
            return None;
        }

        let has_encoded_flag = command_line.contains("-enc")
            || command_line.contains("base64")
            || command_line.contains("frombase64string");
        let has_download_hint = command_line.contains("http://")
            || command_line.contains("https://")
            || command_line.contains("downloadstring");

        let confidence = if has_encoded_flag || has_download_hint {
            self.high_confidence_threshold
        } else {
            self.medium_confidence_threshold
        };
        let severity = if confidence >= self.high_confidence_threshold {
            Severity::Critical
        } else {
            Severity::High
        };

        Some(DetectionFinding {
            finding_id: format!("{}:{}", self.id(), event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::Execution,
            severity,
            confidence,
            evidence: json!({
                "source": event.source,
                "parent_process": process.parent_process,
                "process_name": process.process_name,
                "command_line": process.command_line,
                "user": process.user,
                "host_id": event.host_id,
                "heuristics": {
                    "encoded_flag": has_encoded_flag,
                    "download_hint": has_download_hint,
                }
            }),
            strategy_id: self.id().to_string(),
        })
    }
}

impl DetectionStrategy for SuspiciousProcessTreeDetector {
    fn id(&self) -> &str {
        "suspicious_process_tree"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match &event.payload {
            TelemetryPayload::ProcessStart(process) => {
                self.process_match(event, process).into_iter().collect()
            }
            TelemetryPayload::NetworkConnect(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DetectionStrategy, ProcessStartEvent, SuspiciousProcessTreeDetector, TelemetryEvent,
        TelemetryPayload,
    };
    use swarm_core::types::Severity;

    fn suspicious_event(command_line: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "WINWORD".to_string(),
                process_name: "powershell".to_string(),
                command_line: command_line.to_string(),
                user: Some("alice".to_string()),
            }),
        }
    }

    #[test]
    fn suspicious_process_tree_triggers_finding() {
        let detector = SuspiciousProcessTreeDetector::default();
        let findings = detector.evaluate(&suspicious_event(
            "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ==",
        ));

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.confidence >= 0.9);
    }

    #[test]
    fn benign_process_tree_does_not_trigger() {
        let detector = SuspiciousProcessTreeDetector::default();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-2".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "launchd".to_string(),
                process_name: "ls".to_string(),
                command_line: "ls -la".to_string(),
                user: Some("alice".to_string()),
            }),
        };

        assert!(detector.evaluate(&event).is_empty());
    }
}
