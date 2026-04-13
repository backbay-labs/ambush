//! Detection strategies that Whiskers execute on each telemetry event.

use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::any::Any;
use swarm_core::pheromone::ThreatClass;
pub use swarm_core::telemetry::{
    AuthenticationEventData, DnsQueryEvent, ExhaustedResource, FilePersistenceEvent,
    InfrastructureHealthEvent, NetworkConnectEvent, ProcessMemoryAccessEvent, ProcessStartEvent,
    RegistryAccessEvent, RegistryPersistenceEvent, ResourceExhaustionEvent, TelemetryEvent,
    TelemetryPayload, ThermalAnomalyEvent, ThermalSeverity,
};
use swarm_core::types::Severity;

/// Trait for pluggable detection strategies.
///
/// Strategies must be fast and safe to run on the hot path.
///
/// Stateless detectors are preferred, but windowed/stateful detectors are allowed
/// when they keep internal learning state behind synchronization primitives.
pub trait DetectionStrategy: Send + Sync + 'static {
    /// Downcast hook for runtime-specific persistence helpers.
    fn as_any(&self) -> &dyn Any;

    /// Strategy identifier.
    fn id(&self) -> &str;

    /// Evaluate a single telemetry event. Returns findings (possibly empty).
    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding>;
}

/// Predicate seam used by later multi-event sequence matching over telemetry.
pub trait TelemetryEventPredicate: Send + Sync {
    fn matches(&self, event: &TelemetryEvent) -> bool;
}

impl<F> TelemetryEventPredicate for F
where
    F: Fn(&TelemetryEvent) -> bool + Send + Sync,
{
    fn matches(&self, event: &TelemetryEvent) -> bool {
        self(event)
    }
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

/// Serializable profile for the suspicious process-tree detector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspiciousProcessTreeProfile {
    #[serde(default = "default_suspicious_parents")]
    pub suspicious_parents: Vec<String>,
    #[serde(default = "default_suspicious_children")]
    pub suspicious_children: Vec<String>,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
}

impl Default for SuspiciousProcessTreeProfile {
    fn default() -> Self {
        Self {
            suspicious_parents: default_suspicious_parents(),
            suspicious_children: default_suspicious_children(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

/// Detector for suspicious parent-child process trees.
#[derive(Debug, Clone)]
pub struct SuspiciousProcessTreeDetector {
    suspicious_parents: Vec<String>,
    suspicious_children: Vec<String>,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
}

impl Default for SuspiciousProcessTreeDetector {
    fn default() -> Self {
        Self {
            suspicious_parents: default_suspicious_parents()
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            suspicious_children: default_suspicious_children()
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

impl SuspiciousProcessTreeDetector {
    pub fn from_profile(
        profile: SuspiciousProcessTreeProfile,
    ) -> Result<Self, ProfileValidationError> {
        profile.validate()?;
        Ok(Self {
            suspicious_parents: profile
                .suspicious_parents
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            suspicious_children: profile
                .suspicious_children
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
        })
    }

    pub fn new(high_confidence_threshold: f64, medium_confidence_threshold: f64) -> Self {
        Self {
            suspicious_parents: default_suspicious_parents(),
            suspicious_children: default_suspicious_children(),
            high_confidence_threshold,
            medium_confidence_threshold,
        }
    }

    pub fn profile(&self) -> SuspiciousProcessTreeProfile {
        SuspiciousProcessTreeProfile {
            suspicious_parents: self.suspicious_parents.clone(),
            suspicious_children: self.suspicious_children.clone(),
            high_confidence_threshold: self.high_confidence_threshold,
            medium_confidence_threshold: self.medium_confidence_threshold,
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

        if !self.suspicious_parents.contains(&parent) {
            return None;
        }
        if !self.suspicious_children.contains(&child) {
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

impl SuspiciousProcessTreeProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        validate_confidence_thresholds(
            "SuspiciousProcessTreeProfile",
            self.high_confidence_threshold,
            self.medium_confidence_threshold,
        )
    }
}

impl DetectionStrategy for SuspiciousProcessTreeDetector {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn id(&self) -> &str {
        "suspicious_process_tree"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match &event.payload {
            TelemetryPayload::ProcessStart(process) => {
                self.process_match(event, process).into_iter().collect()
            }
            TelemetryPayload::NetworkConnect(_)
            | TelemetryPayload::ProcessMemoryAccess(_)
            | TelemetryPayload::DnsQuery(_)
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

fn default_suspicious_parents() -> Vec<String> {
    ["winword", "excel", "outlook", "acrord32", "teams"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_suspicious_children() -> Vec<String> {
    ["powershell", "pwsh", "cmd", "sh", "bash", "curl", "wget"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_high_confidence_threshold() -> f64 {
    0.9
}

fn default_medium_confidence_threshold() -> f64 {
    0.7
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DetectionStrategy, ProcessStartEvent, SuspiciousProcessTreeDetector,
        SuspiciousProcessTreeProfile, TelemetryEvent, TelemetryPayload,
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
                executable_path: None,
                signer: None,
                signature_valid: None,
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
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };

        assert!(detector.evaluate(&event).is_empty());
    }

    #[test]
    fn configured_profile_controls_parent_matching() {
        let detector = SuspiciousProcessTreeDetector::from_profile(SuspiciousProcessTreeProfile {
            suspicious_parents: vec!["python".to_string()],
            suspicious_children: vec!["curl".to_string()],
            high_confidence_threshold: 0.9,
            medium_confidence_threshold: 0.7,
        })
        .expect("profile should be valid");
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-3".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-2".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "python".to_string(),
                process_name: "curl".to_string(),
                command_line: "curl https://intranet.local/health".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };

        assert_eq!(detector.evaluate(&event).len(), 1);
    }
}
