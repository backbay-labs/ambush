use crate::detector::{
    AuthenticationEventData, DetectionFinding, DetectionStrategy, ProcessStartEvent,
    TelemetryEvent, TelemetryPayload,
};
use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LateralMovementProfile {
    #[serde(default = "default_remote_exec_indicators")]
    pub remote_exec_indicators: Vec<String>,
    #[serde(default)]
    pub allowed_ssh_sources: Vec<String>,
    #[serde(default = "default_rdp_failure_threshold")]
    pub rdp_failure_threshold: usize,
    #[serde(default = "default_auth_window_ms")]
    pub auth_window_ms: i64,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
}

impl Default for LateralMovementProfile {
    fn default() -> Self {
        Self {
            remote_exec_indicators: default_remote_exec_indicators(),
            allowed_ssh_sources: Vec::new(),
            rdp_failure_threshold: default_rdp_failure_threshold(),
            auth_window_ms: default_auth_window_ms(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LateralMovementDetector {
    remote_exec_indicators: Vec<String>,
    allowed_ssh_sources: Vec<String>,
    rdp_failure_threshold: usize,
    auth_window_ms: i64,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
    failed_rdp_tracker: Arc<Mutex<HashMap<String, VecDeque<i64>>>>,
}

impl Default for LateralMovementDetector {
    fn default() -> Self {
        Self {
            remote_exec_indicators: default_remote_exec_indicators()
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            allowed_ssh_sources: Vec::new(),
            rdp_failure_threshold: default_rdp_failure_threshold(),
            auth_window_ms: default_auth_window_ms(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
            failed_rdp_tracker: Arc::default(),
        }
    }
}

impl LateralMovementDetector {
    pub fn from_profile(profile: LateralMovementProfile) -> Result<Self, ProfileValidationError> {
        profile.validate()?;
        Ok(Self {
            remote_exec_indicators: profile
                .remote_exec_indicators
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            allowed_ssh_sources: profile
                .allowed_ssh_sources
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            rdp_failure_threshold: profile.rdp_failure_threshold,
            auth_window_ms: profile.auth_window_ms,
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
            failed_rdp_tracker: Arc::default(),
        })
    }

    pub fn profile(&self) -> LateralMovementProfile {
        LateralMovementProfile {
            remote_exec_indicators: self.remote_exec_indicators.clone(),
            allowed_ssh_sources: self.allowed_ssh_sources.clone(),
            rdp_failure_threshold: self.rdp_failure_threshold,
            auth_window_ms: self.auth_window_ms,
            high_confidence_threshold: self.high_confidence_threshold,
            medium_confidence_threshold: self.medium_confidence_threshold,
        }
    }

    fn evaluate_process(
        &self,
        event: &TelemetryEvent,
        process: &ProcessStartEvent,
    ) -> Option<DetectionFinding> {
        let process_name = process.process_name.to_ascii_lowercase();
        let command_line = process.command_line.to_ascii_lowercase();
        let matched_indicator = self
            .remote_exec_indicators
            .iter()
            .find(|indicator| {
                process_name.contains(indicator.as_str())
                    || command_line.contains(indicator.as_str())
            })
            .cloned()?;

        let is_remote_exec = match matched_indicator.as_str() {
            "wmic" => {
                command_line.contains("/node:") && command_line.contains("process call create")
            }
            "psexec" | "winrs" | "smbexec" => true,
            "invoke-command" => {
                command_line.contains("-computername") || command_line.contains("-session")
            }
            "new-pssession" | "enter-pssession" => {
                command_line.contains("-computername") || command_line.contains("-connectionuri")
            }
            "invoke-cimmethod" => {
                command_line.contains("-computername") || command_line.contains("-cimsession")
            }
            _ => false,
        };
        if !is_remote_exec {
            return None;
        }

        Some(DetectionFinding {
            finding_id: format!("{}:{}", self.id(), event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::LateralMovement,
            severity: Severity::High,
            confidence: self.high_confidence_threshold,
            evidence: json!({
                "process_name": process.process_name,
                "command_line": process.command_line,
                "matched_indicator": matched_indicator,
                "host_id": event.host_id,
            }),
            strategy_id: self.id().to_string(),
        })
    }

    fn evaluate_auth(
        &self,
        event: &TelemetryEvent,
        auth: &AuthenticationEventData,
    ) -> Option<DetectionFinding> {
        let auth_type = auth.auth_type.to_ascii_lowercase();
        let source_host = auth
            .source_host
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let target_host = auth
            .target_host
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();

        let is_unusual_ssh = auth_type == "ssh"
            && !source_host.is_empty()
            && !target_host.is_empty()
            && source_host != target_host
            && !self.allowed_ssh_sources.contains(&source_host);
        let failed_rdp_attempts = if auth_type == "rdp" && !auth.success {
            self.record_failed_rdp(
                &source_host,
                &target_host,
                normalized_timestamp_ms(event.timestamp),
            )
        } else {
            0
        };
        let is_failed_rdp = failed_rdp_attempts >= self.rdp_failure_threshold;

        if !is_unusual_ssh && !is_failed_rdp {
            return None;
        }

        Some(DetectionFinding {
            finding_id: format!("{}:{}", self.id(), event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::LateralMovement,
            severity: if is_unusual_ssh {
                Severity::High
            } else {
                Severity::Medium
            },
            confidence: if is_unusual_ssh {
                self.medium_confidence_threshold.max(0.8)
            } else {
                self.medium_confidence_threshold
            },
            evidence: json!({
                "auth_type": auth.auth_type,
                "source_host": auth.source_host,
                "target_host": auth.target_host,
                "target_service": auth.target_service,
                "process_name": auth.process_name,
                "success": auth.success,
                "user": auth.user,
                "rdp_failures_in_window": failed_rdp_attempts,
                "rdp_failure_threshold": self.rdp_failure_threshold,
                "auth_window_ms": self.auth_window_ms,
            }),
            strategy_id: self.id().to_string(),
        })
    }

    fn record_failed_rdp(&self, source_host: &str, target_host: &str, timestamp_ms: i64) -> usize {
        let key = format!("{source_host}->{target_host}");
        let window_start = timestamp_ms.saturating_sub(self.auth_window_ms);
        let mut guard = self
            .failed_rdp_tracker
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let entries = guard.entry(key).or_default();
        while entries
            .front()
            .is_some_and(|recorded_at| *recorded_at < window_start)
        {
            entries.pop_front();
        }
        entries.push_back(timestamp_ms);
        entries.len()
    }
}

impl LateralMovementProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        if self.rdp_failure_threshold == 0 {
            return Err(ProfileValidationError {
                profile: "LateralMovementProfile",
                field: "rdp_failure_threshold",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.auth_window_ms <= 0 {
            return Err(ProfileValidationError {
                profile: "LateralMovementProfile",
                field: "auth_window_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        validate_confidence_thresholds(
            "LateralMovementProfile",
            self.high_confidence_threshold,
            self.medium_confidence_threshold,
        )
    }
}

impl DetectionStrategy for LateralMovementDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        "lateral_movement"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match &event.payload {
            TelemetryPayload::ProcessStart(process) => {
                self.evaluate_process(event, process).into_iter().collect()
            }
            TelemetryPayload::AuthenticationEvent(auth) => {
                self.evaluate_auth(event, auth).into_iter().collect()
            }
            TelemetryPayload::NetworkConnect(_)
            | TelemetryPayload::ProcessMemoryAccess(_)
            | TelemetryPayload::DnsQuery(_)
            | TelemetryPayload::RegistryAccess(_)
            | TelemetryPayload::RegistryPersistence(_)
            | TelemetryPayload::FilePersistence(_)
            | TelemetryPayload::InfrastructureHealth(_)
            | TelemetryPayload::ThermalAnomaly(_)
            | TelemetryPayload::ResourceExhaustion(_) => Vec::new(),
        }
    }
}

fn default_remote_exec_indicators() -> Vec<String> {
    [
        "wmic",
        "psexec",
        "winrs",
        "smbexec",
        "invoke-command",
        "new-pssession",
        "enter-pssession",
        "invoke-cimmethod",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_rdp_failure_threshold() -> usize {
    3
}

fn default_auth_window_ms() -> i64 {
    300_000
}

fn default_high_confidence_threshold() -> f64 {
    0.9
}

fn default_medium_confidence_threshold() -> f64 {
    0.7
}

fn normalized_timestamp_ms(timestamp: i64) -> i64 {
    if timestamp.abs() < 100_000_000_000 {
        timestamp.saturating_mul(1_000)
    } else {
        timestamp
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{LateralMovementDetector, LateralMovementProfile};
    use crate::detector::{
        AuthenticationEventData, DetectionStrategy, ProcessStartEvent, TelemetryEvent,
        TelemetryPayload,
    };
    use swarm_core::pheromone::ThreatClass;

    fn process_event(process_name: &str, command_line: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-lm".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-lm".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "cmd".to_string(),
                process_name: process_name.to_string(),
                command_line: command_line.to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    fn auth_event(
        auth_type: &str,
        source_host: &str,
        target_host: &str,
        success: bool,
    ) -> TelemetryEvent {
        auth_event_at(auth_type, source_host, target_host, success, 1_700_000_001)
    }

    fn auth_event_at(
        auth_type: &str,
        source_host: &str,
        target_host: &str,
        success: bool,
        timestamp: i64,
    ) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-auth".to_string(),
            timestamp,
            host_id: Some(target_host.to_string()),
            payload: TelemetryPayload::AuthenticationEvent(AuthenticationEventData {
                auth_type: auth_type.to_string(),
                source_host: Some(source_host.to_string()),
                target_host: Some(target_host.to_string()),
                target_service: Some("cifs/server".to_string()),
                process_name: Some("ssh".to_string()),
                success,
                user: Some("alice".to_string()),
            }),
        }
    }

    #[test]
    fn wmi_remote_execution_produces_lateral_movement_finding() {
        let detector = LateralMovementDetector::default();
        let findings = detector.evaluate(&process_event(
            "wmic",
            "wmic /node:target process call create cmd.exe /c whoami",
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::LateralMovement);
    }

    #[test]
    fn psexec_execution_produces_lateral_movement_finding() {
        let detector = LateralMovementDetector::default();
        let findings =
            detector.evaluate(&process_event("psexec", "psexec \\\\target cmd.exe /c dir"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn powershell_remoting_invoke_command_produces_finding() {
        let detector = LateralMovementDetector::default();
        let findings = detector.evaluate(&process_event(
            "powershell",
            "powershell.exe Invoke-Command -ComputerName srv-01 -ScriptBlock { whoami }",
        ));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn cim_remoting_produces_finding() {
        let detector = LateralMovementDetector::default();
        let findings = detector.evaluate(&process_event(
            "powershell",
            "powershell.exe Invoke-CimMethod -ComputerName srv-02 -ClassName Win32_Process",
        ));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn unusual_ssh_source_produces_finding() {
        let detector = LateralMovementDetector::default();
        let findings = detector.evaluate(&auth_event("ssh", "workstation-42", "db-01", true));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allowed_ssh_source_does_not_trigger() {
        let detector = LateralMovementDetector::from_profile(LateralMovementProfile {
            allowed_ssh_sources: vec!["jump-box".to_string()],
            ..LateralMovementProfile::default()
        })
        .expect("profile should be valid");
        let findings = detector.evaluate(&auth_event("ssh", "jump-box", "db-01", true));
        assert!(findings.is_empty());
    }

    #[test]
    fn normal_local_process_execution_does_not_trigger() {
        let detector = LateralMovementDetector::default();
        let findings = detector.evaluate(&process_event("notepad", "notepad.exe"));
        assert!(findings.is_empty());
    }

    #[test]
    fn repeated_failed_rdp_attempts_produce_finding_after_threshold() {
        let detector = LateralMovementDetector::default();
        assert!(
            detector
                .evaluate(&auth_event_at(
                    "rdp",
                    "workstation-42",
                    "db-01",
                    false,
                    1_700_000_000_000,
                ))
                .is_empty()
        );
        assert!(
            detector
                .evaluate(&auth_event_at(
                    "rdp",
                    "workstation-42",
                    "db-01",
                    false,
                    1_700_000_001_000,
                ))
                .is_empty()
        );

        let findings = detector.evaluate(&auth_event_at(
            "rdp",
            "workstation-42",
            "db-01",
            false,
            1_700_000_002_000,
        ));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::LateralMovement);
    }
}
