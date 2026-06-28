use crate::detector::{
    AuthenticationEventData, DetectionFinding, DetectionStrategy, RegistryAccessEvent,
    TelemetryEvent, TelemetryPayload,
};
use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::json;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAccessProfile {
    #[serde(default = "default_sensitive_registry_paths")]
    pub sensitive_registry_paths: Vec<String>,
    #[serde(default = "default_protected_processes")]
    pub protected_processes: Vec<String>,
    #[serde(default = "default_suspicious_kerberoast_processes")]
    pub suspicious_kerberoast_processes: Vec<String>,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
}

impl Default for CredentialAccessProfile {
    fn default() -> Self {
        Self {
            sensitive_registry_paths: default_sensitive_registry_paths(),
            protected_processes: default_protected_processes(),
            suspicious_kerberoast_processes: default_suspicious_kerberoast_processes(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CredentialAccessDetector {
    sensitive_registry_paths: Vec<String>,
    protected_processes: Vec<String>,
    suspicious_kerberoast_processes: Vec<String>,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
}

impl Default for CredentialAccessDetector {
    fn default() -> Self {
        Self {
            sensitive_registry_paths: default_sensitive_registry_paths()
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            protected_processes: default_protected_processes()
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            suspicious_kerberoast_processes: default_suspicious_kerberoast_processes()
                .into_iter()
                .map(|value| normalize_process_name(&value))
                .collect(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

impl CredentialAccessDetector {
    pub fn from_profile(profile: CredentialAccessProfile) -> Result<Self, ProfileValidationError> {
        profile.validate()?;
        Ok(Self {
            sensitive_registry_paths: profile
                .sensitive_registry_paths
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            protected_processes: profile
                .protected_processes
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            suspicious_kerberoast_processes: profile
                .suspicious_kerberoast_processes
                .into_iter()
                .map(|value| normalize_process_name(&value))
                .collect(),
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
        })
    }

    pub fn profile(&self) -> CredentialAccessProfile {
        CredentialAccessProfile {
            sensitive_registry_paths: self.sensitive_registry_paths.clone(),
            protected_processes: self.protected_processes.clone(),
            suspicious_kerberoast_processes: self.suspicious_kerberoast_processes.clone(),
            high_confidence_threshold: self.high_confidence_threshold,
            medium_confidence_threshold: self.medium_confidence_threshold,
        }
    }

    fn evaluate_registry(
        &self,
        event: &TelemetryEvent,
        registry: &RegistryAccessEvent,
    ) -> Option<DetectionFinding> {
        let target_process = registry
            .target_process
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let registry_path = registry.registry_path.to_ascii_lowercase();
        let access_type = registry.access_type.to_ascii_lowercase();

        if self.protected_processes.contains(&target_process) {
            return Some(DetectionFinding {
                finding_id: format!("{}:{}", self.id(), event.event_id),
                event_id: event.event_id.clone(),
                threat_class: ThreatClass::CredentialAccess,
                severity: Severity::Critical,
                confidence: self.high_confidence_threshold,
                evidence: json!({
                    "process_name": registry.process_name,
                    "registry_path": registry.registry_path,
                    "access_type": registry.access_type,
                    "target_process": registry.target_process,
                    "mode": "protected_process_access",
                }),
                strategy_id: self.id().to_string(),
            });
        }

        if access_type == "read"
            && self
                .sensitive_registry_paths
                .iter()
                .any(|path| registry_path.starts_with(path))
        {
            return Some(DetectionFinding {
                finding_id: format!("{}:{}", self.id(), event.event_id),
                event_id: event.event_id.clone(),
                threat_class: ThreatClass::CredentialAccess,
                severity: Severity::High,
                confidence: self.medium_confidence_threshold,
                evidence: json!({
                    "process_name": registry.process_name,
                    "registry_path": registry.registry_path,
                    "access_type": registry.access_type,
                    "target_process": registry.target_process,
                    "mode": "sensitive_registry_read",
                }),
                strategy_id: self.id().to_string(),
            });
        }

        None
    }

    fn evaluate_auth(
        &self,
        event: &TelemetryEvent,
        auth: &AuthenticationEventData,
    ) -> Option<DetectionFinding> {
        let auth_type = auth.auth_type.to_ascii_lowercase();
        let process_name = normalize_process_name(auth.process_name.as_deref().unwrap_or_default());
        if auth_type != "kerberos_tgs"
            || !self
                .suspicious_kerberoast_processes
                .iter()
                .any(|candidate| candidate == &process_name)
        {
            return None;
        }

        Some(DetectionFinding {
            finding_id: format!("{}:{}", self.id(), event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::CredentialAccess,
            severity: Severity::High,
            confidence: self.medium_confidence_threshold.max(0.8),
            evidence: json!({
                "auth_type": auth.auth_type,
                "source_host": auth.source_host,
                "target_host": auth.target_host,
                "target_service": auth.target_service,
                "process_name": auth.process_name,
                "normalized_process_name": process_name,
                "success": auth.success,
                "user": auth.user,
            }),
            strategy_id: self.id().to_string(),
        })
    }
}

impl CredentialAccessProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        validate_confidence_thresholds(
            "CredentialAccessProfile",
            self.high_confidence_threshold,
            self.medium_confidence_threshold,
        )
    }
}

fn default_sensitive_registry_paths() -> Vec<String> {
    [
        "hklm\\sam",
        "hklm\\security",
        "hklm\\system\\currentcontrolset\\control\\lsa",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_protected_processes() -> Vec<String> {
    ["lsass.exe", "lsass"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_suspicious_kerberoast_processes() -> Vec<String> {
    [
        "powershell",
        "pwsh",
        "rubeus",
        "mimikatz",
        "kekeo",
        "cmd",
        "python",
        "python3",
        "impacket",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
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

impl DetectionStrategy for CredentialAccessDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        "credential_access"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match &event.payload {
            TelemetryPayload::RegistryAccess(registry) => self
                .evaluate_registry(event, registry)
                .into_iter()
                .collect(),
            TelemetryPayload::AuthenticationEvent(auth) => {
                self.evaluate_auth(event, auth).into_iter().collect()
            }
            TelemetryPayload::ProcessStart(_)
            | TelemetryPayload::ProcessMemoryAccess(_)
            | TelemetryPayload::NetworkConnect(_)
            | TelemetryPayload::DnsQuery(_)
            | TelemetryPayload::InfrastructureHealth(_)
            | TelemetryPayload::ThermalAnomaly(_)
            | TelemetryPayload::ResourceExhaustion(_) => Vec::new(),
            TelemetryPayload::RegistryPersistence(_) | TelemetryPayload::FilePersistence(_) => {
                Vec::new()
            }
        }
    }
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
    use super::{CredentialAccessDetector, CredentialAccessProfile};
    use crate::detector::{
        AuthenticationEventData, DetectionStrategy, RegistryAccessEvent, TelemetryEvent,
        TelemetryPayload,
    };
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;

    fn registry_event(
        registry_path: &str,
        access_type: &str,
        target_process: Option<&str>,
    ) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-cred".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-cred".to_string()),
            payload: TelemetryPayload::RegistryAccess(RegistryAccessEvent {
                process_name: "rundll32.exe".to_string(),
                registry_path: registry_path.to_string(),
                access_type: access_type.to_string(),
                target_process: target_process.map(str::to_string),
            }),
        }
    }

    fn kerberos_event(process_name: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-kerb".to_string(),
            timestamp: 1_700_000_001,
            host_id: Some("host-cred".to_string()),
            payload: TelemetryPayload::AuthenticationEvent(AuthenticationEventData {
                auth_type: "kerberos_tgs".to_string(),
                source_host: Some("ws-22".to_string()),
                target_host: Some("dc-01".to_string()),
                target_service: Some("MSSQLSvc/sql01".to_string()),
                process_name: Some(process_name.to_string()),
                success: true,
                user: Some("alice".to_string()),
            }),
        }
    }

    #[test]
    fn lsass_access_produces_critical_credential_access_finding() {
        let detector = CredentialAccessDetector::default();
        let findings = detector.evaluate(&registry_event("MEMORY", "read", Some("lsass.exe")));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::CredentialAccess);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn sam_registry_read_produces_finding() {
        let detector = CredentialAccessDetector::default();
        let findings = detector.evaluate(&registry_event("HKLM\\SAM\\Domains", "read", None));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn kerberoasting_pattern_produces_finding() {
        let detector = CredentialAccessDetector::default();
        let findings = detector.evaluate(&kerberos_event("powershell"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn mimikatz_kerberoasting_pattern_produces_finding() {
        let detector = CredentialAccessDetector::default();
        let findings = detector.evaluate(&kerberos_event("C:\\Tools\\mimikatz.exe"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn normal_registry_read_does_not_trigger() {
        let detector = CredentialAccessDetector::default();
        let findings =
            detector.evaluate(&registry_event("HKLM\\SOFTWARE\\Microsoft", "read", None));
        assert!(findings.is_empty());
    }

    #[test]
    fn profile_round_trips() {
        let profile = CredentialAccessProfile::default();
        let detector = CredentialAccessDetector::from_profile(profile.clone())
            .expect("profile should be valid");
        assert_eq!(detector.profile(), profile);
    }
}
