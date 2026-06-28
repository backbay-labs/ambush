use crate::detector::{
    DetectionFinding, DetectionStrategy, FilePersistenceEvent, RegistryPersistenceEvent,
    TelemetryEvent, TelemetryPayload,
};
use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::json;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistenceProfile {
    #[serde(default = "default_suspicious_registry_run_paths")]
    pub suspicious_registry_run_paths: Vec<String>,
    #[serde(default = "default_suspicious_cron_directories")]
    pub suspicious_cron_directories: Vec<String>,
    #[serde(default = "default_systemd_timer_directories")]
    pub systemd_timer_directories: Vec<String>,
    #[serde(default = "default_dormancy_window_secs")]
    pub dormancy_window_secs: u64,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
}

impl Default for PersistenceProfile {
    fn default() -> Self {
        Self {
            suspicious_registry_run_paths: default_suspicious_registry_run_paths(),
            suspicious_cron_directories: default_suspicious_cron_directories(),
            systemd_timer_directories: default_systemd_timer_directories(),
            dormancy_window_secs: default_dormancy_window_secs(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PersistenceDetector {
    suspicious_registry_run_paths: Vec<String>,
    suspicious_cron_directories: Vec<String>,
    systemd_timer_directories: Vec<String>,
    dormancy_window_secs: u64,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
}

impl Default for PersistenceDetector {
    fn default() -> Self {
        Self {
            suspicious_registry_run_paths: default_suspicious_registry_run_paths()
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            suspicious_cron_directories: default_suspicious_cron_directories()
                .into_iter()
                .map(|value| normalize_path(&value))
                .collect(),
            systemd_timer_directories: default_systemd_timer_directories()
                .into_iter()
                .map(|value| normalize_path(&value))
                .collect(),
            dormancy_window_secs: default_dormancy_window_secs(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

impl PersistenceDetector {
    pub fn from_profile(profile: PersistenceProfile) -> Result<Self, ProfileValidationError> {
        profile.validate()?;
        Ok(Self {
            suspicious_registry_run_paths: profile
                .suspicious_registry_run_paths
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            suspicious_cron_directories: profile
                .suspicious_cron_directories
                .into_iter()
                .map(|value| normalize_path(&value))
                .collect(),
            systemd_timer_directories: profile
                .systemd_timer_directories
                .into_iter()
                .map(|value| normalize_path(&value))
                .collect(),
            dormancy_window_secs: profile.dormancy_window_secs,
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
        })
    }

    pub fn profile(&self) -> PersistenceProfile {
        PersistenceProfile {
            suspicious_registry_run_paths: self.suspicious_registry_run_paths.clone(),
            suspicious_cron_directories: self.suspicious_cron_directories.clone(),
            systemd_timer_directories: self.systemd_timer_directories.clone(),
            dormancy_window_secs: self.dormancy_window_secs,
            high_confidence_threshold: self.high_confidence_threshold,
            medium_confidence_threshold: self.medium_confidence_threshold,
        }
    }

    fn evaluate_registry(
        &self,
        event: &TelemetryEvent,
        registry: &RegistryPersistenceEvent,
    ) -> Option<DetectionFinding> {
        let registry_path = registry.registry_path.to_ascii_lowercase();
        let access_type = registry.access_type.to_ascii_lowercase();
        let value_data = registry
            .value_data
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let is_write = matches!(
            access_type.as_str(),
            "write" | "set" | "create" | "modify" | "update"
        );
        let matches_run_key = self
            .suspicious_registry_run_paths
            .iter()
            .any(|path| registry_path.starts_with(path));

        if !is_write || !matches_run_key {
            return None;
        }

        let value_points_to_executable = [
            ".exe",
            ".dll",
            ".ps1",
            ".bat",
            ".cmd",
            "powershell",
            "rundll32",
        ]
        .iter()
        .any(|needle| value_data.contains(needle));
        let confidence = if value_points_to_executable {
            self.high_confidence_threshold
        } else {
            self.medium_confidence_threshold
        };
        let severity = if value_points_to_executable {
            Severity::Critical
        } else {
            Severity::High
        };

        Some(DetectionFinding {
            finding_id: format!("{}:{}", self.id(), event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::Persistence,
            severity,
            confidence,
            evidence: json!({
                "mitre_technique_id": "T1547.001",
                "process_name": registry.process_name,
                "registry_path": registry.registry_path,
                "value_name": registry.value_name,
                "value_data": registry.value_data,
                "access_type": registry.access_type,
                "mode": "registry_run_key",
                "dormancy_window_secs": self.dormancy_window_secs,
            }),
            strategy_id: self.id().to_string(),
        })
    }

    fn evaluate_file(
        &self,
        event: &TelemetryEvent,
        file: &FilePersistenceEvent,
    ) -> Option<DetectionFinding> {
        let path = normalize_path(&file.file_path);
        let operation = file.operation.to_ascii_lowercase();
        let content_preview = file
            .content_preview
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let is_write = matches!(
            operation.as_str(),
            "write" | "create" | "modify" | "append" | "drop" | "install"
        );
        if !is_write {
            return None;
        }

        let (mode, mitre_technique_id, confidence, severity) = if is_scheduled_task_path(&path)
            || content_preview.contains("schtasks")
            || content_preview.contains("<task")
        {
            (
                "scheduled_task",
                "T1053.005",
                self.high_confidence_threshold,
                Severity::Critical,
            )
        } else if self
            .suspicious_cron_directories
            .iter()
            .any(|dir| path.starts_with(dir))
        {
            let high_signal = content_preview.contains("* * *")
                || content_preview.contains("@reboot")
                || content_preview.contains("/bin/")
                || content_preview.contains("/usr/bin/");
            (
                "cron",
                "T1053.003",
                if high_signal {
                    self.high_confidence_threshold
                } else {
                    self.medium_confidence_threshold
                },
                if high_signal {
                    Severity::High
                } else {
                    Severity::Medium
                },
            )
        } else if self
            .systemd_timer_directories
            .iter()
            .any(|dir| path.starts_with(dir))
            || path.ends_with(".timer")
            || content_preview.contains("[timer]")
            || content_preview.contains("oncalendar=")
        {
            (
                "systemd_timer",
                "T1053.006",
                self.high_confidence_threshold,
                Severity::High,
            )
        } else {
            return None;
        };

        Some(DetectionFinding {
            finding_id: format!("{}:{}", self.id(), event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::Persistence,
            severity,
            confidence,
            evidence: json!({
                "mitre_technique_id": mitre_technique_id,
                "file_path": file.file_path,
                "operation": file.operation,
                "process_name": file.process_name,
                "content_preview": file.content_preview,
                "mode": mode,
                "dormancy_window_secs": self.dormancy_window_secs,
            }),
            strategy_id: self.id().to_string(),
        })
    }
}

impl PersistenceProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        validate_confidence_thresholds(
            "PersistenceProfile",
            self.high_confidence_threshold,
            self.medium_confidence_threshold,
        )?;
        if self.dormancy_window_secs == 0 {
            return Err(ProfileValidationError {
                profile: "PersistenceProfile",
                field: "dormancy_window_secs",
                reason: "must be greater than zero".to_string(),
            });
        }
        validate_non_empty(
            "PersistenceProfile",
            "suspicious_registry_run_paths",
            &self.suspicious_registry_run_paths,
        )?;
        validate_non_empty(
            "PersistenceProfile",
            "suspicious_cron_directories",
            &self.suspicious_cron_directories,
        )?;
        validate_non_empty(
            "PersistenceProfile",
            "systemd_timer_directories",
            &self.systemd_timer_directories,
        )
    }
}

impl DetectionStrategy for PersistenceDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        "persistence"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match &event.payload {
            TelemetryPayload::RegistryPersistence(registry) => self
                .evaluate_registry(event, registry)
                .into_iter()
                .collect(),
            TelemetryPayload::FilePersistence(file) => {
                self.evaluate_file(event, file).into_iter().collect()
            }
            TelemetryPayload::ProcessStart(_)
            | TelemetryPayload::ProcessMemoryAccess(_)
            | TelemetryPayload::NetworkConnect(_)
            | TelemetryPayload::DnsQuery(_)
            | TelemetryPayload::RegistryAccess(_)
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

fn is_scheduled_task_path(path: &str) -> bool {
    path.contains("/system32/tasks/") || path.ends_with(".job") || path.ends_with(".xml")
}

fn default_suspicious_registry_run_paths() -> Vec<String> {
    [
        "hklm\\software\\microsoft\\windows\\currentversion\\run",
        "hklm\\software\\microsoft\\windows\\currentversion\\runonce",
        "hkcu\\software\\microsoft\\windows\\currentversion\\run",
        "hkcu\\software\\microsoft\\windows\\currentversion\\runonce",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_suspicious_cron_directories() -> Vec<String> {
    ["/etc/cron", "/etc/cron.d", "/var/spool/cron"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_systemd_timer_directories() -> Vec<String> {
    ["/etc/systemd/system", "/usr/lib/systemd/system"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_dormancy_window_secs() -> u64 {
    86_400
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
    use super::{PersistenceDetector, PersistenceProfile};
    use crate::detector::{
        DetectionStrategy, FilePersistenceEvent, RegistryPersistenceEvent, TelemetryEvent,
        TelemetryPayload,
    };
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;

    #[test]
    fn registry_run_key_write_triggers_persistence_finding() {
        let detector = PersistenceDetector::default();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-persist-reg".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::RegistryPersistence(RegistryPersistenceEvent {
                process_name: "reg.exe".to_string(),
                registry_path: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
                    .to_string(),
                value_name: Some("Updater".to_string()),
                value_data: Some("C:\\Users\\alice\\AppData\\evil.exe".to_string()),
                access_type: "write".to_string(),
            }),
        };

        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::Persistence);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(
            findings[0].evidence["mitre_technique_id"].as_str(),
            Some("T1547.001")
        );
    }

    #[test]
    fn cron_write_triggers_persistence_finding() {
        let detector = PersistenceDetector::default();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-persist-cron".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::FilePersistence(FilePersistenceEvent {
                file_path: "/etc/cron.d/backup".to_string(),
                operation: "write".to_string(),
                process_name: "bash".to_string(),
                content_preview: Some("* * * * * root /usr/bin/curl http://bad".to_string()),
            }),
        };

        let findings = detector.evaluate(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::Persistence);
        assert_eq!(
            findings[0].evidence["mitre_technique_id"].as_str(),
            Some("T1053.003")
        );
    }

    #[test]
    fn benign_file_persistence_neighbor_stays_silent() {
        let detector = PersistenceDetector::default();
        let event = TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-benign".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::FilePersistence(FilePersistenceEvent {
                file_path: "/tmp/note.txt".to_string(),
                operation: "write".to_string(),
                process_name: "vim".to_string(),
                content_preview: Some("hello".to_string()),
            }),
        };

        assert!(detector.evaluate(&event).is_empty());
    }

    #[test]
    fn invalid_profile_is_rejected() {
        let error = PersistenceProfile {
            dormancy_window_secs: 0,
            ..PersistenceProfile::default()
        }
        .validate()
        .expect_err("zero dormancy window should fail");
        assert_eq!(error.field, "dormancy_window_secs");
    }
}
