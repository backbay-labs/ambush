use crate::detector::{
    DetectionFinding, DetectionStrategy, ProcessMemoryAccessEvent, ProcessStartEvent,
    TelemetryEvent, TelemetryPayload,
};
use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::json;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilelessExecutionProfile {
    #[serde(default = "default_reflective_allocation_types")]
    pub reflective_allocation_types: Vec<String>,
    #[serde(default = "default_executable_protection_flags")]
    pub executable_protection_flags: Vec<String>,
    #[serde(default = "default_reflective_call_stack_indicators")]
    pub reflective_call_stack_indicators: Vec<String>,
    #[serde(default = "default_encoded_command_indicators")]
    pub encoded_command_indicators: Vec<String>,
    #[serde(default = "default_deobfuscation_indicators")]
    pub deobfuscation_indicators: Vec<String>,
    #[serde(default = "default_syscall_gadget_indicators")]
    pub syscall_gadget_indicators: Vec<String>,
    #[serde(default = "default_privileged_target_processes")]
    pub privileged_target_processes: Vec<String>,
    #[serde(default = "default_min_region_size_bytes")]
    pub min_region_size_bytes: u64,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
}

impl Default for FilelessExecutionProfile {
    fn default() -> Self {
        Self {
            reflective_allocation_types: default_reflective_allocation_types(),
            executable_protection_flags: default_executable_protection_flags(),
            reflective_call_stack_indicators: default_reflective_call_stack_indicators(),
            encoded_command_indicators: default_encoded_command_indicators(),
            deobfuscation_indicators: default_deobfuscation_indicators(),
            syscall_gadget_indicators: default_syscall_gadget_indicators(),
            privileged_target_processes: default_privileged_target_processes(),
            min_region_size_bytes: default_min_region_size_bytes(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilelessExecutionDetector {
    reflective_allocation_types: Vec<String>,
    executable_protection_flags: Vec<String>,
    reflective_call_stack_indicators: Vec<String>,
    encoded_command_indicators: Vec<String>,
    deobfuscation_indicators: Vec<String>,
    syscall_gadget_indicators: Vec<String>,
    privileged_target_processes: Vec<String>,
    min_region_size_bytes: u64,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
}

impl Default for FilelessExecutionDetector {
    fn default() -> Self {
        let profile = FilelessExecutionProfile::default();
        debug_assert!(profile.validate().is_ok());
        Self {
            reflective_allocation_types: normalize_entries(profile.reflective_allocation_types),
            executable_protection_flags: normalize_entries(profile.executable_protection_flags),
            reflective_call_stack_indicators: normalize_entries(
                profile.reflective_call_stack_indicators,
            ),
            encoded_command_indicators: normalize_entries(profile.encoded_command_indicators),
            deobfuscation_indicators: normalize_entries(profile.deobfuscation_indicators),
            syscall_gadget_indicators: normalize_entries(profile.syscall_gadget_indicators),
            privileged_target_processes: normalize_entries(profile.privileged_target_processes),
            min_region_size_bytes: profile.min_region_size_bytes,
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
        }
    }
}

impl FilelessExecutionDetector {
    pub fn from_profile(profile: FilelessExecutionProfile) -> Result<Self, ProfileValidationError> {
        profile.validate()?;
        Ok(Self {
            reflective_allocation_types: normalize_entries(profile.reflective_allocation_types),
            executable_protection_flags: normalize_entries(profile.executable_protection_flags),
            reflective_call_stack_indicators: normalize_entries(
                profile.reflective_call_stack_indicators,
            ),
            encoded_command_indicators: normalize_entries(profile.encoded_command_indicators),
            deobfuscation_indicators: normalize_entries(profile.deobfuscation_indicators),
            syscall_gadget_indicators: normalize_entries(profile.syscall_gadget_indicators),
            privileged_target_processes: normalize_entries(profile.privileged_target_processes),
            min_region_size_bytes: profile.min_region_size_bytes,
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
        })
    }

    pub fn profile(&self) -> FilelessExecutionProfile {
        FilelessExecutionProfile {
            reflective_allocation_types: self.reflective_allocation_types.clone(),
            executable_protection_flags: self.executable_protection_flags.clone(),
            reflective_call_stack_indicators: self.reflective_call_stack_indicators.clone(),
            encoded_command_indicators: self.encoded_command_indicators.clone(),
            deobfuscation_indicators: self.deobfuscation_indicators.clone(),
            syscall_gadget_indicators: self.syscall_gadget_indicators.clone(),
            privileged_target_processes: self.privileged_target_processes.clone(),
            min_region_size_bytes: self.min_region_size_bytes,
            high_confidence_threshold: self.high_confidence_threshold,
            medium_confidence_threshold: self.medium_confidence_threshold,
        }
    }

    fn evaluate_process_start(
        &self,
        event: &TelemetryEvent,
        process: &ProcessStartEvent,
    ) -> Option<DetectionFinding> {
        let process_name = process.process_name.to_ascii_lowercase();
        if !process_name.contains("powershell") && !process_name.contains("pwsh") {
            return None;
        }

        let command_line = process.command_line.to_ascii_lowercase();
        let matched_encoded =
            matched_indicators(&command_line, &self.encoded_command_indicators, false);
        let matched_deobfuscation =
            matched_indicators(&command_line, &self.deobfuscation_indicators, false);

        if matched_encoded.is_empty() || matched_deobfuscation.is_empty() {
            return None;
        }

        let multi_stage_hint_count = matched_deobfuscation.len() + matched_encoded.len();
        let severity = if matched_deobfuscation.len() >= 2 || matched_encoded.len() >= 2 {
            Severity::Critical
        } else {
            Severity::High
        };
        let confidence = if matched_deobfuscation.len() >= 2 || matched_encoded.len() >= 2 {
            self.high_confidence_threshold
        } else {
            self.medium_confidence_threshold.max(0.8)
        };

        Some(DetectionFinding {
            finding_id: format!("{}:{}", self.id(), event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::DefenseEvasion,
            severity,
            confidence,
            evidence: json!({
                "source": event.source,
                "host_id": event.host_id,
                "parent_process": process.parent_process,
                "process_name": process.process_name,
                "command_line": process.command_line,
                "user": process.user,
                "heuristics": {
                    "techniques": ["encoded_powershell"],
                    "matched_encoded_indicators": matched_encoded,
                    "matched_deobfuscation_indicators": matched_deobfuscation,
                    "multi_stage_hint_count": multi_stage_hint_count,
                }
            }),
            strategy_id: self.id().to_string(),
        })
    }

    fn evaluate_memory_access(
        &self,
        event: &TelemetryEvent,
        access: &ProcessMemoryAccessEvent,
    ) -> Option<DetectionFinding> {
        if access.region_size < self.min_region_size_bytes {
            return None;
        }

        let source_process = access.source_process.to_ascii_lowercase();
        let target_process = access.target_process.to_ascii_lowercase();
        let allocation_type = access.allocation_type.to_ascii_lowercase();
        let call_stack = access
            .call_stack_hint
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let protection_flags = normalize_entries(access.protection_flags.clone());

        let executable_flags =
            matched_indicators_in_list(&protection_flags, &self.executable_protection_flags);
        let reflective_markers =
            matched_indicators(&call_stack, &self.reflective_call_stack_indicators, true);
        let syscall_markers =
            matched_indicators(&call_stack, &self.syscall_gadget_indicators, true);
        let reflective_allocation =
            contains_any_substring(&allocation_type, &self.reflective_allocation_types);
        let remote_target = !source_process.is_empty()
            && !target_process.is_empty()
            && source_process != target_process;
        let privileged_target =
            contains_any_substring(&target_process, &self.privileged_target_processes);

        let reflective_injection =
            remote_target && reflective_allocation && !executable_flags.is_empty();
        let syscall_gadget = !syscall_markers.is_empty();

        if !reflective_injection && !syscall_gadget {
            return None;
        }

        let threat_class = if privileged_target {
            ThreatClass::PrivilegeEscalation
        } else {
            ThreatClass::DefenseEvasion
        };
        let severity = if privileged_target || syscall_gadget {
            Severity::Critical
        } else {
            Severity::High
        };
        let confidence = if privileged_target || syscall_gadget || !reflective_markers.is_empty() {
            self.high_confidence_threshold
        } else {
            self.medium_confidence_threshold.max(0.75)
        };

        let mut techniques = Vec::new();
        if reflective_injection {
            techniques.push("reflective_dll_injection");
        }
        if syscall_gadget {
            techniques.push("raw_syscall_gadget");
        }

        Some(DetectionFinding {
            finding_id: format!("{}:{}", self.id(), event.event_id),
            event_id: event.event_id.clone(),
            threat_class,
            severity,
            confidence,
            evidence: json!({
                "source": event.source,
                "host_id": event.host_id,
                "source_process": access.source_process,
                "target_process": access.target_process,
                "allocation_type": access.allocation_type,
                "protection_flags": access.protection_flags,
                "region_size": access.region_size,
                "call_stack_hint": access.call_stack_hint,
                "heuristics": {
                    "techniques": techniques,
                    "remote_target": remote_target,
                    "privileged_target": privileged_target,
                    "matched_executable_protection_flags": executable_flags,
                    "matched_reflective_call_stack_indicators": reflective_markers,
                    "matched_syscall_gadget_indicators": syscall_markers,
                }
            }),
            strategy_id: self.id().to_string(),
        })
    }
}

impl FilelessExecutionProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        validate_confidence_thresholds(
            "FilelessExecutionProfile",
            self.high_confidence_threshold,
            self.medium_confidence_threshold,
        )?;
        if self.min_region_size_bytes == 0 {
            return Err(ProfileValidationError {
                profile: "FilelessExecutionProfile",
                field: "min_region_size_bytes",
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

impl DetectionStrategy for FilelessExecutionDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        "fileless_execution"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match &event.payload {
            TelemetryPayload::ProcessStart(process) => self
                .evaluate_process_start(event, process)
                .into_iter()
                .collect(),
            TelemetryPayload::ProcessMemoryAccess(access) => self
                .evaluate_memory_access(event, access)
                .into_iter()
                .collect(),
            TelemetryPayload::NetworkConnect(_)
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

fn normalize_entries(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn contains_any_substring(haystack: &str, needles: &[String]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn matched_indicators(haystack: &str, indicators: &[String], allow_empty: bool) -> Vec<String> {
    if haystack.is_empty() && !allow_empty {
        return Vec::new();
    }
    indicators
        .iter()
        .filter(|indicator| haystack.contains(indicator.as_str()))
        .cloned()
        .collect()
}

fn matched_indicators_in_list(values: &[String], indicators: &[String]) -> Vec<String> {
    indicators
        .iter()
        .filter(|indicator| {
            values
                .iter()
                .any(|value| value.contains(indicator.as_str()) || indicator.contains(value))
        })
        .cloned()
        .collect()
}

fn default_reflective_allocation_types() -> Vec<String> {
    ["private", "mem_private", "section", "mem_commit"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_executable_protection_flags() -> Vec<String> {
    [
        "execute",
        "execute_readwrite",
        "page_execute_readwrite",
        "page_execute_writecopy",
        "rwx",
        "wx",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_reflective_call_stack_indicators() -> Vec<String> {
    [
        "reflective",
        "manualmap",
        "manual_map",
        "ldrloaddll",
        "loadlibrary",
        "mapviewofsection",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_encoded_command_indicators() -> Vec<String> {
    [
        " -enc",
        " -encodedcommand",
        "frombase64string",
        "base64",
        "text.encoding",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_deobfuscation_indicators() -> Vec<String> {
    [
        "iex",
        "invoke-expression",
        "join",
        "[char]",
        "replace(",
        "-bxor",
        "gzipstream",
        "memorystream",
        "scriptblock",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_syscall_gadget_indicators() -> Vec<String> {
    [
        "syscall",
        "hellsgate",
        "halosgate",
        "syswhispers",
        "ntwritevirtualmemory",
        "ntprotectvirtualmemory",
        "ntallocatevirtualmemory",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_privileged_target_processes() -> Vec<String> {
    [
        "lsass", "winlogon", "wininit", "services", "csrss", "lsm", "smss", "samss",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_min_region_size_bytes() -> u64 {
    4096
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
    use super::{FilelessExecutionDetector, FilelessExecutionProfile};
    use crate::detector::{
        DetectionStrategy, ProcessMemoryAccessEvent, ProcessStartEvent, TelemetryEvent,
        TelemetryPayload,
    };
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;

    fn powershell_event(command_line: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-fileless-ps".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-a".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword.exe".to_string(),
                process_name: "powershell.exe".to_string(),
                command_line: command_line.to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    fn memory_event(
        target_process: &str,
        protection_flags: Vec<&str>,
        call_stack_hint: Option<&str>,
    ) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-fileless-mem".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-a".to_string()),
            payload: TelemetryPayload::ProcessMemoryAccess(ProcessMemoryAccessEvent {
                source_process: "powershell.exe".to_string(),
                target_process: target_process.to_string(),
                allocation_type: "private".to_string(),
                protection_flags: protection_flags.into_iter().map(str::to_string).collect(),
                region_size: 16384,
                call_stack_hint: call_stack_hint.map(str::to_string),
            }),
        }
    }

    #[test]
    fn fileless_encoded_powershell_with_deobfuscation_hints_produces_defense_evasion_finding() {
        let detector = FilelessExecutionDetector::default();
        let findings = detector.evaluate(&powershell_event(
            "powershell.exe -enc AAAA; IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('BBBB')))",
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::DefenseEvasion);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn fileless_remote_rwx_memory_access_produces_defense_evasion_finding() {
        let detector = FilelessExecutionDetector::default();
        let findings = detector.evaluate(&memory_event(
            "explorer.exe",
            vec!["PAGE_EXECUTE_READWRITE"],
            Some("ReflectiveLoader -> LdrLoadDll"),
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::DefenseEvasion);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn fileless_privileged_target_memory_access_maps_to_privilege_escalation() {
        let detector = FilelessExecutionDetector::default();
        let findings = detector.evaluate(&memory_event(
            "lsass.exe",
            vec!["PAGE_EXECUTE_READWRITE"],
            Some("NtWriteVirtualMemory -> HellsGate"),
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::PrivilegeEscalation);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn fileless_syscall_gadget_hint_produces_detection() {
        let detector = FilelessExecutionDetector::default();
        let findings = detector.evaluate(&memory_event(
            "svchost.exe",
            vec!["PAGE_READWRITE"],
            Some("syswhispers stub -> syscall"),
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn fileless_benign_memory_access_does_not_trigger() {
        let detector = FilelessExecutionDetector::default();
        let findings = detector.evaluate(&TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: "evt-fileless-benign".to_string(),
            timestamp: 1_700_000_000,
            host_id: Some("host-a".to_string()),
            payload: TelemetryPayload::ProcessMemoryAccess(ProcessMemoryAccessEvent {
                source_process: "runtimebroker.exe".to_string(),
                target_process: "runtimebroker.exe".to_string(),
                allocation_type: "private".to_string(),
                protection_flags: vec!["PAGE_READWRITE".to_string()],
                region_size: 2048,
                call_stack_hint: Some("benign_allocator".to_string()),
            }),
        });

        assert!(findings.is_empty());
    }

    #[test]
    fn fileless_profile_round_trips() {
        let profile = FilelessExecutionProfile::default();
        let detector =
            FilelessExecutionDetector::from_profile(profile.clone()).expect("profile is valid");
        assert_eq!(detector.profile(), profile);
    }
}
