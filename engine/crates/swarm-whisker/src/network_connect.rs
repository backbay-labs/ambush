use crate::detector::{
    DetectionFinding, DetectionStrategy, NetworkConnectEvent, TelemetryEvent, TelemetryPayload,
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
pub struct NetworkConnectProfile {
    #[serde(default = "default_suspicious_ports")]
    pub suspicious_ports: Vec<u16>,
    #[serde(default)]
    pub process_port_allowlist: HashMap<String, Vec<u16>>,
    #[serde(default = "default_beacon_min_sample_count")]
    pub beacon_min_sample_count: usize,
    #[serde(default = "default_beacon_window_ms")]
    pub beacon_window_ms: i64,
    #[serde(default = "default_beacon_min_interval_ms")]
    pub beacon_min_interval_ms: i64,
    #[serde(default = "default_beacon_max_jitter_ratio")]
    pub beacon_max_jitter_ratio: f64,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
}

impl Default for NetworkConnectProfile {
    fn default() -> Self {
        Self {
            suspicious_ports: default_suspicious_ports(),
            process_port_allowlist: HashMap::new(),
            beacon_min_sample_count: default_beacon_min_sample_count(),
            beacon_window_ms: default_beacon_window_ms(),
            beacon_min_interval_ms: default_beacon_min_interval_ms(),
            beacon_max_jitter_ratio: default_beacon_max_jitter_ratio(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkConnectDetector {
    suspicious_ports: Vec<u16>,
    process_port_allowlist: HashMap<String, Vec<u16>>,
    beacon_min_sample_count: usize,
    beacon_window_ms: i64,
    beacon_min_interval_ms: i64,
    beacon_max_jitter_ratio: f64,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
    beacon_tracker: Arc<Mutex<HashMap<BeaconKey, VecDeque<i64>>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BeaconKey {
    host_id: String,
    process_name: String,
    destination_ip: String,
    destination_port: u16,
    protocol: String,
}

#[derive(Debug, Clone)]
struct BeaconStats {
    sample_count: usize,
    intervals_ms: Vec<i64>,
    mean_interval_ms: f64,
    jitter_ratio: f64,
}

impl Default for NetworkConnectDetector {
    fn default() -> Self {
        Self {
            suspicious_ports: normalize_ports(default_suspicious_ports()),
            process_port_allowlist: normalize_allowlist(HashMap::new()),
            beacon_min_sample_count: default_beacon_min_sample_count(),
            beacon_window_ms: default_beacon_window_ms(),
            beacon_min_interval_ms: default_beacon_min_interval_ms(),
            beacon_max_jitter_ratio: default_beacon_max_jitter_ratio(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
            beacon_tracker: Arc::default(),
        }
    }
}

impl NetworkConnectDetector {
    pub fn from_profile(profile: NetworkConnectProfile) -> Result<Self, ProfileValidationError> {
        profile.validate()?;

        Ok(Self {
            suspicious_ports: normalize_ports(profile.suspicious_ports),
            process_port_allowlist: normalize_allowlist(profile.process_port_allowlist),
            beacon_min_sample_count: profile.beacon_min_sample_count,
            beacon_window_ms: profile.beacon_window_ms,
            beacon_min_interval_ms: profile.beacon_min_interval_ms,
            beacon_max_jitter_ratio: profile.beacon_max_jitter_ratio,
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
            beacon_tracker: Arc::default(),
        })
    }

    pub fn profile(&self) -> NetworkConnectProfile {
        NetworkConnectProfile {
            suspicious_ports: self.suspicious_ports.clone(),
            process_port_allowlist: self.process_port_allowlist.clone(),
            beacon_min_sample_count: self.beacon_min_sample_count,
            beacon_window_ms: self.beacon_window_ms,
            beacon_min_interval_ms: self.beacon_min_interval_ms,
            beacon_max_jitter_ratio: self.beacon_max_jitter_ratio,
            high_confidence_threshold: self.high_confidence_threshold,
            medium_confidence_threshold: self.medium_confidence_threshold,
        }
    }

    fn evaluate_connect(
        &self,
        event: &TelemetryEvent,
        connect: &NetworkConnectEvent,
    ) -> Option<DetectionFinding> {
        let process_name = normalize_component(&connect.process_name);
        let destination_ip = normalize_component(&connect.destination_ip);
        if process_name.is_empty() || destination_ip.is_empty() {
            return None;
        }

        let protocol = normalize_component(&connect.protocol);
        let host_id = normalized_host_id(event);
        let suspicious_port = self
            .suspicious_ports
            .binary_search(&connect.destination_port)
            .is_ok();
        let allowed_ports = self.process_port_allowlist.get(&process_name);
        let process_port_mismatch =
            allowed_ports.is_some_and(|ports| !ports.contains(&connect.destination_port));
        let beacon_stats = self.evaluate_beaconing(
            BeaconKey {
                host_id: host_id.clone(),
                process_name: process_name.clone(),
                destination_ip: destination_ip.clone(),
                destination_port: connect.destination_port,
                protocol: protocol.clone(),
            },
            normalized_timestamp_ms(event.timestamp),
        );
        let beaconing = beacon_stats.is_some();

        if !suspicious_port && !process_port_mismatch && !beaconing {
            return None;
        }

        let (severity, confidence) = if beaconing {
            (Severity::High, self.high_confidence_threshold)
        } else {
            (Severity::Medium, self.medium_confidence_threshold)
        };

        let mut evidence = json!({
            "process_name": process_name,
            "destination_ip": destination_ip,
            "destination_port": connect.destination_port,
            "protocol": protocol,
            "host_id": host_id,
            "heuristics": {
                "beaconing": beaconing,
                "suspicious_port": suspicious_port,
                "process_port_mismatch": process_port_mismatch,
            }
        });

        if let Some(object) = evidence.as_object_mut() {
            if let Some(stats) = beacon_stats {
                object.insert(
                    "beacon".to_string(),
                    json!({
                        "sample_count": stats.sample_count,
                        "intervals_ms": stats.intervals_ms,
                        "mean_interval_ms": stats.mean_interval_ms,
                        "jitter_ratio": stats.jitter_ratio,
                    }),
                );
            }
            if let Some(allowed_ports) = allowed_ports {
                object.insert(
                    "allowlist".to_string(),
                    json!({
                        "process_has_allowlist": true,
                        "allowed_ports": allowed_ports,
                    }),
                );
            }
        }

        Some(DetectionFinding {
            finding_id: format!("{}:{}", self.id(), event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::CommandAndControl,
            severity,
            confidence,
            evidence,
            strategy_id: self.id().to_string(),
        })
    }

    fn evaluate_beaconing(&self, key: BeaconKey, timestamp_ms: i64) -> Option<BeaconStats> {
        let timestamps = self.record_connection(key, timestamp_ms);
        self.analyze_beaconing(&timestamps)
    }

    fn record_connection(&self, key: BeaconKey, timestamp_ms: i64) -> Vec<i64> {
        let window_start = timestamp_ms.saturating_sub(self.beacon_window_ms);
        let mut guard = self
            .beacon_tracker
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
        entries.iter().copied().collect()
    }

    fn analyze_beaconing(&self, timestamps: &[i64]) -> Option<BeaconStats> {
        if timestamps.len() < self.beacon_min_sample_count {
            return None;
        }

        let mut ordered_timestamps = timestamps.to_vec();
        ordered_timestamps.sort_unstable();
        let intervals_ms = ordered_timestamps
            .windows(2)
            .map(|window| window[1].saturating_sub(window[0]))
            .collect::<Vec<_>>();
        if intervals_ms.is_empty() || intervals_ms.iter().any(|interval| *interval <= 0) {
            return None;
        }

        let mean_interval_ms = intervals_ms.iter().sum::<i64>() as f64 / intervals_ms.len() as f64;
        if mean_interval_ms <= 0.0 || mean_interval_ms < self.beacon_min_interval_ms as f64 {
            return None;
        }

        let variance = intervals_ms
            .iter()
            .map(|interval| {
                let delta = *interval as f64 - mean_interval_ms;
                delta * delta
            })
            .sum::<f64>()
            / intervals_ms.len() as f64;
        let jitter_ratio = variance.sqrt() / mean_interval_ms;
        if jitter_ratio > self.beacon_max_jitter_ratio {
            return None;
        }

        Some(BeaconStats {
            sample_count: ordered_timestamps.len(),
            intervals_ms,
            mean_interval_ms,
            jitter_ratio,
        })
    }
}

impl NetworkConnectProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        if self.beacon_min_sample_count < 3 {
            return Err(ProfileValidationError {
                profile: "NetworkConnectProfile",
                field: "beacon_min_sample_count",
                reason: "must be greater than or equal to 3".to_string(),
            });
        }
        if self.beacon_window_ms <= 0 {
            return Err(ProfileValidationError {
                profile: "NetworkConnectProfile",
                field: "beacon_window_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.beacon_min_interval_ms <= 0 {
            return Err(ProfileValidationError {
                profile: "NetworkConnectProfile",
                field: "beacon_min_interval_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        if !(0.0 < self.beacon_max_jitter_ratio && self.beacon_max_jitter_ratio <= 1.0) {
            return Err(ProfileValidationError {
                profile: "NetworkConnectProfile",
                field: "beacon_max_jitter_ratio",
                reason: "must be greater than 0.0 and less than or equal to 1.0".to_string(),
            });
        }

        let min_required_window = self
            .beacon_min_interval_ms
            .saturating_mul((self.beacon_min_sample_count - 1) as i64);
        if self.beacon_window_ms < min_required_window {
            return Err(ProfileValidationError {
                profile: "NetworkConnectProfile",
                field: "beacon_window_ms",
                reason: format!(
                    "must be at least beacon_min_interval_ms * (beacon_min_sample_count - 1) ({min_required_window})"
                ),
            });
        }
        if self
            .process_port_allowlist
            .keys()
            .any(|process_name| normalize_component(process_name).is_empty())
        {
            return Err(ProfileValidationError {
                profile: "NetworkConnectProfile",
                field: "process_port_allowlist",
                reason: "contains an empty process name".to_string(),
            });
        }

        validate_confidence_thresholds(
            "NetworkConnectProfile",
            self.high_confidence_threshold,
            self.medium_confidence_threshold,
        )
    }
}

impl DetectionStrategy for NetworkConnectDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        "network_connect"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match &event.payload {
            TelemetryPayload::NetworkConnect(connect) => {
                self.evaluate_connect(event, connect).into_iter().collect()
            }
            TelemetryPayload::ProcessStart(_)
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

fn default_suspicious_ports() -> Vec<u16> {
    vec![4444, 5555, 6667, 31337]
}

fn default_beacon_min_sample_count() -> usize {
    4
}

fn default_beacon_window_ms() -> i64 {
    900_000
}

fn default_beacon_min_interval_ms() -> i64 {
    15_000
}

fn default_beacon_max_jitter_ratio() -> f64 {
    0.20
}

fn default_high_confidence_threshold() -> f64 {
    0.9
}

fn default_medium_confidence_threshold() -> f64 {
    0.7
}

fn normalize_ports(mut ports: Vec<u16>) -> Vec<u16> {
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn normalize_allowlist(raw_allowlist: HashMap<String, Vec<u16>>) -> HashMap<String, Vec<u16>> {
    let mut normalized = HashMap::new();
    for (process_name, ports) in raw_allowlist {
        let entry = normalized
            .entry(normalize_component(&process_name))
            .or_insert_with(Vec::new);
        entry.extend(ports);
    }
    for ports in normalized.values_mut() {
        ports.sort_unstable();
        ports.dedup();
    }
    normalized
}

fn normalize_component(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalized_host_id(event: &TelemetryEvent) -> String {
    normalize_component(event.host_id.as_deref().unwrap_or(&event.source))
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
    use super::{
        DetectionStrategy, NetworkConnectDetector, NetworkConnectEvent, NetworkConnectProfile,
        TelemetryEvent, TelemetryPayload,
    };
    use crate::ProcessStartEvent;
    use serde_json::json;
    use std::collections::HashMap;
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;

    fn network_event(
        event_id: &str,
        timestamp: i64,
        process_name: &str,
        destination_ip: &str,
        destination_port: u16,
        protocol: &str,
    ) -> TelemetryEvent {
        TelemetryEvent {
            source: "sensor-1".to_string(),
            event_id: event_id.to_string(),
            timestamp,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::NetworkConnect(NetworkConnectEvent {
                process_name: process_name.to_string(),
                destination_ip: destination_ip.to_string(),
                destination_port,
                protocol: protocol.to_string(),
            }),
        }
    }

    fn process_event() -> TelemetryEvent {
        TelemetryEvent {
            source: "sensor-1".to_string(),
            event_id: "evt-process".to_string(),
            timestamp: 1_700_000_000_000,
            host_id: Some("host-1".to_string()),
            payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                parent_process: "winword".to_string(),
                process_name: "powershell".to_string(),
                command_line: "powershell.exe".to_string(),
                user: Some("alice".to_string()),
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        }
    }

    #[test]
    fn profile_validation_rejects_impossible_beacon_settings() {
        let profile = NetworkConnectProfile {
            beacon_window_ms: 20_000,
            ..NetworkConnectProfile::default()
        };

        let error = profile
            .validate()
            .expect_err("invalid beacon settings should fail validation");
        assert_eq!(error.field, "beacon_window_ms");
    }

    #[test]
    fn non_network_payloads_do_not_produce_findings() {
        let detector = NetworkConnectDetector::default();

        assert!(detector.evaluate(&process_event()).is_empty());
    }

    #[test]
    fn suspicious_port_triggers_medium_confidence_finding() {
        let detector = NetworkConnectDetector::default();

        let findings = detector.evaluate(&network_event(
            "evt-1",
            1_700_000_000_000,
            "curl",
            "198.51.100.10",
            4444,
            "TCP",
        ));

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.threat_class, ThreatClass::CommandAndControl);
        assert_eq!(finding.strategy_id, "network_connect");
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.confidence, 0.7);
        assert_eq!(finding.evidence["process_name"], json!("curl"));
        assert_eq!(finding.evidence["destination_ip"], json!("198.51.100.10"));
        assert_eq!(finding.evidence["protocol"], json!("tcp"));
        assert_eq!(finding.evidence["host_id"], json!("host-1"));
        assert_eq!(finding.evidence["heuristics"]["beaconing"], json!(false));
        assert_eq!(
            finding.evidence["heuristics"]["suspicious_port"],
            json!(true)
        );
        assert_eq!(
            finding.evidence["heuristics"]["process_port_mismatch"],
            json!(false)
        );
    }

    #[test]
    fn process_port_mismatch_triggers_medium_confidence_finding() {
        let profile = NetworkConnectProfile {
            suspicious_ports: Vec::new(),
            process_port_allowlist: HashMap::from([("chrome".to_string(), vec![443, 80])]),
            ..NetworkConnectProfile::default()
        };
        let detector =
            NetworkConnectDetector::from_profile(profile).expect("profile should be valid");

        let findings = detector.evaluate(&network_event(
            "evt-2",
            1_700_000_000_000,
            "Chrome",
            "203.0.113.20",
            8080,
            "TCP",
        ));

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.confidence, 0.7);
        assert_eq!(
            finding.evidence["heuristics"]["suspicious_port"],
            json!(false)
        );
        assert_eq!(
            finding.evidence["heuristics"]["process_port_mismatch"],
            json!(true)
        );
        assert_eq!(
            finding.evidence["allowlist"],
            json!({
                "process_has_allowlist": true,
                "allowed_ports": [80, 443],
            })
        );
    }

    #[test]
    fn allowlisted_process_port_pair_is_ignored() {
        let profile = NetworkConnectProfile {
            suspicious_ports: Vec::new(),
            process_port_allowlist: HashMap::from([("chrome".to_string(), vec![80, 443])]),
            ..NetworkConnectProfile::default()
        };
        let detector =
            NetworkConnectDetector::from_profile(profile).expect("profile should be valid");

        let findings = detector.evaluate(&network_event(
            "evt-3",
            1_700_000_000_000,
            "chrome",
            "203.0.113.20",
            443,
            "TCP",
        ));

        assert!(findings.is_empty());
    }

    #[test]
    fn low_jitter_periodic_connections_trigger_beaconing() {
        let detector = NetworkConnectDetector::default();
        let timestamps = [
            1_700_000_000_000,
            1_700_000_060_000,
            1_700_000_120_500,
            1_700_000_180_700,
        ];

        for (index, timestamp) in timestamps.iter().enumerate().take(3) {
            let findings = detector.evaluate(&network_event(
                &format!("evt-beacon-{index}"),
                *timestamp,
                "updater",
                "203.0.113.10",
                443,
                "TCP",
            ));
            assert!(findings.is_empty());
        }

        let findings = detector.evaluate(&network_event(
            "evt-beacon-3",
            timestamps[3],
            "updater",
            "203.0.113.10",
            443,
            "TCP",
        ));

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, 0.9);
        assert_eq!(finding.evidence["heuristics"]["beaconing"], json!(true));
        assert_eq!(finding.evidence["beacon"]["sample_count"], json!(4));
        assert_eq!(
            finding.evidence["beacon"]["intervals_ms"],
            json!([60_000, 60_500, 60_200])
        );
        assert!(
            finding.evidence["beacon"]["jitter_ratio"]
                .as_f64()
                .expect("jitter ratio should be present")
                <= 0.20
        );
    }

    #[test]
    fn noisy_intervals_do_not_trigger_beaconing() {
        let detector = NetworkConnectDetector::default();
        let timestamps = [
            1_700_000_000_000,
            1_700_000_020_000,
            1_700_000_110_000,
            1_700_000_140_000,
        ];

        for (index, timestamp) in timestamps.iter().enumerate() {
            let findings = detector.evaluate(&network_event(
                &format!("evt-noisy-{index}"),
                *timestamp,
                "updater",
                "203.0.113.50",
                443,
                "TCP",
            ));
            assert!(findings.is_empty());
        }
    }

    #[test]
    fn second_based_timestamps_are_normalized_for_beaconing() {
        let detector = NetworkConnectDetector::default();
        let timestamps = [1_700_000_000, 1_700_000_060, 1_700_000_120, 1_700_000_180];

        for (index, timestamp) in timestamps.iter().enumerate().take(3) {
            let findings = detector.evaluate(&network_event(
                &format!("evt-seconds-{index}"),
                *timestamp,
                "agent",
                "198.51.100.77",
                443,
                "TCP",
            ));
            assert!(findings.is_empty());
        }

        let findings = detector.evaluate(&network_event(
            "evt-seconds-3",
            timestamps[3],
            "agent",
            "198.51.100.77",
            443,
            "TCP",
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence["heuristics"]["beaconing"], json!(true));
    }

    #[test]
    fn multiple_port_heuristics_emit_single_finding() {
        let profile = NetworkConnectProfile {
            suspicious_ports: vec![4444, 4444],
            process_port_allowlist: HashMap::from([("chrome".to_string(), vec![80, 443])]),
            ..NetworkConnectProfile::default()
        };
        let detector =
            NetworkConnectDetector::from_profile(profile).expect("profile should be valid");

        let findings = detector.evaluate(&network_event(
            "evt-4",
            1_700_000_000_000,
            "chrome",
            "192.0.2.55",
            4444,
            "tcp",
        ));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(
            findings[0].evidence["heuristics"]["suspicious_port"],
            json!(true)
        );
        assert_eq!(
            findings[0].evidence["heuristics"]["process_port_mismatch"],
            json!(true)
        );
    }
}
