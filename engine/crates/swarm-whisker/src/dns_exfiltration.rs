use crate::detector::{
    DetectionFinding, DetectionStrategy, DnsQueryEvent, TelemetryEvent, TelemetryPayload,
};
use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsExfiltrationProfile {
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
    #[serde(default = "default_min_subdomain_length")]
    pub min_subdomain_length: usize,
    #[serde(default)]
    pub allowlisted_domains: Vec<String>,
    #[serde(default = "default_suspicious_query_types")]
    pub suspicious_query_types: Vec<String>,
    #[serde(default = "default_known_tunneling_patterns")]
    pub known_tunneling_patterns: Vec<String>,
    #[serde(default = "default_query_burst_threshold")]
    pub query_burst_threshold: usize,
    #[serde(default = "default_burst_window_ms")]
    pub burst_window_ms: i64,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
}

impl Default for DnsExfiltrationProfile {
    fn default() -> Self {
        Self {
            entropy_threshold: default_entropy_threshold(),
            min_subdomain_length: default_min_subdomain_length(),
            allowlisted_domains: Vec::new(),
            suspicious_query_types: default_suspicious_query_types(),
            known_tunneling_patterns: default_known_tunneling_patterns(),
            query_burst_threshold: default_query_burst_threshold(),
            burst_window_ms: default_burst_window_ms(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsExfiltrationDetector {
    entropy_threshold: f64,
    min_subdomain_length: usize,
    allowlisted_domains: Vec<String>,
    suspicious_query_types: Vec<String>,
    known_tunneling_patterns: Vec<String>,
    query_burst_threshold: usize,
    burst_window_ms: i64,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
    query_tracker: Arc<Mutex<HashMap<String, VecDeque<i64>>>>,
}

impl Default for DnsExfiltrationDetector {
    fn default() -> Self {
        Self {
            entropy_threshold: default_entropy_threshold(),
            min_subdomain_length: default_min_subdomain_length(),
            allowlisted_domains: Vec::new(),
            suspicious_query_types: default_suspicious_query_types()
                .into_iter()
                .map(|value| value.to_ascii_uppercase())
                .collect(),
            known_tunneling_patterns: default_known_tunneling_patterns()
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            query_burst_threshold: default_query_burst_threshold(),
            burst_window_ms: default_burst_window_ms(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
            query_tracker: Arc::default(),
        }
    }
}

impl DnsExfiltrationDetector {
    pub fn from_profile(profile: DnsExfiltrationProfile) -> Result<Self, ProfileValidationError> {
        profile.validate()?;
        Ok(Self {
            entropy_threshold: profile.entropy_threshold,
            min_subdomain_length: profile.min_subdomain_length,
            allowlisted_domains: profile
                .allowlisted_domains
                .into_iter()
                .map(|value| value.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .collect(),
            suspicious_query_types: profile
                .suspicious_query_types
                .into_iter()
                .map(|value| value.to_ascii_uppercase())
                .collect(),
            known_tunneling_patterns: profile
                .known_tunneling_patterns
                .into_iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
            query_burst_threshold: profile.query_burst_threshold,
            burst_window_ms: profile.burst_window_ms,
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
            query_tracker: Arc::default(),
        })
    }

    pub fn profile(&self) -> DnsExfiltrationProfile {
        DnsExfiltrationProfile {
            entropy_threshold: self.entropy_threshold,
            min_subdomain_length: self.min_subdomain_length,
            allowlisted_domains: self.allowlisted_domains.clone(),
            suspicious_query_types: self.suspicious_query_types.clone(),
            known_tunneling_patterns: self.known_tunneling_patterns.clone(),
            query_burst_threshold: self.query_burst_threshold,
            burst_window_ms: self.burst_window_ms,
            high_confidence_threshold: self.high_confidence_threshold,
            medium_confidence_threshold: self.medium_confidence_threshold,
        }
    }

    fn evaluate_dns(
        &self,
        event: &TelemetryEvent,
        dns: &DnsQueryEvent,
    ) -> Option<DetectionFinding> {
        let query_name = dns
            .query_name
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if query_name.is_empty() {
            return None;
        }
        if self.domain_is_allowlisted(&query_name) {
            return None;
        }

        let subdomain = extract_subdomain(&query_name);
        let entropy = shannon_entropy(&subdomain);
        let matched_pattern = self
            .known_tunneling_patterns
            .iter()
            .find(|pattern| query_name.contains(pattern.as_str()))
            .cloned();
        let suspicious_query_type = self
            .suspicious_query_types
            .contains(&dns.query_type.to_ascii_uppercase());
        let high_entropy = entropy >= self.entropy_threshold;
        let query_source = dns.source_ip.clone().or_else(|| event.host_id.clone());
        let query_volume = query_source
            .as_deref()
            .map(|source| self.record_query(source, normalized_timestamp_ms(event.timestamp)))
            .unwrap_or_default();
        let excessive_query_volume = query_volume >= self.query_burst_threshold;

        if matched_pattern.is_none()
            && !high_entropy
            && !excessive_query_volume
            && subdomain.len() < self.min_subdomain_length
        {
            return None;
        }
        if matched_pattern.is_none() && !high_entropy && !excessive_query_volume {
            return None;
        }

        let confidence =
            if matched_pattern.is_some() || suspicious_query_type || excessive_query_volume {
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
            threat_class: ThreatClass::DataExfiltration,
            severity,
            confidence,
            evidence: json!({
                "query_name": dns.query_name,
                "query_type": dns.query_type,
                "source_ip": dns.source_ip,
                "process_name": dns.process_name,
                "response_code": dns.response_code,
                "computed_entropy": entropy,
                "subdomain_length": subdomain.len(),
                "query_source": query_source,
                "query_volume_in_window": query_volume,
                "query_burst_threshold": self.query_burst_threshold,
                "burst_window_ms": self.burst_window_ms,
                "matched_pattern": matched_pattern,
                "suspicious_query_type": suspicious_query_type,
                "excessive_query_volume": excessive_query_volume,
            }),
            strategy_id: self.id().to_string(),
        })
    }

    fn record_query(&self, source: &str, timestamp_ms: i64) -> usize {
        let window_start = timestamp_ms.saturating_sub(self.burst_window_ms);
        let mut guard = self
            .query_tracker
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let entries = guard.entry(source.to_ascii_lowercase()).or_default();
        while entries
            .front()
            .is_some_and(|recorded_at| *recorded_at < window_start)
        {
            entries.pop_front();
        }
        entries.push_back(timestamp_ms);
        entries.len()
    }

    fn domain_is_allowlisted(&self, query_name: &str) -> bool {
        self.allowlisted_domains
            .iter()
            .any(|domain| query_name == domain || query_name.ends_with(&format!(".{domain}")))
    }
}

impl DnsExfiltrationProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        if self.entropy_threshold <= 0.0 {
            return Err(ProfileValidationError {
                profile: "DnsExfiltrationProfile",
                field: "entropy_threshold",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.min_subdomain_length == 0 {
            return Err(ProfileValidationError {
                profile: "DnsExfiltrationProfile",
                field: "min_subdomain_length",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.query_burst_threshold == 0 {
            return Err(ProfileValidationError {
                profile: "DnsExfiltrationProfile",
                field: "query_burst_threshold",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.burst_window_ms <= 0 {
            return Err(ProfileValidationError {
                profile: "DnsExfiltrationProfile",
                field: "burst_window_ms",
                reason: "must be greater than zero".to_string(),
            });
        }
        validate_confidence_thresholds(
            "DnsExfiltrationProfile",
            self.high_confidence_threshold,
            self.medium_confidence_threshold,
        )
    }
}

impl DetectionStrategy for DnsExfiltrationDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        "dns_exfiltration"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        match &event.payload {
            TelemetryPayload::DnsQuery(dns) => self.evaluate_dns(event, dns).into_iter().collect(),
            TelemetryPayload::ProcessStart(_)
            | TelemetryPayload::ProcessMemoryAccess(_)
            | TelemetryPayload::NetworkConnect(_)
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

fn extract_subdomain(query_name: &str) -> String {
    let labels: Vec<&str> = query_name
        .split('.')
        .filter(|label| !label.trim().is_empty())
        .collect();
    if labels.len() <= 2 {
        return String::new();
    }
    labels[..labels.len() - 2].join("")
}

fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }

    let mut counts = BTreeMap::new();
    for ch in value.chars() {
        *counts.entry(ch).or_insert(0usize) += 1;
    }

    let len = value.chars().count() as f64;
    counts
        .into_values()
        .map(|count| {
            let probability = count as f64 / len;
            -(probability * probability.log2())
        })
        .sum()
}

fn default_entropy_threshold() -> f64 {
    3.5
}

fn default_min_subdomain_length() -> usize {
    20
}

fn default_suspicious_query_types() -> Vec<String> {
    ["TXT", "NULL", "CNAME"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_known_tunneling_patterns() -> Vec<String> {
    ["dnscat", "iodine"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_query_burst_threshold() -> usize {
    8
}

fn default_burst_window_ms() -> i64 {
    60_000
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
    use super::{DnsExfiltrationDetector, DnsExfiltrationProfile, shannon_entropy};
    use crate::detector::{DetectionStrategy, DnsQueryEvent, TelemetryEvent, TelemetryPayload};
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;

    fn dns_event(query_name: &str, query_type: &str) -> TelemetryEvent {
        dns_event_at(query_name, query_type, 1_700_000_000_000)
    }

    fn dns_event_at(query_name: &str, query_type: &str, timestamp: i64) -> TelemetryEvent {
        TelemetryEvent {
            source: "dns".to_string(),
            event_id: "evt-dns".to_string(),
            timestamp,
            host_id: Some("host-a".to_string()),
            payload: TelemetryPayload::DnsQuery(DnsQueryEvent {
                query_name: query_name.to_string(),
                query_type: query_type.to_string(),
                source_ip: Some("10.0.0.4".to_string()),
                process_name: Some("powershell".to_string()),
                response_code: Some("NOERROR".to_string()),
            }),
        }
    }

    #[test]
    fn high_entropy_subdomain_produces_data_exfiltration_finding() {
        let detector = DnsExfiltrationDetector::default();
        let findings =
            detector.evaluate(&dns_event("a1b2c3d4e5f6g7h8i9j0k1l2m3.example.com", "TXT"));

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::DataExfiltration);
        assert!(matches!(
            findings[0].severity,
            Severity::High | Severity::Critical
        ));
    }

    #[test]
    fn known_tunneling_pattern_produces_high_confidence_finding() {
        let detector = DnsExfiltrationDetector::default();
        let findings = detector.evaluate(&dns_event("session.dnscat.evil.com", "A"));

        assert_eq!(findings.len(), 1);
        assert!(findings[0].confidence >= 0.9);
    }

    #[test]
    fn normal_dns_query_does_not_trigger() {
        let detector = DnsExfiltrationDetector::default();
        let findings = detector.evaluate(&dns_event("www.google.com", "A"));
        assert!(findings.is_empty());
    }

    #[test]
    fn short_subdomain_does_not_trigger() {
        let detector = DnsExfiltrationDetector::default();
        let findings = detector.evaluate(&dns_event("abc.evil.com", "TXT"));
        assert!(findings.is_empty());
    }

    #[test]
    fn burst_query_volume_from_single_source_produces_finding() {
        let detector = DnsExfiltrationDetector::default();
        let mut findings = Vec::new();
        for idx in 0..8 {
            findings = detector.evaluate(&dns_event_at(
                &format!("www{idx}.example.com"),
                "A",
                1_700_000_000_000 + idx * 1_000,
            ));
        }

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::DataExfiltration);
    }

    #[test]
    fn allowlisted_domain_suppresses_false_positive() {
        let detector = DnsExfiltrationDetector::from_profile(DnsExfiltrationProfile {
            allowlisted_domains: vec!["cdn.example.com".to_string()],
            ..DnsExfiltrationProfile::default()
        })
        .expect("profile should be valid");

        let findings = detector.evaluate(&dns_event(
            "abcdefghijklabcdefghijkl.cdn.example.com",
            "TXT",
        ));
        assert!(findings.is_empty());
    }

    #[test]
    fn entropy_threshold_boundary_requires_crossing_default_cutoff() {
        let detector = DnsExfiltrationDetector::default();
        let below_threshold = "aabbccddeeffgghhiijjkk";
        let above_threshold = "abcdefghijklabcdefghijkl";

        assert!(shannon_entropy(below_threshold) < 3.5);
        assert!(shannon_entropy(above_threshold) > 3.5);

        let below = detector.evaluate(&dns_event(&format!("{below_threshold}.example.com"), "TXT"));
        let above = detector.evaluate(&dns_event(&format!("{above_threshold}.example.com"), "TXT"));

        assert!(below.is_empty());
        assert_eq!(above.len(), 1);
    }

    #[test]
    fn profile_round_trips() {
        let profile = DnsExfiltrationProfile::default();
        let detector = DnsExfiltrationDetector::from_profile(profile.clone())
            .expect("profile should be valid");
        assert_eq!(detector.profile(), profile);
    }
}
