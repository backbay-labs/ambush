use crate::detector::{
    DetectionFinding, DetectionStrategy, ExhaustedResource, InfrastructureHealthEvent,
    ResourceExhaustionEvent, TelemetryEvent, TelemetryPayload, ThermalAnomalyEvent,
};
use crate::{ProfileValidationError, validate_confidence_thresholds};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;

const CRYPTOMINER_RULE: &str = "cryptominer_signature";
const FORK_BOMB_RULE: &str = "fork_bomb_signature";
const DISK_WIPER_RULE: &str = "disk_wiper_signature";
const FILELESS_MEMORY_RULE: &str = "fileless_memory_pressure_signature";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureAnomalyProfile {
    #[serde(default = "default_correlation_window_secs")]
    pub correlation_window_secs: i64,
    #[serde(default = "default_min_sustained_high_cpu_samples")]
    pub min_sustained_high_cpu_samples: usize,
    #[serde(default = "default_cpu_sustained_percent")]
    pub cpu_sustained_percent: f64,
    #[serde(default = "default_load_saturated_threshold")]
    pub load_saturated_threshold: f64,
    #[serde(default = "default_thermal_high_celsius")]
    pub thermal_high_celsius: f64,
    #[serde(default = "default_thermal_critical_celsius")]
    pub thermal_critical_celsius: f64,
    #[serde(default = "default_memory_critical_percent")]
    pub memory_critical_percent: f64,
    #[serde(default = "default_disk_critical_percent")]
    pub disk_critical_percent: f64,
    #[serde(default = "default_low_disk_io_latency_ms")]
    pub low_disk_io_latency_ms: f64,
    #[serde(default = "default_high_disk_io_latency_ms")]
    pub high_disk_io_latency_ms: f64,
    #[serde(default = "default_quiet_network_tx_bytes")]
    pub quiet_network_tx_bytes: u64,
    #[serde(default = "default_quiet_network_rx_bytes")]
    pub quiet_network_rx_bytes: u64,
    #[serde(default = "default_fileless_memory_cpu_ceiling_percent")]
    pub fileless_memory_cpu_ceiling_percent: f64,
    #[serde(default = "default_high_confidence_threshold")]
    pub high_confidence_threshold: f64,
    #[serde(default = "default_medium_confidence_threshold")]
    pub medium_confidence_threshold: f64,
}

impl Default for InfrastructureAnomalyProfile {
    fn default() -> Self {
        Self {
            correlation_window_secs: default_correlation_window_secs(),
            min_sustained_high_cpu_samples: default_min_sustained_high_cpu_samples(),
            cpu_sustained_percent: default_cpu_sustained_percent(),
            load_saturated_threshold: default_load_saturated_threshold(),
            thermal_high_celsius: default_thermal_high_celsius(),
            thermal_critical_celsius: default_thermal_critical_celsius(),
            memory_critical_percent: default_memory_critical_percent(),
            disk_critical_percent: default_disk_critical_percent(),
            low_disk_io_latency_ms: default_low_disk_io_latency_ms(),
            high_disk_io_latency_ms: default_high_disk_io_latency_ms(),
            quiet_network_tx_bytes: default_quiet_network_tx_bytes(),
            quiet_network_rx_bytes: default_quiet_network_rx_bytes(),
            fileless_memory_cpu_ceiling_percent: default_fileless_memory_cpu_ceiling_percent(),
            high_confidence_threshold: default_high_confidence_threshold(),
            medium_confidence_threshold: default_medium_confidence_threshold(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InfrastructureAnomalyDetector {
    correlation_window_ms: i64,
    min_sustained_high_cpu_samples: usize,
    cpu_sustained_percent: f64,
    load_saturated_threshold: f64,
    thermal_high_celsius: f64,
    thermal_critical_celsius: f64,
    memory_critical_percent: f64,
    disk_critical_percent: f64,
    low_disk_io_latency_ms: f64,
    high_disk_io_latency_ms: f64,
    quiet_network_tx_bytes: u64,
    quiet_network_rx_bytes: u64,
    fileless_memory_cpu_ceiling_percent: f64,
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
    state: Arc<Mutex<HashMap<String, NodeCorrelationState>>>,
}

#[derive(Debug, Clone, Default)]
struct NodeCorrelationState {
    recent_high_cpu_samples_ms: VecDeque<i64>,
    last_health: Option<TimestampedInfrastructureHealth>,
    last_thermal: Option<TimestampedThermalAnomaly>,
    last_emitted_rules_ms: HashMap<String, i64>,
}

#[derive(Debug, Clone)]
struct TimestampedInfrastructureHealth {
    observed_at_ms: i64,
    health: InfrastructureHealthEvent,
}

#[derive(Debug, Clone)]
struct TimestampedThermalAnomaly {
    observed_at_ms: i64,
    anomaly: ThermalAnomalyEvent,
}

impl Default for InfrastructureAnomalyDetector {
    fn default() -> Self {
        let profile = InfrastructureAnomalyProfile::default();
        debug_assert!(profile.validate().is_ok());
        Self {
            correlation_window_ms: profile.correlation_window_secs.saturating_mul(1_000),
            min_sustained_high_cpu_samples: profile.min_sustained_high_cpu_samples,
            cpu_sustained_percent: profile.cpu_sustained_percent,
            load_saturated_threshold: profile.load_saturated_threshold,
            thermal_high_celsius: profile.thermal_high_celsius,
            thermal_critical_celsius: profile.thermal_critical_celsius,
            memory_critical_percent: profile.memory_critical_percent,
            disk_critical_percent: profile.disk_critical_percent,
            low_disk_io_latency_ms: profile.low_disk_io_latency_ms,
            high_disk_io_latency_ms: profile.high_disk_io_latency_ms,
            quiet_network_tx_bytes: profile.quiet_network_tx_bytes,
            quiet_network_rx_bytes: profile.quiet_network_rx_bytes,
            fileless_memory_cpu_ceiling_percent: profile.fileless_memory_cpu_ceiling_percent,
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
            state: Arc::default(),
        }
    }
}

impl InfrastructureAnomalyDetector {
    pub fn from_profile(
        profile: InfrastructureAnomalyProfile,
    ) -> Result<Self, ProfileValidationError> {
        profile.validate()?;
        Ok(Self {
            correlation_window_ms: profile.correlation_window_secs.saturating_mul(1_000),
            min_sustained_high_cpu_samples: profile.min_sustained_high_cpu_samples,
            cpu_sustained_percent: profile.cpu_sustained_percent,
            load_saturated_threshold: profile.load_saturated_threshold,
            thermal_high_celsius: profile.thermal_high_celsius,
            thermal_critical_celsius: profile.thermal_critical_celsius,
            memory_critical_percent: profile.memory_critical_percent,
            disk_critical_percent: profile.disk_critical_percent,
            low_disk_io_latency_ms: profile.low_disk_io_latency_ms,
            high_disk_io_latency_ms: profile.high_disk_io_latency_ms,
            quiet_network_tx_bytes: profile.quiet_network_tx_bytes,
            quiet_network_rx_bytes: profile.quiet_network_rx_bytes,
            fileless_memory_cpu_ceiling_percent: profile.fileless_memory_cpu_ceiling_percent,
            high_confidence_threshold: profile.high_confidence_threshold,
            medium_confidence_threshold: profile.medium_confidence_threshold,
            state: Arc::default(),
        })
    }

    pub fn profile(&self) -> InfrastructureAnomalyProfile {
        InfrastructureAnomalyProfile {
            correlation_window_secs: self.correlation_window_ms / 1_000,
            min_sustained_high_cpu_samples: self.min_sustained_high_cpu_samples,
            cpu_sustained_percent: self.cpu_sustained_percent,
            load_saturated_threshold: self.load_saturated_threshold,
            thermal_high_celsius: self.thermal_high_celsius,
            thermal_critical_celsius: self.thermal_critical_celsius,
            memory_critical_percent: self.memory_critical_percent,
            disk_critical_percent: self.disk_critical_percent,
            low_disk_io_latency_ms: self.low_disk_io_latency_ms,
            high_disk_io_latency_ms: self.high_disk_io_latency_ms,
            quiet_network_tx_bytes: self.quiet_network_tx_bytes,
            quiet_network_rx_bytes: self.quiet_network_rx_bytes,
            fileless_memory_cpu_ceiling_percent: self.fileless_memory_cpu_ceiling_percent,
            high_confidence_threshold: self.high_confidence_threshold,
            medium_confidence_threshold: self.medium_confidence_threshold,
        }
    }

    fn evaluate_health(
        &self,
        event: &TelemetryEvent,
        health: &InfrastructureHealthEvent,
        state: &mut NodeCorrelationState,
        timestamp_ms: i64,
    ) -> Vec<DetectionFinding> {
        state.prune(timestamp_ms, self.correlation_window_ms);
        if health.cpu_usage_percent >= self.cpu_sustained_percent {
            state.recent_high_cpu_samples_ms.push_back(timestamp_ms);
        }
        state.last_health = Some(TimestampedInfrastructureHealth {
            observed_at_ms: timestamp_ms,
            health: health.clone(),
        });

        self.detect_cryptominer(event, state, timestamp_ms)
            .into_iter()
            .collect()
    }

    fn evaluate_thermal(
        &self,
        event: &TelemetryEvent,
        thermal: &ThermalAnomalyEvent,
        state: &mut NodeCorrelationState,
        timestamp_ms: i64,
    ) -> Vec<DetectionFinding> {
        state.prune(timestamp_ms, self.correlation_window_ms);
        state.last_thermal = Some(TimestampedThermalAnomaly {
            observed_at_ms: timestamp_ms,
            anomaly: thermal.clone(),
        });

        self.detect_cryptominer(event, state, timestamp_ms)
            .into_iter()
            .collect()
    }

    fn evaluate_exhaustion(
        &self,
        event: &TelemetryEvent,
        exhaustion: &ResourceExhaustionEvent,
        state: &mut NodeCorrelationState,
        timestamp_ms: i64,
    ) -> Vec<DetectionFinding> {
        state.prune(timestamp_ms, self.correlation_window_ms);

        match exhaustion.resource_kind {
            ExhaustedResource::Memory => self
                .detect_memory_resource_abuse(event, exhaustion, state, timestamp_ms)
                .into_iter()
                .collect(),
            ExhaustedResource::Disk => self
                .detect_disk_wiper(event, exhaustion, state, timestamp_ms)
                .into_iter()
                .collect(),
            ExhaustedResource::Cpu
            | ExhaustedResource::Swap
            | ExhaustedResource::NetworkBandwidth => Vec::new(),
        }
    }

    fn detect_cryptominer(
        &self,
        event: &TelemetryEvent,
        state: &mut NodeCorrelationState,
        timestamp_ms: i64,
    ) -> Option<DetectionFinding> {
        if state.recent_high_cpu_samples_ms.len() < self.min_sustained_high_cpu_samples {
            return None;
        }
        let health = state
            .last_health
            .as_ref()
            .filter(|health| {
                timestamp_ms.saturating_sub(health.observed_at_ms) <= self.correlation_window_ms
            })?
            .health
            .clone();
        let thermal = state
            .last_thermal
            .as_ref()
            .filter(|thermal| {
                timestamp_ms.saturating_sub(thermal.observed_at_ms) <= self.correlation_window_ms
            })?
            .anomaly
            .clone();

        let load_saturated = health.load_average_1m >= self.load_saturated_threshold;
        let host_is_quiet = health.disk_io_latency_ms <= self.low_disk_io_latency_ms
            && health.network_tx_bytes <= self.quiet_network_tx_bytes
            && health.network_rx_bytes <= self.quiet_network_rx_bytes;
        let host_is_hot =
            thermal.temperature_celsius >= self.thermal_high_celsius || thermal.cpu_throttled;

        if !load_saturated || !host_is_quiet || !host_is_hot {
            return None;
        }
        if !state.should_emit(CRYPTOMINER_RULE, timestamp_ms, self.correlation_window_ms) {
            return None;
        }

        let confidence = if thermal.temperature_celsius >= self.thermal_critical_celsius
            || thermal.cpu_throttled
            || health.failure_probability >= 0.8
        {
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
            finding_id: format!("{}:{}:{}", self.id(), CRYPTOMINER_RULE, event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::Execution,
            severity,
            confidence,
            evidence: json!({
                "rule": CRYPTOMINER_RULE,
                "node_name": health.node_name,
                "cpu_usage_percent": health.cpu_usage_percent,
                "load_average_1m": health.load_average_1m,
                "recent_high_cpu_samples": state.recent_high_cpu_samples_ms.len(),
                "temperature_celsius": thermal.temperature_celsius,
                "cpu_throttled": thermal.cpu_throttled,
                "disk_io_latency_ms": health.disk_io_latency_ms,
                "network_tx_bytes": health.network_tx_bytes,
                "network_rx_bytes": health.network_rx_bytes,
                "failure_probability": health.failure_probability,
                "prediction_confidence": health.prediction_confidence,
                "host_id": event.host_id,
            }),
            strategy_id: self.id().to_string(),
        })
    }

    fn detect_memory_resource_abuse(
        &self,
        event: &TelemetryEvent,
        exhaustion: &ResourceExhaustionEvent,
        state: &mut NodeCorrelationState,
        timestamp_ms: i64,
    ) -> Option<DetectionFinding> {
        let health = state
            .last_health
            .as_ref()
            .filter(|health| {
                timestamp_ms.saturating_sub(health.observed_at_ms) <= self.correlation_window_ms
            })
            .map(|health| health.health.clone());
        let thermal = state
            .last_thermal
            .as_ref()
            .filter(|thermal| {
                timestamp_ms.saturating_sub(thermal.observed_at_ms) <= self.correlation_window_ms
            })
            .map(|thermal| thermal.anomaly.clone());

        let oom_kill_count = exhaustion.oom_kill_count.unwrap_or_default();
        let swap_used_bytes = exhaustion.swap_used_bytes.unwrap_or_default();

        if exhaustion.utilization_percent >= self.memory_critical_percent
            && (oom_kill_count > 0 || swap_used_bytes > 0)
            && health.as_ref().is_some_and(|health| {
                health.cpu_usage_percent >= self.cpu_sustained_percent
                    || health.load_average_1m >= self.load_saturated_threshold
            })
        {
            if !state.should_emit(FORK_BOMB_RULE, timestamp_ms, self.correlation_window_ms) {
                return None;
            }
            return Some(DetectionFinding {
                finding_id: format!("{}:{}:{}", self.id(), FORK_BOMB_RULE, event.event_id),
                event_id: event.event_id.clone(),
                threat_class: ThreatClass::Impact,
                severity: Severity::Critical,
                confidence: self.high_confidence_threshold,
                evidence: json!({
                    "rule": FORK_BOMB_RULE,
                    "node_name": exhaustion.node_name,
                    "utilization_percent": exhaustion.utilization_percent,
                    "current_value": exhaustion.current_value,
                    "capacity_value": exhaustion.capacity_value,
                    "oom_kill_count": oom_kill_count,
                    "swap_used_bytes": swap_used_bytes,
                    "is_new": exhaustion.is_new,
                    "host_id": event.host_id,
                }),
                strategy_id: self.id().to_string(),
            });
        }

        let health = health?;
        let thermal_is_cool = thermal
            .as_ref()
            .map(|thermal| thermal.temperature_celsius < self.thermal_high_celsius)
            .unwrap_or(true);
        let host_is_quiet = health.disk_io_latency_ms <= self.low_disk_io_latency_ms
            && health.network_tx_bytes <= self.quiet_network_tx_bytes
            && health.network_rx_bytes <= self.quiet_network_rx_bytes;

        if exhaustion.utilization_percent < self.memory_critical_percent
            || swap_used_bytes == 0
            || health.cpu_usage_percent > self.fileless_memory_cpu_ceiling_percent
            || !host_is_quiet
            || !thermal_is_cool
            || !state.should_emit(
                FILELESS_MEMORY_RULE,
                timestamp_ms,
                self.correlation_window_ms,
            )
        {
            return None;
        }

        Some(DetectionFinding {
            finding_id: format!("{}:{}:{}", self.id(), FILELESS_MEMORY_RULE, event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::DefenseEvasion,
            severity: Severity::High,
            confidence: self.medium_confidence_threshold,
            evidence: json!({
                "rule": FILELESS_MEMORY_RULE,
                "node_name": exhaustion.node_name,
                "utilization_percent": exhaustion.utilization_percent,
                "swap_used_bytes": swap_used_bytes,
                "cpu_usage_percent": health.cpu_usage_percent,
                "disk_io_latency_ms": health.disk_io_latency_ms,
                "network_tx_bytes": health.network_tx_bytes,
                "network_rx_bytes": health.network_rx_bytes,
                "host_id": event.host_id,
            }),
            strategy_id: self.id().to_string(),
        })
    }

    fn detect_disk_wiper(
        &self,
        event: &TelemetryEvent,
        exhaustion: &ResourceExhaustionEvent,
        state: &mut NodeCorrelationState,
        timestamp_ms: i64,
    ) -> Option<DetectionFinding> {
        let health = state
            .last_health
            .as_ref()
            .filter(|health| {
                timestamp_ms.saturating_sub(health.observed_at_ms) <= self.correlation_window_ms
            })?
            .health
            .clone();

        if exhaustion.utilization_percent < self.disk_critical_percent
            || health.disk_io_latency_ms < self.high_disk_io_latency_ms
            || health.network_tx_bytes > self.quiet_network_tx_bytes
            || !state.should_emit(DISK_WIPER_RULE, timestamp_ms, self.correlation_window_ms)
        {
            return None;
        }

        Some(DetectionFinding {
            finding_id: format!("{}:{}:{}", self.id(), DISK_WIPER_RULE, event.event_id),
            event_id: event.event_id.clone(),
            threat_class: ThreatClass::Impact,
            severity: Severity::High,
            confidence: if exhaustion.is_new {
                self.high_confidence_threshold
            } else {
                self.medium_confidence_threshold
            },
            evidence: json!({
                "rule": DISK_WIPER_RULE,
                "node_name": exhaustion.node_name,
                "utilization_percent": exhaustion.utilization_percent,
                "current_value": exhaustion.current_value,
                "capacity_value": exhaustion.capacity_value,
                "disk_io_latency_ms": health.disk_io_latency_ms,
                "network_tx_bytes": health.network_tx_bytes,
                "network_rx_bytes": health.network_rx_bytes,
                "is_new": exhaustion.is_new,
                "host_id": event.host_id,
            }),
            strategy_id: self.id().to_string(),
        })
    }
}

impl NodeCorrelationState {
    fn prune(&mut self, timestamp_ms: i64, correlation_window_ms: i64) {
        let earliest = timestamp_ms.saturating_sub(correlation_window_ms);
        while self
            .recent_high_cpu_samples_ms
            .front()
            .is_some_and(|sample| *sample < earliest)
        {
            self.recent_high_cpu_samples_ms.pop_front();
        }
        self.last_emitted_rules_ms
            .retain(|_, emitted_at_ms| *emitted_at_ms >= earliest);
    }

    fn should_emit(&mut self, rule: &str, timestamp_ms: i64, correlation_window_ms: i64) -> bool {
        if self
            .last_emitted_rules_ms
            .get(rule)
            .is_some_and(|last| timestamp_ms.saturating_sub(*last) < correlation_window_ms)
        {
            return false;
        }
        self.last_emitted_rules_ms
            .insert(rule.to_string(), timestamp_ms);
        true
    }
}

impl InfrastructureAnomalyProfile {
    pub fn validate(&self) -> Result<(), ProfileValidationError> {
        validate_confidence_thresholds(
            "InfrastructureAnomalyProfile",
            self.high_confidence_threshold,
            self.medium_confidence_threshold,
        )?;
        validate_positive_i64(
            "InfrastructureAnomalyProfile",
            "correlation_window_secs",
            self.correlation_window_secs,
        )?;
        validate_positive_usize(
            "InfrastructureAnomalyProfile",
            "min_sustained_high_cpu_samples",
            self.min_sustained_high_cpu_samples,
        )?;
        validate_percent(
            "InfrastructureAnomalyProfile",
            "cpu_sustained_percent",
            self.cpu_sustained_percent,
        )?;
        validate_positive_f64(
            "InfrastructureAnomalyProfile",
            "load_saturated_threshold",
            self.load_saturated_threshold,
        )?;
        validate_positive_f64(
            "InfrastructureAnomalyProfile",
            "thermal_high_celsius",
            self.thermal_high_celsius,
        )?;
        validate_positive_f64(
            "InfrastructureAnomalyProfile",
            "thermal_critical_celsius",
            self.thermal_critical_celsius,
        )?;
        validate_percent(
            "InfrastructureAnomalyProfile",
            "memory_critical_percent",
            self.memory_critical_percent,
        )?;
        validate_percent(
            "InfrastructureAnomalyProfile",
            "disk_critical_percent",
            self.disk_critical_percent,
        )?;
        validate_positive_f64(
            "InfrastructureAnomalyProfile",
            "low_disk_io_latency_ms",
            self.low_disk_io_latency_ms,
        )?;
        validate_positive_f64(
            "InfrastructureAnomalyProfile",
            "high_disk_io_latency_ms",
            self.high_disk_io_latency_ms,
        )?;
        validate_percent(
            "InfrastructureAnomalyProfile",
            "fileless_memory_cpu_ceiling_percent",
            self.fileless_memory_cpu_ceiling_percent,
        )?;
        if self.thermal_critical_celsius < self.thermal_high_celsius {
            return Err(ProfileValidationError {
                profile: "InfrastructureAnomalyProfile",
                field: "thermal_critical_celsius",
                reason: "must be greater than or equal to thermal_high_celsius".to_string(),
            });
        }
        if self.high_disk_io_latency_ms < self.low_disk_io_latency_ms {
            return Err(ProfileValidationError {
                profile: "InfrastructureAnomalyProfile",
                field: "high_disk_io_latency_ms",
                reason: "must be greater than or equal to low_disk_io_latency_ms".to_string(),
            });
        }
        if self.quiet_network_tx_bytes == 0 {
            return Err(ProfileValidationError {
                profile: "InfrastructureAnomalyProfile",
                field: "quiet_network_tx_bytes",
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.quiet_network_rx_bytes == 0 {
            return Err(ProfileValidationError {
                profile: "InfrastructureAnomalyProfile",
                field: "quiet_network_rx_bytes",
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

impl DetectionStrategy for InfrastructureAnomalyDetector {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn id(&self) -> &str {
        "infrastructure_anomaly"
    }

    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionFinding> {
        let node_name = match &event.payload {
            TelemetryPayload::InfrastructureHealth(health) => health.node_name.clone(),
            TelemetryPayload::ThermalAnomaly(thermal) => thermal.node_name.clone(),
            TelemetryPayload::ResourceExhaustion(exhaustion) => exhaustion.node_name.clone(),
            TelemetryPayload::ProcessStart(_)
            | TelemetryPayload::ProcessMemoryAccess(_)
            | TelemetryPayload::NetworkConnect(_)
            | TelemetryPayload::DnsQuery(_)
            | TelemetryPayload::RegistryAccess(_)
            | TelemetryPayload::RegistryPersistence(_)
            | TelemetryPayload::FilePersistence(_)
            | TelemetryPayload::AuthenticationEvent(_) => return Vec::new(),
        };
        let timestamp_ms = normalized_timestamp_ms(event.timestamp);
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let state = guard.entry(node_name).or_default();

        match &event.payload {
            TelemetryPayload::InfrastructureHealth(health) => {
                self.evaluate_health(event, health, state, timestamp_ms)
            }
            TelemetryPayload::ThermalAnomaly(thermal) => {
                self.evaluate_thermal(event, thermal, state, timestamp_ms)
            }
            TelemetryPayload::ResourceExhaustion(exhaustion) => {
                self.evaluate_exhaustion(event, exhaustion, state, timestamp_ms)
            }
            TelemetryPayload::ProcessStart(_)
            | TelemetryPayload::ProcessMemoryAccess(_)
            | TelemetryPayload::NetworkConnect(_)
            | TelemetryPayload::DnsQuery(_)
            | TelemetryPayload::RegistryAccess(_)
            | TelemetryPayload::RegistryPersistence(_)
            | TelemetryPayload::FilePersistence(_)
            | TelemetryPayload::AuthenticationEvent(_) => Vec::new(),
        }
    }
}

fn normalized_timestamp_ms(timestamp: i64) -> i64 {
    if timestamp.abs() < 100_000_000_000 {
        timestamp.saturating_mul(1_000)
    } else {
        timestamp
    }
}

fn validate_positive_i64(
    profile: &'static str,
    field: &'static str,
    value: i64,
) -> Result<(), ProfileValidationError> {
    if value <= 0 {
        return Err(ProfileValidationError {
            profile,
            field,
            reason: "must be greater than zero".to_string(),
        });
    }
    Ok(())
}

fn validate_positive_usize(
    profile: &'static str,
    field: &'static str,
    value: usize,
) -> Result<(), ProfileValidationError> {
    if value == 0 {
        return Err(ProfileValidationError {
            profile,
            field,
            reason: "must be greater than zero".to_string(),
        });
    }
    Ok(())
}

fn validate_positive_f64(
    profile: &'static str,
    field: &'static str,
    value: f64,
) -> Result<(), ProfileValidationError> {
    if value <= 0.0 {
        return Err(ProfileValidationError {
            profile,
            field,
            reason: "must be greater than zero".to_string(),
        });
    }
    Ok(())
}

fn validate_percent(
    profile: &'static str,
    field: &'static str,
    value: f64,
) -> Result<(), ProfileValidationError> {
    if !(0.0..=100.0).contains(&value) {
        return Err(ProfileValidationError {
            profile,
            field,
            reason: "must be between 0.0 and 100.0".to_string(),
        });
    }
    Ok(())
}

fn default_correlation_window_secs() -> i64 {
    120
}

fn default_min_sustained_high_cpu_samples() -> usize {
    2
}

fn default_cpu_sustained_percent() -> f64 {
    95.0
}

fn default_load_saturated_threshold() -> f64 {
    4.0
}

fn default_thermal_high_celsius() -> f64 {
    75.0
}

fn default_thermal_critical_celsius() -> f64 {
    85.0
}

fn default_memory_critical_percent() -> f64 {
    95.0
}

fn default_disk_critical_percent() -> f64 {
    95.0
}

fn default_low_disk_io_latency_ms() -> f64 {
    20.0
}

fn default_high_disk_io_latency_ms() -> f64 {
    50.0
}

fn default_quiet_network_tx_bytes() -> u64 {
    1_048_576
}

fn default_quiet_network_rx_bytes() -> u64 {
    1_048_576
}

fn default_fileless_memory_cpu_ceiling_percent() -> f64 {
    80.0
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
    use super::{DetectionStrategy, InfrastructureAnomalyDetector, InfrastructureAnomalyProfile};
    use crate::detector::{
        ExhaustedResource, InfrastructureHealthEvent, ResourceExhaustionEvent, TelemetryEvent,
        TelemetryPayload, ThermalAnomalyEvent, ThermalSeverity,
    };
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;

    fn health_event(
        event_id: &str,
        timestamp: i64,
        cpu_usage_percent: f64,
        load_average_1m: f64,
        disk_io_latency_ms: f64,
        network_tx_bytes: u64,
    ) -> TelemetryEvent {
        TelemetryEvent {
            source: "sentinel".to_string(),
            event_id: event_id.to_string(),
            timestamp,
            host_id: Some("node-a".to_string()),
            payload: TelemetryPayload::InfrastructureHealth(InfrastructureHealthEvent {
                node_name: "node-a".to_string(),
                cpu_usage_percent,
                cpu_frequency_mhz: 3_200.0,
                load_average_1m,
                load_average_5m: load_average_1m,
                load_average_15m: load_average_1m,
                memory_usage_percent: 72.0,
                memory_available_bytes: 128,
                disk_usage_percent: 60.0,
                disk_io_latency_ms,
                network_rx_bytes: 512,
                network_tx_bytes,
                network_rx_errors: 0,
                network_tx_errors: 0,
                failure_probability: 0.85,
                prediction_confidence: 0.9,
                time_to_failure_secs: 45.0,
                collection_duration_ms: 5.0,
            }),
        }
    }

    fn thermal_event(event_id: &str, timestamp: i64, temperature_celsius: f64) -> TelemetryEvent {
        TelemetryEvent {
            source: "sentinel".to_string(),
            event_id: event_id.to_string(),
            timestamp,
            host_id: Some("node-a".to_string()),
            payload: TelemetryPayload::ThermalAnomaly(ThermalAnomalyEvent {
                node_name: "node-a".to_string(),
                temperature_celsius,
                cpu_throttled: true,
                trend_slope: 0.8,
                severity: ThermalSeverity::High,
                estimated_time_to_critical_secs: 30.0,
            }),
        }
    }

    fn memory_event(event_id: &str, timestamp: i64, cpu_usage_percent: f64) -> Vec<TelemetryEvent> {
        vec![
            health_event(
                "memory-health",
                timestamp - 5,
                cpu_usage_percent,
                1.5,
                4.0,
                256,
            ),
            TelemetryEvent {
                source: "sentinel".to_string(),
                event_id: event_id.to_string(),
                timestamp,
                host_id: Some("node-a".to_string()),
                payload: TelemetryPayload::ResourceExhaustion(ResourceExhaustionEvent {
                    node_name: "node-a".to_string(),
                    resource_kind: ExhaustedResource::Memory,
                    utilization_percent: 97.0,
                    current_value: 970,
                    capacity_value: 1_000,
                    oom_kill_count: Some(0),
                    swap_used_bytes: Some(4_096),
                    is_new: true,
                }),
            },
        ]
    }

    #[test]
    fn cryptominer_signature_requires_sustained_cpu_and_thermal_signal() {
        let detector = InfrastructureAnomalyDetector::default();
        assert!(
            detector
                .evaluate(&health_event("infra-1", 1_700_000_000, 97.0, 8.0, 7.0, 128))
                .is_empty()
        );
        assert!(
            detector
                .evaluate(&health_event("infra-2", 1_700_000_030, 98.0, 9.0, 6.0, 64))
                .is_empty()
        );

        let findings = detector.evaluate(&thermal_event("infra-3", 1_700_000_045, 82.0));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::Execution);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].strategy_id, "infrastructure_anomaly");
        assert_eq!(findings[0].evidence["rule"], "cryptominer_signature");
    }

    #[test]
    fn memory_pressure_can_map_to_defense_evasion_without_host_noise() {
        let detector = InfrastructureAnomalyDetector::default();
        let events = memory_event("memory-1", 1_700_000_100, 35.0);
        assert!(detector.evaluate(&events[0]).is_empty());

        let findings = detector.evaluate(&events[1]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::DefenseEvasion);
        assert_eq!(
            findings[0].evidence["rule"],
            "fileless_memory_pressure_signature"
        );
    }

    #[test]
    fn disk_wiper_signature_maps_to_impact() {
        let detector = InfrastructureAnomalyDetector::default();
        assert!(
            detector
                .evaluate(&health_event(
                    "disk-health",
                    1_700_000_200,
                    89.0,
                    5.0,
                    75.0,
                    64
                ))
                .is_empty()
        );

        let findings = detector.evaluate(&TelemetryEvent {
            source: "sentinel".to_string(),
            event_id: "disk-1".to_string(),
            timestamp: 1_700_000_205,
            host_id: Some("node-a".to_string()),
            payload: TelemetryPayload::ResourceExhaustion(ResourceExhaustionEvent {
                node_name: "node-a".to_string(),
                resource_kind: ExhaustedResource::Disk,
                utilization_percent: 98.0,
                current_value: 1_980,
                capacity_value: 2_000,
                oom_kill_count: None,
                swap_used_bytes: None,
                is_new: true,
            }),
        });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].threat_class, ThreatClass::Impact);
        assert_eq!(findings[0].evidence["rule"], "disk_wiper_signature");
    }

    #[test]
    fn invalid_profile_rejects_zero_window() {
        let error = InfrastructureAnomalyProfile {
            correlation_window_secs: 0,
            ..InfrastructureAnomalyProfile::default()
        }
        .validate()
        .unwrap_err();
        assert_eq!(error.field, "correlation_window_secs");
    }
}
