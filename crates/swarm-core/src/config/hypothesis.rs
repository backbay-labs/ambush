use super::*;

const DEFAULT_HYPOTHESIS_GRAPH_MAX_MEMORY_TTL_TICKS: u64 = 86_400_000;
const DEFAULT_HYPOTHESIS_GRAPH_MAX_WORK_UNITS_PER_TICK: u32 = 10_000;
const DEFAULT_HYPOTHESIS_GRAPH_MAX_CLAIMS_PER_TICK: u16 = 128;

/// Bounded collective-reasoning configuration. The feature is deliberately
/// disabled by default so existing runtime paths retain their byte shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisGraphConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_hypothesis_graph_max_nodes")]
    pub max_nodes: usize,
    #[serde(default = "default_hypothesis_graph_max_edges")]
    pub max_edges: usize,
    #[serde(default = "default_hypothesis_graph_max_evidence_bytes")]
    pub max_evidence_bytes: usize,
    #[serde(default = "default_hypothesis_graph_max_evidence_references_per_edge")]
    pub max_evidence_references_per_edge: usize,
    #[serde(default = "default_hypothesis_graph_max_hypotheses")]
    pub max_hypotheses: usize,
    #[serde(default = "default_hypothesis_graph_max_contradictions")]
    pub max_contradictions: usize,
    #[serde(default = "default_hypothesis_graph_max_decisions")]
    pub max_decisions: usize,
    #[serde(default = "default_hypothesis_graph_max_tasks")]
    pub max_tasks: usize,
    #[serde(default = "default_hypothesis_graph_max_lease_ms")]
    pub max_lease_ms: u64,
    #[serde(default = "default_hypothesis_graph_max_retries")]
    pub max_retries: u16,
    #[serde(default = "default_hypothesis_graph_max_memory_records")]
    pub max_memory_records: usize,
    #[serde(default = "default_hypothesis_graph_max_depth")]
    pub max_graph_depth: usize,
    #[serde(default = "default_hypothesis_graph_max_fan_out")]
    pub max_graph_fan_out: usize,
    #[serde(default = "default_hypothesis_graph_max_benchmark_work_units")]
    pub max_benchmark_work_units: usize,
    #[serde(default = "default_hypothesis_graph_max_memory_ttl_ticks")]
    pub max_memory_ttl_ticks: u64,
    #[serde(default = "default_hypothesis_graph_max_work_units_per_tick")]
    pub max_work_units_per_tick: u32,
    #[serde(default = "default_hypothesis_graph_max_claims_per_tick")]
    pub max_claims_per_tick: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HypothesisGraphConfigWire {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_hypothesis_graph_max_nodes")]
    max_nodes: usize,
    #[serde(default = "default_hypothesis_graph_max_edges")]
    max_edges: usize,
    #[serde(default = "default_hypothesis_graph_max_evidence_bytes")]
    max_evidence_bytes: usize,
    #[serde(default = "default_hypothesis_graph_max_evidence_references_per_edge")]
    max_evidence_references_per_edge: usize,
    #[serde(default = "default_hypothesis_graph_max_hypotheses")]
    max_hypotheses: usize,
    #[serde(default = "default_hypothesis_graph_max_contradictions")]
    max_contradictions: usize,
    #[serde(default = "default_hypothesis_graph_max_decisions")]
    max_decisions: usize,
    #[serde(default = "default_hypothesis_graph_max_tasks")]
    max_tasks: usize,
    #[serde(default = "default_hypothesis_graph_max_lease_ms")]
    max_lease_ms: u64,
    #[serde(default = "default_hypothesis_graph_max_retries")]
    max_retries: u16,
    #[serde(default = "default_hypothesis_graph_max_memory_records")]
    max_memory_records: usize,
    #[serde(default = "default_hypothesis_graph_max_depth")]
    max_graph_depth: usize,
    #[serde(default = "default_hypothesis_graph_max_fan_out")]
    max_graph_fan_out: usize,
    #[serde(default = "default_hypothesis_graph_max_benchmark_work_units")]
    max_benchmark_work_units: usize,
    #[serde(default = "default_hypothesis_graph_max_memory_ttl_ticks")]
    max_memory_ttl_ticks: u64,
    #[serde(default = "default_hypothesis_graph_max_work_units_per_tick")]
    max_work_units_per_tick: u32,
    #[serde(default = "default_hypothesis_graph_max_claims_per_tick")]
    max_claims_per_tick: u16,
}

impl<'de> Deserialize<'de> for HypothesisGraphConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = HypothesisGraphConfigWire::deserialize(deserializer)?;
        let config = Self {
            enabled: wire.enabled,
            max_nodes: wire.max_nodes,
            max_edges: wire.max_edges,
            max_evidence_bytes: wire.max_evidence_bytes,
            max_evidence_references_per_edge: wire.max_evidence_references_per_edge,
            max_hypotheses: wire.max_hypotheses,
            max_contradictions: wire.max_contradictions,
            max_decisions: wire.max_decisions,
            max_tasks: wire.max_tasks,
            max_lease_ms: wire.max_lease_ms,
            max_retries: wire.max_retries,
            max_memory_records: wire.max_memory_records,
            max_graph_depth: wire.max_graph_depth,
            max_graph_fan_out: wire.max_graph_fan_out,
            max_benchmark_work_units: wire.max_benchmark_work_units,
            max_memory_ttl_ticks: wire.max_memory_ttl_ticks,
            max_work_units_per_tick: wire.max_work_units_per_tick,
            max_claims_per_tick: wire.max_claims_per_tick,
        };
        config
            .resource_limits()
            .validate()
            .and(config.validate_reasoning_limits())
            .map_err(serde::de::Error::custom)?;
        Ok(config)
    }
}

const fn default_hypothesis_graph_max_memory_ttl_ticks() -> u64 {
    DEFAULT_HYPOTHESIS_GRAPH_MAX_MEMORY_TTL_TICKS
}

const fn default_hypothesis_graph_max_work_units_per_tick() -> u32 {
    DEFAULT_HYPOTHESIS_GRAPH_MAX_WORK_UNITS_PER_TICK
}

const fn default_hypothesis_graph_max_claims_per_tick() -> u16 {
    DEFAULT_HYPOTHESIS_GRAPH_MAX_CLAIMS_PER_TICK
}

impl Default for HypothesisGraphConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_nodes: default_hypothesis_graph_max_nodes(),
            max_edges: default_hypothesis_graph_max_edges(),
            max_evidence_bytes: default_hypothesis_graph_max_evidence_bytes(),
            max_evidence_references_per_edge:
                default_hypothesis_graph_max_evidence_references_per_edge(),
            max_hypotheses: default_hypothesis_graph_max_hypotheses(),
            max_contradictions: default_hypothesis_graph_max_contradictions(),
            max_decisions: default_hypothesis_graph_max_decisions(),
            max_tasks: default_hypothesis_graph_max_tasks(),
            max_lease_ms: default_hypothesis_graph_max_lease_ms(),
            max_retries: default_hypothesis_graph_max_retries(),
            max_memory_records: default_hypothesis_graph_max_memory_records(),
            max_graph_depth: default_hypothesis_graph_max_depth(),
            max_graph_fan_out: default_hypothesis_graph_max_fan_out(),
            max_benchmark_work_units: default_hypothesis_graph_max_benchmark_work_units(),
            max_memory_ttl_ticks: default_hypothesis_graph_max_memory_ttl_ticks(),
            max_work_units_per_tick: default_hypothesis_graph_max_work_units_per_tick(),
            max_claims_per_tick: default_hypothesis_graph_max_claims_per_tick(),
        }
    }
}

impl HypothesisGraphConfig {
    pub fn resource_limits(&self) -> crate::hypothesis_graph::GraphResourceLimits {
        crate::hypothesis_graph::GraphResourceLimits {
            max_nodes: self.max_nodes,
            max_edges: self.max_edges,
            max_evidence_bytes: self.max_evidence_bytes,
            max_evidence_references_per_edge: self.max_evidence_references_per_edge,
            max_hypotheses: self.max_hypotheses,
            max_contradictions: self.max_contradictions,
            max_decisions_per_hypothesis: self.max_decisions,
            max_tasks: self.max_tasks,
            max_task_lease_ms: self.max_lease_ms,
            max_task_retries: self.max_retries,
            max_memory_ttl_ticks: self.max_memory_ttl_ticks,
            max_memory_records: self.max_memory_records,
            max_graph_depth: self.max_graph_depth,
            max_graph_fan_out: self.max_graph_fan_out,
            max_benchmark_work_units: self.max_benchmark_work_units,
        }
    }

    /// Validate the post-Plan-03 logical-time and per-tick ceilings.
    pub fn validate_reasoning_limits(
        &self,
    ) -> Result<(), crate::hypothesis_graph::GraphAdmissionError> {
        if self.max_memory_ttl_ticks == 0
            || self.max_memory_ttl_ticks > crate::hypothesis_graph::MAX_STRATEGY_MEMORY_TTL_TICKS
        {
            return Err(crate::hypothesis_graph::GraphAdmissionError::InvalidLimit {
                field: "max_memory_ttl_ticks".to_string(),
                reason: format!(
                    "must be between 1 and {}",
                    crate::hypothesis_graph::MAX_STRATEGY_MEMORY_TTL_TICKS
                ),
            });
        }
        if self.max_work_units_per_tick == 0
            || self.max_work_units_per_tick
                > crate::hypothesis_graph::SchedulerBudget::MAX_WORK_UNITS
        {
            return Err(crate::hypothesis_graph::GraphAdmissionError::InvalidLimit {
                field: "max_work_units_per_tick".to_string(),
                reason: format!(
                    "must be between 1 and {}",
                    crate::hypothesis_graph::SchedulerBudget::MAX_WORK_UNITS
                ),
            });
        }
        if self.max_claims_per_tick == 0
            || self.max_claims_per_tick > crate::hypothesis_graph::SchedulerBudget::MAX_CLAIMS
        {
            return Err(crate::hypothesis_graph::GraphAdmissionError::InvalidLimit {
                field: "max_claims_per_tick".to_string(),
                reason: format!(
                    "must be between 1 and {}",
                    crate::hypothesis_graph::SchedulerBudget::MAX_CLAIMS
                ),
            });
        }
        Ok(())
    }
}
