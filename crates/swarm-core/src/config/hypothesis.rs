use super::*;

/// Bounded collective-reasoning configuration. The feature is deliberately
/// disabled by default so existing runtime paths retain their byte shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
            max_memory_records: self.max_memory_records,
            max_graph_depth: self.max_graph_depth,
            max_graph_fan_out: self.max_graph_fan_out,
            max_benchmark_work_units: self.max_benchmark_work_units,
        }
    }
}
