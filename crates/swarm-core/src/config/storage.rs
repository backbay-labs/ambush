use super::*;

/// Audit persistence settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Store used for replay bundles and receipt lookup.
    #[serde(default)]
    pub bundle_store: BundleStoreConfig,
    /// How many recent decision records to surface to operators by default.
    #[serde(default = "default_recent_decisions_limit")]
    pub recent_decisions_limit: usize,
}

/// Async investigation settings that stay off the critical lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationConfig {
    /// Whether the investigation queue is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Number of background workers allowed to process queued jobs concurrently.
    #[serde(default = "default_investigation_worker_count")]
    pub worker_count: usize,
    /// Maximum queued jobs buffered before new submissions degrade visibly.
    #[serde(default = "default_investigation_max_pending_jobs")]
    pub max_pending_jobs: usize,
    /// Maximum time budget for one investigation run.
    #[serde(default = "default_investigation_time_budget_ms")]
    pub time_budget_ms: u64,
    /// Priority boost accrued per second while a job waits in the async queue.
    #[serde(default = "default_investigation_starvation_boost_per_second_basis_points")]
    pub starvation_boost_per_second_basis_points: u16,
    /// Upper bound on starvation boost so queue aging remains bounded.
    #[serde(default = "default_investigation_max_starvation_boost_basis_points")]
    pub max_starvation_boost_basis_points: u16,
    /// Vote delta at or below which the final interpretation remains marked ambiguous.
    #[serde(default = "default_investigation_ambiguity_margin_basis_points")]
    pub ambiguity_margin_basis_points: u16,
    /// Store used for investigation bundles and lookup by stable identifiers.
    #[serde(default)]
    pub bundle_store: BundleStoreConfig,
}

/// Incident correlation settings layered on top of investigation bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationConfig {
    /// Whether incident correlation is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum age difference between investigations to be considered together.
    #[serde(default = "default_correlation_time_window_ms")]
    pub time_window_ms: i64,
    /// Minimum shared correlation keys required for inclusion.
    #[serde(default = "default_correlation_min_shared_keys")]
    pub min_shared_keys: usize,
    /// Maximum recent investigations to scan when assembling one incident.
    #[serde(default = "default_correlation_candidate_limit")]
    pub candidate_limit: usize,
    /// Store used for correlated incident artifacts.
    #[serde(default)]
    pub incident_store: BundleStoreConfig,
}

/// Bounded canary settings layered on top of verified candidate detectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BundleStoreConfig {
    #[default]
    Memory,
    LocalFiles {
        directory: String,
    },
}

/// Semantic validation errors that survive after deserialization.
impl BundleStoreConfig {
    pub fn is_durable(&self) -> bool {
        matches!(self, Self::LocalFiles { .. })
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            bundle_store: BundleStoreConfig::default(),
            recent_decisions_limit: default_recent_decisions_limit(),
        }
    }
}

impl Default for InvestigationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            worker_count: default_investigation_worker_count(),
            max_pending_jobs: default_investigation_max_pending_jobs(),
            time_budget_ms: default_investigation_time_budget_ms(),
            starvation_boost_per_second_basis_points:
                default_investigation_starvation_boost_per_second_basis_points(),
            max_starvation_boost_basis_points:
                default_investigation_max_starvation_boost_basis_points(),
            ambiguity_margin_basis_points: default_investigation_ambiguity_margin_basis_points(),
            bundle_store: BundleStoreConfig::default(),
        }
    }
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            time_window_ms: default_correlation_time_window_ms(),
            min_shared_keys: default_correlation_min_shared_keys(),
            candidate_limit: default_correlation_candidate_limit(),
            incident_store: BundleStoreConfig::default(),
        }
    }
}
