use super::*;

/// Bounded canary settings layered on top of verified candidate detectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryConfig {
    /// Whether the bounded canary lane is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Stable slot identifier for the active canary lane.
    #[serde(default = "default_canary_slot_id")]
    pub slot_id: String,
    /// Optional baseline strategy scope used for rollout comparisons.
    #[serde(default)]
    pub strategy_id: Option<String>,
    /// Number of live events observed before a canary can complete normally.
    #[serde(default = "default_canary_observation_window_events")]
    pub observation_window_events: usize,
    /// Maximum allowed candidate-only detection rate across the canary window.
    #[serde(default = "default_canary_max_candidate_only_rate")]
    pub max_candidate_only_rate: f64,
    /// Maximum allowed rate of baseline detections that the candidate misses.
    #[serde(default = "default_canary_max_baseline_miss_rate")]
    pub max_baseline_miss_rate: f64,
    /// ADVISORY ONLY. Recorded as the reference point for the non-gating
    /// `detect_latency_budget` observation on the canary artifact; no canary is
    /// ever rolled back for exceeding it.
    ///
    /// The value it is compared against is a wall-clock `Instant` delta around
    /// the candidate's detect stage, which measures the machine and the build
    /// profile rather than the candidate, so it could roll a healthy detector
    /// out of a live lane on a busy runner.
    ///
    /// Kept in the schema, and kept at its shipped value, for three reasons:
    /// the observation is meaningless without a reference point; a trend tool
    /// wants the historical series to stay comparable; and this struct is
    /// `deny_unknown_fields` while the repo's own `rulesets/default.yaml` sets
    /// the key -- and `rulesets/` is covered by the signed
    /// `rulesets/attestation.json` whose signing key is deliberately not in this
    /// repository, so the ruleset could not be edited to drop it.
    #[serde(default = "default_canary_max_detect_latency_us")]
    pub max_detect_latency_us: u64,
    /// Maximum allowed candidate detection volume across the canary window.
    #[serde(default = "default_canary_max_total_detections")]
    pub max_total_detections: usize,
}

/// Controlled production-promotion settings layered on top of completed canary runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionConfig {
    /// Whether the controlled production-promotion lane is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Stable window identifier for the active production observation window.
    #[serde(default = "default_promotion_window_id")]
    pub window_id: String,
    /// Optional fallback baseline strategy scope for production rollout.
    #[serde(default)]
    pub strategy_id: Option<String>,
    /// Number of live events observed before a promotion can complete normally.
    #[serde(default = "default_promotion_observation_window_events")]
    pub observation_window_events: usize,
    /// Maximum allowed promoted-only detection rate across the observation window.
    #[serde(default = "default_promotion_max_promoted_only_rate")]
    pub max_promoted_only_rate: f64,
    /// Maximum allowed rate of fallback detections that the promoted detector misses.
    #[serde(default = "default_promotion_max_fallback_recovery_rate")]
    pub max_fallback_recovery_rate: f64,
    /// ADVISORY ONLY. Recorded as the reference point for the non-gating
    /// `detect_latency_budget` observation on the promotion artifact; no
    /// promotion is ever rolled back for exceeding it. Same wall-clock
    /// measurement problem, and same reasons for keeping the key, as
    /// [`CanaryConfig::max_detect_latency_us`].
    #[serde(default = "default_promotion_max_detect_latency_us")]
    pub max_detect_latency_us: u64,
    /// Maximum allowed promoted detection volume across the observation window.
    #[serde(default = "default_promotion_max_total_detections")]
    pub max_total_detections: usize,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            slot_id: default_canary_slot_id(),
            strategy_id: None,
            observation_window_events: default_canary_observation_window_events(),
            max_candidate_only_rate: default_canary_max_candidate_only_rate(),
            max_baseline_miss_rate: default_canary_max_baseline_miss_rate(),
            max_detect_latency_us: default_canary_max_detect_latency_us(),
            max_total_detections: default_canary_max_total_detections(),
        }
    }
}

impl Default for PromotionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_id: default_promotion_window_id(),
            strategy_id: None,
            observation_window_events: default_promotion_observation_window_events(),
            max_promoted_only_rate: default_promotion_max_promoted_only_rate(),
            max_fallback_recovery_rate: default_promotion_max_fallback_recovery_rate(),
            max_detect_latency_us: default_promotion_max_detect_latency_us(),
            max_total_detections: default_promotion_max_total_detections(),
        }
    }
}
