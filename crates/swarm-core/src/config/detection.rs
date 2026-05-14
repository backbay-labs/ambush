use super::*;

/// Detector-specific tuning for the first concrete strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionConfig {
    pub strategy: String,
    #[serde(default)]
    pub strategies: Vec<String>,
    pub high_confidence_threshold: f64,
    pub medium_confidence_threshold: f64,
    #[serde(default)]
    pub profiles: DetectorProfilesConfig,
}

impl DetectionConfig {
    pub fn active_strategies(&self) -> Vec<String> {
        if self.strategies.is_empty() {
            vec![self.strategy.clone()]
        } else {
            self.strategies.clone()
        }
    }

    pub fn validate_rollout_strategy_id(
        &self,
        field: &'static str,
        strategy_id: Option<&str>,
    ) -> Result<Option<String>, ConfigValidationError> {
        let Some(strategy_id) = strategy_id else {
            return Ok(None);
        };

        let strategy_id = strategy_id.trim();
        if strategy_id.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field,
                reason: "must not be empty when provided".to_string(),
            });
        }

        if !self
            .active_strategies()
            .iter()
            .any(|entry| entry == strategy_id)
        {
            return Err(ConfigValidationError::InvalidField {
                field,
                reason: format!(
                    "must match one of detection.active_strategies(): {}",
                    self.active_strategies().join(", ")
                ),
            });
        }

        Ok(Some(strategy_id.to_string()))
    }

    pub fn resolve_rollout_strategy_id(
        &self,
        field: &'static str,
        strategy_id: Option<&str>,
        require_explicit_in_multi_strategy: bool,
    ) -> Result<String, ConfigValidationError> {
        if let Some(strategy_id) = self.validate_rollout_strategy_id(field, strategy_id)? {
            return Ok(strategy_id);
        }

        let active = self.active_strategies();
        if active.len() == 1 {
            return Ok(active[0].clone());
        }

        let reason = if require_explicit_in_multi_strategy {
            format!(
                "is required when multiple detection.strategies are active: {}",
                active.join(", ")
            )
        } else {
            format!(
                "could not be resolved because multiple detection.strategies are active: {}",
                active.join(", ")
            )
        };
        Err(ConfigValidationError::InvalidField { field, reason })
    }
}

/// Optional raw detector profile configuration payloads keyed by strategy family.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectorProfilesConfig {
    pub suspicious_process_tree: Option<serde_json::Value>,
    pub kill_chain_sequence: Option<serde_json::Value>,
    pub fileless_execution: Option<serde_json::Value>,
    pub behavioral_anomaly: Option<serde_json::Value>,
    pub dns_exfiltration: Option<serde_json::Value>,
    pub lateral_movement: Option<serde_json::Value>,
    pub credential_access: Option<serde_json::Value>,
    pub suspicious_scripting: Option<serde_json::Value>,
    pub persistence: Option<serde_json::Value>,
    pub supply_chain: Option<serde_json::Value>,
    pub network_connect: Option<serde_json::Value>,
    pub infrastructure_anomaly: Option<serde_json::Value>,
    pub cloudtrail: Option<serde_json::Value>,
    pub kubernetes_audit: Option<serde_json::Value>,
}
