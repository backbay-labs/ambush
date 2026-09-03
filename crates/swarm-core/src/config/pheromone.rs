use super::*;

/// Pheromone substrate tuning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PheromoneConfig {
    /// Default half-life for pheromone decay (seconds).
    pub default_half_life_secs: f64,
    /// Strength below which pheromones are considered evaporated.
    pub evaporation_threshold: f64,
    /// Minimum distinct sources for concentration escalation.
    pub min_sources_for_escalation: usize,
    /// Strength threshold for alert mode transition.
    pub alert_threshold: f64,
    /// Strength threshold for incident mode transition.
    pub incident_threshold: f64,
    /// Cooldown dwell time before the runtime de-escalates back to normal mode.
    #[serde(default = "default_deescalation_cooldown_secs")]
    pub deescalation_cooldown_secs: i64,
    /// Deterministic playbook rules used by PounceAgent action selection.
    #[serde(default)]
    pub response_playbook: ResponsePlaybookConfig,
    /// Backend used to store and recover deposits.
    #[serde(default)]
    pub backend: PheromoneBackendConfig,
}

/// Deterministic action-selection rules for autonomous response.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponsePlaybookConfig {
    /// Ordered matching rules evaluated by PounceAgent.
    pub rules: Vec<ResponsePlaybookRule>,
}

/// One threat/severity/confidence band mapped to an ordered action sequence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlaybookRule {
    /// Threat class this rule applies to.
    pub threat_class: ThreatClass,
    /// Severity this rule applies to.
    pub severity: Severity,
    /// Inclusive lower confidence bound for the rule.
    pub min_confidence: f64,
    /// Inclusive upper confidence bound for the rule.
    pub max_confidence: f64,
    /// Ordered fallback response actions emitted when the rule matches and no
    /// branch-specific selector overrides them.
    #[serde(default)]
    pub actions: Vec<ResponseAction>,
    /// Ordered branch-specific action sequences evaluated after the base rule
    /// matches. The first matching branch wins.
    #[serde(default)]
    pub branches: Vec<ResponsePlaybookBranch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponsePlaybookBranchResolution {
    pub index: usize,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponsePlaybookRuleResolution {
    pub rule_index: usize,
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub min_confidence: f64,
    pub max_confidence: f64,
    pub actions: Vec<ResponseAction>,
    pub branch: Option<ResponsePlaybookBranchResolution>,
}

/// One ordered conditional branch under a matched response playbook rule.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponsePlaybookBranch {
    /// Optional stable branch label for evidence and operator review.
    pub name: Option<String>,
    /// Additional bounded selectors evaluated against the live runtime context.
    pub when: ResponsePlaybookCondition,
    /// Ordered actions emitted when this branch matches.
    pub actions: Vec<ResponseAction>,
}

/// Additional bounded selectors for one playbook branch.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponsePlaybookCondition {
    /// Optional threat-class override or refinement for this branch.
    pub threat_class: Option<ThreatClass>,
    /// Inclusive lower severity bound.
    pub min_severity: Option<Severity>,
    /// Inclusive upper severity bound.
    pub max_severity: Option<Severity>,
    /// Inclusive lower confidence bound.
    pub min_confidence: Option<f64>,
    /// Inclusive upper confidence bound.
    pub max_confidence: Option<f64>,
    /// Optional runtime modes where this branch is allowed to emit actions.
    #[serde(default)]
    pub modes: Vec<SwarmMode>,
}

impl ResponsePlaybookCondition {
    pub fn matches(
        &self,
        threat_class: ThreatClass,
        severity: Severity,
        confidence: f64,
        mode: SwarmMode,
    ) -> bool {
        if let Some(expected) = self.threat_class.as_ref()
            && expected != &threat_class
        {
            return false;
        }
        if let Some(min_severity) = self.min_severity
            && severity < min_severity
        {
            return false;
        }
        if let Some(max_severity) = self.max_severity
            && severity > max_severity
        {
            return false;
        }
        if let Some(min_confidence) = self.min_confidence
            && confidence < min_confidence
        {
            return false;
        }
        if let Some(max_confidence) = self.max_confidence
            && confidence > max_confidence
        {
            return false;
        }
        if !self.modes.is_empty() && !self.modes.contains(&mode) {
            return false;
        }

        true
    }
}

impl ResponsePlaybookRule {
    pub fn matches(&self, threat_class: &ThreatClass, severity: Severity, confidence: f64) -> bool {
        self.threat_class == *threat_class
            && self.severity == severity
            && confidence >= self.min_confidence
            && confidence <= self.max_confidence
    }

    pub fn resolve(
        &self,
        threat_class: &ThreatClass,
        severity: Severity,
        confidence: f64,
        mode: SwarmMode,
    ) -> Option<ResponsePlaybookRuleResolution> {
        if !self.matches(threat_class, severity, confidence) {
            return None;
        }

        self.resolve_with_index(0, threat_class, severity, confidence, mode)
    }

    pub fn resolve_with_index(
        &self,
        rule_index: usize,
        threat_class: &ThreatClass,
        severity: Severity,
        confidence: f64,
        mode: SwarmMode,
    ) -> Option<ResponsePlaybookRuleResolution> {
        if !self.matches(threat_class, severity, confidence) {
            return None;
        }

        for (index, branch) in self.branches.iter().enumerate() {
            if branch
                .when
                .matches(threat_class.clone(), severity, confidence, mode)
            {
                return Some(ResponsePlaybookRuleResolution {
                    rule_index,
                    threat_class: self.threat_class.clone(),
                    severity: self.severity,
                    min_confidence: self.min_confidence,
                    max_confidence: self.max_confidence,
                    actions: branch.actions.clone(),
                    branch: Some(ResponsePlaybookBranchResolution {
                        index,
                        name: branch.name.clone(),
                    }),
                });
            }
        }

        if self.actions.is_empty() {
            return None;
        }

        Some(ResponsePlaybookRuleResolution {
            rule_index,
            threat_class: self.threat_class.clone(),
            severity: self.severity,
            min_confidence: self.min_confidence,
            max_confidence: self.max_confidence,
            actions: self.actions.clone(),
            branch: None,
        })
    }
}

impl ResponsePlaybookConfig {
    pub fn resolve(
        &self,
        threat_class: &ThreatClass,
        severity: Severity,
        confidence: f64,
        mode: SwarmMode,
    ) -> Option<ResponsePlaybookRuleResolution> {
        self.rules.iter().enumerate().find_map(|(index, rule)| {
            rule.resolve_with_index(index, threat_class, severity, confidence, mode)
        })
    }
}

/// Pheromone substrate backend selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PheromoneBackendConfig {
    #[default]
    InMemory,
    LocalJournal {
        path: String,
    },
    JetStream {
        url: String,
        #[serde(default = "default_nats_connect_timeout_ms")]
        connect_timeout_ms: u64,
        #[serde(default = "default_jetstream_gc_page_size")]
        gc_page_size: usize,
    },
}

impl PheromoneBackendConfig {
    pub fn is_durable(&self) -> bool {
        matches!(self, Self::LocalJournal { .. } | Self::JetStream { .. })
    }
}

impl ResponsePlaybookConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        for (index, rule) in self.rules.iter().enumerate() {
            rule.validate(index)?;
        }
        Ok(())
    }
}

impl ResponsePlaybookRule {
    pub(super) fn validate(&self, index: usize) -> Result<(), ConfigValidationError> {
        if !(0.0..=1.0).contains(&self.min_confidence) {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!("rule {index} min_confidence must be between 0.0 and 1.0"),
            });
        }
        if !(0.0..=1.0).contains(&self.max_confidence) {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!("rule {index} max_confidence must be between 0.0 and 1.0"),
            });
        }
        if self.max_confidence < self.min_confidence {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {index} max_confidence must be greater than or equal to min_confidence"
                ),
            });
        }
        if self.actions.is_empty() && self.branches.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {index} must declare fallback actions or at least one conditional branch"
                ),
            });
        }
        let mut branch_names = BTreeSet::new();
        for (branch_index, branch) in self.branches.iter().enumerate() {
            branch.validate(index, branch_index)?;
            if let Some(name) = &branch.name {
                let normalized = name.trim().to_string();
                if !branch_names.insert(normalized.clone()) {
                    return Err(ConfigValidationError::InvalidField {
                        field: "pheromone.response_playbook",
                        reason: format!(
                            "rule {index} declares duplicate branch name `{normalized}`"
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

impl ResponsePlaybookBranch {
    pub(super) fn validate(
        &self,
        rule_index: usize,
        branch_index: usize,
    ) -> Result<(), ConfigValidationError> {
        if let Some(name) = &self.name
            && name.trim().is_empty()
        {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!("rule {rule_index} branch {branch_index} name must not be empty"),
            });
        }
        if self.actions.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {rule_index} branch {branch_index} must declare at least one response action"
                ),
            });
        }
        self.when.validate(rule_index, branch_index)
    }
}

impl ResponsePlaybookCondition {
    pub(super) fn validate(
        &self,
        rule_index: usize,
        branch_index: usize,
    ) -> Result<(), ConfigValidationError> {
        if let Some(min_confidence) = self.min_confidence
            && !(0.0..=1.0).contains(&min_confidence)
        {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {rule_index} branch {branch_index} min_confidence must be between 0.0 and 1.0"
                ),
            });
        }
        if let Some(max_confidence) = self.max_confidence
            && !(0.0..=1.0).contains(&max_confidence)
        {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {rule_index} branch {branch_index} max_confidence must be between 0.0 and 1.0"
                ),
            });
        }
        if let (Some(min_confidence), Some(max_confidence)) =
            (self.min_confidence, self.max_confidence)
            && max_confidence < min_confidence
        {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {rule_index} branch {branch_index} max_confidence must be greater than or equal to min_confidence"
                ),
            });
        }
        if let (Some(min_severity), Some(max_severity)) = (self.min_severity, self.max_severity)
            && max_severity < min_severity
        {
            return Err(ConfigValidationError::InvalidField {
                field: "pheromone.response_playbook",
                reason: format!(
                    "rule {rule_index} branch {branch_index} max_severity must be greater than or equal to min_severity"
                ),
            });
        }

        Ok(())
    }
}
