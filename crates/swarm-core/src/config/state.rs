use super::*;

/// Repo-owned deception settings for the runtime Calico lane.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeceptionConfig {
    /// Whether the runtime should register Calico and manage baseline deception assets.
    pub enabled: bool,
    /// Root directory where durable Calico lifecycle snapshots are persisted.
    #[serde(default = "default_deception_lifecycle_results_dir")]
    pub lifecycle_results_dir: String,
    /// Maximum lifetime for one active decoy generation before Calico rotates it.
    #[serde(default = "default_deception_rotation_interval_secs")]
    pub rotation_interval_secs: u64,
    /// Grace window a rotated decoy remains in the registry before cleanup.
    #[serde(default = "default_deception_cleanup_grace_secs")]
    pub cleanup_grace_secs: u64,
    /// Blend weight used when deception interactions boost Kitten proposal fitness.
    #[serde(default = "default_deception_interaction_fitness_weight")]
    pub interaction_fitness_weight: f64,
    /// Typed repo-owned playbook describing decoys, placement, and monitoring rules.
    pub playbook: DeceptionPlaybookConfig,
}

/// Ordered deception entries the runtime Calico lane deploys and monitors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeceptionPlaybookConfig {
    /// Named deception entries evaluated in order.
    pub entries: Vec<DeceptionPlaybookEntry>,
}

/// One deception asset definition in the repo-owned playbook.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeceptionPlaybookEntry {
    /// Stable entry identifier used in audit and runtime evidence.
    pub name: String,
    /// Decoy asset type routed through `ResponseAction::DeployDecoy`.
    pub decoy_type: String,
    /// Zone or segment where the decoy should be placed.
    pub target_zone: String,
    /// Human-readable legitimate-host profile the decoy emulates.
    pub host_profile: String,
    /// Placement strategy for the asset.
    #[serde(default)]
    pub placement_strategy: DeceptionPlacementStrategy,
    /// Monitoring rules used to treat interaction as high-confidence detection.
    #[serde(default)]
    pub monitoring: DeceptionMonitoringConfig,
}

/// Placement strategy for one deception asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeceptionPlacementStrategy {
    #[default]
    Baseline,
    HighValuePath,
    NetworkSegment,
    InvestigationZone,
}

/// Monitoring rules associated with one deception asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeceptionMonitoringConfig {
    /// File-system tripwires that should never be touched by legitimate activity.
    pub file_paths: Vec<String>,
    /// Honeypot ports that indicate suspicious network access when contacted.
    pub honeypot_ports: Vec<u16>,
    /// Canary credentials whose use indicates suspicious activity.
    pub canary_credentials: Vec<String>,
    /// Threat class used when this monitoring rule fires.
    #[serde(default = "default_deception_monitoring_threat_class")]
    pub threat_class: ThreatClass,
    /// Severity attached to emitted Calico findings.
    #[serde(default = "default_deception_monitoring_severity")]
    pub severity: Severity,
    /// Confidence attached to emitted Calico findings. Must stay high-fidelity.
    #[serde(default = "default_deception_monitoring_confidence")]
    pub confidence: f64,
}

/// Repo-owned Sphinx memory settings for the durable knowledge graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryConfig {
    /// Whether the runtime should register Sphinx and persist graph state.
    #[serde(default)]
    pub enabled: bool,
    /// Root directory for the typed knowledge-graph store.
    #[serde(default = "default_memory_knowledge_graph_results_dir")]
    pub knowledge_graph_results_dir: String,
    /// Correlation window for temporal graph edges between related engagements.
    #[serde(default = "default_memory_temporal_window_secs")]
    pub temporal_window_secs: u64,
    /// Retention window in days before stale graph records are garbage-collected.
    #[serde(default = "default_memory_knowledge_retention_days")]
    pub knowledge_retention_days: u64,
}

/// Repo-owned durable identity settings for runtime agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Directory where runtime agent Ed25519 seeds are persisted.
    #[serde(default = "default_agent_key_dir")]
    pub agent_key_dir: String,
    /// Directory where identity registry snapshots and continuity proofs are persisted.
    #[serde(default = "default_identity_registry_dir")]
    pub registry_dir: String,
}

impl MemoryConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_non_empty(
            "memory.knowledge_graph_results_dir",
            &self.knowledge_graph_results_dir,
        )?;
        if self.temporal_window_secs == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "memory.temporal_window_secs",
                reason: "must be greater than zero when memory is enabled".to_string(),
            });
        }
        if self.knowledge_retention_days == 0 {
            return Err(ConfigValidationError::InvalidField {
                field: "memory.knowledge_retention_days",
                reason: "must be greater than zero when memory is enabled".to_string(),
            });
        }
        Ok(())
    }
}

impl DeceptionConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.enabled {
            validate_non_empty(
                "deception.lifecycle_results_dir",
                &self.lifecycle_results_dir,
            )?;
            if self.rotation_interval_secs == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "deception.rotation_interval_secs",
                    reason: "must be greater than zero when deception is enabled".to_string(),
                });
            }
            if self.cleanup_grace_secs == 0 {
                return Err(ConfigValidationError::InvalidField {
                    field: "deception.cleanup_grace_secs",
                    reason: "must be greater than zero when deception is enabled".to_string(),
                });
            }
            if !(0.0 < self.interaction_fitness_weight && self.interaction_fitness_weight <= 1.0) {
                return Err(ConfigValidationError::InvalidField {
                    field: "deception.interaction_fitness_weight",
                    reason: "must be greater than zero and at most 1.0 when deception is enabled"
                        .to_string(),
                });
            }
        }
        self.playbook.validate(self.enabled)
    }
}

impl DeceptionPlaybookConfig {
    pub(super) fn validate(&self, enabled: bool) -> Result<(), ConfigValidationError> {
        if enabled && self.entries.is_empty() {
            return Err(ConfigValidationError::InvalidField {
                field: "deception.playbook.entries",
                reason: "must contain at least one entry when deception is enabled".to_string(),
            });
        }

        let mut names = BTreeSet::new();
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate(index)?;
            if !names.insert(entry.name.clone()) {
                return Err(ConfigValidationError::InvalidField {
                    field: "deception.playbook.entries.name",
                    reason: format!("duplicate playbook entry `{}`", entry.name),
                });
            }
        }

        Ok(())
    }
}

impl DeceptionPlaybookEntry {
    pub(super) fn validate(&self, index: usize) -> Result<(), ConfigValidationError> {
        validate_non_empty("deception.playbook.entries.name", &self.name)?;
        validate_non_empty("deception.playbook.entries.decoy_type", &self.decoy_type)?;
        validate_non_empty("deception.playbook.entries.target_zone", &self.target_zone)?;
        validate_non_empty(
            "deception.playbook.entries.host_profile",
            &self.host_profile,
        )?;
        self.monitoring.validate(index)
    }
}

impl DeceptionMonitoringConfig {
    pub(super) fn validate(&self, index: usize) -> Result<(), ConfigValidationError> {
        if self.file_paths.is_empty()
            && self.honeypot_ports.is_empty()
            && self.canary_credentials.is_empty()
        {
            return Err(ConfigValidationError::InvalidField {
                field: "deception.playbook.entries.monitoring",
                reason: format!(
                    "entry {index} must define at least one monitored file path, honeypot port, or canary credential"
                ),
            });
        }
        for path in &self.file_paths {
            validate_non_empty("deception.playbook.entries.monitoring.file_paths", path)?;
        }
        for credential in &self.canary_credentials {
            validate_non_empty(
                "deception.playbook.entries.monitoring.canary_credentials",
                credential,
            )?;
        }
        if self.honeypot_ports.contains(&0) {
            return Err(ConfigValidationError::InvalidField {
                field: "deception.playbook.entries.monitoring.honeypot_ports",
                reason: "must contain only positive port values".to_string(),
            });
        }
        if !(0.95..=1.0).contains(&self.confidence) {
            return Err(ConfigValidationError::InvalidField {
                field: "deception.playbook.entries.monitoring.confidence",
                reason: "must be between 0.95 and 1.0".to_string(),
            });
        }
        Ok(())
    }
}

impl IdentityConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_non_empty("identity.agent_key_dir", &self.agent_key_dir)?;
        validate_non_empty("identity.registry_dir", &self.registry_dir)
    }
}

impl Default for DeceptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lifecycle_results_dir: default_deception_lifecycle_results_dir(),
            rotation_interval_secs: default_deception_rotation_interval_secs(),
            cleanup_grace_secs: default_deception_cleanup_grace_secs(),
            interaction_fitness_weight: default_deception_interaction_fitness_weight(),
            playbook: DeceptionPlaybookConfig::default(),
        }
    }
}

impl Default for DeceptionMonitoringConfig {
    fn default() -> Self {
        Self {
            file_paths: Vec::new(),
            honeypot_ports: Vec::new(),
            canary_credentials: Vec::new(),
            threat_class: default_deception_monitoring_threat_class(),
            severity: default_deception_monitoring_severity(),
            confidence: default_deception_monitoring_confidence(),
        }
    }
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            knowledge_graph_results_dir: default_memory_knowledge_graph_results_dir(),
            temporal_window_secs: default_memory_temporal_window_secs(),
            knowledge_retention_days: default_memory_knowledge_retention_days(),
        }
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            agent_key_dir: default_agent_key_dir(),
            registry_dir: default_identity_registry_dir(),
        }
    }
}
