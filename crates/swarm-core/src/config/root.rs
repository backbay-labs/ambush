use super::*;

/// Top-level repository-owned configuration for the v1 Rust runtime slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmConfig {
    /// Explicit schema version for the repository-owned config contract.
    pub schema_version: u32,
    /// Human-readable configuration name.
    pub name: String,
    /// Human-readable configuration description.
    pub description: String,
    /// Runtime settings for the critical lane.
    pub runtime: RuntimeSettings,
    /// Detector tuning for the fast path.
    pub detection: DetectionConfig,
    /// Pheromone substrate tuning.
    pub pheromone: PheromoneConfig,
    /// Deterministic live-response policy settings.
    pub policy: PolicyConfig,
    /// Configured response adapter selection for real side effects.
    #[serde(default)]
    pub response_adapter: ResponseAdapterConfig,
    /// Optional finding forwarder for external SIEM/SOAR ingestion.
    #[serde(default)]
    pub siem_forward: Option<SiemForwardConfig>,
    /// Named notification channels for finding-based alert delivery.
    #[serde(default)]
    pub notification_channels: BTreeMap<String, NotificationChannelConfig>,
    /// Finding-routing rules applied to notification channel delivery.
    #[serde(default)]
    pub notification_routing: NotificationRoutingConfig,
    /// Audit and replay storage settings.
    #[serde(default)]
    pub audit: AuditConfig,
    /// Async investigation settings layered on top of the hot path.
    #[serde(default)]
    pub investigation: InvestigationConfig,
    /// Correlation settings for assembling reviewable incidents.
    #[serde(default)]
    pub correlation: CorrelationConfig,
    /// Bounded live canary settings for verified candidate detectors.
    #[serde(default)]
    pub canary: CanaryConfig,
    /// Controlled production-promotion settings for canary-approved detectors.
    #[serde(default)]
    pub promotion: PromotionConfig,
    /// Repo-owned evolution settings for Kitten orchestration and drift detection.
    #[serde(default)]
    pub evolution: EvolutionConfig,
    /// Repo-owned deception settings for the runtime Calico lane.
    #[serde(default)]
    pub deception: DeceptionConfig,
    /// Repo-owned durable memory settings for the Sphinx knowledge graph.
    #[serde(default)]
    pub memory: MemoryConfig,
    /// Repo-owned durable identity settings for runtime agents.
    #[serde(default)]
    pub identity: IdentityConfig,
    /// Versioned platform read API settings.
    #[serde(default)]
    pub platform_api: PlatformApiConfig,
    /// Local authenticated operator-surface settings.
    #[serde(default, rename = "operator_surface")]
    pub operator: OperatorSurfaceConfig,
    /// Optional shared TLS settings for both HTTP serve surfaces.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

/// Whether the runtime simulates or executes live response actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    DetectOnly,
    LiveResponse,
}

/// Runtime-wide degradation ladder layered on top of the configured runtime mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDegradationLevel {
    Full,
    DetectOnly,
    ReadOnly,
    EmergencyDrain,
}

impl RuntimeDegradationLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::DetectOnly => "detect_only",
            Self::ReadOnly => "read_only",
            Self::EmergencyDrain => "emergency_drain",
        }
    }

    pub fn accepts_ingest(self) -> bool {
        matches!(self, Self::Full | Self::DetectOnly)
    }

    pub fn allows_detection(self) -> bool {
        matches!(self, Self::Full | Self::DetectOnly)
    }

    pub fn allows_live_response(self, configured_mode: RuntimeMode) -> bool {
        configured_mode == RuntimeMode::LiveResponse && matches!(self, Self::Full)
    }

    pub fn allows_artifact_writes(self) -> bool {
        matches!(self, Self::Full | Self::DetectOnly)
    }

    pub fn drains_ingest(self) -> bool {
        matches!(self, Self::EmergencyDrain)
    }

    pub fn operator_read_surfaces_ready(self) -> bool {
        true
    }

    pub fn ready(self) -> bool {
        matches!(self, Self::Full | Self::DetectOnly)
    }
}
