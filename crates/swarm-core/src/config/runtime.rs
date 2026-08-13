use super::*;

/// Runtime settings for the hot path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSettings {
    /// Whether responses execute or remain dry-run.
    pub mode: RuntimeMode,
    /// Enable operator-facing demo endpoints such as replay injection and live event streaming.
    #[serde(default)]
    pub demo_mode: bool,
    /// Telemetry streams or subjects to subscribe to.
    pub telemetry_sources: Vec<TelemetrySourceConfig>,
    /// External threat-intelligence feeds that hydrate the substrate.
    #[serde(default)]
    pub threat_intel_feeds: Vec<ThreatIntelFeedConfig>,
    /// Maximum concurrent response executions.
    pub max_in_flight_actions: usize,
    /// Maximum time to wait for accepted ingest work to drain during shutdown.
    #[serde(default = "default_drain_timeout_ms")]
    pub drain_timeout_ms: u64,
    /// Require a durable substrate before live response can start.
    #[serde(default)]
    pub require_durable_live_response: bool,
    /// Readiness threshold for process heap pressure.
    #[serde(default = "default_max_heap_pressure")]
    pub max_heap_pressure: f64,
    /// Optional directory holding mounted secret files used by `@secret:` references.
    #[serde(default)]
    pub secret_dir: Option<String>,
    /// Runtime self-protection settings for debugger and library tamper checks.
    #[serde(default)]
    pub anti_tamper: RuntimeAntiTamperConfig,
    /// Bounded recent-event retention used by later sequence detectors.
    #[serde(default)]
    pub temporal_event_window: TemporalEventWindowConfig,
    /// Maximum time in milliseconds for a single agent tick before the dispatcher
    /// marks the agent Degraded and skips that cycle.
    #[serde(default = "default_agent_tick_timeout_ms")]
    pub agent_tick_timeout_ms: u64,
    /// Number of consecutive degraded dispatcher ticks TomAgent tolerates before
    /// escalating an agent to Failed.
    #[serde(default = "default_governance_degraded_tick_threshold")]
    pub governance_degraded_tick_threshold: usize,
    /// Maximum lifetime for pre-staged contingency leases that can be redeemed
    /// during quorum loss.
    #[serde(default = "default_partition_contingency_lease_ttl_ms")]
    pub partition_contingency_lease_ttl_ms: i64,
    /// Maximum number of distinct scoped destructive actions one contingency
    /// lease may authorize during a partition window.
    #[serde(default = "default_partition_contingency_blast_radius_cap")]
    pub partition_contingency_blast_radius_cap: usize,
    /// Maximum size in bytes for dead-letter journal files before rotation.
    /// When set, journals exceeding this size are renamed with a timestamp
    /// suffix and a fresh file is started. When `None` (default), no rotation.
    #[serde(default)]
    pub max_dead_letter_bytes: Option<u64>,
    /// Bounds and storage for reversible containment (QRT-01..03).
    #[serde(default)]
    pub containment: ContainmentSettings,
}

/// How long a containment may hold, how often expiry is checked, and where open
/// containments are recorded.
///
/// Separate from the flat runtime keys because these three only make sense
/// together: a TTL with nowhere to record the lease bounds nothing, and a sweep
/// interval with no TTL has nothing to sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentSettings {
    /// Maximum time a containment stays in effect before the sweep releases it.
    /// Must be strictly positive: this is the bound that makes autonomous
    /// containment acceptable.
    #[serde(default = "default_containment_lease_ttl_ms")]
    pub lease_ttl_ms: i64,
    /// How often expired leases are checked for. The worst-case time a
    /// containment outlives its TTL is therefore `lease_ttl_ms + this`.
    #[serde(default = "default_containment_sweep_interval_ms")]
    pub sweep_interval_ms: u64,
    /// Where open leases are persisted.
    ///
    /// `None` keeps them in memory only, which means a restart FORGETS every
    /// open containment and no sweep will ever release it -- the host stays
    /// contained until an operator intervenes. Acceptable for tests and
    /// `detect_only`; set a path for any deployment that enforces.
    ///
    /// `rulesets/default.yaml` does NOT set it, and cannot: that file is
    /// digest-signed by `rulesets/default.yaml.sig.json` and the signing key is
    /// not in the repository, so adding a key to it fails its own load gate.
    /// Every field here is `#[serde(default)]` for that reason -- the shipped
    /// ruleset keeps loading, and a deployment adds the block to its own config.
    /// See `docs/CONFIGURATION.md`.
    #[serde(default)]
    pub lease_store_path: Option<String>,
}

impl Default for ContainmentSettings {
    fn default() -> Self {
        Self {
            lease_ttl_ms: default_containment_lease_ttl_ms(),
            sweep_interval_ms: default_containment_sweep_interval_ms(),
            lease_store_path: None,
        }
    }
}

/// Bounded runtime-owned recent-event retention for temporal sequence matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemporalEventWindowConfig {
    /// Maximum age in milliseconds for retained telemetry.
    #[serde(default = "default_temporal_event_window_retention_ms")]
    pub retention_ms: i64,
    /// Maximum number of retained telemetry events across the shared window.
    #[serde(default = "default_temporal_event_window_max_events")]
    pub max_events: usize,
    /// Maximum span in milliseconds that one ordered predicate query may scan.
    #[serde(default = "default_temporal_event_window_max_match_span_ms")]
    pub max_match_span_ms: i64,
    /// Maximum number of ordered predicates one query may request.
    #[serde(default = "default_temporal_event_window_max_predicates_per_match")]
    pub max_predicates_per_match: usize,
}

/// Runtime self-protection settings for Linux anti-tamper monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAntiTamperConfig {
    /// Whether runtime anti-tamper monitoring is active.
    #[serde(default = "default_runtime_anti_tamper_enabled")]
    pub enabled: bool,
    /// Interval in milliseconds between anti-tamper checks.
    #[serde(default = "default_runtime_anti_tamper_check_interval_ms")]
    pub check_interval_ms: u64,
    /// Whether a live-response runtime should fail closed when tamper is detected.
    #[serde(default)]
    pub fail_closed_live_response: bool,
    /// Library path prefixes allowed to load after the initial runtime baseline.
    #[serde(default = "default_runtime_anti_tamper_allowed_library_prefixes")]
    pub allowed_library_prefixes: Vec<String>,
}

/// One configured telemetry source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySourceConfig {
    pub name: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub bridge: Option<TelemetryBridgeConfig>,
}

/// One configured external threat-intel feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ThreatIntelFeedConfig {
    Taxii {
        #[serde(flatten)]
        config: Box<TaxiiThreatIntelFeedConfig>,
    },
}

/// TAXII-backed threat-intel feed configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaxiiThreatIntelFeedConfig {
    pub name: String,
    pub collection_url: String,
    #[serde(default = "default_taxii_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default = "default_taxii_default_ttl_secs")]
    pub default_ttl_secs: i64,
}

impl Default for RuntimeAntiTamperConfig {
    fn default() -> Self {
        Self {
            enabled: default_runtime_anti_tamper_enabled(),
            check_interval_ms: default_runtime_anti_tamper_check_interval_ms(),
            fail_closed_live_response: false,
            allowed_library_prefixes: default_runtime_anti_tamper_allowed_library_prefixes(),
        }
    }
}

impl Default for TemporalEventWindowConfig {
    fn default() -> Self {
        Self {
            retention_ms: default_temporal_event_window_retention_ms(),
            max_events: default_temporal_event_window_max_events(),
            max_match_span_ms: default_temporal_event_window_max_match_span_ms(),
            max_predicates_per_match: default_temporal_event_window_max_predicates_per_match(),
        }
    }
}

fn default_taxii_poll_interval_ms() -> u64 {
    60_000
}

fn default_taxii_default_ttl_secs() -> i64 {
    86_400
}
