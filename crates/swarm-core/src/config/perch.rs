//! `PerchBridgeConfig` — the `perch` block on `SwarmConfig`.
//!
//! # Why every field is `#[serde(default)]`
//!
//! `SwarmConfig` is `#[serde(deny_unknown_fields)]` (`config/root.rs`), so a
//! `perch` block is a typed field addition and not a free key. And
//! `ContainmentSettings` already documents the reason every field inside such a
//! block must default (`config/runtime.rs`):
//!
//! > `rulesets/default.yaml` does NOT set it, and cannot: that file is digest-signed by
//! > `rulesets/default.yaml.sig.json` and the signing key is not in the repository, so adding a
//! > key to it fails its own load gate. Every field here is `#[serde(default)]` for that reason --
//! > the shipped ruleset keeps loading, and a deployment adds the block to its own config.
//!
//! **`swarm-core` may gain this field and must never gain a dependency:** a
//! transport named by `swarm-core` fails `tools/check-workspace-layering.sh`
//! RULE 1 for all three TCB crates at once. These are pure serde types over
//! `String`/`u64`/`bool`/`BTreeMap`, validated with the crate's own
//! [`ConfigValidationError`]. The bridge crate that consumes them
//! (`swarm-perch-bridge`) sits strictly downstream and is never named here.

use super::*;

/// The twelve serde names of the standard [`ThreatClass`] taxonomy, in
/// `swarm_runtime::escalation::standard_threat_classes()` order.
///
/// Pinned here because `swarm-core` cannot call into `swarm-runtime`
/// (layering); a `swarm-runtime` test asserts the two lists agree, so the pin
/// cannot drift from the runtime's own enumeration.
pub const STANDARD_THREAT_CLASS_SLUGS: [&str; 12] = [
    "lateral_movement",
    "data_exfiltration",
    "privilege_escalation",
    "command_and_control",
    "initial_access",
    "persistence",
    "supply_chain",
    "defense_evasion",
    "credential_access",
    "discovery",
    "execution",
    "impact",
];

/// The `perch` block: how the daemon's evidence reaches the operator console's relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerchBridgeConfig {
    /// Defaults to **false**. A daemon that gains the bridge must opt in: the bridge holds
    /// `AdminChannels` on a relay and writes to a colony's record, and neither should arrive by
    /// upgrade.
    #[serde(default)]
    pub enabled: bool,

    /// The relay's WebSocket URL (`ws://` or `wss://`). Required when `enabled`.
    #[serde(default)]
    pub relay_url: String,

    /// Environment variable holding 32 bytes of hex, the root of the bridge's key derivation
    /// (00-DECISIONS D-FC-1). Unset or short: the bridge refuses to start. Same shape as
    /// `OperatorPrincipalConfig.token_env`.
    #[serde(default = "default_nostr_seed_env")]
    pub nostr_seed_env: String,

    /// Environment variable holding the NIP-OA owner attestation tag, as JSON.
    ///
    /// Absent is legal and HALVES the relay quota: without an owner attestation the relay
    /// applies its human per-minute message budget (60) rather than the agent budget (120).
    /// At 1 Hz the pacer spends 60/min, so 60 is 100% of budget with zero head room. Startup
    /// logs the consequence by name.
    #[serde(default)]
    pub auth_tag_env: Option<String>,

    /// MUST resolve outside the repository. `tools/check-worktree-clean.sh` runs `if: always()`
    /// after the CI test job and uses `find` because it is immune to `.gitignore` and does see
    /// empty directories; the bridge refuses a spool root under the workspace at open.
    #[serde(default)]
    pub spool_dir: String,

    /// Byte budget per **disk-spooled** stream (evidence, alarm). The telemetry stream is
    /// memory-only at depth 1 per key.
    #[serde(default = "default_spool_max_bytes")]
    pub spool_max_bytes: u64,

    /// Segment roll size. 32 segments per 256 MiB budget.
    #[serde(default = "default_segment_bytes")]
    pub segment_bytes: u64,

    /// The pacer's tick, `PERCH_PUBLISH_TICK`.
    #[serde(default = "default_publish_tick_ms")]
    pub publish_tick_ms: u64,

    /// The frame cap, `PERCH_FRAME_MAX_BYTES`.
    #[serde(default = "default_frame_max_bytes")]
    pub frame_max_bytes: usize,

    /// Escalation-card heartbeat (a coalescer setting; consumed once the escalation producer lands).
    #[serde(default = "default_escalation_heartbeat_ms")]
    pub escalation_heartbeat_ms: i64,

    /// Alarm heartbeat (consumed once the alarm producers land).
    #[serde(default = "default_alarm_heartbeat_ms")]
    pub alarm_heartbeat_ms: i64,

    /// Per-minute burst ceiling on the alarm identity.
    #[serde(default = "default_alarm_burst_per_min")]
    pub alarm_burst_per_min: u32,

    /// Ticks of silence on a stream holding a pending gap before the gap is flushed.
    #[serde(default = "default_gap_flush_ticks")]
    pub gap_flush_ticks: u32,

    /// `created_at` vs `emitted_at_ms` disagreement, in ticks, past which a card is late-published.
    #[serde(default = "default_late_published_ticks")]
    pub late_published_ticks: i64,

    /// Slack against the relay's ±900 s `created_at` window for a frame already in flight.
    #[serde(default = "default_publish_window_margin_secs")]
    pub publish_window_margin_secs: i64,

    /// Case-channel TTL in seconds, per threat class, with a `default` key. Written into the
    /// `ttl` tag of the kind:9007 create event.
    #[serde(default)]
    pub case_ttl_seconds: BTreeMap<String, i32>,

    /// The twelve standing threat-class channel UUIDs, keyed by the class slug. Required when
    /// `enabled`; validated at load against [`STANDARD_THREAT_CLASS_SLUGS`]. A missing class is a
    /// config error, not a runtime surprise -- `ThreatClass::Custom(String)` exists and a
    /// `Custom` finding with no lane must land somewhere deliberate rather than nowhere.
    #[serde(default)]
    pub lane_channels: BTreeMap<String, String>,
}

fn default_nostr_seed_env() -> String {
    "PERCH_BRIDGE_NOSTR_SEED".to_string()
}
fn default_spool_max_bytes() -> u64 {
    268_435_456
}
fn default_segment_bytes() -> u64 {
    8_388_608
}
fn default_publish_tick_ms() -> u64 {
    1_000
}
fn default_frame_max_bytes() -> usize {
    65_536
}
fn default_escalation_heartbeat_ms() -> i64 {
    60_000
}
fn default_alarm_heartbeat_ms() -> i64 {
    60_000
}
fn default_alarm_burst_per_min() -> u32 {
    40
}
fn default_gap_flush_ticks() -> u32 {
    3
}
fn default_late_published_ticks() -> i64 {
    2
}
fn default_publish_window_margin_secs() -> i64 {
    120
}

impl Default for PerchBridgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            relay_url: String::new(),
            nostr_seed_env: default_nostr_seed_env(),
            auth_tag_env: None,
            spool_dir: String::new(),
            spool_max_bytes: default_spool_max_bytes(),
            segment_bytes: default_segment_bytes(),
            publish_tick_ms: default_publish_tick_ms(),
            frame_max_bytes: default_frame_max_bytes(),
            escalation_heartbeat_ms: default_escalation_heartbeat_ms(),
            alarm_heartbeat_ms: default_alarm_heartbeat_ms(),
            alarm_burst_per_min: default_alarm_burst_per_min(),
            gap_flush_ticks: default_gap_flush_ticks(),
            late_published_ticks: default_late_published_ticks(),
            publish_window_margin_secs: default_publish_window_margin_secs(),
            case_ttl_seconds: BTreeMap::new(),
            lane_channels: BTreeMap::new(),
        }
    }
}

fn invalid(field: &'static str, reason: impl Into<String>) -> ConfigValidationError {
    ConfigValidationError::InvalidField {
        field,
        reason: reason.into(),
    }
}

impl PerchBridgeConfig {
    /// Validated at config load, alongside every other `validate()` in
    /// `config/validation.rs`. A disabled block is always valid.
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if !self.enabled {
            return Ok(());
        }
        let relay = self.relay_url.trim();
        if !(relay.starts_with("ws://") || relay.starts_with("wss://")) {
            return Err(invalid("perch.relay_url", "must be a ws:// or wss:// URL"));
        }
        if self.spool_dir.trim().is_empty() {
            return Err(invalid(
                "perch.spool_dir",
                "must be set when perch is enabled",
            ));
        }
        if self.publish_tick_ms == 0
            || self.frame_max_bytes == 0
            || self.segment_bytes == 0
            || self.spool_max_bytes < self.segment_bytes
        {
            return Err(invalid(
                "perch",
                "tick, frame and segment sizes must be positive and spool_max_bytes >= segment_bytes",
            ));
        }
        if !self.case_ttl_seconds.contains_key("default") {
            return Err(invalid(
                "perch.case_ttl_seconds",
                "must carry a `default` key",
            ));
        }
        for class in STANDARD_THREAT_CLASS_SLUGS {
            match self.lane_channels.get(class) {
                Some(value) if uuid::Uuid::parse_str(value).is_ok() => {}
                Some(_) => {
                    return Err(invalid(
                        "perch.lane_channels",
                        format!("`{class}` is not a UUID"),
                    ));
                }
                None => {
                    return Err(invalid(
                        "perch.lane_channels",
                        format!("missing lane for threat class `{class}`"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// The lane channel configured for a threat class, or `None` for a class with no lane.
    ///
    /// The class is mapped to its slug through its serde form, so the twelve standard classes
    /// resolve through the same spelling the config file uses; a `Custom(_)` class serializes
    /// as an object and therefore yields `None`, as does a lane value that is not a UUID.
    pub fn lane_channel(&self, class: &ThreatClass) -> Option<uuid::Uuid> {
        let slug = serde_json::to_value(class).ok()?;
        let slug = slug.as_str()?;
        let value = self.lane_channels.get(slug)?;
        uuid::Uuid::parse_str(value).ok()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod perch_config_tests {
    use super::*;

    #[test]
    fn the_shipped_ruleset_still_loads_with_no_perch_block() {
        let cfg: PerchBridgeConfig = serde_yaml::from_str("{}").unwrap();
        assert!(!cfg.enabled);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn an_enabled_block_needs_all_twelve_lanes() {
        let mut cfg = PerchBridgeConfig {
            enabled: true,
            relay_url: "ws://localhost:3000".into(),
            spool_dir: "/tmp/x".into(),
            ..PerchBridgeConfig::default()
        };
        cfg.case_ttl_seconds.insert("default".into(), 2_592_000);
        assert!(cfg.validate().is_err());
        for slug in STANDARD_THREAT_CLASS_SLUGS {
            cfg.lane_channels.insert(
                slug.to_string(),
                "154eea36-c787-4bf7-9c84-4424b0184395".into(),
            );
        }
        assert!(cfg.validate().is_ok());
        cfg.lane_channels
            .insert("impact".into(), "not-a-uuid".into());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn watch_channel_is_not_a_field() {
        let err = serde_yaml::from_str::<PerchBridgeConfig>("watch_channel: abc\n").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn lane_channel_resolves_standard_classes_and_never_a_custom_one() {
        let mut cfg = PerchBridgeConfig::default();
        cfg.lane_channels.insert(
            "execution".into(),
            "154eea36-c787-4bf7-9c84-4424b0184395".into(),
        );
        assert_eq!(
            cfg.lane_channel(&ThreatClass::Execution),
            Some(uuid::Uuid::parse_str("154eea36-c787-4bf7-9c84-4424b0184395").unwrap())
        );
        assert_eq!(cfg.lane_channel(&ThreatClass::Impact), None);
        assert_eq!(
            cfg.lane_channel(&ThreatClass::Custom("execution".into())),
            None
        );
    }

    #[test]
    fn a_relay_url_that_is_not_a_websocket_is_refused() {
        let mut cfg = PerchBridgeConfig {
            enabled: true,
            relay_url: "http://localhost:3000".into(),
            spool_dir: "/tmp/x".into(),
            ..PerchBridgeConfig::default()
        };
        cfg.case_ttl_seconds.insert("default".into(), 1);
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("perch.relay_url"), "{err}");
    }
}
