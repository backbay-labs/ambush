//! `PerchBridgeConfig` — the `perch` block on `SwarmConfig`.
//!
//! # Why every field is `#[serde(default)]`
//!
//! `SwarmConfig` is `#[serde(deny_unknown_fields)]` (`swarm-core/src/config/root.rs:4-6`), so a
//! `perch` block is a typed field addition and not a free key. And `ContainmentSettings` already
//! documents the reason every field inside such a block must default
//! (`swarm-core/src/config/runtime.rs:88-92`):
//!
//! > `rulesets/default.yaml` does NOT set it, and cannot: that file is digest-signed by
//! > `rulesets/default.yaml.sig.json` and the signing key is not in the repository, so adding a
//! > key to it fails its own load gate. Every field here is `#[serde(default)]` for that reason --
//! > the shipped ruleset keeps loading, and a deployment adds the block to its own config.
//!
//! This struct lives in `swarm-core` in the shipped tree (`config/perch.rs`, added to
//! `SwarmConfig` as `#[serde(default)] pub perch: PerchBridgeConfig`). It is mirrored here so the
//! skeleton reads as one crate. **`swarm-core` may gain this field and must never gain a
//! dependency:** a transport named by `swarm-core` fails
//! `tools/check-workspace-layering.sh` RULE 1 for all three TCB crates at once. These are pure
//! serde types over `String`/`u64`/`bool`/`BTreeMap`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerchBridgeConfig {
    /// Defaults to **false**. A daemon that gains this crate must opt in: the bridge holds
    /// `AdminChannels` on a relay and writes to a colony's record, and neither should arrive by
    /// upgrade.
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub relay_url: String,

    /// Environment variable holding 32 bytes of hex, the root of the key derivation in
    /// [`crate::identity::IdentityTable::build`]. Unset or short: refuse to start. Same shape as
    /// `OperatorPrincipalConfig.token_env` (`swarm-core/src/config/operator.rs:117-120`).
    #[serde(default = "default_nostr_seed_env")]
    pub nostr_seed_env: String,

    /// Environment variable holding the NIP-OA owner attestation tag, as JSON.
    ///
    /// Absent is legal and HALVES the relay quota: `agent_owner_pubkey` is set from this tag
    /// (`buzz-relay/src/handlers/auth.rs:244-274`) and selects
    /// `agent_standard_messages_per_min` = 120 over `human_messages_per_min` = 60
    /// (`buzz-relay/src/connection.rs:662-668, 689-692`). At 1 Hz the pacer spends 60/min, so 60
    /// is 100% of budget with zero head room. Startup logs the consequence by name.
    #[serde(default)]
    pub auth_tag_env: Option<String>,

    /// MUST resolve outside the repository. `tools/check-worktree-clean.sh` runs `if: always()`
    /// after the CI test job and uses `find` because it "is immune to .gitignore and does see
    /// empty directories" (`check-worktree-clean.sh:31-35`).
    #[serde(default)]
    pub spool_dir: String,

    /// `APPENDIX-NORMATIVE.md` section 6. Per **disk-spooled** stream (evidence, alarm) --
    /// see the proposed amendment in `11-BRIDGE-CRATE.md` section 5.1: the telemetry stream is
    /// memory-only at depth 1 per key, because a replayed ephemeral is a lie about "now" and
    /// last-wins is already lossless in meaning.
    #[serde(default = "default_spool_max_bytes")]
    pub spool_max_bytes: u64,

    /// PROPOSED. 32 segments per 256 MiB budget.
    #[serde(default = "default_segment_bytes")]
    pub segment_bytes: u64,

    /// `PERCH_PUBLISH_TICK`, `APPENDIX-NORMATIVE.md` section 6.
    #[serde(default = "default_publish_tick_ms")]
    pub publish_tick_ms: u64,

    /// `PERCH_FRAME_MAX_BYTES`, `APPENDIX-NORMATIVE.md` section 6.
    #[serde(default = "default_frame_max_bytes")]
    pub frame_max_bytes: usize,

    /// PROPOSED. See [`crate::coalesce::PERCH_ESCALATION_HEARTBEAT_MS`].
    #[serde(default = "default_escalation_heartbeat_ms")]
    pub escalation_heartbeat_ms: i64,

    /// PROPOSED. See [`crate::coalesce::PERCH_ALARM_HEARTBEAT_MS`].
    #[serde(default = "default_alarm_heartbeat_ms")]
    pub alarm_heartbeat_ms: i64,

    /// PROPOSED. See [`crate::publish::PERCH_ALARM_BURST_PER_MIN`].
    #[serde(default = "default_alarm_burst_per_min")]
    pub alarm_burst_per_min: u32,

    /// PROPOSED. See [`crate::pacer::PERCH_GAP_FLUSH_TICKS`].
    #[serde(default = "default_gap_flush_ticks")]
    pub gap_flush_ticks: u32,

    /// INVENTED, and `APPENDIX-NORMATIVE.md` section 6 records it as such.
    #[serde(default = "default_late_published_ticks")]
    pub late_published_ticks: i64,

    /// PROPOSED. See [`crate::pacer::PERCH_PUBLISH_WINDOW_MARGIN_SECS`].
    #[serde(default = "default_publish_window_margin_secs")]
    pub publish_window_margin_secs: i64,

    /// Case-channel TTL in seconds, per threat class, with a `default` key. Written into the
    /// `ttl` tag of the kind:9007 create event and read by `resolve_ttl`
    /// (`buzz-relay/src/handlers/mod.rs:46-66`).
    #[serde(default)]
    pub case_ttl_seconds: BTreeMap<String, i32>,

    /// The standing `#watch` ops channel the `26006` hold alarm is `h`-scoped to (section 8.6).
    ///
    /// Required when `enabled`. Provisioned once by the relay operator, NOT created by the bridge:
    /// it is a standing object shared across colonies and shifts rather than a per-`hunt_id`
    /// artifact, and creating it would also make the bridge responsible for adding every operator
    /// to a permanent channel.
    ///
    /// It MUST be `visibility: "private"` on the relay, `perch-alarm` MUST be a member, and every
    /// operator console MUST be a member. None of the three is checkable from here -- the bridge
    /// holds no read path at all (zero `REQ`, test T-9) -- so the first alarm is the test and a
    /// failure is [`crate::error::BridgeError::WatchChannelMembership`], alarmed and never retried.
    #[serde(default)]
    pub watch_channel: Option<String>,

    /// The twelve standing threat-class channel UUIDs. Required when `enabled`; validated at load
    /// against `swarm_runtime::escalation::standard_threat_classes()`
    /// (`swarm-runtime/src/escalation.rs:315-330`, twelve entries). A missing class is a config
    /// error, not a runtime surprise -- `ThreatClass::Custom(String)` exists
    /// (`swarm-core/src/pheromone.rs:16-31`) and a `Custom` finding with no lane must land
    /// somewhere deliberate rather than nowhere.
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
            watch_channel: None,
            lane_channels: BTreeMap::new(),
        }
    }
}

impl PerchBridgeConfig {
    /// Validated at config load, alongside every other `validate()` in
    /// `swarm-core/src/config/validation.rs`.
    pub fn validate(&self) -> Result<(), crate::error::BridgeError> {
        todo!("when enabled: relay_url non-empty and wss/ws; spool_dir non-empty and outside the \
               workspace; watch_channel is Some and parses as a Uuid; lane_channels covers all \
               twelve standard_threat_classes(); every value parses as a Uuid; case_ttl_seconds \
               carries a `default` key")
    }
}
