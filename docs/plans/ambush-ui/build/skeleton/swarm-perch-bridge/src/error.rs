//! One typed variant per failure mode in `11-BRIDGE-CRATE.md` section 12.
//!
//! No `.unwrap()`, no `.expect()`, anywhere in this crate's production code:
//! `[workspace.lints.clippy]` sets `unwrap_used = "deny"` and `expect_used = "deny"`
//! (`Cargo.toml:135-137`), `tools/check-runtime-panic-contract.sh` scans `crates/*/src` for
//! exactly those two call shapes, and `[profile.release] panic = "abort"` (`Cargo.toml:139-141`)
//! makes any surviving panic a process kill in the daemon that holds the containment lease store.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BridgeError {
    // ---- startup, all fatal -------------------------------------------------------------
    /// `IngestState::subscribe_runtime_events()` returned `None`
    /// (`swarm-ingest-runtime/src/ingest/mod.rs:1874-1881`), which is the state of any
    /// `IngestState` not built through `.with_runtime_events(...)`. `publish_runtime_event`
    /// (`:1913-1917`) is then a silent no-op: a bridge that started anyway would idle forever
    /// while the daemon believed it was publishing.
    #[error("the runtime has no event broadcaster; the perch bridge cannot subscribe")]
    NoBroadcaster,

    /// Mirrors `OperatorHttpError::MissingTokenEnv`
    /// (`swarm-runtime-http/src/http/auth.rs:57-82`), whose loud failure at
    /// `swarm_detect.rs:1127-1132` is the pattern this follows.
    #[error("environment variable `{env}` is unset or shorter than 32 bytes; \
             the perch bridge has no signing root")]
    MissingNostrSeed { env: String },

    /// `tools/check-worktree-clean.sh` runs `if: always()` after the CI test job and uses `find`
    /// because it is immune to .gitignore and does see empty directories. A spool that defaults
    /// into the repository fails the clean-tree contract on the first test run and blames the
    /// test suite.
    #[error("perch.spool_dir `{path}` resolves inside the workspace; \
             the spool must live outside the repository")]
    SpoolDirInsideWorkspace { path: String },

    /// `standard_threat_classes()` (`swarm-runtime/src/escalation.rs:315-330`) returns twelve
    /// entries. A `Custom` finding with no lane must land somewhere deliberate.
    #[error("perch.lane_channels has no entry for threat class `{threat_class}`")]
    MissingLaneChannel { threat_class: String },

    #[error("perch config is invalid: {reason}")]
    InvalidConfig { reason: String },

    // ---- spool --------------------------------------------------------------------------
    #[error("spool io error at {path}: {source}")]
    SpoolIo {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("spool segment {path} has a bad magic; this is not a perch spool")]
    SpoolBadMagic { path: String },

    #[error("spool segment {path} has format version {found}, expected {expected}")]
    SpoolUnknownFormat {
        path: String,
        found: u16,
        expected: u16,
    },

    /// A spool directory shared between two colonies would merge two `seq` namespaces and produce
    /// a FALSE CONTINUITY, which `07-REALTIME-AND-DATA.md` section 11 names as the worse of the
    /// two failures -- worse than a false gap, because a false gap is visible.
    #[error("spool segment {path} belongs to a different colony; refusing to merge seq namespaces")]
    SpoolColonyMismatch { path: String },

    // ---- publish ------------------------------------------------------------------------
    /// A `p` tag that is not exactly 64 ASCII-hex characters is dropped silently by
    /// `insert_mentions` with a `tracing::debug!` (`buzz-db/src/runtime/mod.rs:66-81`), producing
    /// a stored event, an `OK true`, and NO queue row. An unpublished hold alarms; a hold
    /// published with a malformed `p` tag is a destructive action awaiting a human that no human
    /// is shown.
    #[error("p tag is not 64 hex characters (length {value_len}); refusing to sign")]
    MalformedPTag { value_len: usize },

    /// A `hold_id` that does not look like the daemon-minted opaque token
    /// ([`crate::channels::HoldId`]). The bridge never mints one, so a value of the wrong shape
    /// means either B1 changed its id scheme or a `RuntimeEvent` was constructed by hand. Both
    /// are refusals, because the same value reaches the community-visible `26006` frame, and the
    /// derived form `hold:{hunt_id}:{held_at_ms}` would leak the telemetry event id there.
    #[error("hold_id {value:?} is not an opaque uuid; refusing to publish it to 26006 or 46010")]
    MalformedHoldId { value: String },

    /// A `RuntimeEvent::CasePromoted` (bill item B1d, PROPOSED) named a `case_id` for a `hunt_id`
    /// the routing table already maps to a different channel. The bridge refuses rather than
    /// creating a second channel for one investigation or silently adopting the newer id: the
    /// daemon has by then minted an incident record pointing at the id it sent, and only one of
    /// the two can be the case. Counted as `perch_bridge_case_channel_conflict_total`; failure
    /// mode F20.
    #[error("hunt {hunt_id} already routes to case channel {existing}; refusing to adopt {incoming}")]
    CaseChannelConflict {
        hunt_id: String,
        existing: String,
        incoming: String,
    },

    /// The `26006` alarm frame carries an `h` tag naming the standing `#watch` ops channel, and
    /// `handle_ephemeral_event` runs `check_channel_membership` on the PUBLISHER before it
    /// publishes anything (`BUZZ crates/buzz-relay/src/handlers/event.rs:850-852`). So a
    /// `perch-alarm` identity that is not a member of `#watch` gets `OK false` on every alarm.
    /// This is a provisioning error, detected on the first publish and alarmed immediately rather
    /// than retried: no amount of backoff adds a membership row.
    #[error("the alarm identity is not a member of the #watch channel {watch_channel};              no hold alarm can be published")]
    WatchChannelMembership { watch_channel: String },

    /// `OperatorAuthConfig::effective_principals()` (`swarm-core/src/config/operator.rs:153-168`)
    /// yields no principal holding `OperatorScope::Approve` and carrying a Nostr pubkey. See
    /// `11-BRIDGE-CRATE.md` section 7.5: `OperatorPrincipalConfig` has no such field today, and
    /// adding `nostr_pubkey: Option<String>` is a prerequisite for B1 being useful.
    #[error("no operator principal holding OperatorScope::Approve carries a nostr pubkey; \
             holds cannot be delivered")]
    HoldUndeliverable,

    #[error("relay rejected the event: {message}")]
    RelayRejected { message: String },

    #[error("websocket: {0}")]
    Ws(#[from] crate::ws::WsClientError),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
