//! One typed variant per failure mode in `11-BRIDGE-CRATE.md` section 12.
//!
//! No `.unwrap()`, no `.expect()`, anywhere in this crate's production code:
//! `[workspace.lints.clippy]` sets `unwrap_used = "deny"` and `expect_used = "deny"`,
//! `tools/check-runtime-panic-contract.sh` scans `crates/*/src` for exactly those two call
//! shapes, and `[profile.release] panic = "abort"` makes any surviving panic a process kill in
//! the daemon that holds the containment lease store.

use thiserror::Error;

/// Every way the bridge can fail, typed so the composition root and the operator log can
/// tell a provisioning fault from a transient one.
#[derive(Debug, Error)]
pub enum BridgeError {
    // ---- startup, all fatal -------------------------------------------------------------
    /// `IngestState::subscribe_runtime_events()` returned `None`, which is the state of any
    /// `IngestState` not built through `.with_runtime_events(...)`. `publish_runtime_event` is
    /// then a silent no-op: a bridge that started anyway would idle forever while the daemon
    /// believed it was publishing.
    #[error("the runtime has no event broadcaster; the perch bridge cannot subscribe")]
    NoBroadcaster,

    /// Mirrors `OperatorHttpError::MissingTokenEnv`, whose loud failure in `swarm_detect` is
    /// the pattern this follows.
    #[error(
        "environment variable `{env}` is unset or shorter than 32 bytes; \
         the perch bridge has no signing root"
    )]
    MissingNostrSeed {
        /// The variable named by `perch.nostr_seed_env`.
        env: String,
    },

    /// `tools/check-worktree-clean.sh` runs `if: always()` after the CI test job and uses `find`
    /// because it is immune to .gitignore and does see empty directories. A spool that defaults
    /// into the repository fails the clean-tree contract on the first test run and blames the
    /// test suite.
    #[error(
        "perch.spool_dir `{path}` resolves inside the workspace; \
         the spool must live outside the repository"
    )]
    SpoolDirInsideWorkspace {
        /// The offending root, as configured.
        path: String,
    },

    /// `standard_threat_classes()` returns twelve entries. A `Custom` finding with no lane must
    /// land somewhere deliberate.
    #[error("perch.lane_channels has no entry for threat class `{threat_class}`")]
    MissingLaneChannel {
        /// The class slug that had no lane.
        threat_class: String,
    },

    /// A configuration the bridge cannot run under, with the reason spelled out.
    #[error("perch config is invalid: {reason}")]
    InvalidConfig {
        /// Why the configuration was refused.
        reason: String,
    },

    // ---- spool --------------------------------------------------------------------------
    /// An I/O failure on a spool path.
    #[error("spool io error at {path}: {source}")]
    SpoolIo {
        /// The file or directory involved.
        path: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A segment file that does not start with the spool magic.
    #[error("spool segment {path} has a bad magic; this is not a perch spool")]
    SpoolBadMagic {
        /// The segment path.
        path: String,
    },

    /// A segment written by a format this build does not read.
    #[error("spool segment {path} has format version {found}, expected {expected}")]
    SpoolUnknownFormat {
        /// The segment path.
        path: String,
        /// The version in the header.
        found: u16,
        /// The version this build writes.
        expected: u16,
    },

    /// A spool directory shared between two colonies would merge two `seq` namespaces and produce
    /// a FALSE CONTINUITY, which `07-REALTIME-AND-DATA.md` section 11 names as the worse of the
    /// two failures -- worse than a false gap, because a false gap is visible.
    #[error("spool segment {path} belongs to a different colony; refusing to merge seq namespaces")]
    SpoolColonyMismatch {
        /// The segment path.
        path: String,
    },

    /// A slot that has no spine key. A programming error, surfaced typed.
    #[error("no spine identity for slot {slot}")]
    UnknownSlot {
        /// The slot asked for.
        slot: String,
    },

    /// The spine refused to build or verify an envelope, or it did not decode.
    #[error("spine envelope: {0}")]
    Envelope(String),

    /// The signing profile named a seed env var that carries nothing usable.
    ///
    /// Refusing to start is the point: a bridge that fell back to unsigned
    /// envelopes under a profile that says it signs would publish a chain no
    /// console could tell from a forged one, and it would do so silently.
    #[error(
        "perch.spine_seed_env `{env}` is unset or shorter than 32 bytes of hex; \
         refusing to start rather than publish unsigned envelopes under a signing profile"
    )]
    MissingSpineSeed {
        /// The environment variable the profile named.
        env: String,
    },

    /// The chain-head file could not be read or written as JSON.
    #[error("chain-heads file {path} is unreadable: {reason}")]
    ChainHeadCorrupt {
        /// The file.
        path: String,
        /// What the parser or serializer said.
        reason: String,
    },

    /// A head was advanced to a sequence that is not the next one.
    ///
    /// Refused rather than persisted: a stored regression becomes a gap, and a
    /// console reads a gap as evidence of a missing or forged link.
    #[error("chain head for {issuer} would regress: expected seq {expected}, got {found}")]
    ChainHeadRegression {
        /// The issuer whose chain it is.
        issuer: String,
        /// The sequence the store expected.
        expected: u64,
        /// The sequence it was handed.
        found: u64,
    },

    /// The chain-head file was written under a different colony.
    #[error("chain-head store belongs to colony {found}, not {expected}")]
    ChainHeadColonyMismatch {
        /// The colony this bridge runs as.
        expected: String,
        /// The colony the file names.
        found: String,
    },

    /// The alarm spool reached its byte budget. Alarm work is never evicted, so the append is
    /// refused instead (`11-BRIDGE-CRATE.md` section 4.2, tier 3) and the receive loop counts the
    /// refusal without ever blocking `recv()`.
    #[error("alarm spool is full at {bytes} of {max_bytes} bytes; refusing new alarm work")]
    AlarmSpoolFull {
        /// Bytes currently held.
        bytes: u64,
        /// The configured ceiling.
        max_bytes: u64,
    },

    // ---- publish ------------------------------------------------------------------------
    /// A `p` tag that is not exactly 64 ASCII-hex characters is dropped silently by the relay's
    /// mention insert, producing a stored event, an `OK true`, and NO queue row. An unpublished
    /// hold alarms; a hold published with a malformed `p` tag is a destructive action awaiting a
    /// human that no human is shown.
    #[error("p tag is not 64 hex characters (length {value_len}); refusing to sign")]
    MalformedPTag {
        /// Length of the rejected value after trimming.
        value_len: usize,
    },

    /// A `hold_id` that does not look like the daemon-minted opaque token. The bridge never
    /// mints one, so a value of the wrong shape means either the daemon changed its id scheme or
    /// a `RuntimeEvent` was constructed by hand. Both are refusals, because the same value reaches
    /// a community-visible frame, and the derived form `hold:{hunt_id}:{held_at_ms}` would leak
    /// the telemetry event id there.
    #[error("hold_id {value:?} is not an opaque token; refusing to publish it")]
    MalformedHoldId {
        /// The rejected value.
        value: String,
    },

    /// A `RuntimeEvent::CasePromoted` named a `case_id` for a `hunt_id` the routing table already
    /// maps to a different channel. The bridge refuses rather than creating a second channel for
    /// one investigation or silently adopting the newer id: the daemon has by then minted an
    /// incident record pointing at the id it sent, and only one of the two can be the case.
    /// Counted as `perch_bridge_case_channel_conflict_total`; failure mode F20.
    #[error(
        "hunt {hunt_id} already routes to case channel {existing}; refusing to adopt {incoming}"
    )]
    CaseChannelConflict {
        /// The hunt whose routing entry already exists.
        hunt_id: String,
        /// The channel already routed for that hunt.
        existing: String,
        /// The channel the new promotion named.
        incoming: String,
    },

    /// `OperatorAuthConfig::effective_principals()` yields no principal holding
    /// `OperatorScope::Approve` and carrying a Nostr pubkey.
    #[error(
        "no operator principal holding OperatorScope::Approve carries a nostr pubkey; \
         holds cannot be delivered"
    )]
    HoldUndeliverable,

    /// The relay answered `OK false` with a message the typed classifier did not turn into a
    /// retry, a duplicate, or an infrastructure state.
    #[error("relay rejected the event: {message}")]
    RelayRejected {
        /// The relay's own message.
        message: String,
    },

    /// The socket could not be established and the supervisor is inside its backoff window.
    /// The frame stays at the spool head; nothing is lost.
    #[error("relay unreachable (attempt {attempt}); next connect in {retry_in:?}")]
    RelayUnreachable {
        /// Consecutive failed connection attempts.
        attempt: u32,
        /// Time until the next attempt.
        retry_in: std::time::Duration,
    },

    /// A record could not be serialised into a card or a frame.
    #[error("the perch bridge cannot serialise a record: {0}")]
    Encode(String),

    /// The shutdown watch flipped before an in-flight frame was acknowledged.
    #[error("perch bridge shut down before the frame was acknowledged")]
    ShuttingDown,

    /// A WebSocket-level failure from the path-dependency client.
    #[error("websocket: {0}")]
    Ws(#[from] ambush_ws_client::WsClientError),

    /// A JSON failure.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
