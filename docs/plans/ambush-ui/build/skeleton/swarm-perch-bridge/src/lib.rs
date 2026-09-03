//! Perch bridge: the daemon's only writer of daemon-sourced facts to the Buzz relay.
//!
//! Subscribes **in-process** to [`swarm_runtime::runtime_events::RuntimeEvent`], classifies each
//! event into one of four streams, appends it to a bounded disk spool *before any network I/O*,
//! and drains that spool through a 1 Hz pacer that stamps `created_at`, signs a Nostr envelope,
//! and writes it to the relay over a NIP-42 WebSocket.
//!
//! # The budget that shapes every decision here
//!
//! `DEFAULT_RUNTIME_EVENT_CAPACITY` is `1_024`
//! (`swarm-runtime/src/runtime_events.rs:13`) and a lagged `broadcast::Receiver` drops the oldest
//! frames. At the measured hot-path rate of 3,645 events/sec (`README.md:536`) that is **281 ms**
//! of head room. Any TLS handshake, DNS lookup, `fsync`-per-record or relay round trip inside the
//! receive loop exceeds it, and the loss is silent: both shipped subscribers
//! (`swarm-ingest-runtime/src/ingest/demo.rs:1688-1691` and
//! `.../platform_api.rs:1387-1390`) write `let Ok(event) = result else { return None; };`.
//!
//! So [`receive`] does three things: `recv()`, classify, append. It imports [`stream`], [`spool`]
//! and [`metrics`] and nothing else. If it can name the relay client, somebody will eventually
//! call it from there and no test will fail.
//!
//! ## Owns
//!
//! - The classification of every `RuntimeEvent` into exactly one transport stream.
//! - The disk spool format, its recovery, and the `seq` namespace `(colony_id, issuer)`.
//! - The coalescing rules, and the distinction between a coalesce and a gap.
//! - The publish pacer, the `created_at` stamp, and the relay write budget.
//! - The bridge's own Nostr identities and what their signatures do and do not prove.
//! - Provisioning the case channel and its `ttl`, on both promotion triggers ([`channels`]).
//!
//! ## Does not own
//!
//! - The on-wire card body schemas. Those are `13-WIRE-SCHEMAS.md`'s; [`cards`] assembles, it does
//!   not define.
//! - Any authorization decision. The bridge publishes what the daemon already decided; it never
//!   evaluates policy, never mints a capability lease or a containment lease, and never calls the
//!   runtime.
//! - Reading anything from the relay. There is no REQ and no COUNT in this crate, ever
//!   (`11-BRIDGE-CRATE.md` section 8.4, test `T-9`), which is also why
//!   `perch_queue_reconcile_divergences_total` is the console's counter and not this crate's.
//! - The relay-side `46010` fork, which is `10-RELAY-FORK.md`'s.
//! - Minting a `hold_id`, a `case_id`, a receipt or a containment lease. Every identifier the
//!   bridge publishes was minted by the daemon; the bridge asserts their shape and republishes
//!   them.
//!
//! ## The two headings above are load-bearing, exactly as written
//!
//! `tools/check-workspace-layering.sh:237-238` sets `OWNS_HEADING = "//! ## Owns"` and
//! `NOT_OWNS_HEADING = "//! ## Does not own"`. RULE 5 (`:547-567`, in the Python engine the shell
//! wrapper runs over `cargo metadata`) reads each `TRUST_SENSITIVE` crate's `src/lib.rs`,
//! right-strips every line into a list, and reports `missing-owns-section` when either literal
//! `not in lines`. It is an exact whole-line match: a leading `# `, a trailing space that survives
//! only because it was not stripped, or a `###` all fail it.
//!
//! ADR 0015 adds `swarm-perch-bridge` to `TRUST_SENSITIVE`, so RULE 5 **does** evaluate this file
//! from the commit that lands the crate. That commit is a three-part edit to the gate, not one:
//!
//! 1. the `TRUST_SENSITIVE` tuple (`:184-191`);
//! 2. `FIXTURE_CRATES` (`:618-633`) — the self-test builds its own throwaway workspace, and the
//!    vacuity guard at `:289-294` raises `Vacuity` ("policy names crates that are not workspace
//!    members") for any policy name absent from it. The fixture runs BEFORE the real scan and a
//!    fixture failure exits 1 at `:858-863`, so omitting this row fails the gate without ever
//!    looking at the real tree;
//! 3. `FIXTURE_DOCUMENTED` (`:637`) — otherwise the fixture stub for this crate is written without
//!    the two headings (`:659-671`) and the clean-fixture control case (`:794`) fails.
//!
//! Every shipped `TRUST_SENSITIVE` crate gets the literal right; `crates/swarm-pheromone/src/lib.rs:14`
//! and `:24` are the model this file follows.

#![forbid(unsafe_code)]

pub mod cards;
pub mod channels;
pub mod coalesce;
pub mod config;
pub mod error;
pub mod identity;
pub mod leases;
pub mod metrics;
pub mod pacer;
pub mod publish;
pub mod receive;
pub mod spool;
pub mod stream;
pub mod ws;

use std::sync::Arc;

use swarm_core::types::AgentId;
use swarm_runtime::containment::ContainmentSweep;
use swarm_runtime::runtime_events::RuntimeEvent;
use tokio::sync::{broadcast, watch};

pub use config::PerchBridgeConfig;
pub use error::BridgeError;
pub use stream::Stream;

/// Everything `swarm_detect` hands the bridge at startup.
///
/// `events` is deliberately a receiver rather than an `IngestState`: it keeps this crate off
/// `swarm-ingest-runtime`'s manifest and lets a unit test drive the whole pipeline from a plain
/// `broadcast::channel(16)`.
pub struct BridgeBuildInput {
    pub config: PerchBridgeConfig,
    /// Namespaces every `seq`. Two colonies both running a Whisker both start at `seq: 1`;
    /// merging them under one key produces a false continuity, which is the worse of the two
    /// failures (`07-REALTIME-AND-DATA.md` section 11 item 1).
    pub colony_id: String,
    /// `None` means the daemon has no `RuntimeEventBroadcaster`
    /// (`swarm-ingest-runtime/src/ingest/mod.rs:1875-1881` returns `None` when
    /// `IngestState.runtime_events` is `None`, and `publish_runtime_event` at `:1913-1917` is
    /// then a silent no-op). Startup must fail loudly rather than idle.
    pub events: Option<broadcast::Receiver<RuntimeEvent>>,
    /// A clone of the `Vec<AgentId>` assembled at `swarm_detect.rs:768-962` and handed to
    /// `dispatcher.set_admitted_identities(...)` at `:963`. Its length varies with config gates,
    /// which is why the identity table is sized from this and not from `AgentRole`'s 8 variants.
    pub admitted_identities: Vec<AgentId>,
    /// The process's ONE sweep `Arc` (`swarm_detect.rs:1022-1075`). `None` on the shipped default,
    /// because `ContainmentSettings.lease_store_path` defaults to `None`
    /// (`swarm-core/src/config/runtime.rs:93-95`).
    pub containment: Option<Arc<ContainmentSweep>>,
    pub shutdown: watch::Receiver<bool>,
}

/// The assembled bridge. Construct with [`PerchBridge::build`], hand to `tokio::spawn`.
pub struct PerchBridge {
    _private: (),
}

impl PerchBridge {
    /// Validates configuration, opens the spools, derives the identities, and returns a bridge
    /// ready to run.
    ///
    /// Returns `Ok(None)` when `config.enabled` is false — a daemon that gains this crate must opt
    /// in, because the bridge holds `AdminChannels` on a relay and writes to a colony's record.
    ///
    /// # Errors
    ///
    /// - [`BridgeError::NoBroadcaster`] when `input.events` is `None`.
    /// - [`BridgeError::MissingNostrSeed`] when `config.nostr_seed_env` names an unset or short
    ///   variable. Mirrors `OperatorAuthState::from_config`'s `MissingTokenEnv`
    ///   (`swarm-runtime-http/src/http/auth.rs:57-82`), which is why
    ///   `swarm_detect.rs:1127-1132` reports a router build failure loudly instead of swallowing
    ///   it.
    /// - [`BridgeError::SpoolDirInsideWorkspace`] when `spool_dir` canonicalizes under the
    ///   workspace root. `tools/check-worktree-clean.sh` runs `if: always()` after the test job and
    ///   uses `find` precisely because it "is immune to .gitignore and does see empty directories".
    /// - [`BridgeError::MissingLaneChannel`] when a member of
    ///   `swarm_runtime::escalation::standard_threat_classes()` has no configured lane channel.
    pub fn build(input: BridgeBuildInput) -> Result<Option<Self>, BridgeError> {
        let _ = input;
        todo!("validate config; open spools; derive identities; assemble tasks")
    }

    /// The two-route metrics surface `swarm_detect` merges beside `containment_operator_router`.
    ///
    /// A separate path rather than a merge into the daemon's `/metrics`
    /// (`swarm-ingest-runtime/src/ingest/mod.rs:2547` -> `ingest/health.rs:677-702`) because that
    /// handler encodes only `CriticalPathMetrics`, whose `registry` field is private and has no
    /// public accessor — the only public function over it is `encode_metrics`
    /// (`swarm-runtime/src/detection/metrics.rs:446-454`).
    pub fn metrics_router(&self) -> axum::Router {
        todo!("GET /metrics/perch and GET /metrics/perch/healthz over the perch-prefixed registry")
    }

    /// Runs until the shutdown watch flips or the broadcast closes.
    ///
    /// Spawns and joins four tasks: the receive loop ([`receive`]), the pacer ([`pacer`]), the
    /// connection supervisor ([`publish`]), and the 1 Hz containment-lease diff ([`leases`]).
    /// The receive loop is the only one on the 281 ms budget; the other three may block.
    pub async fn run(self) {
        todo!("select! over the four task handles and the shutdown watch")
    }
}
