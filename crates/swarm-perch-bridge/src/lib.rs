//! Perch bridge: the daemon's only writer of daemon-sourced facts to the Ambush relay.
//!
//! Subscribes **in-process** to [`swarm_runtime::runtime_events::RuntimeEvent`], classifies each
//! event into one of four streams, appends it to a bounded disk spool *before any network I/O*,
//! and drains that spool through a 1 Hz pacer that stamps `created_at`, signs a Nostr envelope,
//! and writes it to the relay over a NIP-42 WebSocket.
//!
//! # The budget that shapes every decision here
//!
//! `DEFAULT_RUNTIME_EVENT_CAPACITY` is `1_024`
//! (`swarm-runtime/src/runtime_events.rs`) and a lagged `broadcast::Receiver` drops the oldest
//! frames. At the measured hot-path rate of 3,645 events/sec that is **281 ms** of head room. Any
//! TLS handshake, DNS lookup, `fsync`-per-record or relay round trip inside the receive loop
//! exceeds it, and the loss is silent: both shipped subscribers write
//! `let Ok(event) = result else { return None; };`.
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
//! - The on-wire card body schemas. Those are `swarm-perch-wire`'s; [`cards`] assembles, it does
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
//! `tools/check-workspace-layering.sh` sets `OWNS_HEADING = "//! ## Owns"` and
//! `NOT_OWNS_HEADING = "//! ## Does not own"`. RULE 5 reads each `TRUST_SENSITIVE` crate's
//! `src/lib.rs`, right-strips every line into a list, and reports `missing-owns-section` when
//! either literal `not in lines`. It is an exact whole-line match: a leading `# `, a trailing
//! space that survives only because it was not stripped, or a `###` all fail it.
//!
//! ADR 0015 adds `swarm-perch-bridge` to `TRUST_SENSITIVE`, so RULE 5 **does** evaluate this file
//! from the commit that lands the crate. That commit is a three-part edit to the gate, not one:
//!
//! 1. the `TRUST_SENSITIVE` tuple;
//! 2. `FIXTURE_CRATES` — the self-test builds its own throwaway workspace, and the vacuity guard
//!    raises `Vacuity` ("policy names crates that are not workspace members") for any policy name
//!    absent from it. The fixture runs BEFORE the real scan and a fixture failure exits 1, so
//!    omitting this row fails the gate without ever looking at the real tree;
//! 3. `FIXTURE_DOCUMENTED` — otherwise the fixture stub for this crate is written without the
//!    two headings and the clean-fixture control case fails.

#![forbid(unsafe_code)]

pub mod alarm;
pub mod cards;
pub mod channels;
pub mod coalesce;
pub mod error;
pub mod holds;
pub mod identity;
pub mod lanes;
pub mod leases;
pub mod metrics;
pub mod pacer;
pub mod publish;
pub mod receive;
pub mod rollback;
pub mod spine;
pub mod spool;
pub mod stream;

use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, PoisonError};

use prometheus_client::registry::Registry;
use swarm_core::config::{OperatorPrincipalConfig, PerchBridgeConfig};
use swarm_core::types::AgentId;
use swarm_runtime::containment::ContainmentSweep;
use swarm_runtime::runtime_events::RuntimeEvent;
use tokio::sync::{broadcast, watch};

use crate::alarm::FALLBACK_CASE_TTL_SECONDS;
use crate::channels::CaseRouting;
use crate::holds::HoldPublisher;
use crate::identity::{IdentityTable, approve_scoped_operator_pubkeys, seed_from_env};
use crate::metrics::BridgeMetrics;
use crate::pacer::Pacer;
use crate::publish::ConnectionSupervisor;
use crate::spool::SpoolSet;

pub use error::BridgeError;
pub use stream::Stream;

/// The sidecar file that holds `hunt_id -> case_channel`, beside the spools.
const CASE_ROUTING_FILE: &str = "case-routing.json";

/// Everything `swarm_detect` hands the bridge at startup.
///
/// `events` is deliberately a receiver rather than an `IngestState`: it keeps this crate off
/// `swarm-ingest-runtime`'s manifest (00-DECISIONS W3-13) and lets a unit test drive the whole
/// pipeline from a plain `broadcast::channel(16)`.
pub struct BridgeBuildInput {
    /// The `perch` block of the daemon's config.
    pub config: PerchBridgeConfig,
    /// Namespaces every `seq`. `swarm_detect` passes `config.name`.
    pub colony_id: String,
    /// `None` means the daemon has no `RuntimeEventBroadcaster`; startup fails loudly.
    pub events: Option<broadcast::Receiver<RuntimeEvent>>,
    /// The `Vec<AgentId>` handed to `dispatcher.set_admitted_identities`, cloned before the move.
    pub admitted_identities: Vec<AgentId>,
    /// The daemon's persisted Whisker "primary" identity. Finding cards from the HTTP
    /// ingest lane carry no producer id, so this is the issuer they are attributed to.
    pub ingest_identity: AgentId,
    /// `config.operator.auth.effective_principals()`; the Approve-scoped ones with a
    /// `nostr_pubkey` are added to every case channel the bridge creates.
    pub operator_principals: Vec<OperatorPrincipalConfig>,
    /// The process's one sweep, or `None` on the shipped default.
    pub containment: Option<Arc<ContainmentSweep>>,
    /// The daemon's ONE hold store.
    ///
    /// Read only in the PUBLISH task, never in [`receive`], to build the `swarm:hold:v1` card
    /// body from the record a `RuntimeEvent::ResponseHeld` announces, and written back through
    /// `mark_case_channel` / `mark_notified` once the relay OKs the `9007` and the `46010`.
    ///
    /// `None` on a daemon that never called `with_hold_store`. The bridge then refuses every
    /// `ResponseHeld` by name (`hold_undeliverable{reason="no_hold_store"}`) rather than
    /// publishing a card it would have to invent.
    ///
    /// # Why the Approve set is NOT a sibling field
    ///
    /// The set is `approve_scoped_operator_pubkeys(&operator_principals)` — derivable from the
    /// field directly above it, and derived exactly once inside [`PerchBridge::build`], where
    /// the `HoldUndeliverable` case is already turned into a warning and an empty set. A second
    /// input carrying the same list is a second source that can disagree with the first, and the
    /// disagreement would be invisible: case channels provisioned for one set of operators and
    /// notices `p`-tagged to another. [`PerchBridge::approve_pubkeys`] exposes the one answer.
    pub hold_store: Option<Arc<dyn swarm_runtime::held_action::HeldActionStore>>,
    /// The process-wide shutdown watch.
    pub shutdown: watch::Receiver<bool>,
}

/// The assembled bridge. Construct with [`PerchBridge::build`], hand to `tokio::spawn`.
pub struct PerchBridge {
    config: PerchBridgeConfig,
    colony_id: String,
    identities: Arc<IdentityTable>,
    spools: Arc<Mutex<SpoolSet>>,
    routing: CaseRouting,
    operators: Vec<String>,
    metrics: BridgeMetrics,
    registry: Arc<Mutex<Registry>>,
    stall: Arc<AtomicU64>,
    events: broadcast::Receiver<RuntimeEvent>,
    containment: Option<Arc<ContainmentSweep>>,
    /// B6. The spine identities every published envelope is sealed under.
    spine: Arc<crate::spine::SpineSigner>,
    /// B6. The durable per-issuer chain heads, so a restart continues its
    /// chains rather than forking them.
    chain_heads: Arc<Mutex<crate::spool::chain_heads::ChainHeadStore>>,
    hold_store: Option<Arc<dyn swarm_runtime::held_action::HeldActionStore>>,
    shutdown: watch::Receiver<bool>,
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
    ///   variable.
    /// - [`BridgeError::SpoolDirInsideWorkspace`] when `spool_dir` resolves under the workspace.
    /// - [`BridgeError::InvalidConfig`] when the `perch` block fails its own validation.
    pub fn build(input: BridgeBuildInput) -> Result<Option<Self>, BridgeError> {
        let BridgeBuildInput {
            config,
            colony_id,
            events,
            admitted_identities,
            ingest_identity,
            operator_principals,
            containment,
            hold_store,
            shutdown,
        } = input;

        if !config.enabled {
            return Ok(None);
        }
        config
            .validate()
            .map_err(|error| BridgeError::InvalidConfig {
                reason: error.to_string(),
            })?;

        let events = events.ok_or(BridgeError::NoBroadcaster)?;
        let seed = seed_from_env(&config.nostr_seed_env)?;
        let identities = Arc::new(IdentityTable::build(
            &seed,
            &colony_id,
            &admitted_identities,
            &ingest_identity,
            None,
        )?);

        let spool_root = Path::new(config.spool_dir.trim());
        let spools = Arc::new(Mutex::new(SpoolSet::open(
            spool_root,
            &colony_id,
            config.segment_bytes,
            config.spool_max_bytes,
        )?));
        let routing = CaseRouting::open(&spool_root.join(CASE_ROUTING_FILE))?;

        // B6. Both before the bridge can publish anything. A missing or unusable
        // seed is FATAL here rather than a silent fallback to unsigned
        // envelopes: a bridge that published an unsigned chain under a signing
        // profile would emit records nobody could tell from forged ones, and it
        // would do so without a single line of output.
        let spine = Arc::new(crate::spine::SpineSigner::from_config(
            &config,
            &colony_id,
            &identities.slot_labels(),
        )?);
        let chain_heads = Arc::new(Mutex::new(crate::spool::chain_heads::ChainHeadStore::open(
            spool_root, &colony_id,
        )?));

        let (metrics, registry) = BridgeMetrics::new();

        // First card promotes findings; a hold is Operator-complete. A deployment with no
        // Approve-scoped principal carrying a Nostr pubkey therefore still runs, with case
        // channels whose only member is the bridge.
        let operators = match approve_scoped_operator_pubkeys(&operator_principals) {
            Ok(operators) => operators,
            Err(BridgeError::HoldUndeliverable) => {
                metrics.hold_undeliverable("no_operator_pubkey");
                tracing::warn!(
                    module = module_path!(),
                    "no Approve principal carries a nostr_pubkey; case channels will be created \
                     with the bridge as their only member"
                );
                Vec::new()
            }
            Err(error) => return Err(error),
        };

        Ok(Some(Self {
            config,
            colony_id,
            identities,
            spools,
            routing,
            operators,
            metrics,
            registry,
            stall: Arc::new(AtomicU64::new(0)),
            events,
            containment,
            spine,
            chain_heads,
            hold_store,
            shutdown,
        }))
    }

    /// The metrics surface `swarm_detect` merges beside `containment_operator_router`.
    pub fn metrics_router(&self) -> axum::Router {
        metrics::router(
            Arc::clone(&self.registry),
            Arc::clone(&self.identities),
            self.colony_id.clone(),
            Arc::clone(&self.stall),
        )
    }

    /// The process's containment sweep, when it has one.
    ///
    /// Held for the containment-lease poll that publishes `swarm:lease:v1` cards. That producer
    /// lands in Operator-complete; nothing in this milestone reads it, and the field is kept
    /// rather than dropped so the composition root does not have to be rewired for it.
    pub fn containment(&self) -> Option<&Arc<ContainmentSweep>> {
        self.containment.as_ref()
    }

    /// The identities this bridge signs with.
    pub fn identities(&self) -> &Arc<IdentityTable> {
        &self.identities
    }

    /// The lowercase 64-hex Nostr pubkeys of every principal holding `OperatorScope::Approve`
    /// and carrying a `nostr_pubkey`.
    ///
    /// THE one answer, derived once in [`PerchBridge::build`]. It is the membership list of
    /// every case channel the bridge creates AND the `p` set of every `46010` and `26006` it
    /// publishes, and those three must be the same list or a hold is delivered to a channel one
    /// operator can read and mentioned to a different one. Empty means no hold is deliverable
    /// and the bridge says so per hold (failure mode F18).
    pub fn approve_pubkeys(&self) -> &[String] {
        &self.operators
    }

    /// The daemon's hold store, when the composition root gave the bridge one.
    pub fn hold_store(&self) -> Option<&Arc<dyn swarm_runtime::held_action::HeldActionStore>> {
        self.hold_store.as_ref()
    }

    /// Runs until the shutdown watch flips or the broadcast closes.
    ///
    /// Three tasks: the receive loop, the evidence pacer, and the alarm drainer. Each holds the
    /// spool mutex only for an append, a peek or a commit, never across an await.
    pub async fn run(self) {
        let Self {
            config,
            colony_id,
            identities,
            spools,
            routing,
            operators,
            metrics,
            registry: _registry,
            stall,
            events,
            containment: _containment,
            spine,
            chain_heads,
            hold_store,
            shutdown,
        } = self;

        tracing::info!(
            module = module_path!(),
            colony_id = %colony_id,
            relay = %config.relay_url,
            "perch bridge starting"
        );

        // Alarm-class events are signed by the alarm identity, everything else by the ingest
        // identity. The receive loop is handed this as a closure because it may not name the
        // identity table (see `receive`'s module docs).
        let alarm_idx = identities.alarm();
        let ingest_idx = identities.ingest();
        let issuer_of: receive::IssuerOf = Arc::new(move |event: &RuntimeEvent| {
            if stream::classify(event) == Stream::Alarm {
                alarm_idx
            } else {
                ingest_idx
            }
        });

        let mut receive_task = tokio::spawn(receive::run(
            events,
            Arc::clone(&spools),
            metrics.clone(),
            issuer_of,
            stall,
            shutdown.clone(),
        ));

        let Some(ingest_identity) = identities.get(ingest_idx).cloned() else {
            tracing::error!(
                module = module_path!(),
                "the perch identity table has no ingest slot; the bridge cannot publish"
            );
            return;
        };
        let Some(alarm_identity) = identities.get(alarm_idx).cloned() else {
            tracing::error!(
                module = module_path!(),
                "the perch identity table has no alarm slot; the bridge cannot provision channels"
            );
            return;
        };

        let pacer = Pacer::new(
            Arc::clone(&spools),
            Arc::clone(&identities),
            config.clone(),
            colony_id.clone(),
            metrics.clone(),
            ConnectionSupervisor::new(config.relay_url.clone(), ingest_identity),
        )
        // B6. Every evidence envelope is sealed under its slot's spine identity,
        // and the durable head advances only when the relay acknowledges it.
        .with_spine(Arc::clone(&spine), Arc::clone(&chain_heads));
        let mut pacer_task = tokio::spawn(pacer.run(shutdown.clone()));

        // The hold publisher owns the routing sidecar: the hold path writes card ids into it
        // and the promotion path writes case channels, and one file gets one writer.
        let holds = HoldPublisher::new(
            routing,
            hold_store,
            operators,
            config
                .case_ttl_seconds
                .get("default")
                .copied()
                .unwrap_or(FALLBACK_CASE_TTL_SECONDS),
            alarm_identity.clone(),
            alarm_idx,
            metrics.clone(),
        )
        // B6. Hold cards are sealed under the spine identity too; a hold is the
        // record an operator acts on, so it is the last card that should be
        // publishable without attestation.
        .with_spine(Arc::clone(&spine));
        let mut alarm_task = Some(tokio::spawn(alarm::run(alarm::AlarmDrainer {
            spools: Arc::clone(&spools),
            identities: Arc::clone(&identities),
            config: config.clone(),
            holds,
            publisher: ConnectionSupervisor::new(config.relay_url.clone(), alarm_identity)
                .with_alarm_burst(config.alarm_burst_per_min),
            metrics,
            shutdown: shutdown.clone(),
        })));

        let mut shutdown = shutdown;
        loop {
            tokio::select! {
                biased;

                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                result = &mut receive_task => {
                    // Nothing else can produce work once the receive loop is gone.
                    if let Ok(Err(error)) = result {
                        tracing::error!(
                            module = module_path!(),
                            reason = %error,
                            "perch bridge receive loop exited"
                        );
                    }
                    break;
                }
                // The pacer only returns on shutdown.
                _ = &mut pacer_task => break,
                // The alarm drainer is allowed to die alone. A relay that refuses a lane
                // create, or a `case_id` the daemon minted as something other than a UUID,
                // must not stop evidence from reaching the relay: the alarm records stay
                // spooled and a restart replays them, while findings keep publishing.
                result = async {
                    match alarm_task.as_mut() {
                        Some(handle) => handle.await,
                        None => std::future::pending().await,
                    }
                }, if alarm_task.is_some() => {
                    alarm_task = None;
                    match result {
                        Ok(Err(error)) => tracing::error!(
                            module = module_path!(),
                            reason = %error,
                            "perch bridge alarm drainer exited; case channels will not be \
                             provisioned until this daemon restarts"
                        ),
                        Err(error) => tracing::error!(
                            module = module_path!(),
                            reason = %error,
                            "perch bridge alarm drainer panicked; case channels will not be \
                             provisioned until this daemon restarts"
                        ),
                        Ok(Ok(())) => tracing::info!(
                            module = module_path!(),
                            "perch bridge alarm drainer stopped"
                        ),
                    }
                }
            }
        }

        receive_task.abort();
        pacer_task.abort();
        if let Some(handle) = alarm_task {
            handle.abort();
        }

        // The last thing the bridge does is make the spool durable: everything it holds is
        // unpublished, and the pacer resumes from the cursor on the next start.
        if let Err(error) = spools.lock().unwrap_or_else(PoisonError::into_inner).seal() {
            tracing::error!(
                module = module_path!(),
                reason = %error,
                "perch bridge could not seal its spools at shutdown"
            );
        }
        tracing::info!(module = module_path!(), "perch bridge stopped");
    }
}

#[cfg(test)]
mod tests {
    /// T-17: the two RULE 5 headings are present as exact whole lines, so the layering gate
    /// cannot fail on this file after a doc edit.
    #[test]
    fn owns_headings_are_the_gate_literals() {
        let lines: Vec<&str> = include_str!("lib.rs").lines().map(str::trim_end).collect();
        assert!(lines.contains(&"//! ## Owns"));
        assert!(lines.contains(&"//! ## Does not own"));
    }

    /// B6. A signing profile with no usable seed refuses to start.
    ///
    /// The alternative is the failure this whole task exists to prevent: a
    /// bridge that quietly published unsigned envelopes under a profile that
    /// says it signs, emitting a chain no reader could tell from a forged one.
    #[test]
    fn a_signing_profile_with_no_seed_refuses_rather_than_publishing_unsigned() {
        let config = swarm_core::config::PerchBridgeConfig {
            spine_seed_env: "PERCH_TEST_SEED_THAT_IS_NOT_SET".to_string(),
            ..swarm_core::config::PerchBridgeConfig::default()
        };
        let result = crate::spine::SpineSigner::from_config(
            &config,
            "colony-a",
            &["perch-alarm".to_string()],
        );
        assert!(matches!(
            result,
            Err(crate::error::BridgeError::MissingSpineSeed { .. })
        ));
    }
}
