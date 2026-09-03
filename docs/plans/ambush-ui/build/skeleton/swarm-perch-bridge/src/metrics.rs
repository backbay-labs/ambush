//! Metrics: a `perch`-prefixed registry served at `GET /metrics/perch`.
//!
//! # Why a separate registry and a separate route
//!
//! The daemon already exposes `GET /metrics`
//! (`swarm-ingest-runtime/src/ingest/mod.rs:2547` -> `ingest/health.rs:677-702`), which encodes
//! ONLY `CriticalPathMetrics` (`swarm-runtime/src/detection/metrics.rs:71-98`). That struct's
//! `registry` field is private and has no public accessor -- the only public function over it is
//! `encode_metrics(&CriticalPathMetrics) -> String` (`metrics.rs:446-454`). Registering into it
//! means editing `swarm-runtime`, a crate below this one; merging into the handler means editing
//! `swarm-ingest-runtime`'s `health.rs`. A second path costs neither.
//!
//! # THE NAMING TRAP
//!
//! `prometheus-client` appends `_total` to counter sample names on encode. The in-tree evidence:
//! the variable `ingest_events_total` is a `Family<IngestOutcomeLabels, Counter>` registered under
//! the name `"ingest_events"` (`swarm-runtime/src/detection/metrics.rs:101, 129-133`) against a
//! `Registry::with_prefix("swarm")` (`:126`), and encodes as `swarm_ingest_events_total`.
//!
//! So with prefix `perch`, every name in `APPENDIX-NORMATIVE.md` section 6 comes out byte-exact
//! **if and only if** the `_total` suffix is omitted at registration. Registering
//! `"bridge_broadcast_lagged_total"` emits `perch_bridge_broadcast_lagged_total_total`. Test T-11
//! asserts each of the seven appendix names appears exactly once in the encoded text, because this
//! is the kind of mistake that ships and then lives in a dashboard forever.

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

use crate::stream::Stream;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct StreamLabel {
    pub stream: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DropLabel {
    pub stream: String,
    /// Exactly four values: `broadcast_lagged`, `spool_evicted`, `spool_torn_tail`,
    /// `publish_window_expired`. A COALESCE IS NOT A DROP and never appears here -- a coalesced
    /// input is counted in `bridge_source_events_published` because its meaning was published.
    pub cause: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReasonLabel {
    pub reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct IdentityLabel {
    pub identity: String,
}

/// Exactly three values, mirroring [`crate::channels::PromotionClause`]: `held_action`,
/// `correlated_incident`, `manual`. ADR 0018 C4 ships all three as configuration and enables only
/// `manual` first, so a dashboard split on this label is how the other two are shown to be off
/// rather than merely believed to be.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ClauseLabel {
    pub clause: String,
}

/// Seconds. A frame that waited more than a tick or two is the interesting case, and a frame that
/// waited an hour is the one an operator has to be told about.
const PUBLISH_LATENCY_BUCKETS_S: [f64; 8] = [0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 30.0, 300.0];
const LATE_PUBLISHED_BUCKETS_S: [f64; 7] = [1.0, 5.0, 30.0, 120.0, 600.0, 1_800.0, 4_200.0];

#[derive(Clone)]
pub struct BridgeMetrics {
    _private: (),
}

impl BridgeMetrics {
    /// Builds the registry and registers every metric.
    ///
    /// The seven `APPENDIX-NORMATIVE.md` section 6 names, plus what this crate adds to make its
    /// own honesty rules checkable from a scrape rather than a debugger.
    pub fn new() -> (Self, Registry) {
        let mut registry = Registry::with_prefix("perch");

        // ---- the seven the appendix names ------------------------------------------------
        let broadcast_lagged = Counter::<u64>::default();
        registry.register(
            "bridge_broadcast_lagged", // -> perch_bridge_broadcast_lagged_total
            "Events lost to a lagged tokio broadcast receiver before the bridge saw them",
            broadcast_lagged.clone(),
        );

        let spool_bytes = Family::<StreamLabel, Gauge<u64, std::sync::atomic::AtomicU64>>::default();
        registry.register(
            "bridge_spool_bytes", // -> perch_bridge_spool_bytes
            "Bytes currently held in each disk spool",
            spool_bytes.clone(),
        );

        let dropped_events = Family::<DropLabel, Counter>::default();
        registry.register(
            "bridge_dropped_events", // -> perch_bridge_dropped_events_total
            "Events the bridge accepted and cannot deliver, by stream and cause",
            dropped_events.clone(),
        );

        let alarm_spool_full = Counter::<u64>::default();
        registry.register(
            "bridge_alarm_spool_full", // -> perch_bridge_alarm_spool_full_total
            "Times the alarm spool reached its budget and refused new alarm work",
            alarm_spool_full.clone(),
        );

        let publish_latency = Histogram::new(PUBLISH_LATENCY_BUCKETS_S.into_iter());
        registry.register(
            "bridge_publish_latency_seconds",
            "Seconds from pacer tick to the relay OK",
            publish_latency.clone(),
        );

        let admission_rejections = Family::<ReasonLabel, Counter>::default();
        registry.register(
            "bridge_admission_rejections", // -> perch_bridge_admission_rejections_total
            "Relay rejections by typed reason",
            admission_rejections.clone(),
        );

        let late_published = Histogram::new(LATE_PUBLISHED_BUCKETS_S.into_iter());
        registry.register(
            "bridge_late_published_seconds",
            "Seconds between a card's emitted_at_ms and the created_at stamped at publish",
            late_published.clone(),
        );

        // ---- what this crate adds --------------------------------------------------------
        //
        // The three terms of the accounting invariant, stated verbatim at
        // `BUZZ crates/buzz-acp/src/lib.rs:453`:
        //     ingested == dropped + Sum(source_events over published)
        // Exported so an operator can check it from a scrape.
        let ingested = Family::<StreamLabel, Counter>::default();
        registry.register(
            "bridge_ingested",
            "RuntimeEvents received from the broadcast, by stream",
            ingested.clone(),
        );
        let source_events_published = Family::<StreamLabel, Counter>::default();
        registry.register(
            "bridge_source_events_published",
            "Source events whose meaning reached the relay, by stream",
            source_events_published.clone(),
        );
        let coalesced = Family::<DropLabel, Counter>::default();
        registry.register(
            "bridge_coalesced",
            "Inputs folded into another by a meaning-preserving rule. NOT a drop",
            coalesced.clone(),
        );

        // One case channel per `hunt_id`, first-write-wins. A non-zero value means two parties
        // minted case ids for one investigation and a daemon incident record now names a channel
        // the bridge refused to create -- failure mode F20, and the symptom the amendment in
        // `11-BRIDGE-CRATE.md` section 9.1 exists to make impossible.
        let case_channel_conflict = Counter::<u64>::default();
        registry.register(
            "bridge_case_channel_conflict", // -> perch_bridge_case_channel_conflict_total
            "CasePromoted events naming a case id different from the one already routed for \
             their hunt_id",
            case_channel_conflict.clone(),
        );

        // Case channels this bridge created, by promotion clause. The denominator ADR 0018 C4's
        // promoted/suppressed ratio needs, from the process that actually did the creating.
        let case_channels_created = Family::<ClauseLabel, Counter>::default();
        registry.register(
            "bridge_case_channels_created", // -> perch_bridge_case_channels_created_total
            "Case channels provisioned, by promotion clause",
            case_channels_created.clone(),
        );

        let _ = (&spool_bytes, &dropped_events, &alarm_spool_full, &publish_latency,
                 &admission_rejections, &late_published, &ingested,
                 &source_events_published, &coalesced, &broadcast_lagged,
                 &case_channel_conflict, &case_channels_created);

        todo!("register the remaining seven: bridge_spool_torn_tail, bridge_spool_corrupt, \
               bridge_connection_state, bridge_hold_undeliverable, bridge_lease_store_absent, \
               bridge_unknown_action_kind, bridge_watch_membership_refused (publish_window_expired \
               is NOT a separate counter -- it is a `cause` label on bridge_dropped_events, which \
               is its only home); \
               then return (Self { .. }, registry)")
    }

    pub fn ingested(&self, stream: Stream) {
        let _ = stream;
        todo!("bridge_ingested{{stream}}.inc()")
    }

    pub fn broadcast_lagged(&self, count: u64) {
        let _ = count;
        todo!("bridge_broadcast_lagged.inc_by(count)")
    }
}

/// `GET /metrics/perch` and `GET /metrics/perch/healthz`.
///
/// Merged by `swarm_detect` beside `containment_operator_router`
/// (`swarm-runtime-http/src/bin/swarm_detect.rs:1113-1125`).
pub fn router(registry: std::sync::Arc<std::sync::Mutex<Registry>>) -> axum::Router {
    let _ = registry;
    todo!("two routes; content-type application/openmetrics-text; version=1.0.0; charset=utf-8, \
           matching ingest/health.rs:693-695")
}

// NOT EXPORTED HERE, DELIBERATELY: `perch_queue_reconcile_divergences_total`.
//
// `APPENDIX-NORMATIVE.md` section 4 layer 3 counts divergences between `query_needs_action` and
// `GET /v1/response/holds`. Both reads happen in the console; the bridge holds no relay read path
// at all and cannot observe either. It belongs to `14-CLIENT-ARCHITECTURE.md`. Recorded here so it
// is not implemented twice or, worse, once in the wrong process where it would always read zero.
