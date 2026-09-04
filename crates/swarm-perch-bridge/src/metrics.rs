//! Metrics: a `perch`-prefixed registry served at `GET /metrics/perch`.
//!
//! # Why a separate registry and a separate route
//!
//! The daemon already exposes `GET /metrics`
//! (`swarm-ingest-runtime/src/ingest/mod.rs` -> `ingest/health.rs`), which encodes
//! ONLY `CriticalPathMetrics` (`swarm-runtime/src/detection/metrics.rs`). That struct's
//! `registry` field is private and has no public accessor -- the only public function over it is
//! `encode_metrics(&CriticalPathMetrics) -> String`. Registering into it
//! means editing `swarm-runtime`, a crate below this one; merging into the handler means editing
//! `swarm-ingest-runtime`'s `health.rs`. A second path costs neither.
//!
//! # THE NAMING TRAP
//!
//! `prometheus-client` appends `_total` to counter sample names on encode. The in-tree evidence:
//! the variable `ingest_events_total` is a `Family<IngestOutcomeLabels, Counter>` registered under
//! the name `"ingest_events"` (`swarm-runtime/src/detection/metrics.rs`) against a
//! `Registry::with_prefix("swarm")`, and encodes as `swarm_ingest_events_total`.
//!
//! So with prefix `perch`, every name in `APPENDIX-NORMATIVE.md` section 6 comes out byte-exact
//! **if and only if** the `_total` suffix is omitted at registration. Registering
//! `"bridge_broadcast_lagged_total"` emits `perch_bridge_broadcast_lagged_total_total`. Test T-11
//! asserts each of the seven appendix names appears exactly once in the encoded text, because this
//! is the kind of mistake that ships and then lives in a dashboard forever.

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use axum::extract::Json;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

use crate::identity::IdentityTable;
use crate::stream::Stream;

/// One `stream` label: the four transport classes.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct StreamLabel {
    /// `evidence`, `telemetry`, `alarm` or `dropped_at_source`.
    pub stream: String,
}

/// A drop, by stream and cause.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DropLabel {
    /// The transport class the loss belongs to.
    pub stream: String,
    /// Exactly four values: `broadcast_lagged`, `spool_evicted`, `spool_torn_tail`,
    /// `publish_window_expired`. A COALESCE IS NOT A DROP and never appears here -- a coalesced
    /// input is counted in `bridge_source_events_published` because its meaning was published.
    pub cause: String,
}

/// A typed relay refusal.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReasonLabel {
    /// The `OkOutcome` discriminant, snake_case.
    pub reason: String,
}

/// One identity slot.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct IdentityLabel {
    /// The slot label, as `Slot::label()` spells it.
    pub identity: String,
}

/// Exactly three values, mirroring [`crate::channels::PromotionClause`]: `held_action`,
/// `correlated_incident`, `manual`. ADR 0018 C4 ships all three as configuration and enables only
/// `manual` first, so a dashboard split on this label is how the other two are shown to be off
/// rather than merely believed to be.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ClauseLabel {
    /// The promotion clause that fired.
    pub clause: String,
}

/// Seconds. A frame that waited more than a tick or two is the interesting case, and a frame that
/// waited an hour is the one an operator has to be told about.
const PUBLISH_LATENCY_BUCKETS_S: [f64; 8] = [0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 30.0, 300.0];
const LATE_PUBLISHED_BUCKETS_S: [f64; 7] = [1.0, 5.0, 30.0, 120.0, 600.0, 1_800.0, 4_200.0];

/// The content type the daemon's own `/metrics` handler already sets.
const OPENMETRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Every metric the bridge publishes, cloneable so each task holds its own handle.
#[derive(Clone)]
pub struct BridgeMetrics {
    broadcast_lagged: Counter<u64>,
    spool_bytes: Family<StreamLabel, Gauge<u64, AtomicU64>>,
    dropped_events: Family<DropLabel, Counter>,
    alarm_spool_full: Counter<u64>,
    publish_latency: Histogram,
    admission_rejections: Family<ReasonLabel, Counter>,
    late_published: Histogram,
    ingested: Family<StreamLabel, Counter>,
    source_events_published: Family<StreamLabel, Counter>,
    coalesced: Family<DropLabel, Counter>,
    skipped_unpublished: Family<StreamLabel, Counter>,
    redacted_library_loads: Counter<u64>,
    spool_torn_tail: Counter<u64>,
    spool_corrupt: Counter<u64>,
    connection_state: Family<IdentityLabel, Gauge>,
    case_channel_conflict: Counter<u64>,
    case_channels_created: Family<ClauseLabel, Counter>,
    hold_undeliverable: Counter<u64>,
    lease_store_absent: Counter<u64>,
    unknown_action_kind: Counter<u64>,
}

impl BridgeMetrics {
    /// Builds the registry and registers every metric.
    ///
    /// The seven `APPENDIX-NORMATIVE.md` section 6 names, plus what this crate adds to make its
    /// own honesty rules checkable from a scrape rather than a debugger.
    #[allow(clippy::too_many_lines)]
    pub fn new() -> (Self, Arc<Mutex<Registry>>) {
        let mut registry = Registry::with_prefix("perch");

        // ---- the seven the appendix names ------------------------------------------------
        let broadcast_lagged = Counter::<u64>::default();
        registry.register(
            "bridge_broadcast_lagged", // -> perch_bridge_broadcast_lagged_total
            "Events lost to a lagged tokio broadcast receiver before the bridge saw them",
            broadcast_lagged.clone(),
        );

        let spool_bytes = Family::<StreamLabel, Gauge<u64, AtomicU64>>::default();
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

        let publish_latency = Histogram::new(PUBLISH_LATENCY_BUCKETS_S);
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

        let late_published = Histogram::new(LATE_PUBLISHED_BUCKETS_S);
        registry.register(
            "bridge_late_published_seconds",
            "Seconds between a card's emitted_at_ms and the created_at stamped at publish",
            late_published.clone(),
        );

        // ---- what this crate adds --------------------------------------------------------
        //
        // The three terms of the accounting invariant:
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

        // A record whose card type this milestone does not publish. Its meaning is not lost --
        // it stays in the daemon's own stores -- so it is neither a drop nor a publish, and it
        // needs a third name or the accounting invariant reads as a leak.
        let skipped_unpublished = Family::<StreamLabel, Counter>::default();
        registry.register(
            "bridge_skipped_unpublished",
            "Spooled records committed without a card because no producer exists yet, by stream",
            skipped_unpublished.clone(),
        );

        let redacted_library_loads = Counter::<u64>::default();
        registry.register(
            "bridge_redacted_library_loads",
            "Unexpected library paths stripped from a TamperAlert before it reached the spool",
            redacted_library_loads.clone(),
        );

        let spool_torn_tail = Counter::<u64>::default();
        registry.register(
            "bridge_spool_torn_tail",
            "Segments whose torn tail was truncated at open",
            spool_torn_tail.clone(),
        );
        let spool_corrupt = Counter::<u64>::default();
        registry.register(
            "bridge_spool_corrupt",
            "Segments quarantined because a checksum failed mid-file",
            spool_corrupt.clone(),
        );

        let connection_state = Family::<IdentityLabel, Gauge>::default();
        registry.register(
            "bridge_connection_state",
            "1 when the identity's relay socket is established, 0 otherwise",
            connection_state.clone(),
        );

        // One case channel per `hunt_id`, first-write-wins. A non-zero value means two parties
        // minted case ids for one investigation and a daemon incident record now names a channel
        // the bridge refused to create -- failure mode F20.
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

        let hold_undeliverable = Counter::<u64>::default();
        registry.register(
            "bridge_hold_undeliverable",
            "Times no operator principal holding OperatorScope::Approve carried a nostr pubkey",
            hold_undeliverable.clone(),
        );
        let lease_store_absent = Counter::<u64>::default();
        registry.register(
            "bridge_lease_store_absent",
            "Times the containment lease poll found no sweep to read",
            lease_store_absent.clone(),
        );
        let unknown_action_kind = Counter::<u64>::default();
        registry.register(
            "bridge_unknown_action_kind",
            "Response records whose action kind this build does not map to a wire kind",
            unknown_action_kind.clone(),
        );

        (
            Self {
                broadcast_lagged,
                spool_bytes,
                dropped_events,
                alarm_spool_full,
                publish_latency,
                admission_rejections,
                late_published,
                ingested,
                source_events_published,
                coalesced,
                skipped_unpublished,
                redacted_library_loads,
                spool_torn_tail,
                spool_corrupt,
                connection_state,
                case_channel_conflict,
                case_channels_created,
                hold_undeliverable,
                lease_store_absent,
                unknown_action_kind,
            },
            Arc::new(Mutex::new(registry)),
        )
    }

    fn stream_label(stream: Stream) -> StreamLabel {
        StreamLabel {
            stream: stream.as_str().to_string(),
        }
    }

    /// One `RuntimeEvent` arrived from the broadcast and was classified.
    pub fn ingested(&self, stream: Stream) {
        self.ingested
            .get_or_create(&Self::stream_label(stream))
            .inc();
    }

    /// The broadcast dropped `count` events before the bridge saw them.
    pub fn broadcast_lagged(&self, count: u64) {
        self.broadcast_lagged.inc_by(count);
    }

    /// `count` library paths were stripped from a `TamperAlert`.
    pub fn redacted_library_loads(&self, count: usize) {
        self.redacted_library_loads.inc_by(count as u64);
    }

    /// The alarm spool refused an append because it was at its budget.
    pub fn alarm_spool_full(&self) {
        self.alarm_spool_full.inc();
    }

    /// A card reached the relay and was acknowledged.
    pub fn source_events_published(&self, stream: Stream) {
        self.source_events_published
            .get_or_create(&Self::stream_label(stream))
            .inc();
    }

    /// A spooled record was committed without a card because no producer exists for it yet.
    pub fn skipped_unpublished(&self, stream: Stream) {
        self.skipped_unpublished
            .get_or_create(&Self::stream_label(stream))
            .inc();
    }

    /// An input was folded into another by a meaning-preserving rule.
    pub fn coalesced(&self, stream: Stream, cause: &str) {
        self.coalesced
            .get_or_create(&DropLabel {
                stream: stream.as_str().to_string(),
                cause: cause.to_string(),
            })
            .inc();
    }

    /// An accepted event the bridge cannot deliver.
    pub fn dropped_event(&self, stream: Stream, cause: &str) {
        self.dropped_events
            .get_or_create(&DropLabel {
                stream: stream.as_str().to_string(),
                cause: cause.to_string(),
            })
            .inc();
    }

    /// Publishes the current disk-spool sizes.
    pub fn observe_spool_bytes(&self, stream: Stream, bytes: u64) {
        self.spool_bytes
            .get_or_create(&Self::stream_label(stream))
            .set(bytes);
    }

    /// Seconds from the pacer tick to the relay's OK.
    pub fn observe_publish_latency(&self, seconds: f64) {
        self.publish_latency.observe(seconds);
    }

    /// Seconds between a card's `emitted_at_ms` and its stamped `created_at`.
    pub fn observe_late_published(&self, seconds: f64) {
        self.late_published.observe(seconds);
    }

    /// A typed relay refusal.
    pub fn admission_rejection(&self, reason: &str) {
        self.admission_rejections
            .get_or_create(&ReasonLabel {
                reason: reason.to_string(),
            })
            .inc();
    }

    /// A segment's torn tail was truncated at open.
    pub fn spool_torn_tail(&self) {
        self.spool_torn_tail.inc();
    }

    /// A segment was quarantined because a checksum failed mid-file.
    pub fn spool_corrupt(&self) {
        self.spool_corrupt.inc();
    }

    /// Whether an identity's relay socket is established.
    pub fn connection_state(&self, identity: &str, connected: bool) {
        self.connection_state
            .get_or_create(&IdentityLabel {
                identity: identity.to_string(),
            })
            .set(i64::from(connected));
    }

    /// A `CasePromoted` named a case id different from the one already routed for its hunt.
    pub fn case_channel_conflict(&self) {
        self.case_channel_conflict.inc();
    }

    /// A case channel was provisioned under `clause`.
    pub fn case_channel_created(&self, clause: &str) {
        self.case_channels_created
            .get_or_create(&ClauseLabel {
                clause: clause.to_string(),
            })
            .inc();
    }

    /// No operator principal holding `OperatorScope::Approve` carried a Nostr pubkey.
    pub fn hold_undeliverable(&self) {
        self.hold_undeliverable.inc();
    }

    /// The containment lease poll found no sweep to read.
    pub fn lease_store_absent(&self) {
        self.lease_store_absent.inc();
    }

    /// A response record carried an action kind this build does not map.
    pub fn unknown_action_kind(&self) {
        self.unknown_action_kind.inc();
    }
}

/// The debug-only stall request body.
#[derive(Debug, serde::Deserialize)]
pub struct StallRequest {
    /// Milliseconds to sleep before the next `recv()`.
    pub ms: u64,
}

/// `GET /metrics/perch`, `GET /metrics/perch/healthz` and `GET /metrics/perch/identities`.
///
/// Merged by `swarm_detect` beside `containment_operator_router`.
///
/// `POST /metrics/perch/test/stall` exists in debug builds only. In a release build the route is
/// never registered, so the path answers 404 — the same shape a feature that does not exist has.
pub fn router(
    registry: Arc<Mutex<Registry>>,
    identities: Arc<IdentityTable>,
    colony_id: String,
    stall: Arc<AtomicU64>,
) -> axum::Router {
    let identities_for_route = Arc::clone(&identities);
    let router = axum::Router::new()
        .route(
            "/metrics/perch",
            get(move || encode_registry(Arc::clone(&registry))),
        )
        .route("/metrics/perch/healthz", get(|| async { "ok" }))
        // D-FC-2 default: public keys only, unauthenticated, the admitted-issuer set the
        // console reads to decide which markers may render as cards (INV-15).
        .route(
            "/metrics/perch/identities",
            get(move || identities_json(Arc::clone(&identities_for_route), colony_id.clone())),
        );

    #[cfg(debug_assertions)]
    let router = router.route(
        "/metrics/perch/test/stall",
        axum::routing::post(move |Json(body): Json<StallRequest>| {
            stall_handler(Arc::clone(&stall), body)
        }),
    );
    #[cfg(not(debug_assertions))]
    let _ = stall;

    router
}

async fn encode_registry(registry: Arc<Mutex<Registry>>) -> impl IntoResponse {
    let mut out = String::new();
    {
        let guard = registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = encode(&mut out, &guard);
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, OPENMETRICS_CONTENT_TYPE)],
        out,
    )
}

async fn identities_json(identities: Arc<IdentityTable>, colony_id: String) -> impl IntoResponse {
    let listed: Vec<serde_json::Value> = identities
        .public_identities()
        .into_iter()
        .map(|(slot, pubkey)| serde_json::json!({"slot": slot, "pubkey": pubkey}))
        .collect();
    Json(serde_json::json!({"colony_id": colony_id, "identities": listed}))
}

#[cfg(debug_assertions)]
async fn stall_handler(stall: Arc<AtomicU64>, body: StallRequest) -> impl IntoResponse {
    stall.store(body.ms, std::sync::atomic::Ordering::Release);
    (StatusCode::ACCEPTED, "stall armed")
}

// NOT EXPORTED HERE, DELIBERATELY: `perch_queue_reconcile_divergences_total`.
//
// `APPENDIX-NORMATIVE.md` section 4 layer 3 counts divergences between `query_needs_action` and
// `GET /v1/response/holds`. Both reads happen in the console; the bridge holds no relay read path
// at all and cannot observe either. It belongs to `14-CLIENT-ARCHITECTURE.md`. Recorded here so it
// is not implemented twice or, worse, once in the wrong process where it would always read zero.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn encoded() -> String {
        let (metrics, registry) = BridgeMetrics::new();
        // Touch every family so its samples exist in the encoding too.
        metrics.ingested(Stream::Evidence);
        metrics.broadcast_lagged(2);
        metrics.redacted_library_loads(3);
        metrics.alarm_spool_full();
        metrics.source_events_published(Stream::Evidence);
        metrics.skipped_unpublished(Stream::Alarm);
        metrics.coalesced(Stream::Evidence, "escalation_edge");
        metrics.dropped_event(Stream::Evidence, "publish_window_expired");
        metrics.observe_spool_bytes(Stream::Evidence, 4_096);
        metrics.observe_publish_latency(0.4);
        metrics.observe_late_published(90.0);
        metrics.admission_rejection("rate_limited");
        metrics.spool_torn_tail();
        metrics.spool_corrupt();
        metrics.connection_state("perch-alarm", true);
        metrics.case_channel_conflict();
        metrics.case_channel_created("manual");
        metrics.hold_undeliverable();
        metrics.lease_store_absent();
        metrics.unknown_action_kind();
        let mut out = String::new();
        encode(&mut out, &registry.lock().unwrap()).unwrap();
        out
    }

    /// Asserts the dashboard-visible sample name comes out byte-exact, exactly once.
    ///
    /// `prometheus-client` 0.23 puts the BASE name on the `# HELP` and `# TYPE` lines and the
    /// `_total` suffix on the counter's sample line only, so a single substring count over the
    /// whole encoding is not the right test for both counters and gauges. Measured against the
    /// encoder rather than assumed: the plan's `# HELP {name} ` form matches no counter.
    fn assert_encoded_once(out: &str, name: &str) {
        let base = name.strip_suffix("_total").unwrap_or(name);
        assert_eq!(
            out.matches(&format!("# HELP {base} ")).count(),
            1,
            "{name} must be registered exactly once\n{out}"
        );
        let samples = out
            .lines()
            .filter(|line| {
                line.strip_prefix(name).is_some_and(|rest| {
                    // A counter or gauge sample is `name ` or `name{...}`; a histogram's
                    // samples are `name_sum`, `name_count` and `name_bucket{le=...}`.
                    rest.starts_with('{')
                        || rest.starts_with(' ')
                        || rest.starts_with("_sum")
                        || rest.starts_with("_count")
                        || rest.starts_with("_bucket")
                })
            })
            .count();
        assert!(samples >= 1, "{name} has no sample line\n{out}");
    }

    #[test]
    fn the_seven_appendix_names_encode_exactly_once_without_a_double_total() {
        let out = encoded();
        for name in [
            "perch_bridge_broadcast_lagged_total",
            "perch_bridge_spool_bytes",
            "perch_bridge_dropped_events_total",
            "perch_bridge_alarm_spool_full_total",
            "perch_bridge_publish_latency_seconds",
            "perch_bridge_admission_rejections_total",
            "perch_bridge_late_published_seconds",
        ] {
            assert_encoded_once(&out, name);
        }
        assert!(!out.contains("_total_total"));
    }

    #[test]
    fn every_added_name_encodes_exactly_once_too() {
        let out = encoded();
        for name in [
            "perch_bridge_ingested_total",
            "perch_bridge_source_events_published_total",
            "perch_bridge_coalesced_total",
            "perch_bridge_skipped_unpublished_total",
            "perch_bridge_redacted_library_loads_total",
            "perch_bridge_spool_torn_tail_total",
            "perch_bridge_spool_corrupt_total",
            "perch_bridge_connection_state",
            "perch_bridge_case_channel_conflict_total",
            "perch_bridge_case_channels_created_total",
            "perch_bridge_hold_undeliverable_total",
            "perch_bridge_lease_store_absent_total",
            "perch_bridge_unknown_action_kind_total",
        ] {
            assert_encoded_once(&out, name);
        }
    }

    #[test]
    fn a_drop_carries_its_stream_and_its_cause() {
        let out = encoded();
        assert!(
            out.contains(r#"perch_bridge_dropped_events_total{stream="evidence",cause="publish_window_expired"}"#),
            "{out}"
        );
    }
}
