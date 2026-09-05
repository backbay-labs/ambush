use super::*;

use swarm_core::agent::SwarmMode;
use swarm_core::pheromone::ThreatClass;
use swarm_runtime::runtime_events::RuntimeThreatConcentration;

use crate::publish::AlarmAdmission;
use crate::publish::OkOutcome;
use crate::spool::{IssuerIdx, Record};

/// Records every frame it is handed and answers with a scripted outcome.
struct Recorder {
    published: Vec<(u16, serde_json::Value)>,
    outcome: OkOutcome,
}

impl Recorder {
    fn accepting() -> Self {
        Self {
            published: Vec::new(),
            outcome: OkOutcome::Accepted,
        }
    }
}

impl FramePublisher for Recorder {
    async fn publish(&mut self, frame: &Frame) -> Result<OkOutcome, BridgeError> {
        let body: serde_json::Value =
            serde_json::from_str(&frame.signed.content).expect("frame content is JSON");
        self.published.push((frame.signed.kind.as_u16(), body));
        Ok(self.outcome.clone())
    }

    async fn submit_alarm(
        &mut self,
        _frame: &Frame,
        _now_ms: i64,
    ) -> Result<AlarmAdmission, BridgeError> {
        unreachable!("the telemetry publisher never submits an alarm")
    }
}

fn spools_with(events: &[RuntimeEvent]) -> Arc<Mutex<SpoolSet>> {
    let dir = tempfile::tempdir().expect("a temp dir");
    let mut set = SpoolSet::open(dir.path(), "colony", 1 << 20, 8 << 20).expect("a spool set");
    for event in events {
        let class = crate::stream::classify(event);
        let record = Record::from_event(event, 0 as IssuerIdx).expect("a record");
        let _ = set.append(class, record);
    }
    // The dir must outlive the set; leak it, this is a test.
    std::mem::forget(dir);
    Arc::new(Mutex::new(set))
}

fn snapshot(at: i64, mode: SwarmMode, strength: f64) -> RuntimeEvent {
    RuntimeEvent::ConcentrationSnapshot {
        emitted_at_ms: at,
        current_mode: mode,
        concentrations: vec![RuntimeThreatConcentration {
            threat_class: ThreatClass::Execution,
            total_strength: strength,
            distinct_sources: 2,
            peak_confidence: 0.9,
        }],
    }
}

fn ingest(source: &str, accepted: bool) -> RuntimeEvent {
    RuntimeEvent::Ingest {
        emitted_at_ms: 0,
        correlation_id: "c".into(),
        event_id: "e".into(),
        source: source.into(),
        host_id: Some("web-04".into()),
        accepted,
        reason: None,
    }
}

async fn tick_once(
    spools: &Arc<Mutex<SpoolSet>>,
    publisher: &mut Recorder,
    seqs: &mut BTreeMap<u16, u64>,
    now_ms: i64,
) {
    let (metrics, _registry) = BridgeMetrics::new();
    let keys = nostr::Keys::generate();
    publish_tick(
        spools,
        publisher,
        &metrics,
        &keys,
        "spine-issuer",
        0 as IssuerIdx,
        seqs,
        now_ms,
    )
    .await
    .expect("a tick");
}

#[tokio::test]
async fn a_tick_publishes_the_gauge_even_when_nothing_was_ingested() {
    let spools = spools_with(&[]);
    let mut publisher = Recorder::accepting();
    let mut seqs = BTreeMap::new();
    tick_once(&spools, &mut publisher, &mut seqs, 1_000).await;

    // Zero accepted is a measurement -- the collectors are connected and quiet.
    assert_eq!(
        publisher
            .published
            .iter()
            .map(|(k, _)| *k)
            .collect::<Vec<_>>(),
        vec![26000]
    );
    assert_eq!(publisher.published[0].1["accepted"], 0);
}

#[tokio::test]
async fn ingest_events_are_counted_though_they_are_never_spooled() {
    // `Ingest` is DroppedAtSource: no record survives, but the gauge IS the
    // counts, so the window must have seen them.
    let spools = spools_with(&[
        ingest("syslog-collector", true),
        ingest("syslog-collector", true),
        ingest("edr-collector", false),
    ]);
    let mut publisher = Recorder::accepting();
    let mut seqs = BTreeMap::new();
    tick_once(&spools, &mut publisher, &mut seqs, 1_000).await;

    let gauge = &publisher.published[0].1;
    assert_eq!(gauge["accepted"], 2);
    assert_eq!(gauge["rejected"], 1);
    assert_eq!(gauge["by_source"]["syslog-collector"], 2);
    // The host on every one of those events reaches no field.
    assert!(!gauge.to_string().contains("web-04"));
}

#[tokio::test]
async fn the_window_resets_between_ticks() {
    let spools = spools_with(&[ingest("syslog-collector", true)]);
    let mut publisher = Recorder::accepting();
    let mut seqs = BTreeMap::new();
    tick_once(&spools, &mut publisher, &mut seqs, 1_000).await;
    tick_once(&spools, &mut publisher, &mut seqs, 2_000).await;

    assert_eq!(publisher.published[0].1["accepted"], 1);
    // A window that carried its predecessor's counts would read as an
    // accelerating collector that is in fact idle.
    assert_eq!(publisher.published[1].1["accepted"], 0);
}

#[tokio::test]
async fn the_concentration_frame_reports_how_many_ticks_it_collapsed() {
    // The spool is last-wins, so only the newest snapshot survives -- but the
    // frame must still say it stands for thirty.
    let mut events = Vec::new();
    for i in 0..30 {
        events.push(snapshot(1_000 + i, SwarmMode::Normal, i as f64));
    }
    let spools = spools_with(&events);
    let mut publisher = Recorder::accepting();
    let mut seqs = BTreeMap::new();
    tick_once(&spools, &mut publisher, &mut seqs, 5_000).await;

    let frame = publisher
        .published
        .iter()
        .find(|(kind, _)| *kind == 26001)
        .expect("a 26001 frame");
    assert_eq!(frame.1["coalesced_from"], 30);
    assert_eq!(
        frame.1["concentrations"][0]["total_strength"], 29.0,
        "the LAST snapshot wins, never an average"
    );
}

#[tokio::test]
async fn a_refused_frame_is_dropped_rather_than_retried() {
    let spools = spools_with(&[snapshot(1_000, SwarmMode::Normal, 1.0)]);
    let mut publisher = Recorder::accepting();
    publisher.outcome = OkOutcome::RateLimited {
        retry_in_secs: Some(5),
    };
    let mut seqs = BTreeMap::new();
    tick_once(&spools, &mut publisher, &mut seqs, 1_000).await;
    let refused = publisher.published.len();

    // The next tick has nothing to say: the slots were drained. A replayed
    // ephemeral is a lie about now, so nothing is re-sent.
    publisher.outcome = OkOutcome::Accepted;
    tick_once(&spools, &mut publisher, &mut seqs, 2_000).await;
    assert_eq!(
        publisher.published.len(),
        refused + 1,
        "only the always-published gauge; the refused 26001 is gone, not retried"
    );
    assert_eq!(publisher.published[refused].0, 26000);
}

#[tokio::test]
async fn the_sequence_continues_across_ticks_so_a_gap_is_visible() {
    let spools = spools_with(&[]);
    let mut publisher = Recorder::accepting();
    let mut seqs = BTreeMap::new();
    tick_once(&spools, &mut publisher, &mut seqs, 1_000).await;
    tick_once(&spools, &mut publisher, &mut seqs, 2_000).await;
    tick_once(&spools, &mut publisher, &mut seqs, 3_000).await;

    let seq: Vec<_> = publisher
        .published
        .iter()
        .map(|(_, body)| body["seq"].as_u64().expect("a seq"))
        .collect();
    assert_eq!(seq, vec![1, 2, 3]);
}

#[tokio::test]
async fn the_frames_carry_no_tags_because_they_are_community_global() {
    let spools = spools_with(&[snapshot(1_000, SwarmMode::Normal, 1.0)]);
    let mut publisher = Recorder::accepting();
    let mut seqs = BTreeMap::new();
    let (metrics, _registry) = BridgeMetrics::new();
    let keys = nostr::Keys::generate();

    // Re-run the tick against a publisher that inspects the signed event, not
    // just its content: an `h` would scope a colony state to one channel and a
    // `p` would page someone.
    struct TagSpy(Vec<usize>);
    impl FramePublisher for TagSpy {
        async fn publish(&mut self, frame: &Frame) -> Result<OkOutcome, BridgeError> {
            self.0.push(frame.signed.tags.len());
            Ok(OkOutcome::Accepted)
        }
        async fn submit_alarm(
            &mut self,
            _frame: &Frame,
            _now_ms: i64,
        ) -> Result<AlarmAdmission, BridgeError> {
            unreachable!()
        }
    }
    let mut spy = TagSpy(Vec::new());
    publish_tick(
        &spools,
        &mut spy,
        &metrics,
        &keys,
        "i",
        0 as IssuerIdx,
        &mut seqs,
        1_000,
    )
    .await
    .expect("a tick");
    assert!(!spy.0.is_empty());
    assert!(spy.0.iter().all(|count| *count == 0), "tags: {:?}", spy.0);
    let _ = &mut publisher;
}
