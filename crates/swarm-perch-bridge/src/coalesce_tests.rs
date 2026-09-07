use super::*;
use std::collections::BTreeMap;
use swarm_core::agent::{AgentHealth, AgentRole, SwarmMode};
use swarm_core::pheromone::ThreatClass;
use swarm_runtime::runtime_events::RuntimeThreatConcentration;

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

#[test]
fn the_ingest_gauge_counts_and_never_carries_a_host() {
    let rate = ingest_rate(&[
        ingest("syslog-collector", true),
        ingest("syslog-collector", true),
        ingest("edr-collector", false),
    ]);
    assert_eq!(rate.window_ms, COALESCE_WINDOW_MS);
    assert_eq!(rate.accepted, 2);
    assert_eq!(rate.rejected, 1);
    assert_eq!(rate.by_source.get("syslog-collector"), Some(&2));
    assert_eq!(rate.by_source.get("edr-collector"), Some(&1));
    // `host_id` is on every one of those events and reaches no field here.
    let json = serde_json::to_string(&rate).expect("serialised");
    assert!(
        !json.contains("web-04"),
        "a host id must not reach a global frame"
    );
}

#[test]
fn a_source_that_looks_like_a_host_is_replaced_by_a_visible_sentinel() {
    // The cost of a false positive is a sentinel an operator can act on; the
    // cost of a false negative is a host id on a community-global frame.
    for source in ["10.0.0.4", "web-04.corp.internal", "192.168.1.1"] {
        let rate = ingest_rate(&[ingest(source, true)]);
        assert_eq!(
            rate.by_source.keys().collect::<Vec<_>>(),
            vec![SUSPECT_SOURCE],
            "source {source:?} must not reach the wire"
        );
    }
}

#[test]
fn an_empty_ingest_window_is_zeroes_and_not_an_absent_frame() {
    // Zero accepted IS a measurement: the collectors are connected and quiet.
    // That differs from no concentration frame, which means nothing was said.
    let rate = ingest_rate(&[]);
    assert_eq!((rate.accepted, rate.rejected), (0, 0));
    assert!(rate.by_source.is_empty());
}

#[test]
fn the_concentration_frame_keeps_the_last_snapshot_not_an_average() {
    let frame = concentration_frame(
        &[
            snapshot(1_000, SwarmMode::Normal, 1.0),
            snapshot(3_000, SwarmMode::Alert, 5.0),
            snapshot(2_000, SwarmMode::Normal, 2.0),
        ],
        3,
    )
    .expect("a frame");
    assert_eq!(frame.coalesced_from, 3);
    assert_eq!(frame.concentrations[0].total_strength, 5.0);
    assert_eq!(frame.current_mode, WireSwarmMode::Alert);
    // An average of a decaying quantity is a number the substrate never held.
    assert_ne!(
        frame.concentrations[0].total_strength,
        (1.0 + 5.0 + 2.0) / 3.0
    );
}

#[test]
fn the_observed_time_is_seconds_and_the_field_says_so() {
    let frame = concentration_frame(&[snapshot(1_773_738_881_000, SwarmMode::Normal, 1.0)], 1)
        .expect("a frame");
    assert_eq!(frame.observed_at_seconds, 1_773_738_881);
}

#[test]
fn an_empty_window_publishes_no_concentration_frame() {
    // Not a frame of zeroes: an empty window is "the bridge saw nothing", and
    // a zero frame would tell the wall the substrate went quiet.
    assert!(concentration_frame(&[], 0).is_none());
    assert!(concentration_frame(&[ingest("s", true)], 0).is_none());
}

#[test]
fn health_takes_the_newest_state_and_actions_add() {
    let events = vec![
        RuntimeEvent::AgentHealth {
            emitted_at_ms: 1_000,
            agent_id: "a1".into(),
            role: AgentRole::Whisker,
            from: Some(AgentHealth::Healthy),
            to: AgentHealth::Degraded,
        },
        RuntimeEvent::AgentAction {
            emitted_at_ms: 1_100,
            agent_id: "a1".into(),
            role: AgentRole::Whisker,
            action_kind: "scan".into(),
            hunt_id: Some("hunt-1".into()),
            details: serde_json::json!({ "command_line": "rm -rf /" }),
        },
        RuntimeEvent::AgentAction {
            emitted_at_ms: 1_200,
            agent_id: "a1".into(),
            role: AgentRole::Whisker,
            action_kind: "scan".into(),
            hunt_id: None,
            details: serde_json::Value::Null,
        },
        RuntimeEvent::AgentHealth {
            emitted_at_ms: 1_500,
            agent_id: "a1".into(),
            role: AgentRole::Whisker,
            from: Some(AgentHealth::Degraded),
            to: AgentHealth::Failed,
        },
    ];
    let frame = agent_health_frame(&events).expect("a frame");
    assert_eq!(frame.agents.len(), 1);
    let entry = &frame.agents[0];
    // Health is a state: the newest wins. `from` keeps where the window began,
    // so healthy->degraded->failed reports healthy->failed rather than losing
    // where the agent started.
    assert_eq!(entry.to, WireAgentHealth::Failed);
    assert_eq!(entry.from, Some(WireAgentHealth::Healthy));
    assert_eq!(entry.changed_at_ms, Some(1_500));
    // Actions are counts: they add.
    assert_eq!(entry.actions.get("scan"), Some(&2));

    // Neither `hunt_id` nor `details` crosses. `details` is
    // serde_json::to_value over the whole action — adversary-influenced
    // content with no route that serves it.
    let json = serde_json::to_string(&frame).expect("serialised");
    assert!(!json.contains("hunt-1"), "hunt_id must not cross: {json}");
    assert!(!json.contains("rm -rf"), "details must not cross: {json}");
}

#[test]
fn an_agent_that_only_acted_still_gets_a_row() {
    // A tally with no row would be a count nobody can attribute.
    let frame = agent_health_frame(&[RuntimeEvent::AgentAction {
        emitted_at_ms: 1,
        agent_id: "a2".into(),
        role: AgentRole::Pouncer,
        action_kind: "isolate".into(),
        hunt_id: None,
        details: serde_json::Value::Null,
    }])
    .expect("a frame");
    assert_eq!(frame.agents[0].agent_id, "a2");
    assert_eq!(frame.agents[0].actions.get("isolate"), Some(&1));
    // No health observation this window. `Healthy` would be an assertion the
    // bridge cannot make.
    assert_ne!(frame.agents[0].to, WireAgentHealth::Healthy);
    assert_eq!(frame.agents[0].changed_at_ms, None);
}

#[test]
fn an_empty_window_publishes_no_health_frame() {
    assert!(agent_health_frame(&[]).is_none());
}

#[test]
fn every_mode_transition_survives_the_window() {
    // A window collapsed to its last frame would say the mode went to alert
    // without ever saying it reached incident.
    let events = vec![
        RuntimeEvent::ModeTransition {
            emitted_at_ms: 1,
            from: SwarmMode::Normal,
            to: SwarmMode::Incident,
            triggering_threat_class: Some(ThreatClass::Execution),
            reason: "crossed incident_threshold".into(),
        },
        RuntimeEvent::ModeTransition {
            emitted_at_ms: 2,
            from: SwarmMode::Incident,
            to: SwarmMode::Alert,
            triggering_threat_class: Some(ThreatClass::Execution),
            reason: "deescalation cooldown elapsed".into(),
        },
    ];
    let frames = mode_transitions(&events);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].to, WireSwarmMode::Incident);
    assert!(frames[0].triggering_threat_class.is_some());
    // A de-escalation names no class: carrying the escalating one would read
    // as "this class caused the step down".
    assert_eq!(frames[1].to, WireSwarmMode::Alert);
    assert_eq!(frames[1].triggering_threat_class, None);
}

#[test]
fn a_window_with_no_transition_produces_no_frames() {
    assert!(mode_transitions(&[ingest("s", true)]).is_empty());
}

#[test]
fn the_telemetry_key_is_the_frame_kind_and_never_the_issuer() {
    // Keying by issuer makes two agents' health reports evict each other, and
    // 26002 is a list of agents rather than one agent's row.
    assert_eq!(
        telemetry_slot_key(&snapshot(0, SwarmMode::Normal, 1.0)),
        Some("26001")
    );
    assert_eq!(
        telemetry_slot_key(&RuntimeEvent::AgentHealth {
            emitted_at_ms: 0,
            agent_id: "a1".into(),
            role: AgentRole::Whisker,
            from: None,
            to: AgentHealth::Healthy,
        }),
        Some("26002")
    );
    assert_eq!(
        telemetry_slot_key(&RuntimeEvent::AgentAction {
            emitted_at_ms: 0,
            agent_id: "a2".into(),
            role: AgentRole::Pouncer,
            action_kind: "isolate".into(),
            hunt_id: None,
            details: serde_json::Value::Null,
        }),
        Some("26002"),
        "health and actions feed one frame, so they share one slot"
    );
    assert_eq!(
        telemetry_slot_key(&RuntimeEvent::ModeTransition {
            emitted_at_ms: 0,
            from: SwarmMode::Normal,
            to: SwarmMode::Alert,
            triggering_threat_class: None,
            reason: "r".into(),
        }),
        Some("26003")
    );
}

#[test]
fn ingest_has_no_telemetry_slot_because_a_slot_would_lie() {
    // `Ingest` is classified DroppedAtSource and never reaches this spool. A
    // key here would be a slot that always holds ONE ingest event, and a gauge
    // computed from it would report `accepted: 1` for a window that carried
    // three thousand.
    assert_eq!(telemetry_slot_key(&ingest("syslog-collector", true)), None);
}

#[test]
fn the_ingest_window_accumulates_then_resets() {
    let mut window = IngestWindow::default();
    window.record("syslog-collector", true);
    window.record("syslog-collector", true);
    window.record("edr-collector", false);
    let first = window.drain();
    assert_eq!((first.accepted, first.rejected), (2, 1));
    assert_eq!(first.by_source.get("syslog-collector"), Some(&2));

    // Drained means drained: the next window starts empty, or a rate would
    // grow monotonically and read as an accelerating collector.
    let second = window.drain();
    assert_eq!((second.accepted, second.rejected), (0, 0));
    assert!(second.by_source.is_empty());
}

#[test]
fn the_window_publishes_a_zero_frame_rather_than_no_frame() {
    // Zero accepted is a measurement -- the collectors are connected and quiet
    // -- and differs from no frame, which means nothing was said.
    let rate = IngestWindow::default().drain();
    assert_eq!(rate.window_ms, COALESCE_WINDOW_MS);
    assert_eq!((rate.accepted, rate.rejected), (0, 0));
}

#[test]
fn the_window_applies_the_same_host_sentinel_as_the_batch_reducer() {
    let mut window = IngestWindow::default();
    window.record("10.0.0.4", true);
    let rate = window.drain();
    assert_eq!(
        rate.by_source.keys().collect::<Vec<_>>(),
        vec![SUSPECT_SOURCE]
    );
    // One rule, one place: the batch reducer must agree.
    assert_eq!(
        ingest_rate(&[ingest("10.0.0.4", true)]).by_source,
        rate.by_source
    );
}

fn seq_counter() -> impl FnMut(u16) -> u64 {
    let mut seqs: BTreeMap<u16, u64> = BTreeMap::new();
    move |kind| {
        let next = seqs.entry(kind).or_insert(0);
        *next += 1;
        *next
    }
}

#[test]
fn a_quiet_tick_still_publishes_the_gauge_and_nothing_else() {
    let mut seq = seq_counter();
    let frames = tick_frames(
        IngestWindow::default().drain(),
        &[],
        0,
        "issuer",
        1_000,
        &mut seq,
    )
    .expect("frames");
    // The gauge always: zero accepted is a measurement. The other three only
    // when something was said, because absence is not zero on the wall.
    assert_eq!(
        frames.iter().map(|f| f.kind).collect::<Vec<_>>(),
        vec![26000]
    );
}

#[test]
fn concentration_precedes_the_mode_transition_it_explains() {
    let mut seq = seq_counter();
    let frames = tick_frames(
        IngestWindow::default().drain(),
        &[
            RuntimeEvent::ModeTransition {
                emitted_at_ms: 2,
                from: SwarmMode::Normal,
                to: SwarmMode::Incident,
                triggering_threat_class: Some(ThreatClass::Execution),
                reason: "crossed".into(),
            },
            snapshot(1_000, SwarmMode::Incident, 6.0),
        ],
        1,
        "issuer",
        1_000,
        &mut seq,
    )
    .expect("frames");
    // An operator seeing INCIDENT with no number behind it, even for one tick,
    // is the reading this ordering avoids.
    assert_eq!(
        frames.iter().map(|f| f.kind).collect::<Vec<_>>(),
        vec![26000, 26001, 26003]
    );
}

#[test]
fn the_sequence_is_per_kind_so_a_gap_in_one_is_visible() {
    let mut seq = seq_counter();
    let first = tick_frames(IngestWindow::default().drain(), &[], 0, "i", 1, &mut seq).unwrap();
    let second = tick_frames(
        IngestWindow::default().drain(),
        &[snapshot(2_000, SwarmMode::Normal, 1.0)],
        1,
        "i",
        2,
        &mut seq,
    )
    .unwrap();
    assert_eq!(first[0].value["seq"], 1);
    assert_eq!(second[0].value["seq"], 2, "26000 continues its own run");
    let concentration = second.iter().find(|f| f.kind == 26001).expect("26001");
    assert_eq!(
        concentration.value["seq"], 1,
        "26001 starts at 1; a shared counter would show a gap where none exists"
    );
}

#[test]
fn every_frame_carries_its_kind_and_schema_in_the_body() {
    let mut seq = seq_counter();
    let frames = tick_frames(
        IngestWindow::default().drain(),
        &[snapshot(1_000, SwarmMode::Normal, 1.0)],
        1,
        "spine-issuer",
        7,
        &mut seq,
    )
    .unwrap();
    for frame in &frames {
        // Self-describing: a copied frame still says what it is.
        assert_eq!(frame.value["kind"], frame.kind);
        assert_eq!(frame.value["issuer"], "spine-issuer");
        assert_eq!(frame.value["emitted_at_ms"], 7);
        assert!(
            frame.value["schema"]
                .as_str()
                .unwrap()
                .starts_with("swarm.perch.frame."),
            "{:?}",
            frame.value["schema"]
        );
    }
}

#[test]
fn the_coalesced_count_comes_from_the_caller_not_the_slice() {
    // The spool is last-wins, so at publish time the slice holds ONE snapshot.
    // Deriving the count here would report 1 for a window that collapsed
    // thirty, on the field whose whole job is to admit the coalescing.
    let frame =
        concentration_frame(&[snapshot(1_000, SwarmMode::Normal, 1.0)], 30).expect("a frame");
    assert_eq!(frame.coalesced_from, 30);
}

#[test]
fn a_zero_count_still_reports_one_because_a_frame_collapsed_at_least_itself() {
    let frame =
        concentration_frame(&[snapshot(1_000, SwarmMode::Normal, 1.0)], 0).expect("a frame");
    assert_eq!(frame.coalesced_from, 1);
}

/// One governance reading, at `at`, reporting `healthy` of `total` governors.
fn governance(at: i64, total: usize, healthy: usize) -> RuntimeEvent {
    RuntimeEvent::GovernanceStatus {
        emitted_at_ms: at,
        partition_state: swarm_policy::governance::PartitionState::Healthy,
        total_governors: total,
        healthy_governors: healthy,
        quorum_threshold: 1,
        unauthorized_partition_actions: 0,
        active_contingency_leases: 0,
        last_transition_at_ms: None,
        last_reconciliation_report_id: None,
        contingency_lease_ttl_ms: 300_000,
    }
}

#[test]
fn a_governance_reading_keys_to_the_26004_slot() {
    // One slot per frame kind, so readings coalesce newest-wins rather than
    // evicting some other telemetry.
    assert_eq!(telemetry_slot_key(&governance(0, 1, 1)), Some("26004"));
}

#[test]
fn the_governance_frame_keeps_the_newest_reading() {
    // Newest by emitted_at_ms, not by slice position — the spool is last-wins,
    // and a governance reading is a statement about now.
    let frame = governance_status_frame(&[
        governance(1_000, 3, 1),
        governance(3_000, 3, 3),
        governance(2_000, 3, 2),
    ])
    .expect("a frame");
    assert_eq!(frame.healthy_governors, 3, "the newest reading wins");
    // And with the newest first, the same reading still wins.
    let frame = governance_status_frame(&[governance(3_000, 3, 3), governance(1_000, 3, 1)])
        .expect("a frame");
    assert_eq!(frame.healthy_governors, 3);
}

#[test]
fn an_empty_window_publishes_no_governance_frame() {
    // Absence is "the console has not been told", which the strip renders as
    // bridge-down. A synthetic frame would paint a fabricated healthy.
    assert!(governance_status_frame(&[]).is_none());
    assert!(governance_status_frame(&[ingest("s", true)]).is_none());
}

#[test]
fn a_governance_reading_becomes_a_26004_that_matches_the_golden_vector() {
    // The golden is extracted from the schema's own example; the producer must
    // reproduce it field for field. Read it the way `tests/wire_parity.rs`
    // reads the card goldens.
    let golden_raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../swarm-perch-wire/golden/frame-26004-governance-status.json"
    ))
    .expect("the 26004 golden vector");
    let golden: serde_json::Value = serde_json::from_str(&golden_raw).expect("valid JSON");

    // A reading carrying the golden's numbers, published by the golden's issuer
    // on the golden's clock and seq.
    let emitted_at_ms = golden["emitted_at_ms"].as_i64().expect("emitted_at_ms");
    let reading = governance(emitted_at_ms, 1, 1);
    let issuer = golden["issuer"].as_str().expect("issuer");
    let seq = golden["seq"].as_u64().expect("seq");
    let mut seq_for = |_kind: u16| seq;
    let frames = tick_frames(
        IngestWindow::default().drain(),
        std::slice::from_ref(&reading),
        0,
        issuer,
        emitted_at_ms,
        &mut seq_for,
    )
    .expect("frames");
    let frame = frames
        .iter()
        .find(|f| f.kind == 26004)
        .expect("a 26004 frame");

    // The typed producer omits an absent optional where the schema example
    // spells it null, and both decode the same — so compare against the golden
    // with its explicit nulls stripped, exactly as `tests/golden.rs` does.
    let mut expected = golden.clone();
    if let serde_json::Value::Object(map) = &mut expected {
        map.retain(|_, value| !value.is_null());
    }
    assert_eq!(
        frame.value, expected,
        "every field matches the golden vector"
    );
    assert_eq!(
        frame.value["schema"], "swarm.perch.frame.governance_status.v1",
        "the schema string is the one the console reads"
    );

    // And the produced bytes round-trip back into the typed wire frame — the
    // zod/serde parity the desktop mirror asserts on the same golden.
    let round_trip: swarm_perch_wire::Frame =
        serde_json::from_value(frame.value.clone()).expect("round trip");
    assert_eq!(
        round_trip.frame_kind(),
        swarm_perch_wire::FrameKind::GovernanceStatus
    );
}

#[test]
fn the_governance_frame_follows_the_gauge_in_kind_order() {
    let mut seq = seq_counter();
    let frames = tick_frames(
        IngestWindow::default().drain(),
        &[governance(1_000, 1, 1)],
        0,
        "issuer",
        1_000,
        &mut seq,
    )
    .expect("frames");
    assert_eq!(
        frames.iter().map(|f| f.kind).collect::<Vec<_>>(),
        vec![26000, 26004]
    );
}
