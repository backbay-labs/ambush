use super::*;
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
    let frame = concentration_frame(&[
        snapshot(1_000, SwarmMode::Normal, 1.0),
        snapshot(3_000, SwarmMode::Alert, 5.0),
        snapshot(2_000, SwarmMode::Normal, 2.0),
    ])
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
    let frame = concentration_frame(&[snapshot(1_773_738_881_000, SwarmMode::Normal, 1.0)])
        .expect("a frame");
    assert_eq!(frame.observed_at_seconds, 1_773_738_881);
}

#[test]
fn an_empty_window_publishes_no_concentration_frame() {
    // Not a frame of zeroes: an empty window is "the bridge saw nothing", and
    // a zero frame would tell the wall the substrate went quiet.
    assert!(concentration_frame(&[]).is_none());
    assert!(concentration_frame(&[ingest("s", true)]).is_none());
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
