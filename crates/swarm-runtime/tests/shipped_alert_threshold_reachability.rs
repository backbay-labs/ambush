//! What the SHIPPED `rulesets/default.yaml` actually escalates on.
//!
//! `rulesets/default.yaml` pairs `alert_threshold: 2.0` with
//! `min_sources_for_escalation: 2`, and pheromone strength decays as
//! `confidence * 0.5^(elapsed_secs / half_life_secs)` with a 3600s half life.
//! Two unit-confidence deposits therefore sum to exactly 2.0 at the instant
//! they are made and to less than 2.0 one second later -- a threshold reachable
//! only on an exact equality.
//!
//! This file measures what that means for a real operator, end to end, against
//! the shipped file rather than a hand-written config literal. Every number in
//! `.planning/ALERT-THRESHOLD-KNIFE-EDGE.md` is asserted here, so the write-up
//! cannot drift away from the code.
//!
//! It deliberately asserts NOTHING about what the threshold *should* be.
//! `rulesets/default.yaml` is covered by the ed25519 signature in
//! `rulesets/attestation.json` and cannot be edited in this repo; changing it is
//! a decision for whoever holds that key. These are characterization tests: if
//! the shipped numbers change, they fail and say so.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use std::sync::Arc;
use swarm_core::agent::SwarmMode;
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig, SwarmConfig};
use swarm_core::pheromone::{PheromoneDeposit, ThreatClass};
use swarm_core::telemetry::{ProcessStartEvent, TelemetryEvent, TelemetryPayload};
use swarm_core::types::{AgentId, EscalationEvent, Severity};
use swarm_pheromone::{InMemoryPheromoneSubstrate, PheromoneSubstrate};
use swarm_runtime::config::load_config;
use swarm_runtime::detection::detect_and_deposit;
use swarm_runtime::detector_factory::build_detector_from_strategy;
use swarm_runtime::escalation::ConcentrationMonitor;

/// Detection time for every deposit and every evaluation below.
const T: i64 = 1_700_000_000;

fn shipped_config() -> SwarmConfig {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/default.yaml");
    load_config(&path).expect("the shipped ruleset must load")
}

/// The shipped pheromone block, but with the in-memory backend so the test does
/// not need external storage. Every threshold below comes from the file.
fn shipped_pheromone_config(config: &SwarmConfig) -> PheromoneConfig {
    let mut pheromone = config.pheromone.clone();
    pheromone.backend = PheromoneBackendConfig::InMemory;
    pheromone
}

/// A process-start event that trips the HIGH-confidence branch of
/// `suspicious_process_tree`: a suspicious parent, a suspicious child, and an
/// encoded command line.
fn maximally_suspicious_event(event_id: &str) -> TelemetryEvent {
    TelemetryEvent {
        source: "synthetic-process".to_string(),
        event_id: event_id.to_string(),
        timestamp: T,
        host_id: Some("host-a".to_string()),
        payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
            process_name: "powershell".to_string(),
            parent_process: "winword".to_string(),
            command_line: "powershell.exe -enc SQBFAFgA".to_string(),
            user: Some("victim".to_string()),
            executable_path: Some("C:\\Windows\\System32\\powershell.exe".to_string()),
            signer: None,
            signature_valid: None,
        }),
    }
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn unit_confidence_deposit(key: &SigningKey, timestamp: i64) -> PheromoneDeposit {
    let agent_id = AgentId::from_verifying_key(&key.verifying_key());
    let mut deposit = PheromoneDeposit {
        schema_version: PheromoneDeposit::current_schema_version(),
        indicator: serde_json::json!({"signal": "execution"}),
        threat_class: ThreatClass::Execution,
        severity: Severity::Critical,
        confidence: 1.0,
        timestamp,
        decay_half_life: 3600.0,
        agent_id: agent_id.clone(),
        agent_identity: agent_id.0,
        agent_role: None,
        signature: Vec::new(),
        agent_key: Vec::new(),
    };
    // Signed exactly the way `swarm_runtime::detection::sign_deposit` signs, so
    // the substrate's own verification accepts it.
    let payload = swarm_pheromone::DepositSigningPayload {
        schema_version: deposit.schema_version,
        indicator: &deposit.indicator,
        threat_class: &deposit.threat_class,
        severity: &deposit.severity,
        confidence: deposit.confidence,
        timestamp: deposit.timestamp,
        decay_half_life: deposit.decay_half_life,
        agent_id: &deposit.agent_id,
        agent_identity: &deposit.agent_identity,
        agent_role: deposit.agent_role,
    };
    let payload_bytes = serde_json::to_vec(&payload).expect("signing payload serializes");
    let signature = ed25519_dalek::Signer::sign(key, &payload_bytes);
    deposit.signature = signature.to_bytes().to_vec();
    deposit.agent_key = key.verifying_key().to_bytes().to_vec();
    deposit
}

#[test]
fn shipped_ruleset_carries_the_thresholds_this_file_reasons_about() {
    let config = shipped_config();
    assert_eq!(config.pheromone.alert_threshold, 2.0);
    assert_eq!(config.pheromone.incident_threshold, 5.0);
    assert_eq!(config.pheromone.min_sources_for_escalation, 2);
    assert_eq!(config.pheromone.default_half_life_secs, 3600.0);
    assert_eq!(config.pheromone.deescalation_cooldown_secs, 300);
    assert_eq!(config.detection.high_confidence_threshold, 0.90);
    assert_eq!(config.detection.strategy, "suspicious_process_tree");
    assert!(
        config.detection.strategies.is_empty(),
        "the shipped file selects a single strategy, so one agent contributes one source"
    );
    assert_eq!(
        config.detection.active_strategies(),
        vec!["suspicious_process_tree".to_string()]
    );
}

/// FINDING 1: the shipped alert threshold is not a knife edge for the shipped
/// detector -- it is unreachable. The strongest finding
/// `suspicious_process_tree` can emit carries `high_confidence_threshold`
/// (0.90), so two saturated sources sum to 1.80, and 1.80 never reaches 2.0 at
/// any elapsed time. Decay is not what keeps this below the line; the ceiling
/// is.
#[tokio::test]
async fn two_saturated_shipped_detections_never_reach_the_alert_threshold() {
    let config = shipped_config();
    let pheromone = shipped_pheromone_config(&config);
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new_for_replay(
        pheromone.clone(),
    ));
    let detector = build_detector_from_strategy("suspicious_process_tree", &config.detection)
        .expect("the shipped strategy builds");

    // Two distinct agents, each observing the same maximally suspicious event.
    let mut measured_confidence = 0.0_f64;
    for (index, seed) in [11u8, 22u8].into_iter().enumerate() {
        let key = signing_key(seed);
        let agent_id = AgentId::from_verifying_key(&key.verifying_key());
        let outcome = detect_and_deposit(
            &detector,
            substrate.as_ref(),
            &maximally_suspicious_event(&format!("evt-{index}")),
            &agent_id,
            &pheromone,
            &key,
        )
        .await
        .expect("detection pipeline runs");
        assert_eq!(outcome.findings.len(), 1, "the event must detect");
        measured_confidence = measured_confidence.max(outcome.findings[0].confidence);
    }

    // MEASURED: the ceiling on a single finding's confidence.
    assert_eq!(
        measured_confidence, config.detection.high_confidence_threshold,
        "a suspicious_process_tree finding is capped at high_confidence_threshold"
    );
    assert_eq!(measured_confidence, 0.90);

    let concentration = substrate
        .query_concentration(&ThreatClass::Execution, T)
        .await
        .unwrap();
    println!(
        "MEASURED two-source shipped concentration at t=0: total_strength={:.6} distinct_sources={}",
        concentration.total_strength, concentration.distinct_sources
    );
    assert_eq!(concentration.distinct_sources, 2);
    assert!(
        (concentration.total_strength - 1.80).abs() < 1e-9,
        "two 0.90 deposits sum to 1.80, got {}",
        concentration.total_strength
    );

    // Zero elapsed time, both sources present, and still no escalation.
    let mut monitor = ConcentrationMonitor::new(pheromone, Arc::clone(&substrate));
    let outcome = monitor.evaluate_all(T).await.unwrap();
    assert!(
        outcome.events.is_empty(),
        "1.80 is below the shipped alert_threshold of 2.0 even with zero decay"
    );
    assert_eq!(outcome.current_mode, SwarmMode::Normal);
}

/// FINDING 2: the knife edge is real for the hypothetical unit-confidence pair.
/// Two 1.0-confidence deposits reach exactly 2.0 in the second they are made and
/// 1.99961... one second later. `exceeds_threshold` uses `>=`, so the boundary
/// second escalates and the next one does not.
#[tokio::test]
async fn unit_confidence_pair_clears_the_threshold_for_one_second_only() {
    let config = shipped_config();
    let pheromone = shipped_pheromone_config(&config);
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new_for_replay(
        pheromone.clone(),
    ));
    for seed in [11u8, 22u8] {
        substrate
            .deposit(unit_confidence_deposit(&signing_key(seed), T))
            .await
            .unwrap();
    }

    let at_zero = substrate
        .query_concentration(&ThreatClass::Execution, T)
        .await
        .unwrap();
    let at_one = substrate
        .query_concentration(&ThreatClass::Execution, T + 1)
        .await
        .unwrap();
    let at_two = substrate
        .query_concentration(&ThreatClass::Execution, T + 2)
        .await
        .unwrap();
    println!(
        "MEASURED unit-confidence pair: t+0={:.9} t+1={:.9} t+2={:.9}",
        at_zero.total_strength, at_one.total_strength, at_two.total_strength
    );
    assert_eq!(at_zero.total_strength, 2.0);
    assert!(
        (at_one.total_strength - 1.999_614_9).abs() < 1e-6,
        "one second of 3600s-half-life decay, got {}",
        at_one.total_strength
    );
    assert!(at_one.total_strength < config.pheromone.alert_threshold);

    // A monitor that first looks in the boundary second sees the Alert.
    let mut on_time = ConcentrationMonitor::new(pheromone.clone(), Arc::clone(&substrate));
    let outcome = on_time.evaluate_all(T).await.unwrap();
    assert_eq!(outcome.events.len(), 1);
    assert!(matches!(outcome.events[0], EscalationEvent::Alert { .. }));
    assert_eq!(outcome.current_mode, SwarmMode::Alert);

    // A monitor that first looks one second later sees nothing at all. This is
    // the operational consequence: the escalation is not merely brief, it is
    // MISSABLE.
    let mut one_second_late = ConcentrationMonitor::new(pheromone, Arc::clone(&substrate));
    let missed = one_second_late.evaluate_all(T + 1).await.unwrap();
    assert!(
        missed.events.is_empty(),
        "a monitor whose first tick lands one second late never sees the alert"
    );
    assert_eq!(missed.current_mode, SwarmMode::Normal);
}

/// FINDING 3: what the operator SEES does not flip after one second. `SwarmMode`
/// is a latch: once `ConcentrationMonitor` escalates, it only returns to Normal
/// after `deescalation_cooldown_secs` (300) of continuously observing nothing.
/// So a single boundary-second Alert holds the runtime in Alert for five
/// minutes -- the concentration flips after one second, the mode does not.
#[tokio::test]
async fn the_mode_latch_holds_alert_for_the_full_deescalation_cooldown() {
    let config = shipped_config();
    let pheromone = shipped_pheromone_config(&config);
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new_for_replay(
        pheromone.clone(),
    ));
    for seed in [11u8, 22u8] {
        substrate
            .deposit(unit_confidence_deposit(&signing_key(seed), T))
            .await
            .unwrap();
    }

    let mut monitor = ConcentrationMonitor::new(pheromone, Arc::clone(&substrate));
    assert_eq!(
        monitor.evaluate_all(T).await.unwrap().current_mode,
        SwarmMode::Alert
    );

    // One second later the concentration is below the threshold, so no further
    // Alert event is emitted -- and the mode is unchanged.
    let after_one = monitor.evaluate_all(T + 1).await.unwrap();
    assert!(after_one.events.is_empty());
    assert!(!after_one.mode_changed);
    assert_eq!(after_one.current_mode, SwarmMode::Alert);

    // Still Alert one second before the cooldown elapses.
    let before_cooldown = monitor
        .evaluate_all(T + config.pheromone.deescalation_cooldown_secs)
        .await
        .unwrap();
    assert_eq!(before_cooldown.current_mode, SwarmMode::Alert);

    // The cooldown is measured from the first quiet observation (T + 1), so it
    // elapses at T + 1 + 300.
    let after_cooldown = monitor
        .evaluate_all(T + 1 + config.pheromone.deescalation_cooldown_secs)
        .await
        .unwrap();
    assert!(after_cooldown.mode_changed);
    assert_eq!(after_cooldown.current_mode, SwarmMode::Normal);
}

/// FINDING 4: re-deposit does not rescue the shipped configuration. A second
/// event from the same two agents adds two more deposits, but they are two more
/// deposits from the SAME two strategy-scoped sources -- strength accumulates,
/// `distinct_sources` does not. Four 0.90 deposits reach 3.6 and DO cross 2.0,
/// so in a real deployment the escalation arrives on the second event rather
/// than the first.
#[tokio::test]
async fn a_second_event_from_the_same_two_agents_crosses_the_threshold() {
    let config = shipped_config();
    let pheromone = shipped_pheromone_config(&config);
    let substrate = Arc::new(InMemoryPheromoneSubstrate::new_for_replay(
        pheromone.clone(),
    ));
    let detector = build_detector_from_strategy("suspicious_process_tree", &config.detection)
        .expect("the shipped strategy builds");

    for event_index in 0..2 {
        for seed in [11u8, 22u8] {
            let key = signing_key(seed);
            let agent_id = AgentId::from_verifying_key(&key.verifying_key());
            detect_and_deposit(
                &detector,
                substrate.as_ref(),
                &maximally_suspicious_event(&format!("evt-{seed}-{event_index}")),
                &agent_id,
                &pheromone,
                &key,
            )
            .await
            .expect("detection pipeline runs");
        }
    }

    let concentration = substrate
        .query_concentration(&ThreatClass::Execution, T)
        .await
        .unwrap();
    println!(
        "MEASURED four shipped deposits from two agents: total_strength={:.6} distinct_sources={}",
        concentration.total_strength, concentration.distinct_sources
    );
    assert_eq!(concentration.distinct_sources, 2);
    assert!((concentration.total_strength - 3.60).abs() < 1e-9);

    let mut monitor = ConcentrationMonitor::new(pheromone, Arc::clone(&substrate));
    let outcome = monitor.evaluate_all(T).await.unwrap();
    assert_eq!(outcome.events.len(), 1);
    assert!(matches!(outcome.events[0], EscalationEvent::Alert { .. }));
    assert_eq!(outcome.current_mode, SwarmMode::Alert);

    // And 3.6 has real margin. Walk the decay curve to find where it actually
    // crosses 2.0 rather than asserting a number nobody derived: this is the
    // duration an operator's Alert condition is genuinely held by strength, and
    // it is measured in tens of minutes, not in one second.
    let mut crossing_secs = None;
    for elapsed in 0..7_200 {
        let strength = substrate
            .query_concentration(&ThreatClass::Execution, T + elapsed)
            .await
            .unwrap()
            .total_strength;
        if strength < config.pheromone.alert_threshold {
            crossing_secs = Some(elapsed);
            break;
        }
    }
    let crossing_secs = crossing_secs.expect("3.6 must fall below 2.0 within two hours");
    println!("MEASURED seconds the four-deposit concentration stays >= 2.0: {crossing_secs}");
    assert!(
        crossing_secs > 3_000,
        "the shipped escalation must hold for tens of minutes, held {crossing_secs}s"
    );
}

/// FINDING 5: whether a one-second-wide escalation is observed at all is
/// decided by the monitor's cadence, and the shipped cadence observes it from
/// all but the last tenth of a second.
///
/// `swarm_detect` runs `ConcentrationMonitor::run_until_shutdown` with
/// `CONCENTRATION_MONITOR_INTERVAL_MS = 100`, and every evaluation reads
/// `unix_timestamp_secs()` -- whole seconds. Deposits carry second-granularity
/// timestamps too. So the boundary "instant" is really a whole second, and a
/// 100ms loop takes ten ticks inside it.
///
/// A detection does NOT land on a tick boundary, so this sweeps the deposit
/// across the second in 10ms steps and MEASURES from how many arrival offsets
/// the escalation is still seen. The miss window is the gap between the last
/// tick of the deposit's own second and the end of that second.
#[tokio::test]
async fn the_hundred_millisecond_cadence_misses_only_the_last_tenth_of_the_boundary_second() {
    let config = shipped_config();
    let pheromone = shipped_pheromone_config(&config);

    // The shipped daemon's loop: a tick every 100ms at absolute offsets
    // 0, 100, ... 900ms of each second, each evaluating at whole-second
    // granularity.
    const TICK_MS: i64 = 100;
    const STEP_MS: i64 = 10;
    const OFFSETS: i64 = 1_000 / STEP_MS;

    let mut seen = 0i64;
    let mut missed_offsets = Vec::new();
    for step in 0..OFFSETS {
        let deposit_offset_ms = step * STEP_MS;

        // A fresh substrate and monitor per arrival offset: this measures first
        // sighting, not a latch left over from the previous iteration.
        let substrate = Arc::new(InMemoryPheromoneSubstrate::new_for_replay(
            pheromone.clone(),
        ));
        for seed in [11u8, 22u8] {
            substrate
                .deposit(unit_confidence_deposit(&signing_key(seed), T))
                .await
                .unwrap();
        }
        let mut monitor = ConcentrationMonitor::new(pheromone.clone(), Arc::clone(&substrate));

        // Every tick strictly after the deposit arrives, across two seconds.
        let mut saw_alert = false;
        for tick in 0..(2 * (1_000 / TICK_MS)) {
            let tick_offset_ms = tick * TICK_MS;
            if tick_offset_ms < deposit_offset_ms {
                continue;
            }
            let now_secs = T + tick_offset_ms.div_euclid(1_000);
            let outcome = monitor.evaluate_all(now_secs).await.unwrap();
            if outcome
                .events
                .iter()
                .any(|event| matches!(event, EscalationEvent::Alert { .. }))
            {
                saw_alert = true;
            }
        }
        if saw_alert {
            seen += 1;
        } else {
            missed_offsets.push(deposit_offset_ms);
        }
    }

    println!(
        "MEASURED arrival offsets (of {OFFSETS}, 10ms apart) that still observe the boundary-second Alert: {seen}; missed at {missed_offsets:?}"
    );

    // A deposit arriving after the second's last tick (900ms) has no further
    // tick inside its own second, so its next evaluation reads one second of
    // decay and 1.9996 -- below the line.
    assert_eq!(
        missed_offsets,
        vec![910, 920, 930, 940, 950, 960, 970, 980, 990],
        "only arrivals past the last 100ms tick of the second are missed"
    );
    assert_eq!(
        seen, 91,
        "91 of 100 arrival offsets still see the escalation"
    );
}
