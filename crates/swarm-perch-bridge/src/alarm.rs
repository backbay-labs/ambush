//! The alarm drainer: the twelve lanes at startup, then case channels on `CasePromoted`.
//!
//! It runs on the alarm identity's socket and the same 1 Hz cadence as the pacer. A promotion is
//! not a hold; it does not bypass the tick. What makes it a separate task from the pacer is the
//! spool it drains and the identity it signs with, not its urgency.
//!
//! `CasePromoted` is `Stream::Alarm` for one reason: it is the only trigger that creates a case
//! channel on the manual-promotion clause, which ADR 0018 C4 enables FIRST. Coalescing or
//! shedding it would leave a daemon incident record whose `case_id` names a channel that does not
//! exist.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use swarm_core::config::PerchBridgeConfig;
use swarm_runtime::runtime_events::RuntimeEvent;
use tokio::sync::watch;

use crate::channels::{
    self, CasePromotionTrigger, PromotionClause, PublishStep, case_channel_name, step_to_event,
};
use crate::error::BridgeError;
use crate::identity::IdentityTable;
use crate::metrics::BridgeMetrics;
use crate::pacer::{Frame, FramePublisher, PERCH_FRAME_MAX_BYTES};
use crate::spool::{Spool, SpoolSet};
use crate::stream::{Stream, threat_class_slug};

/// The case TTL used when neither the threat class nor `default` is configured: thirty days.
const FALLBACK_CASE_TTL_SECONDS: i32 = 2_592_000;

/// Drains the alarm spool, one record per tick, after ensuring the twelve lanes exist.
///
/// # Errors
///
/// [`BridgeError::SpoolIo`] when the spool or its cursor fails, [`BridgeError::InvalidConfig`]
/// when the identity table has no alarm slot or the daemon minted a `case_id` that is not a UUID,
/// and [`BridgeError::Encode`] when a record does not deserialize.
///
/// Eight parameters, deliberately: every one is a distinct piece of composition-root state with
/// its own lifetime, and folding them into a context struct would create a type that exists only
/// to satisfy a lint and would have to be threaded through the tests as well.
#[allow(clippy::too_many_arguments)]
pub async fn run<P: FramePublisher>(
    spools: Arc<Mutex<SpoolSet>>,
    identities: Arc<IdentityTable>,
    config: PerchBridgeConfig,
    operators: Vec<String>,
    mut routing: channels::CaseRouting,
    mut publisher: P,
    metrics: BridgeMetrics,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), BridgeError> {
    let keys = identities
        .get(identities.alarm())
        .ok_or(BridgeError::InvalidConfig {
            reason: "the perch identity table has no alarm slot".to_string(),
        })?
        .keys
        .clone();
    let alarm_issuer = identities.alarm();

    // Startup: the twelve lanes, idempotently. A duplicate is success (decision D-FC-5).
    for step in channels::lane_channel_steps(&config, &operators) {
        publish_step(&mut publisher, &step, &keys, alarm_issuer, &metrics).await?;
    }
    tracing::info!(
        module = module_path!(),
        lanes = config.lane_channels.len(),
        "lane channels ensured"
    );

    let mut interval = tokio::time::interval(Duration::from_millis(config.publish_tick_ms.max(1)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;

            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    tracing::info!(module = module_path!(), "perch bridge alarm drainer stopping");
                    return Ok(());
                }
            }

            _ = interval.tick() => {
                let head = {
                    let mut guard = spools.lock().unwrap_or_else(PoisonError::into_inner);
                    guard.alarm().peek(PERCH_FRAME_MAX_BYTES)?.into_iter().next()
                };
                let Some(record) = head else { continue };
                let event: RuntimeEvent = serde_json::from_slice(&record.payload)
                    .map_err(|error| BridgeError::Encode(error.to_string()))?;

                match event {
                    RuntimeEvent::CasePromoted {
                        hunt_id,
                        case_id,
                        clause,
                        threat_class,
                        ..
                    } => {
                        let case = uuid::Uuid::parse_str(&case_id).map_err(|_| {
                            BridgeError::InvalidConfig {
                                reason: format!("daemon minted a non-uuid case_id {case_id}"),
                            }
                        })?;
                        let ttl = config
                            .case_ttl_seconds
                            .get(&threat_class_slug(&threat_class))
                            .or_else(|| config.case_ttl_seconds.get("default"))
                            .copied()
                            .unwrap_or(FALLBACK_CASE_TTL_SECONDS);
                        let clause = PromotionClause::from(clause);
                        let trigger = CasePromotionTrigger::Promoted {
                            hunt_id: hunt_id.clone(),
                            case_id: case,
                            clause,
                        };
                        match routing.ensure_case_channel(&trigger, &operators, ttl) {
                            Ok((_, steps)) => {
                                let mut all_ok = true;
                                for step in &steps {
                                    if let Err(error) = publish_step(
                                        &mut publisher, step, &keys, alarm_issuer, &metrics,
                                    )
                                    .await
                                    {
                                        all_ok = false;
                                        tracing::warn!(
                                            module = module_path!(),
                                            reason = %error,
                                            "case channel step failed; retrying next tick"
                                        );
                                        break;
                                    }
                                }
                                if all_ok {
                                    // The relay accepted the create, so stop replanning it. Until
                                    // this lands the hunt is routed but unconfirmed, which is what
                                    // makes a refused create retry instead of committing silently.
                                    routing.mark_case_channel_created(case)?;
                                    metrics.case_channel_created(clause.as_str());
                                    metrics.source_events_published(Stream::Alarm);
                                    tracing::info!(
                                        module = module_path!(),
                                        case_id = %case,
                                        name = %case_channel_name(case),
                                        %hunt_id,
                                        clause = clause.as_str(),
                                        "case channel created"
                                    );
                                    commit(&spools, record.issuer, record.seq)?;
                                }
                            }
                            // Two parties minted case ids for one investigation. The record is
                            // committed rather than retried forever: the daemon's incident
                            // already names the id it sent, and only one of the two can be the
                            // case. Failure mode F20 — visible in a counter, not blank.
                            Err(BridgeError::CaseChannelConflict {
                                hunt_id,
                                existing,
                                incoming,
                            }) => {
                                metrics.case_channel_conflict();
                                tracing::error!(
                                    module = module_path!(),
                                    %hunt_id,
                                    %existing,
                                    %incoming,
                                    "a second case id was minted for one hunt; refusing to create \
                                     a second channel"
                                );
                                commit(&spools, record.issuer, record.seq)?;
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    // ModeTransition / TamperAlert: alarm-class facts this milestone does not
                    // publish. Their meaning stays in the daemon's own stores, so they are
                    // committed and counted apart from a drop.
                    _ => {
                        metrics.skipped_unpublished(Stream::Alarm);
                        commit(&spools, record.issuer, record.seq)?;
                    }
                }
            }
        }
    }
}

/// Signs one step, publishes it, and treats an already-existing channel as success.
async fn publish_step<P: FramePublisher>(
    publisher: &mut P,
    step: &PublishStep,
    keys: &nostr::Keys,
    identity: crate::spool::IssuerIdx,
    metrics: &BridgeMetrics,
) -> Result<(), BridgeError> {
    let now_secs = chrono::Utc::now().timestamp().max(0) as u64;
    let signed = step_to_event(step, keys, now_secs)?;
    let channel = step.channel();
    let frame = Frame {
        identity,
        channel,
        event_id: signed.id.to_hex(),
        signed,
        // A provisioning step discharges no spool record on its own; the drainer commits the
        // record once every step of its sequence has been accepted.
        covers: (identity, 0),
        created_at_secs: now_secs as i64,
    };
    let outcome = publisher.publish(&frame).await?;
    if outcome.is_success() {
        return Ok(());
    }
    metrics.admission_rejection(outcome.reason());
    Err(BridgeError::RelayRejected {
        message: outcome.reason().to_string(),
    })
}

fn commit(
    spools: &Arc<Mutex<SpoolSet>>,
    issuer: crate::spool::IssuerIdx,
    seq: crate::spool::Seq,
) -> Result<(), BridgeError> {
    spools
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .alarm()
        .commit(issuer, seq)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_core::config::SecretString;
    use swarm_core::types::AgentId;

    use crate::publish::OkOutcome;
    use crate::spool::Record;

    struct Recording {
        frames: Vec<Frame>,
        answer: OkOutcome,
    }

    impl FramePublisher for Recording {
        async fn publish(&mut self, frame: &Frame) -> Result<OkOutcome, BridgeError> {
            self.frames.push(frame.clone());
            Ok(self.answer.clone())
        }
    }

    fn config() -> PerchBridgeConfig {
        let mut config = PerchBridgeConfig::default();
        for (index, slug) in swarm_core::config::STANDARD_THREAT_CLASS_SLUGS
            .iter()
            .enumerate()
        {
            config.lane_channels.insert(
                (*slug).to_string(),
                format!("00000000-0000-4000-8000-{:012x}", index + 1),
            );
        }
        config.case_ttl_seconds.insert("default".into(), 2_592_000);
        config.publish_tick_ms = 5;
        config
    }

    fn identities() -> Arc<IdentityTable> {
        Arc::new(
            IdentityTable::build(
                &SecretString::new("11".repeat(32)),
                "c",
                &[],
                &AgentId("swarm:ed25519:".to_string() + &"ab".repeat(32)),
                None,
            )
            .unwrap(),
        )
    }

    fn case_promoted(hunt_id: &str, case_id: &str) -> RuntimeEvent {
        serde_json::from_value(serde_json::json!({
            "event_type": "case_promoted", "emitted_at_ms": 1, "hunt_id": hunt_id,
            "case_id": case_id, "clause": "manual",
            "incident_id": format!("incident:perch-case:{case_id}"),
            "finding_id": "f-1", "threat_class": "execution", "severity": "HIGH",
            "summary": "promoted"
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn startup_ensures_the_lanes_and_a_promotion_creates_its_case_channel() {
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let identities = identities();
        let alarm_idx = identities.alarm();
        let case = "9499a6e2-8872-453b-80d9-dafc6fc7fc69";
        spools
            .lock()
            .unwrap()
            .append(
                Stream::Alarm,
                Record::from_event(&case_promoted("hunt-evt-1", case), alarm_idx).unwrap(),
            )
            .unwrap();

        let (metrics, _registry) = BridgeMetrics::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let routing = channels::CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        let handle = tokio::spawn(run(
            Arc::clone(&spools),
            Arc::clone(&identities),
            config(),
            vec!["a".repeat(64)],
            routing,
            Recording {
                frames: vec![],
                answer: OkOutcome::Accepted,
            },
            metrics,
            shutdown_rx,
        ));
        tokio::time::sleep(Duration::from_millis(120)).await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();

        assert!(
            spools
                .lock()
                .unwrap()
                .alarm()
                .peek(usize::MAX)
                .unwrap()
                .is_empty(),
            "the promotion was committed once its channel existed"
        );
        let routing = channels::CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        assert_eq!(
            routing.case_for_hunt("hunt-evt-1"),
            Some(uuid::Uuid::parse_str(case).unwrap())
        );
    }

    #[tokio::test]
    async fn an_alarm_record_with_no_producer_is_committed_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let identities = identities();
        let alarm_idx = identities.alarm();
        let mode: RuntimeEvent = serde_json::from_value(serde_json::json!({
            "event_type": "mode_transition", "emitted_at_ms": 1, "from": "normal",
            "to": "incident", "triggering_threat_class": null, "reason": "test"
        }))
        .unwrap();
        spools
            .lock()
            .unwrap()
            .append(Stream::Alarm, Record::from_event(&mode, alarm_idx).unwrap())
            .unwrap();

        let (metrics, _registry) = BridgeMetrics::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let routing = channels::CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        let handle = tokio::spawn(run(
            Arc::clone(&spools),
            identities,
            config(),
            vec![],
            routing,
            Recording {
                frames: vec![],
                answer: OkOutcome::Accepted,
            },
            metrics,
            shutdown_rx,
        ));
        tokio::time::sleep(Duration::from_millis(120)).await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(
            spools
                .lock()
                .unwrap()
                .alarm()
                .peek(usize::MAX)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_lane_the_relay_already_has_is_success_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let (metrics, _registry) = BridgeMetrics::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let routing = channels::CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        let handle = tokio::spawn(run(
            spools,
            identities(),
            config(),
            vec![],
            routing,
            Recording {
                frames: vec![],
                answer: OkOutcome::ChannelAlreadyExists,
            },
            metrics,
            shutdown_rx,
        ));
        tokio::time::sleep(Duration::from_millis(60)).await;
        shutdown_tx.send(true).unwrap();
        handle
            .await
            .unwrap()
            .expect("a duplicate channel must not fail startup");
    }
}
