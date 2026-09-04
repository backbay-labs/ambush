//! The alarm drainer: the twelve lanes at startup, then case channels on `CasePromoted` and the
//! whole hold sequence on `ResponseHeld`.
//!
//! It runs on the alarm identity's socket and the same 1 Hz cadence as the pacer. A promotion is
//! not a hold; it does not bypass the tick. What makes it a separate task from the pacer is the
//! spool it drains and the identity it signs with, not its urgency.
//!
//! `CasePromoted` is `Stream::Alarm` for one reason: it is the only trigger that creates a case
//! channel on the manual-promotion clause, which ADR 0018 C4 enables FIRST. Coalescing or
//! shedding it would leave a daemon incident record whose `case_id` names a channel that does not
//! exist.
//!
//! `ResponseHeld` is `Stream::Alarm` for a different reason: it is the event an operator is
//! waiting on, and the `26006` frame it drives must never be coalesced or shed (R-1).
//!
//! # One record, a whole sequence, committed only when every step lands
//!
//! A held action costs up to five frames. They are ONE spool record, and the cursor advances
//! only after the last of them is accepted, so a crash mid-sequence replays it. The replay is
//! safe because [`crate::holds::HoldPublisher::plan`] is re-derived from durable state each
//! tick: the store's `notice_event_id` and the routing sidecar's card ledger, both written by
//! this drainer's own callbacks. Every step already accepted is skipped.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use swarm_core::config::PerchBridgeConfig;
use swarm_runtime::runtime_events::RuntimeEvent;
use tokio::sync::watch;

use crate::channels::{
    self, CasePromotionTrigger, PromotionClause, PublishStep, case_channel_name, step_to_event,
};
use crate::error::BridgeError;
use crate::holds::{HoldPlan, HoldPublisher};
use crate::identity::IdentityTable;
use crate::metrics::BridgeMetrics;
use crate::pacer::{Frame, FramePublisher, PERCH_FRAME_MAX_BYTES};
use crate::publish::AlarmAdmission;
use crate::spool::{Spool, SpoolSet};
use crate::stream::{Stream, threat_class_slug};

/// The case TTL used when neither the threat class nor `default` is configured: thirty days.
pub const FALLBACK_CASE_TTL_SECONDS: i32 = 2_592_000;

/// Everything the drainer needs, as one value.
///
/// A struct rather than nine positional parameters: every field is composition-root state with
/// its own lifetime, and at nine arguments a caller that swaps two `Vec<String>`-shaped
/// arguments compiles.
pub struct AlarmDrainer<P: FramePublisher> {
    /// The spool set; only the alarm spool is drained here.
    pub spools: Arc<Mutex<SpoolSet>>,
    /// The identity table, for the alarm slot's issuer index.
    pub identities: Arc<IdentityTable>,
    /// The `perch` config block.
    pub config: PerchBridgeConfig,
    /// The hold publisher, which also owns the routing sidecar and the Approve set.
    pub holds: HoldPublisher,
    /// Where frames go.
    pub publisher: P,
    /// The bridge's metrics.
    pub metrics: BridgeMetrics,
    /// The process-wide shutdown watch.
    pub shutdown: watch::Receiver<bool>,
}

/// Drains the alarm spool, one record per tick, after ensuring the twelve lanes exist.
///
/// # Errors
///
/// [`BridgeError::SpoolIo`] when the spool or its cursor fails, [`BridgeError::InvalidConfig`]
/// when the identity table has no alarm slot or the daemon minted a `case_id` that is not a UUID,
/// and [`BridgeError::Encode`] when a record does not deserialize.
///
pub async fn run<P: FramePublisher>(drainer: AlarmDrainer<P>) -> Result<(), BridgeError> {
    let AlarmDrainer {
        spools,
        identities,
        config,
        mut holds,
        mut publisher,
        metrics,
        mut shutdown,
    } = drainer;
    let keys = identities
        .get(identities.alarm())
        .ok_or(BridgeError::InvalidConfig {
            reason: "the perch identity table has no alarm slot".to_string(),
        })?
        .keys
        .clone();
    let alarm_issuer = identities.alarm();
    let operators = holds.approve_pubkeys().to_vec();

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
                        match holds
                            .routing_mut()
                            .ensure_case_channel(&trigger, &operators, ttl)
                        {
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
                    // A held destructive action: the whole sequence, in order, on one record.
                    RuntimeEvent::ResponseHeld { .. } => {
                        let now_ms = chrono::Utc::now().timestamp_millis();
                        match holds.plan(&event)? {
                            HoldPlan::Undeliverable { hold_id, reason } => {
                                // Refusing is the outcome, not an error to retry forever: no
                                // number of ticks adds an operator pubkey to the config or a
                                // record to a store that lost it. The counter carries the
                                // reason and the record is committed.
                                tracing::error!(
                                    module = module_path!(),
                                    %hold_id,
                                    reason,
                                    "a held action cannot be delivered; it is counted, not \
                                     retried"
                                );
                                commit(&spools, record.issuer, record.seq)?;
                            }
                            HoldPlan::Steps(steps) if steps.is_empty() => {
                                // Already published, or a state the daemon does not ask the
                                // bridge to republish. Neither a drop nor a publish.
                                metrics.skipped_unpublished(Stream::Alarm);
                                commit(&spools, record.issuer, record.seq)?;
                            }
                            HoldPlan::Steps(steps) => {
                                if publish_hold_sequence(
                                    &mut holds,
                                    &mut publisher,
                                    &steps,
                                    &keys,
                                    alarm_issuer,
                                    record.seq,
                                    now_ms,
                                    &metrics,
                                )
                                .await?
                                {
                                    metrics.source_events_published(Stream::Alarm);
                                    commit(&spools, record.issuer, record.seq)?;
                                }
                                // A partial sequence leaves the record at the spool head. The
                                // next tick replans from durable state and resumes where the
                                // relay stopped taking events.
                            }
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

/// Publishes one hold sequence in order, acknowledging each accepted step before the next.
///
/// Returns `true` when every step landed, which is the only condition under which the drainer
/// commits the spool record.
///
/// The order is load-bearing twice over. The `9007` must precede the `9000`s because
/// `create_channel_with_id` bootstraps only its creator as a member; the card must precede the
/// notice because the notice's `card` tag is the id the card step returned; and the alarm is
/// last because a frame naming a hold whose durable record is not yet on the relay sends an
/// operator to a case that has nothing in it.
///
/// # Errors
///
/// Propagates a spool or ledger failure. A relay refusal is NOT an error: it returns `false`,
/// the record stays at the head, and the next tick replans.
#[allow(clippy::too_many_arguments)]
async fn publish_hold_sequence<P: FramePublisher>(
    holds: &mut HoldPublisher,
    publisher: &mut P,
    steps: &[PublishStep],
    keys: &nostr::Keys,
    identity: crate::spool::IssuerIdx,
    seq: crate::spool::Seq,
    now_ms: i64,
    metrics: &BridgeMetrics,
) -> Result<bool, BridgeError> {
    for step in steps {
        let now_secs = now_ms / 1_000;
        let signed = match holds.build(step, seq, now_ms)? {
            Some(body) => sign_body(&body, keys, now_secs)?,
            // A tag-only provisioning step: the shared builder owns it.
            None => step_to_event(step, keys, now_secs.max(0) as u64)?,
        };
        let event_id = signed.id.to_hex();
        let frame = Frame {
            identity,
            channel: step.channel(),
            event_id: event_id.clone(),
            signed,
            // The sequence discharges its record as a whole; the drainer commits once.
            covers: (identity, 0),
            created_at_secs: now_secs,
        };
        // The `26006` is the ONE frame that leaves outside the tick: the <= 400 ms end-to-end
        // budget rides it, and a frame that waits for a tick has already spent 1000 ms of that.
        // It is bounded instead by a sliding one-minute burst window, and a full window DEFERS
        // it -- the record stays at the spool head and the ledger still has no alarm entry, so
        // the next tick re-plans exactly this step.
        let submitted = if matches!(step, PublishStep::PublishAlarm { .. }) {
            match publisher.submit_alarm(&frame, now_ms).await {
                Ok(AlarmAdmission::Sent(outcome)) => Ok(outcome),
                Ok(AlarmAdmission::Deferred) => {
                    metrics.alarm_deferred();
                    tracing::warn!(
                        module = module_path!(),
                        step = step.label(),
                        "the alarm burst window is full; this 26006 is deferred to a later tick"
                    );
                    return Ok(false);
                }
                Err(error) => Err(error),
            }
        } else {
            publisher.publish(&frame).await
        };
        let outcome = match submitted {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::warn!(
                    module = module_path!(),
                    step = step.label(),
                    reason = %error,
                    "a hold step could not be published; the sequence resumes next tick"
                );
                return Ok(false);
            }
        };
        if !outcome.is_success() {
            metrics.admission_rejection(outcome.reason());
            tracing::warn!(
                module = module_path!(),
                step = step.label(),
                reason = outcome.reason(),
                "the relay refused a hold step; the sequence resumes next tick"
            );
            return Ok(false);
        }
        // The callback runs only on an accepted step, and a ledger write that fails stops the
        // sequence: an unrecorded card id is exactly the state that republishes the card.
        holds.on_ok(step, &event_id, now_ms)?;
    }
    Ok(true)
}

/// Signs one hold body into the relay event it is.
fn sign_body(
    body: &crate::holds::HoldFrameBody,
    keys: &nostr::Keys,
    created_at_secs: i64,
) -> Result<nostr::Event, BridgeError> {
    let tags: Vec<nostr::Tag> = body
        .tags
        .iter()
        .map(|tag| nostr::Tag::parse(tag.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| BridgeError::Encode(error.to_string()))?;
    nostr::EventBuilder::new(nostr::Kind::Custom(body.kind), body.content.clone())
        .tags(tags)
        .custom_created_at(nostr::Timestamp::from(created_at_secs.max(0) as u64))
        .sign_with_keys(keys)
        .map_err(|error| BridgeError::Encode(error.to_string()))
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
    use swarm_runtime::held_action::HeldActionStore;

    use crate::publish::OkOutcome;
    use crate::spool::Record;

    struct Recording {
        frames: Vec<Frame>,
        answer: OkOutcome,
        /// A handle the test keeps after the drainer is moved into a task.
        sink: Option<Arc<Mutex<Vec<Frame>>>>,
        /// The REAL burst window, so the drainer's alarm lane is exercised through the same
        /// bound production runs under rather than through a stub that always admits.
        burst: crate::publish::AlarmBurst,
    }

    impl FramePublisher for Recording {
        async fn publish(&mut self, frame: &Frame) -> Result<OkOutcome, BridgeError> {
            if let Some(sink) = &self.sink {
                sink.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(frame.clone());
            }
            self.frames.push(frame.clone());
            Ok(self.answer.clone())
        }

        async fn submit_alarm(
            &mut self,
            frame: &Frame,
            now_ms: i64,
        ) -> Result<AlarmAdmission, BridgeError> {
            if !self.burst.try_admit(now_ms) {
                return Ok(AlarmAdmission::Deferred);
            }
            self.publish(frame).await.map(AlarmAdmission::Sent)
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

    /// Builds a drainer over a `Recording` publisher, with an optional hold store.
    #[allow(clippy::too_many_arguments)]
    fn drainer(
        dir: &tempfile::TempDir,
        spools: Arc<Mutex<SpoolSet>>,
        identities: Arc<IdentityTable>,
        operators: Vec<String>,
        store: Option<Arc<dyn swarm_runtime::held_action::HeldActionStore>>,
        answer: OkOutcome,
        metrics: BridgeMetrics,
        shutdown: watch::Receiver<bool>,
    ) -> AlarmDrainer<Recording> {
        let routing = channels::CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        let alarm_idx = identities.alarm();
        let issuer = identities.get(alarm_idx).unwrap().clone();
        AlarmDrainer {
            spools,
            identities,
            config: config(),
            holds: HoldPublisher::new(
                routing,
                store,
                operators,
                FALLBACK_CASE_TTL_SECONDS,
                issuer,
                alarm_idx,
                metrics.clone(),
            ),
            publisher: Recording {
                frames: vec![],
                answer,
                sink: None,
                burst: crate::publish::AlarmBurst::new(crate::publish::PERCH_ALARM_BURST_PER_MIN),
            },
            metrics,
            shutdown,
        }
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
        let handle = tokio::spawn(run(drainer(
            &dir,
            Arc::clone(&spools),
            Arc::clone(&identities),
            vec!["a".repeat(64)],
            None,
            OkOutcome::Accepted,
            metrics,
            shutdown_rx,
        )));
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
        let handle = tokio::spawn(run(drainer(
            &dir,
            Arc::clone(&spools),
            identities,
            vec![],
            None,
            OkOutcome::Accepted,
            metrics,
            shutdown_rx,
        )));
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

    /// Polls `ready` until it holds or the deadline passes.
    ///
    /// A fixed `sleep` is a race here: the drainer publishes one record per tick and the number
    /// of ticks a sequence needs depends on how many steps the relay took, so a test that sleeps
    /// asserts on whatever the scheduler happened to finish. Polling asserts on the STATE the
    /// test is about, and the deadline only bounds a failure.
    async fn wait_for(mut ready: impl FnMut() -> bool) -> bool {
        for _ in 0..600 {
            if ready() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        ready()
    }

    /// How many frames of `kind` the recording sink has seen.
    fn kind_count(recorded: &Arc<Mutex<Vec<Frame>>>, kind: u16) -> usize {
        recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|frame| frame.signed.kind.as_u16() == kind)
            .count()
    }

    /// The current value of a counter sample, by its full encoded name.
    fn counter(registry: &Arc<Mutex<prometheus_client::registry::Registry>>, name: &str) -> u64 {
        let mut out = String::new();
        prometheus_client::encoding::text::encode(
            &mut out,
            &registry.lock().unwrap_or_else(PoisonError::into_inner),
        )
        .unwrap();
        out.lines()
            .find_map(|line| line.strip_prefix(&format!("{name} ")))
            .and_then(|value| value.parse().ok())
            .unwrap_or_default()
    }

    fn held_fixture() -> swarm_runtime::held_action::HeldAction {
        swarm_runtime::held_action_fixtures::fixture_hold(
            swarm_core::types::ResponseAction::IsolateHost {
                host_id: "host-ops-1".into(),
            },
            1_773_738_882_600,
        )
    }

    fn response_held(
        hold: &swarm_runtime::held_action::HeldAction,
        state: swarm_runtime::held_action::HoldState,
    ) -> RuntimeEvent {
        RuntimeEvent::ResponseHeld {
            emitted_at_ms: hold.held_at_ms,
            hold_id: hold.hold_id.clone(),
            hunt_id: hold.action_request.hunt_id.0.clone(),
            action_kind: hold.action_request.action.kind().to_string(),
            severity: hold.action_request.severity,
            expires_at_ms: hold.expires_at_ms,
            state,
        }
    }

    /// Kinds the recording publisher saw, in the order they were submitted, skipping the twelve
    /// lane creates and their membership steps that every startup performs.
    fn hold_kinds(frames: &[Frame], lane_frames: usize) -> Vec<u16> {
        frames
            .iter()
            .skip(lane_frames)
            .map(|frame| frame.signed.kind.as_u16())
            .collect()
    }

    #[tokio::test]
    async fn a_held_action_publishes_the_case_the_card_the_notice_and_the_alarm_then_commits() {
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let identities = identities();
        let alarm_idx = identities.alarm();
        let store = Arc::new(swarm_runtime::held_action::MemoryHeldActionStore::default());
        let hold = held_fixture();
        store.create(hold.clone()).unwrap();
        spools
            .lock()
            .unwrap()
            .append(
                Stream::Alarm,
                Record::from_event(
                    &response_held(&hold, swarm_runtime::held_action::HoldState::Created),
                    alarm_idx,
                )
                .unwrap(),
            )
            .unwrap();

        let (metrics, registry) = BridgeMetrics::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(run(drainer(
            &dir,
            Arc::clone(&spools),
            Arc::clone(&identities),
            vec!["68".repeat(32)],
            Some(Arc::clone(&store) as Arc<dyn swarm_runtime::held_action::HeldActionStore>),
            OkOutcome::Accepted,
            metrics,
            shutdown_rx,
        )));
        let drained = Arc::clone(&spools);
        let settled = wait_for(|| {
            drained
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .alarm()
                .peek(usize::MAX)
                .is_ok_and(|records| records.is_empty())
        })
        .await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();

        assert!(
            settled,
            "the whole sequence landed, so the record is committed"
        );
        // The daemon record learned both callbacks.
        let after = store.get(&hold.hold_id).unwrap().unwrap();
        assert_eq!(
            after.state,
            swarm_runtime::held_action::HoldState::Notified,
            "the 46010 OK reported notified"
        );
        assert!(
            after.case_channel.is_some(),
            "the 9007 OK reported the channel"
        );
        assert!(after.notice_event_id.is_some());
        assert!(
            after.card_event_id.is_some(),
            "the notice carried the card's id"
        );
        // The routing sidecar is durable, so a restart replays nothing.
        let reopened = channels::CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        assert_eq!(
            reopened.open_card_for_hold(&hold.hold_id),
            after.card_event_id.as_deref()
        );
        assert_eq!(reopened.terminal_card_for_hold(&hold.hold_id), None);
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &registry.lock().unwrap()).unwrap();
        assert!(
            out.contains("perch_bridge_source_events_published_total{stream=\"alarm\"} 1"),
            "{out}"
        );
    }

    #[tokio::test]
    async fn the_hold_sequence_reaches_the_relay_in_kind_order_and_the_alarm_is_global() {
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let identities = identities();
        let alarm_idx = identities.alarm();
        let store = Arc::new(swarm_runtime::held_action::MemoryHeldActionStore::default());
        let hold = held_fixture();
        store.create(hold.clone()).unwrap();
        spools
            .lock()
            .unwrap()
            .append(
                Stream::Alarm,
                Record::from_event(
                    &response_held(&hold, swarm_runtime::held_action::HoldState::Created),
                    alarm_idx,
                )
                .unwrap(),
            )
            .unwrap();

        let (metrics, _registry) = BridgeMetrics::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut built = drainer(
            &dir,
            Arc::clone(&spools),
            Arc::clone(&identities),
            vec!["68".repeat(32)],
            Some(Arc::clone(&store) as Arc<dyn swarm_runtime::held_action::HeldActionStore>),
            OkOutcome::Accepted,
            metrics,
            shutdown_rx,
        );
        // No lanes, so every recorded frame belongs to the hold sequence.
        built.config.lane_channels.clear();
        let lane_frames = 0;
        let recorded = Arc::new(Mutex::new(Vec::new()));
        built.publisher.sink = Some(Arc::clone(&recorded));
        let handle = tokio::spawn(run(built));
        let sink = Arc::clone(&recorded);
        let settled = wait_for(|| kind_count(&sink, 26006) == 1).await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(settled, "the sequence never reached its alarm");

        let frames = recorded.lock().unwrap().clone();
        assert_eq!(
            hold_kinds(&frames, lane_frames),
            vec![9007, 9000, 9, 46010, 26006],
            "the five steps, in publish order"
        );
        let notice = &frames[lane_frames + 3];
        let names: Vec<String> = notice
            .signed
            .tags
            .iter()
            .filter_map(|tag| tag.clone().to_vec().first().cloned())
            .collect();
        assert_eq!(names, vec!["h", "p", "hold", "card"]);
        assert!(!names.contains(&"e".to_string()), "RF-D1");
        let card_id = frames[lane_frames + 2].signed.id.to_hex();
        assert!(
            notice
                .signed
                .tags
                .iter()
                .any(|tag| tag.clone().to_vec() == vec!["card".to_string(), card_id.clone()]),
            "the notice points at the card that preceded it"
        );
        assert_eq!(
            notice.signed.content,
            frames[lane_frames + 2]
                .signed
                .content
                .lines()
                .nth(1)
                .unwrap(),
            "the notice line is the card line, verbatim"
        );
        let alarm = &frames[lane_frames + 4];
        assert_eq!(alarm.channel, None, "26006 is global (R-1)");
        let alarm_names: Vec<String> = alarm
            .signed
            .tags
            .iter()
            .filter_map(|tag| tag.clone().to_vec().first().cloned())
            .collect();
        assert_eq!(alarm_names, vec!["p"]);
    }

    #[tokio::test]
    async fn a_refused_step_leaves_the_record_at_the_head_and_publishes_no_duplicate_card() {
        // The relay refuses everything. Nothing is committed, no callback fires, and the case
        // channel is never claimed as published.
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let identities = identities();
        let alarm_idx = identities.alarm();
        let store = Arc::new(swarm_runtime::held_action::MemoryHeldActionStore::default());
        let hold = held_fixture();
        store.create(hold.clone()).unwrap();
        spools
            .lock()
            .unwrap()
            .append(
                Stream::Alarm,
                Record::from_event(
                    &response_held(&hold, swarm_runtime::held_action::HoldState::Created),
                    alarm_idx,
                )
                .unwrap(),
            )
            .unwrap();

        let (metrics, _registry) = BridgeMetrics::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut built = drainer(
            &dir,
            Arc::clone(&spools),
            Arc::clone(&identities),
            vec!["68".repeat(32)],
            Some(Arc::clone(&store) as Arc<dyn swarm_runtime::held_action::HeldActionStore>),
            OkOutcome::Rejected {
                message: "blocked".into(),
            },
            metrics,
            shutdown_rx,
        );
        built.config.lane_channels.clear();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        built.publisher.sink = Some(Arc::clone(&recorded));
        let handle = tokio::spawn(run(built));
        let sink = Arc::clone(&recorded);
        let settled = wait_for(|| kind_count(&sink, 9007) >= 2).await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(settled, "the refused sequence never retried");

        assert!(
            !spools
                .lock()
                .unwrap()
                .alarm()
                .peek(usize::MAX)
                .unwrap()
                .is_empty(),
            "a refused sequence stays at the spool head"
        );
        assert_eq!(
            store.get(&hold.hold_id).unwrap().unwrap().state,
            swarm_runtime::held_action::HoldState::Created
        );
        let reopened = channels::CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        assert_eq!(reopened.open_card_for_hold(&hold.hold_id), None);
        // The 9007 was refused, so every later step in the sequence was abandoned: exactly one
        // frame per tick attempt, never a card into a channel that does not exist.
        let kinds: Vec<u16> = recorded
            .lock()
            .unwrap()
            .iter()
            .map(|frame| frame.signed.kind.as_u16())
            .collect();
        assert!(kinds.iter().all(|kind| *kind == 9007), "{kinds:?}");
    }

    #[tokio::test]
    async fn the_alarm_burst_cap_defers_rather_than_drops_and_holds_the_record() {
        // The cap is proved against the DRAINER, not only against the window type: with room
        // for two alarms and three holds waiting, exactly two 26006 frames reach the relay, the
        // third is counted as deferred, and its spool record is still at the head with its card
        // and notice already accepted -- so the retry publishes the alarm and nothing else.
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let identities = identities();
        let alarm_idx = identities.alarm();
        let store = Arc::new(swarm_runtime::held_action::MemoryHeldActionStore::default());
        let mut holds = Vec::new();
        for _ in 0..3 {
            let mut hold = held_fixture();
            hold.hold_id = swarm_runtime::held_action::mint_hold_id();
            store.create(hold.clone()).unwrap();
            spools
                .lock()
                .unwrap()
                .append(
                    Stream::Alarm,
                    Record::from_event(
                        &response_held(&hold, swarm_runtime::held_action::HoldState::Created),
                        alarm_idx,
                    )
                    .unwrap(),
                )
                .unwrap();
            holds.push(hold);
        }

        let (metrics, registry) = BridgeMetrics::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut built = drainer(
            &dir,
            Arc::clone(&spools),
            Arc::clone(&identities),
            vec!["68".repeat(32)],
            Some(Arc::clone(&store) as Arc<dyn swarm_runtime::held_action::HeldActionStore>),
            OkOutcome::Accepted,
            metrics,
            shutdown_rx,
        );
        built.config.lane_channels.clear();
        built.publisher.burst = crate::publish::AlarmBurst::new(2);
        let recorded = Arc::new(Mutex::new(Vec::new()));
        built.publisher.sink = Some(Arc::clone(&recorded));
        let handle = tokio::spawn(run(built));
        let sink = Arc::clone(&recorded);
        let counts = Arc::clone(&registry);
        let settled = wait_for(|| {
            kind_count(&sink, 46010) == 3
                && counter(&counts, "perch_bridge_alarm_deferred_total") >= 1
        })
        .await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(
            settled,
            "the drainer never reached the third hold's deferred alarm"
        );

        assert_eq!(
            kind_count(&recorded, 26006),
            2,
            "the burst window admits exactly its cap"
        );
        assert!(
            counter(&registry, "perch_bridge_alarm_deferred_total") >= 1,
            "the third alarm is DEFERRED, not dropped"
        );

        // The deferred hold kept its record, and everything before the alarm already landed --
        // so the retry costs one frame, not a republished card.
        assert!(
            !spools
                .lock()
                .unwrap()
                .alarm()
                .peek(usize::MAX)
                .unwrap()
                .is_empty(),
            "the deferred hold's record is still at the spool head"
        );
        let reopened = channels::CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        let deferred_holds: Vec<_> = holds
            .iter()
            .filter(|hold| !reopened.alarm_published_for_hold(&hold.hold_id))
            .collect();
        assert_eq!(
            deferred_holds.len(),
            1,
            "exactly one hold is still un-alarmed"
        );
        let pending = deferred_holds[0];
        assert!(
            reopened.open_card_for_hold(&pending.hold_id).is_some(),
            "its card was accepted and is never republished"
        );
        assert_eq!(
            store.get(&pending.hold_id).unwrap().unwrap().state,
            swarm_runtime::held_action::HoldState::Notified,
            "and its notice was accepted"
        );
        // Exactly one card and one notice per hold, deferral or not.
        let kinds: Vec<u16> = recorded
            .lock()
            .unwrap()
            .iter()
            .map(|frame| frame.signed.kind.as_u16())
            .collect();
        assert_eq!(kinds.iter().filter(|kind| **kind == 9).count(), 3);
        assert_eq!(kinds.iter().filter(|kind| **kind == 46010).count(), 3);
    }

    #[tokio::test]
    async fn alarms_are_never_shed_while_evidence_is() {
        // T-15. The evidence spool sheds oldest-first under its byte budget and records the
        // range it lost; the alarm spool refuses an append instead, so alarm work is never
        // evicted. With evidence actively evicting, every spooled hold still reaches the relay.
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 4096, 8192).unwrap(),
        ));
        let identities = identities();
        let alarm_idx = identities.alarm();
        let store = Arc::new(swarm_runtime::held_action::MemoryHeldActionStore::default());

        // Push the evidence spool past its budget so it evicts.
        for index in 0..24 {
            let bulky = finding_with_evidence(2_000 + index);
            spools
                .lock()
                .unwrap()
                .append(Stream::Evidence, Record::from_event(&bulky, 0).unwrap())
                .unwrap();
        }
        let evidence_gaps = spools.lock().unwrap().evidence().take_gaps();
        assert!(
            evidence_gaps
                .iter()
                .any(|gap| matches!(gap, crate::spool::GapCause::SpoolEvicted { .. })),
            "the evidence spool must have shed to make this test meaningful: {evidence_gaps:?}"
        );

        // The alarm spool, at the same budget, takes every hold and refuses none.
        let mut holds = Vec::new();
        for _ in 0..3 {
            let mut hold = held_fixture();
            hold.hold_id = swarm_runtime::held_action::mint_hold_id();
            store.create(hold.clone()).unwrap();
            spools
                .lock()
                .unwrap()
                .append(
                    Stream::Alarm,
                    Record::from_event(
                        &response_held(&hold, swarm_runtime::held_action::HoldState::Created),
                        alarm_idx,
                    )
                    .unwrap(),
                )
                .expect("alarm work is never shed");
            holds.push(hold);
        }
        assert!(
            spools.lock().unwrap().alarm().take_gaps().is_empty(),
            "the alarm spool never records an eviction gap"
        );

        let (metrics, _registry) = BridgeMetrics::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut built = drainer(
            &dir,
            Arc::clone(&spools),
            Arc::clone(&identities),
            vec!["68".repeat(32)],
            Some(Arc::clone(&store) as Arc<dyn swarm_runtime::held_action::HeldActionStore>),
            OkOutcome::Accepted,
            metrics,
            shutdown_rx,
        );
        built.config.lane_channels.clear();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        built.publisher.sink = Some(Arc::clone(&recorded));
        let handle = tokio::spawn(run(built));
        let sink = Arc::clone(&recorded);
        let settled = wait_for(|| kind_count(&sink, 26006) == 3).await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(
            settled,
            "an alarm was lost while the evidence spool was shedding"
        );
        assert_eq!(
            kind_count(&recorded, 26006),
            3,
            "every alarm survived a spool that was shedding evidence"
        );
        let reopened = channels::CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        for hold in &holds {
            assert!(
                reopened.alarm_published_for_hold(&hold.hold_id),
                "hold {} lost its alarm",
                hold.hold_id
            );
        }
    }

    /// A `Finding` event whose evidence blob is large enough to roll spool segments.
    fn finding_with_evidence(seed: usize) -> RuntimeEvent {
        serde_json::from_value(serde_json::json!({
            "event_type": "finding", "emitted_at_ms": 1, "host_id": "web-04",
            "finding": {"schema": "swarm_finding", "finding_id": format!("f{seed}"),
                        "event_id": "tel-1", "strategy_id": "s", "threat_class": "execution",
                        "severity": "LOW", "confidence": 0.5,
                        "evidence": {"blob": "x".repeat(1_500)}}
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn a_lane_the_relay_already_has_is_success_not_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let (metrics, _registry) = BridgeMetrics::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(run(drainer(
            &dir,
            spools,
            identities(),
            vec![],
            None,
            OkOutcome::ChannelAlreadyExists,
            metrics,
            shutdown_rx,
        )));
        tokio::time::sleep(Duration::from_millis(60)).await;
        shutdown_tx.send(true).unwrap();
        handle
            .await
            .unwrap()
            .expect("a duplicate channel must not fail startup");
    }
}
