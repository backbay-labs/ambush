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
//!
//! # When the relay's answer is settled, and what happens then (W3-38)
//!
//! Replaying a refused sequence forever is right exactly as long as the relay might yet change
//! its answer, and wrong the moment it will not. A case channel the relay no longer has --
//! restored, migrated, wiped -- refuses every write into itself with the same message on every
//! tick, and because the spool has one head, the hold behind it never drains either. A live run
//! measured that at twenty-five minutes and counting.
//!
//! Two mechanisms bound it, in this order. First the ledger yields: a refusal that says the
//! channel is not there deletes the recorded acceptance
//! ([`crate::channels::CaseRouting::forget_channel_created`]), so the next tick re-plans the
//! idempotent `9007` and most of these repair themselves in one tick. What survives that is
//! settled, and [`HEAD_REFUSAL_BUDGET`] consecutive REFUSALS -- never a transport failure, never
//! a deferred alarm, because neither is the relay answering -- move the record into a durable
//! dead-letter ([`ParkedLedger`]) so the queue behind it drains. The parked record is retried on
//! ticks where the spool is idle, so the live head is never made to wait for one.

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
use crate::publish::{AlarmAdmission, OkOutcome};
use crate::spool::{Spool, SpoolSet};
use crate::stream::{Stream, threat_class_slug};

mod parked;

pub use parked::{ParkReason, ParkedLedger, ParkedRecord};

/// The case TTL used when neither the threat class nor `default` is configured: thirty days.
pub const FALLBACK_CASE_TTL_SECONDS: i32 = 2_592_000;

/// Consecutive relay REFUSALS of one head record before it is parked. Thirty ticks at the
/// 1 Hz cadence is thirty seconds: a relay that is down is a transport error and never
/// counts, so thirty refusals in a row means the relay's state disagrees with the ledger
/// and no further tick will change its answer. Equals the daemon's default
/// `runtime.response.refile_after_ms`.
pub const HEAD_REFUSAL_BUDGET: u32 = 30;

/// A parked record is retried no sooner than this after it was parked or last retried.
pub const PARKED_RETRY_INTERVAL_MS: i64 = 30_000;

/// The dead-letter holds at most this many records; the oldest is dropped past it, counted
/// as `perch_bridge_dropped_events_total{stream="alarm",cause="parked_overflow"}`.
pub const PARKED_CAPACITY: usize = 256;

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
    /// The dead-letter for the records the relay refuses permanently.
    pub parked: ParkedLedger,
    /// How this drainer reads the wall clock.
    ///
    /// Injected rather than read from `chrono` at each use because
    /// [`PARKED_RETRY_INTERVAL_MS`] is thirty seconds, and a test that proved the retry by
    /// waiting for it would take thirty seconds to answer. Production passes
    /// [`system_clock`].
    pub clock: Clock,
    /// The process-wide shutdown watch.
    pub shutdown: watch::Receiver<bool>,
}

/// A source of wall-clock milliseconds.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// The clock the daemon runs on: `chrono::Utc::now()`, in milliseconds.
#[must_use]
pub fn system_clock() -> Clock {
    Arc::new(|| chrono::Utc::now().timestamp_millis())
}

/// The refusals the record currently at the spool head has collected.
///
/// Keyed by `(issuer, seq)` rather than merely counted, so a record that lands and a later one
/// that starts failing can never share a budget: the count belongs to a record, not to a
/// position in the queue.
#[derive(Debug, Clone, Copy)]
struct HeadBudget {
    key: (crate::spool::IssuerIdx, crate::spool::Seq),
    refusals: u32,
    first_refused_at_ms: i64,
}

impl HeadBudget {
    /// A fresh budget for `key`, with no refusals yet.
    const fn new(key: (crate::spool::IssuerIdx, crate::spool::Seq), now_ms: i64) -> Self {
        Self {
            key,
            refusals: 0,
            first_refused_at_ms: now_ms,
        }
    }
}

/// The state one drained record needs.
///
/// A struct because the spool head and the dead-letter run the same record through the same
/// code, and seven positional parameters at two call sites is where a caller swaps two of them
/// and it still compiles.
struct DrainContext<'a, P: FramePublisher> {
    holds: &'a mut HoldPublisher,
    publisher: &'a mut P,
    keys: &'a nostr::Keys,
    identity: crate::spool::IssuerIdx,
    config: &'a PerchBridgeConfig,
    operators: &'a [String],
    metrics: &'a BridgeMetrics,
}

/// What draining one record did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drained {
    /// Every step the plan asked for was accepted.
    Landed,
    /// The relay answered `OK false`. The record is unchanged and the next tick re-plans it --
    /// and this is the ONLY outcome that spends the head budget, because it is the only one in
    /// which the relay has actually answered.
    Refused {
        /// The refusal's `OkOutcome::reason()`.
        reason: &'static str,
    },
    /// Nothing was answered: the socket failed, or the bridge's own burst window deferred the
    /// alarm. Neither says anything about whether the relay would take the sequence.
    Stalled,
    /// There is nothing to publish and there never will be: undeliverable, already published, a
    /// state this milestone does not publish, or a second case id for one hunt.
    Discarded,
}

/// What publishing one hold sequence did.
///
/// Three-valued so the caller cannot conflate a refusal with a transport failure or a
/// deferral. It used to be a `bool`, and under a `bool` a relay that was down and a relay that
/// disagreed were the same answer -- which is exactly the distinction the head budget rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SequenceOutcome {
    /// Every step was accepted.
    Landed,
    /// A step was refused, with the reason the relay gave.
    Refused {
        /// The refusal's `OkOutcome::reason()`.
        reason: &'static str,
    },
    /// A step was never answered.
    Stalled,
}

impl From<SequenceOutcome> for Drained {
    fn from(outcome: SequenceOutcome) -> Self {
        match outcome {
            SequenceOutcome::Landed => Self::Landed,
            SequenceOutcome::Refused { reason } => Self::Refused { reason },
            SequenceOutcome::Stalled => Self::Stalled,
        }
    }
}

/// Drains the alarm spool, one record per tick, after ensuring the twelve lanes exist.
///
/// # Errors
///
/// [`BridgeError::SpoolIo`] when the spool, its cursor or the dead-letter fails,
/// [`BridgeError::InvalidConfig`] when the identity table has no alarm slot or the daemon minted
/// a `case_id` that is not a UUID, and [`BridgeError::Encode`] when a record does not
/// deserialize.
///
pub async fn run<P: FramePublisher>(drainer: AlarmDrainer<P>) -> Result<(), BridgeError> {
    let AlarmDrainer {
        spools,
        identities,
        config,
        mut holds,
        mut publisher,
        metrics,
        mut parked,
        clock,
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
    // The refusals the record at the head has collected. `None` whenever the head is empty or
    // has just changed, so it is a property of one record and never of the drainer.
    let mut head_budget: Option<HeadBudget> = None;
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
                let now_ms = clock();
                let head = {
                    let mut guard = spools.lock().unwrap_or_else(PoisonError::into_inner);
                    guard.alarm().peek(PERCH_FRAME_MAX_BYTES)?.into_iter().next()
                };
                let mut context = DrainContext {
                    holds: &mut holds,
                    publisher: &mut publisher,
                    keys: &keys,
                    identity: alarm_issuer,
                    config: &config,
                    operators: &operators,
                    metrics: &metrics,
                };
                let Some(record) = head else {
                    // An idle tick. The live spool has nothing, so this is the only kind of tick
                    // a parked record is served on: the head is never made to wait for one.
                    head_budget = None;
                    retry_parked(&mut context, &mut parked, now_ms).await?;
                    continue;
                };
                let event: RuntimeEvent = serde_json::from_slice(&record.payload)
                    .map_err(|error| BridgeError::Encode(error.to_string()))?;

                match drain_one(&mut context, &event, record.seq, now_ms).await? {
                    Drained::Landed | Drained::Discarded => {
                        commit(&spools, record.issuer, record.seq)?;
                        head_budget = None;
                    }
                    // Nothing was answered, so nothing is learned: the record keeps its place
                    // and its budget, and the next tick asks the relay again. A relay that is
                    // down for an hour must not park the work that is waiting for it.
                    Drained::Stalled => {}
                    // A refused sequence leaves the record at the head, and the next tick
                    // replans from durable state -- until the budget says the relay's answer is
                    // settled and no further tick will change it.
                    Drained::Refused { reason } => {
                        let key = (record.issuer, record.seq);
                        let budget = head_budget.get_or_insert(HeadBudget::new(key, now_ms));
                        if budget.key != key {
                            *budget = HeadBudget::new(key, now_ms);
                        }
                        budget.refusals = budget.refusals.saturating_add(1);
                        if budget.refusals >= HEAD_REFUSAL_BUDGET {
                            park_head(
                                &mut parked, &metrics, &record, &event, budget, reason, now_ms,
                            )?;
                            commit(&spools, record.issuer, record.seq)?;
                            head_budget = None;
                        }
                    }
                }
            }
        }
    }
}

/// Plans and publishes ONE record, whether it came from the spool head or from the dead-letter.
///
/// Every counter and log line a record earns is emitted here, so a parked record is accounted
/// for exactly as the head record it once was. What the two callers do NOT share is the
/// bookkeeping an outcome implies: the head path moves the spool cursor, the parked path edits
/// the dead-letter, and neither of those is part of publishing.
///
/// # Errors
///
/// Propagates a spool, ledger or configuration failure. A relay refusal is not one: it comes
/// back as [`Drained::Refused`].
async fn drain_one<P: FramePublisher>(
    context: &mut DrainContext<'_, P>,
    event: &RuntimeEvent,
    seq: crate::spool::Seq,
    now_ms: i64,
) -> Result<Drained, BridgeError> {
    match event {
        RuntimeEvent::CasePromoted {
            hunt_id,
            case_id,
            clause,
            threat_class,
            ..
        } => {
            let case = uuid::Uuid::parse_str(case_id).map_err(|_| BridgeError::InvalidConfig {
                reason: format!("daemon minted a non-uuid case_id {case_id}"),
            })?;
            let ttl = context
                .config
                .case_ttl_seconds
                .get(&threat_class_slug(threat_class))
                .or_else(|| context.config.case_ttl_seconds.get("default"))
                .copied()
                .unwrap_or(FALLBACK_CASE_TTL_SECONDS);
            let clause = PromotionClause::from(*clause);
            let trigger = CasePromotionTrigger::Promoted {
                hunt_id: hunt_id.clone(),
                case_id: case,
                clause,
            };
            let planned =
                context
                    .holds
                    .routing_mut()
                    .ensure_case_channel(&trigger, context.operators, ttl);
            match planned {
                Ok((_, steps)) => {
                    let mut outcome = Drained::Landed;
                    for step in &steps {
                        if let Err(error) = publish_step(
                            context.publisher,
                            step,
                            context.keys,
                            context.identity,
                            context.metrics,
                        )
                        .await
                        {
                            outcome = Drained::Stalled;
                            // The same healing the hold sequence performs, on the one path that
                            // provisions a case channel without one. `publish_step` renders the
                            // outcome into the message, so the refusal is recognised by that
                            // rendering.
                            if let BridgeError::RelayRejected { message } = &error {
                                if let Some(channel) = step.channel()
                                    && (message.as_str() == OkOutcome::NotAChannelMember.reason()
                                        || message.contains("channel not found"))
                                {
                                    context
                                        .holds
                                        .routing_mut()
                                        .forget_channel_created(channel)?;
                                    tracing::warn!(
                                        module = module_path!(),
                                        step = step.label(),
                                        "the relay no longer knows case channel {channel}; its \
                                         create is re-planned before the next step"
                                    );
                                }
                                outcome = Drained::Refused {
                                    reason: refusal_label(message),
                                };
                            }
                            tracing::warn!(
                                module = module_path!(),
                                reason = %error,
                                "case channel step failed; retrying next tick"
                            );
                            break;
                        }
                    }
                    if outcome == Drained::Landed {
                        // The relay accepted the create, so stop replanning it. Until this lands
                        // the hunt is routed but unconfirmed, which is what makes a refused
                        // create retry instead of committing silently.
                        context.holds.routing_mut().record_channel_created(case)?;
                        context.metrics.case_channel_created(clause.as_str());
                        context.metrics.source_events_published(Stream::Alarm);
                        tracing::info!(
                            module = module_path!(),
                            case_id = %case,
                            name = %case_channel_name(case),
                            %hunt_id,
                            clause = clause.as_str(),
                            "case channel created"
                        );
                    }
                    Ok(outcome)
                }
                // Two parties minted case ids for one investigation. The record is discarded
                // rather than retried forever: the daemon's incident already names the id it
                // sent, and only one of the two can be the case. Failure mode F20 -- visible in
                // a counter, not blank.
                Err(BridgeError::CaseChannelConflict {
                    hunt_id,
                    existing,
                    incoming,
                }) => {
                    context.metrics.case_channel_conflict();
                    tracing::error!(
                        module = module_path!(),
                        %hunt_id,
                        %existing,
                        %incoming,
                        "a second case id was minted for one hunt; refusing to create a second \
                         channel"
                    );
                    Ok(Drained::Discarded)
                }
                Err(error) => Err(error),
            }
        }
        // A held destructive action: the whole sequence, in order, on one record.
        RuntimeEvent::ResponseHeld { .. } => match context.holds.plan(event)? {
            HoldPlan::Undeliverable { hold_id, reason } => {
                // Refusing is the outcome, not an error to retry forever: no number of ticks
                // adds an operator pubkey to the config or a record to a store that lost it.
                // The counter carries the reason and the record is discharged.
                tracing::error!(
                    module = module_path!(),
                    %hold_id,
                    reason,
                    "a held action cannot be delivered; it is counted, not retried"
                );
                Ok(Drained::Discarded)
            }
            // Already published, or a state the daemon does not ask the bridge to republish.
            // Neither a drop nor a publish.
            HoldPlan::Steps(steps) if steps.is_empty() => {
                context.metrics.skipped_unpublished(Stream::Alarm);
                Ok(Drained::Discarded)
            }
            HoldPlan::Steps(steps) => {
                let outcome = publish_hold_sequence(context, &steps, seq, now_ms).await?;
                if outcome == SequenceOutcome::Landed {
                    context.metrics.source_events_published(Stream::Alarm);
                }
                Ok(outcome.into())
            }
        },
        // ModeTransition / TamperAlert: alarm-class facts this milestone does not publish. Their
        // meaning stays in the daemon's own stores, so they are discharged and counted apart
        // from a drop.
        _ => {
            context.metrics.skipped_unpublished(Stream::Alarm);
            Ok(Drained::Discarded)
        }
    }
}

/// Serves one due record from the dead-letter, on a tick that had no head work.
///
/// One record per tick, because a retry costs the relay budget a head record would have spent,
/// and oldest first, so a newer parked record cannot starve an older one.
///
/// # Errors
///
/// Propagates a spool or ledger failure, exactly as the head path does.
async fn retry_parked<P: FramePublisher>(
    context: &mut DrainContext<'_, P>,
    parked: &mut ParkedLedger,
    now_ms: i64,
) -> Result<(), BridgeError> {
    let Some(due) = parked.next_due(now_ms, PARKED_RETRY_INTERVAL_MS) else {
        return Ok(());
    };
    let (issuer, seq, retries, payload) = (due.issuer, due.seq, due.retries, due.payload.clone());
    let event: RuntimeEvent = match serde_json::from_slice(&payload) {
        Ok(event) => event,
        Err(error) => {
            // A payload this build cannot read. Keeping it would hold the dead-letter open on a
            // record no tick can ever publish, and propagating the error would take the whole
            // alarm lane down over one record already abandoned, so it is dropped with its
            // reason. This is the only place a parked record leaves without being planned.
            tracing::error!(
                module = module_path!(),
                issuer,
                seq,
                reason = %error,
                "a parked alarm record no longer deserializes; it leaves the dead-letter unread"
            );
            parked.remove(issuer, seq)?;
            context.metrics.alarm_unparked("undecodable");
            return Ok(());
        }
    };

    match drain_one(context, &event, seq, now_ms).await? {
        // Planned from durable state, exactly like a head record: `Landed` means the steps that
        // were still outstanding were accepted, and `Discarded` means there were none left to
        // publish -- the daemon re-filed the hold and it has since been served, or it expired.
        left @ (Drained::Landed | Drained::Discarded) => {
            parked.remove(issuer, seq)?;
            let outcome = if left == Drained::Landed {
                "landed"
            } else {
                "discarded"
            };
            context.metrics.alarm_unparked(outcome);
            tracing::info!(
                module = module_path!(),
                issuer,
                seq,
                retries,
                outcome,
                "a parked alarm record left the dead-letter"
            );
        }
        // Still refused. The interval starts again, so a permanently broken record costs one
        // frame every thirty seconds rather than one per tick.
        Drained::Refused { reason } => {
            parked.touch(issuer, seq, now_ms)?;
            tracing::warn!(
                module = module_path!(),
                issuer,
                seq,
                retries,
                reason,
                "a parked alarm record was refused again; it stays parked for another interval"
            );
        }
        // The relay is down or the burst window is full. Nothing was answered, so the record
        // keeps the instant it was parked at and the next idle tick past the interval asks
        // again.
        Drained::Stalled => {}
    }
    Ok(())
}

/// Moves the head record into the dead-letter, because the relay's answer is settled.
///
/// The spool cursor may only be moved past a record nobody published once that record is
/// durably written down somewhere else, which is the whole reason [`ParkedLedger`] is a file.
///
/// # Errors
///
/// [`BridgeError::SpoolIo`] when the dead-letter cannot be written. The caller must then NOT
/// commit: a park that is not durable is a drop.
fn park_head(
    parked: &mut ParkedLedger,
    metrics: &BridgeMetrics,
    record: &crate::spool::Record,
    event: &RuntimeEvent,
    budget: &HeadBudget,
    reason: &'static str,
    now_ms: i64,
) -> Result<(), BridgeError> {
    let evicted = parked.park(ParkedRecord {
        issuer: record.issuer,
        seq: record.seq,
        payload: record.payload.clone(),
        parked_at_ms: now_ms,
        retries: 0,
        reason: ParkReason::refusal_budget_exhausted(reason),
    })?;
    if let Some(evicted) = evicted {
        // The dead-letter is bounded, so the record abandoned longest ago goes. That IS a drop:
        // nothing will retry it again, and it is counted where every other lost event is.
        metrics.dropped_event(Stream::Alarm, "parked_overflow");
        tracing::error!(
            module = module_path!(),
            issuer = evicted.issuer,
            seq = evicted.seq,
            parked_at_ms = evicted.parked_at_ms,
            "the parked alarm dead-letter is full; its oldest record was dropped to make room"
        );
    }
    metrics.alarm_parked(reason);
    let (subject, id) = subject_of(event);
    tracing::error!(
        module = module_path!(),
        subject,
        id,
        refusals = budget.refusals,
        reason,
        blocked_for_ms = now_ms - budget.first_refused_at_ms,
        "a hold sequence was refused {} times in a row and is parked; later holds no longer \
         wait behind it",
        budget.refusals
    );
    Ok(())
}

/// Which identifier a record is about, for a log line: `("hold_id", ...)` or
/// `("case_id", ...)`.
fn subject_of(event: &RuntimeEvent) -> (&'static str, &str) {
    match event {
        RuntimeEvent::ResponseHeld { hold_id, .. } => ("hold_id", hold_id.as_str()),
        RuntimeEvent::CasePromoted { case_id, .. } => ("case_id", case_id.as_str()),
        // Unreachable in practice: no other event is ever refused, because no other event
        // publishes anything.
        _ => ("event", ""),
    }
}

/// Recovers the refusal label from the message [`publish_step`] rendered into its error.
///
/// `publish_step` answers a refusal with `RelayRejected { message: outcome.reason() }`, so the
/// label set is closed and a message outside it can only be `rejected` -- which is the label
/// `OkOutcome::Rejected` itself carries. Kept as a `&'static str` so the parked reason and the
/// counter label are the same closed set the hold path uses.
fn refusal_label(message: &str) -> &'static str {
    const REFUSALS: [&str; 5] = [
        "admission_unavailable",
        "rate_limited",
        "relay_fork_absent",
        "not_a_channel_member",
        "clock_skew",
    ];
    REFUSALS
        .into_iter()
        .find(|label| *label == message)
        .unwrap_or("rejected")
}

/// Publishes one hold sequence in order, acknowledging each accepted step before the next.
///
/// [`SequenceOutcome::Landed`] is the only answer under which the caller discharges the record.
///
/// The order is load-bearing twice over. The `9007` must precede the `9000`s because
/// `create_channel_with_id` bootstraps only its creator as a member; the card must precede the
/// notice because the notice's `card` tag is the id the card step returned; and the alarm is
/// last because a frame naming a hold whose durable record is not yet on the relay sends an
/// operator to a case that has nothing in it.
///
/// # Errors
///
/// Propagates a spool or ledger failure. A relay refusal is NOT an error: it comes back as
/// [`SequenceOutcome::Refused`], the record stays at the head, and the next tick replans.
async fn publish_hold_sequence<P: FramePublisher>(
    context: &mut DrainContext<'_, P>,
    steps: &[PublishStep],
    seq: crate::spool::Seq,
    now_ms: i64,
) -> Result<SequenceOutcome, BridgeError> {
    for step in steps {
        let now_secs = now_ms / 1_000;
        let signed = match context.holds.build(step, seq, now_ms)? {
            Some(body) => sign_body(&body, context.keys, now_secs)?,
            // A tag-only provisioning step: the shared builder owns it.
            None => step_to_event(step, context.keys, now_secs.max(0) as u64)?,
        };
        let event_id = signed.id.to_hex();
        let frame = Frame {
            identity: context.identity,
            channel: step.channel(),
            event_id: event_id.clone(),
            signed,
            // The sequence discharges its record as a whole; the drainer commits once.
            covers: (context.identity, 0),
            created_at_secs: now_secs,
        };
        // The `26006` is the ONE frame that leaves outside the tick: the <= 400 ms end-to-end
        // budget rides it, and a frame that waits for a tick has already spent 1000 ms of that.
        // It is bounded instead by a sliding one-minute burst window, and a full window DEFERS
        // it -- the record stays at the spool head and the ledger still has no alarm entry, so
        // the next tick re-plans exactly this step.
        let submitted = if matches!(step, PublishStep::PublishAlarm { .. }) {
            match context.publisher.submit_alarm(&frame, now_ms).await {
                Ok(AlarmAdmission::Sent(outcome)) => Ok(outcome),
                Ok(AlarmAdmission::Deferred) => {
                    context.metrics.alarm_deferred();
                    tracing::warn!(
                        module = module_path!(),
                        step = step.label(),
                        "the alarm burst window is full; this 26006 is deferred to a later tick"
                    );
                    // The bridge's own back-pressure, not the relay's answer: STALLED, so it
                    // never spends the budget that exists for a relay which disagrees.
                    return Ok(SequenceOutcome::Stalled);
                }
                Err(error) => Err(error),
            }
        } else {
            context.publisher.publish(&frame).await
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
                // The socket failed, which says nothing about whether the relay would have
                // taken this step. A relay that is down must never park the work waiting on it.
                return Ok(SequenceOutcome::Stalled);
            }
        };
        if !outcome.is_success() {
            context.metrics.admission_rejection(outcome.reason());
            // The relay's state disagrees with the ledger about whether this channel exists,
            // and the relay is the ground truth. Forgetting the recorded acceptance is what
            // makes the next tick re-plan the idempotent `9007` ahead of this step; without it
            // the create is never offered again and every later hold queues behind this one
            // (W3-38).
            if let Some(case) = step.channel()
                && channel_state_refusal(&outcome)
            {
                context.holds.routing_mut().forget_channel_created(case)?;
                tracing::warn!(
                    module = module_path!(),
                    step = step.label(),
                    reason = outcome.reason(),
                    "the relay no longer knows case channel {case}; its create is re-planned \
                     before the next step"
                );
            }
            tracing::warn!(
                module = module_path!(),
                step = step.label(),
                reason = outcome.reason(),
                "the relay refused a hold step; the sequence resumes next tick"
            );
            return Ok(SequenceOutcome::Refused {
                reason: outcome.reason(),
            });
        }
        // The callback runs only on an accepted step, and a ledger write that fails stops the
        // sequence: an unrecorded card id is exactly the state that republishes the card.
        context.holds.on_ok(step, &event_id, now_ms)?;
    }
    Ok(SequenceOutcome::Landed)
}

/// Whether a refusal says the relay does not have the channel the step named.
///
/// Two shapes mean it. `restricted: not a channel member` is the membership precondition every
/// channel-scoped kind acquires, and a channel that does not exist has no members at all, so a
/// relay whose database was restored answers a perfectly valid write with it. `channel not
/// found` is the same fact, spelled by whichever handler checked existence first. Neither is a
/// reason to retry the step as written: no number of ticks adds this bridge to a channel that is
/// gone, and only a fresh `9007` does.
fn channel_state_refusal(outcome: &OkOutcome) -> bool {
    match outcome {
        OkOutcome::NotAChannelMember => true,
        OkOutcome::Rejected { message } => message.contains("channel not found"),
        _ => false,
    }
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

    /// A per-frame answer: what the relay says to THIS frame, or `None` to fall through to the
    /// publisher's blanket `answer`.
    ///
    /// A single fixed answer cannot express the state W3-38 is about, where the relay accepts
    /// one kind and refuses another for the same channel, nor a transport failure that must not
    /// count as a refusal. The reply is a `Result`, not an `OkOutcome`, for exactly that second
    /// reason: `Err` is the socket failing, which the drainer must treat differently from `OK
    /// false`.
    type Reply = Arc<dyn Fn(&Frame) -> Option<Result<OkOutcome, BridgeError>> + Send + Sync>;

    struct Recording {
        frames: Vec<Frame>,
        answer: OkOutcome,
        /// The relay's per-frame answer, when a test needs one.
        reply: Option<Reply>,
        /// A handle the test keeps after the drainer is moved into a task.
        sink: Option<Arc<Mutex<Vec<Frame>>>>,
        /// The REAL burst window, so the drainer's alarm lane is exercised through the same
        /// bound production runs under rather than through a stub that always admits.
        burst: crate::publish::AlarmBurst,
    }

    impl FramePublisher for Recording {
        async fn publish(&mut self, frame: &Frame) -> Result<OkOutcome, BridgeError> {
            // Recorded before the answer, refusals and transport failures included: what a test
            // asserts on is the frames that LEFT, not the ones the relay liked.
            if let Some(sink) = &self.sink {
                sink.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(frame.clone());
            }
            self.frames.push(frame.clone());
            match self.reply.as_ref().and_then(|reply| reply(frame)) {
                Some(answer) => answer,
                None => Ok(self.answer.clone()),
            }
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
                reply: None,
                sink: None,
                burst: crate::publish::AlarmBurst::new(crate::publish::PERCH_ALARM_BURST_PER_MIN),
            },
            metrics,
            parked: ParkedLedger::open(&dir.path().join("parked-alarms.json")).unwrap(),
            clock: system_clock(),
            shutdown,
        }
    }

    /// A clock the test moves, in milliseconds off the real one.
    ///
    /// Real time still runs underneath, because the drainer's own cadence is a real
    /// `tokio::time::interval` and the tests drive it by waiting for state. What a test needs is
    /// to be thirty seconds later without waiting thirty seconds, and an offset is the smallest
    /// thing that gives it that.
    fn offset_clock() -> (Clock, Arc<std::sync::atomic::AtomicI64>) {
        let offset = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let handle = Arc::clone(&offset);
        (
            Arc::new(move || {
                chrono::Utc::now().timestamp_millis()
                    + handle.load(std::sync::atomic::Ordering::SeqCst)
            }),
            offset,
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

    /// The whole scrape, for an assertion about a sample that must NOT exist.
    fn scrape(registry: &Arc<Mutex<prometheus_client::registry::Registry>>) -> String {
        let mut out = String::new();
        prometheus_client::encoding::text::encode(
            &mut out,
            &registry.lock().unwrap_or_else(PoisonError::into_inner),
        )
        .unwrap();
        out
    }

    /// The current value of a counter sample, by its full encoded name.
    fn counter(registry: &Arc<Mutex<prometheus_client::registry::Registry>>, name: &str) -> u64 {
        scrape(registry)
            .lines()
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
    async fn a_not_a_channel_member_refusal_forgets_the_created_channel_and_the_next_tick_recreates_it()
     {
        // The relay's database was reset between the create and the membership write. The 9007
        // was accepted and recorded, and the 9000 behind it finds a channel the relay no longer
        // has. Believing the recorded acceptance would leave the create un-planned forever and
        // every step after it refused; forgetting it makes the next tick offer the idempotent
        // 9007 again, and the sequence completes with exactly one card.
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
        built.config.lane_channels.clear();
        // The relay's own view of which channels exist. A 9007 creates one; the reset drops
        // every one of them, once, just before the first membership write.
        let known: Arc<Mutex<std::collections::HashSet<uuid::Uuid>>> =
            Arc::new(Mutex::new(std::collections::HashSet::new()));
        let reset_once = Arc::new(std::sync::atomic::AtomicBool::new(false));
        built.publisher.reply = Some(Arc::new(move |frame: &Frame| {
            let channel = frame.channel?;
            let mut known = known.lock().unwrap_or_else(PoisonError::into_inner);
            if frame.signed.kind.as_u16() == 9007 {
                known.insert(channel);
                return None;
            }
            if frame.signed.kind.as_u16() == 9000
                && !reset_once.swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                known.clear();
            }
            (!known.contains(&channel)).then_some(Ok(OkOutcome::NotAChannelMember))
        }));
        let recorded = Arc::new(Mutex::new(Vec::new()));
        built.publisher.sink = Some(Arc::clone(&recorded));
        let handle = tokio::spawn(run(built));
        let sink = Arc::clone(&recorded);
        let settled = wait_for(|| kind_count(&sink, 26006) == 1).await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(
            settled,
            "the sequence never recovered from a channel the relay had lost"
        );

        let frames = recorded.lock().unwrap().clone();
        assert_eq!(
            hold_kinds(&frames, 0),
            vec![9007, 9000, 9007, 9000, 9, 46010, 26006],
            "the refused 9000 buys exactly one more create, then the sequence completes"
        );
        let routing = channels::CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        let case = routing
            .case_for_hunt(&hold.action_request.hunt_id.0)
            .expect("the hold routed its hunt to a case channel");
        assert!(
            routing.channel_is_created(case),
            "the re-created channel is recorded again once the relay accepts it"
        );
        assert_eq!(
            kind_count(&recorded, 9),
            1,
            "healing touches the channel ledger only: one card, ever"
        );
    }

    /// Appends one `created` hold for `hunt`, and routes its hunt to a case channel the test can
    /// name in the publisher's rules.
    ///
    /// The route is written through the same sidecar the drainer opens, so the drainer inherits
    /// it exactly as it would after a restart: the hunt is routed and its channel is not yet
    /// recorded as created, which is where every one of these sequences begins.
    fn route_and_spool_hold(
        dir: &tempfile::TempDir,
        spools: &Arc<Mutex<SpoolSet>>,
        store: &Arc<swarm_runtime::held_action::MemoryHeldActionStore>,
        alarm_idx: crate::spool::IssuerIdx,
        hunt: &str,
    ) -> (swarm_runtime::held_action::HeldAction, uuid::Uuid) {
        let mut hold = held_fixture();
        hold.hold_id = swarm_runtime::held_action::mint_hold_id();
        hold.action_request.hunt_id = swarm_core::types::HuntId(hunt.to_string());
        store.create(hold.clone()).unwrap();
        let mut routing =
            channels::CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        let (case, _) = routing
            .ensure_case_channel(
                &CasePromotionTrigger::Held {
                    hunt_id: hunt.to_string(),
                    hold_id: hold.hold_id.clone(),
                },
                &[],
                FALLBACK_CASE_TTL_SECONDS,
            )
            .unwrap();
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
        (hold, case)
    }

    /// The kinds published into one channel, in order.
    fn kinds_for_channel(frames: &Arc<Mutex<Vec<Frame>>>, channel: uuid::Uuid) -> Vec<u16> {
        frames
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|frame| frame.channel == Some(channel))
            .map(|frame| frame.signed.kind.as_u16())
            .collect()
    }

    /// The dead-letter as it is on disk.
    fn parked_ledger(dir: &tempfile::TempDir) -> ParkedLedger {
        ParkedLedger::open(&dir.path().join("parked-alarms.json")).unwrap()
    }

    /// The hold id inside a parked record's payload.
    fn parked_hold_id(record: &ParkedRecord) -> String {
        match serde_json::from_slice::<RuntimeEvent>(&record.payload).unwrap() {
            RuntimeEvent::ResponseHeld { hold_id, .. } => hold_id,
            other => panic!("a parked record that is not a hold: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_permanently_refused_sequence_is_parked_after_the_budget_and_the_record_behind_it_drains()
     {
        // W3-38 itself. The relay answers the idempotent create for case A with "it already
        // exists" and refuses every membership write into it, so no tick can ever finish A's
        // sequence -- and until the budget existed, the hold behind it waited for as long as
        // the operator did.
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let identities = identities();
        let alarm_idx = identities.alarm();
        let store = Arc::new(swarm_runtime::held_action::MemoryHeldActionStore::default());
        let (blocked_hold, blocked_case) =
            route_and_spool_hold(&dir, &spools, &store, alarm_idx, "hunt-blocked");
        let (behind_hold, behind_case) =
            route_and_spool_hold(&dir, &spools, &store, alarm_idx, "hunt-behind");

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
        built.publisher.reply = Some(Arc::new(move |frame: &Frame| {
            match (frame.signed.kind.as_u16(), frame.channel) {
                (9007, Some(channel)) if channel == blocked_case => {
                    Some(Ok(OkOutcome::ChannelAlreadyExists))
                }
                (_, Some(channel)) if channel == blocked_case => {
                    Some(Ok(OkOutcome::NotAChannelMember))
                }
                _ => None,
            }
        }));
        let recorded = Arc::new(Mutex::new(Vec::new()));
        built.publisher.sink = Some(Arc::clone(&recorded));
        let handle = tokio::spawn(run(built));
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
            "the hold behind the refused one never reached the head"
        );

        // The refused sequence is in the dead-letter, named, with the refusal that put it there.
        let parked = parked_ledger(&dir);
        assert_eq!(parked.len(), 1);
        let record = parked.next_due(i64::MAX, 0).unwrap();
        assert_eq!(parked_hold_id(record), blocked_hold.hold_id);
        assert_eq!(
            record.reason,
            ParkReason::refusal_budget_exhausted("not_a_channel_member")
        );
        assert_eq!(record.retries, 0);
        assert_eq!(
            counter(
                &registry,
                r#"perch_bridge_alarm_parked_total{reason="not_a_channel_member"}"#
            ),
            1
        );

        // And the hold behind it published its whole sequence, in order.
        assert_eq!(
            kinds_for_channel(&recorded, behind_case),
            vec![9007, 9000, 9, 46010],
            "the record behind the parked one drains its four channel frames in order"
        );
        assert_eq!(
            kind_count(&recorded, 26006),
            1,
            "exactly one alarm reached the relay: the one that could"
        );
        assert_eq!(
            store.get(&behind_hold.hold_id).unwrap().unwrap().state,
            swarm_runtime::held_action::HoldState::Notified
        );
        assert_eq!(
            store.get(&blocked_hold.hold_id).unwrap().unwrap().state,
            swarm_runtime::held_action::HoldState::Created,
            "parking publishes nothing; the parked hold is exactly as the daemon left it"
        );
    }

    #[tokio::test]
    async fn a_refused_promotion_is_parked_after_the_budget_like_a_hold() {
        // The budget belongs to the spool head, not to the hold path: a promotion whose case
        // channel the relay refuses to admit anybody to blocks the same queue, and it is parked
        // by the same rule -- under the case id it is about.
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
                Record::from_event(&case_promoted("hunt-promoted", case), alarm_idx).unwrap(),
            )
            .unwrap();

        let (metrics, registry) = BridgeMetrics::new();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut built = drainer(
            &dir,
            Arc::clone(&spools),
            Arc::clone(&identities),
            vec!["68".repeat(32)],
            None,
            OkOutcome::Accepted,
            metrics,
            shutdown_rx,
        );
        built.config.lane_channels.clear();
        built.publisher.reply = Some(refuse_channel(
            uuid::Uuid::parse_str(case).unwrap(),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        ));
        let handle = tokio::spawn(run(built));
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
        assert!(settled, "the refused promotion never left the spool head");

        let parked = parked_ledger(&dir);
        assert_eq!(parked.len(), 1);
        let record = parked.next_due(i64::MAX, 0).unwrap();
        assert_eq!(
            record.reason,
            ParkReason::refusal_budget_exhausted("not_a_channel_member")
        );
        assert!(
            matches!(
                serde_json::from_slice::<RuntimeEvent>(&record.payload).unwrap(),
                RuntimeEvent::CasePromoted { case_id, .. } if case_id == case
            ),
            "the parked payload is the promotion, verbatim"
        );
        assert_eq!(
            counter(
                &registry,
                r#"perch_bridge_alarm_parked_total{reason="not_a_channel_member"}"#
            ),
            1
        );
    }

    #[tokio::test]
    async fn transport_errors_never_count_toward_the_budget() {
        // A relay that is down is not a relay that disagrees. Every tick fails at the socket,
        // which says nothing about whether the sequence would be accepted, so the budget must
        // not move and the record must stay where a later tick can publish it.
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let identities = identities();
        let alarm_idx = identities.alarm();
        let store = Arc::new(swarm_runtime::held_action::MemoryHeldActionStore::default());
        let (hold, _case) = route_and_spool_hold(&dir, &spools, &store, alarm_idx, "hunt-offline");

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
        built.publisher.reply = Some(Arc::new(|_frame: &Frame| {
            Some(Err(BridgeError::RelayUnreachable {
                attempt: 1,
                retry_in: Duration::from_millis(1),
            }))
        }));
        let recorded = Arc::new(Mutex::new(Vec::new()));
        built.publisher.sink = Some(Arc::clone(&recorded));
        let handle = tokio::spawn(run(built));
        let attempts = HEAD_REFUSAL_BUDGET as usize + 5;
        let sink = Arc::clone(&recorded);
        let settled =
            wait_for(|| sink.lock().unwrap_or_else(PoisonError::into_inner).len() >= attempts)
                .await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(settled, "the drainer stopped retrying an unreachable relay");

        assert!(
            !dir.path().join("parked-alarms.json").exists(),
            "a relay that is down parks nothing, so the dead-letter is never written"
        );
        assert!(
            !spools
                .lock()
                .unwrap()
                .alarm()
                .peek(usize::MAX)
                .unwrap()
                .is_empty(),
            "the record is still at the head, waiting for the relay to come back"
        );
        assert!(
            !scrape(&registry).contains("perch_bridge_alarm_parked_total{"),
            "nothing was parked, so the counter has no sample at all"
        );
        assert_eq!(
            store.get(&hold.hold_id).unwrap().unwrap().state,
            swarm_runtime::held_action::HoldState::Created
        );
    }

    #[tokio::test]
    async fn a_deferred_alarm_never_counts_toward_the_budget() {
        // The burst window admits nothing, so every tick re-plans the same 26006 and defers it.
        // A deferral is the bridge's own back-pressure, not the relay's answer: it must never
        // spend the budget that exists for a relay which disagrees.
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let identities = identities();
        let alarm_idx = identities.alarm();
        let store = Arc::new(swarm_runtime::held_action::MemoryHeldActionStore::default());
        let (hold, _case) = route_and_spool_hold(&dir, &spools, &store, alarm_idx, "hunt-deferred");

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
        built.publisher.burst = crate::publish::AlarmBurst::new(0);
        let handle = tokio::spawn(run(built));
        let deferrals = u64::from(HEAD_REFUSAL_BUDGET) + 5;
        let counts = Arc::clone(&registry);
        let settled =
            wait_for(|| counter(&counts, "perch_bridge_alarm_deferred_total") >= deferrals).await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(
            settled,
            "the drainer stopped re-planning the deferred alarm"
        );

        assert!(
            !dir.path().join("parked-alarms.json").exists(),
            "a deferral parks nothing"
        );
        assert!(
            !spools
                .lock()
                .unwrap()
                .alarm()
                .peek(usize::MAX)
                .unwrap()
                .is_empty(),
            "the deferred hold keeps its record"
        );
        // Everything before the alarm landed on the first tick and is never republished.
        assert_eq!(
            store.get(&hold.hold_id).unwrap().unwrap().state,
            swarm_runtime::held_action::HoldState::Notified
        );
    }

    /// Refuses every write into `case` except the idempotent create, while `refusing` holds.
    ///
    /// The shape of a relay whose channel state was restored out from under the bridge: it
    /// answers the create "it already exists" and refuses everything that needs the channel to
    /// actually be there.
    fn refuse_channel(case: uuid::Uuid, refusing: Arc<std::sync::atomic::AtomicBool>) -> Reply {
        Arc::new(
            move |frame: &Frame| match (frame.signed.kind.as_u16(), frame.channel) {
                (9007, Some(channel)) if channel == case => {
                    Some(Ok(OkOutcome::ChannelAlreadyExists))
                }
                (_, Some(channel))
                    if channel == case && refusing.load(std::sync::atomic::Ordering::SeqCst) =>
                {
                    Some(Ok(OkOutcome::NotAChannelMember))
                }
                _ => None,
            },
        )
    }

    #[tokio::test]
    async fn a_parked_record_is_retried_on_an_idle_tick_and_removed_when_it_lands() {
        // The dead-letter is a queue, not a grave. Once the relay is repaired the parked hold
        // publishes the steps it still owes -- and only those, because the retry re-plans from
        // the same durable state the head path does.
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let identities = identities();
        let alarm_idx = identities.alarm();
        let store = Arc::new(swarm_runtime::held_action::MemoryHeldActionStore::default());
        let (hold, case) = route_and_spool_hold(&dir, &spools, &store, alarm_idx, "hunt-parked");

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
        let (clock, offset) = offset_clock();
        built.clock = clock;
        let refusing = Arc::new(std::sync::atomic::AtomicBool::new(true));
        built.publisher.reply = Some(refuse_channel(case, Arc::clone(&refusing)));
        let recorded = Arc::new(Mutex::new(Vec::new()));
        built.publisher.sink = Some(Arc::clone(&recorded));
        let handle = tokio::spawn(run(built));

        let parked_path = dir.path().join("parked-alarms.json");
        let banished = wait_for(|| parked_path.exists()).await;
        assert!(
            banished,
            "the permanently refused sequence was never parked"
        );

        // The relay is repaired, and the retry interval passes.
        refusing.store(false, std::sync::atomic::Ordering::SeqCst);
        offset.fetch_add(
            PARKED_RETRY_INTERVAL_MS + 1_000,
            std::sync::atomic::Ordering::SeqCst,
        );
        let counts = Arc::clone(&registry);
        let landed = wait_for(|| {
            counter(
                &counts,
                r#"perch_bridge_alarm_unparked_total{outcome="landed"}"#,
            ) == 1
        })
        .await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(
            landed,
            "the parked record was never retried on an idle tick"
        );

        assert!(
            parked_ledger(&dir).is_empty(),
            "a record that landed leaves the dead-letter"
        );
        assert_eq!(
            store.get(&hold.hold_id).unwrap().unwrap().state,
            swarm_runtime::held_action::HoldState::Notified,
            "the notice the hold was parked owing finally reached the relay"
        );
        let routing = channels::CaseRouting::open(&dir.path().join("case-routing.json")).unwrap();
        assert!(routing.alarm_published_for_hold(&hold.hold_id));
        assert_eq!(
            (
                kind_count(&recorded, 9),
                kind_count(&recorded, 46010),
                kind_count(&recorded, 26006)
            ),
            (1, 1, 1),
            "the retry publishes what was still owed, exactly once each"
        );
    }

    #[tokio::test]
    async fn a_parked_record_is_never_retried_while_the_head_has_work() {
        // The dead-letter must never take a tick from the live spool. Here the head is occupied
        // by a hold whose frames the socket keeps failing, while a parked record has been due
        // the whole time: it must not be touched until the head is empty -- and then it must be,
        // or the first half of this test would pass on a drainer that never retries at all.
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let identities = identities();
        let alarm_idx = identities.alarm();
        let store = Arc::new(swarm_runtime::held_action::MemoryHeldActionStore::default());
        let (_blocked_hold, blocked_case) =
            route_and_spool_hold(&dir, &spools, &store, alarm_idx, "hunt-blocked");
        let (queued_hold, queued_case) =
            route_and_spool_hold(&dir, &spools, &store, alarm_idx, "hunt-queued");

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
        let (clock, offset) = offset_clock();
        built.clock = clock;
        let unreachable = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let socket = Arc::clone(&unreachable);
        built.publisher.reply = Some(Arc::new(move |frame: &Frame| {
            match (frame.signed.kind.as_u16(), frame.channel) {
                (9007, Some(channel)) if channel == blocked_case => {
                    Some(Ok(OkOutcome::ChannelAlreadyExists))
                }
                (_, Some(channel)) if channel == blocked_case => {
                    Some(Ok(OkOutcome::NotAChannelMember))
                }
                (_, Some(channel))
                    if channel == queued_case
                        && socket.load(std::sync::atomic::Ordering::SeqCst) =>
                {
                    Some(Err(BridgeError::RelayUnreachable {
                        attempt: 1,
                        retry_in: Duration::from_millis(1),
                    }))
                }
                _ => None,
            }
        }));
        let recorded = Arc::new(Mutex::new(Vec::new()));
        built.publisher.sink = Some(Arc::clone(&recorded));
        let handle = tokio::spawn(run(built));

        let parked_path = dir.path().join("parked-alarms.json");
        let banished = wait_for(|| parked_path.exists()).await;
        assert!(banished, "the refused sequence was never parked");
        // Due from now on, and the head is busy for as long as the socket keeps failing.
        offset.fetch_add(
            PARKED_RETRY_INTERVAL_MS + 1_000,
            std::sync::atomic::Ordering::SeqCst,
        );
        let attempts = Arc::clone(&recorded);
        let busy = wait_for(|| kinds_for_channel(&attempts, queued_case).len() >= 20).await;
        assert!(busy, "the head record never got its twenty attempts");

        let parked = parked_ledger(&dir);
        assert_eq!(parked.len(), 1);
        assert_eq!(
            parked.next_due(i64::MAX, 0).unwrap().retries,
            0,
            "a due parked record is not touched on a tick that had head work"
        );
        assert!(
            !scrape(&registry).contains("perch_bridge_alarm_unparked_total{"),
            "nothing left the dead-letter while the head had work"
        );

        // The socket recovers: the head empties, and the first idle tick serves the dead-letter.
        unreachable.store(false, std::sync::atomic::Ordering::SeqCst);
        let served = wait_for(|| {
            parked_ledger(&dir)
                .next_due(i64::MAX, 0)
                .is_some_and(|record| record.retries >= 1)
        })
        .await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(
            served,
            "the parked record was never retried once the head emptied"
        );
        assert_eq!(
            kinds_for_channel(&recorded, queued_case)
                .into_iter()
                .rev()
                .take(4)
                .rev()
                .collect::<Vec<u16>>(),
            vec![9007, 9000, 9, 46010],
            "the head record published its own sequence once the socket came back"
        );
        assert_eq!(
            store.get(&queued_hold.hold_id).unwrap().unwrap().state,
            swarm_runtime::held_action::HoldState::Notified
        );
    }

    #[tokio::test]
    async fn a_parked_hold_whose_plan_is_empty_is_discarded() {
        // The daemon's TTL sweep expired the hold while it sat in the dead-letter. Its retry
        // plans nothing -- there is no card to publish for a hold the case has already lost --
        // so the record is discarded rather than retried until the end of time.
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let identities = identities();
        let alarm_idx = identities.alarm();
        let store = Arc::new(swarm_runtime::held_action::MemoryHeldActionStore::default());
        let (hold, case) = route_and_spool_hold(&dir, &spools, &store, alarm_idx, "hunt-expired");

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
        let (clock, offset) = offset_clock();
        built.clock = clock;
        built.publisher.reply = Some(refuse_channel(
            case,
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        ));
        let recorded = Arc::new(Mutex::new(Vec::new()));
        built.publisher.sink = Some(Arc::clone(&recorded));
        let handle = tokio::spawn(run(built));

        let banished = wait_for(|| dir.path().join("parked-alarms.json").exists()).await;
        assert!(banished, "the refused sequence was never parked");

        store.expire_due(hold.expires_at_ms + 1).unwrap();
        offset.fetch_add(
            PARKED_RETRY_INTERVAL_MS + 1_000,
            std::sync::atomic::Ordering::SeqCst,
        );
        let counts = Arc::clone(&registry);
        let dropped = wait_for(|| {
            counter(
                &counts,
                r#"perch_bridge_alarm_unparked_total{outcome="discarded"}"#,
            ) == 1
        })
        .await;
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap().unwrap();
        assert!(
            dropped,
            "the expired hold was never discarded from the dead-letter"
        );

        assert!(parked_ledger(&dir).is_empty());
        assert_eq!(
            kind_count(&recorded, 9),
            0,
            "a hold the case has already lost never gets a card"
        );
        assert_eq!(
            store.get(&hold.hold_id).unwrap().unwrap().state,
            swarm_runtime::held_action::HoldState::Expired
        );
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
