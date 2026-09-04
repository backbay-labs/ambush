//! The hold path: `RuntimeEvent::ResponseHeld` -> case channel -> `swarm:hold:v1` card ->
//! `kind:46010` notice -> `kind:26006` alarm, and the two in-process callbacks that tell the
//! daemon what the relay accepted.
//!
//! Runs in the PUBLISH task, never in [`crate::receive`]. The receive loop has 281 ms of head
//! room against a lagged broadcast at the measured hot-path rate; a store read there would spend
//! it.
//!
//! # What a `ResponseHeld` becomes
//!
//! A `created` hold on an unrouted hunt plans five steps, in this order:
//!
//! ```text
//! 9007 create the case channel   -> the bridge is bootstrapped as its owner
//! 9000 put-user, one per Approve principal
//! 9    swarm:hold:v1 card        -> the DURABLE record, in the case channel
//! 46010 hold notice              -> the queue row, `card` = the card's event id
//! 26006 hold alarm               -> GLOBAL, ephemeral, bypasses the pacer
//! ```
//!
//! Every TERMINAL transition (`granted`, `refused`, `expired`, `executed`, `failed`) plans
//! exactly ONE step: a second `swarm:hold:v1` card, published as a NIP-10 reply to the open one.
//! W3-26 publishes a `ResponseHeld` on creation and on every terminal transition, so the bridge
//! publishes the terminal card too and a case timeline reads top to bottom without a join.
//!
//! `notified`, `armed` and `deciding` publish NOTHING. `notified` is the bridge's own callback,
//! not a fact the daemon asks it to republish; `armed` is client-reported; `deciding` is a
//! compare-and-set the console already knows the outcome of.
//!
//! # Exactly one card per transition, across restarts and redeliveries
//!
//! Two durable facts answer "has this already been published", and neither is a heuristic:
//!
//! - The STORE record. `mark_notified` is the bridge's own callback, so `notice_event_id` is
//!   `Some` if and only if the relay accepted a `46010` for this hold. A replayed `created`
//!   event therefore plans no notice and no alarm.
//! - The ROUTING LEDGER ([`CaseRouting::open_card_for_hold`],
//!   [`CaseRouting::terminal_card_for_hold`]). The store has no field for "the card was
//!   accepted" and the trait has no method that could set one, so the bridge keeps its own
//!   write-once record of the two card ids beside the spool.
//!
//! Neither is an optimisation. A `kind:9` card re-signed on a later tick carries a different
//! `created_at`, which is inside the Nostr signature, so its event id differs and the relay's
//! `ON CONFLICT DO NOTHING` insert does NOT deduplicate it. Without the ledger a crash between
//! the accepted card and the accepted notice puts the same hold in the case twice.

use std::sync::Arc;

use swarm_runtime::held_action::{HeldAction, HeldActionStore, HoldState};
use swarm_runtime::runtime_events::RuntimeEvent;
use uuid::Uuid;

use crate::cards::{CardBody, SeqChain, hold_card, hold_human_line, hold_notice_tags};
use crate::channels::{CasePromotionTrigger, CaseRouting, HoldId, PublishStep};
use crate::error::BridgeError;
use crate::identity::Identity;
use crate::metrics::BridgeMetrics;
use crate::spool::{IssuerIdx, Seq};

/// What one `ResponseHeld` becomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldPlan {
    /// The steps to publish, in order. EMPTY is a legitimate answer: an already-published
    /// sequence, a state the daemon does not ask the bridge to republish, or a terminal card
    /// that is already on the relay.
    Steps(Vec<PublishStep>),
    /// Nothing is built, and the reason names the repair.
    Undeliverable {
        /// The hold that reaches nobody.
        hold_id: String,
        /// One of `no_operator_pubkey`, `no_hold_store`, `hold_not_found`, `no_case_channel`.
        reason: &'static str,
    },
}

/// A signed-ready body for one hold step: the content, the tags and the Nostr kind.
///
/// The three hold steps are the only ones that carry a BODY, which is why
/// [`crate::channels::step_to_event`] refuses them: the card is a sealed spine envelope over the
/// store record, the notice repeats that card's human line, and the alarm is a `26006` frame.
#[derive(Debug, Clone)]
pub struct HoldFrameBody {
    /// The Nostr kind: `9`, `46010` or `26006`.
    pub kind: u16,
    /// The event content.
    pub content: String,
    /// The tags, already through `TagSet::assert_publishable`.
    pub tags: Vec<Vec<String>>,
    /// The channel the `h` tag names, or `None` for the global alarm.
    pub channel: Option<Uuid>,
}

/// Plans the hold sequence, builds its bodies, and acknowledges what the relay accepted.
pub struct HoldPublisher {
    routing: CaseRouting,
    store: Option<Arc<dyn HeldActionStore>>,
    approve_pubkeys: Vec<String>,
    case_ttl_seconds: i32,
    issuer: Identity,
    issuer_idx: IssuerIdx,
    chain: SeqChain,
    alarm_seq: u64,
    metrics: BridgeMetrics,
}

impl HoldPublisher {
    /// Bundles the routing sidecar, the store handle, the Approve set and the alarm identity.
    ///
    /// `routing` is OWNED here because the sidecar has exactly one writer: the hold path records
    /// card ids in it and the promotion path records case channels, and two owners of one file
    /// is how a routing entry gets lost between two `write_atomic` calls. The promotion path
    /// reaches it through [`HoldPublisher::routing_mut`].
    pub fn new(
        routing: CaseRouting,
        store: Option<Arc<dyn HeldActionStore>>,
        approve_pubkeys: Vec<String>,
        case_ttl_seconds: i32,
        issuer: Identity,
        issuer_idx: IssuerIdx,
        metrics: BridgeMetrics,
    ) -> Self {
        Self {
            routing,
            store,
            approve_pubkeys,
            case_ttl_seconds,
            issuer,
            issuer_idx,
            chain: SeqChain::default(),
            alarm_seq: 0,
            metrics,
        }
    }

    /// The routing sidecar, for the case-promotion path that shares it.
    pub fn routing_mut(&mut self) -> &mut CaseRouting {
        &mut self.routing
    }

    /// The Approve set: the membership of every case channel and the `p` set of every notice
    /// and alarm.
    pub fn approve_pubkeys(&self) -> &[String] {
        &self.approve_pubkeys
    }

    /// The identity every hold step is signed with.
    pub fn issuer(&self) -> &Identity {
        &self.issuer
    }

    /// The record behind a `ResponseHeld`, read from the daemon's store.
    ///
    /// # Errors
    ///
    /// [`BridgeError::InvalidConfig`] when the store read itself failed. A missing record is
    /// `Ok(None)`, which [`HoldPublisher::plan`] turns into `hold_not_found`.
    pub fn record(&self, hold_id: &str) -> Result<Option<HeldAction>, BridgeError> {
        let Some(store) = &self.store else {
            return Ok(None);
        };
        store
            .get(hold_id)
            .map_err(|error| BridgeError::InvalidConfig {
                reason: format!("hold store read failed: {error}"),
            })
    }

    /// Plans the sequence for one event.
    ///
    /// Only `ResponseHeld` is planned; any other variant returns an empty step list, so the
    /// caller can route every alarm-class record through here without a second match.
    ///
    /// # Errors
    ///
    /// [`BridgeError::MalformedHoldId`] when the event carries an id of the wrong shape;
    /// [`BridgeError::CaseChannelConflict`] or [`BridgeError::SpoolIo`] from the routing table;
    /// [`BridgeError::InvalidConfig`] when the store read failed.
    pub fn plan(&mut self, event: &RuntimeEvent) -> Result<HoldPlan, BridgeError> {
        let RuntimeEvent::ResponseHeld {
            hold_id,
            hunt_id,
            state,
            ..
        } = event
        else {
            return Ok(HoldPlan::Steps(Vec::new()));
        };
        let hold_id = HoldId::parse(hold_id)?;
        let id = hold_id.as_str().to_string();

        if self.store.is_none() {
            return Ok(self.undeliverable(id, "no_hold_store"));
        }
        let Some(record) = self.record(&id)? else {
            // The event announced a hold the store does not have. That is a real state after an
            // in-memory store outlives a restart, and the honest answer is a counter and a log
            // rather than a card built from the event's seven fields.
            return Ok(self.undeliverable(id, "hold_not_found"));
        };

        // ONE terminal card per hold, whatever order the events arrive in. A `created` event
        // that lands after the terminal card -- a spool replay, a redelivery -- must not reopen
        // a hold the case timeline has already closed.
        if self.routing.terminal_card_for_hold(&id).is_some() {
            return Ok(HoldPlan::Steps(Vec::new()));
        }

        match state {
            HoldState::Created => self.plan_open(&hold_id, hunt_id, &record),
            // The bridge's own callback, a client report, and a compare-and-set the console
            // already holds the outcome of. None is a fact the daemon asks the bridge to
            // publish.
            HoldState::Notified | HoldState::Armed | HoldState::Deciding => {
                Ok(HoldPlan::Steps(Vec::new()))
            }
            HoldState::Granted
            | HoldState::Refused
            | HoldState::Expired
            | HoldState::Executed
            | HoldState::Failed => self.plan_terminal(&hold_id, hunt_id, &record),
        }
    }

    /// The open sequence: case channel, membership, card, notice, alarm.
    fn plan_open(
        &mut self,
        hold_id: &HoldId,
        hunt_id: &str,
        record: &HeldAction,
    ) -> Result<HoldPlan, BridgeError> {
        let id = hold_id.as_str().to_string();
        if record.is_terminal() {
            // The hold reached a terminal state before its `created` event drained -- an expiry
            // sweep on a stalled spool, say. Opening it now would put a card in the case that is
            // already false; the terminal event behind this one carries the truth.
            return Ok(HoldPlan::Steps(Vec::new()));
        }
        if self.approve_pubkeys.is_empty() {
            // F18. A `46010` with no `p` tag is stored, acknowledged `OK true`, and delivered to
            // NOBODY: `query_needs_action` INNER JOINs `event_mentions`. Refusing is the honest
            // failure, and the log names the config key that repairs it.
            tracing::error!(
                module = module_path!(),
                hold_id = %id,
                "no operator principal carries a nostr_pubkey (operator.auth principals with \
                 OperatorScope::Approve); refusing to publish a 46010 nobody is p-tagged on"
            );
            return Ok(self.undeliverable(id, "no_operator_pubkey"));
        }

        let trigger = CasePromotionTrigger::Held {
            hunt_id: hunt_id.to_string(),
            hold_id: id.clone(),
        };
        let (case, mut steps) = self.routing.ensure_case_channel(
            &trigger,
            &self.approve_pubkeys,
            self.case_ttl_seconds,
        )?;

        // A hunt already routed returns NO steps. That is right for a second hold on the same
        // hunt and wrong twice over for a first hold whose sequence was interrupted:
        //
        // - the routing entry is written BEFORE anything is published, so a refused `9007`
        //   leaves a routed hunt and no channel, and the very next step would put a card into a
        //   channel that does not exist;
        // - a `9000` that failed after its `9007` succeeded leaves the notice landing in a
        //   channel the operator is not a member of and cannot read.
        //
        // Both are answered by re-planning from the accepted-ids ledger rather than from the
        // routing entry. `9007` and `9000` are both idempotent, so re-asserting them before the
        // first notice costs one frame each and closes both holes.
        if steps.is_empty() && record.notice_event_id.is_none() {
            if !self.routing.channel_is_created(case) {
                steps.push(PublishStep::CreateChannel {
                    channel: case,
                    name: crate::channels::case_channel_name(case),
                    visibility: "private",
                    ttl_seconds: Some(self.case_ttl_seconds),
                });
            }
            steps.extend(
                self.approve_pubkeys
                    .iter()
                    .map(|pubkey| PublishStep::AddMember {
                        channel: case,
                        pubkey: pubkey.clone(),
                    }),
            );
        }

        let open_card = self.routing.open_card_for_hold(&id).map(str::to_string);
        if open_card.is_none() {
            steps.push(PublishStep::PublishHoldCard {
                channel: case,
                hold_id: hold_id.clone(),
                reply_to: None,
            });
        }
        // `notice_event_id` is set by this crate's own `mark_notified` callback, so it is `Some`
        // if and only if the relay accepted a 46010 for this hold. It survives every later state
        // transition, which `state == Created` does not.
        if record.notice_event_id.is_none() {
            steps.push(PublishStep::PublishHoldNotice {
                channel: case,
                hold_id: hold_id.clone(),
                card_event_id: open_card,
            });
            steps.push(PublishStep::PublishAlarm {
                hold_id: hold_id.clone(),
            });
        }
        Ok(HoldPlan::Steps(steps))
    }

    /// The terminal card: one `swarm:hold:v1` reply to the open card, and nothing else.
    fn plan_terminal(
        &mut self,
        hold_id: &HoldId,
        hunt_id: &str,
        record: &HeldAction,
    ) -> Result<HoldPlan, BridgeError> {
        let id = hold_id.as_str().to_string();
        let case = record
            .case_channel
            .as_deref()
            .and_then(|channel| Uuid::parse_str(channel).ok())
            .or_else(|| self.routing.case_for_hunt(hunt_id));
        let Some(case) = case else {
            // The hold ended before its case channel existed -- an expiry on a daemon whose
            // relay was unreachable for the whole TTL. There is nowhere to publish the terminal
            // card, and minting a channel for a closed hold would create an empty case.
            return Ok(self.undeliverable(id, "no_case_channel"));
        };
        Ok(HoldPlan::Steps(vec![PublishStep::PublishHoldCard {
            channel: case,
            hold_id: hold_id.clone(),
            // Both sources are this crate's own callbacks and agree; the ledger is preferred
            // because it is written first.
            reply_to: self
                .routing
                .open_card_for_hold(&id)
                .map(str::to_string)
                .or_else(|| record.card_event_id.clone()),
        }]))
    }

    /// Counts a refusal and returns it.
    fn undeliverable(&self, hold_id: String, reason: &'static str) -> HoldPlan {
        self.metrics.hold_undeliverable(reason);
        HoldPlan::Undeliverable { hold_id, reason }
    }

    /// Builds the body of one hold step, or `None` for a step that carries only tags.
    ///
    /// `seq` is the spool record's, so the envelope chain's sequence is the same number the
    /// spool cursor commits and a gap in one is a gap in the other.
    ///
    /// # Errors
    ///
    /// [`BridgeError::InvalidConfig`] when the store no longer has the record the step names;
    /// [`BridgeError::Encode`] when the envelope, the content grammar or a tag set is refused.
    pub fn build(
        &mut self,
        step: &PublishStep,
        seq: Seq,
        now_ms: i64,
    ) -> Result<Option<HoldFrameBody>, BridgeError> {
        match step {
            PublishStep::PublishHoldCard {
                channel,
                hold_id,
                reply_to,
            } => {
                let hold = self.require_record(hold_id.as_str())?;
                let body = self.card_body(&hold, *channel, reply_to.as_deref(), seq, now_ms)?;
                Ok(Some(HoldFrameBody {
                    kind: swarm_perch_wire::KIND_CARD,
                    content: body.content,
                    tags: body.tags,
                    channel: Some(*channel),
                }))
            }
            PublishStep::PublishHoldNotice {
                channel,
                hold_id,
                card_event_id,
            } => {
                let hold = self.require_record(hold_id.as_str())?;
                // The notice's line is the CARD's line, verbatim, derived from the record
                // rather than copied from a card object -- so neither side holds the other's
                // string and the notice does not advance the issuer's envelope chain for a
                // card nobody published.
                let content = hold_human_line(&hold, *channel)?;
                // The `card` tag is the id the CARD STEP returned, so it is not knowable when
                // the sequence is planned -- only after that step's OK, which is when
                // `record_open_card` wrote it. The planned value is the fallback for a resumed
                // sequence, where the card landed on an earlier tick.
                let card_event_id = self
                    .routing
                    .open_card_for_hold(hold_id.as_str())
                    .map(str::to_string)
                    .or_else(|| card_event_id.clone());
                let tags = hold_notice_tags(
                    *channel,
                    &self.approve_pubkeys,
                    hold_id.as_str(),
                    card_event_id.as_deref(),
                );
                tags.assert_publishable(swarm_perch_wire::KIND_HOLD_NOTICE)
                    .map_err(|error| BridgeError::Encode(error.to_string()))?;
                Ok(Some(HoldFrameBody {
                    kind: swarm_perch_wire::KIND_HOLD_NOTICE,
                    content,
                    tags: tags.to_tags(),
                    channel: Some(*channel),
                }))
            }
            PublishStep::PublishAlarm { hold_id } => {
                let hold = self.require_record(hold_id.as_str())?;
                let Some(case) = hold
                    .case_channel
                    .as_deref()
                    .and_then(|channel| Uuid::parse_str(channel).ok())
                    .or_else(|| self.routing.case_for_hunt(&hold.action_request.hunt_id.0))
                else {
                    return Err(BridgeError::InvalidConfig {
                        reason: format!(
                            "hold {} has no case channel; the alarm would name none",
                            hold_id.as_str()
                        ),
                    });
                };
                self.alarm_seq = self.alarm_seq.saturating_add(1);
                let frame = crate::cards::hold_alarm_frame(
                    &hold,
                    case,
                    &self.spine_issuer(),
                    self.alarm_seq,
                    now_ms,
                )?;
                let tags = crate::cards::hold_alarm_tags(&self.approve_pubkeys);
                tags.assert_publishable(swarm_perch_wire::KIND_HOLD_ALARM)
                    .map_err(|error| BridgeError::Encode(error.to_string()))?;
                Ok(Some(HoldFrameBody {
                    kind: swarm_perch_wire::KIND_HOLD_ALARM,
                    content: serde_json::to_string(&frame)
                        .map_err(|error| BridgeError::Encode(error.to_string()))?,
                    tags: tags.to_tags(),
                    channel: None,
                }))
            }
            PublishStep::CreateChannel { .. } | PublishStep::AddMember { .. } => Ok(None),
        }
    }

    /// The card body for one hold, with the issuer's envelope chain advanced.
    fn card_body(
        &mut self,
        hold: &HeldAction,
        channel: Uuid,
        reply_to: Option<&str>,
        seq: Seq,
        now_ms: i64,
    ) -> Result<CardBody, BridgeError> {
        let mut chain = self.chain.clone();
        let body = hold_card(
            hold,
            channel,
            None,
            reply_to,
            &self.issuer,
            seq,
            &mut chain,
            (self.issuer_idx, seq),
            now_ms,
        )?;
        self.chain = chain;
        Ok(body)
    }

    /// The bridge's spine identity, as the frame header renders it.
    fn spine_issuer(&self) -> String {
        format!("swarm:ed25519:{}", self.issuer.keys.public_key().to_hex())
    }

    /// The record a step names, or a typed refusal.
    fn require_record(&self, hold_id: &str) -> Result<HeldAction, BridgeError> {
        self.record(hold_id)?
            .ok_or_else(|| BridgeError::InvalidConfig {
                reason: format!("hold {hold_id} is no longer in the store"),
            })
    }

    /// Records what the relay accepted, after each successful step.
    ///
    /// A `duplicate: channel already exists` OK counts as acceptance (F14).
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the routing sidecar cannot be written. The caller MUST
    /// treat that as a failed step: an unrecorded card id is exactly the state that republishes
    /// the card on the next tick, and a republished card is a duplicate the relay cannot
    /// deduplicate because its `created_at` -- and therefore its event id -- has changed.
    pub fn on_ok(
        &mut self,
        step: &PublishStep,
        event_id: &str,
        now_ms: i64,
    ) -> Result<(), BridgeError> {
        match step {
            PublishStep::CreateChannel { channel, .. } => {
                // Recorded FIRST, and its failure aborts the sequence: an unrecorded create
                // makes the next tick re-plan a `9007` for a channel that already exists, which
                // is harmless, while an unrecorded card makes it re-plan a card that is not.
                self.routing.record_channel_created(*channel)?;
                self.mark_case_channel(*channel);
                Ok(())
            }
            PublishStep::PublishHoldCard {
                hold_id, reply_to, ..
            } => {
                if reply_to.is_none() {
                    self.routing.record_open_card(hold_id.as_str(), event_id)
                } else {
                    self.routing
                        .record_terminal_card(hold_id.as_str(), event_id)
                }
            }
            PublishStep::PublishHoldNotice {
                hold_id,
                card_event_id,
                ..
            } => {
                let card_event_id = self
                    .routing
                    .open_card_for_hold(hold_id.as_str())
                    .map(str::to_string)
                    .or_else(|| card_event_id.clone());
                if let Some(store) = &self.store
                    && let Err(error) = store.mark_notified(
                        hold_id.as_str(),
                        now_ms,
                        event_id,
                        card_event_id.as_deref(),
                    )
                {
                    // Informational, and only informational: `notified` gates nothing in the
                    // decide route. The relay has the notice, so the operator has the row; the
                    // daemon record is merely behind, and a retry would republish a notice the
                    // relay already stored.
                    tracing::error!(
                        module = module_path!(),
                        hold_id = %hold_id.as_str(),
                        reason = %error,
                        "the hold notice was accepted but the daemon record could not be \
                         updated; the record is behind the relay"
                    );
                }
                Ok(())
            }
            PublishStep::AddMember { .. } | PublishStep::PublishAlarm { .. } => Ok(()),
        }
    }

    /// Tells every open hold routed to `channel` which case channel it landed in.
    ///
    /// The routing map is keyed on `hunt_id`, so the holds are found through the store rather
    /// than through the map. Informational: a hold is decidable without a case channel, but leg
    /// 1 of the operator's write has nowhere to be published until it exists.
    fn mark_case_channel(&self, channel: Uuid) {
        let Some(store) = &self.store else {
            return;
        };
        let holds = match store.list(false, usize::MAX) {
            Ok(holds) => holds,
            Err(error) => {
                tracing::error!(
                    module = module_path!(),
                    reason = %error,
                    "the hold store could not be listed; open holds will not learn their case \
                     channel"
                );
                return;
            }
        };
        let channel_text = channel.to_string();
        for hold in holds.iter().filter(|hold| {
            self.routing.case_for_hunt(&hold.action_request.hunt_id.0) == Some(channel)
        }) {
            if let Err(error) = store.mark_case_channel(&hold.hold_id, &channel_text) {
                tracing::error!(
                    module = module_path!(),
                    hold_id = %hold.hold_id,
                    reason = %error,
                    "the case channel could not be recorded on the hold"
                );
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use swarm_core::config::SecretString;
    use swarm_core::types::{AgentId, ResponseAction};
    use swarm_runtime::held_action::{HoldState, MemoryHeldActionStore};

    use crate::identity::IdentityTable;

    fn identity() -> (Identity, IssuerIdx) {
        let table = IdentityTable::build(
            &SecretString::new("11".repeat(32)),
            "c",
            &[],
            &AgentId("swarm:ed25519:".to_string() + &"ab".repeat(32)),
            None,
        )
        .unwrap();
        let idx = table.alarm();
        (table.get(idx).unwrap().clone(), idx)
    }

    fn held_event(hold: &HeldAction, state: HoldState) -> RuntimeEvent {
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

    fn fixture() -> HeldAction {
        swarm_runtime::held_action_fixtures::fixture_hold(
            ResponseAction::IsolateHost {
                host_id: "host-ops-1".into(),
            },
            1_773_738_882_600,
        )
    }

    struct Harness {
        publisher: HoldPublisher,
        store: Arc<MemoryHeldActionStore>,
        _dir: tempfile::TempDir,
    }

    fn harness(operators: Vec<String>, with_store: bool) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let routing = CaseRouting::open(&dir.path().join("routing.json")).unwrap();
        let store = Arc::new(MemoryHeldActionStore::default());
        let handle: Option<Arc<dyn HeldActionStore>> =
            with_store.then(|| Arc::clone(&store) as Arc<dyn HeldActionStore>);
        let (issuer, idx) = identity();
        Harness {
            publisher: HoldPublisher::new(
                routing,
                handle,
                operators,
                2_592_000,
                issuer,
                idx,
                BridgeMetrics::for_test(),
            ),
            store,
            _dir: dir,
        }
    }

    fn steps(plan: HoldPlan) -> Vec<PublishStep> {
        match plan {
            HoldPlan::Steps(steps) => steps,
            HoldPlan::Undeliverable { hold_id, reason } => {
                panic!("undeliverable {hold_id}: {reason}")
            }
        }
    }

    fn labels(steps: &[PublishStep]) -> Vec<&'static str> {
        steps.iter().map(PublishStep::label).collect()
    }

    #[test]
    fn a_created_hold_plans_the_five_step_sequence_in_order() {
        let mut h = harness(vec!["68".repeat(32)], true);
        let hold = fixture();
        h.store.create(hold.clone()).unwrap();
        let plan = steps(
            h.publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
        );
        assert_eq!(
            labels(&plan),
            [
                "create_channel",
                "add_member",
                "publish_hold_card",
                "publish_hold_notice",
                "publish_alarm"
            ]
        );
        let PublishStep::CreateChannel { channel, .. } = &plan[0] else {
            unreachable!()
        };
        let channel = *channel;

        // The 9007 OK reports the channel back to the daemon.
        h.publisher.on_ok(&plan[0], &"01".repeat(32), 1).unwrap();
        assert_eq!(
            h.store
                .get(&hold.hold_id)
                .unwrap()
                .unwrap()
                .case_channel
                .as_deref(),
            Some(channel.to_string().as_str())
        );
        // The card OK goes to the bridge's own ledger, which the store has no field for.
        h.publisher.on_ok(&plan[2], &"02".repeat(32), 2).unwrap();
        assert_eq!(
            h.publisher.routing_mut().open_card_for_hold(&hold.hold_id),
            Some("02".repeat(32).as_str())
        );
        // The 46010 OK reports `notified`.
        let PublishStep::PublishHoldNotice { .. } = &plan[3] else {
            unreachable!()
        };
        h.publisher.on_ok(&plan[3], &"03".repeat(32), 3).unwrap();
        let after = h.store.get(&hold.hold_id).unwrap().unwrap();
        assert_eq!(after.state, HoldState::Notified);
        assert_eq!(
            after.notice_event_id.as_deref(),
            Some("03".repeat(32).as_str())
        );
        assert_eq!(after.notified_at_ms, Some(3));
    }

    #[test]
    fn no_approve_pubkey_means_undeliverable_and_nothing_is_built() {
        let mut h = harness(vec![], true);
        let hold = fixture();
        h.store.create(hold.clone()).unwrap();
        assert!(matches!(
            h.publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
            HoldPlan::Undeliverable {
                reason: "no_operator_pubkey",
                ..
            }
        ));
        // And nothing was routed: a case channel with no operator in it is not progress.
        assert_eq!(
            h.publisher
                .routing_mut()
                .case_for_hunt(&hold.action_request.hunt_id.0),
            None
        );
    }

    #[test]
    fn a_daemon_with_no_hold_store_and_a_hold_the_store_lost_are_named_apart() {
        let hold = fixture();
        let mut without = harness(vec!["68".repeat(32)], false);
        assert!(matches!(
            without
                .publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
            HoldPlan::Undeliverable {
                reason: "no_hold_store",
                ..
            }
        ));
        let mut lost = harness(vec!["68".repeat(32)], true);
        assert!(matches!(
            lost.publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
            HoldPlan::Undeliverable {
                reason: "hold_not_found",
                ..
            }
        ));
    }

    #[test]
    fn a_terminal_state_plans_exactly_one_reply_card() {
        let mut h = harness(vec!["68".repeat(32)], true);
        let mut hold = fixture();
        hold.state = HoldState::Refused;
        hold.card_event_id = Some("03".repeat(32));
        hold.case_channel = Some(uuid::Uuid::new_v4().to_string());
        h.store.create(hold.clone()).unwrap();
        let plan = steps(
            h.publisher
                .plan(&held_event(&hold, HoldState::Refused))
                .unwrap(),
        );
        assert_eq!(plan.len(), 1);
        assert!(
            matches!(
                &plan[0],
                PublishStep::PublishHoldCard { reply_to: Some(id), .. } if id == &"03".repeat(32)
            ),
            "{:?}",
            plan[0]
        );
    }

    #[test]
    fn every_terminal_transition_produces_exactly_one_terminal_card() {
        // The property, over all five terminal states and over a redelivery of each: the plan
        // is one card the first time and NOTHING every time after, because the accepted event
        // id is on disk.
        for state in [
            HoldState::Granted,
            HoldState::Refused,
            HoldState::Expired,
            HoldState::Executed,
            HoldState::Failed,
        ] {
            let mut h = harness(vec!["68".repeat(32)], true);
            let mut hold = fixture();
            hold.hold_id = swarm_runtime::held_action::mint_hold_id();
            h.store.create(hold.clone()).unwrap();

            // Open the hold for real, so the terminal card has an open card to reply to.
            let open = steps(
                h.publisher
                    .plan(&held_event(&hold, HoldState::Created))
                    .unwrap(),
            );
            for (index, step) in open.iter().enumerate() {
                h.publisher
                    .on_ok(step, &format!("{:02x}", index).repeat(32), 1)
                    .unwrap();
            }
            let open_card_id = h
                .publisher
                .routing_mut()
                .open_card_for_hold(&hold.hold_id)
                .unwrap()
                .to_string();

            let mut terminal = h.store.get(&hold.hold_id).unwrap().unwrap();
            terminal.state = state;
            let event = held_event(&terminal, state);

            let first = steps(h.publisher.plan(&event).unwrap());
            assert_eq!(labels(&first), ["publish_hold_card"], "{state:?}");
            assert!(
                matches!(
                    &first[0],
                    PublishStep::PublishHoldCard { reply_to: Some(id), .. } if *id == open_card_id
                ),
                "{state:?} {:?}",
                first[0]
            );
            h.publisher.on_ok(&first[0], &"ff".repeat(32), 2).unwrap();

            // Redelivery of the same terminal event: nothing.
            assert_eq!(
                steps(h.publisher.plan(&event).unwrap()),
                Vec::new(),
                "{state:?} planned a second terminal card"
            );
            // A `created` event arriving after the close does not reopen it either.
            assert_eq!(
                steps(
                    h.publisher
                        .plan(&held_event(&hold, HoldState::Created))
                        .unwrap()
                ),
                Vec::new(),
                "{state:?} reopened after its terminal card"
            );
            // And a DIFFERENT terminal state on the same hold is still refused: one card, ever.
            assert_eq!(
                steps(
                    h.publisher
                        .plan(&held_event(&terminal, HoldState::Failed))
                        .unwrap()
                ),
                Vec::new(),
                "{state:?} planned a second terminal card under another state"
            );
        }
    }

    #[test]
    fn a_replayed_created_event_republishes_neither_the_card_nor_the_notice() {
        // The restart case: the spool replays the whole `created` record. Every step whose OK
        // the bridge already recorded is skipped, so the case timeline carries one card and the
        // operator's queue one row.
        let mut h = harness(vec!["68".repeat(32)], true);
        let hold = fixture();
        h.store.create(hold.clone()).unwrap();
        let first = steps(
            h.publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
        );
        for (index, step) in first.iter().enumerate() {
            h.publisher
                .on_ok(step, &format!("{:02x}", index + 1).repeat(32), 1)
                .unwrap();
        }
        let replay = steps(
            h.publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
        );
        assert!(
            replay.is_empty(),
            "a fully published sequence replans nothing, got {:?}",
            labels(&replay)
        );
    }

    #[test]
    fn a_crash_between_the_card_and_the_notice_resumes_at_the_notice() {
        // The window the ledger exists for. The card was accepted; the process died before the
        // 46010. The store still says `created`, so without the ledger the replay would
        // republish the card under a fresh `created_at` -- a new event id, which the relay's
        // ON CONFLICT insert does not deduplicate.
        let mut h = harness(vec!["68".repeat(32)], true);
        let hold = fixture();
        h.store.create(hold.clone()).unwrap();
        let first = steps(
            h.publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
        );
        h.publisher.on_ok(&first[0], &"01".repeat(32), 1).unwrap();
        h.publisher.on_ok(&first[1], &"02".repeat(32), 1).unwrap();
        h.publisher.on_ok(&first[2], &"0a".repeat(32), 1).unwrap();
        assert_eq!(
            h.store.get(&hold.hold_id).unwrap().unwrap().state,
            HoldState::Created,
            "the notice never landed, so the record is still created"
        );

        let resumed = steps(
            h.publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
        );
        // The card is NOT replanned -- that is what the ledger buys. Membership is re-asserted
        // because the notice has still not landed and `9000` is idempotent; see `plan_open`.
        assert_eq!(
            labels(&resumed),
            ["add_member", "publish_hold_notice", "publish_alarm"]
        );
        assert!(
            !labels(&resumed).contains(&"publish_hold_card"),
            "the accepted card must never be republished under a fresh created_at"
        );
        assert!(
            matches!(
                &resumed[1],
                PublishStep::PublishHoldNotice { card_event_id: Some(id), .. }
                    if *id == "0a".repeat(32)
            ),
            "the notice points at the card the relay already took: {:?}",
            resumed[1]
        );
    }

    #[test]
    fn a_second_hold_on_a_routed_hunt_reuses_the_case_and_reasserts_membership() {
        let mut h = harness(vec!["68".repeat(32), "69".repeat(32)], true);
        let first = fixture();
        h.store.create(first.clone()).unwrap();
        let opened = steps(
            h.publisher
                .plan(&held_event(&first, HoldState::Created))
                .unwrap(),
        );
        for (index, step) in opened.iter().enumerate() {
            h.publisher
                .on_ok(step, &format!("{:02x}", index + 1).repeat(32), 1)
                .unwrap();
        }
        let case = h
            .publisher
            .routing_mut()
            .case_for_hunt(&first.action_request.hunt_id.0)
            .unwrap();

        let mut second = fixture();
        second.hold_id = swarm_runtime::held_action::mint_hold_id();
        h.store.create(second.clone()).unwrap();
        let plan = steps(
            h.publisher
                .plan(&held_event(&second, HoldState::Created))
                .unwrap(),
        );
        // No second channel for one hunt, and membership is re-asserted before the first notice
        // so a 9000 that failed after its 9007 cannot leave the operator outside the case.
        assert_eq!(
            labels(&plan),
            [
                "add_member",
                "add_member",
                "publish_hold_card",
                "publish_hold_notice",
                "publish_alarm"
            ]
        );
        assert!(
            plan.iter()
                .all(|step| step.channel() != Some(uuid::Uuid::nil()))
        );
        assert_eq!(plan[0].channel(), Some(case));
    }

    #[test]
    fn a_refused_case_channel_create_is_replanned_until_the_relay_takes_it() {
        // `ensure_case_channel` writes its routing entry BEFORE anything is published and
        // returns no steps on a second call, so a refused `9007` would otherwise never be
        // retried -- and the next step would put a card into a channel that does not exist.
        // The accepted-create ledger is the separate question, and only an OK writes it.
        let mut h = harness(vec!["68".repeat(32)], true);
        let hold = fixture();
        h.store.create(hold.clone()).unwrap();
        let first = steps(
            h.publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
        );
        assert_eq!(labels(&first)[0], "create_channel");
        let PublishStep::CreateChannel { channel, .. } = &first[0] else {
            unreachable!()
        };
        let case = *channel;
        assert!(!h.publisher.routing_mut().channel_is_created(case));

        // The relay refused every step: nothing is acknowledged.
        let retry = steps(
            h.publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
        );
        assert_eq!(
            labels(&retry),
            [
                "create_channel",
                "add_member",
                "publish_hold_card",
                "publish_hold_notice",
                "publish_alarm"
            ],
            "the create is re-planned while the relay has not taken it"
        );
        assert_eq!(retry[0].channel(), Some(case), "and for the SAME channel");

        // Once the create is accepted it stops being planned, and a `duplicate: channel already
        // exists` OK counts as acceptance.
        h.publisher.on_ok(&first[0], &"01".repeat(32), 1).unwrap();
        assert!(h.publisher.routing_mut().channel_is_created(case));
        let after = steps(
            h.publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
        );
        assert_eq!(
            labels(&after),
            [
                "add_member",
                "publish_hold_card",
                "publish_hold_notice",
                "publish_alarm"
            ]
        );
    }

    #[test]
    fn the_notice_names_the_card_the_relay_took_in_the_same_sequence() {
        // The `card` tag is not knowable when the sequence is PLANNED -- the card step has not
        // run -- so it is resolved from the ledger at BUILD time. A notice with no `card` tag
        // still publishes, and the console then cannot join the queue row to its card.
        let mut h = harness(vec!["68".repeat(32)], true);
        let hold = fixture();
        h.store.create(hold.clone()).unwrap();
        let plan = steps(
            h.publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
        );
        assert!(
            matches!(
                &plan[3],
                PublishStep::PublishHoldNotice {
                    card_event_id: None,
                    ..
                }
            ),
            "planned before the card ran"
        );
        h.publisher.on_ok(&plan[0], &"01".repeat(32), 1).unwrap();
        h.publisher.on_ok(&plan[2], &"0a".repeat(32), 1).unwrap();
        let notice = h.publisher.build(&plan[3], 7, 1).unwrap().unwrap();
        assert!(
            notice
                .tags
                .contains(&vec!["card".to_string(), "0a".repeat(32)]),
            "{:?}",
            notice.tags
        );
        h.publisher.on_ok(&plan[3], &"0b".repeat(32), 5).unwrap();
        assert_eq!(
            h.store
                .get(&hold.hold_id)
                .unwrap()
                .unwrap()
                .card_event_id
                .as_deref(),
            Some("0a".repeat(32).as_str()),
            "and the daemon record learns the same id"
        );
    }

    #[test]
    fn the_three_intermediate_states_publish_nothing() {
        let mut h = harness(vec!["68".repeat(32)], true);
        let hold = fixture();
        h.store.create(hold.clone()).unwrap();
        for state in [HoldState::Notified, HoldState::Armed, HoldState::Deciding] {
            assert_eq!(
                steps(h.publisher.plan(&held_event(&hold, state)).unwrap()),
                Vec::new(),
                "{state:?}"
            );
        }
    }

    #[test]
    fn a_non_hold_event_plans_nothing() {
        let mut h = harness(vec!["68".repeat(32)], true);
        let promoted: RuntimeEvent = serde_json::from_value(serde_json::json!({
            "event_type": "case_promoted", "emitted_at_ms": 1, "hunt_id": "hunt-evt-1",
            "case_id": "9499a6e2-8872-453b-80d9-dafc6fc7fc69", "clause": "manual",
            "incident_id": "incident:perch-case:9499a6e2-8872-453b-80d9-dafc6fc7fc69",
            "finding_id": "f-1", "threat_class": "execution", "severity": "HIGH",
            "summary": "promoted"
        }))
        .unwrap();
        assert_eq!(steps(h.publisher.plan(&promoted).unwrap()), Vec::new());
    }

    #[test]
    fn a_derived_hold_id_never_reaches_the_planner() {
        let mut h = harness(vec!["68".repeat(32)], true);
        let mut hold = fixture();
        hold.hold_id = "hold:hunt-evt-1:1773738882600".to_string();
        let error = h
            .publisher
            .plan(&held_event(&hold, HoldState::Created))
            .unwrap_err();
        assert!(
            matches!(error, BridgeError::MalformedHoldId { ref value } if value == &hold.hold_id),
            "{error}"
        );
    }

    #[test]
    fn a_terminal_hold_with_no_case_channel_is_named_rather_than_given_one() {
        let mut h = harness(vec!["68".repeat(32)], true);
        let mut hold = fixture();
        hold.state = HoldState::Expired;
        h.store.create(hold.clone()).unwrap();
        assert!(matches!(
            h.publisher
                .plan(&held_event(&hold, HoldState::Expired))
                .unwrap(),
            HoldPlan::Undeliverable {
                reason: "no_case_channel",
                ..
            }
        ));
    }

    #[test]
    fn the_built_bodies_are_the_three_kinds_with_their_ruled_tag_sets() {
        let mut h = harness(vec!["68".repeat(32)], true);
        let hold = fixture();
        h.store.create(hold.clone()).unwrap();
        let plan = steps(
            h.publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
        );
        for step in &plan[..2] {
            assert!(h.publisher.build(step, 7, 1).unwrap().is_none());
        }
        h.publisher.on_ok(&plan[0], &"01".repeat(32), 1).unwrap();

        let card = h
            .publisher
            .build(&plan[2], 7, 1_773_738_882_700)
            .unwrap()
            .unwrap();
        assert_eq!(card.kind, 9);
        assert!(card.content.starts_with("<!-- swarm:hold:v1 -->\n"));
        assert!(!card.tags.iter().any(|tag| tag[0] == "p"));

        let notice = h
            .publisher
            .build(&plan[3], 7, 1_773_738_882_700)
            .unwrap()
            .unwrap();
        assert_eq!(notice.kind, 46010);
        assert_eq!(
            notice
                .tags
                .iter()
                .map(|tag| tag[0].as_str())
                .collect::<Vec<_>>(),
            ["h", "p", "hold"]
        );
        assert_eq!(notice.content, card.content.lines().nth(1).unwrap());
        assert!(!notice.tags.iter().any(|tag| tag[0] == "e"), "RF-D1");

        let alarm = h
            .publisher
            .build(&plan[4], 7, 1_773_738_882_700)
            .unwrap()
            .unwrap();
        assert_eq!(alarm.kind, 26006);
        assert_eq!(alarm.channel, None, "26006 is global (R-1)");
        assert_eq!(
            alarm
                .tags
                .iter()
                .map(|tag| tag[0].as_str())
                .collect::<Vec<_>>(),
            ["p"]
        );
        let frame: serde_json::Value = serde_json::from_str(&alarm.content).unwrap();
        assert_eq!(frame["schema"], "swarm.perch.frame.hold_alarm.v1");
        assert_eq!(frame["hold_id"], hold.hold_id);
        assert!(frame.get("hunt_id").is_none());
    }

    #[test]
    fn the_card_envelope_chain_advances_once_per_published_card() {
        let mut h = harness(vec!["68".repeat(32)], true);
        let hold = fixture();
        h.store.create(hold.clone()).unwrap();
        let plan = steps(
            h.publisher
                .plan(&held_event(&hold, HoldState::Created))
                .unwrap(),
        );
        h.publisher.on_ok(&plan[0], &"01".repeat(32), 1).unwrap();
        let first = h.publisher.build(&plan[2], 7, 1).unwrap().unwrap();
        let parsed = swarm_perch_wire::marker::parse_content(&first.content).unwrap();
        let envelope: serde_json::Value = serde_json::from_str(parsed.json).unwrap();
        assert!(envelope["prev_envelope_hash"].is_null());

        // The notice derives the same human line WITHOUT sealing an envelope, so the chain
        // still stands where the one published card left it.
        let notice = h.publisher.build(&plan[3], 7, 1).unwrap().unwrap();
        assert_eq!(notice.content, first.content.lines().nth(1).unwrap());
        assert_eq!(
            h.publisher.chain.prev_envelope_hash.as_deref(),
            Some(envelope["envelope_hash"].as_str().unwrap()),
            "the notice must not advance the chain"
        );
    }
}
