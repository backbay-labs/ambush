//! The pacer: one frame per tick, `created_at` stamped at drain.
//!
//! Written fresh rather than ported. The chat app's own `ObserverPublishQueue` is private inside
//! a crate this repository does not link, and vendoring it a second time would carry a NOTICE
//! obligation, a dependency-bill line, and the same `unwrap_used`/`expect_used` problem as the
//! WebSocket client. What we take is the *specification*, cited inline below.

use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use swarm_core::config::PerchBridgeConfig;
use swarm_runtime::runtime_events::RuntimeEvent;
use tokio::sync::watch;

use crate::cards::{SeqChain, build_finding_card};
use crate::error::BridgeError;
use crate::identity::IdentityTable;
use crate::metrics::BridgeMetrics;
use crate::publish::{AlarmAdmission, OkOutcome, RetryDecision, retry_decision};
use crate::spool::{GapCause, IssuerIdx, Seq, Spool, SpoolSet};
use crate::stream::Stream;

/// `APPENDIX-NORMATIVE.md` section 6. Proposed.
///
/// The invariant: *AT MOST ONE relay frame per tick — not one per channel, and not one per
/// drain. At 1 frame/s the bridge spends at most 60/min — half the agent budget.* This is the
/// structural answer to the relay's 120/min quota: it is not a measurement that might drift, it
/// is the loop's shape.
pub const PERCH_PUBLISH_TICK_MS: u64 = 1_000;

/// `APPENDIX-NORMATIVE.md` section 6. Proposed.
///
/// Mirrors the chat app's `OBSERVER_MAX_PLAINTEXT_LEN = 65_535`. Sits under both the relay's
/// `DEFAULT_MAX_FRAME_BYTES` (512 KiB) and `MAX_EVENT_CONTENT_BYTES` (256 KB), so a full frame is
/// never a protocol risk.
pub const PERCH_FRAME_MAX_BYTES: usize = 64 * 1024;

/// The most unpublishable records one tick will discharge before it yields, so a poisoned or
/// flooded spool cannot pin the drain task on a single tick.
///
/// The invariant is at most one relay FRAME per tick, not one spool RECORD per tick: a producer
/// that emits faster than the pacer drains (found-15 measured a 10 Hz escalation flood against a
/// 1 Hz pacer, 20,436 records spooled and no card published in 45 min) would otherwise leave
/// every finding card behind a wall the pacer clears one record per tick. A tick therefore
/// commits every consecutive record no producer turns into a card and publishes the first
/// publishable record it reaches. This bound exists only so the loop cannot run unbounded on a
/// spool that is *entirely* unpublishable; at 4,096 records a tick and 1 Hz it clears a day of
/// the measured flood in seconds.
pub const PACER_SKIP_BUDGET: usize = 4096;

/// Ticks of silence on a stream holding a pending gap before the pacer would emit a **gap-only
/// card**. PROPOSED; three ticks is the smallest value that does not race a busy stream's own
/// next card.
///
/// **Not reached in this milestone.** A gap-only card needs a payload-array schema the wire
/// registry does not have: `swarm:finding:v1` carries exactly one finding, so there is no legal
/// card with an empty payload and a populated `gap` block. Until the escalation producer lands
/// (Operator-complete), a gap rides the next real card on its stream and a stream that publishes
/// nothing carries its gap forward. That limitation is recorded in the milestone's exit criteria.
pub const PERCH_GAP_FLUSH_TICKS: u32 = 3;

/// `created_at` vs `emitted_at_ms` disagreement, in ticks, past which the card is observed as
/// late-published. INVENTED -- `APPENDIX-NORMATIVE.md` section 6 records it as such, and it
/// stays invented until somebody measures a real spool drain.
pub const PERCH_LATE_PUBLISHED_TICKS: i64 = 2;

/// Slack against the relay's +/-900 s `created_at` window for a frame already signed and in
/// flight. Sized so a clock skew inside the +/-30 s warning band cannot push a frame over the
/// edge. PROPOSED.
pub const PERCH_PUBLISH_WINDOW_MARGIN_SECS: i64 = 120;

/// A packed, stamped, signed frame ready for the socket.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Which identity slot signed it.
    pub identity: IssuerIdx,
    /// `None` for a global ephemeral (`26000`-`26006` carry no `h`); `Some` for a lane or case
    /// channel card.
    pub channel: Option<uuid::Uuid>,
    /// The signed Nostr event. Retried **byte-identically**: the event id is a hash over
    /// `(pubkey, created_at, kind, tags, content)`, and the relay's insert is
    /// `ON CONFLICT DO NOTHING`, so an identical resend is a no-op.
    pub signed: nostr::Event,
    /// The signed event's id, hex.
    pub event_id: String,
    /// The `(issuer, seq)` this frame discharges. Committed on `OK true` only.
    pub covers: (IssuerIdx, Seq),
    /// The transport timestamp, stamped at drain.
    pub created_at_secs: i64,
}

/// Where a frame goes. Implemented by [`crate::publish::ConnectionSupervisor`] in production and
/// by a recording double in tests.
pub trait FramePublisher: Send {
    /// Submits one frame and resolves the relay's answer.
    ///
    /// # Errors
    ///
    /// [`BridgeError::Ws`] when the socket failed or the OK never arrived, and
    /// [`BridgeError::RelayUnreachable`] while the supervisor is inside its backoff window.
    fn publish(
        &mut self,
        frame: &Frame,
    ) -> impl Future<Output = Result<OkOutcome, BridgeError>> + Send;

    /// Submits one ephemeral `26006` OUTSIDE the tick, bounded by a sliding one-minute burst
    /// window.
    ///
    /// A REQUIRED method, not a defaulted one. A default that ignored the cap would make the
    /// cap unreachable from any test that drives the drainer through a double, and an
    /// unexercised bound on the one frame the bridge is allowed to send unpaced is not a bound.
    ///
    /// # Errors
    ///
    /// As [`FramePublisher::publish`]. A full window is `Ok(AlarmAdmission::Deferred)`, not an
    /// error: the caller keeps its spool record and the next tick re-plans.
    fn submit_alarm(
        &mut self,
        frame: &Frame,
        now_ms: i64,
    ) -> impl Future<Output = Result<AlarmAdmission, BridgeError>> + Send;
}

/// What one submission did, so the caller knows whether to rewind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubmitOutcome {
    /// The relay stored it (or already had it). Committed.
    Acknowledged,
    /// The relay answered `OK false`. The record stays at the spool head.
    Refused,
    /// The OK never arrived. The signed frame is kept for a byte-identical retry.
    Held,
}

/// Drains the evidence spool at exactly one frame per tick.
pub struct Pacer<P: FramePublisher> {
    spools: Arc<Mutex<SpoolSet>>,
    identities: Arc<IdentityTable>,
    config: PerchBridgeConfig,
    colony_id: String,
    metrics: BridgeMetrics,
    publisher: P,
    chains: std::collections::BTreeMap<IssuerIdx, SeqChain>,
    /// Each issuer's chain as it stood BEFORE the card currently in flight or last refused. A
    /// card the relay did not take must not advance the chain, and the value to restore is not
    /// derivable from the current one.
    chain_before: std::collections::BTreeMap<IssuerIdx, SeqChain>,
    /// B6. The spine identities every envelope is sealed under, when the
    /// bridge was built with a signing profile.
    spine: Option<Arc<crate::spine::SpineSigner>>,
    /// B6. The durable chain heads, advanced only on ACKNOWLEDGEMENT: a card
    /// the relay did not take must not advance a chain that survives restart.
    chain_heads: Option<Arc<Mutex<crate::spool::chain_heads::ChainHeadStore>>>,
    /// A signed frame whose OK never arrived, awaiting a byte-identical retry.
    inflight: Option<Frame>,
    /// The gaps the in-flight frame carries. Returned to the spool if it is abandoned.
    inflight_gaps: Vec<GapCause>,
}

impl<P: FramePublisher> Pacer<P> {
    /// Assembles a pacer over one publisher.
    pub fn new(
        spools: Arc<Mutex<SpoolSet>>,
        identities: Arc<IdentityTable>,
        config: PerchBridgeConfig,
        colony_id: String,
        metrics: BridgeMetrics,
        publisher: P,
    ) -> Self {
        Self {
            spools,
            identities,
            config,
            colony_id,
            metrics,
            publisher,
            chains: std::collections::BTreeMap::new(),
            chain_before: std::collections::BTreeMap::new(),
            spine: None,
            chain_heads: None,
            inflight: None,
            inflight_gaps: Vec::new(),
        }
    }

    /// Attach B6's signer and durable chain heads.
    ///
    /// Absent leaves envelopes unsigned, which is what the fixture generator
    /// and the pre-B6 tests construct.
    #[must_use]
    pub fn with_spine(
        mut self,
        spine: Arc<crate::spine::SpineSigner>,
        chain_heads: Arc<Mutex<crate::spool::chain_heads::ChainHeadStore>>,
    ) -> Self {
        self.spine = Some(spine);
        self.chain_heads = Some(chain_heads);
        self
    }

    /// The publisher, for assertions.
    pub const fn publisher(&self) -> &P {
        &self.publisher
    }

    /// The publisher, mutably, for a test that changes its answer mid-run.
    pub fn publisher_mut(&mut self) -> &mut P {
        &mut self.publisher
    }

    /// One tick. Returns the number of frames the relay acknowledged this tick — zero or one.
    ///
    /// Front-run packing degenerates to one record per frame for single-fact cards, which is
    /// every card this milestone publishes, so the packer the skeleton sketched is not written:
    /// one finding is one card is one frame. The rule is here rather than in a comment on a
    /// deleted function so the next card type has to restate it deliberately.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the spool cannot be read or its cursor cannot be written,
    /// and [`BridgeError::MissingLaneChannel`] when a finding's threat class has no lane.
    pub async fn tick(&mut self, now_ms: i64) -> Result<usize, BridgeError> {
        let now_secs = now_ms / 1_000;

        // 1. A frame already signed and in flight is retried byte-identically while the relay's
        //    timestamp window is open, and abandoned with an accounted gap after that.
        if let Some(frame) = self.inflight.take() {
            match retry_decision(&frame, now_secs) {
                RetryDecision::ResendIdentical => {
                    let issuer = frame.covers.0;
                    return match self.submit(frame).await? {
                        SubmitOutcome::Acknowledged => Ok(1),
                        SubmitOutcome::Held => Ok(0),
                        SubmitOutcome::Refused => {
                            self.rewind(issuer);
                            Ok(0)
                        }
                    };
                }
                RetryDecision::RestampFromSpool => {
                    let (issuer, seq) = frame.covers;
                    self.metrics
                        .dropped_event(Stream::Evidence, "publish_window_expired");
                    {
                        let mut guard = self.spools.lock().unwrap_or_else(PoisonError::into_inner);
                        guard.evidence().mark_gap(GapCause::PublishWindowExpired {
                            from_seq: seq,
                            to_seq: seq,
                        });
                    }
                    self.rewind(issuer);
                    tracing::warn!(
                        module = module_path!(),
                        issuer,
                        seq,
                        "a signed frame aged past the relay timestamp window; re-stamping from \
                         the spool head"
                    );
                }
            }
        }

        // 2. Discharge the head records no producer turns into a card -- and any whose issuer
        //    index is past the table -- until a publishable record is reached or the skip budget
        //    bounds the tick (found-15). The invariant is at most one relay FRAME per tick, NOT
        //    one spool RECORD per tick: a producer that emits faster than the pacer drains would
        //    otherwise leave every finding card behind a wall the pacer clears one record per
        //    tick, which is the 20,436-record spool the walk measured with no card published.
        //    Records are consumed a peeked batch at a time rather than re-peeked per record, so a
        //    tick that clears thousands of them re-scans the spool a handful of times, not once
        //    per record. A record that fails to BUILD (a `BridgeError` from a producer) still
        //    propagates and keeps its current handling.
        let mut skipped: usize = 0;
        loop {
            // A batch of head records and the pending gaps, taken once for the batch. The gaps
            // ride the first publishable record in the batch, or are put back if there is none.
            let (records, gaps) = {
                let mut guard = self.spools.lock().unwrap_or_else(PoisonError::into_inner);
                let evidence = guard.evidence();
                let records = evidence.peek(PERCH_FRAME_MAX_BYTES)?;
                if records.is_empty() {
                    let bytes = guard.disk_bytes();
                    drop(guard);
                    for (stream, held) in bytes {
                        self.metrics.observe_spool_bytes(stream, held);
                    }
                    return Ok(0);
                }
                let gaps = evidence.take_gaps();
                (records, gaps)
            };

            for record in records {
                if skipped >= PACER_SKIP_BUDGET {
                    // The budget is spent; this record and the rest of the batch wait for the next
                    // tick. No frame was published, so one-frame-per-tick holds; the gaps go back.
                    self.restore_gaps(&gaps);
                    return Ok(0);
                }

                let event: RuntimeEvent = serde_json::from_slice(&record.payload)
                    .map_err(|error| BridgeError::Encode(error.to_string()))?;

                let Some(identity) = self.identities.get(record.issuer) else {
                    // A record whose issuer index is past the table can never be signed. Commit it
                    // and account for it rather than blocking the head forever; being unpublishable
                    // it is discharged within the tick's budget rather than ending the tick.
                    self.metrics
                        .dropped_event(Stream::Evidence, "unknown_issuer");
                    self.commit(record.issuer, record.seq)?;
                    skipped += 1;
                    continue;
                };
                let identity = identity.clone();

                let before = self.chains.get(&record.issuer).cloned().unwrap_or_default();
                let mut chain = before.clone();
                let built = build_finding_card(
                    &record,
                    &event,
                    &identity,
                    &self.colony_id,
                    &self.config,
                    &mut chain,
                    &gaps,
                    now_ms,
                    self.spine.as_deref(),
                )?;

                // B6. Counted where the seal happened, so an operator comparing this with
                // `bridge_source_events_published` can see whether what reached the relay was
                // signed rather than taking it on faith.
                if let Some(spine) = self.spine.as_ref()
                    && built.is_some()
                {
                    self.metrics
                        .envelope_signed(spine.issuer(identity.slot.label()));
                }

                let Some(body) = built else {
                    // A card type this milestone does not publish. The record's meaning is not lost
                    // -- it stays in the daemon's own stores -- so it is committed and counted
                    // apart from both a drop and a publish, and the tick moves to the next record.
                    self.metrics.skipped_unpublished(Stream::Evidence);
                    self.commit(record.issuer, record.seq)?;
                    skipped += 1;
                    continue;
                };

                // 3. Stamp `created_at` from the daemon's clock, immediately before signing.
                //
                // FORCED, not preferred. The relay's `MAX_TIMESTAMP_DRIFT_SECS` is 900 s and it
                // REJECTS, and `created_at` is inside the Nostr signature, so a spooled card
                // carrying its true emit time would become permanently unpublishable fifteen
                // minutes after it was produced and could not be corrected without re-signing.
                // `emitted_at_ms` in the body is the domain timestamp and every Perch surface
                // sorts on it.
                let tags: Vec<nostr::Tag> = body
                    .tags
                    .iter()
                    .map(|tag| nostr::Tag::parse(tag.clone()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| BridgeError::Encode(error.to_string()))?;
                let signed = nostr::EventBuilder::new(
                    nostr::Kind::Custom(swarm_perch_wire::KIND_CARD),
                    body.content,
                )
                .tags(tags)
                .custom_created_at(nostr::Timestamp::from(now_secs.max(0) as u64))
                .sign_with_keys(&identity.keys)
                .map_err(|error| BridgeError::Encode(error.to_string()))?;

                let lateness_secs = now_secs - record.emitted_at_ms / 1_000;
                if lateness_secs > PERCH_LATE_PUBLISHED_TICKS {
                    self.metrics.observe_late_published(lateness_secs as f64);
                }

                let frame = Frame {
                    identity: record.issuer,
                    channel: Some(body.channel),
                    event_id: signed.id.to_hex(),
                    signed,
                    covers: body.covers,
                    created_at_secs: now_secs,
                };
                self.chain_before.insert(record.issuer, before);
                self.chains.insert(record.issuer, chain);
                self.inflight_gaps = gaps;

                return match self.submit(frame).await {
                    Ok(SubmitOutcome::Acknowledged) => Ok(1),
                    Ok(SubmitOutcome::Held) => Ok(0),
                    Ok(SubmitOutcome::Refused) => {
                        self.rewind(record.issuer);
                        Ok(0)
                    }
                    Err(error) => {
                        self.rewind(record.issuer);
                        Err(error)
                    }
                };
            }

            // The whole batch was unpublishable and under budget. Put the gaps back for the next
            // batch's peek to re-take, and go on to the next batch.
            self.restore_gaps(&gaps);
        }
    }

    /// Publishes one frame and applies the relay's answer.
    async fn submit(&mut self, frame: Frame) -> Result<SubmitOutcome, BridgeError> {
        let started = std::time::Instant::now();
        match self.publisher.publish(&frame).await {
            Ok(outcome) if outcome.is_success() => {
                let (issuer, seq) = frame.covers;
                self.commit(issuer, seq)?;
                // B6. The durable head advances HERE and nowhere else. A card
                // the relay never took must not advance a chain that survives
                // restart, or the next real card chains from a link nobody can
                // fetch — a broken chain produced by the mechanism meant to
                // guarantee it.
                self.commit_chain_head(issuer, seq);
                self.chain_before.remove(&issuer);
                self.inflight_gaps.clear();
                self.metrics.source_events_published(Stream::Evidence);
                self.metrics
                    .observe_publish_latency(started.elapsed().as_secs_f64());
                let bytes = self
                    .spools
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .disk_bytes();
                for (stream, held) in bytes {
                    self.metrics.observe_spool_bytes(stream, held);
                }
                Ok(SubmitOutcome::Acknowledged)
            }
            Ok(outcome) => {
                // A rejection is not a timeout: the relay answered. The record stays at the head
                // and the next tick re-stamps it, because a changed `created_at` requires a new
                // signature anyway.
                self.metrics.admission_rejection(outcome.reason());
                tracing::warn!(
                    module = module_path!(),
                    reason = outcome.reason(),
                    event_id = %frame.event_id,
                    "the relay refused a perch card; it stays at the spool head"
                );
                Ok(SubmitOutcome::Refused)
            }
            // The OK never arrived. Keep the SIGNED frame so the retry is byte-identical, and
            // keep the chain advanced: the retry publishes that same envelope.
            Err(BridgeError::Ws(ambush_ws_client::WsClientError::Timeout)) => {
                self.inflight = Some(frame);
                Ok(SubmitOutcome::Held)
            }
            Err(error) => Err(error),
        }
    }

    /// Undoes the effect of a card the relay did not take: the chain goes back to what the last
    /// ACKNOWLEDGED card left, and the gaps it would have carried return to the spool.
    fn rewind(&mut self, issuer: IssuerIdx) {
        if let Some(before) = self.chain_before.remove(&issuer) {
            self.chains.insert(issuer, before);
        }
        let gaps = std::mem::take(&mut self.inflight_gaps);
        self.restore_gaps(&gaps);
    }

    /// Puts gaps back when the card that would have carried them was not published.
    fn restore_gaps(&self, gaps: &[GapCause]) {
        if gaps.is_empty() {
            return;
        }
        let mut guard = self.spools.lock().unwrap_or_else(PoisonError::into_inner);
        for cause in gaps {
            guard.evidence().mark_gap(cause.clone());
        }
    }

    /// Advance the durable chain head for `issuer` to the envelope the relay
    /// just acknowledged.
    ///
    /// Failures are counted and logged rather than propagated: the card IS
    /// published, and returning an error here would re-send a frame the relay
    /// already took. The next seal reads the stale head, produces a duplicate
    /// `seq`, and the store refuses it — visible, and not a silent fork.
    fn commit_chain_head(&self, issuer: IssuerIdx, seq: Seq) {
        let (Some(spine), Some(heads)) = (self.spine.as_ref(), self.chain_heads.as_ref()) else {
            return;
        };
        let Some(identity) = self.identities.get(issuer) else {
            return;
        };
        let Some(chain) = self.chains.get(&issuer) else {
            return;
        };
        let Some(envelope_hash) = chain.prev_envelope_hash.clone() else {
            return;
        };
        // The head carries the seq that was SIGNED. `verify_chain_link` requires
        // the next envelope's `seq` to be exactly one past the head's, so a head
        // counted separately from the envelope would fail every check.
        let head = swarm_perch_wire::envelope::IssuerChainHead {
            issuer: spine.issuer(identity.slot.label()).to_string(),
            seq,
            envelope_hash,
        };
        if let Err(error) = heads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .advance(head)
        {
            tracing::warn!(
                module = module_path!(),
                reason = %error,
                "chain head could not be advanced; the next seal will be refused rather than fork"
            );
        }
    }

    fn commit(&self, issuer: IssuerIdx, seq: Seq) -> Result<(), BridgeError> {
        self.spools
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .evidence()
            .commit(issuer, seq)
    }

    /// Runs until shutdown.
    ///
    /// `MissedTickBehavior::Delay`, not the default `Burst`. A pacer that catches up after a
    /// stall fires N ticks back to back and hands the relay N frames inside one second — exactly
    /// the shape that trips the relay's 50-frames-per-5-second budget and turns a stall into a
    /// rate-limit window.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        let mut interval =
            tokio::time::interval(Duration::from_millis(self.config.publish_tick_ms.max(1)));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;

                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!(module = module_path!(), "perch bridge pacer stopping");
                        return;
                    }
                }

                _ = interval.tick() => {
                    let now_ms = chrono::Utc::now().timestamp_millis();
                    // A per-tick error is logged and never propagated: the pacer is the only
                    // drain, and a task that exits on a transient spool or relay error would
                    // silently stop publishing for the life of the daemon.
                    if let Err(error) = self.tick(now_ms).await {
                        tracing::warn!(
                            module = module_path!(),
                            reason = %error,
                            "perch bridge pacer tick failed; retrying on the next tick"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use prometheus_client::encoding::text::encode;
    use prometheus_client::registry::Registry;
    use swarm_core::agent::SwarmMode;
    use swarm_core::config::SecretString;
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::AgentId;
    use swarm_runtime::runtime_events::EscalationLevel;

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

        /// The pacer never submits an alarm -- the alarm lane is the drainer's. Recording it
        /// the same way keeps this double honest if that ever changes.
        async fn submit_alarm(
            &mut self,
            frame: &Frame,
            _now_ms: i64,
        ) -> Result<AlarmAdmission, BridgeError> {
            self.publish(frame).await.map(AlarmAdmission::Sent)
        }
    }

    const LANES: [(&str, &str); 12] = [
        ("lateral_movement", "154eea36-c787-4bf7-9c84-4424b0184395"),
        ("data_exfiltration", "2c8d1a90-6e40-4b1f-9f18-1b3f5c2d7a01"),
        (
            "privilege_escalation",
            "3a1b7c22-9d55-4c07-8f2a-6d4e91b0c3f2",
        ),
        (
            "command_and_control",
            "4b2c8d33-ae66-4d18-9034-7e5f02c1d4a3",
        ),
        ("initial_access", "5c3d9e44-bf77-4e29-a145-8f6013d2e5b4"),
        ("persistence", "6d4eaf55-c088-4f3a-b256-900124e3f6c5"),
        ("supply_chain", "7e5fb066-d199-4a4b-c367-a11235f407d6"),
        ("defense_evasion", "8f60c177-e2aa-4b5c-d478-b2234605918e"),
        ("credential_access", "9071d288-f3bb-4c6d-e589-c334570629f8"),
        ("discovery", "a182e399-04cc-4d7e-f69a-d44568173a09"),
        ("execution", "b293f4aa-15dd-4e8f-07ab-e55679284b1a"),
        ("impact", "c3a405bb-26ee-4f90-18bc-f6678a395c2b"),
    ];

    type Harness = (
        Arc<Mutex<SpoolSet>>,
        Arc<IdentityTable>,
        PerchBridgeConfig,
        BridgeMetrics,
        tempfile::TempDir,
    );

    type HarnessWithRegistry = (
        Arc<Mutex<SpoolSet>>,
        Arc<IdentityTable>,
        PerchBridgeConfig,
        BridgeMetrics,
        Arc<Mutex<Registry>>,
        tempfile::TempDir,
    );

    fn harness() -> Harness {
        let (spools, identities, config, metrics, _registry, dir) = harness_with_registry();
        (spools, identities, config, metrics, dir)
    }

    /// The harness plus the metrics registry, for a test that reads a counter's encoded value.
    fn harness_with_registry() -> HarnessWithRegistry {
        let dir = tempfile::tempdir().unwrap();
        let spools = Arc::new(Mutex::new(
            SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap(),
        ));
        let identities = Arc::new(
            IdentityTable::build(
                &SecretString::new("11".repeat(32)),
                "c",
                &[],
                &AgentId("swarm:ed25519:".to_string() + &"ab".repeat(32)),
                None,
            )
            .unwrap(),
        );
        let mut config = PerchBridgeConfig::default();
        for (slug, uuid) in LANES {
            config.lane_channels.insert(slug.into(), uuid.into());
        }
        config.case_ttl_seconds.insert("default".into(), 2_592_000);
        let (metrics, registry) = BridgeMetrics::new();
        (spools, identities, config, metrics, registry, dir)
    }

    /// A record that classifies to `Stream::Evidence` but has no producer this milestone, so the
    /// pacer commits it as `skipped_unpublished`. This is the record found-15 measured flooding.
    fn escalation_event() -> RuntimeEvent {
        RuntimeEvent::Escalation {
            emitted_at_ms: 1_700_000_000_000,
            threat_class: ThreatClass::Execution,
            level: EscalationLevel::Alert,
            total_strength: 3.6,
            distinct_sources: 2,
            peak_confidence: 0.9,
            mode_changed: false,
            current_mode: SwarmMode::Alert,
        }
    }

    fn append_event(spools: &Arc<Mutex<SpoolSet>>, event: &RuntimeEvent) {
        spools
            .lock()
            .unwrap()
            .append(Stream::Evidence, Record::from_event(event, 0).unwrap())
            .unwrap();
    }

    fn evidence_records(spools: &Arc<Mutex<SpoolSet>>) -> usize {
        spools
            .lock()
            .unwrap()
            .evidence()
            .peek(usize::MAX)
            .unwrap()
            .len()
    }

    fn skipped_evidence(registry: &Arc<Mutex<Registry>>) -> u64 {
        let mut out = String::new();
        encode(&mut out, &registry.lock().unwrap()).unwrap();
        out.lines()
            .find(|line| {
                line.starts_with("perch_bridge_skipped_unpublished_total")
                    && line.contains("stream=\"evidence\"")
            })
            .and_then(|line| line.rsplit(' ').next())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    }

    fn finding_event(finding_id: &str, threat_class: &str, severity: &str) -> RuntimeEvent {
        serde_json::from_value(serde_json::json!({
            "event_type": "finding", "emitted_at_ms": 1_700_000_000_000i64, "host_id": "web-04",
            "finding": {"schema": "swarm_finding", "finding_id": finding_id,
                        "event_id": "tel-8831", "strategy_id": "dns_exfil_beaconing",
                        "threat_class": threat_class, "severity": severity,
                        "confidence": 0.82, "evidence": {}}
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn one_tick_publishes_one_card_per_identity_and_commits_only_on_ok() {
        let (spools, identities, config, metrics, _dir) = harness();
        for i in 0..3 {
            spools
                .lock()
                .unwrap()
                .append(
                    Stream::Evidence,
                    Record::from_event(&finding_event(&format!("f{i}"), "execution", "LOW"), 0)
                        .unwrap(),
                )
                .unwrap();
        }
        let mut pacer = Pacer::new(
            Arc::clone(&spools),
            identities,
            config,
            "c".into(),
            metrics,
            Recording {
                frames: vec![],
                answer: OkOutcome::Accepted,
            },
        );
        assert_eq!(pacer.tick(1_700_000_000_000).await.unwrap(), 1);
        assert_eq!(pacer.tick(1_700_000_001_000).await.unwrap(), 1);
        assert_eq!(pacer.tick(1_700_000_002_000).await.unwrap(), 1);
        assert_eq!(
            pacer.tick(1_700_000_003_000).await.unwrap(),
            0,
            "nothing left"
        );
        assert!(
            spools
                .lock()
                .unwrap()
                .evidence()
                .peek(usize::MAX)
                .unwrap()
                .is_empty()
        );
        let frames = &pacer.publisher().frames;
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].signed.kind.as_u16(), 9);
        assert_eq!(
            frames[0].signed.content.lines().next(),
            Some("<!-- swarm:finding:v1 -->")
        );
        // created_at is the drain instant, not the domain instant.
        assert_eq!(frames[0].created_at_secs, 1_700_000_000);
        assert_eq!(frames[0].signed.created_at.as_secs(), 1_700_000_000);
        assert_eq!(frames[0].covers, (0, 1));
        assert_eq!(frames[2].covers, (0, 3));
    }

    #[tokio::test]
    async fn a_rejected_frame_is_not_committed_and_a_lag_gap_flushes_on_the_next_card() {
        let (spools, identities, config, metrics, _dir) = harness();
        spools
            .lock()
            .unwrap()
            .append(
                Stream::Evidence,
                Record::from_event(&finding_event("f0", "execution", "LOW"), 0).unwrap(),
            )
            .unwrap();
        let mut pacer = Pacer::new(
            Arc::clone(&spools),
            identities,
            config,
            "c".into(),
            metrics,
            Recording {
                frames: vec![],
                answer: OkOutcome::Rejected {
                    message: "blocked".into(),
                },
            },
        );
        assert_eq!(pacer.tick(1_700_000_000_000).await.unwrap(), 0);
        assert_eq!(
            spools
                .lock()
                .unwrap()
                .evidence()
                .peek(usize::MAX)
                .unwrap()
                .len(),
            1,
            "still at the head"
        );
        spools
            .lock()
            .unwrap()
            .mark_gap_all_disk_spooled(GapCause::BroadcastLagged { count: 3 });
        pacer.publisher_mut().answer = OkOutcome::Accepted;
        assert_eq!(pacer.tick(1_700_000_001_000).await.unwrap(), 1);
        let content = &pacer.publisher().frames.last().unwrap().signed.content;
        assert!(
            content.contains("\"gap\":{\"cause\":\"broadcast_lagged\",\"count\":3"),
            "{content}"
        );
    }

    #[tokio::test]
    async fn a_gap_taken_for_a_refused_card_is_put_back_and_not_lost() {
        let (spools, identities, config, metrics, _dir) = harness();
        spools
            .lock()
            .unwrap()
            .append(
                Stream::Evidence,
                Record::from_event(&finding_event("f0", "execution", "LOW"), 0).unwrap(),
            )
            .unwrap();
        spools
            .lock()
            .unwrap()
            .mark_gap_all_disk_spooled(GapCause::BroadcastLagged { count: 5 });
        let mut pacer = Pacer::new(
            Arc::clone(&spools),
            identities,
            config,
            "c".into(),
            metrics,
            Recording {
                frames: vec![],
                answer: OkOutcome::Rejected {
                    message: "blocked".into(),
                },
            },
        );
        assert_eq!(pacer.tick(1_700_000_000_000).await.unwrap(), 0);
        pacer.publisher_mut().answer = OkOutcome::Accepted;
        assert_eq!(pacer.tick(1_700_000_001_000).await.unwrap(), 1);
        let content = &pacer.publisher().frames.last().unwrap().signed.content;
        assert!(
            content.contains("\"count\":5"),
            "the gap survived a refused card: {content}"
        );
    }

    #[tokio::test]
    async fn an_event_with_no_producer_is_committed_and_counted_not_dropped() {
        let (spools, identities, config, metrics, _dir) = harness();
        let escalation: RuntimeEvent = serde_json::from_value(serde_json::json!({
            "event_type": "escalation", "emitted_at_ms": 1, "threat_class": "execution",
            "level": "alert", "total_strength": 2.5, "distinct_sources": 2,
            "peak_confidence": 0.9, "mode_changed": false, "current_mode": "alert"
        }))
        .unwrap();
        spools
            .lock()
            .unwrap()
            .append(
                Stream::Evidence,
                Record::from_event(&escalation, 0).unwrap(),
            )
            .unwrap();
        let mut pacer = Pacer::new(
            Arc::clone(&spools),
            identities,
            config,
            "c".into(),
            metrics,
            Recording {
                frames: vec![],
                answer: OkOutcome::Accepted,
            },
        );
        assert_eq!(pacer.tick(1_700_000_000_000).await.unwrap(), 0);
        assert!(pacer.publisher().frames.is_empty(), "nothing was published");
        assert!(
            spools
                .lock()
                .unwrap()
                .evidence()
                .peek(usize::MAX)
                .unwrap()
                .is_empty(),
            "the record was committed, not left to block the head"
        );
    }

    #[tokio::test]
    async fn a_frame_whose_ok_never_arrived_is_resent_byte_identically_then_abandoned() {
        struct Timeout {
            seen: Vec<String>,
            contents: Vec<String>,
        }
        impl FramePublisher for Timeout {
            async fn publish(&mut self, frame: &Frame) -> Result<OkOutcome, BridgeError> {
                self.seen.push(frame.event_id.clone());
                self.contents.push(frame.signed.content.clone());
                Err(BridgeError::Ws(ambush_ws_client::WsClientError::Timeout))
            }

            async fn submit_alarm(
                &mut self,
                frame: &Frame,
                _now_ms: i64,
            ) -> Result<AlarmAdmission, BridgeError> {
                self.publish(frame).await.map(AlarmAdmission::Sent)
            }
        }

        let (spools, identities, config, metrics, _dir) = harness();
        spools
            .lock()
            .unwrap()
            .append(
                Stream::Evidence,
                Record::from_event(&finding_event("f0", "execution", "LOW"), 0).unwrap(),
            )
            .unwrap();
        let mut pacer = Pacer::new(
            Arc::clone(&spools),
            identities,
            config,
            "c".into(),
            metrics,
            Timeout {
                seen: vec![],
                contents: vec![],
            },
        );
        assert_eq!(pacer.tick(1_700_000_000_000).await.unwrap(), 0);
        assert_eq!(pacer.tick(1_700_000_001_000).await.unwrap(), 0);
        let seen = &pacer.publisher().seen;
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], seen[1], "the retry is the identical signed event");

        // Past the window the signed frame is abandoned, the loss is recorded exactly, and the
        // record is re-stamped from the spool head — so the replacement card CARRIES the gap
        // its predecessor's abandonment created.
        assert_eq!(
            pacer.tick(1_700_000_000_000 + 800_000).await.unwrap(),
            0,
            "the abandoned frame is re-stamped from the spool head"
        );
        let restamped = pacer.publisher().contents.last().unwrap();
        assert!(
            restamped.contains("\"cause\":\"publish_window_expired\"")
                && restamped.contains("\"from_seq\":1")
                && restamped.contains("\"to_seq\":1"),
            "{restamped}"
        );
        assert_ne!(
            pacer.publisher().seen[2],
            pacer.publisher().seen[1],
            "the re-stamped frame is a new event id"
        );
    }

    #[tokio::test]
    async fn a_tick_discharges_unpublishable_records_and_publishes_the_finding_behind_them() {
        // found-15: 100 records no producer turns into a card, then one finding. A single tick
        // commits all 100 as skipped and publishes the finding in the SAME tick -- the invariant
        // is one relay FRAME per tick, not one spool RECORD per tick.
        let (spools, identities, config, metrics, registry, _dir) = harness_with_registry();
        for _ in 0..100 {
            append_event(&spools, &escalation_event());
        }
        append_event(&spools, &finding_event("f0", "execution", "LOW"));

        let mut pacer = Pacer::new(
            Arc::clone(&spools),
            identities,
            config,
            "c".into(),
            metrics,
            Recording {
                frames: vec![],
                answer: OkOutcome::Accepted,
            },
        );

        assert_eq!(pacer.tick(1_700_000_000_000).await.unwrap(), 1);
        assert_eq!(pacer.publisher().frames.len(), 1);
        assert_eq!(
            pacer.publisher().frames[0].signed.content.lines().next(),
            Some("<!-- swarm:finding:v1 -->")
        );
        assert_eq!(
            evidence_records(&spools),
            0,
            "the flood and the finding were both committed this tick"
        );
        assert_eq!(skipped_evidence(&registry), 100);
    }

    #[tokio::test]
    async fn the_skip_budget_bounds_one_tick() {
        // A spool that is entirely unpublishable cannot pin the drain task: one tick discharges at
        // most PACER_SKIP_BUDGET records and yields, leaving the rest for the next tick.
        let (spools, identities, config, metrics, _dir) = harness();
        for _ in 0..(PACER_SKIP_BUDGET + 1) {
            append_event(&spools, &escalation_event());
        }
        let mut pacer = Pacer::new(
            Arc::clone(&spools),
            identities,
            config,
            "c".into(),
            metrics,
            Recording {
                frames: vec![],
                answer: OkOutcome::Accepted,
            },
        );

        assert_eq!(
            pacer.tick(1_700_000_000_000).await.unwrap(),
            0,
            "nothing publishable this tick"
        );
        assert_eq!(
            evidence_records(&spools),
            1,
            "the budget bounded the tick; one record waits for the next"
        );
        // The next tick clears the remainder.
        assert_eq!(pacer.tick(1_700_000_001_000).await.unwrap(), 0);
        assert_eq!(evidence_records(&spools), 0);
    }

    #[tokio::test]
    async fn interleaved_unpublishable_records_still_publish_one_frame_per_tick() {
        // A skip does not buy a second frame: with unpublishable records between findings, each
        // tick still publishes exactly one finding.
        let (spools, identities, config, metrics, _dir) = harness();
        append_event(&spools, &escalation_event());
        append_event(&spools, &finding_event("f0", "execution", "LOW"));
        append_event(&spools, &escalation_event());
        append_event(&spools, &finding_event("f1", "execution", "LOW"));
        append_event(&spools, &escalation_event());

        let mut pacer = Pacer::new(
            Arc::clone(&spools),
            identities,
            config,
            "c".into(),
            metrics,
            Recording {
                frames: vec![],
                answer: OkOutcome::Accepted,
            },
        );

        assert_eq!(
            pacer.tick(1_700_000_000_000).await.unwrap(),
            1,
            "the first finding, past the leading flood record"
        );
        assert_eq!(
            pacer.tick(1_700_000_001_000).await.unwrap(),
            1,
            "the second finding, past the record between them"
        );
        assert_eq!(
            pacer.tick(1_700_000_002_000).await.unwrap(),
            0,
            "only the trailing flood record remained"
        );
        assert_eq!(evidence_records(&spools), 0);
        assert_eq!(
            pacer.publisher().frames.len(),
            2,
            "exactly one frame per publishing tick"
        );
    }
}
