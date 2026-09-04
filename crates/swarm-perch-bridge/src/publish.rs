//! The relay write path: one supervised socket per identity, typed OK classification, backoff.

use std::time::Duration;

use ambush_ws_client::{NostrWsConnection, WsClientError};

use crate::error::BridgeError;
use crate::identity::Identity;
use crate::pacer::{Frame, FramePublisher, PERCH_PUBLISH_WINDOW_MARGIN_SECS};

/// The alarm stream may exceed one frame per second when a case is provisioned, so this bounds
/// it. A hold costs at most five frames (`9007` + P x `9000` + kind:9 + `46010` + `26006`,
/// P = 1 in the shipped default), so 40/min is eight new cases per minute -- well above anything
/// a single-analyst deployment produces -- and it leaves 80/min of the alarm identity's 120/min
/// quota unspent. PROPOSED. Overridable by `perch.alarm_burst_per_min`.
pub const PERCH_ALARM_BURST_PER_MIN: u32 = 40;

/// The burst window the cap is measured over: one minute, sliding.
pub const PERCH_ALARM_BURST_WINDOW_MS: i64 = 60_000;

/// A sliding one-minute admission window for `kind:26006`.
///
/// # Why the alarm needs a cap at all when it also bypasses the pacer
///
/// The pacer's one-frame-per-tick shape is the structural answer to the relay's 120/min quota,
/// and the alarm deliberately steps outside it: the <= 400 ms end-to-end budget rides the
/// `26006`, and a frame that waits for a tick has already spent 1000 ms of it. But "outside the
/// pacer" with no bound is an unbounded firehose. `enforce_ws_admission` charges EVERY inbound
/// frame against 50 per rolling 5 seconds per pubkey with no agent exemption, so a burst of
/// alarms does not merely delay itself -- it rate-limits the `9007`, the card and the notice
/// behind it, and the durable record an operator is being paged about never arrives.
///
/// Past the cap an alarm is DEFERRED, never dropped: the spool record stays at its head, the
/// routing ledger still has no alarm entry for that hold, and the next tick re-plans it.
#[derive(Debug, Clone)]
pub struct AlarmBurst {
    per_min: u32,
    admitted: std::collections::VecDeque<i64>,
}

impl AlarmBurst {
    /// A window admitting `per_min` frames per rolling minute.
    ///
    /// `per_min == 0` admits nothing, which is what a deployment that set it to zero asked for;
    /// the deferral counter makes that visible rather than silent.
    #[must_use]
    pub fn new(per_min: u32) -> Self {
        Self {
            per_min,
            admitted: std::collections::VecDeque::new(),
        }
    }

    /// Admits one frame at `now_ms`, or refuses it because the window is full.
    ///
    /// Refusing records nothing, so a deferred alarm does not consume the slot it was refused.
    pub fn try_admit(&mut self, now_ms: i64) -> bool {
        self.expire(now_ms);
        if self.admitted.len() >= self.per_min as usize {
            return false;
        }
        self.admitted.push_back(now_ms);
        true
    }

    /// How many frames the window currently holds.
    pub fn in_window(&mut self, now_ms: i64) -> usize {
        self.expire(now_ms);
        self.admitted.len()
    }

    /// The cap this window enforces.
    #[must_use]
    pub const fn per_min(&self) -> u32 {
        self.per_min
    }

    /// Drops every admission older than the window. A clock that went backwards keeps its
    /// entries rather than clearing the window, because clearing it would turn a clock jump into
    /// an unbounded burst.
    fn expire(&mut self, now_ms: i64) {
        let floor = now_ms.saturating_sub(PERCH_ALARM_BURST_WINDOW_MS);
        while self
            .admitted
            .front()
            .is_some_and(|admitted| *admitted <= floor)
        {
            self.admitted.pop_front();
        }
    }
}

/// What one alarm submission did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlarmAdmission {
    /// The frame went to the socket outside the tick, with the relay's answer.
    Sent(OkOutcome),
    /// The burst window is full. Nothing was sent, the frame is unchanged, and the caller keeps
    /// its spool record for a later tick. DEFERRED, NEVER DROPPED.
    Deferred,
}

/// The relay's `MAX_TIMESTAMP_DRIFT_SECS`. A frame whose `created_at` is further than this from
/// the relay's clock is rejected, and `created_at` is inside the Nostr signature.
pub const RELAY_TIMESTAMP_DRIFT_SECS: i64 = 900;

/// First backoff step; doubles per attempt.
const BACKOFF_BASE_MS: u64 = 500;
/// Ceiling on the doubling.
const BACKOFF_CAP_SECS: u64 = 30;
/// What a clock disagreement backs off to. Nothing this identity publishes will be accepted until
/// somebody fixes a clock, so retrying at the socket cadence is pure noise.
const CLOCK_SKEW_BACKOFF_SECS: u64 = 3_600;

/// One socket per identity, supervised.
///
/// `rate_limit_key` is `ambush:{community}:ratelimit:{pubkey}:{suffix}`, so quotas are per-pubkey
/// and identity count IS capacity. Ten identities at 1 Hz is 600 EVENT/min spread over ten
/// pubkeys, each allowed 120/min.
pub struct ConnectionSupervisor {
    relay_url: String,
    identity: Identity,
    conn: Option<NostrWsConnection>,
    attempt: u32,
    alarm_burst: AlarmBurst,
}

impl ConnectionSupervisor {
    /// A supervisor that has not connected yet. The first [`FramePublisher::publish`] dials.
    pub fn new(relay_url: String, identity: Identity) -> Self {
        Self {
            relay_url,
            identity,
            conn: None,
            attempt: 0,
            alarm_burst: AlarmBurst::new(PERCH_ALARM_BURST_PER_MIN),
        }
    }

    /// Overrides the alarm burst cap from `perch.alarm_burst_per_min`.
    #[must_use]
    pub fn with_alarm_burst(mut self, per_min: u32) -> Self {
        self.alarm_burst = AlarmBurst::new(per_min);
        self
    }

    /// The slot this supervisor signs for.
    pub fn slot_label(&self) -> &str {
        self.identity.slot.label()
    }

    /// Whether a socket is currently established.
    pub const fn is_connected(&self) -> bool {
        self.conn.is_some()
    }

    /// Connects and performs NIP-42 AUTH with the identity's `auth_tag`.
    ///
    /// Sleeps for [`backoff_for`] before a retry, so a relay outage costs one socket attempt per
    /// backoff window rather than one per pacer tick.
    ///
    /// # Errors
    ///
    /// [`BridgeError::RelayUnreachable`] carrying the attempt count and the next delay.
    pub async fn connect(&mut self) -> Result<(), BridgeError> {
        if self.conn.is_some() {
            return Ok(());
        }
        if self.attempt > 0 {
            tokio::time::sleep(backoff_for(self.attempt, &OkOutcome::Accepted)).await;
        }
        match NostrWsConnection::connect_authenticated(
            &self.relay_url,
            &self.identity.keys,
            self.identity.auth_tag.as_ref(),
        )
        .await
        {
            Ok(conn) => {
                self.conn = Some(conn);
                self.attempt = 0;
                tracing::info!(
                    module = module_path!(),
                    slot = self.identity.slot.label(),
                    relay = %self.relay_url,
                    "perch bridge socket authenticated"
                );
                Ok(())
            }
            Err(error) => {
                self.attempt = self.attempt.saturating_add(1);
                let retry_in = backoff_for(self.attempt, &OkOutcome::Accepted);
                tracing::warn!(
                    module = module_path!(),
                    slot = self.identity.slot.label(),
                    attempt = self.attempt,
                    reason = %error,
                    "perch bridge cannot reach the relay"
                );
                Err(BridgeError::RelayUnreachable {
                    attempt: self.attempt,
                    retry_in,
                })
            }
        }
    }

    /// Turns an `OK false` message into a typed outcome. Every arm is a row in
    /// `11-BRIDGE-CRATE.md` section 12.
    pub fn classify_ok(accepted: bool, message: &str) -> OkOutcome {
        if accepted {
            return OkOutcome::Accepted;
        }
        // `duplicate: channel already exists` is SUCCESS, not an error. kind:9007 with a
        // client-supplied UUID calls `create_channel_with_id`, whose
        // `INSERT ... ON CONFLICT (community_id, id) DO NOTHING` yields `was_created = false` and
        // the relay answers with this string.
        if message.starts_with("duplicate: channel already exists") {
            return OkOutcome::ChannelAlreadyExists;
        }
        // Redis outage. `check_principal` returns `AdmissionError::Unavailable` and
        // `send_admission_result` rejects the frame. The string carries NO `retry in Ns` hint, so
        // the desktop gate would fall back to `DEFAULT_RATE_LIMIT_SECONDS = 10`. The bridge uses
        // its own exponential backoff and the console renders this as a DISTINCT state -- never
        // as "relay unreachable", and never as "connected".
        if message.contains("shared admission unavailable") {
            return OkOutcome::AdmissionUnavailable;
        }
        if message.starts_with("rate-limited") {
            return OkOutcome::RateLimited {
                retry_in_secs: parse_retry_hint(message),
            };
        }
        // The relay fork is not applied: `required_scope_for_kind`'s default arm is
        // `_ => Err("restricted: unknown event kind")`. The hold stream is dead until
        // `10-RELAY-FORK.md` lands. Logged at error NAMING that document.
        if message.starts_with("restricted: unknown event kind") {
            return OkOutcome::RelayForkAbsent;
        }
        // The membership precondition a channel-scoped 46010 newly acquires: 46010 is not in the
        // relay's `skip_membership` list, so `check_channel_membership` refuses a non-member.
        if message.starts_with("restricted: not a channel member") {
            return OkOutcome::NotAChannelMember;
        }
        // P0. `MAX_TIMESTAMP_DRIFT_SECS` is 900 s and it rejects. If this fires on a freshly
        // stamped frame, the bridge and the relay disagree about the time and nothing this
        // identity publishes will be accepted.
        if message.starts_with("invalid: event timestamp too far") {
            return OkOutcome::ClockSkew;
        }
        OkOutcome::Rejected {
            message: message.to_string(),
        }
    }
}

impl FramePublisher for ConnectionSupervisor {
    async fn submit_alarm(
        &mut self,
        frame: &Frame,
        now_ms: i64,
    ) -> Result<AlarmAdmission, BridgeError> {
        if !self.alarm_burst.try_admit(now_ms) {
            return Ok(AlarmAdmission::Deferred);
        }
        // No tick wait: the frame goes straight to this identity's socket. That is the whole
        // point of the alarm lane, and `publish` is already a direct write -- what the pacer
        // adds is the once-per-tick cadence the drainer's loop imposes on the steps around it.
        self.publish(frame).await.map(AlarmAdmission::Sent)
    }

    async fn publish(&mut self, frame: &Frame) -> Result<OkOutcome, BridgeError> {
        self.connect().await?;
        let Some(conn) = self.conn.as_mut() else {
            return Err(BridgeError::RelayUnreachable {
                attempt: self.attempt,
                retry_in: backoff_for(self.attempt, &OkOutcome::Accepted),
            });
        };
        match conn.send_event(frame.signed.clone()).await {
            Ok(ok) => {
                let outcome = Self::classify_ok(ok.accepted, &ok.message);
                if let OkOutcome::ClockSkew = outcome {
                    tracing::error!(
                        module = module_path!(),
                        slot = self.identity.slot.label(),
                        created_at = frame.created_at_secs,
                        message = %ok.message,
                        "the relay refused a freshly stamped frame as out of its timestamp \
                         window; the bridge and the relay disagree about the time"
                    );
                }
                Ok(outcome)
            }
            // The OK never arrived. The socket may still be healthy and the event may still have
            // been stored, so the frame is kept for a byte-identical resend rather than re-signed.
            Err(WsClientError::Timeout) => Err(BridgeError::Ws(WsClientError::Timeout)),
            Err(error) => {
                self.conn = None;
                self.attempt = self.attempt.saturating_add(1);
                Err(BridgeError::Ws(error))
            }
        }
    }
}

/// The relay's answer to one submitted event, typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OkOutcome {
    /// Stored, or already stored.
    Accepted,
    /// kind:9007 for a channel that already exists. Success for an idempotent provisioning step.
    ChannelAlreadyExists,
    /// The relay's shared admission backend is down. An infrastructure state, not a quota.
    AdmissionUnavailable,
    /// Over quota, with the relay's own hint when it carried one.
    RateLimited {
        /// Seconds the relay asked for, clamped at 300.
        retry_in_secs: Option<u64>,
    },
    /// The relay does not know this kind: the relay fork is not applied.
    RelayForkAbsent,
    /// The publisher is not a member of the channel the `h` tag names.
    NotAChannelMember,
    /// The relay refused the `created_at` stamp as outside its ±900 s window.
    ClockSkew,
    /// Anything else, with the relay's own message.
    Rejected {
        /// The relay's message, verbatim.
        message: String,
    },
}

impl OkOutcome {
    /// The `reason` label value for `perch_bridge_admission_rejections_total`.
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::ChannelAlreadyExists => "channel_already_exists",
            Self::AdmissionUnavailable => "admission_unavailable",
            Self::RateLimited { .. } => "rate_limited",
            Self::RelayForkAbsent => "relay_fork_absent",
            Self::NotAChannelMember => "not_a_channel_member",
            Self::ClockSkew => "clock_skew",
            Self::Rejected { .. } => "rejected",
        }
    }

    /// Whether the frame's records may be committed.
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Accepted | Self::ChannelAlreadyExists)
    }
}

/// What to do with a frame whose OK never arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryDecision {
    /// Re-send the identical signed bytes.
    ResendIdentical,
    /// The 900 s window is closing. Return the records to the spool head and re-stamp.
    RestampFromSpool,
}

/// Retry policy for a frame whose OK never arrived.
///
/// Retry the **identical signed bytes** while
/// `now - created_at < 900 - PERCH_PUBLISH_WINDOW_MARGIN_SECS`. The event id is a hash over
/// `(pubkey, created_at, kind, tags, content)` and the relay's insert is
/// `ON CONFLICT DO NOTHING`, so an identical resend is a no-op.
///
/// Past that: discard the signed frame, return its records to the spool head, let the pacer
/// re-stamp and re-sign next tick. The re-signed frame is a NEW event id, so if the original
/// was in fact accepted the relay now holds two rows for the same facts. That is what the
/// margin exists to make rare, and why the discard is counted as
/// `perch_bridge_dropped_events_total{cause="publish_window_expired"}` and recorded as a
/// [`crate::spool::GapCause::PublishWindowExpired`].
///
/// One consequence worth stating separately: a retry does **not** repair a missing mention row.
/// `insert_mentions` is called only on the first insert of an event id.
pub fn retry_decision(frame: &Frame, now_secs: i64) -> RetryDecision {
    if now_secs - frame.created_at_secs
        < RELAY_TIMESTAMP_DRIFT_SECS - PERCH_PUBLISH_WINDOW_MARGIN_SECS
    {
        RetryDecision::ResendIdentical
    } else {
        RetryDecision::RestampFromSpool
    }
}

/// Parses the relay's `retry in Ns` hint, clamped at 300 seconds.
///
/// A relay that asks for longer than five minutes is asking for longer than the pacer's whole
/// publish window, so the clamp is what keeps a hint from becoming an outage.
fn parse_retry_hint(message: &str) -> Option<u64> {
    let after = message.split("retry in ").nth(1)?;
    let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse::<u64>().ok().map(|secs| secs.min(300))
}

/// The bridge issues **zero** `REQ` and **zero** `COUNT` frames. Ever.
///
/// `enforce_ws_admission` charges `LimitType::WsEvents` on every inbound EVENT, REQ and COUNT
/// frame, with a budget of `human_ws_events_per_sec` (10) x `WS_BURST_WINDOW_SECS` (5) = 50
/// frames per rolling 5 s and **no agent exemption**.
///
/// A write-only bridge spends at most 5 of those 50 per window -- 10% -- leaving 90% to absorb an
/// alarm burst. It learns everything it needs from OK responses on frames it sent: a duplicate
/// channel, a missing fork, a clock skew, a membership refusal all arrive that way.
///
/// This function exists so the commitment is greppable, and it is asserted by test T-9.
pub const fn bridge_issues_no_req_frames() -> bool {
    true
}

/// Backoff for a socket that cannot connect or is being rejected wholesale.
///
/// Exponential from 500 ms, capped at 30 s, jittered by `attempt % 7 * 100` ms so a fleet of
/// daemons does not reconnect in lockstep. `AdmissionUnavailable` doubles the base because it is
/// an infrastructure outage rather than a quota, and `ClockSkew` does not retry on this curve at
/// all: nothing this identity publishes will be accepted until a clock is fixed.
pub fn backoff_for(attempt: u32, outcome: &OkOutcome) -> Duration {
    if matches!(outcome, OkOutcome::ClockSkew) {
        return Duration::from_secs(CLOCK_SKEW_BACKOFF_SECS);
    }
    if let OkOutcome::RateLimited {
        retry_in_secs: Some(secs),
    } = outcome
    {
        return Duration::from_secs(*secs);
    }
    let base = if matches!(outcome, OkOutcome::AdmissionUnavailable) {
        BACKOFF_BASE_MS * 2
    } else {
        BACKOFF_BASE_MS
    };
    let doubled = base.saturating_mul(1u64 << attempt.min(16));
    let capped = doubled.min(BACKOFF_CAP_SECS * 1_000);
    Duration::from_millis(capped + u64::from(attempt % 7) * 100)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::spool::Seq;

    fn frame_created_at(created_at_secs: i64) -> Frame {
        let keys = nostr::Keys::generate();
        let signed = nostr::EventBuilder::new(nostr::Kind::Custom(9), "x")
            .custom_created_at(nostr::Timestamp::from(created_at_secs as u64))
            .sign_with_keys(&keys)
            .unwrap();
        Frame {
            identity: 0,
            channel: None,
            event_id: signed.id.to_hex(),
            signed,
            covers: (0, 1 as Seq),
            created_at_secs,
        }
    }

    /// T-9: the write-only commitment, asserted from the source of EVERY module.
    ///
    /// The plan lists the files to scan by name and has each later task append its own. A walk
    /// over `src/` is the same assertion without the per-task edit, and it covers a module
    /// somebody adds without reading this test — which is the case the list cannot cover.
    #[test]
    fn the_bridge_never_sends_a_req_or_count_frame() {
        assert!(bridge_issues_no_req_frames());
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut scanned = 0usize;
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                assert!(
                    !source.contains("\"REQ\"") && !source.contains("\"COUNT\""),
                    "{} builds a relay read frame; the bridge is write-only",
                    path.display()
                );
                scanned += 1;
            }
        }
        assert!(
            scanned >= 12,
            "the walk found only {scanned} modules; it cannot have covered the crate"
        );
    }

    #[test]
    fn retry_is_byte_identical_inside_the_window_and_restamps_after_it() {
        let frame = frame_created_at(1_700_000_000);
        assert_eq!(
            retry_decision(&frame, 1_700_000_000 + 779),
            RetryDecision::ResendIdentical
        );
        assert_eq!(
            retry_decision(&frame, 1_700_000_000 + 780),
            RetryDecision::RestampFromSpool
        );
    }

    #[test]
    fn every_relay_refusal_the_bridge_knows_has_its_own_arm() {
        assert_eq!(
            ConnectionSupervisor::classify_ok(true, ""),
            OkOutcome::Accepted
        );
        assert_eq!(
            ConnectionSupervisor::classify_ok(false, "duplicate: channel already exists"),
            OkOutcome::ChannelAlreadyExists
        );
        assert_eq!(
            ConnectionSupervisor::classify_ok(false, "error: shared admission unavailable"),
            OkOutcome::AdmissionUnavailable
        );
        assert_eq!(
            ConnectionSupervisor::classify_ok(false, "rate-limited: retry in 12s"),
            OkOutcome::RateLimited {
                retry_in_secs: Some(12)
            }
        );
        assert_eq!(
            ConnectionSupervisor::classify_ok(false, "rate-limited: slow down"),
            OkOutcome::RateLimited {
                retry_in_secs: None
            }
        );
        assert_eq!(
            ConnectionSupervisor::classify_ok(false, "restricted: unknown event kind 46010"),
            OkOutcome::RelayForkAbsent
        );
        assert_eq!(
            ConnectionSupervisor::classify_ok(false, "restricted: not a channel member"),
            OkOutcome::NotAChannelMember
        );
        assert_eq!(
            ConnectionSupervisor::classify_ok(false, "invalid: event timestamp too far from now"),
            OkOutcome::ClockSkew
        );
        assert_eq!(
            ConnectionSupervisor::classify_ok(false, "blocked"),
            OkOutcome::Rejected {
                message: "blocked".to_string()
            }
        );
        // Every arm has a distinct metric label, so a dashboard split names the actual failure.
        let reasons = [
            OkOutcome::Accepted.reason(),
            OkOutcome::ChannelAlreadyExists.reason(),
            OkOutcome::AdmissionUnavailable.reason(),
            OkOutcome::RateLimited {
                retry_in_secs: None,
            }
            .reason(),
            OkOutcome::RelayForkAbsent.reason(),
            OkOutcome::NotAChannelMember.reason(),
            OkOutcome::ClockSkew.reason(),
            OkOutcome::Rejected {
                message: String::new(),
            }
            .reason(),
        ];
        assert_eq!(
            reasons
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            reasons.len()
        );
    }

    #[test]
    fn the_alarm_burst_admits_exactly_the_cap_per_rolling_minute() {
        // The cap is PROVED, not trusted to the constant: the window admits `per_min` and
        // refuses the next, and refusing consumes no slot -- otherwise a burst of refusals
        // would push admissions out of the window and let a later flood through.
        const START: i64 = 1_773_738_882_600;
        let mut burst = AlarmBurst::new(PERCH_ALARM_BURST_PER_MIN);
        for index in 0..PERCH_ALARM_BURST_PER_MIN {
            assert!(
                burst.try_admit(START + i64::from(index)),
                "frame {index} inside the cap must be admitted"
            );
        }
        assert_eq!(burst.in_window(START + 100), 40);
        for _ in 0..500 {
            assert!(
                !burst.try_admit(START + 100),
                "past the cap the window refuses"
            );
        }
        assert_eq!(
            burst.in_window(START + 100),
            40,
            "a refusal consumes no slot"
        );
        // The window is SLIDING, not a fixed bucket: the first admission ages out one minute
        // after it was made and exactly one slot reopens.
        assert!(burst.try_admit(START + PERCH_ALARM_BURST_WINDOW_MS));
        assert!(!burst.try_admit(START + PERCH_ALARM_BURST_WINDOW_MS));
        // Once the whole window has passed, the full cap is available again.
        let far = START + PERCH_ALARM_BURST_WINDOW_MS * 4;
        assert_eq!(burst.in_window(far), 0);
        for _ in 0..PERCH_ALARM_BURST_PER_MIN {
            assert!(burst.try_admit(far));
        }
        assert!(!burst.try_admit(far));
    }

    #[test]
    fn a_backwards_clock_does_not_reopen_the_burst_window() {
        // Clearing the window on a backwards clock would turn an NTP step into an unbounded
        // burst on the one frame that bypasses the pacer.
        const START: i64 = 1_773_738_882_600;
        let mut burst = AlarmBurst::new(3);
        for offset in 0..3 {
            assert!(burst.try_admit(START + offset));
        }
        assert!(!burst.try_admit(START - 3_600_000));
        assert_eq!(burst.in_window(START - 3_600_000), 3);
    }

    #[test]
    fn a_zero_cap_defers_everything_rather_than_dropping_it() {
        let mut burst = AlarmBurst::new(0);
        assert_eq!(burst.per_min(), 0);
        assert!(!burst.try_admit(1));
        assert_eq!(burst.in_window(1), 0);
    }

    #[test]
    fn a_retry_hint_is_parsed_and_clamped() {
        assert_eq!(parse_retry_hint("rate-limited: retry in 9s"), Some(9));
        assert_eq!(parse_retry_hint("rate-limited: retry in 9000s"), Some(300));
        assert_eq!(parse_retry_hint("rate-limited"), None);
        assert_eq!(parse_retry_hint("rate-limited: retry in soon"), None);
    }

    #[test]
    fn backoff_grows_is_capped_and_treats_an_outage_apart_from_a_quota() {
        let first = backoff_for(1, &OkOutcome::Accepted);
        let later = backoff_for(4, &OkOutcome::Accepted);
        assert!(later > first, "{later:?} !> {first:?}");
        assert!(backoff_for(30, &OkOutcome::Accepted) <= Duration::from_millis(30_600));
        assert!(
            backoff_for(1, &OkOutcome::AdmissionUnavailable) > backoff_for(1, &OkOutcome::Accepted),
            "an infrastructure outage backs off slower than a plain failure"
        );
        assert_eq!(
            backoff_for(1, &OkOutcome::ClockSkew),
            Duration::from_secs(CLOCK_SKEW_BACKOFF_SECS)
        );
        assert_eq!(
            backoff_for(
                1,
                &OkOutcome::RateLimited {
                    retry_in_secs: Some(7)
                }
            ),
            Duration::from_secs(7),
            "the relay's own hint wins over the curve"
        );
    }
}
