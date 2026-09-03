//! The relay write path: one supervised socket per identity, an OK reaper, and backoff.

use std::time::Duration;

use crate::error::BridgeError;
use crate::pacer::Frame;
use crate::ws::NostrWsConnection;

/// The alarm stream bypasses the pacer to meet the <=400 ms budget on the `26006` frame
/// (`APPENDIX-NORMATIVE.md` section 4), so it is the one stream that can exceed 1 frame/s. This
/// bounds it. A hold costs at most four frames (`9007` + P x `9000` + `46010` + `26006`, P = 1 in
/// the shipped default), so 40/min is ten new cases per minute -- an order of magnitude above
/// anything a single-analyst deployment produces -- and it leaves 80/min of the alarm identity's
/// 120/min quota unspent. Excess spills to the pacer with `perch_bridge_alarm_deferred_total`
/// incremented; it is never dropped. PROPOSED.
pub const PERCH_ALARM_BURST_PER_MIN: u32 = 40;

/// One socket per identity, supervised.
///
/// `rate_limit_key` is `buzz:{community}:ratelimit:{pubkey}:{suffix}`
/// (`BUZZ crates/buzz-auth/src/rate_limit.rs:167-172`), so quotas are per-pubkey and identity
/// count IS capacity. Ten identities at 1 Hz is 600 EVENT/min spread over ten pubkeys, each
/// allowed 120/min.
pub struct ConnectionSupervisor {
    _private: (),
}

impl ConnectionSupervisor {
    /// Connects, performs NIP-42 AUTH with the identity's `auth_tag`, and spawns the reaper.
    ///
    /// Retries with exponential backoff. See [`Self::classify_ok`] for why one particular
    /// rejection gets its own backoff curve.
    pub async fn connect(&mut self, identity: u8) -> Result<NostrWsConnection, BridgeError> {
        let _ = identity;
        todo!("ws::connect; authenticate(keys, auth_tag); split; spawn the reaper")
    }

    /// Submits a frame. Returns immediately; the reaper resolves the OK.
    ///
    /// **`send_event` is deliberately not used.** It is strictly serial -- send, then
    /// `wait_for_ok` up to `PUBLISH_OK_TIMEOUT_SECS = 30`
    /// (`BUZZ crates/buzz-ws-client/src/connection.rs:96-101`, `:23`). One in-flight event per
    /// connection is an RTT-bound ceiling we cannot afford even at 1 Hz across ten identities.
    /// The bridge uses `send_raw` (`connection.rs:121-126`, already `pub`) plus a separate reaper
    /// task that owns the read half and resolves in-flight frames by event id.
    pub async fn submit(&mut self, frame: Frame) -> Result<(), BridgeError> {
        let _ = frame;
        todo!("send_raw([\"EVENT\", signed]); record in-flight keyed by event_id with a deadline")
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
    /// One consequence worth stating separately: a retry does **not** repair a missing mention
    /// row. `insert_mentions` is called only under `if result.1`
    /// (`BUZZ crates/buzz-db/src/store/event.rs:1690`), i.e. only on the first insert.
    pub fn retry_decision(&self, frame: &Frame, now_secs: i64) -> RetryDecision {
        let _ = (frame, now_secs);
        todo!("compare now_secs - frame.created_at_secs against 900 - margin")
    }

    /// Turns an `OK false` message into a typed outcome. Every arm is a row in
    /// `11-BRIDGE-CRATE.md` section 12.
    pub fn classify_ok(accepted: bool, message: &str) -> OkOutcome {
        if accepted {
            return OkOutcome::Accepted;
        }
        // `duplicate: channel already exists` is SUCCESS, not an error. kind:9007 with a
        // client-supplied UUID calls `create_channel_with_id`
        // (`BUZZ crates/buzz-db/src/store/channel.rs:171-263`), whose
        // `INSERT ... ON CONFLICT (community_id, id) DO NOTHING` yields `was_created = false` and
        // the relay answers with this string at `ingest.rs:2879-2884`.
        if message.starts_with("duplicate: channel already exists") {
            return OkOutcome::ChannelAlreadyExists;
        }
        // Redis outage. `check_principal` returns `AdmissionError::Unavailable`
        // (`BUZZ crates/buzz-relay/src/admission.rs:33-36`) and `send_admission_result` rejects
        // the frame (`connection.rs:728-735`). The string carries NO `retry in Ns` hint, so the
        // desktop gate would fall back to `DEFAULT_RATE_LIMIT_SECONDS = 10`
        // (`BUZZ desktop/src/shared/api/relayRateLimitGate.ts:15`). The bridge uses its own
        // exponential backoff and the console renders this as a DISTINCT state -- never as
        // "relay unreachable", and never as "connected".
        if message.contains("shared admission unavailable") {
            return OkOutcome::AdmissionUnavailable;
        }
        if message.starts_with("rate-limited") {
            return OkOutcome::RateLimited {
                retry_in_secs: parse_retry_hint(message),
            };
        }
        // The relay fork is not applied: `required_scope_for_kind`'s default arm at
        // `BUZZ crates/buzz-relay/src/handlers/ingest.rs:545` is
        // `_ => Err("restricted: unknown event kind")`. The hold stream is dead until
        // `10-RELAY-FORK.md` lands. Log at error NAMING that document.
        if message.starts_with("restricted: unknown event kind") {
            return OkOutcome::RelayForkAbsent;
        }
        // The membership precondition a channel-scoped 46010 newly acquires
        // (`ingest.rs:2509-2552` -> `check_channel_membership` at `:742-772`; 46010 is not in the
        // skip list at `:2517-2522`).
        if message.starts_with("restricted: not a channel member") {
            return OkOutcome::NotAChannelMember;
        }
        // P0. `MAX_TIMESTAMP_DRIFT_SECS` is 900 s and rejects (`ingest.rs:2224-2231`). If this
        // fires on a freshly stamped frame, the bridge and the relay disagree about the time and
        // nothing this identity publishes will be accepted.
        if message.starts_with("invalid: event timestamp too far") {
            return OkOutcome::ClockSkew;
        }
        OkOutcome::Rejected {
            message: message.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OkOutcome {
    Accepted,
    ChannelAlreadyExists,
    AdmissionUnavailable,
    RateLimited { retry_in_secs: Option<u64> },
    RelayForkAbsent,
    NotAChannelMember,
    ClockSkew,
    Rejected { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryDecision {
    /// Re-send the identical signed bytes.
    ResendIdentical,
    /// The 900 s window is closing. Return the records to the spool head and re-stamp.
    RestampFromSpool,
}

fn parse_retry_hint(message: &str) -> Option<u64> {
    let _ = message;
    todo!("parse `retry in Ns`; clamp at 300 s; never shrink an active window")
}

/// The bridge issues **zero** `REQ` and **zero** `COUNT` frames. Ever.
///
/// `enforce_ws_admission` charges `LimitType::WsEvents` on every inbound `EVENT`, `REQ` and
/// `COUNT` (`BUZZ crates/buzz-relay/src/connection.rs:652-685`), with a budget of
/// `human_ws_events_per_sec` (10) x `WS_BURST_WINDOW_SECS` (5) = 50 frames per rolling 5 s and
/// **no agent exemption**. `buzz-touchpoints.md` records that no plan document budgets REQ frames
/// against this counter.
///
/// A write-only bridge spends at most 5 of those 50 per window -- 10% -- leaving 90% to absorb an
/// alarm burst. It learns everything it needs from `OK` responses on frames it sent: a duplicate
/// channel, a missing fork, a clock skew, a membership refusal all arrive that way.
///
/// This function exists so the commitment is greppable, and it is asserted by test T-9.
pub const fn bridge_issues_no_req_frames() -> bool {
    true
}

/// Backoff for a socket that cannot connect or is being rejected wholesale.
pub fn backoff_for(attempt: u32, outcome: &OkOutcome) -> Duration {
    let _ = (attempt, outcome);
    todo!("exponential with jitter; AdmissionUnavailable gets its own slower curve because it is \
           an infrastructure outage rather than a quota, and ClockSkew does not retry at all")
}
