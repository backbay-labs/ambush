//! The pacer: one frame per identity per tick, `created_at` stamped at drain.
//!
//! Written fresh rather than ported. Buzz's `ObserverPublishQueue` is private
//! (`struct ObserverPublishQueue` at `BUZZ crates/buzz-acp/src/lib.rs:440`, no `pub`) inside a
//! crate `02-ARCHITECTURE-INTEGRATION.md` section 5 deletes outright, and vendoring it a second
//! time would carry a NOTICE obligation, a dependency-bill line, and the same
//! `unwrap_used`/`expect_used` problem as the ws client. What we take is the *specification*,
//! which `buzz-acp` states in prose and which is cited inline below.

use std::time::Duration;

use crate::spool::{GapCause, Record};

/// `APPENDIX-NORMATIVE.md` section 6. Proposed.
///
/// The invariant, from `BUZZ crates/buzz-acp/src/lib.rs:382-394`: *"AT MOST ONE relay frame per
/// tick -- not one per channel, and not one per drain... At 1 frame/s telemetry spends at most
/// 60/min -- half that budget"*. This is the structural answer to the relay's 120/min quota: it is
/// not a measurement that might drift, it is the loop's shape.
pub const PERCH_PUBLISH_TICK_MS: u64 = 1_000;

/// `APPENDIX-NORMATIVE.md` section 6. Proposed.
///
/// Mirrors `OBSERVER_MAX_PLAINTEXT_LEN = 65_535` (`BUZZ crates/buzz-core/src/observer.rs:25`).
/// Sits under both `DEFAULT_MAX_FRAME_BYTES = 512 KiB`
/// (`BUZZ crates/buzz-relay/src/config.rs:14`) and `MAX_EVENT_CONTENT_BYTES = 256 KB`
/// (`BUZZ crates/buzz-relay/src/handlers/ingest.rs:2233-2240`), so a full frame is never a
/// protocol risk.
pub const PERCH_FRAME_MAX_BYTES: usize = 64 * 1024;

/// Ticks of silence on a stream holding a pending gap before the pacer emits a **gap-only card**:
/// same marker, same schema, populated `gap` block, empty payload array. Without this, a loss
/// followed by silence would never publish its gap. PROPOSED; three ticks is the smallest value
/// that does not race a busy stream's own next card.
pub const PERCH_GAP_FLUSH_TICKS: u32 = 3;

/// `created_at` vs `emitted_at_ms` disagreement, in ticks, past which the card is marked
/// `late-published`. INVENTED -- `APPENDIX-NORMATIVE.md` section 6 records it as such, and it
/// stays invented until somebody measures a real spool drain.
pub const PERCH_LATE_PUBLISHED_TICKS: i64 = 2;

/// Slack against the relay's +/-900 s `created_at` window for a frame already signed and in
/// flight. Sized so a clock skew inside the +/-30 s warning band cannot push a frame over the
/// edge. PROPOSED.
pub const PERCH_PUBLISH_WINDOW_MARGIN_SECS: i64 = 120;

/// A packed, stamped, signed frame ready for the socket.
pub struct Frame {
    pub identity: u8,
    /// `None` for a global ephemeral (`26000`-`26006` carry no `h`); `Some` for a lane or case
    /// channel card.
    pub channel: Option<uuid::Uuid>,
    /// The signed Nostr event, JSON. Retried **byte-identically**: the event id is a hash over
    /// `(pubkey, created_at, kind, tags, content)`, and the relay's insert is
    /// `ON CONFLICT DO NOTHING` (`BUZZ crates/buzz-db/src/store/event.rs`, inside
    /// `insert_event_with_thread_metadata_tx`, ON CONFLICT DO NOTHING at `:1193`), so an identical resend is a no-op.
    pub signed: Vec<u8>,
    pub event_id: String,
    /// Advanced on `OK true` only.
    pub covers: (crate::spool::Seq, crate::spool::Seq),
    pub created_at_secs: i64,
}

pub struct Pacer {
    _private: (),
}

impl Pacer {
    /// Runs until shutdown.
    ///
    /// `MissedTickBehavior::Delay`, not the default `Burst`. A pacer that catches up after a stall
    /// fires N ticks back to back and hands the relay N frames inside one second -- exactly the
    /// shape that trips the 50-frames-per-5-second `WsEvents` budget
    /// (`BUZZ crates/buzz-relay/src/connection.rs:671-681` x
    /// `BUZZ crates/buzz-relay/src/admission.rs:9,40-45`) and turns a stall into a rate-limit
    /// window.
    pub async fn run(self) {
        let _ = Duration::from_millis(PERCH_PUBLISH_TICK_MS);
        todo!("interval with MissedTickBehavior::Delay; biased select over shutdown and tick")
    }

    /// One tick: coalesce, pack, stamp, sign, hand to the publisher.
    async fn tick(&mut self) {
        todo!("for each identity: pack_front_run -> stamp_and_sign -> publisher.submit")
    }

    /// Greedy over the **front run of one `(identity, channel)`**, never a global scan.
    ///
    /// The specification and its rationale, from `buzz-acp`'s `next_frame`
    /// (`BUZZ crates/buzz-acp/src/lib.rs:551-585`): it takes `self.events.front()`'s `channel_id`
    /// and gathers only that channel's run. *"A front-run packer degrades to one event per slot
    /// under round-robin producers; a channel-scan packer starves the tail."* Buzz learned that;
    /// we do not re-learn it, and we do not copy the code to inherit it.
    ///
    /// Perch keys the run on `(identity, channel)` rather than channel alone: evidence cards are
    /// attributed per agent, and two agents writing to the same lane must not be packed into one
    /// frame signed by one of them.
    fn pack_front_run(&mut self, identity: u8) -> Option<(Option<uuid::Uuid>, Vec<Record>)> {
        let _ = (identity, PERCH_FRAME_MAX_BYTES);
        todo!("peek; take the front run; stop at the byte cap; always yield at least one record")
    }

    /// Stamps `created_at` from the daemon's clock, immediately before signing.
    ///
    /// **Forced, not preferred.** `MAX_TIMESTAMP_DRIFT_SECS` is 900 s and it REJECTS
    /// (`BUZZ crates/buzz-relay/src/handlers/ingest.rs:2224-2231`:
    /// `if (event_ts - now).abs() > MAX_TIMESTAMP_DRIFT_SECS { return Err(... "invalid: event
    /// timestamp too far from server time") }`), and `created_at` is inside the Nostr signature,
    /// so a spooled card carrying its true emit time in `created_at` becomes permanently
    /// unpublishable fifteen minutes after it was produced and cannot be corrected without
    /// re-signing. A 68-minute spool under that design would drain fifteen minutes of backlog and
    /// then reject every remaining frame, one at a time, forever.
    ///
    /// So: `created_at` is a **transport** timestamp and the copy calls it one. `emitted_at_ms` in
    /// the body is the domain timestamp and every Perch surface sorts on it. When they disagree by
    /// more than [`PERCH_LATE_PUBLISHED_TICKS`], the body carries `late_published_ms` and the
    /// console renders `late-published -- held in the bridge spool 22 min`.
    fn stamp_and_sign(
        &self,
        identity: u8,
        channel: Option<uuid::Uuid>,
        records: Vec<Record>,
        gaps: Vec<GapCause>,
    ) -> Frame {
        let _ = (identity, channel, records, gaps);
        todo!("build the card body incl. gap/coalesced blocks; stamp created_at; sign; observe \
               perch_bridge_late_published_seconds")
    }

    /// Emitted when a stream holds a pending gap and has produced nothing for
    /// [`PERCH_GAP_FLUSH_TICKS`] ticks. Same marker, same schema, empty payload array.
    ///
    /// `13-WIRE-SCHEMAS.md` must therefore NOT set `minItems: 1` on any card's payload array.
    fn flush_gap_only_card(&self, identity: u8, gaps: Vec<GapCause>) -> Frame {
        let _ = (identity, gaps);
        todo!("card with an empty payload array and a populated gap block")
    }
}
