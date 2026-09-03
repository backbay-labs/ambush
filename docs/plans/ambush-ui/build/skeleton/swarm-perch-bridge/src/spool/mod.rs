//! The spool: what stands between the receive loop and every blocking thing.
//!
//! Two implementations behind one [`Spool`] trait:
//!
//! - [`DiskSpool`] — a segmented append-only log with a committed-offset cursor. `fsync` on
//!   segment roll, never per record. Survives a bridge crash and a relay outage; on restart the
//!   pacer resumes from the cursor. Used by [`Stream::Evidence`] and [`Stream::Alarm`].
//! - [`MemorySpool`] — one slot per key, overwrite-on-write. Used by [`Stream::Telemetry`], for
//!   the reasons in `11-BRIDGE-CRATE.md` section 5.1.
//!
//! **The spool holds UNSIGNED bodies.** `created_at` is stamped and the envelope signed in the
//! pacer, at publish time, so nothing here is a signed artifact and the spool is not a second
//! record.

pub mod checksum;
pub mod segment;

use std::path::PathBuf;

use swarm_runtime::runtime_events::RuntimeEvent;

use crate::error::BridgeError;
use crate::stream::Stream;

/// Per-`(colony_id, issuer)` monotonic sequence. Assigned **at spool append**, never at publish.
///
/// At append, because the two losses that matter happen on opposite sides of the spool: an
/// eviction must renumber nothing, or it would hide itself.
///
/// What it proves: no envelope from this issuer, *after the bridge saw it*, is missing.
/// What it does not prove: that the daemon did not drop something before the bridge saw it. The
/// only signal for that is [`GapCause::BroadcastLagged`], and no copy anywhere may imply
/// otherwise.
pub type Seq = u64;

/// Index into the identity table. One byte on disk; the table is at most ten entries.
pub type IssuerIdx = u8;

/// One spooled item. Payload is `serde_json` of a redacted `RuntimeEvent`, or a containment-lease
/// diff.
#[derive(Debug, Clone)]
pub struct Record {
    pub seq: Seq,
    /// The **domain** timestamp, straight off the event
    /// (`swarm-runtime/src/runtime_events.rs:308-322`). Every Perch surface sorts and renders on
    /// this; `created_at` is a transport timestamp and is stamped 1,000 ms to 68 minutes later.
    pub emitted_at_ms: i64,
    pub issuer: IssuerIdx,
    pub flags: RecordFlags,
    pub payload: Vec<u8>,
}

impl Record {
    /// `seq` and `issuer` are filled by the spool on append; this constructor leaves them zero.
    pub fn from_event(event: &RuntimeEvent) -> Self {
        let _ = event;
        todo!("serde_json::to_vec(event); emitted_at_ms = event.emitted_at_ms()")
    }
}

/// One byte of record flags. No dependency; the set is closed and tiny.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecordFlags(pub u8);

impl RecordFlags {
    /// The payload is a lease diff (`swarm_response::ContainmentLease`) rather than a
    /// `RuntimeEvent`. There is no `RuntimeEvent` for a containment lease opening, so the lease
    /// poll writes into the same evidence spool with this bit set.
    pub const LEASE_DIFF: u8 = 0b0000_0001;

    pub const fn is_lease_diff(self) -> bool {
        self.0 & Self::LEASE_DIFF != 0
    }
}

/// Why content is missing. Three causes, named apart, because the operator's correct reaction to
/// each is different (`11-BRIDGE-CRATE.md` section 3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GapCause {
    /// The 1,024-slot broadcast overran before the bridge saw the events. The bridge knows the
    /// **count only** — never which events, never a `seq` range.
    BroadcastLagged { count: u64 },
    /// The disk spool hit its budget and unlinked its oldest segment, or a torn tail was
    /// truncated on recovery. The range is exact.
    SpoolEvicted { from_seq: Seq, to_seq: Seq },
    /// A signed frame aged past the relay's ±900 s `created_at` window while in flight and could
    /// not be re-sent without re-stamping (`buzz-relay/src/handlers/ingest.rs:2224-2231`).
    PublishWindowExpired { from_seq: Seq, to_seq: Seq },
}

/// A pending gap awaiting a carrier card.
///
/// Persisted **inside the affected stream's cursor file**, deliberately: the one thing that must
/// survive a crash is the record that something did not.
#[derive(Debug, Clone, Default)]
pub struct GapSlot {
    pub pending: Vec<GapCause>,
    /// Ticks since the pacer last emitted anything for this stream. At
    /// `PERCH_GAP_FLUSH_TICKS` the pacer emits a **gap-only card**: same marker, same schema,
    /// populated `gap` block, empty payload array. Without this a loss followed by silence would
    /// never publish its gap.
    pub idle_ticks: u32,
}

/// What the pacer drains, and what the spool promises.
pub trait Spool: Send {
    /// Appends. MUST NOT block on a syscall that can wait on a disk: the caller is the receive
    /// loop and its whole budget is 281 ms of broadcast head room.
    fn append(&mut self, record: Record) -> Result<Seq, BridgeError>;

    /// Reads forward from the committed cursor without advancing it, up to `max_bytes`.
    fn peek(&mut self, max_bytes: usize) -> Result<Vec<Record>, BridgeError>;

    /// Advances the committed cursor. Called ONLY after the relay's `OK true` — never on send.
    fn commit_through(&mut self, seq: Seq) -> Result<(), BridgeError>;

    /// Records a gap and returns it for carriage on the next card.
    fn mark_gap(&mut self, cause: GapCause);

    /// Takes and clears the pending gap set.
    fn take_gaps(&mut self) -> Vec<GapCause>;

    fn bytes(&self) -> u64;
}

/// The set of spools, one per stream, with the classification-time routing.
pub struct SpoolSet {
    _private: (),
}

impl SpoolSet {
    /// Opens or creates every disk spool under `root/{colony_id}/{stream}/`.
    ///
    /// `root` MUST resolve outside the workspace. `tools/check-worktree-clean.sh` runs
    /// `if: always()` after the CI test job and asserts on `git status --porcelain` **and** on a
    /// `find` over known store roots — `find` was chosen because it "is immune to .gitignore and
    /// does see empty directories" (`check-worktree-clean.sh:31-35`). A spool that defaults into
    /// `crates/` fails the clean-tree contract on the first test run and blames the test suite.
    pub fn open(root: PathBuf, colony_id: &str) -> Result<Self, BridgeError> {
        let _ = (root, colony_id);
        todo!("refuse a root under the workspace; open evidence+alarm DiskSpool, build MemorySpool")
    }

    pub fn append(&mut self, stream: Stream, record: Record) -> Result<Seq, BridgeError> {
        let _ = (stream, record);
        todo!("route to the per-stream spool; DroppedAtSource appends nothing and only counts")
    }

    /// A broadcast lag is recorded against every disk-spooled stream: the events are gone and
    /// their discriminants were never observed, so the bridge cannot attribute the loss.
    pub fn mark_gap_all_disk_spooled(&mut self, cause: GapCause) {
        let _ = cause;
        todo!("mark_gap on evidence and alarm")
    }
}
