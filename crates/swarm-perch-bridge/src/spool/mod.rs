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

pub mod chain_heads;
pub mod checksum;
pub mod cursor;
pub mod segment;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use swarm_runtime::runtime_events::RuntimeEvent;

use crate::error::BridgeError;
use crate::spool::cursor::Cursor;
use crate::spool::segment::{
    HEADER_BYTES, Segment, SegmentHeader, TailVerdict, list_segments, read_records_from,
};
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
    /// Assigned by [`Spool::append`]; zero on a freshly built record.
    pub seq: Seq,
    /// The **domain** timestamp, straight off the event
    /// (`swarm-runtime/src/runtime_events.rs`). Every Perch surface sorts and renders on
    /// this; `created_at` is a transport timestamp and is stamped 1,000 ms to 68 minutes later.
    pub emitted_at_ms: i64,
    /// Which identity slot signs the card built from this record.
    pub issuer: IssuerIdx,
    /// One byte of record flags.
    pub flags: RecordFlags,
    /// The serialized, already-redacted body.
    pub payload: Vec<u8>,
}

impl Record {
    /// Serializes a redacted `RuntimeEvent` into a record for `issuer`.
    ///
    /// `seq` is left zero: it is assigned by [`Spool::append`], which is the only place that
    /// knows the issuer's run.
    ///
    /// # Errors
    ///
    /// [`BridgeError::Encode`] when the event does not serialize, which for a `RuntimeEvent` can
    /// only happen if a non-finite float reached one of its `f64` fields.
    pub fn from_event(event: &RuntimeEvent, issuer: IssuerIdx) -> Result<Self, BridgeError> {
        let payload =
            serde_json::to_vec(event).map_err(|error| BridgeError::Encode(error.to_string()))?;
        Ok(Self {
            seq: 0,
            emitted_at_ms: event.emitted_at_ms(),
            issuer,
            flags: RecordFlags::default(),
            payload,
        })
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

    /// Whether [`Self::LEASE_DIFF`] is set.
    pub const fn is_lease_diff(self) -> bool {
        self.0 & Self::LEASE_DIFF != 0
    }
}

/// Why content is missing. Four causes, named apart, because the operator's correct reaction to
/// each is different (`11-BRIDGE-CRATE.md` section 3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapCause {
    /// The 1,024-slot broadcast overran before the bridge saw the events. The bridge knows the
    /// **count only** — never which events, never a `seq` range.
    BroadcastLagged {
        /// How many events the broadcast dropped.
        count: u64,
    },
    /// The disk spool hit its budget and unlinked its oldest segment. The range is exact.
    SpoolEvicted {
        /// First lost seq, inclusive.
        from_seq: Seq,
        /// Last lost seq, inclusive.
        to_seq: Seq,
    },
    /// A segment ended in a torn record and recovery truncated it. Named apart from
    /// [`Self::SpoolEvicted`] because the metric label set names `spool_torn_tail` separately,
    /// and because a torn tail is a crash while an eviction is a budget.
    SpoolTornTail {
        /// First burned seq, inclusive.
        from_seq: Seq,
        /// Last burned seq, inclusive.
        to_seq: Seq,
    },
    /// A signed frame aged past the relay's ±900 s `created_at` window while in flight and could
    /// not be re-sent without re-stamping.
    PublishWindowExpired {
        /// First affected seq, inclusive.
        from_seq: Seq,
        /// Last affected seq, inclusive.
        to_seq: Seq,
    },
}

impl GapCause {
    /// The `cause` label value, matching the wire's `GapBlockCause` spelling.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::BroadcastLagged { .. } => "broadcast_lagged",
            Self::SpoolEvicted { .. } => "spool_evicted",
            Self::SpoolTornTail { .. } => "spool_torn_tail",
            Self::PublishWindowExpired { .. } => "publish_window_expired",
        }
    }
}

/// A pending gap awaiting a carrier card.
///
/// Persisted **inside the affected stream's cursor file**, deliberately: the one thing that must
/// survive a crash is the record that something did not.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GapSlot {
    /// Losses not yet carried by a published card.
    #[serde(default)]
    pub pending: Vec<GapCause>,
    /// Ticks since the pacer last emitted anything for this stream. At
    /// `PERCH_GAP_FLUSH_TICKS` the pacer would emit a **gap-only card**; this milestone carries
    /// gaps on the next real card only (`crate::pacer`), and the counter is kept because the
    /// escalation producer that needs it lands in Operator-complete.
    #[serde(default)]
    pub idle_ticks: u32,
}

/// What the pacer drains, and what the spool promises.
pub trait Spool: Send {
    /// Appends. MUST NOT block on a syscall that can wait on a disk: the caller is the receive
    /// loop and its whole budget is 281 ms of broadcast head room.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] on a write failure, [`BridgeError::AlarmSpoolFull`] when an alarm
    /// spool is at its budget (alarm work is never shed).
    fn append(&mut self, record: Record) -> Result<Seq, BridgeError>;

    /// Reads forward from the committed cursor without advancing it, up to `max_bytes` of
    /// payload. Always yields at least one record when one is uncommitted.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when a segment cannot be read.
    fn peek(&mut self, max_bytes: usize) -> Result<Vec<Record>, BridgeError>;

    /// Advances the committed cursor for one issuer. Called ONLY after the relay's `OK true` —
    /// never on send.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the cursor cannot be persisted.
    fn commit(&mut self, issuer: IssuerIdx, seq: Seq) -> Result<(), BridgeError>;

    /// Records a gap for carriage on the next card.
    fn mark_gap(&mut self, cause: GapCause);

    /// Takes and clears the pending gap set.
    fn take_gaps(&mut self) -> Vec<GapCause>;

    /// Bytes currently held.
    fn bytes(&self) -> u64;
}

/// First sixteen bytes of `sha256(colony_id)`. Two colonies sharing a spool directory would merge
/// two `seq` namespaces and produce a false continuity.
fn colony_hash(colony_id: &str) -> [u8; 16] {
    let digest = Sha256::digest(colony_id.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// A path component derived from a colony id: anything outside `[A-Za-z0-9._-]` becomes `_`.
/// The header's `colony_hash` is what actually enforces the namespace; this only keeps the
/// directory name printable and portable.
fn colony_dir_component(colony_id: &str) -> String {
    let mapped: String = colony_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if mapped.is_empty() {
        "colony".to_string()
    } else {
        mapped
    }
}

/// A segmented append-only log for one stream.
#[derive(Debug)]
pub struct DiskSpool {
    dir: PathBuf,
    stream: Stream,
    colony_hash: [u8; 16],
    segment_bytes: u64,
    max_bytes: u64,
    active: Segment,
    /// Sealed segments, oldest first.
    sealed: Vec<PathBuf>,
    cursor: Cursor,
    bytes: u64,
    next_ordinal: u64,
}

impl DiskSpool {
    /// Opens or creates `dir/{stream}`, recovering every segment it finds.
    ///
    /// Recovery applies each [`TailVerdict`]: a torn tail is truncated and recorded as
    /// [`GapCause::SpoolTornTail`]; a mid-file corruption renames the segment to `*.seg.corrupt`
    /// and records [`GapCause::SpoolEvicted`] over its whole readable range; a header from
    /// another colony refuses the open outright.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`], [`BridgeError::SpoolBadMagic`],
    /// [`BridgeError::SpoolUnknownFormat`], [`BridgeError::SpoolColonyMismatch`].
    pub fn open(
        dir: &Path,
        colony_id: &str,
        stream: Stream,
        segment_bytes: u64,
        max_bytes: u64,
    ) -> Result<Self, BridgeError> {
        let dir = dir.join(stream.as_str());
        std::fs::create_dir_all(&dir).map_err(|error| BridgeError::SpoolIo {
            path: dir.display().to_string(),
            source: error,
        })?;
        let colony_hash = colony_hash(colony_id);
        let mut cursor = Cursor::load(&dir)?;

        let mut sealed: Vec<PathBuf> = Vec::new();
        let mut bytes = 0u64;
        let mut next_ordinal = 0u64;
        let mut recovered_next_seq: BTreeMap<IssuerIdx, Seq> = BTreeMap::new();
        let mut last_clean: Option<(PathBuf, u64)> = None;

        for path in list_segments(&dir)? {
            let report = Segment::scan(&path, &colony_hash, |_, _| {})?;
            next_ordinal = next_ordinal.max(report.header.ordinal + 1);
            for (issuer, (_, hi)) in &report.seq_ranges {
                let entry = recovered_next_seq.entry(*issuer).or_insert(1);
                *entry = (*entry).max(hi + 1);
            }
            match report.verdict {
                TailVerdict::Clean { end_offset } => {
                    bytes += end_offset;
                    if let Some((previous, _)) = last_clean.replace((path.clone(), end_offset)) {
                        sealed.push(previous);
                    }
                }
                TailVerdict::TornTail {
                    truncate_at,
                    burned,
                    burned_issuer,
                } => {
                    let file = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .map_err(|error| BridgeError::SpoolIo {
                            path: path.display().to_string(),
                            source: error,
                        })?;
                    file.set_len(truncate_at)
                        .map_err(|error| BridgeError::SpoolIo {
                            path: path.display().to_string(),
                            source: error,
                        })?;
                    if let Some(issuer) = burned_issuer {
                        let entry = recovered_next_seq.entry(issuer).or_insert(1);
                        *entry = (*entry).max(burned.1 + 1);
                    }
                    cursor.mark_gap(GapCause::SpoolTornTail {
                        from_seq: burned.0,
                        to_seq: burned.1,
                    });
                    bytes += truncate_at;
                    if let Some((previous, _)) = last_clean.replace((path.clone(), truncate_at)) {
                        sealed.push(previous);
                    }
                }
                TailVerdict::Corrupt { at: _, range } => {
                    let quarantined = path.with_extension("seg.corrupt");
                    std::fs::rename(&path, &quarantined).map_err(|error| BridgeError::SpoolIo {
                        path: path.display().to_string(),
                        source: error,
                    })?;
                    cursor.mark_gap(GapCause::SpoolEvicted {
                        from_seq: range.0,
                        to_seq: range.1,
                    });
                }
            }
        }

        // The scan is authoritative for `next_seq`; a cursor that claims a higher value is
        // honoured, because a fully drained and evicted run leaves no segment to recover from.
        for (issuer, seq) in &cursor.next_seq {
            let entry = recovered_next_seq.entry(*issuer).or_insert(1);
            *entry = (*entry).max(*seq);
        }
        cursor.next_seq = recovered_next_seq;

        let active = match last_clean {
            Some((path, end)) => {
                let report = Segment::scan(&path, &colony_hash, |_, _| {})?;
                Segment::open_for_append(&path, &report, end)?
            }
            None => {
                let header = SegmentHeader {
                    format_version: segment::FORMAT_VERSION,
                    stream: stream.disk_code(),
                    ordinal: next_ordinal,
                    created_at_ms: now_ms(),
                    colony_hash,
                };
                next_ordinal += 1;
                bytes += HEADER_BYTES as u64;
                Segment::create(&dir, header)?
            }
        };

        cursor.store(&dir)?;

        Ok(Self {
            dir,
            stream,
            colony_hash,
            segment_bytes,
            max_bytes,
            active,
            sealed,
            cursor,
            bytes,
            next_ordinal,
        })
    }

    /// Flushes and fsyncs the active segment. Called on graceful shutdown.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the flush or fsync fails.
    pub fn seal(&mut self) -> Result<(), BridgeError> {
        self.active.seal()?;
        self.cursor.store(&self.dir)
    }

    /// The stream this spool holds.
    pub const fn stream(&self) -> Stream {
        self.stream
    }

    /// Next seq this spool would assign to `issuer`.
    pub fn next_seq(&self, issuer: IssuerIdx) -> Seq {
        self.cursor.next_seq.get(&issuer).copied().unwrap_or(1)
    }

    fn roll(&mut self) -> Result<(), BridgeError> {
        self.active.seal()?;
        self.sealed.push(self.active.path().to_path_buf());
        let header = SegmentHeader {
            format_version: segment::FORMAT_VERSION,
            stream: self.stream.disk_code(),
            ordinal: self.next_ordinal,
            created_at_ms: now_ms(),
            colony_hash: self.colony_hash,
        };
        self.next_ordinal += 1;
        self.active = Segment::create(&self.dir, header)?;
        self.bytes += HEADER_BYTES as u64;
        self.cursor.store(&self.dir)
    }

    /// Unlinks whole sealed segments, oldest first, while the budget is exceeded. Evidence only:
    /// alarm work is refused at append rather than shed.
    fn evict_to_budget(&mut self) -> Result<(), BridgeError> {
        while self.bytes > self.max_bytes && !self.sealed.is_empty() {
            let path = self.sealed.remove(0);
            let report = Segment::scan(&path, &self.colony_hash, |_, _| {})?;
            let size = std::fs::metadata(&path)
                .map(|meta| meta.len())
                .unwrap_or_default();
            std::fs::remove_file(&path).map_err(|error| BridgeError::SpoolIo {
                path: path.display().to_string(),
                source: error,
            })?;
            self.bytes = self.bytes.saturating_sub(size);
            let lo = report.seq_ranges.values().map(|(lo, _)| *lo).min();
            let hi = report.seq_ranges.values().map(|(_, hi)| *hi).max();
            if let (Some(from_seq), Some(to_seq)) = (lo, hi) {
                self.cursor
                    .mark_gap(GapCause::SpoolEvicted { from_seq, to_seq });
            }
        }
        self.cursor.store(&self.dir)
    }

    fn is_committed(&self, record: &Record) -> bool {
        self.cursor
            .committed
            .get(&record.issuer)
            .is_some_and(|committed| record.seq <= *committed)
    }
}

impl Spool for DiskSpool {
    fn append(&mut self, mut record: Record) -> Result<Seq, BridgeError> {
        if self.stream == Stream::Alarm && self.bytes >= self.max_bytes {
            return Err(BridgeError::AlarmSpoolFull {
                bytes: self.bytes,
                max_bytes: self.max_bytes,
            });
        }
        let seq = self.next_seq(record.issuer);
        record.seq = seq;
        let end = self.active.append(&record)?;
        self.bytes += (segment::RECORD_PREFIX_BYTES + record.payload.len()) as u64;
        self.cursor.next_seq.insert(record.issuer, seq + 1);
        if end >= self.segment_bytes {
            self.roll()?;
            if self.stream != Stream::Alarm {
                self.evict_to_budget()?;
            }
        }
        Ok(seq)
    }

    fn peek(&mut self, max_bytes: usize) -> Result<Vec<Record>, BridgeError> {
        let mut paths = self.sealed.clone();
        paths.push(self.active.path().to_path_buf());
        let mut out: Vec<Record> = Vec::new();
        let mut budget = 0usize;
        for path in paths {
            for (record, _) in read_records_from(&path, HEADER_BYTES as u64)? {
                if self.is_committed(&record) {
                    continue;
                }
                let size = record.payload.len();
                if !out.is_empty() && budget.saturating_add(size) > max_bytes {
                    return Ok(out);
                }
                budget = budget.saturating_add(size);
                out.push(record);
            }
        }
        Ok(out)
    }

    fn commit(&mut self, issuer: IssuerIdx, seq: Seq) -> Result<(), BridgeError> {
        let entry = self.cursor.committed.entry(issuer).or_insert(0);
        *entry = (*entry).max(seq);
        self.cursor.store(&self.dir)
    }

    fn mark_gap(&mut self, cause: GapCause) {
        self.cursor.mark_gap(cause);
        // Best effort: a gap that cannot be persisted is still carried in memory, and the
        // failure surfaces on the next commit, which is the write that must not be lost.
        let _ = self.cursor.store(&self.dir);
    }

    fn take_gaps(&mut self) -> Vec<GapCause> {
        let taken = self.cursor.take_gaps();
        if !taken.is_empty() {
            let _ = self.cursor.store(&self.dir);
        }
        taken
    }

    fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// One slot per key, overwrite-on-write. The telemetry stream's home.
///
/// Last-wins at depth 1 is lossless in meaning for a gauge-shaped ephemeral, and a replayed
/// ephemeral is a lie about "now", so nothing here is durable by design.
#[derive(Debug, Default)]
pub struct MemorySpool {
    slots: BTreeMap<String, Record>,
    gaps: Vec<GapCause>,
}

impl MemorySpool {
    /// An empty spool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Overwrites the slot at `key`.
    pub fn put(&mut self, key: impl Into<String>, record: Record) {
        self.slots.insert(key.into(), record);
    }

    /// Takes every slot, leaving the spool empty.
    pub fn drain(&mut self) -> Vec<(String, Record)> {
        std::mem::take(&mut self.slots).into_iter().collect()
    }

    /// Slots currently held.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether the spool holds nothing.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Records a gap.
    pub fn mark_gap(&mut self, cause: GapCause) {
        self.gaps.push(cause);
    }

    /// Takes and clears the pending gap set.
    pub fn take_gaps(&mut self) -> Vec<GapCause> {
        std::mem::take(&mut self.gaps)
    }

    /// Bytes currently held.
    pub fn bytes(&self) -> u64 {
        self.slots
            .values()
            .map(|record| record.payload.len() as u64)
            .sum()
    }
}

/// The set of spools, one per stream, with the classification-time routing.
#[derive(Debug)]
pub struct SpoolSet {
    evidence: DiskSpool,
    alarm: DiskSpool,
    telemetry: MemorySpool,
    /// Events classified [`Stream::DroppedAtSource`], counted and never stored.
    dropped_at_source: u64,
}

impl SpoolSet {
    /// Opens or creates every disk spool under `root/{colony_id}/{stream}/`.
    ///
    /// `root` MUST resolve outside the workspace. `tools/check-worktree-clean.sh` runs
    /// `if: always()` after the CI test job and asserts on `git status --porcelain` **and** on a
    /// `find` over known store roots — `find` was chosen because it is immune to `.gitignore` and
    /// does see empty directories. A spool that defaults into `crates/` fails the clean-tree
    /// contract on the first test run and blames the test suite.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolDirInsideWorkspace`] when `root` resolves under the repository or the
    /// process's working directory; otherwise every error [`DiskSpool::open`] can return.
    pub fn open(
        root: &Path,
        colony_id: &str,
        segment_bytes: u64,
        max_bytes: u64,
    ) -> Result<Self, BridgeError> {
        assert_outside_workspace(root)?;
        let dir = root.join(colony_dir_component(colony_id));
        Ok(Self {
            evidence: DiskSpool::open(&dir, colony_id, Stream::Evidence, segment_bytes, max_bytes)?,
            alarm: DiskSpool::open(&dir, colony_id, Stream::Alarm, segment_bytes, max_bytes)?,
            telemetry: MemorySpool::new(),
            dropped_at_source: 0,
        })
    }

    /// Routes a record to its stream's spool. `Ok(None)` for [`Stream::DroppedAtSource`], which
    /// stores nothing and only counts.
    ///
    /// # Errors
    ///
    /// Whatever [`Spool::append`] returns for the routed spool.
    /// The slot a telemetry record occupies, decoded from its own payload.
    ///
    /// A record whose payload does not decode, or whose event has no frame,
    /// lands in one shared `other` slot rather than being dropped: the spool's
    /// job is to hold the last of each thing, and silently discarding a record
    /// it could not classify would lose telemetry with nothing to show for it.
    fn telemetry_slot_key_for(record: &Record) -> &'static str {
        serde_json::from_slice::<swarm_runtime::runtime_events::RuntimeEvent>(&record.payload)
            .ok()
            .and_then(|event| crate::coalesce::telemetry_slot_key(&event))
            .unwrap_or("other")
    }

    pub fn append(&mut self, stream: Stream, record: Record) -> Result<Option<Seq>, BridgeError> {
        match stream {
            Stream::Evidence => self.evidence.append(record).map(Some),
            Stream::Alarm => self.alarm.append(record).map(Some),
            Stream::Telemetry => {
                // One slot per FRAME KIND, from `coalesce::telemetry_slot_key`
                // (W3-29). Not per issuer: keying by issuer makes two agents'
                // health reports evict each other, and 26002 is a list of
                // agents rather than one agent's row.
                //
                // The key is derived from the record's own payload rather than
                // taken as an argument, because the receive loop appends
                // without knowing what a frame is -- its whole discipline is
                // that it may not name the publisher side.
                let key = Self::telemetry_slot_key_for(&record).to_string();
                self.telemetry.put(key, record);
                Ok(None)
            }
            Stream::DroppedAtSource => {
                self.dropped_at_source = self.dropped_at_source.saturating_add(1);
                Ok(None)
            }
        }
    }

    /// A broadcast lag is recorded against every disk-spooled stream: the events are gone and
    /// their discriminants were never observed, so the bridge cannot attribute the loss.
    pub fn mark_gap_all_disk_spooled(&mut self, cause: GapCause) {
        self.evidence.mark_gap(cause.clone());
        self.alarm.mark_gap(cause);
    }

    /// The evidence spool.
    pub fn evidence(&mut self) -> &mut DiskSpool {
        &mut self.evidence
    }

    /// The alarm spool.
    pub fn alarm(&mut self) -> &mut DiskSpool {
        &mut self.alarm
    }

    /// The telemetry spool.
    pub fn telemetry(&mut self) -> &mut MemorySpool {
        &mut self.telemetry
    }

    /// Events classified [`Stream::DroppedAtSource`] since open.
    pub const fn dropped_at_source(&self) -> u64 {
        self.dropped_at_source
    }

    /// Bytes held by each disk spool, for the `perch_bridge_spool_bytes` gauge.
    pub fn disk_bytes(&self) -> [(Stream, u64); 2] {
        [
            (Stream::Evidence, self.evidence.bytes()),
            (Stream::Alarm, self.alarm.bytes()),
        ]
    }

    /// Flushes and fsyncs both disk spools. Called once, at graceful shutdown.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] from either spool.
    pub fn seal(&mut self) -> Result<(), BridgeError> {
        self.evidence.seal()?;
        self.alarm.seal()
    }
}

/// The repository root, as known at build time: two levels above this crate's manifest.
fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .unwrap_or(manifest)
        .to_path_buf()
}

/// Resolves `path` to an absolute, symlink-free form without requiring it to exist: the longest
/// existing ancestor is canonicalized and the remainder appended.
fn resolve_lexically(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    let mut existing = absolute.as_path();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(canonical) = existing.canonicalize() {
            let mut out = canonical;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                existing = parent;
            }
            _ => return absolute,
        }
    }
}

/// The Cargo checkout the process is running inside, if it is running inside one: the nearest
/// ancestor of the working directory that holds a `Cargo.toml`.
///
/// The run-time half of the check has to be this and not the working directory itself. CI runs
/// `cargo test` from the repository root, so a spool configured relative to a DIFFERENT checkout
/// still has to be caught — but `/var/lib/swarm/perch-spool` under a daemon started from
/// `/var/lib/swarm` is an ordinary deployment layout and refusing it would make the guard a bug.
/// A directory with no `Cargo.toml` above it is not a checkout and is not this crate's business.
fn runtime_checkout_root() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let mut candidate = cwd.as_path();
    loop {
        if candidate.join("Cargo.toml").is_file() {
            return Some(candidate.to_path_buf());
        }
        candidate = candidate.parent()?;
    }
}

/// Refuses a spool root inside this crate's own repository (known at build time) or inside the
/// Cargo checkout the process was started from (known at run time).
fn assert_outside_workspace(root: &Path) -> Result<(), BridgeError> {
    let resolved = resolve_lexically(root);
    let mut forbidden = vec![resolve_lexically(&workspace_root())];
    if let Some(checkout) = runtime_checkout_root() {
        forbidden.push(resolve_lexically(&checkout));
    }
    for base in forbidden {
        if resolved.starts_with(&base) {
            return Err(BridgeError::SpoolDirInsideWorkspace {
                path: root.display().to_string(),
            });
        }
    }
    Ok(())
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::stream::Stream;

    fn rec(issuer: IssuerIdx, payload: &[u8]) -> Record {
        Record {
            seq: 0,
            emitted_at_ms: 1_700_000_000_000,
            issuer,
            flags: RecordFlags::default(),
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn seq_is_assigned_at_append_per_issuer_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut spool =
                DiskSpool::open(dir.path(), "colony-a", Stream::Evidence, 1 << 20, 8 << 20)
                    .unwrap();
            assert_eq!(spool.append(rec(0, b"a")).unwrap(), 1);
            assert_eq!(spool.append(rec(1, b"b")).unwrap(), 1);
            assert_eq!(spool.append(rec(0, b"c")).unwrap(), 2);
            // dropped without seal(): the page cache is the only copy.
        }
        let mut spool =
            DiskSpool::open(dir.path(), "colony-a", Stream::Evidence, 1 << 20, 8 << 20).unwrap();
        let records = spool.peek(usize::MAX).unwrap();
        assert_eq!(
            records
                .iter()
                .map(|r| (r.issuer, r.seq))
                .collect::<Vec<_>>(),
            vec![(0, 1), (1, 1), (0, 2)]
        );
        assert_eq!(
            spool.append(rec(0, b"d")).unwrap(),
            3,
            "seq continues across a restart"
        );
    }

    #[test]
    fn commit_advances_and_peek_never_returns_committed_records() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool =
            DiskSpool::open(dir.path(), "c", Stream::Evidence, 1 << 20, 8 << 20).unwrap();
        for p in [b"1", b"2", b"3"] {
            spool.append(rec(0, p)).unwrap();
        }
        spool.commit(0, 2).unwrap();
        let left = spool.peek(usize::MAX).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].payload, b"3");
    }

    #[test]
    fn peek_respects_its_byte_budget_but_always_yields_one_record() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool =
            DiskSpool::open(dir.path(), "c", Stream::Evidence, 1 << 20, 8 << 20).unwrap();
        for _ in 0..3 {
            spool.append(rec(0, &[b'x'; 100])).unwrap();
        }
        assert_eq!(spool.peek(0).unwrap().len(), 1);
        assert_eq!(spool.peek(150).unwrap().len(), 1);
        assert_eq!(spool.peek(250).unwrap().len(), 2);
    }

    #[test]
    fn a_torn_tail_is_truncated_and_recorded_as_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut spool =
                DiskSpool::open(dir.path(), "c", Stream::Evidence, 1 << 20, 8 << 20).unwrap();
            spool.append(rec(0, b"whole")).unwrap();
            spool.append(rec(0, b"torn-away")).unwrap();
            spool.seal().unwrap();
        }
        // Chop the last 4 bytes of the only segment: a crash mid-write.
        let seg = segment::list_segments(&dir.path().join("evidence"))
            .unwrap()
            .pop()
            .unwrap();
        let bytes = std::fs::read(&seg).unwrap();
        std::fs::write(&seg, &bytes[..bytes.len() - 4]).unwrap();
        let mut spool =
            DiskSpool::open(dir.path(), "c", Stream::Evidence, 1 << 20, 8 << 20).unwrap();
        let records = spool.peek(usize::MAX).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].payload, b"whole");
        assert_eq!(
            spool.take_gaps(),
            vec![GapCause::SpoolTornTail {
                from_seq: 2,
                to_seq: 2
            }]
        );
        assert_eq!(
            spool.append(rec(0, b"next")).unwrap(),
            3,
            "the burned seq is never reused"
        );
    }

    #[test]
    fn a_spool_from_another_colony_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        DiskSpool::open(dir.path(), "colony-a", Stream::Evidence, 1 << 20, 8 << 20)
            .unwrap()
            .append(rec(0, b"x"))
            .unwrap();
        let err = DiskSpool::open(dir.path(), "colony-b", Stream::Evidence, 1 << 20, 8 << 20)
            .unwrap_err();
        assert!(
            matches!(err, BridgeError::SpoolColonyMismatch { .. }),
            "{err}"
        );
    }

    #[test]
    fn eviction_unlinks_the_oldest_segment_and_records_the_range() {
        let dir = tempfile::tempdir().unwrap();
        // 4 KiB segments, 8 KiB budget: the third segment evicts the first.
        let mut spool = DiskSpool::open(dir.path(), "c", Stream::Evidence, 4096, 8192).unwrap();
        let payload = vec![b'x'; 1000];
        for _ in 0..12 {
            spool
                .append(Record {
                    payload: payload.clone(),
                    ..rec(0, b"")
                })
                .unwrap();
        }
        let gaps = spool.take_gaps();
        assert!(
            matches!(
                gaps.first(),
                Some(GapCause::SpoolEvicted { from_seq: 1, .. })
            ),
            "{gaps:?}"
        );
        assert!(
            spool.bytes() <= 8192 + 4096,
            "budget is enforced at segment granularity: {}",
            spool.bytes()
        );
    }

    #[test]
    fn an_alarm_spool_refuses_rather_than_shedding() {
        let dir = tempfile::tempdir().unwrap();
        let mut spool = DiskSpool::open(dir.path(), "c", Stream::Alarm, 4096, 8192).unwrap();
        let payload = vec![b'x'; 1000];
        let mut refused = None;
        for _ in 0..24 {
            if let Err(error) = spool.append(Record {
                payload: payload.clone(),
                ..rec(0, b"")
            }) {
                refused = Some(error);
                break;
            }
        }
        let refused = refused.expect("the alarm spool must refuse once it is full");
        assert!(
            matches!(refused, BridgeError::AlarmSpoolFull { .. }),
            "{refused}"
        );
        assert!(
            spool.take_gaps().is_empty(),
            "alarm work is never shed, so it never produces an eviction gap"
        );
    }

    #[test]
    fn the_spool_root_may_not_be_inside_the_workspace() {
        let inside = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("spool-test");
        let err = SpoolSet::open(&inside, "c", 1 << 20, 8 << 20).unwrap_err();
        assert!(matches!(err, BridgeError::SpoolDirInsideWorkspace { .. }));
        // The build-time root is this crate's repository, two levels above its manifest.
        assert!(workspace_root().join("Cargo.toml").is_file());
        // ... and a root outside any checkout is accepted, because a daemon started from
        // /var/lib/swarm with its spool underneath is an ordinary deployment.
        let outside = tempfile::tempdir().unwrap();
        SpoolSet::open(outside.path(), "c", 1 << 20, 8 << 20).unwrap();
    }

    #[test]
    fn the_run_time_check_names_a_checkout_and_not_merely_the_working_directory() {
        // The tests run with the crate directory as the working directory, which IS inside a
        // checkout, so the nearest `Cargo.toml` above it must be found.
        let checkout = runtime_checkout_root().expect("the test process runs inside a checkout");
        assert!(checkout.join("Cargo.toml").is_file(), "{checkout:?}");
        // A temp directory has no `Cargo.toml` above it on any supported platform, so nothing
        // under it is refused on the run-time rule.
        let outside = tempfile::tempdir().unwrap();
        assert!(assert_outside_workspace(outside.path()).is_ok());
    }

    #[test]
    fn a_spool_set_routes_each_stream_to_its_own_home() {
        let dir = tempfile::tempdir().unwrap();
        let mut spools = SpoolSet::open(dir.path(), "c", 1 << 20, 8 << 20).unwrap();
        assert_eq!(
            spools.append(Stream::Evidence, rec(0, b"e")).unwrap(),
            Some(1)
        );
        assert_eq!(spools.append(Stream::Alarm, rec(0, b"a")).unwrap(), Some(1));
        assert_eq!(
            spools.append(Stream::Telemetry, rec(0, b"t")).unwrap(),
            None
        );
        assert_eq!(
            spools
                .append(Stream::DroppedAtSource, rec(0, b"d"))
                .unwrap(),
            None
        );
        assert_eq!(spools.dropped_at_source(), 1);
        assert_eq!(spools.telemetry().len(), 1);
        assert_eq!(spools.evidence().peek(usize::MAX).unwrap().len(), 1);
        assert_eq!(spools.alarm().peek(usize::MAX).unwrap().len(), 1);

        spools.mark_gap_all_disk_spooled(GapCause::BroadcastLagged { count: 3 });
        assert_eq!(
            spools.evidence().take_gaps(),
            vec![GapCause::BroadcastLagged { count: 3 }]
        );
        assert_eq!(
            spools.alarm().take_gaps(),
            vec![GapCause::BroadcastLagged { count: 3 }]
        );
    }

    #[test]
    fn a_record_carries_the_events_own_domain_timestamp() {
        let event: RuntimeEvent = serde_json::from_value(serde_json::json!({
            "event_type": "finding", "emitted_at_ms": 1_700_000_000_123i64, "host_id": "web-04",
            "finding": {"schema": "swarm_finding", "finding_id": "f1", "event_id": "e1",
                        "strategy_id": "s", "threat_class": "execution",
                        "severity": "LOW", "confidence": 0.1, "evidence": {}}
        }))
        .unwrap();
        let record = Record::from_event(&event, 3).unwrap();
        assert_eq!(record.emitted_at_ms, 1_700_000_000_123);
        assert_eq!(record.issuer, 3);
        assert_eq!(record.seq, 0, "seq is the spool's to assign");
        let round_trip: RuntimeEvent = serde_json::from_slice(&record.payload).unwrap();
        assert_eq!(round_trip.emitted_at_ms(), 1_700_000_000_123);
    }
}
