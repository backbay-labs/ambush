//! Segment file format, rotation, and crash recovery.
//!
//! ```text
//! SEGMENT HEADER -- 48 bytes, written at create, fsynced with the file's first roll
//!   0  ..  8   magic          b"PERCHSPL"
//!   8  .. 10   format_version u16 le   = 1
//!  10  .. 11   stream          u8      = 1 evidence | 3 alarm  (2 telemetry never lands here)
//!  11  .. 12   reserved        u8      = 0
//!  12  .. 20   first_seq       u64 le
//!  20  .. 28   created_at_ms   i64 le
//!  28  .. 44   colony_hash    [u8;16]  first 16 bytes of sha256(colony_id)
//!  44  .. 48   header_crc      u32 le  CRC-32C over bytes 0..44
//!
//! RECORD -- variable, appended, never rewritten
//!   0  ..  4   len             u32 le  length of `payload`
//!   4  ..  8   crc             u32 le  CRC-32C over bytes 8..(26+len)
//!   8  .. 16   seq             u64 le
//!  16  .. 24   emitted_at_ms   i64 le
//!  24  .. 25   issuer_idx       u8
//!  25  .. 26   flags            u8
//!  26  ..(26+len) payload
//! ```

use std::path::{Path, PathBuf};

use crate::error::BridgeError;
use crate::spool::{Record, Seq};

pub const MAGIC: &[u8; 8] = b"PERCHSPL";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 48;
pub const RECORD_PREFIX_BYTES: usize = 26;

/// Roll when the active segment reaches this. 32 segments per 256 MiB budget, so eviction
/// granularity is 1/32 of the budget -- coarse enough that eviction is rare, fine enough that one
/// eviction is not a quarter of the history. PROPOSED; no measurement behind it.
pub const DEFAULT_SEGMENT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentHeader {
    pub format_version: u16,
    pub stream: u8,
    pub first_seq: Seq,
    pub created_at_ms: i64,
    /// First 16 bytes of `sha256(colony_id)`. A mismatch refuses to open: a spool directory shared
    /// between two colonies would merge two `seq` namespaces and produce a *false continuity*,
    /// which `07-REALTIME-AND-DATA.md` section 11 names as the worse of the two failures.
    pub colony_hash: [u8; 16],
}

impl SegmentHeader {
    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        todo!("little-endian pack, then CRC-32C over bytes 0..44 into 44..48")
    }

    /// # Errors
    /// [`BridgeError::SpoolBadMagic`], [`BridgeError::SpoolUnknownFormat`],
    /// [`BridgeError::SpoolColonyMismatch`].
    pub fn decode(bytes: &[u8], expect_colony_hash: &[u8; 16]) -> Result<Self, BridgeError> {
        let _ = (bytes, expect_colony_hash);
        todo!("verify magic, version, header_crc, colony_hash")
    }
}

/// What a recovery scan concluded about a segment's tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailVerdict {
    /// Every record decoded. `last_seq` is the highest present.
    Clean { last_seq: Seq, end_offset: u64 },
    /// A record's `len` ran past EOF, or its CRC failed, at the very end of the file. That is a
    /// torn tail from a crash -- expected, because the spool fsyncs on roll and not per record.
    /// The segment is truncated here and the burned range becomes a
    /// [`crate::spool::GapCause::SpoolEvicted`]: from the operator's point of view a torn tail
    /// and an eviction are the same fact, content the bridge accepted and cannot deliver.
    TornTail {
        last_valid_seq: Seq,
        truncate_at: u64,
        burned: (Seq, Seq),
    },
    /// A CRC failed in the MIDDLE of the file, with valid records after it. That is corruption,
    /// not a crash. The segment is renamed `*.seg.corrupt`, the whole range becomes a gap, and
    /// the bridge continues -- refusing to start over one bad segment would take the console down
    /// for a disk problem that has already cost only its oldest history.
    Corrupt { range: (Seq, Seq) },
}

pub struct Segment {
    _private: (),
}

impl Segment {
    /// Creates `{dir}/{first_seq:020}.seg` and writes the header.
    pub fn create(dir: &Path, header: SegmentHeader) -> Result<Self, BridgeError> {
        let _ = (dir, header);
        todo!("create_new, write header, keep the file handle open for append")
    }

    /// Opens an existing segment and scans it forward from `from_offset`.
    pub fn open_and_scan(
        path: &Path,
        expect_colony_hash: &[u8; 16],
        from_offset: u64,
    ) -> Result<(Self, TailVerdict), BridgeError> {
        let _ = (path, expect_colony_hash, from_offset);
        todo!("decode header; loop decode_record; classify the tail")
    }

    /// Appends. Buffered write into the page cache -- **no fsync here**. A per-record fsync is a
    /// syscall with a disk round trip inside the receive loop's 281 ms budget, which is the whole
    /// reason the spool exists.
    pub fn append(&mut self, record: &Record) -> Result<u64, BridgeError> {
        let _ = record;
        todo!("pack prefix + payload, write, return the new end offset")
    }

    /// Flushes and fsyncs. Called on roll and on graceful shutdown only.
    pub fn seal(&mut self) -> Result<(), BridgeError> {
        todo!("flush + File::sync_all")
    }

    pub fn bytes(&self) -> u64 {
        todo!("cached end offset")
    }
}

/// Lists a stream's segments oldest-first. Names are `{first_seq:020}.seg`, so lexicographic
/// order is numeric order for every `u64` -- which is why the padding is 20 digits and not 16.
pub fn list_segments(dir: &Path) -> Result<Vec<PathBuf>, BridgeError> {
    let _ = dir;
    todo!("read_dir, filter *.seg, sort by file name")
}
