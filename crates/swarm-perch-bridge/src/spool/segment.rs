//! Segment file format, rotation, and crash recovery.
//!
//! ```text
//! SEGMENT HEADER -- 48 bytes, written at create, fsynced with the file's first roll
//!   0  ..  8   magic          b"PERCHSPL"
//!   8  .. 10   format_version u16 le   = 1
//!  10  .. 11   stream          u8      = 1 evidence | 3 alarm  (2 telemetry never lands here)
//!  11  .. 12   reserved        u8      = 0
//!  12  .. 20   ordinal         u64 le  the segment's position in the spool (names the file)
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
//!
//! # Why the header slot is an ordinal and not a record `seq`
//!
//! `seq` is per `(colony_id, issuer)`, so two segments can each begin at `seq: 1` for two
//! issuers and a name built from it would collide. The header carries the segment's ordinal
//! instead: unique, monotonic, and what `{ordinal:020}.seg` sorts by. The `seq` range a
//! segment holds is recovered by scanning it, which recovery does anyway.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::BridgeError;
use crate::spool::checksum::crc32c;
use crate::spool::{IssuerIdx, Record, RecordFlags, Seq};

/// The eight bytes every segment starts with.
pub const MAGIC: &[u8; 8] = b"PERCHSPL";
/// The on-disk format this build reads and writes.
pub const FORMAT_VERSION: u16 = 1;
/// Fixed header size.
pub const HEADER_BYTES: usize = 48;
/// Fixed record prefix size before the payload.
pub const RECORD_PREFIX_BYTES: usize = 26;

/// Roll when the active segment reaches this. 32 segments per 256 MiB budget, so eviction
/// granularity is 1/32 of the budget -- coarse enough that eviction is rare, fine enough that one
/// eviction is not a quarter of the history.
pub const DEFAULT_SEGMENT_BYTES: u64 = 8 * 1024 * 1024;

fn io_error(path: &Path, source: std::io::Error) -> BridgeError {
    BridgeError::SpoolIo {
        path: path.display().to_string(),
        source,
    }
}

/// The decoded 48-byte header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentHeader {
    /// [`FORMAT_VERSION`] at write time.
    pub format_version: u16,
    /// `Stream::disk_code()` of the owning stream.
    pub stream: u8,
    /// The segment's position in the spool; the file is named after it.
    pub ordinal: u64,
    /// Daemon clock at create.
    pub created_at_ms: i64,
    /// First 16 bytes of `sha256(colony_id)`. A mismatch refuses to open: a spool directory shared
    /// between two colonies would merge two `seq` namespaces and produce a *false continuity*,
    /// which `07-REALTIME-AND-DATA.md` section 11 names as the worse of the two failures.
    pub colony_hash: [u8; 16],
}

impl SegmentHeader {
    /// Little-endian pack, then CRC-32C over bytes 0..44 into 44..48.
    pub fn encode(&self) -> [u8; HEADER_BYTES] {
        let mut out = [0u8; HEADER_BYTES];
        out[0..8].copy_from_slice(MAGIC);
        out[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        out[10] = self.stream;
        out[11] = 0;
        out[12..20].copy_from_slice(&self.ordinal.to_le_bytes());
        out[20..28].copy_from_slice(&self.created_at_ms.to_le_bytes());
        out[28..44].copy_from_slice(&self.colony_hash);
        let crc = crc32c(&out[0..44]);
        out[44..48].copy_from_slice(&crc.to_le_bytes());
        out
    }

    /// Verify length, magic, version, CRC and colony hash.
    ///
    /// # Errors
    /// [`BridgeError::SpoolBadMagic`], [`BridgeError::SpoolUnknownFormat`],
    /// [`BridgeError::SpoolColonyMismatch`]; a short or CRC-failed header is reported as a bad
    /// magic, because nothing after the first eight bytes can be trusted either.
    pub fn decode(
        bytes: &[u8],
        expect_colony_hash: &[u8; 16],
        path: &Path,
    ) -> Result<Self, BridgeError> {
        let bad_magic = || BridgeError::SpoolBadMagic {
            path: path.display().to_string(),
        };
        if bytes.len() < HEADER_BYTES || &bytes[0..8] != MAGIC {
            return Err(bad_magic());
        }
        let stored_crc = u32::from_le_bytes(le4(&bytes[44..48]));
        if crc32c(&bytes[0..44]) != stored_crc {
            return Err(bad_magic());
        }
        let format_version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if format_version != FORMAT_VERSION {
            return Err(BridgeError::SpoolUnknownFormat {
                path: path.display().to_string(),
                found: format_version,
                expected: FORMAT_VERSION,
            });
        }
        let mut colony_hash = [0u8; 16];
        colony_hash.copy_from_slice(&bytes[28..44]);
        if &colony_hash != expect_colony_hash {
            return Err(BridgeError::SpoolColonyMismatch {
                path: path.display().to_string(),
            });
        }
        Ok(Self {
            format_version,
            stream: bytes[10],
            ordinal: u64::from_le_bytes(le8(&bytes[12..20])),
            created_at_ms: i64::from_le_bytes(le8(&bytes[20..28])),
            colony_hash,
        })
    }
}

fn le4(bytes: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    out.copy_from_slice(&bytes[..4]);
    out
}

fn le8(bytes: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[..8]);
    out
}

/// Pack a record: 26-byte prefix, CRC over `seq .. payload`, then the payload.
pub fn encode_record(record: &Record) -> Vec<u8> {
    let mut body = Vec::with_capacity(RECORD_PREFIX_BYTES + record.payload.len());
    body.extend_from_slice(&(record.payload.len() as u32).to_le_bytes());
    body.extend_from_slice(&[0u8; 4]); // crc placeholder
    body.extend_from_slice(&record.seq.to_le_bytes());
    body.extend_from_slice(&record.emitted_at_ms.to_le_bytes());
    body.push(record.issuer);
    body.push(record.flags.0);
    body.extend_from_slice(&record.payload);
    let crc = crc32c(&body[8..]);
    body[4..8].copy_from_slice(&crc.to_le_bytes());
    body
}

/// The fixed part of a record, readable even when its payload is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordPrefix {
    /// Payload length the prefix claims.
    pub len: u32,
    /// The stored CRC.
    pub crc: u32,
    /// The record's seq.
    pub seq: Seq,
    /// The domain timestamp.
    pub emitted_at_ms: i64,
    /// The issuer index.
    pub issuer: IssuerIdx,
    /// The flag byte.
    pub flags: RecordFlags,
}

fn decode_prefix(bytes: &[u8]) -> Option<RecordPrefix> {
    if bytes.len() < RECORD_PREFIX_BYTES {
        return None;
    }
    Some(RecordPrefix {
        len: u32::from_le_bytes(le4(&bytes[0..4])),
        crc: u32::from_le_bytes(le4(&bytes[4..8])),
        seq: u64::from_le_bytes(le8(&bytes[8..16])),
        emitted_at_ms: i64::from_le_bytes(le8(&bytes[16..24])),
        issuer: bytes[24],
        flags: RecordFlags(bytes[25]),
    })
}

/// Why a record did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordDecodeError {
    /// Fewer than 26 bytes remained: the prefix itself is torn.
    TruncatedPrefix,
    /// The prefix is readable but its `len` runs past the end of the bytes.
    TruncatedPayload(RecordPrefix),
    /// The prefix and payload are present but the CRC does not match.
    ChecksumMismatch(RecordPrefix),
}

/// `Ok(Some((record, consumed)))`, `Ok(None)` at a clean end, `Err` on a short or corrupt record.
pub fn decode_record(bytes: &[u8]) -> Result<Option<(Record, usize)>, RecordDecodeError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let prefix = decode_prefix(bytes).ok_or(RecordDecodeError::TruncatedPrefix)?;
    let total = RECORD_PREFIX_BYTES + prefix.len as usize;
    if bytes.len() < total {
        return Err(RecordDecodeError::TruncatedPayload(prefix));
    }
    if crc32c(&bytes[8..total]) != prefix.crc {
        return Err(RecordDecodeError::ChecksumMismatch(prefix));
    }
    Ok(Some((
        Record {
            seq: prefix.seq,
            emitted_at_ms: prefix.emitted_at_ms,
            issuer: prefix.issuer,
            flags: prefix.flags,
            payload: bytes[RECORD_PREFIX_BYTES..total].to_vec(),
        },
        total,
    )))
}

/// What a recovery scan concluded about a segment's tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailVerdict {
    /// Every record decoded. `end_offset` is the file length.
    Clean {
        /// Bytes in the segment.
        end_offset: u64,
    },
    /// A record's `len` ran past EOF, or its CRC failed, at the very end of the file. That is a
    /// torn tail from a crash -- expected, because the spool fsyncs on roll and not per record.
    /// The segment is truncated at `truncate_at` and the burned seq becomes a
    /// [`crate::spool::GapCause::SpoolTornTail`].
    TornTail {
        /// Offset of the first undecodable byte; the caller truncates here.
        truncate_at: u64,
        /// The seq of the torn record when its prefix was readable, else the seq after the last
        /// valid record of the same issuer as a best effort.
        burned: (Seq, Seq),
        /// The issuer the burned seq belongs to, when known.
        burned_issuer: Option<IssuerIdx>,
    },
    /// A CRC failed in the MIDDLE of the file, with valid records after it. That is corruption,
    /// not a crash. The segment is renamed `*.seg.corrupt`, the whole range becomes a gap, and
    /// the bridge continues.
    Corrupt {
        /// Offset of the corrupt record.
        at: u64,
        /// `(min_seq, max_seq)` over every record whose prefix was readable in the segment.
        range: (Seq, Seq),
    },
}

/// The result of scanning one segment from its header to its end.
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// The decoded header.
    pub header: SegmentHeader,
    /// The tail verdict.
    pub verdict: TailVerdict,
    /// Records that decoded cleanly.
    pub records: u64,
    /// `(min, max)` seq per issuer over the cleanly decoded records.
    pub seq_ranges: std::collections::BTreeMap<IssuerIdx, (Seq, Seq)>,
}

/// An open segment: the active one being appended to, or a sealed one being read.
#[derive(Debug)]
pub struct Segment {
    path: PathBuf,
    file: File,
    end: u64,
    ordinal: u64,
    seq_ranges: std::collections::BTreeMap<IssuerIdx, (Seq, Seq)>,
}

impl Segment {
    /// Creates `{dir}/{ordinal:020}.seg` and writes the header. Fails if the file exists.
    pub fn create(dir: &Path, header: SegmentHeader) -> Result<Self, BridgeError> {
        let path = segment_path(dir, header.ordinal);
        let mut file = File::create_new(&path).map_err(|e| io_error(&path, e))?;
        file.write_all(&header.encode())
            .map_err(|e| io_error(&path, e))?;
        Ok(Self {
            path,
            file,
            end: HEADER_BYTES as u64,
            ordinal: header.ordinal,
            seq_ranges: std::collections::BTreeMap::new(),
        })
    }

    /// Opens an existing segment for append after a scan established its clean end.
    pub fn open_for_append(
        path: &Path,
        report: &ScanReport,
        end: u64,
    ) -> Result<Self, BridgeError> {
        let mut file = OpenOptions::new()
            .append(true)
            .read(true)
            .open(path)
            .map_err(|e| io_error(path, e))?;
        file.seek(SeekFrom::End(0)).map_err(|e| io_error(path, e))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            end,
            ordinal: report.header.ordinal,
            seq_ranges: report.seq_ranges.clone(),
        })
    }

    /// Reads and verifies the header, then decodes every record and classifies the tail.
    ///
    /// Calls `on_record` with each clean record's prefix and byte offset, oldest first, so the
    /// caller can locate its committed cursor without a second pass.
    pub fn scan(
        path: &Path,
        expect_colony_hash: &[u8; 16],
        mut on_record: impl FnMut(&RecordPrefix, u64),
    ) -> Result<ScanReport, BridgeError> {
        let bytes = std::fs::read(path).map_err(|e| io_error(path, e))?;
        let header = SegmentHeader::decode(&bytes, expect_colony_hash, path)?;
        let mut offset = HEADER_BYTES;
        let mut records = 0u64;
        let mut seq_ranges: std::collections::BTreeMap<IssuerIdx, (Seq, Seq)> =
            std::collections::BTreeMap::new();
        let mut last_by_issuer: std::collections::BTreeMap<IssuerIdx, Seq> =
            std::collections::BTreeMap::new();
        let note = |ranges: &mut std::collections::BTreeMap<IssuerIdx, (Seq, Seq)>,
                    issuer: IssuerIdx,
                    seq: Seq| {
            ranges
                .entry(issuer)
                .and_modify(|(lo, hi)| {
                    *lo = (*lo).min(seq);
                    *hi = (*hi).max(seq);
                })
                .or_insert((seq, seq));
        };
        let verdict = loop {
            match decode_record(&bytes[offset..]) {
                Ok(None) => {
                    break TailVerdict::Clean {
                        end_offset: offset as u64,
                    };
                }
                Ok(Some((record, consumed))) => {
                    let prefix = RecordPrefix {
                        len: record.payload.len() as u32,
                        crc: 0,
                        seq: record.seq,
                        emitted_at_ms: record.emitted_at_ms,
                        issuer: record.issuer,
                        flags: record.flags,
                    };
                    on_record(&prefix, offset as u64);
                    note(&mut seq_ranges, record.issuer, record.seq);
                    last_by_issuer.insert(record.issuer, record.seq);
                    records += 1;
                    offset += consumed;
                }
                Err(RecordDecodeError::TruncatedPrefix) => {
                    // The last valid record of the same issuer is unknown: burn the next seq of
                    // the most recently seen issuer as the best available estimate.
                    let (issuer, burned) = last_by_issuer
                        .iter()
                        .next_back()
                        .map(|(i, s)| (Some(*i), s + 1))
                        .unwrap_or((None, 1));
                    break TailVerdict::TornTail {
                        truncate_at: offset as u64,
                        burned: (burned, burned),
                        burned_issuer: issuer,
                    };
                }
                Err(RecordDecodeError::TruncatedPayload(prefix)) => {
                    break TailVerdict::TornTail {
                        truncate_at: offset as u64,
                        burned: (prefix.seq, prefix.seq),
                        burned_issuer: Some(prefix.issuer),
                    };
                }
                Err(RecordDecodeError::ChecksumMismatch(prefix)) => {
                    // Corruption is a CRC failure with a decodable record after it; a CRC failure
                    // that nothing follows is a torn tail.
                    let next = offset + RECORD_PREFIX_BYTES + prefix.len as usize;
                    let followed_by_valid =
                        next < bytes.len() && matches!(decode_record(&bytes[next..]), Ok(Some(_)));
                    if followed_by_valid {
                        let mut ranges = seq_ranges.clone();
                        note(&mut ranges, prefix.issuer, prefix.seq);
                        let mut rest = next;
                        while let Ok(Some((record, consumed))) = decode_record(&bytes[rest..]) {
                            note(&mut ranges, record.issuer, record.seq);
                            rest += consumed;
                        }
                        let lo = ranges
                            .values()
                            .map(|(lo, _)| *lo)
                            .min()
                            .unwrap_or(prefix.seq);
                        let hi = ranges
                            .values()
                            .map(|(_, hi)| *hi)
                            .max()
                            .unwrap_or(prefix.seq);
                        break TailVerdict::Corrupt {
                            at: offset as u64,
                            range: (lo, hi),
                        };
                    }
                    break TailVerdict::TornTail {
                        truncate_at: offset as u64,
                        burned: (prefix.seq, prefix.seq),
                        burned_issuer: Some(prefix.issuer),
                    };
                }
            }
        };
        Ok(ScanReport {
            header,
            verdict,
            records,
            seq_ranges,
        })
    }

    /// Appends. One `write_all` into the page cache -- **no fsync here**. A per-record fsync is
    /// a syscall with a disk round trip inside the receive loop's 281 ms budget, which is the
    /// whole reason the spool exists. Returns the new end offset.
    pub fn append(&mut self, record: &Record) -> Result<u64, BridgeError> {
        let bytes = encode_record(record);
        self.file
            .write_all(&bytes)
            .map_err(|e| io_error(&self.path, e))?;
        self.end += bytes.len() as u64;
        self.seq_ranges
            .entry(record.issuer)
            .and_modify(|(lo, hi)| {
                *lo = (*lo).min(record.seq);
                *hi = (*hi).max(record.seq);
            })
            .or_insert((record.seq, record.seq));
        Ok(self.end)
    }

    /// Flushes and fsyncs. Called on roll and on graceful shutdown only.
    pub fn seal(&mut self) -> Result<(), BridgeError> {
        self.file.flush().map_err(|e| io_error(&self.path, e))?;
        self.file.sync_all().map_err(|e| io_error(&self.path, e))
    }

    /// The cached end offset.
    pub fn bytes(&self) -> u64 {
        self.end
    }

    /// The segment's ordinal.
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// The segment's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `(min, max)` seq per issuer over the records this segment holds.
    pub fn seq_ranges(&self) -> &std::collections::BTreeMap<IssuerIdx, (Seq, Seq)> {
        &self.seq_ranges
    }
}

/// `{dir}/{ordinal:020}.seg`.
pub fn segment_path(dir: &Path, ordinal: u64) -> PathBuf {
    dir.join(format!("{ordinal:020}.seg"))
}

/// Lists a stream's segments oldest-first. Names are `{ordinal:020}.seg`, so lexicographic order
/// is numeric order for every `u64` -- which is why the padding is 20 digits and not 16.
pub fn list_segments(dir: &Path) -> Result<Vec<PathBuf>, BridgeError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| io_error(dir, e))? {
        let entry = entry.map_err(|e| io_error(dir, e))?;
        let path = entry.path();
        let is_segment = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".seg") && n.len() == 24);
        if is_segment {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Reads the records of a segment from `offset` to its end. A torn or corrupt tail ends the
/// read where the last clean record ended; recovery at open is what repairs it.
pub fn read_records_from(path: &Path, offset: u64) -> Result<Vec<(Record, u64)>, BridgeError> {
    let mut file = File::open(path).map_err(|e| io_error(path, e))?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| io_error(path, e))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| io_error(path, e))?;
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Ok(Some((record, consumed))) = decode_record(&bytes[at..]) {
        out.push((record, offset + at as u64));
        at += consumed;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn record(seq: Seq, issuer: IssuerIdx, payload: &[u8]) -> Record {
        Record {
            seq,
            emitted_at_ms: 1_700_000_000_000,
            issuer,
            flags: RecordFlags::default(),
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn a_record_round_trips_and_a_flipped_payload_bit_fails_its_crc() {
        let bytes = encode_record(&record(41, 2, b"payload"));
        assert_eq!(bytes.len(), RECORD_PREFIX_BYTES + 7);
        let (decoded, consumed) = decode_record(&bytes).unwrap().unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!((decoded.seq, decoded.issuer), (41, 2));
        assert_eq!(decoded.payload, b"payload");
        let mut dirty = bytes.clone();
        dirty[RECORD_PREFIX_BYTES + 3] ^= 1;
        assert!(matches!(
            decode_record(&dirty),
            Err(RecordDecodeError::ChecksumMismatch(p)) if p.seq == 41
        ));
        assert!(matches!(
            decode_record(&bytes[..bytes.len() - 1]),
            Err(RecordDecodeError::TruncatedPayload(p)) if p.seq == 41
        ));
        assert!(matches!(
            decode_record(&bytes[..10]),
            Err(RecordDecodeError::TruncatedPrefix)
        ));
        assert!(decode_record(&[]).unwrap().is_none());
    }

    #[test]
    fn the_header_refuses_the_wrong_colony_magic_and_version() {
        let colony = [7u8; 16];
        let header = SegmentHeader {
            format_version: FORMAT_VERSION,
            stream: 1,
            ordinal: 3,
            created_at_ms: 5,
            colony_hash: colony,
        };
        let bytes = header.encode();
        let path = Path::new("x.seg");
        assert_eq!(
            SegmentHeader::decode(&bytes, &colony, path).unwrap(),
            header
        );
        assert!(matches!(
            SegmentHeader::decode(&bytes, &[8u8; 16], path),
            Err(BridgeError::SpoolColonyMismatch { .. })
        ));
        let mut wrong_magic = bytes;
        wrong_magic[0] = b'X';
        assert!(matches!(
            SegmentHeader::decode(&wrong_magic, &colony, path),
            Err(BridgeError::SpoolBadMagic { .. })
        ));
        let mut wrong_version = bytes;
        wrong_version[8] = 9;
        let crc = crc32c(&wrong_version[0..44]);
        wrong_version[44..48].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            SegmentHeader::decode(&wrong_version, &colony, path),
            Err(BridgeError::SpoolUnknownFormat { found: 9, .. })
        ));
    }

    #[test]
    fn a_mid_file_crc_failure_is_corruption_and_a_tail_failure_is_a_torn_tail() {
        let dir = tempfile::tempdir().unwrap();
        let colony = [1u8; 16];
        let header = SegmentHeader {
            format_version: FORMAT_VERSION,
            stream: 1,
            ordinal: 0,
            created_at_ms: 0,
            colony_hash: colony,
        };
        let mut segment = Segment::create(dir.path(), header).unwrap();
        for seq in 1..=3 {
            segment.append(&record(seq, 0, b"0123456789")).unwrap();
        }
        segment.seal().unwrap();
        let path = segment.path().to_path_buf();
        let clean = std::fs::read(&path).unwrap();

        // Flip a payload byte of the SECOND record: valid records follow, so it is corruption.
        let mut corrupt = clean.clone();
        let second = HEADER_BYTES + RECORD_PREFIX_BYTES + 10 + RECORD_PREFIX_BYTES + 2;
        corrupt[second] ^= 0xFF;
        std::fs::write(&path, &corrupt).unwrap();
        let report = Segment::scan(&path, &colony, |_, _| {}).unwrap();
        assert_eq!(report.records, 1);
        assert!(matches!(
            report.verdict,
            TailVerdict::Corrupt { range: (1, 3), .. }
        ));

        // Flip a payload byte of the LAST record: nothing follows, so it is a torn tail.
        let mut torn = clean;
        let third = HEADER_BYTES + 2 * (RECORD_PREFIX_BYTES + 10) + RECORD_PREFIX_BYTES + 2;
        torn[third] ^= 0xFF;
        std::fs::write(&path, &torn).unwrap();
        let report = Segment::scan(&path, &colony, |_, _| {}).unwrap();
        assert_eq!(report.records, 2);
        assert!(matches!(
            report.verdict,
            TailVerdict::TornTail {
                burned: (3, 3),
                burned_issuer: Some(0),
                ..
            }
        ));
    }
}
