//! Append-only store of per-technique detection outcomes (ATKSCORE-03, SC 3).
//!
//! Every step a red plan runs either got caught by a detector or it didn't.
//! [`AttackPatternDb`] is the durable memory of that history: one
//! [`AttackPatternRecord`] per `(generation, technique, detector)`
//! observation, appended in order and never rewritten or pruned.
//! [`AttackPatternDb::technique_success_rate`] turns that history into the
//! one number a later generation needs -- what share of the time this
//! technique got past detection.
//!
//! This module delivers the store and the rate, nothing more. Reading the
//! rate back into an operator's technique choice -- biasing generation
//! toward what evaded before -- is Phase 290's co-evolution loop
//! (COEVOLVE-03/-04), not this one. Nothing here reaches into `operators/`,
//! and nothing here reaches response authority: no name in this file
//! resolves to `execute_response`, `ResponseAdapter`, `live_response`,
//! `swarm_response`, or a broadcaster. This is red's memory of what blue
//! caught, not a lever on what blue does next.
//!
//! IO sits behind an explicit seam: [`AttackPatternDb::from_reader`] and
//! [`AttackPatternDb::write`] take a `BufRead`/`Write` rather than a path, so
//! the unit tests below exercise the parser and serializer against an
//! in-memory buffer, never a tempfile. [`AttackPatternDb::load`] and
//! [`AttackPatternDb::append_line`] are thin file wrappers around that seam
//! for a future CLI; they are not exercised by this module's tests.

use super::RedSwarmError;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// One observation: did `detector` catch `technique` when it ran in
/// `generation`.
///
/// Records are immutable once appended -- correcting history is not a
/// feature this store offers. `generation` is a caller-supplied ordinal, not
/// a timestamp: nothing in this module reads the wall clock, so an
/// identical sequence of records always serializes to identical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackPatternRecord {
    /// The generation the observation was made in, as assigned by the
    /// caller (the evolutionary loop), never by this store.
    pub generation: u32,
    /// The MITRE-style technique id the step realised (e.g. `"T1055"`).
    pub technique: String,
    /// The detector whose verdict this observation records.
    pub detector: String,
    /// Whether `detector` caught the step. `false` is the evasion this
    /// store exists to remember.
    pub detected: bool,
}

/// Append-only history of [`AttackPatternRecord`]s, held in append order.
///
/// The order is preserved end to end -- [`Self::write`] emits it and
/// [`Self::from_reader`] restores it -- but no query here depends on it:
/// [`Self::technique_success_rate`] is a sum and a count over whatever
/// subset matches, independent of position.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttackPatternDb {
    records: Vec<AttackPatternRecord>,
}

impl AttackPatternDb {
    /// Parses a JSONL stream -- one [`AttackPatternRecord`] per line -- into
    /// a db, preserving the order the lines appear in.
    ///
    /// A blank line (empty once trimmed) is skipped rather than parsed: a
    /// file this store wrote always ends with a trailing newline, and
    /// nothing about a trailing (or stray) blank line is a data error. Any
    /// other line that fails to parse as an `AttackPatternRecord` fails the
    /// whole read closed with [`RedSwarmError::MalformedPatternRecord`],
    /// never a panic -- a silently dropped record would understate a
    /// technique's detection history in a way nothing downstream could
    /// detect.
    pub fn from_reader(r: impl BufRead) -> Result<Self, RedSwarmError> {
        let mut records = Vec::new();
        for (index, line) in r.lines().enumerate() {
            let line_number = index + 1;
            let line = line.map_err(|source| RedSwarmError::MalformedPatternRecord {
                line: line_number,
                reason: source.to_string(),
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let record: AttackPatternRecord = serde_json::from_str(&line).map_err(|source| {
                RedSwarmError::MalformedPatternRecord {
                    line: line_number,
                    reason: source.to_string(),
                }
            })?;
            records.push(record);
        }
        Ok(Self { records })
    }

    /// Appends one record to the in-memory history. The store never
    /// rewrites or reorders what is already there.
    pub fn append(&mut self, record: AttackPatternRecord) {
        self.records.push(record);
    }

    /// Serializes every record as JSONL, one line per record, in append
    /// order.
    ///
    /// Each line is `serde_json::to_string` of a plain struct with no map
    /// fields, so field order is fixed by [`AttackPatternRecord`]'s
    /// declaration order, never by hash iteration -- two dbs holding the
    /// same records in the same order always write identical bytes.
    pub fn write(&self, mut w: impl Write) -> Result<(), RedSwarmError> {
        for (index, record) in self.records.iter().enumerate() {
            write_record_line(&mut w, record, index + 1)?;
        }
        Ok(())
    }

    /// The share of `technique`'s recorded observations that evaded
    /// detection: `(records naming technique with detected == false) /
    /// (records naming technique)`.
    ///
    /// A technique with no records at all returns `1.0` -- never seen is
    /// never caught, the optimistic prior a fresh technique needs so it
    /// gets tried at least once rather than starting from a `0.0` it never
    /// earned. That same branch is the divide-by-zero guard: the
    /// empty-history case is defined, not skipped or panicking.
    pub fn technique_success_rate(&self, technique: &str) -> f64 {
        let total = self
            .records
            .iter()
            .filter(|record| record.technique == technique)
            .count();
        if total == 0 {
            return 1.0;
        }
        let undetected = self
            .records
            .iter()
            .filter(|record| record.technique == technique && !record.detected)
            .count();
        undetected as f64 / total as f64
    }

    /// Loads a db from the JSONL file at `path`, via [`Self::from_reader`].
    ///
    /// A thin wrapper for a future CLI. A failure to open `path` is reported
    /// as [`RedSwarmError::MalformedPatternRecord`] with `line: 0` -- a
    /// sentinel for "not a specific data line", since the failure happens
    /// before any line is read. Unit tests exercise the parser itself
    /// through [`Self::from_reader`] on an in-memory buffer instead of this
    /// wrapper.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RedSwarmError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| RedSwarmError::MalformedPatternRecord {
            line: 0,
            reason: format!("failed to open {}: {source}", path.display()),
        })?;
        Self::from_reader(BufReader::new(file))
    }

    /// Appends one record's JSONL line directly to the file at `path`,
    /// creating it if absent.
    ///
    /// A thin wrapper for a future CLI, mirroring [`Self::write`]'s line
    /// format without holding the whole history in memory. Not exercised by
    /// this module's unit tests, which do no file IO.
    pub fn append_line(
        path: impl AsRef<Path>,
        record: &AttackPatternRecord,
    ) -> Result<(), RedSwarmError> {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|source| RedSwarmError::MalformedPatternRecord {
                line: 0,
                reason: format!("failed to open {} for append: {source}", path.display()),
            })?;
        write_record_line(&mut file, record, 0)
    }
}

/// Writes one record as a JSONL line (`{json}\n`), mapping any
/// serialization or IO failure to [`RedSwarmError::MalformedPatternRecord`]
/// at `line`.
///
/// Shared by [`AttackPatternDb::write`] (`line` = the record's 1-based
/// position in the file being written) and [`AttackPatternDb::append_line`]
/// (`line: 0`, since a single append does not know the file's existing
/// length).
fn write_record_line(
    w: &mut impl Write,
    record: &AttackPatternRecord,
    line: usize,
) -> Result<(), RedSwarmError> {
    let encoded =
        serde_json::to_string(record).map_err(|source| RedSwarmError::MalformedPatternRecord {
            line,
            reason: source.to_string(),
        })?;
    writeln!(w, "{encoded}").map_err(|source| RedSwarmError::MalformedPatternRecord {
        line,
        reason: source.to_string(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::{AttackPatternDb, AttackPatternRecord};
    use crate::red_swarm::RedSwarmError;

    /// Builds a record with the given fields; a short constructor so tests
    /// read as a table of `(generation, technique, detector, detected)`
    /// tuples rather than repeating struct-literal noise.
    fn record(
        generation: u32,
        technique: &str,
        detector: &str,
        detected: bool,
    ) -> AttackPatternRecord {
        AttackPatternRecord {
            generation,
            technique: technique.to_string(),
            detector: detector.to_string(),
            detected,
        }
    }

    fn db_with(records: impl IntoIterator<Item = AttackPatternRecord>) -> AttackPatternDb {
        let mut db = AttackPatternDb::default();
        for record in records {
            db.append(record);
        }
        db
    }

    #[test]
    fn a_fresh_db_reports_full_success_rate_for_an_unrecorded_technique() {
        let db = AttackPatternDb::default();

        assert_eq!(db.technique_success_rate("T1055"), 1.0);
    }

    #[test]
    fn a_technique_detected_in_every_record_has_zero_success_rate() {
        let db = db_with([
            record(1, "T1055", "det-a", true),
            record(2, "T1055", "det-b", true),
            record(3, "T1055", "det-a", true),
        ]);

        assert_eq!(db.technique_success_rate("T1055"), 0.0);
    }

    #[test]
    fn a_mixed_detection_history_returns_the_exact_success_rate() {
        let db = db_with([
            record(1, "T1055", "det-a", true),
            record(2, "T1055", "det-b", false),
            record(3, "T1055", "det-a", true),
            record(4, "T1055", "det-b", false),
        ]);

        assert_eq!(db.technique_success_rate("T1055"), 0.5);
    }

    #[test]
    fn technique_success_rate_only_counts_records_naming_that_technique() {
        let db = db_with([
            record(1, "T1055", "det-a", true),
            record(2, "T1027", "det-a", false),
            record(3, "T1027", "det-a", false),
        ]);

        assert_eq!(db.technique_success_rate("T1055"), 0.0);
        assert_eq!(db.technique_success_rate("T1027"), 1.0);
        assert_eq!(db.technique_success_rate("T9999"), 1.0);
    }

    #[test]
    fn write_then_from_reader_round_trips_the_same_records() {
        let db = db_with([
            record(1, "T1055", "det-a", true),
            record(1, "T1027", "det-b", false),
            record(2, "T1055", "det-a", false),
        ]);

        let mut buffer: Vec<u8> = Vec::new();
        db.write(&mut buffer).expect("write should succeed");
        let restored = AttackPatternDb::from_reader(buffer.as_slice())
            .expect("from_reader should parse the just-written buffer");

        assert_eq!(restored, db);
    }

    #[test]
    fn writing_an_identical_record_sequence_twice_produces_byte_identical_output() {
        let build = || {
            db_with([
                record(7, "T1055", "det-a", true),
                record(8, "T1027", "det-b", false),
            ])
        };

        let mut first: Vec<u8> = Vec::new();
        build()
            .write(&mut first)
            .expect("first write should succeed");
        let mut second: Vec<u8> = Vec::new();
        build()
            .write(&mut second)
            .expect("second write should succeed");

        assert_eq!(first, second);
        assert_eq!(
            String::from_utf8(first).expect("output should be valid utf-8"),
            "{\"generation\":7,\"technique\":\"T1055\",\"detector\":\"det-a\",\"detected\":true}\n\
             {\"generation\":8,\"technique\":\"T1027\",\"detector\":\"det-b\",\"detected\":false}\n"
        );
    }

    #[test]
    fn from_reader_skips_a_trailing_blank_line_without_erroring() {
        let jsonl = "{\"generation\":1,\"technique\":\"T1055\",\"detector\":\"det-a\",\"detected\":true}\n\n";

        let db = AttackPatternDb::from_reader(jsonl.as_bytes())
            .expect("a trailing blank line should not be a parse error");

        assert_eq!(db, db_with([record(1, "T1055", "det-a", true)]));
    }

    #[test]
    fn a_malformed_jsonl_line_returns_a_pattern_db_error_instead_of_panicking() {
        let jsonl = "{\"generation\":1,\"technique\":\"T1055\",\"detector\":\"det-a\",\"detected\":true}\nnot json\n";

        let result = AttackPatternDb::from_reader(jsonl.as_bytes());

        assert!(matches!(
            result,
            Err(RedSwarmError::MalformedPatternRecord { line: 2, .. })
        ));
    }
}
