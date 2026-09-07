//! The alarm drainer's dead-letter: the records the relay refuses permanently.
//!
//! A spool is a queue with one head, and a head the relay will never accept is a stop, not a
//! delay. The drainer bounds how long it argues with the relay about one record
//! ([`super::HEAD_REFUSAL_BUDGET`]) and then moves that record here, out of the queue's way, so
//! the holds behind it drain. This file is what makes that move safe to take: parking is not a
//! drop, and the only thing that lets the cursor advance past a record nobody published is a
//! durable record of what was abandoned and why.
//!
//! # Why it is a file and not a `Vec`
//!
//! The whole failure this answers begins with durable state the relay contradicted, and it is
//! reached by a bridge that restarts. A dead-letter held in memory would be emptied by the very
//! restart most likely to follow a relay's database being restored, and the abandoned holds
//! would then exist nowhere at all: past the spool cursor, absent from the ledger, and
//! `created` in the daemon's store with nothing left to re-file them. Written down, they are
//! retried on the next idle tick, and read by an operator in the meantime.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::BridgeError;
use crate::spool::cursor::write_atomic;
use crate::spool::{IssuerIdx, Seq};

/// The on-disk schema version. A file written by any other version is refused, never adapted:
/// the payloads here are the only copy of an unpublished hold.
const LEDGER_VERSION: u32 = 1;

/// Why a record is in the dead-letter.
///
/// One variant today, and an enum rather than a string because the on-disk document is read by
/// an operator deciding what to repair, and because the reason a record was abandoned is the
/// kind of fact that grows a second case rather than a second spelling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParkReason {
    /// The relay refused this record [`super::HEAD_REFUSAL_BUDGET`] times in a row.
    RefusalBudgetExhausted {
        /// The last refusal's `OkOutcome::reason()`, which names the repair.
        ///
        /// A [`Cow`] because every write passes the `&'static str` the classifier already owns,
        /// and every read off disk owns a `String`.
        last: Cow<'static, str>,
    },
}

impl ParkReason {
    /// The budget-exhausted reason, from the label the last refusal carried.
    #[must_use]
    pub fn refusal_budget_exhausted(last: &'static str) -> Self {
        Self::RefusalBudgetExhausted {
            last: Cow::Borrowed(last),
        }
    }

    /// The `reason` label a parked record is counted under.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::RefusalBudgetExhausted { last } => last.as_ref(),
        }
    }
}

/// What a parked record is about: the id an operator searches for, and the key that says two
/// entries are the same work.
///
/// # Why the spool key is not enough
///
/// The daemon's sweep re-publishes a hold that is still unfiled every `refile_after_ms`, and an
/// alarm record is never coalesced, so every re-file is a new spool record with a new `seq`.
/// Against a relay that refuses the hold's sequence forever — the exact relay this whole
/// mechanism exists for — that is one parked entry per interval, roughly a hundred and twenty
/// over a hold's TTL, out of [`super::PARKED_CAPACITY`]. Evicting oldest-first, those duplicates
/// would push out records that are genuinely distinct and that nothing re-files: a case
/// promotion, or a hold whose terminal card was refused.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParkSubject {
    /// A held destructive action, by its daemon-minted hold id.
    Hold(String),
    /// A case promotion, by its case id.
    Case(String),
    /// An event carrying no id of its own. Never equal to anything, itself included: two such
    /// records are two records. Also what a ledger written before this field existed reads as.
    #[default]
    Unknown,
}

impl ParkSubject {
    /// The hold id, when this subject is a hold.
    #[must_use]
    pub fn hold_id(&self) -> Option<&str> {
        match self {
            Self::Hold(hold_id) => Some(hold_id.as_str()),
            _ => None,
        }
    }

    /// The case id, when this subject is a promotion.
    #[must_use]
    pub fn case_id(&self) -> Option<&str> {
        match self {
            Self::Case(case_id) => Some(case_id.as_str()),
            _ => None,
        }
    }

    /// Whether both name the same hold, or the same case.
    ///
    /// [`ParkSubject::Unknown`] matches nothing, itself included, so a record with no id is
    /// never deduplicated against another.
    fn is_same_work(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Hold(left), Self::Hold(right)) | (Self::Case(left), Self::Case(right)) => {
                left == right
            }
            _ => false,
        }
    }
}

/// One abandoned spool record, with everything needed to publish it later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParkedRecord {
    /// The identity slot the record was spooled under.
    pub issuer: IssuerIdx,
    /// The spool sequence it had. With `issuer` it is this record's identity, and it is the
    /// sequence the cursor was moved past when the record was parked.
    pub seq: Seq,
    /// The spooled `RuntimeEvent` bytes, verbatim. Re-planned from durable state on every
    /// retry, exactly as the head path re-plans its own record.
    #[serde(with = "payload_base64")]
    pub payload: Vec<u8>,
    /// When it was parked, or last retried. The retry interval is measured from this.
    pub parked_at_ms: i64,
    /// How many idle-tick retries it has had. Never a budget: a parked record is already out of
    /// everybody's way, so there is nothing to protect by giving up on it a second time.
    pub retries: u32,
    /// Why it is here.
    pub reason: ParkReason,
    /// The hold or case this record is about.
    ///
    /// Persisted so that a re-filed hold replaces its own entry across a restart, and so that
    /// the eviction that drops a record can still name what was lost. Defaulted for a ledger
    /// written before this field existed, whose payloads still carry the id.
    #[serde(default)]
    pub subject: ParkSubject,
    /// Set when a retry could not deserialize [`ParkedRecord::payload`] at all.
    ///
    /// The record stays on disk with its bytes intact, because they are the only copy of the
    /// hold, and [`ParkedLedger::next_due`] passes over it, because a record no build of this
    /// code can read would otherwise be the oldest due one forever and take every retry tick.
    /// Only an operator clears it: deleting the entry, or a build whose `RuntimeEvent` can read
    /// those bytes once the entry is re-parked.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unreadable: bool,
}

/// The dead-letter file, beside the routing sidecar and the spool cursor.
#[derive(Debug)]
pub struct ParkedLedger {
    path: PathBuf,
    state: LedgerState,
}

/// The document as it is written.
#[derive(Debug, Serialize, Deserialize)]
struct LedgerState {
    version: u32,
    #[serde(default)]
    records: Vec<ParkedRecord>,
}

impl Default for LedgerState {
    fn default() -> Self {
        Self {
            version: LEDGER_VERSION,
            records: Vec::new(),
        }
    }
}

impl ParkedLedger {
    /// Loads the dead-letter at `path`, or an empty one when the file does not exist.
    ///
    /// Nothing is written here: a bridge that never parks anything leaves no file, which is
    /// also how an operator tells at a glance that nothing was ever abandoned.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the file exists and cannot be read, does not parse, or was
    /// written by another schema version. It is NEVER silently reset: the payloads here are the
    /// only remaining copy of holds the spool cursor has already moved past, and starting over
    /// with an empty file would discard them without a trace.
    pub fn open(path: &Path) -> Result<Self, BridgeError> {
        let invalid = |path: &Path, message: String| BridgeError::SpoolIo {
            path: path.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, message),
        };
        let state = match std::fs::read(path) {
            Ok(bytes) => {
                let state: LedgerState = serde_json::from_slice(&bytes)
                    .map_err(|error| invalid(path, error.to_string()))?;
                if state.version != LEDGER_VERSION {
                    return Err(invalid(
                        path,
                        format!(
                            "parked alarm ledger version {} was written by another build; this \
                             one reads version {LEDGER_VERSION}",
                            state.version
                        ),
                    ));
                }
                state
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => LedgerState::default(),
            Err(error) => {
                return Err(BridgeError::SpoolIo {
                    path: path.display().to_string(),
                    source: error,
                });
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            state,
        })
    }

    /// Parks one record, evicting the oldest when the ledger is already at
    /// [`super::PARKED_CAPACITY`].
    ///
    /// The evicted record is RETURNED rather than dropped here, so the caller counts the loss
    /// against the same drop counter every other lost event uses. An unbounded dead-letter is
    /// the other way to lose the hold path: a file that grows without limit is read by nobody
    /// and eventually fills the disk the spool lives on.
    ///
    /// # One record has ONE entry
    ///
    /// Re-parking REPLACES the entry the same work already had, matched on `(issuer, seq)` OR
    /// on [`ParkedRecord::subject`]. Both halves answer a real duplicate.
    ///
    /// The spool key: parking and committing the cursor are two files and two renames, so a
    /// crash between them leaves the record at the spool head to be refused and parked a second
    /// time. Two entries for one record is not a cosmetic duplicate —
    /// [`ParkedLedger::next_due`] selects on the smallest `parked_at_ms` while
    /// [`ParkedLedger::touch`] advances the first entry that matches, so the younger twin would
    /// stay the oldest due record forever, be selected every idle tick, and keep every other
    /// parked record from being retried at all.
    ///
    /// The subject: the daemon re-files an unfiled hold under a NEW `seq` every
    /// `refile_after_ms`, so the spool key alone would let one hold fill the dead-letter and
    /// evict records nothing re-files. See [`ParkSubject`].
    ///
    /// The survivor is always the entry written last, which carries the newest payload and the
    /// newest stamp; every other method still addresses a record by `(issuer, seq)`.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the file cannot be written. The caller must then leave the
    /// record where it is: a park that is not durable is a drop.
    pub fn park(&mut self, record: ParkedRecord) -> Result<Option<ParkedRecord>, BridgeError> {
        self.state.records.retain(|held| {
            (held.issuer, held.seq) != (record.issuer, record.seq)
                && !held.subject.is_same_work(&record.subject)
        });
        self.state.records.push(record);
        let evicted = (self.state.records.len() > super::PARKED_CAPACITY)
            .then(|| {
                self.oldest_index()
                    .map(|index| self.state.records.remove(index))
            })
            .flatten();
        self.persist()?;
        Ok(evicted)
    }

    /// The record due for a retry, oldest first, or `None` when none is due.
    ///
    /// Oldest first so a record cannot be starved by a newer one that keeps failing, and one at
    /// a time because a retry costs the same relay budget a head record does.
    ///
    /// `skip` is the caller's set of records that have already stalled on this pass. A stall
    /// writes nothing here — nothing was learned about the record, so its stamp must not move —
    /// and a stamp that never moves would otherwise leave that record permanently the oldest
    /// due one, taking every idle tick while nothing behind it is ever retried. A record marked
    /// [`ParkedRecord::unreadable`] is passed over for the same reason, and permanently.
    #[must_use]
    pub fn next_due(
        &self,
        now_ms: i64,
        interval_ms: i64,
        skip: &BTreeSet<(IssuerIdx, Seq)>,
    ) -> Option<&ParkedRecord> {
        self.state
            .records
            .iter()
            .filter(|record| {
                !record.unreadable
                    && !skip.contains(&(record.issuer, record.seq))
                    && record.parked_at_ms.saturating_add(interval_ms) <= now_ms
            })
            .min_by_key(|record| record.parked_at_ms)
    }

    /// Drops a record from the dead-letter, because it was published or is undeliverable.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the file cannot be written. A record the ledger does not
    /// hold is not an error and costs no I/O.
    pub fn remove(&mut self, issuer: IssuerIdx, seq: Seq) -> Result<(), BridgeError> {
        let before = self.state.records.len();
        self.state
            .records
            .retain(|record| (record.issuer, record.seq) != (issuer, seq));
        if self.state.records.len() == before {
            return Ok(());
        }
        self.persist()
    }

    /// Marks a record whose payload this build cannot deserialize.
    ///
    /// It is NOT removed. The dead-letter's whole premise is that these bytes are the only copy
    /// of a hold the spool cursor has already moved past, so deleting a record because this
    /// build cannot read it would discard exactly what the file exists to preserve. The mark is
    /// what keeps it from holding the retry rotation, and the bytes stay for an operator.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the file cannot be written. A record the ledger does not
    /// hold, or one already marked, is not an error and costs no I/O.
    pub fn mark_unreadable(&mut self, issuer: IssuerIdx, seq: Seq) -> Result<(), BridgeError> {
        let Some(record) = self
            .state
            .records
            .iter_mut()
            .find(|record| (record.issuer, record.seq) == (issuer, seq) && !record.unreadable)
        else {
            return Ok(());
        };
        record.unreadable = true;
        self.persist()
    }

    /// Records a retry that did not land: one more attempt, and the interval starts again.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the file cannot be written. A record the ledger does not
    /// hold is not an error.
    pub fn touch(&mut self, issuer: IssuerIdx, seq: Seq, now_ms: i64) -> Result<(), BridgeError> {
        let Some(record) = self
            .state
            .records
            .iter_mut()
            .find(|record| (record.issuer, record.seq) == (issuer, seq))
        else {
            return Ok(());
        };
        record.retries = record.retries.saturating_add(1);
        record.parked_at_ms = now_ms;
        self.persist()
    }

    /// How many records the dead-letter holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.records.len()
    }

    /// Whether the dead-letter is empty, which is the state every healthy deployment is in.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state.records.is_empty()
    }

    /// The index of the record parked longest ago.
    fn oldest_index(&self) -> Option<usize> {
        self.state
            .records
            .iter()
            .enumerate()
            .min_by_key(|(_, record)| record.parked_at_ms)
            .map(|(index, _)| index)
    }

    fn persist(&self) -> Result<(), BridgeError> {
        let bytes =
            serde_json::to_vec_pretty(&self.state).map_err(|error| BridgeError::SpoolIo {
                path: self.path.display().to_string(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
            })?;
        write_atomic(&self.path, &bytes)
    }
}

/// The payload as base64, so the dead-letter stays one document an operator can read rather
/// than a JSON array of byte integers.
mod payload_base64 {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use base64::Engine as _;

    use super::*;

    fn parked(seq: Seq, parked_at_ms: i64) -> ParkedRecord {
        hold_record(seq, parked_at_ms, &format!("hold-{seq}"))
    }

    fn hold_record(seq: Seq, parked_at_ms: i64, hold_id: &str) -> ParkedRecord {
        ParkedRecord {
            issuer: 3,
            seq,
            payload: format!(r#"{{"event_type":"response_held","seq":{seq}}}"#).into_bytes(),
            parked_at_ms,
            retries: 0,
            reason: ParkReason::refusal_budget_exhausted("not_a_channel_member"),
            subject: ParkSubject::Hold(hold_id.to_string()),
            unreadable: false,
        }
    }

    fn case_record(seq: Seq, parked_at_ms: i64, case_id: &str) -> ParkedRecord {
        ParkedRecord {
            subject: ParkSubject::Case(case_id.to_string()),
            ..hold_record(seq, parked_at_ms, "unused")
        }
    }

    #[test]
    fn the_parked_ledger_survives_a_reopen_and_refuses_a_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("parked-alarms.json");

        let mut ledger = ParkedLedger::open(&path).unwrap();
        assert!(ledger.is_empty());
        assert!(
            !path.exists(),
            "an empty dead-letter writes no file, so the file's existence is itself a signal"
        );

        assert!(ledger.park(parked(7, 1_000)).unwrap().is_none());
        assert!(ledger.park(parked(9, 2_000)).unwrap().is_none());

        // Every field round-trips, the payload bytes included.
        let reopened = ParkedLedger::open(&path).unwrap();
        assert_eq!(reopened.len(), 2);
        assert_eq!(
            reopened.next_due(31_000, 30_000, &BTreeSet::new()),
            Some(&parked(7, 1_000)),
            "the oldest due record comes back first, byte for byte"
        );
        assert_eq!(
            reopened.next_due(30_999, 30_000, &BTreeSet::new()),
            None,
            "nothing is due before its interval has passed"
        );

        // A retry that did not land moves the interval and counts the attempt, durably.
        ledger.touch(3, 7, 40_000).unwrap();
        let reopened = ParkedLedger::open(&path).unwrap();
        let retried = reopened.next_due(40_000, 0, &BTreeSet::new()).unwrap();
        assert_eq!(
            (retried.seq, retried.retries, retried.parked_at_ms),
            (9, 0, 2_000)
        );
        ledger.remove(3, 9).unwrap();
        let reopened = ParkedLedger::open(&path).unwrap();
        assert_eq!(reopened.len(), 1);
        let kept = reopened.next_due(40_000, 0, &BTreeSet::new()).unwrap();
        assert_eq!((kept.seq, kept.retries, kept.parked_at_ms), (7, 1, 40_000));

        // The document an operator reads: a version, the records, and each payload as one
        // base64 string rather than an array of byte integers.
        let written = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
        assert!(written.contains(r#""version": 1"#), "{written}");
        assert!(
            written.contains(
                &base64::engine::general_purpose::STANDARD
                    .encode(r#"{"event_type":"response_held","seq":7}"#)
            ),
            "{written}"
        );
        assert!(
            written.contains(r#""refusal_budget_exhausted""#)
                && written.contains(r#""last": "not_a_channel_member""#),
            "{written}"
        );
        assert!(
            written.contains(r#""subject""#) && written.contains(r#""hold": "hold-7""#),
            "the record says which hold it is, for the operator and for the dedupe\n{written}"
        );

        // Corrupt is refused, and left exactly as found: these payloads are the only copy of
        // holds the spool cursor has already moved past.
        std::fs::write(&path, b"{ this is not the ledger").unwrap();
        assert!(matches!(
            ParkedLedger::open(&path),
            Err(BridgeError::SpoolIo { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"{ this is not the ledger");

        // So is a document from a schema this build does not read.
        std::fs::write(&path, br#"{"version":2,"records":[]}"#).unwrap();
        assert!(matches!(
            ParkedLedger::open(&path),
            Err(BridgeError::SpoolIo { .. })
        ));
    }

    #[test]
    fn an_unreadable_record_keeps_its_bytes_and_is_never_selected_again() {
        // These bytes are the only copy of a hold the spool cursor has moved past, so a payload
        // this build cannot parse is kept, not deleted. It is marked instead, and the mark takes
        // it out of the retry rotation -- otherwise it would be the oldest due record forever
        // and nothing behind it would ever be tried.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("parked-alarms.json");
        let mut ledger = ParkedLedger::open(&path).unwrap();
        ledger.park(parked(7, 1_000)).unwrap();
        ledger.park(parked(9, 2_000)).unwrap();

        ledger.mark_unreadable(3, 7).unwrap();

        assert_eq!(ledger.len(), 2, "the record is kept, not removed");
        assert_eq!(
            ledger.next_due(60_000, 0, &BTreeSet::new()).map(|r| r.seq),
            Some(9),
            "and the record behind it gets its turn"
        );
        let reopened = ParkedLedger::open(&path).unwrap();
        assert_eq!(reopened.len(), 2, "the mark is durable");
        assert_eq!(
            reopened
                .next_due(60_000, 0, &BTreeSet::new())
                .map(|r| r.seq),
            Some(9)
        );
        let written = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
        assert!(written.contains(r#""unreadable": true"#), "{written}");
        assert!(
            written.contains(
                &base64::engine::general_purpose::STANDARD
                    .encode(r#"{"event_type":"response_held","seq":7}"#)
            ),
            "the bytes an operator needs are still there\n{written}"
        );
    }

    #[test]
    fn re_parking_a_record_replaces_its_entry_rather_than_adding_a_second() {
        // Parking and committing the spool cursor are two files and two renames, so a crash
        // between them leaves the record at the head to be refused and parked a second time.
        // Two entries for one record is not a cosmetic duplicate: `next_due` selects the
        // smallest `parked_at_ms` and `touch` advances the first entry that matches, so the
        // younger twin would stay the oldest due record forever, be chosen on every idle tick,
        // and no other parked record would ever be retried.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("parked-alarms.json");
        let mut ledger = ParkedLedger::open(&path).unwrap();
        ledger.park(parked(7, 1_000)).unwrap();
        ledger.park(parked(9, 2_000)).unwrap();

        // A second park of `(3, 7)`, distinguishable from the first by every field it carries.
        let mut again = parked(7, 1_500);
        again.retries = 4;
        assert!(ledger.park(again).unwrap().is_none());

        assert_eq!(
            ledger.len(),
            2,
            "re-parking replaces, it does not accumulate"
        );
        let survivor = ledger.next_due(31_500, 30_000, &BTreeSet::new()).unwrap();
        assert_eq!(
            (survivor.seq, survivor.parked_at_ms, survivor.retries),
            (7, 1_500, 4),
            "the entry that survives is the one just written"
        );

        // And one touch is enough to hand the queue on, which is the property a duplicate broke.
        ledger.touch(3, 7, 60_000).unwrap();
        assert_eq!(
            ParkedLedger::open(&path)
                .unwrap()
                .next_due(61_000, 30_000, &BTreeSet::new())
                .map(|record| record.seq),
            Some(9),
            "with one entry per record, advancing it gives the next record its turn"
        );
    }

    #[test]
    fn re_filing_one_hold_keeps_one_entry_and_leaves_other_subjects_alone() {
        // The daemon's sweep re-publishes an unfiled hold every `refile_after_ms`, and an alarm
        // record is never coalesced, so each re-file is a NEW spool record with a new `seq`. A
        // relay that refuses one hold forever therefore parks it once per interval: about a
        // hundred and twenty entries over a hold's TTL, out of a capacity of 256, evicting
        // records that are genuinely distinct -- a case promotion, a terminal card -- and that
        // nothing re-files. One hold takes one slot, however many times it is re-filed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("parked-alarms.json");
        let mut ledger = ParkedLedger::open(&path).unwrap();

        for (seq, parked_at_ms) in [(1, 1_000), (2, 31_000), (3, 61_000)] {
            assert!(
                ledger
                    .park(hold_record(seq, parked_at_ms, "hold-refiled"))
                    .unwrap()
                    .is_none()
            );
        }

        assert_eq!(ledger.len(), 1, "one hold, one entry");
        let survivor = ledger.next_due(i64::MAX, 0, &BTreeSet::new()).unwrap();
        assert_eq!(
            (survivor.seq, survivor.parked_at_ms),
            (3, 61_000),
            "the entry that survives is the newest re-file, not the first"
        );

        // A different hold is a different record, and a case is never a hold.
        ledger.park(case_record(4, 70_000, "case-abc")).unwrap();
        ledger.park(hold_record(5, 80_000, "hold-other")).unwrap();
        assert_eq!(ledger.len(), 3, "other subjects are left alone");

        // The subject comes back off disk: re-parking the same case after a reopen still
        // replaces its entry rather than adding a fourth.
        let mut reopened = ParkedLedger::open(&path).unwrap();
        assert_eq!(reopened.len(), 3);
        reopened.park(case_record(6, 90_000, "case-abc")).unwrap();
        assert_eq!(
            reopened.len(),
            3,
            "a reopened ledger still knows its subjects"
        );
        assert_eq!(
            ParkedLedger::open(&path)
                .unwrap()
                .next_due(i64::MAX, 0, &BTreeSet::new())
                .map(|record| record.seq),
            Some(3),
            "and the hold's own entry is untouched by all of it"
        );
    }

    #[test]
    fn the_parked_ledger_evicts_the_oldest_past_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("parked-alarms.json");
        let mut ledger = ParkedLedger::open(&path).unwrap();

        for index in 0..super::super::PARKED_CAPACITY {
            let seq = index as Seq;
            assert!(
                ledger
                    .park(parked(seq, 1_000 + seq as i64))
                    .unwrap()
                    .is_none(),
                "nothing is evicted below the cap"
            );
        }
        assert_eq!(ledger.len(), super::super::PARKED_CAPACITY);

        let evicted = ledger
            .park(parked(9_999, 500_000))
            .unwrap()
            .expect("the cap is enforced by evicting one record");
        assert_eq!(
            (evicted.seq, evicted.parked_at_ms),
            (0, 1_000),
            "the record parked longest ago is the one that goes"
        );
        assert_eq!(ledger.len(), super::super::PARKED_CAPACITY);
        let reopened = ParkedLedger::open(&path).unwrap();
        assert_eq!(reopened.len(), super::super::PARKED_CAPACITY);
        assert!(
            reopened.next_due(600_000, 0, &BTreeSet::new()).unwrap().seq != 0,
            "the eviction is durable, not only in memory"
        );
    }
}
