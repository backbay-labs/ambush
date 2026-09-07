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
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the file cannot be written. The caller must then leave the
    /// record where it is: a park that is not durable is a drop.
    pub fn park(&mut self, record: ParkedRecord) -> Result<Option<ParkedRecord>, BridgeError> {
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
    #[must_use]
    pub fn next_due(&self, now_ms: i64, interval_ms: i64) -> Option<&ParkedRecord> {
        self.state
            .records
            .iter()
            .filter(|record| record.parked_at_ms.saturating_add(interval_ms) <= now_ms)
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
        ParkedRecord {
            issuer: 3,
            seq,
            payload: format!(r#"{{"event_type":"response_held","seq":{seq}}}"#).into_bytes(),
            parked_at_ms,
            retries: 0,
            reason: ParkReason::refusal_budget_exhausted("not_a_channel_member"),
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
            reopened.next_due(31_000, 30_000),
            Some(&parked(7, 1_000)),
            "the oldest due record comes back first, byte for byte"
        );
        assert_eq!(
            reopened.next_due(30_999, 30_000),
            None,
            "nothing is due before its interval has passed"
        );

        // A retry that did not land moves the interval and counts the attempt, durably.
        ledger.touch(3, 7, 40_000).unwrap();
        let reopened = ParkedLedger::open(&path).unwrap();
        let retried = reopened.next_due(40_000, 0).unwrap();
        assert_eq!(
            (retried.seq, retried.retries, retried.parked_at_ms),
            (9, 0, 2_000)
        );
        ledger.remove(3, 9).unwrap();
        let reopened = ParkedLedger::open(&path).unwrap();
        assert_eq!(reopened.len(), 1);
        let kept = reopened.next_due(40_000, 0).unwrap();
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
            reopened.next_due(600_000, 0).unwrap().seq != 0,
            "the eviction is durable, not only in memory"
        );
    }
}
