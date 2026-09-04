//! `CURSOR.json` beside the segments. Written with write-then-rename so a crash
//! mid-write leaves the previous cursor intact. Holds the one thing that must
//! survive a crash: the record that something did not.
//!
//! Two maps and a gap slot, all keyed by issuer index:
//!
//! - `committed` — the highest `seq` the relay has acknowledged. A record at or below it is
//!   never handed to the pacer again.
//! - `next_seq` — the next `seq` to assign. Recovered from the segments themselves at open (the
//!   scan is authoritative), then kept here so an empty spool after a full drain still continues
//!   the run rather than restarting at 1.
//! - `gaps` — the pending [`GapCause`] set. Persisted **inside the affected stream's cursor**
//!   deliberately: a loss that is only in memory is lost by the crash that caused it.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::BridgeError;
use crate::spool::{GapCause, GapSlot, IssuerIdx, Seq};

/// File name of the cursor, in the stream's own directory.
pub const CURSOR_FILE: &str = "CURSOR.json";

/// The durable half of a [`crate::spool::DiskSpool`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Cursor {
    /// Highest seq the relay has acknowledged, per issuer index.
    #[serde(default)]
    pub committed: BTreeMap<IssuerIdx, Seq>,
    /// Next seq to assign, per issuer index.
    #[serde(default)]
    pub next_seq: BTreeMap<IssuerIdx, Seq>,
    /// Losses awaiting a carrier card.
    #[serde(default)]
    pub gaps: GapSlot,
}

impl Cursor {
    /// Loads `dir/CURSOR.json`. An absent file is [`Cursor::default`]; a corrupt one is an error,
    /// because silently restarting `seq` at 1 would republish a run the relay already stored
    /// under different envelope hashes.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] when the file exists and cannot be read or parsed.
    pub fn load(dir: &Path) -> Result<Self, BridgeError> {
        let path = dir.join(CURSOR_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(BridgeError::SpoolIo {
                    path: path.display().to_string(),
                    source: error,
                });
            }
        };
        serde_json::from_slice(&bytes).map_err(|error| BridgeError::SpoolIo {
            path: path.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        })
    }

    /// Writes `dir/CURSOR.json` atomically.
    ///
    /// # Errors
    ///
    /// [`BridgeError::SpoolIo`] on any failure of the write, the fsync or the rename.
    pub fn store(&self, dir: &Path) -> Result<(), BridgeError> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| BridgeError::SpoolIo {
            path: dir.join(CURSOR_FILE).display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        })?;
        write_atomic(&dir.join(CURSOR_FILE), &bytes)
    }

    /// Records a loss against this stream.
    pub fn mark_gap(&mut self, cause: GapCause) {
        self.gaps.pending.push(cause);
    }

    /// Takes and clears the pending gap set.
    pub fn take_gaps(&mut self) -> Vec<GapCause> {
        std::mem::take(&mut self.gaps.pending)
    }
}

/// Write `bytes` to `path` through a sibling temporary file, an fsync and a rename.
///
/// The rename is atomic within a directory on every filesystem the daemon runs on, so a crash
/// leaves either the previous contents or the new ones and never a half-written file. Used by the
/// cursor and by [`crate::channels::CaseRouting`], which has the same requirement for the same
/// reason: a routing entry that is not durable produces a second case channel after a restart.
///
/// # Errors
///
/// [`BridgeError::SpoolIo`] naming the path that failed.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), BridgeError> {
    use std::io::Write;

    let io = |p: &Path, source: std::io::Error| BridgeError::SpoolIo {
        path: p.display().to_string(),
        source,
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| io(parent, error))?;
    }
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp).map_err(|error| io(&tmp, error))?;
    file.write_all(bytes).map_err(|error| io(&tmp, error))?;
    file.sync_all().map_err(|error| io(&tmp, error))?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(|error| io(path, error))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_cursor_is_the_default_and_a_stored_one_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = Cursor::load(dir.path()).unwrap();
        assert!(loaded.committed.is_empty() && loaded.next_seq.is_empty());

        let mut cursor = Cursor::default();
        cursor.committed.insert(0, 41);
        cursor.next_seq.insert(0, 42);
        cursor.mark_gap(GapCause::BroadcastLagged { count: 7 });
        cursor.store(dir.path()).unwrap();

        let mut reloaded = Cursor::load(dir.path()).unwrap();
        assert_eq!(reloaded.committed.get(&0), Some(&41));
        assert_eq!(reloaded.next_seq.get(&0), Some(&42));
        assert_eq!(
            reloaded.take_gaps(),
            vec![GapCause::BroadcastLagged { count: 7 }]
        );
        assert!(
            !dir.path().join("CURSOR.tmp").exists(),
            "no temp file survives"
        );
    }

    #[test]
    fn a_corrupt_cursor_is_an_error_and_never_a_silent_reset() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(CURSOR_FILE), b"{not json").unwrap();
        assert!(matches!(
            Cursor::load(dir.path()),
            Err(BridgeError::SpoolIo { .. })
        ));
    }
}
