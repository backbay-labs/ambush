//! Per-issuer chain heads for B6, persisted beside the spool.
//!
//! One JSON file, rewritten atomically (write `chain-heads.json.tmp`, fsync,
//! rename) on every advance. The file carries the colony id so a spool
//! directory moved between colonies fails loudly rather than merging two
//! sequence namespaces into one apparently-continuous chain.
//!
//! Ten issuers, one head each: rewriting the whole file is cheaper than a log,
//! and leaves no partial-write state to recover.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
pub use swarm_perch_wire::envelope::IssuerChainHead;

use crate::error::BridgeError;

const FILE_NAME: &str = "chain-heads.json";

#[derive(Debug, Serialize, Deserialize)]
struct OnDisk {
    colony_id: String,
    heads: BTreeMap<String, IssuerChainHead>,
}

/// The chain-head store. Holds the newest `(seq, envelope_hash)` per issuer.
#[derive(Debug)]
pub struct ChainHeadStore {
    path: PathBuf,
    colony_id: String,
    heads: BTreeMap<String, IssuerChainHead>,
}

impl ChainHeadStore {
    /// Open or create `<dir>/chain-heads.json` for `colony_id`.
    ///
    /// # Errors
    ///
    /// [`BridgeError::ChainHeadColonyMismatch`] when the file was written under
    /// another colony; [`BridgeError::ChainHeadCorrupt`] when it does not
    /// parse or cannot be written; [`BridgeError::SpoolIo`] on the filesystem.
    pub fn open(dir: &Path, colony_id: &str) -> Result<Self, BridgeError> {
        let path = dir.join(FILE_NAME);
        let heads = if path.exists() {
            let bytes = std::fs::read(&path).map_err(|source| BridgeError::SpoolIo {
                path: path.display().to_string(),
                source,
            })?;
            let on_disk: OnDisk =
                serde_json::from_slice(&bytes).map_err(|error| BridgeError::ChainHeadCorrupt {
                    path: path.display().to_string(),
                    reason: error.to_string(),
                })?;
            if on_disk.colony_id != colony_id {
                return Err(BridgeError::ChainHeadColonyMismatch {
                    expected: colony_id.to_string(),
                    found: on_disk.colony_id,
                });
            }
            on_disk.heads
        } else {
            BTreeMap::new()
        };
        let store = Self {
            path,
            colony_id: colony_id.to_string(),
            heads,
        };
        store.persist()?;
        Ok(store)
    }

    /// The newest head for `issuer`, if any envelope was ever sealed under it.
    #[must_use]
    pub fn head(&self, issuer: &str) -> Option<&IssuerChainHead> {
        self.heads.get(issuer)
    }

    /// Record a newly sealed envelope's head.
    ///
    /// `seq` must be exactly one past the stored head, or `1` on a fresh
    /// issuer.
    ///
    /// # Errors
    ///
    /// [`BridgeError::ChainHeadRegression`] for anything else. It is refused
    /// rather than persisted: a stored regression becomes a gap, and a console
    /// reads a gap as a missing or forged link.
    pub fn advance(&mut self, head: IssuerChainHead) -> Result<(), BridgeError> {
        let expected = self
            .heads
            .get(&head.issuer)
            .map_or(1, |stored| stored.seq + 1);
        if head.seq != expected {
            return Err(BridgeError::ChainHeadRegression {
                issuer: head.issuer,
                expected,
                found: head.seq,
            });
        }
        self.heads.insert(head.issuer.clone(), head);
        self.persist()
    }

    fn persist(&self) -> Result<(), BridgeError> {
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&OnDisk {
            colony_id: self.colony_id.clone(),
            heads: self.heads.clone(),
        })
        .map_err(|error| BridgeError::ChainHeadCorrupt {
            path: self.path.display().to_string(),
            reason: error.to_string(),
        })?;
        let mut file = std::fs::File::create(&tmp).map_err(|source| BridgeError::SpoolIo {
            path: tmp.display().to_string(),
            source,
        })?;
        file.write_all(&bytes)
            .map_err(|source| BridgeError::SpoolIo {
                path: tmp.display().to_string(),
                source,
            })?;
        // fsync before rename: a rename that lands before the bytes do would
        // leave a head file that names a sequence whose contents never reached
        // the disk.
        file.sync_all().map_err(|source| BridgeError::SpoolIo {
            path: tmp.display().to_string(),
            source,
        })?;
        std::fs::rename(&tmp, &self.path).map_err(|source| BridgeError::SpoolIo {
            path: self.path.display().to_string(),
            source,
        })?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const ISSUER: &str =
        "swarm:ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn head(seq: u64, hash: &str) -> IssuerChainHead {
        IssuerChainHead {
            issuer: ISSUER.to_string(),
            seq,
            envelope_hash: hash.to_string(),
        }
    }

    /// The head is what makes a restart continue a chain rather than fork it.
    #[test]
    fn heads_survive_reopen_and_refuse_a_regression() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = ChainHeadStore::open(dir.path(), "colony-a").unwrap();
            assert!(store.head(ISSUER).is_none());
            store.advance(head(1, "0x01")).unwrap();
            store.advance(head(2, "0x02")).unwrap();
        }
        let mut store = ChainHeadStore::open(dir.path(), "colony-a").unwrap();
        assert_eq!(store.head(ISSUER).map(|stored| stored.seq), Some(2));
        assert!(matches!(
            store.advance(head(2, "0x03")),
            Err(BridgeError::ChainHeadRegression {
                expected: 3,
                found: 2,
                ..
            })
        ));
        // A skipped sequence is refused for the same reason a repeat is.
        assert!(matches!(
            store.advance(head(4, "0x04")),
            Err(BridgeError::ChainHeadRegression {
                expected: 3,
                found: 4,
                ..
            })
        ));
        // And the refusals left the stored head alone.
        assert_eq!(store.head(ISSUER).map(|stored| stored.seq), Some(2));
    }

    /// Two colonies sharing a directory would merge two sequence namespaces
    /// into one apparently-continuous chain, which is a false continuity and
    /// worse than a visible gap.
    #[test]
    fn a_store_written_under_another_colony_refuses_to_open() {
        let dir = tempfile::tempdir().unwrap();
        ChainHeadStore::open(dir.path(), "colony-a").unwrap();
        assert!(matches!(
            ChainHeadStore::open(dir.path(), "colony-b"),
            Err(BridgeError::ChainHeadColonyMismatch { .. })
        ));
    }

    /// An unreadable file is named, not silently treated as an empty chain.
    #[test]
    fn a_corrupt_file_is_reported_rather_than_restarting_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), b"{ not json").unwrap();
        assert!(matches!(
            ChainHeadStore::open(dir.path(), "colony-a"),
            Err(BridgeError::ChainHeadCorrupt { .. })
        ));
    }
}
