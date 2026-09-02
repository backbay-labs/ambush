use crate::ReplayBundle;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use swarm_core::config::BundleStoreConfig;
use swarm_core::types::ResponseRehearsalPreview;

/// Metadata for one persisted replay bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayBundleRecord {
    pub bundle_id: String,
    #[serde(default)]
    pub store_sequence: u64,
    pub hunt_id: String,
    pub trail_id: String,
    pub action_kind: String,
    #[serde(default)]
    pub is_rehearsal: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rehearsal_id: Option<String>,
    pub response_kind: String,
    pub response_receipt_id: Option<String>,
    pub related_receipt_ids: Vec<String>,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl ReplayBundleRecord {
    fn from_bundle(bundle: &ReplayBundle, bundle_path: String, store_sequence: u64) -> Self {
        Self {
            bundle_id: bundle.bundle_id.clone(),
            store_sequence,
            hunt_id: bundle.audit.hunt_id.clone(),
            trail_id: bundle.audit.trail_id.clone(),
            action_kind: bundle.action_kind().to_string(),
            is_rehearsal: bundle.is_rehearsal(),
            rehearsal_id: bundle.rehearsal_id().map(ToString::to_string),
            response_kind: bundle.audit.response_kind().to_string(),
            response_receipt_id: bundle.audit.response_receipt_id().map(ToString::to_string),
            related_receipt_ids: bundle.audit.all_receipt_ids(),
            created_at_ms: bundle.audit.created_at_ms,
            bundle_path,
        }
    }
}

/// Loaded replay bundle with its persisted metadata.
#[derive(Debug, Clone)]
pub struct ReplayBundleLookup {
    pub record: ReplayBundleRecord,
    pub bundle: ReplayBundle,
}

/// Replay-only preview that never re-executes the original response action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayPreview {
    pub bundle_id: String,
    pub hunt_id: String,
    pub trail_id: String,
    pub action_kind: String,
    pub response_kind: String,
    pub receipt_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rehearsal: Option<ResponseRehearsalPreview>,
    pub note: String,
}

impl ReplayPreview {
    pub fn from_bundle(bundle: &ReplayBundle) -> Self {
        Self {
            bundle_id: bundle.bundle_id.clone(),
            hunt_id: bundle.audit.hunt_id.clone(),
            trail_id: bundle.audit.trail_id.clone(),
            action_kind: bundle.action_kind().to_string(),
            response_kind: bundle.audit.response_kind().to_string(),
            receipt_ids: bundle.audit.all_receipt_ids(),
            rehearsal: bundle.rehearsal.clone(),
            note: if bundle.is_rehearsal() {
                "rehearsal proof is backed by a persisted dry-run receipt; no live response action was executed"
                    .to_string()
            } else {
                "replay preview uses persisted artifacts only; no live response action was re-executed"
                    .to_string()
            },
        }
    }
}

/// Health summary for a replay store backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayStoreHealth {
    pub backend: String,
    pub durable: bool,
    pub ready: bool,
    pub stored_bundles: usize,
    pub details: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisGraphReplayCheckpoint {
    pub cursor_sequence: u64,
    #[serde(default)]
    pub retry_bundle_ids: BTreeSet<String>,
}

/// Replay store errors.
#[derive(Debug, thiserror::Error)]
pub enum ReplayStoreError {
    #[error("replay store lock poisoned")]
    PoisonedLock,

    #[error("invalid replay store state: {reason}")]
    InvalidState { reason: String },

    #[error("failed to read replay store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write replay store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse replay store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Store contract for persisted replay bundles.
pub trait ReplayBundleStore: Send + Sync {
    fn persist(&self, bundle: &ReplayBundle) -> Result<ReplayBundleRecord, ReplayStoreError>;
    fn load_by_bundle_id(
        &self,
        bundle_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError>;
    fn load_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError>;
    fn load_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError>;
    fn recent(&self, limit: usize) -> Result<Vec<ReplayBundleRecord>, ReplayStoreError>;
    /// Return a stable, bundle-ID-ordered page from the complete replay index.
    ///
    /// `after_bundle_id` is an exclusive cursor. Unlike [`Self::recent`], this
    /// scan is intended for durable background reconciliation and must not
    /// silently discard older records when the store grows beyond a runtime
    /// work limit.
    fn scan_after_bundle_id(
        &self,
        after_bundle_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ReplayBundleRecord>, ReplayStoreError>;
    fn scan_after_sequence(
        &self,
        after_sequence: u64,
        limit: usize,
    ) -> Result<Vec<ReplayBundleRecord>, ReplayStoreError>;
    /// Load the durable consumer checkpoint used by hypothesis-graph admission.
    fn hypothesis_graph_checkpoint(
        &self,
    ) -> Result<HypothesisGraphReplayCheckpoint, ReplayStoreError>;
    /// Atomically persist a monotonic admission cursor and its bounded retry set.
    fn persist_hypothesis_graph_checkpoint(
        &self,
        checkpoint: &HypothesisGraphReplayCheckpoint,
    ) -> Result<(), ReplayStoreError>;
    fn health(&self) -> Result<ReplayStoreHealth, ReplayStoreError>;
}

/// Selectable replay store backend used by runtime composition.
#[derive(Debug, Clone)]
pub enum ConfiguredReplayBundleStore {
    Memory(MemoryReplayBundleStore),
    LocalFiles(FileReplayBundleStore),
}

impl ConfiguredReplayBundleStore {
    pub fn from_config(config: &BundleStoreConfig) -> Result<Self, ReplayStoreError> {
        match config {
            BundleStoreConfig::Memory => Ok(Self::Memory(MemoryReplayBundleStore::default())),
            BundleStoreConfig::LocalFiles { directory } => {
                Ok(Self::LocalFiles(FileReplayBundleStore::open(directory)?))
            }
        }
    }
}

impl ReplayBundleStore for ConfiguredReplayBundleStore {
    fn persist(&self, bundle: &ReplayBundle) -> Result<ReplayBundleRecord, ReplayStoreError> {
        match self {
            Self::Memory(store) => store.persist(bundle),
            Self::LocalFiles(store) => store.persist(bundle),
        }
    }

    fn load_by_bundle_id(
        &self,
        bundle_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError> {
        match self {
            Self::Memory(store) => store.load_by_bundle_id(bundle_id),
            Self::LocalFiles(store) => store.load_by_bundle_id(bundle_id),
        }
    }

    fn load_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError> {
        match self {
            Self::Memory(store) => store.load_by_hunt_id(hunt_id),
            Self::LocalFiles(store) => store.load_by_hunt_id(hunt_id),
        }
    }

    fn load_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError> {
        match self {
            Self::Memory(store) => store.load_by_receipt_id(receipt_id),
            Self::LocalFiles(store) => store.load_by_receipt_id(receipt_id),
        }
    }

    fn recent(&self, limit: usize) -> Result<Vec<ReplayBundleRecord>, ReplayStoreError> {
        match self {
            Self::Memory(store) => store.recent(limit),
            Self::LocalFiles(store) => store.recent(limit),
        }
    }

    fn scan_after_bundle_id(
        &self,
        after_bundle_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ReplayBundleRecord>, ReplayStoreError> {
        match self {
            Self::Memory(store) => store.scan_after_bundle_id(after_bundle_id, limit),
            Self::LocalFiles(store) => store.scan_after_bundle_id(after_bundle_id, limit),
        }
    }

    fn scan_after_sequence(
        &self,
        after_sequence: u64,
        limit: usize,
    ) -> Result<Vec<ReplayBundleRecord>, ReplayStoreError> {
        match self {
            Self::Memory(store) => store.scan_after_sequence(after_sequence, limit),
            Self::LocalFiles(store) => store.scan_after_sequence(after_sequence, limit),
        }
    }

    fn hypothesis_graph_checkpoint(
        &self,
    ) -> Result<HypothesisGraphReplayCheckpoint, ReplayStoreError> {
        match self {
            Self::Memory(store) => store.hypothesis_graph_checkpoint(),
            Self::LocalFiles(store) => store.hypothesis_graph_checkpoint(),
        }
    }

    fn persist_hypothesis_graph_checkpoint(
        &self,
        checkpoint: &HypothesisGraphReplayCheckpoint,
    ) -> Result<(), ReplayStoreError> {
        match self {
            Self::Memory(store) => store.persist_hypothesis_graph_checkpoint(checkpoint),
            Self::LocalFiles(store) => store.persist_hypothesis_graph_checkpoint(checkpoint),
        }
    }

    fn health(&self) -> Result<ReplayStoreHealth, ReplayStoreError> {
        match self {
            Self::Memory(store) => store.health(),
            Self::LocalFiles(store) => store.health(),
        }
    }
}

/// In-memory replay store for tests and detect-only workflows.
#[derive(Debug, Clone, Default)]
pub struct MemoryReplayBundleStore {
    bundles: Arc<RwLock<Vec<ReplayBundle>>>,
    sequencing: Arc<RwLock<MemoryReplaySequencing>>,
}

#[derive(Debug, Default)]
struct MemoryReplaySequencing {
    next_sequence: u64,
    by_bundle_id: BTreeMap<String, u64>,
    hypothesis_graph_checkpoint: HypothesisGraphReplayCheckpoint,
}

fn memory_replay_record(
    bundle: &ReplayBundle,
    sequencing: &MemoryReplaySequencing,
) -> Result<ReplayBundleRecord, ReplayStoreError> {
    let store_sequence = sequencing
        .by_bundle_id
        .get(&bundle.bundle_id)
        .copied()
        .ok_or_else(|| ReplayStoreError::InvalidState {
            reason: format!(
                "replay bundle `{}` is missing its store sequence",
                bundle.bundle_id
            ),
        })?;
    Ok(ReplayBundleRecord::from_bundle(
        bundle,
        "memory".to_string(),
        store_sequence,
    ))
}

impl ReplayBundleStore for MemoryReplayBundleStore {
    fn persist(&self, bundle: &ReplayBundle) -> Result<ReplayBundleRecord, ReplayStoreError> {
        let mut guard = self
            .bundles
            .write()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let mut sequencing = self
            .sequencing
            .write()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let store_sequence = match sequencing.by_bundle_id.get(&bundle.bundle_id).copied() {
            Some(sequence) => sequence,
            None => {
                sequencing.next_sequence =
                    sequencing.next_sequence.checked_add(1).ok_or_else(|| {
                        ReplayStoreError::InvalidState {
                            reason: "replay store sequence exhausted".to_string(),
                        }
                    })?;
                let sequence = sequencing.next_sequence;
                sequencing
                    .by_bundle_id
                    .insert(bundle.bundle_id.clone(), sequence);
                sequence
            }
        };
        guard.retain(|existing| existing.bundle_id != bundle.bundle_id);
        guard.push(bundle.clone());
        Ok(ReplayBundleRecord::from_bundle(
            bundle,
            "memory".to_string(),
            store_sequence,
        ))
    }

    fn load_by_bundle_id(
        &self,
        bundle_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let sequencing = self
            .sequencing
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let Some(bundle) = guard
            .iter()
            .find(|bundle| bundle.bundle_id == bundle_id)
            .cloned()
        else {
            return Ok(None);
        };
        let record = memory_replay_record(&bundle, &sequencing)?;
        Ok(Some(ReplayBundleLookup { record, bundle }))
    }

    fn load_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let sequencing = self
            .sequencing
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let bundle = sorted_recent_bundles(&guard)
            .into_iter()
            .find(|bundle| bundle.audit.hunt_id == hunt_id);
        let Some(bundle) = bundle else {
            return Ok(None);
        };
        let record = memory_replay_record(&bundle, &sequencing)?;
        Ok(Some(ReplayBundleLookup { record, bundle }))
    }

    fn load_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let sequencing = self
            .sequencing
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let bundle = sorted_recent_bundles(&guard).into_iter().find(|bundle| {
            bundle
                .audit
                .all_receipt_ids()
                .iter()
                .any(|id| id == receipt_id)
        });
        let Some(bundle) = bundle else {
            return Ok(None);
        };
        let record = memory_replay_record(&bundle, &sequencing)?;
        Ok(Some(ReplayBundleLookup { record, bundle }))
    }

    fn recent(&self, limit: usize) -> Result<Vec<ReplayBundleRecord>, ReplayStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let sequencing = self
            .sequencing
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let mut entries = sorted_recent_bundles(&guard)
            .into_iter()
            .map(|bundle| memory_replay_record(&bundle, &sequencing))
            .collect::<Result<Vec<_>, _>>()?;
        entries.truncate(limit);
        Ok(entries)
    }

    fn scan_after_bundle_id(
        &self,
        after_bundle_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ReplayBundleRecord>, ReplayStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let sequencing = self
            .sequencing
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let mut entries = guard
            .iter()
            .filter(|bundle| {
                after_bundle_id.is_none_or(|cursor| bundle.bundle_id.as_str() > cursor)
            })
            .map(|bundle| memory_replay_record(bundle, &sequencing))
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by(|left, right| left.bundle_id.cmp(&right.bundle_id));
        entries.truncate(limit);
        Ok(entries)
    }

    fn scan_after_sequence(
        &self,
        after_sequence: u64,
        limit: usize,
    ) -> Result<Vec<ReplayBundleRecord>, ReplayStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let sequencing = self
            .sequencing
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let mut records = guard
            .iter()
            .map(|bundle| memory_replay_record(bundle, &sequencing))
            .collect::<Result<Vec<_>, _>>()?;
        records.retain(|record| record.store_sequence > after_sequence);
        records.sort_by_key(|record| record.store_sequence);
        records.truncate(limit);
        Ok(records)
    }

    fn hypothesis_graph_checkpoint(
        &self,
    ) -> Result<HypothesisGraphReplayCheckpoint, ReplayStoreError> {
        Ok(self
            .sequencing
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?
            .hypothesis_graph_checkpoint
            .clone())
    }

    fn persist_hypothesis_graph_checkpoint(
        &self,
        checkpoint: &HypothesisGraphReplayCheckpoint,
    ) -> Result<(), ReplayStoreError> {
        let mut sequencing = self
            .sequencing
            .write()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        if checkpoint.cursor_sequence < sequencing.hypothesis_graph_checkpoint.cursor_sequence
            || checkpoint.cursor_sequence > sequencing.next_sequence
        {
            return Err(ReplayStoreError::InvalidState {
                reason: "hypothesis graph replay cursor is outside the monotonic store sequence"
                    .to_string(),
            });
        }
        sequencing.hypothesis_graph_checkpoint = checkpoint.clone();
        Ok(())
    }

    fn health(&self) -> Result<ReplayStoreHealth, ReplayStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        Ok(ReplayStoreHealth {
            backend: "memory".to_string(),
            durable: false,
            ready: true,
            stored_bundles: guard.len(),
            details: "ephemeral in-process replay store".to_string(),
        })
    }
}

/// File-backed replay store used for persistent audit and replay.
#[derive(Debug, Clone)]
pub struct FileReplayBundleStore {
    root: PathBuf,
    index_lock: Arc<Mutex<()>>,
}

static NEXT_REPLAY_INDEX_TEMP: AtomicU64 = AtomicU64::new(0);

impl FileReplayBundleStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReplayStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("bundles")).map_err(|source| ReplayStoreError::Write {
            path: root.clone(),
            source,
        })?;
        Ok(Self {
            root,
            index_lock: Arc::new(Mutex::new(())),
        })
    }

    fn bundles_dir(&self) -> PathBuf {
        self.root.join("bundles")
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ReplayIndex, ReplayStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReplayIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| ReplayStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let index = serde_json::from_str(&raw)
            .map_err(|source| ReplayStoreError::Parse { path, source })?;
        normalize_replay_index(index)
    }

    fn write_index(&self, index: &ReplayIndex) -> Result<(), ReplayStoreError> {
        let path = self.index_path();
        let raw =
            serde_json::to_string_pretty(index).map_err(|source| ReplayStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        let (temporary, mut file) = loop {
            let nonce = NEXT_REPLAY_INDEX_TEMP.fetch_add(1, Ordering::Relaxed);
            let temporary = self
                .root
                .join(format!(".index.json.tmp-{}-{nonce}", std::process::id()));
            match fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
            {
                Ok(file) => break (temporary, file),
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(ReplayStoreError::Write {
                        path: temporary,
                        source,
                    });
                }
            }
        };
        let result = (|| -> Result<(), std::io::Error> {
            file.write_all(raw.as_bytes())?;
            file.sync_all()?;
            fs::rename(&temporary, &path)?;
            fs::File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if let Err(source) = result {
            let _ = fs::remove_file(&temporary);
            return Err(ReplayStoreError::Write { path, source });
        }
        Ok(())
    }

    fn bundle_path(&self, bundle_id: &str) -> PathBuf {
        self.bundles_dir()
            .join(format!("{}.json", sanitize_id(bundle_id)))
    }

    fn write_bundle(&self, bundle: &ReplayBundle) -> Result<String, ReplayStoreError> {
        let path = self.bundle_path(&bundle.bundle_id);
        let raw =
            serde_json::to_string_pretty(bundle).map_err(|source| ReplayStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| ReplayStoreError::Write {
            path: path.clone(),
            source,
        })?;
        Ok(path
            .strip_prefix(&self.root)
            .unwrap_or(&path)
            .display()
            .to_string())
    }

    fn read_bundle(
        &self,
        record: ReplayBundleRecord,
    ) -> Result<ReplayBundleLookup, ReplayStoreError> {
        let path = self.root.join(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| ReplayStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let bundle = serde_json::from_str(&raw)
            .map_err(|source| ReplayStoreError::Parse { path, source })?;
        Ok(ReplayBundleLookup { record, bundle })
    }
}

impl ReplayBundleStore for FileReplayBundleStore {
    fn persist(&self, bundle: &ReplayBundle) -> Result<ReplayBundleRecord, ReplayStoreError> {
        let _guard = self
            .index_lock
            .lock()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let bundle_path = self.write_bundle(bundle)?;
        let mut index = self.read_index()?;
        let store_sequence = match index
            .entries
            .iter()
            .find(|entry| entry.bundle_id == bundle.bundle_id)
            .map(|entry| entry.store_sequence)
        {
            Some(sequence) => sequence,
            None => {
                index.next_sequence = index.next_sequence.checked_add(1).ok_or_else(|| {
                    ReplayStoreError::InvalidState {
                        reason: "replay store sequence exhausted".to_string(),
                    }
                })?;
                index.next_sequence
            }
        };
        index
            .entries
            .retain(|entry| entry.bundle_id != bundle.bundle_id);
        let record = ReplayBundleRecord::from_bundle(bundle, bundle_path, store_sequence);
        index.entries.push(record.clone());
        self.write_index(&index)?;
        Ok(record)
    }

    fn load_by_bundle_id(
        &self,
        bundle_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError> {
        let index = self.read_index()?;
        if let Some(record) = index
            .entries
            .into_iter()
            .find(|entry| entry.bundle_id == bundle_id)
        {
            return self.read_bundle(record).map(Some);
        }
        Ok(None)
    }

    fn load_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        if let Some(record) = entries.into_iter().find(|entry| entry.hunt_id == hunt_id) {
            return self.read_bundle(record).map(Some);
        }
        Ok(None)
    }

    fn load_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        if let Some(record) = entries.into_iter().find(|entry| {
            entry
                .related_receipt_ids
                .iter()
                .any(|candidate| candidate == receipt_id)
        }) {
            return self.read_bundle(record).map(Some);
        }
        Ok(None)
    }

    fn recent(&self, limit: usize) -> Result<Vec<ReplayBundleRecord>, ReplayStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        entries.truncate(limit);
        Ok(entries)
    }

    fn scan_after_bundle_id(
        &self,
        after_bundle_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ReplayBundleRecord>, ReplayStoreError> {
        let mut entries = self.read_index()?.entries;
        entries
            .retain(|entry| after_bundle_id.is_none_or(|cursor| entry.bundle_id.as_str() > cursor));
        entries.sort_by(|left, right| left.bundle_id.cmp(&right.bundle_id));
        entries.truncate(limit);
        Ok(entries)
    }

    fn scan_after_sequence(
        &self,
        after_sequence: u64,
        limit: usize,
    ) -> Result<Vec<ReplayBundleRecord>, ReplayStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.retain(|entry| entry.store_sequence > after_sequence);
        entries.sort_by_key(|entry| entry.store_sequence);
        entries.truncate(limit);
        Ok(entries)
    }

    fn hypothesis_graph_checkpoint(
        &self,
    ) -> Result<HypothesisGraphReplayCheckpoint, ReplayStoreError> {
        Ok(self.read_index()?.hypothesis_graph_checkpoint)
    }

    fn persist_hypothesis_graph_checkpoint(
        &self,
        checkpoint: &HypothesisGraphReplayCheckpoint,
    ) -> Result<(), ReplayStoreError> {
        let _guard = self
            .index_lock
            .lock()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let mut index = self.read_index()?;
        if checkpoint.cursor_sequence < index.hypothesis_graph_checkpoint.cursor_sequence
            || checkpoint.cursor_sequence > index.next_sequence
        {
            return Err(ReplayStoreError::InvalidState {
                reason: "hypothesis graph replay cursor is outside the monotonic store sequence"
                    .to_string(),
            });
        }
        if index.hypothesis_graph_checkpoint == *checkpoint {
            return Ok(());
        }
        index.hypothesis_graph_checkpoint = checkpoint.clone();
        self.write_index(&index)
    }

    fn health(&self) -> Result<ReplayStoreHealth, ReplayStoreError> {
        fs::create_dir_all(self.bundles_dir()).map_err(|source| ReplayStoreError::Write {
            path: self.root.clone(),
            source,
        })?;
        let stored_bundles = self.read_index()?.entries.len();
        Ok(ReplayStoreHealth {
            backend: "local_files".to_string(),
            durable: true,
            ready: true,
            stored_bundles,
            details: format!("bundle directory at {}", self.root.display()),
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ReplayIndex {
    entries: Vec<ReplayBundleRecord>,
    #[serde(default)]
    next_sequence: u64,
    #[serde(default)]
    hypothesis_graph_checkpoint: HypothesisGraphReplayCheckpoint,
}

fn normalize_replay_index(mut index: ReplayIndex) -> Result<ReplayIndex, ReplayStoreError> {
    let mut observed = BTreeSet::new();
    let mut bundle_ids = BTreeSet::new();
    let mut high_water = index.next_sequence;
    for entry in &index.entries {
        if entry.bundle_id.is_empty() || !bundle_ids.insert(entry.bundle_id.clone()) {
            return Err(ReplayStoreError::InvalidState {
                reason: format!(
                    "replay store bundle ID `{}` is empty or assigned more than once",
                    entry.bundle_id
                ),
            });
        }
        if entry.store_sequence == 0 {
            continue;
        }
        if !observed.insert(entry.store_sequence) {
            return Err(ReplayStoreError::InvalidState {
                reason: format!(
                    "replay store sequence {} is assigned more than once",
                    entry.store_sequence
                ),
            });
        }
        high_water = high_water.max(entry.store_sequence);
    }
    for entry in &mut index.entries {
        if entry.store_sequence == 0 {
            high_water =
                high_water
                    .checked_add(1)
                    .ok_or_else(|| ReplayStoreError::InvalidState {
                        reason: "replay store sequence exhausted during legacy migration"
                            .to_string(),
                    })?;
            entry.store_sequence = high_water;
        }
    }
    index.next_sequence = high_water;
    if index.hypothesis_graph_checkpoint.cursor_sequence > high_water {
        return Err(ReplayStoreError::InvalidState {
            reason: "hypothesis graph replay cursor exceeds the replay sequence high-water"
                .to_string(),
        });
    }
    Ok(index)
}

fn sorted_recent_bundles(bundles: &[ReplayBundle]) -> Vec<ReplayBundle> {
    let mut ordered = bundles.to_vec();
    ordered.sort_by_key(|entry| std::cmp::Reverse(entry.audit.created_at_ms));
    ordered
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        ConfiguredReplayBundleStore, FileReplayBundleStore, HypothesisGraphReplayCheckpoint,
        MemoryReplayBundleStore, ReplayBundleStore, ReplayPreview, ReplayStoreHealth,
    };
    use crate::{AuditResponseRecord, AuditTrail, PolicyRecord, ReplayBundle};
    use swarm_core::config::BundleStoreConfig;
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::{ActionRequest, PolicyVerdict};
    use swarm_response::{ExecutionMode, ResponseReceipt, ResponseStatus};
    use swarm_whisker::{DetectionFinding, ProcessStartEvent, TelemetryEvent, TelemetryPayload};

    fn sample_bundle() -> ReplayBundle {
        ReplayBundle {
            bundle_id: "bundle:hunt-1:1".to_string(),
            event: TelemetryEvent {
                source: "synthetic".to_string(),
                event_id: "evt-1".to_string(),
                timestamp: 1_700_000_000,
                host_id: Some("host-1".to_string()),
                payload: TelemetryPayload::ProcessStart(ProcessStartEvent {
                    parent_process: "winword".to_string(),
                    process_name: "powershell".to_string(),
                    command_line: "powershell.exe -enc AAA=".to_string(),
                    user: Some("alice".to_string()),
                    executable_path: None,
                    signer: None,
                    signature_valid: None,
                }),
            },
            findings: vec![DetectionFinding {
                finding_id: "finding-1".to_string(),
                event_id: "evt-1".to_string(),
                threat_class: ThreatClass::Execution,
                severity: Severity::Critical,
                confidence: 0.95,
                evidence: serde_json::json!({"signal": "encoded-command"}),
                strategy_id: "suspicious_process_tree".to_string(),
            }],
            deposits: Vec::new(),
            action_request: ActionRequest {
                hunt_id: HuntId("hunt-1".to_string()),
                requested_by: AgentId("whisker-a".to_string()),
                action: ResponseAction::DeployDecoy {
                    decoy_type: "honeypot".to_string(),
                    target_zone: "dmz".to_string(),
                },
                severity: Severity::Critical,
                evidence: serde_json::json!({"signal": "encoded-command"}),
            },
            rehearsal: None,
            audit: AuditTrail {
                trail_id: "trail:hunt-1:1".to_string(),
                hunt_id: "hunt-1".to_string(),
                related_receipt_ids: vec!["receipt-upstream-1".to_string()],
                detection: DetectionFinding {
                    finding_id: "finding-1".to_string(),
                    event_id: "evt-1".to_string(),
                    threat_class: ThreatClass::Execution,
                    severity: Severity::Critical,
                    confidence: 0.95,
                    evidence: serde_json::json!({"signal": "encoded-command"}),
                    strategy_id: "suspicious_process_tree".to_string(),
                },
                policy: PolicyRecord {
                    verdict: PolicyVerdict::Allow,
                    rule_name: "test.allow".to_string(),
                    reason: "allowed".to_string(),
                    lease: None,
                },
                response: AuditResponseRecord::Success(ResponseReceipt {
                    receipt_id: "receipt-response-1".to_string(),
                    action: "deploy_decoy".to_string(),
                    mode: ExecutionMode::Enforced,
                    status: ResponseStatus::Executed,
                    summary: "decoy deployed".to_string(),
                    details: serde_json::json!({"zone": "dmz"}),
                    audit: Default::default(),
                }),
                created_at_ms: 1_700_000_000_123,
            },
        }
    }

    #[test]
    fn file_store_persists_and_loads_by_hunt_and_receipt() {
        let root = std::env::temp_dir().join("swarm-spine-store");
        let _ = std::fs::remove_dir_all(&root);
        let store = FileReplayBundleStore::open(&root).unwrap();
        let bundle = sample_bundle();
        let record = store.persist(&bundle).unwrap();

        assert_eq!(record.hunt_id, "hunt-1");
        assert_eq!(
            record.response_receipt_id.as_deref(),
            Some("receipt-response-1")
        );

        let by_hunt = store.load_by_hunt_id("hunt-1").unwrap().unwrap();
        assert_eq!(by_hunt.bundle.bundle_id, bundle.bundle_id);

        let by_receipt = store
            .load_by_receipt_id("receipt-response-1")
            .unwrap()
            .unwrap();
        assert_eq!(by_receipt.record.bundle_id, bundle.bundle_id);

        let preview = ReplayPreview::from_bundle(&by_receipt.bundle);
        assert_eq!(preview.response_kind, "success");
        assert!(
            preview
                .note
                .contains("no live response action was re-executed")
        );

        let health = store.health().unwrap();
        assert_eq!(
            health,
            ReplayStoreHealth {
                backend: "local_files".to_string(),
                durable: true,
                ready: true,
                stored_bundles: 1,
                details: format!("bundle directory at {}", root.display()),
            }
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn configured_store_selects_memory_and_local_backends() {
        let memory = ConfiguredReplayBundleStore::from_config(&BundleStoreConfig::Memory).unwrap();
        assert_eq!(memory.health().unwrap().backend, "memory");

        let root = std::env::temp_dir().join("swarm-spine-configured-store");
        let _ = std::fs::remove_dir_all(&root);
        let local = ConfiguredReplayBundleStore::from_config(&BundleStoreConfig::LocalFiles {
            directory: root.display().to_string(),
        })
        .unwrap();
        assert_eq!(local.health().unwrap().backend, "local_files");
        let _ = std::fs::remove_dir_all(root);
    }

    fn assert_complete_stable_scan(store: &dyn ReplayBundleStore) {
        for bundle_id in ["bundle:c", "bundle:a", "bundle:d", "bundle:b"] {
            let mut bundle = sample_bundle();
            bundle.bundle_id = bundle_id.to_string();
            store.persist(&bundle).unwrap();
        }

        let first = store.scan_after_bundle_id(None, 2).unwrap();
        assert_eq!(
            first
                .iter()
                .map(|record| record.bundle_id.as_str())
                .collect::<Vec<_>>(),
            ["bundle:a", "bundle:b"]
        );
        let second = store
            .scan_after_bundle_id(first.last().map(|record| record.bundle_id.as_str()), 2)
            .unwrap();
        assert_eq!(
            second
                .iter()
                .map(|record| record.bundle_id.as_str())
                .collect::<Vec<_>>(),
            ["bundle:c", "bundle:d"]
        );
        assert!(
            store
                .scan_after_bundle_id(Some("bundle:d"), 2)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn memory_and_file_stores_scan_every_replay_with_an_exclusive_stable_cursor() {
        assert_complete_stable_scan(&MemoryReplayBundleStore::default());

        let root =
            std::env::temp_dir().join(format!("swarm-spine-complete-scan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let file = FileReplayBundleStore::open(&root).unwrap();
        assert_complete_stable_scan(&file);
        let _ = std::fs::remove_dir_all(root);
    }

    fn assert_monotonic_sequence_scan(store: &dyn ReplayBundleStore) {
        for bundle_id in ["bundle:z", "bundle:a"] {
            let mut bundle = sample_bundle();
            bundle.bundle_id = bundle_id.to_string();
            store.persist(&bundle).unwrap();
        }

        let first = store.scan_after_sequence(0, 1).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].bundle_id, "bundle:z");
        assert_eq!(first[0].store_sequence, 1);
        let second = store
            .scan_after_sequence(first[0].store_sequence, 1)
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].bundle_id, "bundle:a");
        assert_eq!(second[0].store_sequence, 2);
    }

    #[test]
    fn memory_and_file_stores_scan_by_monotonic_persistence_sequence() {
        assert_monotonic_sequence_scan(&MemoryReplayBundleStore::default());

        let root = std::env::temp_dir().join(format!(
            "swarm-spine-monotonic-sequence-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let file = FileReplayBundleStore::open(&root).unwrap();
        assert_monotonic_sequence_scan(&file);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn file_store_persists_hypothesis_graph_checkpoint_across_reopen() {
        let root = std::env::temp_dir().join(format!(
            "swarm-spine-graph-checkpoint-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = FileReplayBundleStore::open(&root).unwrap();
        store.persist(&sample_bundle()).unwrap();
        let checkpoint = HypothesisGraphReplayCheckpoint {
            cursor_sequence: 1,
            retry_bundle_ids: ["bundle:retry".to_string()].into_iter().collect(),
        };
        store
            .persist_hypothesis_graph_checkpoint(&checkpoint)
            .unwrap();
        drop(store);

        let reopened = FileReplayBundleStore::open(&root).unwrap();
        assert_eq!(reopened.hypothesis_graph_checkpoint().unwrap(), checkpoint);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn replay_checkpoint_rejects_cursor_regression_and_future_sequence() {
        let store = MemoryReplayBundleStore::default();
        store.persist(&sample_bundle()).unwrap();
        store
            .persist_hypothesis_graph_checkpoint(&HypothesisGraphReplayCheckpoint {
                cursor_sequence: 1,
                retry_bundle_ids: Default::default(),
            })
            .unwrap();

        assert!(
            store
                .persist_hypothesis_graph_checkpoint(&HypothesisGraphReplayCheckpoint {
                    cursor_sequence: 0,
                    retry_bundle_ids: Default::default(),
                })
                .is_err()
        );
        assert!(
            store
                .persist_hypothesis_graph_checkpoint(&HypothesisGraphReplayCheckpoint {
                    cursor_sequence: 2,
                    retry_bundle_ids: Default::default(),
                })
                .is_err()
        );
    }
}
