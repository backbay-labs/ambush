use crate::ReplayBundle;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use swarm_core::config::BundleStoreConfig;
use swarm_core::types::ResponseRehearsalPreview;

/// Metadata for one persisted replay bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayBundleRecord {
    pub bundle_id: String,
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
    fn from_bundle(bundle: &ReplayBundle, bundle_path: String) -> Self {
        Self {
            bundle_id: bundle.bundle_id.clone(),
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

/// Replay store errors.
#[derive(Debug, thiserror::Error)]
pub enum ReplayStoreError {
    #[error("replay store lock poisoned")]
    PoisonedLock,

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
}

impl ReplayBundleStore for MemoryReplayBundleStore {
    fn persist(&self, bundle: &ReplayBundle) -> Result<ReplayBundleRecord, ReplayStoreError> {
        let mut guard = self
            .bundles
            .write()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        guard.retain(|existing| existing.bundle_id != bundle.bundle_id);
        guard.push(bundle.clone());
        Ok(ReplayBundleRecord::from_bundle(
            bundle,
            "memory".to_string(),
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
        Ok(guard
            .iter()
            .find(|bundle| bundle.bundle_id == bundle_id)
            .cloned()
            .map(|bundle| ReplayBundleLookup {
                record: ReplayBundleRecord::from_bundle(&bundle, "memory".to_string()),
                bundle,
            }))
    }

    fn load_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        Ok(sorted_recent_bundles(&guard)
            .into_iter()
            .find(|bundle| bundle.audit.hunt_id == hunt_id)
            .map(|bundle| ReplayBundleLookup {
                record: ReplayBundleRecord::from_bundle(&bundle, "memory".to_string()),
                bundle,
            }))
    }

    fn load_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ReplayBundleLookup>, ReplayStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        Ok(sorted_recent_bundles(&guard)
            .into_iter()
            .find(|bundle| {
                bundle
                    .audit
                    .all_receipt_ids()
                    .iter()
                    .any(|id| id == receipt_id)
            })
            .map(|bundle| ReplayBundleLookup {
                record: ReplayBundleRecord::from_bundle(&bundle, "memory".to_string()),
                bundle,
            }))
    }

    fn recent(&self, limit: usize) -> Result<Vec<ReplayBundleRecord>, ReplayStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayStoreError::PoisonedLock)?;
        let mut entries = sorted_recent_bundles(&guard)
            .into_iter()
            .map(|bundle| ReplayBundleRecord::from_bundle(&bundle, "memory".to_string()))
            .collect::<Vec<_>>();
        entries.truncate(limit);
        Ok(entries)
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
}

impl FileReplayBundleStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReplayStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("bundles")).map_err(|source| ReplayStoreError::Write {
            path: root.clone(),
            source,
        })?;
        Ok(Self { root })
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
        serde_json::from_str(&raw).map_err(|source| ReplayStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &ReplayIndex) -> Result<(), ReplayStoreError> {
        let path = self.index_path();
        let raw =
            serde_json::to_string_pretty(index).map_err(|source| ReplayStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| ReplayStoreError::Write { path, source })
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
        let bundle_path = self.write_bundle(bundle)?;
        let mut index = self.read_index()?;
        index
            .entries
            .retain(|entry| entry.bundle_id != bundle.bundle_id);
        let record = ReplayBundleRecord::from_bundle(bundle, bundle_path);
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
        entries.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
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
        entries.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
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
        entries.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
        entries.truncate(limit);
        Ok(entries)
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
}

fn sorted_recent_bundles(bundles: &[ReplayBundle]) -> Vec<ReplayBundle> {
    let mut ordered = bundles.to_vec();
    ordered.sort_by(|left, right| right.audit.created_at_ms.cmp(&left.audit.created_at_ms));
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
        ConfiguredReplayBundleStore, FileReplayBundleStore, ReplayBundleStore, ReplayPreview,
        ReplayStoreHealth,
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
}
