use super::types::{
    DetectorVerificationLookup, DetectorVerificationRecord, DetectorVerificationReport,
    PromotionReviewLookup, PromotionReviewPacket, PromotionReviewRecord, ReplayRunBundle,
    ReplayRunLookup, ReplayRunRecord, ReplayRunStoreHealth, StrategyExperimentLookup,
    StrategyExperimentRecord, StrategyExperimentReport, StrategyShadowLookup, StrategyShadowRecord,
    StrategyShadowReport,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Replay run store errors.
#[derive(Debug, thiserror::Error)]
pub enum ReplayRunStoreError {
    #[error("replay run store lock poisoned")]
    PoisonedLock,

    #[error("failed to read replay run store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write replay run store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse replay run store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Store contract for durable replay runs.
pub trait ReplayRunStore: Send + Sync {
    fn persist(&self, bundle: &ReplayRunBundle) -> Result<ReplayRunRecord, ReplayRunStoreError>;
    fn load_by_run_id(&self, run_id: &str) -> Result<Option<ReplayRunLookup>, ReplayRunStoreError>;
    fn recent(&self, limit: usize) -> Result<Vec<ReplayRunRecord>, ReplayRunStoreError>;
    fn health(&self) -> Result<ReplayRunStoreHealth, ReplayRunStoreError>;
}

/// In-memory replay run store used by tests.
#[derive(Debug, Clone, Default)]
pub struct MemoryReplayRunStore {
    bundles: Arc<RwLock<Vec<ReplayRunBundle>>>,
}

impl ReplayRunStore for MemoryReplayRunStore {
    fn persist(&self, bundle: &ReplayRunBundle) -> Result<ReplayRunRecord, ReplayRunStoreError> {
        let mut guard = self
            .bundles
            .write()
            .map_err(|_| ReplayRunStoreError::PoisonedLock)?;
        guard.retain(|existing| existing.run_id != bundle.run_id);
        guard.push(bundle.clone());
        Ok(ReplayRunRecord::from_bundle(bundle, "memory".to_string()))
    }

    fn load_by_run_id(&self, run_id: &str) -> Result<Option<ReplayRunLookup>, ReplayRunStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayRunStoreError::PoisonedLock)?;
        Ok(guard
            .iter()
            .find(|bundle| bundle.run_id == run_id)
            .cloned()
            .map(|bundle| ReplayRunLookup {
                record: ReplayRunRecord::from_bundle(&bundle, "memory".to_string()),
                bundle,
            }))
    }

    fn recent(&self, limit: usize) -> Result<Vec<ReplayRunRecord>, ReplayRunStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayRunStoreError::PoisonedLock)?;
        let mut entries = sorted_recent_runs(&guard)
            .into_iter()
            .map(|bundle| ReplayRunRecord::from_bundle(&bundle, "memory".to_string()))
            .collect::<Vec<_>>();
        entries.truncate(limit);
        Ok(entries)
    }

    fn health(&self) -> Result<ReplayRunStoreHealth, ReplayRunStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| ReplayRunStoreError::PoisonedLock)?;
        Ok(ReplayRunStoreHealth {
            backend: "memory".to_string(),
            durable: false,
            ready: true,
            stored_runs: guard.len(),
            details: "ephemeral in-process replay run store".to_string(),
        })
    }
}

/// File-backed replay run store used by the operator CLI and CI flows.
#[derive(Debug, Clone)]
pub struct FileReplayRunStore {
    root: PathBuf,
}

impl FileReplayRunStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReplayRunStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("runs")).map_err(|source| ReplayRunStoreError::Write {
            path: root.clone(),
            source,
        })?;
        Ok(Self { root })
    }

    fn run_path(&self, run_id: &str) -> PathBuf {
        self.root
            .join("runs")
            .join(format!("{}.json", sanitize_id(run_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ReplayRunIndex, ReplayRunStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReplayRunIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| ReplayRunStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| ReplayRunStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &ReplayRunIndex) -> Result<(), ReplayRunStoreError> {
        let path = self.index_path();
        let raw =
            serde_json::to_string_pretty(index).map_err(|source| ReplayRunStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| ReplayRunStoreError::Write { path, source })
    }
}

impl ReplayRunStore for FileReplayRunStore {
    fn persist(&self, bundle: &ReplayRunBundle) -> Result<ReplayRunRecord, ReplayRunStoreError> {
        let path = self.run_path(&bundle.run_id);
        let raw =
            serde_json::to_string_pretty(bundle).map_err(|source| ReplayRunStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| ReplayRunStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = ReplayRunRecord::from_bundle(bundle, path.display().to_string());
        index.entries.retain(|entry| entry.run_id != record.run_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    fn load_by_run_id(&self, run_id: &str) -> Result<Option<ReplayRunLookup>, ReplayRunStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.run_id == run_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| ReplayRunStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let bundle = serde_json::from_str(&raw).map_err(|source| ReplayRunStoreError::Parse {
            path: path.clone(),
            source,
        })?;
        Ok(Some(ReplayRunLookup { record, bundle }))
    }

    fn recent(&self, limit: usize) -> Result<Vec<ReplayRunRecord>, ReplayRunStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.truncate(limit);
        Ok(entries)
    }

    fn health(&self) -> Result<ReplayRunStoreHealth, ReplayRunStoreError> {
        let entries = self.read_index()?.entries;
        Ok(ReplayRunStoreHealth {
            backend: "local_files".to_string(),
            durable: true,
            ready: true,
            stored_runs: entries.len(),
            details: format!("replay run bundles persisted under {}", self.root.display()),
        })
    }
}

/// Detector experiment store errors.
#[derive(Debug, thiserror::Error)]
pub enum ExperimentStoreError {
    #[error("failed to read experiment store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write experiment store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse experiment store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Detector verification store errors.
#[derive(Debug, thiserror::Error)]
pub enum VerificationStoreError {
    #[error("failed to read verification store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write verification store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse verification store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Shadow report store errors.
#[derive(Debug, thiserror::Error)]
pub enum ShadowStoreError {
    #[error("failed to read shadow store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write shadow store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse shadow store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Promotion review store errors.
#[derive(Debug, thiserror::Error)]
pub enum PromotionReviewStoreError {
    #[error("failed to read promotion review store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write promotion review store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse promotion review store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed experiment store used for offline detector reports.
#[derive(Debug, Clone)]
pub struct FileExperimentStore {
    root: PathBuf,
}

impl FileExperimentStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ExperimentStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| ExperimentStoreError::Write {
            path: root.clone(),
            source,
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, experiment_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(experiment_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ExperimentIndex, ExperimentStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ExperimentIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| ExperimentStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| ExperimentStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &ExperimentIndex) -> Result<(), ExperimentStoreError> {
        let path = self.index_path();
        let raw =
            serde_json::to_string_pretty(index).map_err(|source| ExperimentStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| ExperimentStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &StrategyExperimentReport,
    ) -> Result<StrategyExperimentRecord, ExperimentStoreError> {
        let path = self.report_path(&report.experiment_id);
        let raw =
            serde_json::to_string_pretty(report).map_err(|source| ExperimentStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| ExperimentStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = StrategyExperimentRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.experiment_id != record.experiment_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        experiment_id: &str,
    ) -> Result<Option<StrategyExperimentLookup>, ExperimentStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.experiment_id == experiment_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| ExperimentStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report = serde_json::from_str(&raw).map_err(|source| ExperimentStoreError::Parse {
            path: path.clone(),
            source,
        })?;
        Ok(Some(StrategyExperimentLookup { record, report }))
    }
}

/// File-backed store for detector verification reports.
#[derive(Debug, Clone)]
pub struct FileVerificationStore {
    root: PathBuf,
}

impl FileVerificationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, VerificationStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            VerificationStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, verification_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(verification_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<VerificationIndex, VerificationStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(VerificationIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| VerificationStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| VerificationStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &VerificationIndex) -> Result<(), VerificationStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            VerificationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| VerificationStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &DetectorVerificationReport,
    ) -> Result<DetectorVerificationRecord, VerificationStoreError> {
        let path = self.report_path(&report.verification_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            VerificationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| VerificationStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = DetectorVerificationRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.verification_id != record.verification_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        verification_id: &str,
    ) -> Result<Option<DetectorVerificationLookup>, VerificationStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.verification_id == verification_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| VerificationStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report =
            serde_json::from_str(&raw).map_err(|source| VerificationStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(DetectorVerificationLookup { record, report }))
    }
}

/// File-backed store for shadow comparison reports.
#[derive(Debug, Clone)]
pub struct FileShadowStore {
    root: PathBuf,
}

impl FileShadowStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ShadowStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| ShadowStoreError::Write {
            path: root.clone(),
            source,
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, shadow_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(shadow_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ShadowIndex, ShadowStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ShadowIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| ShadowStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| ShadowStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &ShadowIndex) -> Result<(), ShadowStoreError> {
        let path = self.index_path();
        let raw =
            serde_json::to_string_pretty(index).map_err(|source| ShadowStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| ShadowStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &StrategyShadowReport,
    ) -> Result<StrategyShadowRecord, ShadowStoreError> {
        let path = self.report_path(&report.shadow_id);
        let raw =
            serde_json::to_string_pretty(report).map_err(|source| ShadowStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| ShadowStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = StrategyShadowRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.shadow_id != record.shadow_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(&self, shadow_id: &str) -> Result<Option<StrategyShadowLookup>, ShadowStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.shadow_id == shadow_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| ShadowStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report = serde_json::from_str(&raw).map_err(|source| ShadowStoreError::Parse {
            path: path.clone(),
            source,
        })?;
        Ok(Some(StrategyShadowLookup { record, report }))
    }
}

/// File-backed store for promotion review packets.
#[derive(Debug, Clone)]
pub struct FilePromotionReviewStore {
    root: PathBuf,
}

impl FilePromotionReviewStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PromotionReviewStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            PromotionReviewStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, review_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(review_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<PromotionReviewIndex, PromotionReviewStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(PromotionReviewIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| PromotionReviewStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| PromotionReviewStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &PromotionReviewIndex) -> Result<(), PromotionReviewStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            PromotionReviewStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| PromotionReviewStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        packet: &PromotionReviewPacket,
    ) -> Result<PromotionReviewRecord, PromotionReviewStoreError> {
        let path = self.report_path(&packet.review_id);
        let raw = serde_json::to_string_pretty(packet).map_err(|source| {
            PromotionReviewStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| PromotionReviewStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = PromotionReviewRecord::from_packet(packet, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.review_id != record.review_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        review_id: &str,
    ) -> Result<Option<PromotionReviewLookup>, PromotionReviewStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.review_id == review_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| PromotionReviewStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let packet =
            serde_json::from_str(&raw).map_err(|source| PromotionReviewStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(PromotionReviewLookup { record, packet }))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ReplayRunIndex {
    entries: Vec<ReplayRunRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ExperimentIndex {
    entries: Vec<StrategyExperimentRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct VerificationIndex {
    entries: Vec<DetectorVerificationRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ShadowIndex {
    entries: Vec<StrategyShadowRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PromotionReviewIndex {
    entries: Vec<PromotionReviewRecord>,
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

fn sorted_recent_runs(bundles: &[ReplayRunBundle]) -> Vec<ReplayRunBundle> {
    let mut ordered = bundles.to_vec();
    ordered.sort_by_key(|bundle| std::cmp::Reverse(bundle.created_at_ms));
    ordered
}
