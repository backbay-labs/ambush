use crate::ReplayBundle;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use swarm_core::config::BundleStoreConfig;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;
use swarm_whisker::TelemetryPayload;

static INVESTIGATION_CLAIM_TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);
const INVESTIGATION_CLAIM_TEMP_ATTEMPTS: usize = 64;

/// Persisted status of one investigation job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationStatus {
    Queued,
    Running,
    Completed,
    Failed,
    TimedOut,
}

/// Priority class assigned to an async investigation job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationPriorityClass {
    Critical,
    High,
    Normal,
    #[default]
    Deferred,
}

/// Explainable priority breakdown for one queued investigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InvestigationPriority {
    pub class: InvestigationPriorityClass,
    pub severity_basis_points: u16,
    pub freshness_basis_points: u16,
    pub learned_value_basis_points: u16,
    pub starvation_boost_basis_points: u16,
    pub total_basis_points: u16,
}

/// One candidate interpretation for an ambiguous investigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InvestigationInterpretation {
    pub interpretation_id: String,
    pub label: String,
    pub rationale: String,
    #[serde(default)]
    pub supporting_evidence: Vec<String>,
}

/// One durable vote supporting a candidate interpretation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InvestigationVote {
    pub voter: String,
    pub interpretation_id: String,
    pub confidence_basis_points: u16,
    pub rationale: String,
}

/// Final interpretation decision for one investigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InvestigationDecision {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_interpretation_id: Option<String>,
    #[serde(default)]
    pub final_confidence_basis_points: u16,
    #[serde(default)]
    pub ambiguous: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// Durable enrichment artifact derived from a replay bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationBundle {
    pub investigation_id: String,
    pub source_bundle_id: String,
    pub hunt_id: String,
    pub trail_id: String,
    pub event_id: String,
    pub finding_id: String,
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub strategy_id: String,
    pub response_kind: String,
    pub related_receipt_ids: Vec<String>,
    pub host_id: Option<String>,
    pub user: Option<String>,
    pub process_name: Option<String>,
    pub queued_at_ms: i64,
    pub started_at_ms: Option<i64>,
    pub completed_at_ms: Option<i64>,
    pub status: InvestigationStatus,
    #[serde(default)]
    pub priority: InvestigationPriority,
    pub summary: Option<String>,
    pub evidence_points: Vec<String>,
    pub correlation_keys: Vec<String>,
    #[serde(default)]
    pub candidate_interpretations: Vec<InvestigationInterpretation>,
    #[serde(default)]
    pub vote_lineage: Vec<InvestigationVote>,
    #[serde(default)]
    pub decision: InvestigationDecision,
    pub failure_reason: Option<String>,
    #[serde(default)]
    pub graph_findings_published: bool,
}

impl InvestigationBundle {
    pub fn queued_from_bundle(
        replay: &ReplayBundle,
        investigation_id: String,
        queued_at_ms: i64,
        priority: InvestigationPriority,
    ) -> Self {
        let host_id = replay.event.host_id.clone();
        let process_name = extract_process_name(replay);
        let user = extract_user(replay);
        Self {
            investigation_id,
            source_bundle_id: replay.bundle_id.clone(),
            hunt_id: replay.audit.hunt_id.clone(),
            trail_id: replay.audit.trail_id.clone(),
            event_id: replay.event.event_id.clone(),
            finding_id: replay.audit.detection.finding_id.clone(),
            threat_class: replay.audit.detection.threat_class.clone(),
            severity: replay.audit.detection.severity,
            strategy_id: replay.audit.detection.strategy_id.clone(),
            response_kind: replay.audit.response_kind().to_string(),
            related_receipt_ids: replay.audit.all_receipt_ids(),
            host_id,
            user,
            process_name,
            queued_at_ms,
            started_at_ms: None,
            completed_at_ms: None,
            status: InvestigationStatus::Queued,
            priority,
            summary: None,
            evidence_points: Vec::new(),
            correlation_keys: Vec::new(),
            candidate_interpretations: Vec::new(),
            vote_lineage: Vec::new(),
            decision: InvestigationDecision::default(),
            failure_reason: None,
            graph_findings_published: false,
        }
    }

    pub fn with_status(
        mut self,
        status: InvestigationStatus,
        started_at_ms: Option<i64>,
        completed_at_ms: Option<i64>,
    ) -> Self {
        self.status = status;
        self.started_at_ms = started_at_ms;
        self.completed_at_ms = completed_at_ms;
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_summary(
        mut self,
        summary: String,
        evidence_points: Vec<String>,
        correlation_keys: Vec<String>,
        candidate_interpretations: Vec<InvestigationInterpretation>,
        vote_lineage: Vec<InvestigationVote>,
        decision: InvestigationDecision,
        completed_at_ms: i64,
    ) -> Self {
        self.status = InvestigationStatus::Completed;
        self.completed_at_ms = Some(completed_at_ms);
        self.summary = Some(summary);
        self.evidence_points = evidence_points;
        self.correlation_keys = correlation_keys;
        self.candidate_interpretations = candidate_interpretations;
        self.vote_lineage = vote_lineage;
        self.decision = decision;
        self.failure_reason = None;
        self
    }

    pub fn with_failure(
        mut self,
        status: InvestigationStatus,
        reason: String,
        completed_at_ms: i64,
    ) -> Self {
        self.status = status;
        self.completed_at_ms = Some(completed_at_ms);
        self.failure_reason = Some(reason);
        self
    }

    pub fn with_graph_findings_published(mut self) -> Self {
        self.graph_findings_published = true;
        self
    }

    pub fn last_updated_ms(&self) -> i64 {
        self.completed_at_ms
            .or(self.started_at_ms)
            .unwrap_or(self.queued_at_ms)
    }
}

/// Metadata surfaced for recent investigations and operator review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationBundleRecord {
    pub investigation_id: String,
    pub source_bundle_id: String,
    pub hunt_id: String,
    pub trail_id: String,
    pub event_id: String,
    pub finding_id: String,
    pub related_receipt_ids: Vec<String>,
    pub host_id: Option<String>,
    pub user: Option<String>,
    pub process_name: Option<String>,
    pub response_kind: String,
    pub status: InvestigationStatus,
    pub queued_at_ms: i64,
    pub last_updated_ms: i64,
    pub priority_class: InvestigationPriorityClass,
    pub priority_score_basis_points: u16,
    pub candidate_interpretation_count: usize,
    pub selected_interpretation_id: Option<String>,
    pub final_confidence_basis_points: u16,
    pub ambiguous: bool,
    #[serde(default)]
    pub graph_findings_published: bool,
    pub summary_preview: Option<String>,
    pub failure_reason: Option<String>,
    pub correlation_keys: Vec<String>,
    pub bundle_path: String,
}

impl InvestigationBundleRecord {
    fn from_bundle(bundle: &InvestigationBundle, bundle_path: String) -> Self {
        Self {
            investigation_id: bundle.investigation_id.clone(),
            source_bundle_id: bundle.source_bundle_id.clone(),
            hunt_id: bundle.hunt_id.clone(),
            trail_id: bundle.trail_id.clone(),
            event_id: bundle.event_id.clone(),
            finding_id: bundle.finding_id.clone(),
            related_receipt_ids: bundle.related_receipt_ids.clone(),
            host_id: bundle.host_id.clone(),
            user: bundle.user.clone(),
            process_name: bundle.process_name.clone(),
            response_kind: bundle.response_kind.clone(),
            status: bundle.status,
            queued_at_ms: bundle.queued_at_ms,
            last_updated_ms: bundle.last_updated_ms(),
            priority_class: bundle.priority.class,
            priority_score_basis_points: bundle.priority.total_basis_points,
            candidate_interpretation_count: bundle.candidate_interpretations.len(),
            selected_interpretation_id: bundle.decision.selected_interpretation_id.clone(),
            final_confidence_basis_points: bundle.decision.final_confidence_basis_points,
            ambiguous: bundle.decision.ambiguous,
            graph_findings_published: bundle.graph_findings_published,
            summary_preview: bundle
                .summary
                .as_ref()
                .map(|summary| truncate(summary, 120)),
            failure_reason: bundle.failure_reason.clone(),
            correlation_keys: bundle.correlation_keys.clone(),
            bundle_path,
        }
    }
}

/// Lookup result for a persisted investigation bundle.
#[derive(Debug, Clone)]
pub struct InvestigationBundleLookup {
    pub record: InvestigationBundleRecord,
    pub bundle: InvestigationBundle,
}

/// Health summary for an investigation bundle backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationStoreHealth {
    pub backend: String,
    pub durable: bool,
    pub ready: bool,
    pub stored_bundles: usize,
    pub details: String,
}

/// Investigation store errors.
#[derive(Debug, thiserror::Error)]
pub enum InvestigationStoreError {
    #[error("investigation store lock poisoned")]
    PoisonedLock,

    #[error("failed to read investigation store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write investigation store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse investigation store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("investigation execution claim conflicts for `{investigation_id}`")]
    ExecutionClaimConflict { investigation_id: String },

    #[error(
        "investigation `{investigation_id}` cannot regress from {persisted:?} to {attempted:?}"
    )]
    StatusRegression {
        investigation_id: String,
        persisted: InvestigationStatus,
        attempted: InvestigationStatus,
    },

    #[error("investigation store path contains a parent-directory component: `{path}`")]
    UnsafePath { path: PathBuf },
}

/// Result of the non-reclaimable durable fence acquired immediately before an
/// investigation strategy executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvestigationExecutionClaim {
    Acquired,
    AlreadyAcquired,
}

/// Store contract for durable investigation bundles.
pub trait InvestigationBundleStore: Send + Sync {
    fn persist(
        &self,
        bundle: &InvestigationBundle,
    ) -> Result<InvestigationBundleRecord, InvestigationStoreError>;
    fn load_by_investigation_id(
        &self,
        investigation_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationStoreError>;
    fn load_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationStoreError>;
    fn load_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationStoreError>;
    fn recent(
        &self,
        limit: usize,
    ) -> Result<Vec<InvestigationBundleRecord>, InvestigationStoreError>;
    fn health(&self) -> Result<InvestigationStoreHealth, InvestigationStoreError>;
    fn claim_execution(
        &self,
        bundle: &InvestigationBundle,
    ) -> Result<InvestigationExecutionClaim, InvestigationStoreError>;
}

/// Configured investigation store backend.
#[derive(Debug, Clone)]
pub enum ConfiguredInvestigationBundleStore {
    Memory(MemoryInvestigationBundleStore),
    LocalFiles(FileInvestigationBundleStore),
}

impl ConfiguredInvestigationBundleStore {
    pub fn from_config(config: &BundleStoreConfig) -> Result<Self, InvestigationStoreError> {
        match config {
            BundleStoreConfig::Memory => {
                Ok(Self::Memory(MemoryInvestigationBundleStore::default()))
            }
            BundleStoreConfig::LocalFiles { directory } => Ok(Self::LocalFiles(
                FileInvestigationBundleStore::open(directory)?,
            )),
        }
    }
}

impl InvestigationBundleStore for ConfiguredInvestigationBundleStore {
    fn persist(
        &self,
        bundle: &InvestigationBundle,
    ) -> Result<InvestigationBundleRecord, InvestigationStoreError> {
        match self {
            Self::Memory(store) => store.persist(bundle),
            Self::LocalFiles(store) => store.persist(bundle),
        }
    }

    fn load_by_investigation_id(
        &self,
        investigation_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationStoreError> {
        match self {
            Self::Memory(store) => store.load_by_investigation_id(investigation_id),
            Self::LocalFiles(store) => store.load_by_investigation_id(investigation_id),
        }
    }

    fn load_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationStoreError> {
        match self {
            Self::Memory(store) => store.load_by_hunt_id(hunt_id),
            Self::LocalFiles(store) => store.load_by_hunt_id(hunt_id),
        }
    }

    fn load_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationStoreError> {
        match self {
            Self::Memory(store) => store.load_by_receipt_id(receipt_id),
            Self::LocalFiles(store) => store.load_by_receipt_id(receipt_id),
        }
    }

    fn recent(
        &self,
        limit: usize,
    ) -> Result<Vec<InvestigationBundleRecord>, InvestigationStoreError> {
        match self {
            Self::Memory(store) => store.recent(limit),
            Self::LocalFiles(store) => store.recent(limit),
        }
    }

    fn health(&self) -> Result<InvestigationStoreHealth, InvestigationStoreError> {
        match self {
            Self::Memory(store) => store.health(),
            Self::LocalFiles(store) => store.health(),
        }
    }

    fn claim_execution(
        &self,
        bundle: &InvestigationBundle,
    ) -> Result<InvestigationExecutionClaim, InvestigationStoreError> {
        match self {
            Self::Memory(store) => store.claim_execution(bundle),
            Self::LocalFiles(store) => store.claim_execution(bundle),
        }
    }
}

/// In-memory investigation bundle store for tests and detect-only runs.
#[derive(Debug, Clone, Default)]
pub struct MemoryInvestigationBundleStore {
    bundles: Arc<RwLock<Vec<InvestigationBundle>>>,
    execution_claims: Arc<RwLock<BTreeMap<String, String>>>,
}

impl InvestigationBundleStore for MemoryInvestigationBundleStore {
    fn persist(
        &self,
        bundle: &InvestigationBundle,
    ) -> Result<InvestigationBundleRecord, InvestigationStoreError> {
        let mut guard = self
            .bundles
            .write()
            .map_err(|_| InvestigationStoreError::PoisonedLock)?;
        if let Some(existing) = guard
            .iter()
            .find(|existing| existing.investigation_id == bundle.investigation_id)
        {
            validate_investigation_persist_transition(existing, bundle)?;
        }
        guard.retain(|existing| existing.investigation_id != bundle.investigation_id);
        guard.push(bundle.clone());
        Ok(InvestigationBundleRecord::from_bundle(
            bundle,
            "memory".to_string(),
        ))
    }

    fn load_by_investigation_id(
        &self,
        investigation_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| InvestigationStoreError::PoisonedLock)?;
        Ok(guard
            .iter()
            .find(|bundle| bundle.investigation_id == investigation_id)
            .cloned()
            .map(|bundle| InvestigationBundleLookup {
                record: InvestigationBundleRecord::from_bundle(&bundle, "memory".to_string()),
                bundle,
            }))
    }

    fn load_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| InvestigationStoreError::PoisonedLock)?;
        Ok(sorted_recent_bundles(&guard)
            .into_iter()
            .find(|bundle| bundle.hunt_id == hunt_id)
            .map(|bundle| InvestigationBundleLookup {
                record: InvestigationBundleRecord::from_bundle(&bundle, "memory".to_string()),
                bundle,
            }))
    }

    fn load_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| InvestigationStoreError::PoisonedLock)?;
        Ok(sorted_recent_bundles(&guard)
            .into_iter()
            .find(|bundle| {
                bundle
                    .related_receipt_ids
                    .iter()
                    .any(|candidate| candidate == receipt_id)
            })
            .map(|bundle| InvestigationBundleLookup {
                record: InvestigationBundleRecord::from_bundle(&bundle, "memory".to_string()),
                bundle,
            }))
    }

    fn recent(
        &self,
        limit: usize,
    ) -> Result<Vec<InvestigationBundleRecord>, InvestigationStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| InvestigationStoreError::PoisonedLock)?;
        let mut entries = sorted_recent_bundles(&guard)
            .into_iter()
            .map(|bundle| InvestigationBundleRecord::from_bundle(&bundle, "memory".to_string()))
            .collect::<Vec<_>>();
        entries.truncate(limit);
        Ok(entries)
    }

    fn health(&self) -> Result<InvestigationStoreHealth, InvestigationStoreError> {
        let guard = self
            .bundles
            .read()
            .map_err(|_| InvestigationStoreError::PoisonedLock)?;
        Ok(InvestigationStoreHealth {
            backend: "memory".to_string(),
            durable: false,
            ready: true,
            stored_bundles: guard.len(),
            details: "ephemeral in-process investigation store".to_string(),
        })
    }

    fn claim_execution(
        &self,
        bundle: &InvestigationBundle,
    ) -> Result<InvestigationExecutionClaim, InvestigationStoreError> {
        let digest = investigation_execution_digest(bundle)?;
        let mut claims = self
            .execution_claims
            .write()
            .map_err(|_| InvestigationStoreError::PoisonedLock)?;
        match claims.get(&bundle.investigation_id) {
            Some(existing) if existing == &digest => {
                Ok(InvestigationExecutionClaim::AlreadyAcquired)
            }
            Some(_) => Err(InvestigationStoreError::ExecutionClaimConflict {
                investigation_id: bundle.investigation_id.clone(),
            }),
            None => {
                claims.insert(bundle.investigation_id.clone(), digest);
                Ok(InvestigationExecutionClaim::Acquired)
            }
        }
    }
}

/// File-backed investigation bundle store for restart-safe enrichment state.
#[derive(Debug, Clone)]
pub struct FileInvestigationBundleStore {
    root: PathBuf,
}

impl FileInvestigationBundleStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, InvestigationStoreError> {
        let root = path.as_ref().to_path_buf();
        create_investigation_directory_tree_durable(&root)?;
        create_investigation_directory_tree_durable(&root.join("bundles"))?;
        create_investigation_directory_tree_durable(&root.join("execution-claims"))?;
        Ok(Self { root })
    }

    fn bundles_dir(&self) -> PathBuf {
        self.root.join("bundles")
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn execution_claim_path(&self, investigation_id: &str) -> PathBuf {
        self.root.join("execution-claims").join(format!(
            "{}.json",
            swarm_crypto::sha256_hex(investigation_id.as_bytes())
        ))
    }

    fn read_index(&self) -> Result<InvestigationIndex, InvestigationStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(InvestigationIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| InvestigationStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| InvestigationStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &InvestigationIndex) -> Result<(), InvestigationStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            InvestigationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| InvestigationStoreError::Write { path, source })
    }

    fn bundle_path(&self, investigation_id: &str) -> PathBuf {
        self.bundles_dir()
            .join(format!("{}.json", sanitize_id(investigation_id)))
    }

    fn write_bundle(
        &self,
        bundle: &InvestigationBundle,
    ) -> Result<String, InvestigationStoreError> {
        let path = self.bundle_path(&bundle.investigation_id);
        let raw = serde_json::to_string_pretty(bundle).map_err(|source| {
            InvestigationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| InvestigationStoreError::Write {
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
        record: InvestigationBundleRecord,
    ) -> Result<InvestigationBundleLookup, InvestigationStoreError> {
        let path = self.root.join(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| InvestigationStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let bundle = serde_json::from_str(&raw)
            .map_err(|source| InvestigationStoreError::Parse { path, source })?;
        Ok(InvestigationBundleLookup { record, bundle })
    }
}

impl InvestigationBundleStore for FileInvestigationBundleStore {
    fn persist(
        &self,
        bundle: &InvestigationBundle,
    ) -> Result<InvestigationBundleRecord, InvestigationStoreError> {
        let existing_path = self.bundle_path(&bundle.investigation_id);
        if existing_path.exists() {
            let raw = fs::read_to_string(&existing_path).map_err(|source| {
                InvestigationStoreError::Read {
                    path: existing_path.clone(),
                    source,
                }
            })?;
            let existing = serde_json::from_str::<InvestigationBundle>(&raw).map_err(|source| {
                InvestigationStoreError::Parse {
                    path: existing_path,
                    source,
                }
            })?;
            validate_investigation_persist_transition(&existing, bundle)?;
        }
        let bundle_path = self.write_bundle(bundle)?;
        let mut index = self.read_index()?;
        index
            .entries
            .retain(|entry| entry.investigation_id != bundle.investigation_id);
        let record = InvestigationBundleRecord::from_bundle(bundle, bundle_path);
        index.entries.push(record.clone());
        self.write_index(&index)?;
        Ok(record)
    }

    fn load_by_investigation_id(
        &self,
        investigation_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationStoreError> {
        let index = self.read_index()?;
        if let Some(record) = index
            .entries
            .into_iter()
            .find(|entry| entry.investigation_id == investigation_id)
        {
            return self.read_bundle(record).map(Some);
        }
        Ok(None)
    }

    fn load_by_hunt_id(
        &self,
        hunt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.last_updated_ms));
        if let Some(record) = entries.into_iter().find(|entry| entry.hunt_id == hunt_id) {
            return self.read_bundle(record).map(Some);
        }
        Ok(None)
    }

    fn load_by_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<InvestigationBundleLookup>, InvestigationStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.last_updated_ms));
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

    fn recent(
        &self,
        limit: usize,
    ) -> Result<Vec<InvestigationBundleRecord>, InvestigationStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.last_updated_ms));
        entries.truncate(limit);
        Ok(entries)
    }

    fn health(&self) -> Result<InvestigationStoreHealth, InvestigationStoreError> {
        fs::create_dir_all(self.bundles_dir()).map_err(|source| {
            InvestigationStoreError::Write {
                path: self.root.clone(),
                source,
            }
        })?;
        let stored_bundles = self.read_index()?.entries.len();
        Ok(InvestigationStoreHealth {
            backend: "local_files".to_string(),
            durable: true,
            ready: true,
            stored_bundles,
            details: format!("bundle directory at {}", self.root.display()),
        })
    }

    fn claim_execution(
        &self,
        bundle: &InvestigationBundle,
    ) -> Result<InvestigationExecutionClaim, InvestigationStoreError> {
        let claim = InvestigationExecutionClaimRecord {
            investigation_id: bundle.investigation_id.clone(),
            submission_digest: investigation_execution_digest(bundle)?,
        };
        let path = self.execution_claim_path(&bundle.investigation_id);
        let raw =
            serde_json::to_vec_pretty(&claim).map_err(|source| InvestigationStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        let claims_directory = self.root.join("execution-claims");
        let mut opened_temporary = None;
        for _ in 0..INVESTIGATION_CLAIM_TEMP_ATTEMPTS {
            let restart_nonce = uuid::Uuid::new_v4().simple();
            let temporary_path = claims_directory.join(format!(
                ".claim.{}.{restart_nonce}.{}.tmp",
                std::process::id(),
                INVESTIGATION_CLAIM_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary_path)
            {
                Ok(temporary) => {
                    opened_temporary = Some((temporary_path, temporary));
                    break;
                }
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(InvestigationStoreError::Write {
                        path: temporary_path,
                        source,
                    });
                }
            }
        }
        let Some((temporary_path, mut temporary)) = opened_temporary else {
            return Err(InvestigationStoreError::Write {
                path: claims_directory,
                source: std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "exhausted unique investigation execution-claim temporary paths",
                ),
            });
        };
        if let Err(source) = temporary
            .write_all(&raw)
            .and_then(|()| temporary.sync_all())
        {
            drop(temporary);
            let _ = fs::remove_file(&temporary_path);
            return Err(InvestigationStoreError::Write {
                path: temporary_path,
                source,
            });
        }
        drop(temporary);

        match fs::hard_link(&temporary_path, &path) {
            Ok(()) => {
                finish_acquired_execution_claim(
                    &temporary_path,
                    &claims_directory,
                    |path| fs::remove_file(path),
                    sync_investigation_directory,
                )?;
                Ok(InvestigationExecutionClaim::Acquired)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&temporary_path);
                let existing_raw =
                    fs::read_to_string(&path).map_err(|source| InvestigationStoreError::Read {
                        path: path.clone(),
                        source,
                    })?;
                let existing =
                    serde_json::from_str::<InvestigationExecutionClaimRecord>(&existing_raw)
                        .map_err(|source| InvestigationStoreError::Parse {
                            path: path.clone(),
                            source,
                        })?;
                if existing == claim {
                    Ok(InvestigationExecutionClaim::AlreadyAcquired)
                } else {
                    Err(InvestigationStoreError::ExecutionClaimConflict {
                        investigation_id: bundle.investigation_id.clone(),
                    })
                }
            }
            Err(source) => {
                let _ = fs::remove_file(&temporary_path);
                Err(InvestigationStoreError::Write { path, source })
            }
        }
    }
}

fn create_investigation_directory_tree_durable(path: &Path) -> Result<(), InvestigationStoreError> {
    create_investigation_directory_tree_durable_with(path, sync_investigation_directory)
}

fn create_investigation_directory_tree_durable_with<SyncDirectory>(
    path: &Path,
    mut sync_directory: SyncDirectory,
) -> Result<(), InvestigationStoreError>
where
    SyncDirectory: FnMut(&Path) -> io::Result<()>,
{
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(InvestigationStoreError::UnsafePath {
            path: path.to_path_buf(),
        });
    }

    let mut missing = Vec::new();
    let mut cursor = Some(path);
    while let Some(candidate) = cursor {
        match fs::symlink_metadata(candidate) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(candidate.to_path_buf());
                cursor = candidate
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty());
            }
            Err(source) => {
                return Err(InvestigationStoreError::Write {
                    path: candidate.to_path_buf(),
                    source,
                });
            }
        }
    }
    fs::create_dir_all(path).map_err(|source| InvestigationStoreError::Write {
        path: path.to_path_buf(),
        source,
    })?;
    for created in missing.iter().rev() {
        sync_directory(created).map_err(|source| InvestigationStoreError::Write {
            path: created.clone(),
            source,
        })?;
        let parent = created
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        sync_directory(parent).map_err(|source| InvestigationStoreError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn sync_investigation_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn finish_acquired_execution_claim<RemoveTemporary, SyncDirectory>(
    temporary_path: &Path,
    claims_directory: &Path,
    mut remove_temporary: RemoveTemporary,
    mut sync_directory: SyncDirectory,
) -> Result<(), InvestigationStoreError>
where
    RemoveTemporary: FnMut(&Path) -> io::Result<()>,
    SyncDirectory: FnMut(&Path) -> io::Result<()>,
{
    // The hard link is the non-reclaimable fence. Once it exists, failure to
    // remove the private temporary alias must not report that acquisition
    // failed and strand every exact retry behind an already-owned claim.
    let _ = remove_temporary(temporary_path);
    sync_directory(claims_directory).map_err(|source| InvestigationStoreError::Write {
        path: claims_directory.to_path_buf(),
        source,
    })
}

fn validate_investigation_persist_transition(
    persisted: &InvestigationBundle,
    attempted: &InvestigationBundle,
) -> Result<(), InvestigationStoreError> {
    let persisted_is_terminal = matches!(
        persisted.status,
        InvestigationStatus::Completed
            | InvestigationStatus::Failed
            | InvestigationStatus::TimedOut
    );
    let regresses_running = persisted.status == InvestigationStatus::Running
        && attempted.status == InvestigationStatus::Queued;
    let publication_ack = if persisted_is_terminal
        && !persisted.graph_findings_published
        && attempted.graph_findings_published
    {
        let mut expected = persisted.clone();
        expected.graph_findings_published = true;
        &expected == attempted
    } else {
        false
    };
    if (persisted_is_terminal && persisted != attempted && !publication_ack) || regresses_running {
        return Err(InvestigationStoreError::StatusRegression {
            investigation_id: persisted.investigation_id.clone(),
            persisted: persisted.status,
            attempted: attempted.status,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct InvestigationIndex {
    entries: Vec<InvestigationBundleRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvestigationExecutionClaimRecord {
    investigation_id: String,
    submission_digest: String,
}

fn investigation_execution_digest(
    bundle: &InvestigationBundle,
) -> Result<String, InvestigationStoreError> {
    let identity = serde_json::to_vec(&(
        "swarm-investigation-execution-v1",
        &bundle.investigation_id,
        &bundle.source_bundle_id,
        &bundle.hunt_id,
        &bundle.trail_id,
        &bundle.event_id,
        &bundle.finding_id,
        &bundle.threat_class,
        bundle.severity,
        &bundle.strategy_id,
        &bundle.response_kind,
        &bundle.related_receipt_ids,
        &bundle.host_id,
        &bundle.user,
        &bundle.process_name,
        bundle.queued_at_ms,
    ))
    .map_err(|source| InvestigationStoreError::Parse {
        path: PathBuf::from("<investigation-execution-identity>"),
        source,
    })?;
    Ok(swarm_crypto::sha256_hex(&identity))
}

fn sorted_recent_bundles(bundles: &[InvestigationBundle]) -> Vec<InvestigationBundle> {
    let mut ordered = bundles.to_vec();
    ordered.sort_by_key(|bundle| std::cmp::Reverse(bundle.last_updated_ms()));
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

fn truncate(value: &str, max_len: usize) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }
    let mut truncated = value
        .chars()
        .take(max_len.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

fn extract_process_name(replay: &ReplayBundle) -> Option<String> {
    match &replay.event.payload {
        TelemetryPayload::ProcessStart(process) => Some(process.process_name.clone()),
        TelemetryPayload::ProcessMemoryAccess(access) => Some(access.source_process.clone()),
        TelemetryPayload::NetworkConnect(connect) => Some(connect.process_name.clone()),
        TelemetryPayload::DnsQuery(dns) => dns.process_name.clone(),
        TelemetryPayload::CloudTrail(event) => event.principal_name.clone().or_else(|| {
            event
                .principal_arn
                .as_ref()
                .filter(|value| !value.trim().is_empty())
                .cloned()
        }),
        TelemetryPayload::KubernetesAudit(event) => event.username.clone(),
        TelemetryPayload::RegistryAccess(registry) => Some(registry.process_name.clone()),
        TelemetryPayload::RegistryPersistence(registry) => Some(registry.process_name.clone()),
        TelemetryPayload::FilePersistence(file) => Some(file.process_name.clone()),
        TelemetryPayload::AuthenticationEvent(auth) => auth.process_name.clone(),
        TelemetryPayload::InfrastructureHealth(_) => None,
        TelemetryPayload::ThermalAnomaly(_) => None,
        TelemetryPayload::ResourceExhaustion(_) => None,
    }
}

fn extract_user(replay: &ReplayBundle) -> Option<String> {
    match &replay.event.payload {
        TelemetryPayload::ProcessStart(process) => process.user.clone(),
        TelemetryPayload::ProcessMemoryAccess(_) => replay
            .audit
            .detection
            .evidence
            .get("user")
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        TelemetryPayload::NetworkConnect(_) => replay
            .audit
            .detection
            .evidence
            .get("user")
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        TelemetryPayload::CloudTrail(event) => event
            .principal_name
            .clone()
            .or_else(|| event.principal_arn.clone()),
        TelemetryPayload::KubernetesAudit(event) => event.username.clone(),
        TelemetryPayload::DnsQuery(_) | TelemetryPayload::RegistryAccess(_) => replay
            .audit
            .detection
            .evidence
            .get("user")
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        TelemetryPayload::RegistryPersistence(_) | TelemetryPayload::FilePersistence(_) => replay
            .audit
            .detection
            .evidence
            .get("user")
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        TelemetryPayload::AuthenticationEvent(auth) => auth.user.clone(),
        TelemetryPayload::InfrastructureHealth(_)
        | TelemetryPayload::ThermalAnomaly(_)
        | TelemetryPayload::ResourceExhaustion(_) => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        ConfiguredInvestigationBundleStore, FileInvestigationBundleStore,
        INVESTIGATION_CLAIM_TEMP_COUNTER, InvestigationBundle, InvestigationBundleRecord,
        InvestigationBundleStore, InvestigationDecision, InvestigationExecutionClaim,
        InvestigationIndex, InvestigationInterpretation, InvestigationPriority,
        InvestigationPriorityClass, InvestigationStatus, InvestigationStoreError,
        InvestigationStoreHealth, InvestigationVote,
        create_investigation_directory_tree_durable_with, finish_acquired_execution_claim,
    };
    use crate::{AuditResponseRecord, AuditTrail, PolicyRecord, ReplayBundle};
    use swarm_core::config::BundleStoreConfig;
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::{AgentId, HuntId, ResponseAction, Severity};
    use swarm_policy::{ActionRequest, PolicyVerdict};
    use swarm_response::{ExecutionMode, ResponseReceipt, ResponseStatus};
    use swarm_whisker::{DetectionFinding, ProcessStartEvent, TelemetryEvent, TelemetryPayload};

    fn sample_replay_bundle() -> ReplayBundle {
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
                evidence: serde_json::json!({
                    "source": "synthetic",
                    "parent_process": "winword",
                    "process_name": "powershell",
                    "command_line": "powershell.exe -enc AAA=",
                    "user": "alice",
                    "host_id": "host-1",
                }),
                strategy_id: "suspicious_process_tree".to_string(),
            }],
            deposits: Vec::new(),
            action_request: ActionRequest {
                hunt_id: HuntId("hunt-1".to_string()),
                requested_by: AgentId("whisker-a".to_string()),
                action: ResponseAction::BlockEgress {
                    target: "203.0.113.10".to_string(),
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
                    evidence: serde_json::json!({
                        "source": "synthetic",
                        "parent_process": "winword",
                        "process_name": "powershell",
                        "command_line": "powershell.exe -enc AAA=",
                        "user": "alice",
                        "host_id": "host-1",
                    }),
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
                    action: "block_egress".to_string(),
                    mode: ExecutionMode::Enforced,
                    status: ResponseStatus::Executed,
                    summary: "egress blocked".to_string(),
                    details: serde_json::json!({"target": "203.0.113.10"}),
                    audit: Default::default(),
                }),
                created_at_ms: 1_700_000_000_123,
            },
        }
    }

    fn sample_investigation_bundle() -> InvestigationBundle {
        InvestigationBundle::queued_from_bundle(
            &sample_replay_bundle(),
            "investigation:hunt-1:1".to_string(),
            1_700_000_000_200,
            InvestigationPriority {
                class: InvestigationPriorityClass::High,
                severity_basis_points: 3_800,
                freshness_basis_points: 1_600,
                learned_value_basis_points: 1_200,
                starvation_boost_basis_points: 0,
                total_basis_points: 6_600,
            },
        )
        .with_status(InvestigationStatus::Running, Some(1_700_000_000_210), None)
        .with_summary(
            "Suspicious Office child process with encoded PowerShell".to_string(),
            vec![
                "parent_process=winword".to_string(),
                "process_name=powershell".to_string(),
            ],
            vec![
                "host:host-1".to_string(),
                "user:alice".to_string(),
                "threat:execution".to_string(),
            ],
            vec![InvestigationInterpretation {
                interpretation_id: "malicious_execution".to_string(),
                label: "Likely malicious activity".to_string(),
                rationale: "Encoded PowerShell launched from Office.".to_string(),
                supporting_evidence: vec!["parent_process=winword".to_string()],
            }],
            vec![InvestigationVote {
                voter: "threat_class".to_string(),
                interpretation_id: "malicious_execution".to_string(),
                confidence_basis_points: 6_200,
                rationale: "Execution threat class and Office lineage are both suspicious."
                    .to_string(),
            }],
            InvestigationDecision {
                selected_interpretation_id: Some("malicious_execution".to_string()),
                final_confidence_basis_points: 10_000,
                ambiguous: false,
                rationale: Some("single interpretation preserved in fixture".to_string()),
            },
            1_700_000_000_300,
        )
    }

    #[test]
    fn queued_bundle_extracts_hot_path_metadata() {
        let bundle = InvestigationBundle::queued_from_bundle(
            &sample_replay_bundle(),
            "investigation:hunt-1:queued".to_string(),
            1_700_000_000_200,
            InvestigationPriority::default(),
        );

        assert_eq!(bundle.hunt_id, "hunt-1");
        assert_eq!(bundle.host_id.as_deref(), Some("host-1"));
        assert_eq!(bundle.user.as_deref(), Some("alice"));
        assert_eq!(bundle.process_name.as_deref(), Some("powershell"));
        assert_eq!(bundle.related_receipt_ids.len(), 2);
        assert_eq!(bundle.status, InvestigationStatus::Queued);
    }

    #[test]
    fn file_store_persists_and_loads_by_hunt_and_receipt() {
        let root = std::env::temp_dir().join("swarm-spine-investigations");
        let _ = std::fs::remove_dir_all(&root);
        let store = FileInvestigationBundleStore::open(&root).unwrap();
        let bundle = sample_investigation_bundle();
        let record = store.persist(&bundle).unwrap();

        assert_eq!(record.hunt_id, "hunt-1");
        assert_eq!(record.status, InvestigationStatus::Completed);

        let by_hunt = store.load_by_hunt_id("hunt-1").unwrap().unwrap();
        assert_eq!(by_hunt.bundle.investigation_id, bundle.investigation_id);

        let by_receipt = store
            .load_by_receipt_id("receipt-response-1")
            .unwrap()
            .unwrap();
        assert_eq!(by_receipt.record.investigation_id, bundle.investigation_id);

        let health = store.health().unwrap();
        assert_eq!(
            health,
            InvestigationStoreHealth {
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
    fn legacy_investigation_index_defaults_graph_publication_state() {
        let bundle = sample_investigation_bundle();
        let record = InvestigationBundleRecord::from_bundle(
            &bundle,
            "bundles/legacy-investigation.json".to_string(),
        );
        let mut value = serde_json::json!({ "entries": [record] });
        value["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("graph_findings_published");

        let index: InvestigationIndex = serde_json::from_value(value).unwrap();
        assert!(!index.entries[0].graph_findings_published);
    }

    #[test]
    fn terminal_investigation_cannot_be_overwritten_by_a_stale_running_worker() {
        let terminal = sample_investigation_bundle();
        let stale_running = terminal.clone().with_status(
            InvestigationStatus::Running,
            terminal.started_at_ms,
            None,
        );

        let memory = super::MemoryInvestigationBundleStore::default();
        memory.persist(&terminal).unwrap();
        assert!(matches!(
            memory.persist(&stale_running),
            Err(InvestigationStoreError::StatusRegression {
                persisted: InvestigationStatus::Completed,
                attempted: InvestigationStatus::Running,
                ..
            })
        ));
        assert_eq!(
            memory
                .load_by_investigation_id(&terminal.investigation_id)
                .unwrap()
                .unwrap()
                .bundle,
            terminal
        );

        let root = std::env::temp_dir().join(format!(
            "swarm-spine-investigation-terminal-fence-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let files = FileInvestigationBundleStore::open(&root).unwrap();
        files.persist(&terminal).unwrap();
        assert!(matches!(
            files.persist(&stale_running),
            Err(InvestigationStoreError::StatusRegression {
                persisted: InvestigationStatus::Completed,
                attempted: InvestigationStatus::Running,
                ..
            })
        ));
        assert_eq!(
            files
                .load_by_investigation_id(&terminal.investigation_id)
                .unwrap()
                .unwrap()
                .bundle,
            terminal
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    fn assert_terminal_graph_publication_ack(store: &dyn super::InvestigationBundleStore) {
        let terminal = sample_investigation_bundle();
        assert!(!terminal.graph_findings_published);
        store.persist(&terminal).unwrap();

        let acknowledged = terminal.clone().with_graph_findings_published();
        let record = store.persist(&acknowledged).unwrap();
        assert!(record.graph_findings_published);
        store.persist(&acknowledged).unwrap();

        assert!(matches!(
            store.persist(&terminal),
            Err(InvestigationStoreError::StatusRegression { .. })
        ));
        let mut mutated = acknowledged.clone();
        mutated.summary = Some("terminal payload mutation".to_string());
        assert!(matches!(
            store.persist(&mutated),
            Err(InvestigationStoreError::StatusRegression { .. })
        ));
        assert_eq!(
            store
                .load_by_investigation_id(&terminal.investigation_id)
                .unwrap()
                .unwrap()
                .bundle,
            acknowledged
        );
    }

    #[test]
    fn terminal_investigation_allows_only_one_way_graph_publication_ack() {
        assert_terminal_graph_publication_ack(&super::MemoryInvestigationBundleStore::default());

        let root = std::env::temp_dir().join(format!(
            "swarm-spine-investigation-publication-ack-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let files = FileInvestigationBundleStore::open(&root).unwrap();
        assert_terminal_graph_publication_ack(&files);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn configured_store_selects_memory_and_local_backends() {
        let memory =
            ConfiguredInvestigationBundleStore::from_config(&BundleStoreConfig::Memory).unwrap();
        assert_eq!(memory.health().unwrap().backend, "memory");

        let root = std::env::temp_dir().join("swarm-spine-configured-investigations");
        let _ = std::fs::remove_dir_all(&root);
        let local =
            ConfiguredInvestigationBundleStore::from_config(&BundleStoreConfig::LocalFiles {
                directory: root.display().to_string(),
            })
            .unwrap();
        assert_eq!(local.health().unwrap().backend, "local_files");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn file_execution_claim_has_one_cross_process_winner_and_fails_closed_on_conflict() {
        let root = std::env::temp_dir().join(format!(
            "swarm-spine-investigation-claim-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store_a = FileInvestigationBundleStore::open(&root).unwrap();
        let store_b = FileInvestigationBundleStore::open(&root).unwrap();
        let bundle = sample_investigation_bundle();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let a_barrier = std::sync::Arc::clone(&barrier);
        let b_barrier = std::sync::Arc::clone(&barrier);
        let a_bundle = bundle.clone();
        let b_bundle = bundle.clone();
        let a = std::thread::spawn(move || {
            a_barrier.wait();
            store_a.claim_execution(&a_bundle).unwrap()
        });
        let b = std::thread::spawn(move || {
            b_barrier.wait();
            store_b.claim_execution(&b_bundle).unwrap()
        });
        let mut outcomes = [a.join().unwrap(), b.join().unwrap()];
        outcomes.sort_by_key(|outcome| match outcome {
            InvestigationExecutionClaim::Acquired => 0,
            InvestigationExecutionClaim::AlreadyAcquired => 1,
        });
        assert_eq!(
            outcomes,
            [
                InvestigationExecutionClaim::Acquired,
                InvestigationExecutionClaim::AlreadyAcquired
            ]
        );

        let mut conflict = bundle;
        conflict.finding_id = "different-finding".to_string();
        let reopened = FileInvestigationBundleStore::open(&root).unwrap();
        assert!(matches!(
            reopened.claim_execution(&conflict),
            Err(super::InvestigationStoreError::ExecutionClaimConflict { .. })
        ));
        assert!(
            std::fs::read_dir(root.join("execution-claims"))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn fresh_execution_claim_directory_syncs_the_root_naming_edge() {
        let root = std::env::temp_dir().join(format!(
            "swarm-spine-investigation-directory-sync-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let claims = root.join("execution-claims");
        let mut synced = Vec::new();
        create_investigation_directory_tree_durable_with(&claims, |path| {
            synced.push(path.to_path_buf());
            Ok(())
        })
        .unwrap();

        assert!(claims.is_dir());
        assert_eq!(synced.last(), Some(&root));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn acquired_execution_claim_survives_temporary_cleanup_failure() {
        let root = std::env::temp_dir().join(format!(
            "swarm-spine-investigation-claim-cleanup-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let temporary = root.join("claim.tmp");
        let claim = root.join("claim.json");
        std::fs::write(&temporary, b"claim").unwrap();
        std::fs::hard_link(&temporary, &claim).unwrap();
        let mut synced = false;

        finish_acquired_execution_claim(
            &temporary,
            &root,
            |_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "simulated cleanup refusal",
                ))
            },
            |_| {
                synced = true;
                Ok(())
            },
        )
        .unwrap();

        assert!(synced);
        assert!(claim.exists());
        assert!(temporary.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_execution_claim_ignores_stale_legacy_process_counter_temporary_files() {
        let root = std::env::temp_dir().join(format!(
            "swarm-spine-investigation-stale-claim-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = FileInvestigationBundleStore::open(&root).unwrap();
        let stale = root.join("execution-claims").join(format!(
            ".claim.{}.{}.tmp",
            std::process::id(),
            INVESTIGATION_CLAIM_TEMP_COUNTER.load(std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::write(&stale, b"stale legacy temporary claim").unwrap();

        assert_eq!(
            store
                .claim_execution(&sample_investigation_bundle())
                .unwrap(),
            InvestigationExecutionClaim::Acquired
        );
        assert!(stale.exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
