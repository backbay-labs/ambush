use crate::ReplayBundle;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use swarm_core::config::BundleStoreConfig;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;
use swarm_whisker::TelemetryPayload;

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
}

/// In-memory investigation bundle store for tests and detect-only runs.
#[derive(Debug, Clone, Default)]
pub struct MemoryInvestigationBundleStore {
    bundles: Arc<RwLock<Vec<InvestigationBundle>>>,
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
}

/// File-backed investigation bundle store for restart-safe enrichment state.
#[derive(Debug, Clone)]
pub struct FileInvestigationBundleStore {
    root: PathBuf,
}

impl FileInvestigationBundleStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, InvestigationStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("bundles")).map_err(|source| {
            InvestigationStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn bundles_dir(&self) -> PathBuf {
        self.root.join("bundles")
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
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
        entries.sort_by(|left, right| right.last_updated_ms.cmp(&left.last_updated_ms));
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
        entries.sort_by(|left, right| right.last_updated_ms.cmp(&left.last_updated_ms));
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
        entries.sort_by(|left, right| right.last_updated_ms.cmp(&left.last_updated_ms));
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct InvestigationIndex {
    entries: Vec<InvestigationBundleRecord>,
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
        ConfiguredInvestigationBundleStore, FileInvestigationBundleStore, InvestigationBundle,
        InvestigationBundleStore, InvestigationDecision, InvestigationInterpretation,
        InvestigationPriority, InvestigationPriorityClass, InvestigationStatus,
        InvestigationStoreHealth, InvestigationVote,
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
}
