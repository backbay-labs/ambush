use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use swarm_core::config::BundleStoreConfig;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::{
    ProvidenceCallbackAuditEntry, ProvidenceFeedbackAction, ProvidenceFeedbackEvidence,
    ProvidenceIncidentReconciliation, Severity,
};

/// Generic outbound-system reference linked to a correlated incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalReference {
    pub system: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Durable analyst feedback audit entry attached to an incident.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalystFeedbackAuditEntry {
    pub feedback_id: String,
    pub received_at_ms: i64,
    pub action: ProvidenceFeedbackAction,
    pub analyst_id: String,
    pub incident_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub request_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<ProvidenceFeedbackEvidence>,
    pub payload: Value,
    pub outcome: Value,
}

/// Normalized latest analyst disposition for one reviewed finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FalsePositiveMeasurement {
    pub finding_id: String,
    pub hunt_id: String,
    pub strategy_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    pub feedback_id: String,
    pub reviewed_at_ms: i64,
    pub analyst_id: String,
    pub action: ProvidenceFeedbackAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub false_positive: bool,
}

/// Aggregate detector-level false-positive rate summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FalsePositiveDetectorSummary {
    pub strategy_id: String,
    pub reviewed_findings: usize,
    pub false_positive_findings: usize,
    pub false_positive_rate: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_feedback_at_ms: Option<i64>,
}

/// Aggregate host-level false-positive rate summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FalsePositiveHostSummary {
    pub host_id: String,
    pub reviewed_findings: usize,
    pub false_positive_findings: usize,
    pub false_positive_rate: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_feedback_at_ms: Option<i64>,
}

/// Compact operator-facing summary derived from normalized analyst feedback.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FalsePositiveMeasurementReport {
    pub reviewed_findings: usize,
    pub false_positive_findings: usize,
    pub false_positive_rate: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_feedback_at_ms: Option<i64>,
    #[serde(default)]
    pub detectors: Vec<FalsePositiveDetectorSummary>,
    #[serde(default)]
    pub hosts: Vec<FalsePositiveHostSummary>,
}

/// One candidate investigation evaluated during incident assembly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentMemberDecision {
    pub investigation_id: String,
    pub hunt_id: String,
    pub finding_id: String,
    pub reason: String,
    pub shared_keys: Vec<String>,
    #[serde(default)]
    pub evidence_links: Vec<IncidentEvidenceLink>,
    #[serde(default)]
    pub confidence_score: f64,
}

/// Graph dimensions used to explain correlated incident stitching.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentGraphDimension {
    Temporal,
    Causal,
    Entity,
    Semantic,
}

/// One explainable link in the evidence chain between investigations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentEvidenceLink {
    pub dimension: IncidentGraphDimension,
    pub explanation: String,
    #[serde(default)]
    pub shared_values: Vec<String>,
    #[serde(default)]
    pub weight: usize,
}

/// Durable incident artifact assembled from persisted investigation bundles.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelatedIncident {
    pub incident_id: String,
    pub summary: String,
    pub created_at_ms: i64,
    pub window_start_ms: i64,
    pub window_end_ms: i64,
    pub correlation_keys: Vec<String>,
    pub related_receipt_ids: Vec<String>,
    pub included_members: Vec<IncidentMemberDecision>,
    pub rejected_members: Vec<IncidentMemberDecision>,
    #[serde(default)]
    pub graph_dimensions: Vec<IncidentGraphDimension>,
    #[serde(default)]
    pub confidence_score: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_finding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_strategy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_class: Option<ThreatClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub external_references: Vec<ExternalReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub providence_reconciliation: Option<ProvidenceIncidentReconciliation>,
    #[serde(default)]
    pub providence_callback_audit_entries: Vec<ProvidenceCallbackAuditEntry>,
    #[serde(default)]
    pub feedback_audit_entries: Vec<AnalystFeedbackAuditEntry>,
    #[serde(default)]
    pub false_positive_measurements: Vec<FalsePositiveMeasurement>,
}

impl CorrelatedIncident {
    pub fn included_hunt_ids(&self) -> Vec<String> {
        dedupe_strings(
            self.included_members
                .iter()
                .map(|member| member.hunt_id.clone()),
        )
    }

    pub fn included_investigation_ids(&self) -> Vec<String> {
        dedupe_strings(
            self.included_members
                .iter()
                .map(|member| member.investigation_id.clone()),
        )
    }

    pub fn upsert_false_positive_measurement(&mut self, measurement: FalsePositiveMeasurement) {
        if let Some(existing) = self
            .false_positive_measurements
            .iter_mut()
            .find(|existing| existing.finding_id == measurement.finding_id)
        {
            *existing = measurement;
        } else {
            self.false_positive_measurements.push(measurement);
        }
        self.false_positive_measurements.sort_by(|left, right| {
            right
                .reviewed_at_ms
                .cmp(&left.reviewed_at_ms)
                .then_with(|| left.finding_id.cmp(&right.finding_id))
        });
    }
}

/// Metadata surfaced for recent incidents and operator review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentRecord {
    pub incident_id: String,
    pub summary: String,
    pub created_at_ms: i64,
    pub included_hunt_ids: Vec<String>,
    pub included_investigation_ids: Vec<String>,
    pub related_receipt_ids: Vec<String>,
    pub correlation_keys: Vec<String>,
    pub bundle_path: String,
    #[serde(default)]
    pub graph_dimensions: Vec<IncidentGraphDimension>,
    #[serde(default)]
    pub confidence_score: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_finding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_strategy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_class: Option<ThreatClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub external_references: Vec<ExternalReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub providence_reconciliation: Option<ProvidenceIncidentReconciliation>,
    #[serde(default)]
    pub providence_callback_audit_entries: Vec<ProvidenceCallbackAuditEntry>,
    #[serde(default)]
    pub feedback_audit_entries: Vec<AnalystFeedbackAuditEntry>,
    #[serde(default)]
    pub false_positive_measurements: Vec<FalsePositiveMeasurement>,
}

impl IncidentRecord {
    fn from_incident(incident: &CorrelatedIncident, bundle_path: String) -> Self {
        Self {
            incident_id: incident.incident_id.clone(),
            summary: incident.summary.clone(),
            created_at_ms: incident.created_at_ms,
            included_hunt_ids: incident.included_hunt_ids(),
            included_investigation_ids: incident.included_investigation_ids(),
            related_receipt_ids: incident.related_receipt_ids.clone(),
            correlation_keys: incident.correlation_keys.clone(),
            bundle_path,
            graph_dimensions: incident.graph_dimensions.clone(),
            confidence_score: incident.confidence_score,
            trigger_event_id: incident.trigger_event_id.clone(),
            trigger_finding_id: incident.trigger_finding_id.clone(),
            trigger_strategy_id: incident.trigger_strategy_id.clone(),
            threat_class: incident.threat_class.clone(),
            severity: incident.severity,
            external_references: incident.external_references.clone(),
            providence_reconciliation: incident.providence_reconciliation.clone(),
            providence_callback_audit_entries: incident.providence_callback_audit_entries.clone(),
            feedback_audit_entries: incident.feedback_audit_entries.clone(),
            false_positive_measurements: incident.false_positive_measurements.clone(),
        }
    }
}

/// Loaded incident artifact with its persisted metadata.
#[derive(Debug, Clone)]
pub struct IncidentLookup {
    pub record: IncidentRecord,
    pub incident: CorrelatedIncident,
}

/// Health summary for an incident store backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentStoreHealth {
    pub backend: String,
    pub durable: bool,
    pub ready: bool,
    pub stored_incidents: usize,
    pub details: String,
}

/// Incident store errors.
#[derive(Debug, thiserror::Error)]
pub enum IncidentStoreError {
    #[error("incident store lock poisoned")]
    PoisonedLock,

    #[error("failed to read incident store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write incident store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse incident store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Store contract for durable incident artifacts.
pub trait IncidentStore: Send + Sync {
    fn persist(&self, incident: &CorrelatedIncident) -> Result<IncidentRecord, IncidentStoreError>;
    fn upsert_external_reference(
        &self,
        incident_id: &str,
        external_reference: ExternalReference,
    ) -> Result<Option<IncidentRecord>, IncidentStoreError>;
    fn append_feedback_audit(
        &self,
        incident_id: &str,
        entry: AnalystFeedbackAuditEntry,
    ) -> Result<Option<IncidentRecord>, IncidentStoreError>;
    fn load_by_incident_id(
        &self,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, IncidentStoreError>;
    fn load_by_hunt_id(&self, hunt_id: &str) -> Result<Option<IncidentLookup>, IncidentStoreError>;
    fn recent(&self, limit: usize) -> Result<Vec<IncidentRecord>, IncidentStoreError>;
    fn health(&self) -> Result<IncidentStoreHealth, IncidentStoreError>;
}

/// Configured incident store backend.
#[derive(Debug, Clone)]
pub enum ConfiguredIncidentStore {
    Memory(MemoryIncidentStore),
    LocalFiles(FileIncidentStore),
}

impl ConfiguredIncidentStore {
    pub fn from_config(config: &BundleStoreConfig) -> Result<Self, IncidentStoreError> {
        match config {
            BundleStoreConfig::Memory => Ok(Self::Memory(MemoryIncidentStore::default())),
            BundleStoreConfig::LocalFiles { directory } => {
                Ok(Self::LocalFiles(FileIncidentStore::open(directory)?))
            }
        }
    }
}

impl IncidentStore for ConfiguredIncidentStore {
    fn persist(&self, incident: &CorrelatedIncident) -> Result<IncidentRecord, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.persist(incident),
            Self::LocalFiles(store) => store.persist(incident),
        }
    }

    fn upsert_external_reference(
        &self,
        incident_id: &str,
        external_reference: ExternalReference,
    ) -> Result<Option<IncidentRecord>, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.upsert_external_reference(incident_id, external_reference),
            Self::LocalFiles(store) => {
                store.upsert_external_reference(incident_id, external_reference)
            }
        }
    }

    fn append_feedback_audit(
        &self,
        incident_id: &str,
        entry: AnalystFeedbackAuditEntry,
    ) -> Result<Option<IncidentRecord>, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.append_feedback_audit(incident_id, entry),
            Self::LocalFiles(store) => store.append_feedback_audit(incident_id, entry),
        }
    }

    fn load_by_incident_id(
        &self,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.load_by_incident_id(incident_id),
            Self::LocalFiles(store) => store.load_by_incident_id(incident_id),
        }
    }

    fn load_by_hunt_id(&self, hunt_id: &str) -> Result<Option<IncidentLookup>, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.load_by_hunt_id(hunt_id),
            Self::LocalFiles(store) => store.load_by_hunt_id(hunt_id),
        }
    }

    fn recent(&self, limit: usize) -> Result<Vec<IncidentRecord>, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.recent(limit),
            Self::LocalFiles(store) => store.recent(limit),
        }
    }

    fn health(&self) -> Result<IncidentStoreHealth, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.health(),
            Self::LocalFiles(store) => store.health(),
        }
    }
}

/// In-memory incident store for tests and operator snapshots.
#[derive(Debug, Clone, Default)]
pub struct MemoryIncidentStore {
    incidents: Arc<RwLock<Vec<CorrelatedIncident>>>,
}

impl IncidentStore for MemoryIncidentStore {
    fn persist(&self, incident: &CorrelatedIncident) -> Result<IncidentRecord, IncidentStoreError> {
        let mut guard = self
            .incidents
            .write()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        guard.retain(|existing| existing.incident_id != incident.incident_id);
        guard.push(incident.clone());
        Ok(IncidentRecord::from_incident(
            incident,
            "memory".to_string(),
        ))
    }

    fn upsert_external_reference(
        &self,
        incident_id: &str,
        external_reference: ExternalReference,
    ) -> Result<Option<IncidentRecord>, IncidentStoreError> {
        let mut guard = self
            .incidents
            .write()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        let Some(incident) = guard
            .iter_mut()
            .find(|incident| incident.incident_id == incident_id)
        else {
            return Ok(None);
        };
        upsert_external_reference_list(&mut incident.external_references, external_reference);
        Ok(Some(IncidentRecord::from_incident(
            incident,
            "memory".to_string(),
        )))
    }

    fn append_feedback_audit(
        &self,
        incident_id: &str,
        entry: AnalystFeedbackAuditEntry,
    ) -> Result<Option<IncidentRecord>, IncidentStoreError> {
        let mut guard = self
            .incidents
            .write()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        let Some(incident) = guard
            .iter_mut()
            .find(|incident| incident.incident_id == incident_id)
        else {
            return Ok(None);
        };
        incident.feedback_audit_entries.push(entry);
        Ok(Some(IncidentRecord::from_incident(
            incident,
            "memory".to_string(),
        )))
    }

    fn load_by_incident_id(
        &self,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, IncidentStoreError> {
        let guard = self
            .incidents
            .read()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        Ok(guard
            .iter()
            .find(|incident| incident.incident_id == incident_id)
            .cloned()
            .map(|incident| IncidentLookup {
                record: IncidentRecord::from_incident(&incident, "memory".to_string()),
                incident,
            }))
    }

    fn load_by_hunt_id(&self, hunt_id: &str) -> Result<Option<IncidentLookup>, IncidentStoreError> {
        let guard = self
            .incidents
            .read()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        Ok(sorted_recent_incidents(&guard)
            .into_iter()
            .find(|incident| {
                incident
                    .included_hunt_ids()
                    .iter()
                    .any(|candidate| candidate == hunt_id)
            })
            .map(|incident| IncidentLookup {
                record: IncidentRecord::from_incident(&incident, "memory".to_string()),
                incident,
            }))
    }

    fn recent(&self, limit: usize) -> Result<Vec<IncidentRecord>, IncidentStoreError> {
        let guard = self
            .incidents
            .read()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        let mut entries = sorted_recent_incidents(&guard)
            .into_iter()
            .map(|incident| IncidentRecord::from_incident(&incident, "memory".to_string()))
            .collect::<Vec<_>>();
        entries.truncate(limit);
        Ok(entries)
    }

    fn health(&self) -> Result<IncidentStoreHealth, IncidentStoreError> {
        let guard = self
            .incidents
            .read()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        Ok(IncidentStoreHealth {
            backend: "memory".to_string(),
            durable: false,
            ready: true,
            stored_incidents: guard.len(),
            details: "ephemeral in-process incident store".to_string(),
        })
    }
}

/// File-backed incident store for restart-safe review artifacts.
#[derive(Debug, Clone)]
pub struct FileIncidentStore {
    root: PathBuf,
}

impl FileIncidentStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IncidentStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("incidents")).map_err(|source| IncidentStoreError::Write {
            path: root.clone(),
            source,
        })?;
        Ok(Self { root })
    }

    fn incidents_dir(&self) -> PathBuf {
        self.root.join("incidents")
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<IncidentIndex, IncidentStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(IncidentIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| IncidentStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| IncidentStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &IncidentIndex) -> Result<(), IncidentStoreError> {
        let path = self.index_path();
        let raw =
            serde_json::to_string_pretty(index).map_err(|source| IncidentStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| IncidentStoreError::Write { path, source })
    }

    fn incident_path(&self, incident_id: &str) -> PathBuf {
        self.incidents_dir()
            .join(format!("{}.json", sanitize_id(incident_id)))
    }

    fn write_incident(&self, incident: &CorrelatedIncident) -> Result<String, IncidentStoreError> {
        let path = self.incident_path(&incident.incident_id);
        let raw =
            serde_json::to_string_pretty(incident).map_err(|source| IncidentStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| IncidentStoreError::Write {
            path: path.clone(),
            source,
        })?;
        Ok(path
            .strip_prefix(&self.root)
            .unwrap_or(&path)
            .display()
            .to_string())
    }

    fn read_incident(&self, record: IncidentRecord) -> Result<IncidentLookup, IncidentStoreError> {
        let path = self.root.join(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| IncidentStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let incident = serde_json::from_str(&raw)
            .map_err(|source| IncidentStoreError::Parse { path, source })?;
        Ok(IncidentLookup { record, incident })
    }
}

impl IncidentStore for FileIncidentStore {
    fn persist(&self, incident: &CorrelatedIncident) -> Result<IncidentRecord, IncidentStoreError> {
        let bundle_path = self.write_incident(incident)?;
        let mut index = self.read_index()?;
        index
            .entries
            .retain(|entry| entry.incident_id != incident.incident_id);
        let record = IncidentRecord::from_incident(incident, bundle_path);
        index.entries.push(record.clone());
        self.write_index(&index)?;
        Ok(record)
    }

    fn upsert_external_reference(
        &self,
        incident_id: &str,
        external_reference: ExternalReference,
    ) -> Result<Option<IncidentRecord>, IncidentStoreError> {
        let mut index = self.read_index()?;
        let Some(entry_index) = index
            .entries
            .iter()
            .position(|entry| entry.incident_id == incident_id)
        else {
            return Ok(None);
        };
        let record = index.entries[entry_index].clone();
        let mut lookup = self.read_incident(record)?;
        upsert_external_reference_list(
            &mut lookup.incident.external_references,
            external_reference,
        );
        let bundle_path = self.write_incident(&lookup.incident)?;
        let updated = IncidentRecord::from_incident(&lookup.incident, bundle_path);
        index.entries[entry_index] = updated.clone();
        self.write_index(&index)?;
        Ok(Some(updated))
    }

    fn append_feedback_audit(
        &self,
        incident_id: &str,
        entry: AnalystFeedbackAuditEntry,
    ) -> Result<Option<IncidentRecord>, IncidentStoreError> {
        let mut index = self.read_index()?;
        let Some(entry_index) = index
            .entries
            .iter()
            .position(|candidate| candidate.incident_id == incident_id)
        else {
            return Ok(None);
        };
        let record = index.entries[entry_index].clone();
        let mut lookup = self.read_incident(record)?;
        lookup.incident.feedback_audit_entries.push(entry);
        let bundle_path = self.write_incident(&lookup.incident)?;
        let updated = IncidentRecord::from_incident(&lookup.incident, bundle_path);
        index.entries[entry_index] = updated.clone();
        self.write_index(&index)?;
        Ok(Some(updated))
    }

    fn load_by_incident_id(
        &self,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, IncidentStoreError> {
        let index = self.read_index()?;
        if let Some(record) = index
            .entries
            .into_iter()
            .find(|entry| entry.incident_id == incident_id)
        {
            return self.read_incident(record).map(Some);
        }
        Ok(None)
    }

    fn load_by_hunt_id(&self, hunt_id: &str) -> Result<Option<IncidentLookup>, IncidentStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
        if let Some(record) = entries.into_iter().find(|entry| {
            entry
                .included_hunt_ids
                .iter()
                .any(|candidate| candidate == hunt_id)
        }) {
            return self.read_incident(record).map(Some);
        }
        Ok(None)
    }

    fn recent(&self, limit: usize) -> Result<Vec<IncidentRecord>, IncidentStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
        entries.truncate(limit);
        Ok(entries)
    }

    fn health(&self) -> Result<IncidentStoreHealth, IncidentStoreError> {
        fs::create_dir_all(self.incidents_dir()).map_err(|source| IncidentStoreError::Write {
            path: self.root.clone(),
            source,
        })?;
        let stored_incidents = self.read_index()?.entries.len();
        Ok(IncidentStoreHealth {
            backend: "local_files".to_string(),
            durable: true,
            ready: true,
            stored_incidents,
            details: format!("incident directory at {}", self.root.display()),
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct IncidentIndex {
    entries: Vec<IncidentRecord>,
}

fn sorted_recent_incidents(incidents: &[CorrelatedIncident]) -> Vec<CorrelatedIncident> {
    let mut ordered = incidents.to_vec();
    ordered.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
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

fn dedupe_strings<I>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut output = Vec::new();
    for value in values {
        if !output.iter().any(|existing| existing == &value) {
            output.push(value);
        }
    }
    output
}

pub fn summarize_false_positive_measurements(
    records: &[IncidentRecord],
) -> FalsePositiveMeasurementReport {
    let mut report = FalsePositiveMeasurementReport::default();
    let mut detector_counts: BTreeMap<String, (usize, usize, Option<i64>)> = BTreeMap::new();
    let mut host_counts: BTreeMap<String, (usize, usize, Option<i64>)> = BTreeMap::new();

    for record in records {
        for measurement in &record.false_positive_measurements {
            report.reviewed_findings += 1;
            if measurement.false_positive {
                report.false_positive_findings += 1;
            }
            report.latest_feedback_at_ms = max_optional_timestamp(
                report.latest_feedback_at_ms,
                Some(measurement.reviewed_at_ms),
            );

            let detector = detector_counts
                .entry(measurement.strategy_id.clone())
                .or_insert((0, 0, None));
            detector.0 += 1;
            if measurement.false_positive {
                detector.1 += 1;
            }
            detector.2 = max_optional_timestamp(detector.2, Some(measurement.reviewed_at_ms));

            if let Some(host_id) = &measurement.host_id {
                let host = host_counts.entry(host_id.clone()).or_insert((0, 0, None));
                host.0 += 1;
                if measurement.false_positive {
                    host.1 += 1;
                }
                host.2 = max_optional_timestamp(host.2, Some(measurement.reviewed_at_ms));
            }
        }
    }

    report.false_positive_rate =
        false_positive_rate(report.false_positive_findings, report.reviewed_findings);
    report.detectors = detector_counts
        .into_iter()
        .map(
            |(strategy_id, (reviewed_findings, false_positive_findings, latest_feedback_at_ms))| {
                FalsePositiveDetectorSummary {
                    strategy_id,
                    reviewed_findings,
                    false_positive_findings,
                    false_positive_rate: false_positive_rate(
                        false_positive_findings,
                        reviewed_findings,
                    ),
                    latest_feedback_at_ms,
                }
            },
        )
        .collect();
    report.hosts = host_counts
        .into_iter()
        .map(
            |(host_id, (reviewed_findings, false_positive_findings, latest_feedback_at_ms))| {
                FalsePositiveHostSummary {
                    host_id,
                    reviewed_findings,
                    false_positive_findings,
                    false_positive_rate: false_positive_rate(
                        false_positive_findings,
                        reviewed_findings,
                    ),
                    latest_feedback_at_ms,
                }
            },
        )
        .collect();
    report.detectors.sort_by(|left, right| {
        right
            .reviewed_findings
            .cmp(&left.reviewed_findings)
            .then_with(|| {
                right
                    .false_positive_rate
                    .partial_cmp(&left.false_positive_rate)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| left.strategy_id.cmp(&right.strategy_id))
    });
    report.hosts.sort_by(|left, right| {
        right
            .reviewed_findings
            .cmp(&left.reviewed_findings)
            .then_with(|| {
                right
                    .false_positive_rate
                    .partial_cmp(&left.false_positive_rate)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| left.host_id.cmp(&right.host_id))
    });

    report
}

fn false_positive_rate(false_positive_findings: usize, reviewed_findings: usize) -> f64 {
    if reviewed_findings == 0 {
        0.0
    } else {
        false_positive_findings as f64 / reviewed_findings as f64
    }
}

fn max_optional_timestamp(current: Option<i64>, candidate: Option<i64>) -> Option<i64> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.max(candidate)),
        (Some(current), None) => Some(current),
        (None, Some(candidate)) => Some(candidate),
        (None, None) => None,
    }
}

fn upsert_external_reference_list(
    references: &mut Vec<ExternalReference>,
    external_reference: ExternalReference,
) {
    if let Some(existing) = references
        .iter_mut()
        .find(|existing| existing.system == external_reference.system)
    {
        *existing = external_reference;
    } else {
        references.push(external_reference);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        AnalystFeedbackAuditEntry, ConfiguredIncidentStore, CorrelatedIncident, ExternalReference,
        FileIncidentStore, IncidentEvidenceLink, IncidentGraphDimension, IncidentMemberDecision,
        IncidentStore, IncidentStoreHealth,
    };
    use swarm_core::config::BundleStoreConfig;
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::{ProvidenceFeedbackAction, Severity};

    fn sample_incident() -> CorrelatedIncident {
        CorrelatedIncident {
            incident_id: "incident:hunt-1:1".to_string(),
            summary: "Two related investigations share host and user".to_string(),
            created_at_ms: 1_700_000_000_500,
            window_start_ms: 1_700_000_000_100,
            window_end_ms: 1_700_000_000_450,
            correlation_keys: vec!["host:host-1".to_string(), "user:alice".to_string()],
            related_receipt_ids: vec![
                "receipt-upstream-1".to_string(),
                "receipt-response-1".to_string(),
            ],
            included_members: vec![
                IncidentMemberDecision {
                    investigation_id: "investigation:hunt-1:1".to_string(),
                    hunt_id: "hunt-1".to_string(),
                    finding_id: "finding-1".to_string(),
                    reason: "seed investigation".to_string(),
                    shared_keys: vec!["host:host-1".to_string(), "user:alice".to_string()],
                    evidence_links: Vec::new(),
                    confidence_score: 1.0,
                },
                IncidentMemberDecision {
                    investigation_id: "investigation:hunt-2:1".to_string(),
                    hunt_id: "hunt-2".to_string(),
                    finding_id: "finding-2".to_string(),
                    reason: "shared host and user within correlation window".to_string(),
                    shared_keys: vec!["host:host-1".to_string(), "user:alice".to_string()],
                    evidence_links: vec![IncidentEvidenceLink {
                        dimension: IncidentGraphDimension::Entity,
                        explanation: "shared host and user context".to_string(),
                        shared_values: vec!["host:host-1".to_string(), "user:alice".to_string()],
                        weight: 2,
                    }],
                    confidence_score: 0.9,
                },
            ],
            rejected_members: vec![IncidentMemberDecision {
                investigation_id: "investigation:hunt-3:1".to_string(),
                hunt_id: "hunt-3".to_string(),
                finding_id: "finding-3".to_string(),
                reason: "outside correlation time window".to_string(),
                shared_keys: vec!["host:host-1".to_string()],
                evidence_links: vec![IncidentEvidenceLink {
                    dimension: IncidentGraphDimension::Temporal,
                    explanation: "time delta exceeded the configured correlation window"
                        .to_string(),
                    shared_values: vec!["host:host-1".to_string()],
                    weight: 1,
                }],
                confidence_score: 0.1,
            }],
            graph_dimensions: vec![
                IncidentGraphDimension::Entity,
                IncidentGraphDimension::Temporal,
            ],
            confidence_score: 0.9,
            trigger_event_id: Some("evt:hunt-1".to_string()),
            trigger_finding_id: Some("finding-1".to_string()),
            trigger_strategy_id: Some("summary_investigator".to_string()),
            threat_class: Some(ThreatClass::Execution),
            severity: Some(Severity::Critical),
            external_references: Vec::new(),
            providence_reconciliation: None,
            providence_callback_audit_entries: Vec::new(),
            feedback_audit_entries: Vec::new(),
            false_positive_measurements: Vec::new(),
        }
    }

    #[test]
    fn file_store_persists_and_loads_by_hunt_id() {
        let root = std::env::temp_dir().join("swarm-spine-incidents");
        let _ = std::fs::remove_dir_all(&root);
        let store = FileIncidentStore::open(&root).unwrap();
        let incident = sample_incident();
        let record = store.persist(&incident).unwrap();

        assert_eq!(record.included_hunt_ids.len(), 2);
        let loaded = store.load_by_hunt_id("hunt-2").unwrap().unwrap();
        assert_eq!(loaded.incident.incident_id, incident.incident_id);

        let health = store.health().unwrap();
        assert_eq!(
            health,
            IncidentStoreHealth {
                backend: "local_files".to_string(),
                durable: true,
                ready: true,
                stored_incidents: 1,
                details: format!("incident directory at {}", root.display()),
            }
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn configured_store_selects_memory_and_local_backends() {
        let memory = ConfiguredIncidentStore::from_config(&BundleStoreConfig::Memory).unwrap();
        assert_eq!(memory.health().unwrap().backend, "memory");

        let root = std::env::temp_dir().join("swarm-spine-configured-incidents");
        let _ = std::fs::remove_dir_all(&root);
        let local = ConfiguredIncidentStore::from_config(&BundleStoreConfig::LocalFiles {
            directory: root.display().to_string(),
        })
        .unwrap();
        assert_eq!(local.health().unwrap().backend, "local_files");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn file_store_upserts_external_reference_and_persists_it() {
        let root = std::env::temp_dir().join("swarm-spine-incidents-refs");
        let _ = std::fs::remove_dir_all(&root);
        let store = FileIncidentStore::open(&root).unwrap();
        let incident = sample_incident();
        let record = store.persist(&incident).unwrap();

        let updated = store
            .upsert_external_reference(
                &record.incident_id,
                ExternalReference {
                    system: "providence".to_string(),
                    id: "prov-incident-1".to_string(),
                    url: Some("https://providence.example/incidents/prov-incident-1".to_string()),
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(updated.external_references.len(), 1);
        assert_eq!(updated.trigger_finding_id.as_deref(), Some("finding-1"));

        let reloaded = FileIncidentStore::open(&root)
            .unwrap()
            .load_by_incident_id(&record.incident_id)
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.record.external_references.len(), 1);
        assert_eq!(reloaded.incident.external_references.len(), 1);
        assert_eq!(reloaded.record.external_references[0].system, "providence");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn file_store_appends_feedback_audit_and_persists_it() {
        let root = std::env::temp_dir().join("swarm-spine-incidents-feedback");
        let _ = std::fs::remove_dir_all(&root);
        let store = FileIncidentStore::open(&root).unwrap();
        let incident = sample_incident();
        let record = store.persist(&incident).unwrap();

        let updated = store
            .append_feedback_audit(
                &record.incident_id,
                AnalystFeedbackAuditEntry {
                    feedback_id: "feedback-1".to_string(),
                    received_at_ms: 1_700_000_000_600,
                    action: ProvidenceFeedbackAction::Dismiss,
                    analyst_id: "analyst-7".to_string(),
                    incident_id: record.incident_id.clone(),
                    finding_id: Some("finding-1".to_string()),
                    reason: Some("false positive".to_string()),
                    request_signature: "sha256=test".to_string(),
                    evidence: None,
                    payload: serde_json::json!({
                        "action": "dismiss",
                        "incident_id": record.incident_id,
                        "finding_id": "finding-1"
                    }),
                    outcome: serde_json::json!({
                        "status": "pending_feedback"
                    }),
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(updated.feedback_audit_entries.len(), 1);
        assert_eq!(updated.feedback_audit_entries[0].analyst_id, "analyst-7");

        let reloaded = FileIncidentStore::open(&root)
            .unwrap()
            .load_by_incident_id(&record.incident_id)
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.record.feedback_audit_entries.len(), 1);
        assert_eq!(reloaded.incident.feedback_audit_entries.len(), 1);
        assert_eq!(
            reloaded.incident.feedback_audit_entries[0].action,
            ProvidenceFeedbackAction::Dismiss
        );

        let _ = std::fs::remove_dir_all(root);
    }
}
