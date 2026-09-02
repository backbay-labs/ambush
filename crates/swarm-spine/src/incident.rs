use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use swarm_core::config::BundleStoreConfig;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::{
    ProvidenceCallbackAuditEntry, ProvidenceFeedbackAction, ProvidenceFeedbackEvidence,
    ProvidenceIncidentReconciliation, Severity, SoarSourceSystem, SoarVerdictLineage,
};
use swarm_crypto::sha256_hex;

static INCIDENT_TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(1);

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soar_lineage: Option<SoarVerdictLineage>,
    pub payload: Value,
    pub outcome: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soar_claim_lease: Option<SoarVerdictClaimLease>,
}

/// Fencing lease for one recoverable SOAR side-effect attempt. Exact retries
/// may replace an expired lease; an older worker cannot commit through the
/// replacement token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoarVerdictClaimLease {
    pub token: String,
    /// Wall-clock observation that established this deadline. Persisting the
    /// interval lets a retry detect a clock rollback instead of treating a
    /// pre-rollback deadline as active indefinitely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at_ms: Option<i64>,
    pub expires_at_ms: i64,
}

/// Result of atomically claiming one externally identified SOAR verdict.
/// Exact retries observe the winner's durable entry and never repeat effects;
/// a different request reusing the source identity is a conflict.
#[derive(Debug, Clone, PartialEq)]
pub enum SoarVerdictClaimResult {
    Claimed(AnalystFeedbackAuditEntry),
    PendingExact(AnalystFeedbackAuditEntry),
    CompletedExact(AnalystFeedbackAuditEntry),
    Conflict,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soar_lineage: Option<SoarVerdictLineage>,
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
            if (measurement.reviewed_at_ms, measurement.feedback_id.as_str())
                > (existing.reviewed_at_ms, existing.feedback_id.as_str())
            {
                *existing = measurement;
            }
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

    #[error("Providence feedback timestamp high-water is exhausted")]
    FeedbackTimestampExhausted,

    #[error("feedback outcome conflicts with its durable claim: {reason}")]
    FeedbackOutcomeConflict { reason: String },

    #[error("SOAR lineage index is inconsistent: {reason}")]
    SoarLineageIndexConflict { reason: String },
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
    fn claim_soar_verdict(
        &self,
        incident_id: &str,
        entry: AnalystFeedbackAuditEntry,
    ) -> Result<Option<SoarVerdictClaimResult>, IncidentStoreError>;
    fn load_soar_verdict_claim(
        &self,
        source_system: SoarSourceSystem,
        source_verdict_id: &str,
    ) -> Result<Option<AnalystFeedbackAuditEntry>, IncidentStoreError>;
    fn record_feedback_outcome(
        &self,
        incident_id: &str,
        entry: AnalystFeedbackAuditEntry,
        measurement: FalsePositiveMeasurement,
    ) -> Result<Option<IncidentRecord>, IncidentStoreError>;
    fn load_by_incident_id(
        &self,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, IncidentStoreError>;
    fn load_by_hunt_id(&self, hunt_id: &str) -> Result<Option<IncidentLookup>, IncidentStoreError>;
    fn recent(&self, limit: usize) -> Result<Vec<IncidentRecord>, IncidentStoreError>;
    fn health(&self) -> Result<IncidentStoreHealth, IncidentStoreError>;
    fn reserve_feedback_timestamp_ms(&self, observed_at_ms: i64)
    -> Result<i64, IncidentStoreError>;
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

    fn claim_soar_verdict(
        &self,
        incident_id: &str,
        entry: AnalystFeedbackAuditEntry,
    ) -> Result<Option<SoarVerdictClaimResult>, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.claim_soar_verdict(incident_id, entry),
            Self::LocalFiles(store) => store.claim_soar_verdict(incident_id, entry),
        }
    }

    fn load_soar_verdict_claim(
        &self,
        source_system: SoarSourceSystem,
        source_verdict_id: &str,
    ) -> Result<Option<AnalystFeedbackAuditEntry>, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.load_soar_verdict_claim(source_system, source_verdict_id),
            Self::LocalFiles(store) => {
                store.load_soar_verdict_claim(source_system, source_verdict_id)
            }
        }
    }

    fn record_feedback_outcome(
        &self,
        incident_id: &str,
        entry: AnalystFeedbackAuditEntry,
        measurement: FalsePositiveMeasurement,
    ) -> Result<Option<IncidentRecord>, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.record_feedback_outcome(incident_id, entry, measurement),
            Self::LocalFiles(store) => {
                store.record_feedback_outcome(incident_id, entry, measurement)
            }
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

    fn reserve_feedback_timestamp_ms(
        &self,
        observed_at_ms: i64,
    ) -> Result<i64, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.reserve_feedback_timestamp_ms(observed_at_ms),
            Self::LocalFiles(store) => store.reserve_feedback_timestamp_ms(observed_at_ms),
        }
    }
}

/// In-memory incident store for tests and operator snapshots.
#[derive(Debug, Clone, Default)]
pub struct MemoryIncidentStore {
    incidents: Arc<RwLock<Vec<CorrelatedIncident>>>,
    feedback_timestamp_high_water_ms: Arc<AtomicI64>,
}

impl IncidentStore for MemoryIncidentStore {
    fn persist(&self, incident: &CorrelatedIncident) -> Result<IncidentRecord, IncidentStoreError> {
        let mut guard = self
            .incidents
            .write()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        let mut incident = incident.clone();
        if let Some(existing) = guard
            .iter()
            .find(|existing| existing.incident_id == incident.incident_id)
        {
            merge_incident_operational_state(&mut incident, existing);
        }
        guard.retain(|existing| existing.incident_id != incident.incident_id);
        guard.push(incident.clone());
        advance_feedback_timestamp_high_water(
            &self.feedback_timestamp_high_water_ms,
            incident_feedback_timestamp_high_water(&incident),
        );
        Ok(IncidentRecord::from_incident(
            &incident,
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
        if entry.soar_lineage.is_some() && !is_rejected_soar_audit(&entry) {
            return Err(IncidentStoreError::FeedbackOutcomeConflict {
                reason: "non-rejected SOAR audit entries must use the atomic claim path"
                    .to_string(),
            });
        }
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
        advance_feedback_timestamp_high_water(
            &self.feedback_timestamp_high_water_ms,
            entry.received_at_ms,
        );
        incident.feedback_audit_entries.push(entry);
        Ok(Some(IncidentRecord::from_incident(
            incident,
            "memory".to_string(),
        )))
    }

    fn claim_soar_verdict(
        &self,
        incident_id: &str,
        mut entry: AnalystFeedbackAuditEntry,
    ) -> Result<Option<SoarVerdictClaimResult>, IncidentStoreError> {
        if entry.soar_lineage.is_none() {
            return Ok(Some(SoarVerdictClaimResult::Conflict));
        }
        validate_proposed_soar_claim(&entry)?;
        let mut guard = self
            .incidents
            .write()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        for incident in guard.iter_mut() {
            if find_soar_verdict_entry(incident, &entry).is_none() {
                continue;
            }
            if incident.incident_id != incident_id {
                return Ok(Some(SoarVerdictClaimResult::Conflict));
            }
            let Some(existing) = find_soar_verdict_entry_mut(incident, &entry) else {
                return Err(IncidentStoreError::SoarLineageIndexConflict {
                    reason: "in-memory SOAR lineage disappeared under the incident write lock"
                        .to_string(),
                });
            };
            return Ok(Some(claim_or_classify_soar_verdict(existing, &entry)));
        }
        let Some(incident) = guard
            .iter_mut()
            .find(|incident| incident.incident_id == incident_id)
        else {
            return Ok(None);
        };
        entry.received_at_ms = reserve_atomic_feedback_timestamp(
            &self.feedback_timestamp_high_water_ms,
            entry.received_at_ms,
        )?;
        incident.feedback_audit_entries.push(entry.clone());
        Ok(Some(SoarVerdictClaimResult::Claimed(entry)))
    }

    fn load_soar_verdict_claim(
        &self,
        source_system: SoarSourceSystem,
        source_verdict_id: &str,
    ) -> Result<Option<AnalystFeedbackAuditEntry>, IncidentStoreError> {
        let guard = self
            .incidents
            .read()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        let mut found = None;
        for entry in guard
            .iter()
            .flat_map(|incident| &incident.feedback_audit_entries)
            .filter(|entry| !is_rejected_soar_audit(entry))
            .filter(|entry| {
                entry.soar_lineage.as_ref().is_some_and(|lineage| {
                    lineage.source_system == source_system
                        && lineage.source_verdict_id == source_verdict_id
                })
            })
        {
            if found.as_ref().is_some_and(|existing| existing != entry) {
                return Err(IncidentStoreError::SoarLineageIndexConflict {
                    reason: "in-memory SOAR lineage maps to conflicting retained claims"
                        .to_string(),
                });
            }
            found = Some(entry.clone());
        }
        Ok(found)
    }

    fn record_feedback_outcome(
        &self,
        incident_id: &str,
        entry: AnalystFeedbackAuditEntry,
        measurement: FalsePositiveMeasurement,
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
        advance_feedback_timestamp_high_water(
            &self.feedback_timestamp_high_water_ms,
            entry.received_at_ms,
        );
        commit_feedback_outcome(incident, entry, measurement)?;
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

    fn reserve_feedback_timestamp_ms(
        &self,
        observed_at_ms: i64,
    ) -> Result<i64, IncidentStoreError> {
        reserve_atomic_feedback_timestamp(&self.feedback_timestamp_high_water_ms, observed_at_ms)
    }
}

/// File-backed incident store for restart-safe review artifacts.
#[derive(Debug, Clone)]
pub struct FileIncidentStore {
    root: PathBuf,
    mutation_lock: Arc<Mutex<()>>,
}

struct IncidentMutationGuard<'a> {
    _process_guard: MutexGuard<'a, ()>,
    _file_guard: File,
}

impl FileIncidentStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IncidentStoreError> {
        let root = path.as_ref().to_path_buf();
        create_dir_all_durably(&root)?;
        create_dir_all_durably(&root.join("incidents"))?;
        create_dir_all_durably(&root.join("soar-lineage"))?;
        let store = Self {
            root,
            mutation_lock: Arc::new(Mutex::new(())),
        };
        {
            let _guard = store.lock_mutation()?;
            let mut index = store.read_index()?;
            if store.ensure_soar_lineage_index_initialized(&mut index)? {
                store.write_index(&index)?;
            }
        }
        Ok(store)
    }

    fn incidents_dir(&self) -> PathBuf {
        self.root.join("incidents")
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn soar_lineage_root(&self) -> PathBuf {
        self.root.join("soar-lineage")
    }

    fn soar_lineage_path(&self, lineage_key: &str) -> Result<PathBuf, IncidentStoreError> {
        if lineage_key.len() != 64 || !lineage_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(IncidentStoreError::SoarLineageIndexConflict {
                reason: "SOAR lineage key is not a SHA-256 digest".to_string(),
            });
        }
        Ok(self
            .soar_lineage_root()
            .join(&lineage_key[..2])
            .join(format!("{lineage_key}.json")))
    }

    fn mutation_lock_path(&self) -> PathBuf {
        self.root.join(".incident-store.lock")
    }

    fn lock_mutation(&self) -> Result<IncidentMutationGuard<'_>, IncidentStoreError> {
        let process_guard = self
            .mutation_lock
            .lock()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        let path = self.mutation_lock_path();
        let file_guard = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| IncidentStoreError::Write {
                path: path.clone(),
                source,
            })?;
        file_guard
            .lock()
            .map_err(|source| IncidentStoreError::Write { path, source })?;
        Ok(IncidentMutationGuard {
            _process_guard: process_guard,
            _file_guard: file_guard,
        })
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
        // Full audit payloads live in the per-incident document and lineage
        // shards. Keeping another copy in index.json made every SOAR verdict
        // an O(lifetime traffic) read/serialize/replace operation.
        let mut compact = index.clone();
        for record in &mut compact.entries {
            record.feedback_audit_entries.clear();
        }
        compact.legacy_soar_lineage_claims.clear();
        let raw =
            serde_json::to_string_pretty(&compact).map_err(|source| IncidentStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        write_file_atomically(&path, raw.as_bytes())
    }

    fn read_soar_lineage_claim(
        &self,
        lineage_key: &str,
    ) -> Result<Option<SoarLineageIndexEntry>, IncidentStoreError> {
        let path = self.soar_lineage_path(lineage_key)?;
        let raw = match fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(IncidentStoreError::Read { path, source }),
        };
        let claim: SoarLineageIndexEntry = serde_json::from_str(&raw)
            .map_err(|source| IncidentStoreError::Parse { path, source })?;
        if soar_lineage_index_key(&claim.entry).as_deref() != Some(lineage_key)
            || !claim.matches_entry(&claim.entry)
        {
            return Err(IncidentStoreError::SoarLineageIndexConflict {
                reason: format!("lineage shard `{lineage_key}` is not bound to its path"),
            });
        }
        Ok(Some(claim))
    }

    fn write_soar_lineage_claim(
        &self,
        lineage_key: &str,
        claim: &SoarLineageIndexEntry,
    ) -> Result<(), IncidentStoreError> {
        if soar_lineage_index_key(&claim.entry).as_deref() != Some(lineage_key)
            || !claim.matches_entry(&claim.entry)
        {
            return Err(IncidentStoreError::SoarLineageIndexConflict {
                reason: format!("lineage claim does not match shard `{lineage_key}`"),
            });
        }
        if let Some(existing) = self.read_soar_lineage_claim(lineage_key)?
            && (existing.incident_id != claim.incident_id
                || !same_soar_verdict_request(&existing.entry, &claim.entry))
        {
            return Err(IncidentStoreError::SoarLineageIndexConflict {
                reason: format!("lineage shard `{lineage_key}` has conflicting ownership"),
            });
        }
        let path = self.soar_lineage_path(lineage_key)?;
        let parent = path.parent().ok_or_else(|| IncidentStoreError::Write {
            path: path.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SOAR lineage shard has no parent",
            ),
        })?;
        create_dir_all_durably(parent)?;
        let raw = serde_json::to_vec_pretty(claim).map_err(|source| IncidentStoreError::Parse {
            path: path.clone(),
            source,
        })?;
        write_file_atomically(&path, &raw)
    }

    fn reconcile_soar_lineage_claim(
        &self,
        index: &mut IncidentIndex,
        lineage_key: &str,
        claim: &SoarLineageIndexEntry,
    ) -> Result<(), IncidentStoreError> {
        let record_index = index
            .entries
            .iter()
            .position(|record| record.incident_id == claim.incident_id)
            .ok_or_else(|| IncidentStoreError::SoarLineageIndexConflict {
                reason: format!(
                    "lineage `{lineage_key}` references missing incident `{}`",
                    claim.incident_id
                ),
            })?;
        let record = index.entries[record_index].clone();
        let mut lookup = self.read_incident(record)?;
        let durable_entry =
            if let Some(existing) = find_soar_verdict_entry(&lookup.incident, &claim.entry) {
                if !same_soar_verdict_request(existing, &claim.entry) {
                    return Err(IncidentStoreError::SoarLineageIndexConflict {
                        reason: format!(
                            "lineage `{lineage_key}` conflicts with incident `{}`",
                            claim.incident_id
                        ),
                    });
                }
                existing.clone()
            } else {
                lookup
                    .incident
                    .feedback_audit_entries
                    .push(claim.entry.clone());
                let bundle_path = self.write_incident(&lookup.incident)?;
                index.entries[record_index] =
                    IncidentRecord::from_incident(&lookup.incident, bundle_path);
                claim.entry.clone()
            };
        let durable_claim = SoarLineageIndexEntry::from_entry(&claim.incident_id, durable_entry)?;
        self.write_soar_lineage_claim(lineage_key, &durable_claim)
    }

    fn ensure_soar_lineage_index_initialized(
        &self,
        index: &mut IncidentIndex,
    ) -> Result<bool, IncidentStoreError> {
        if index.soar_lineage_index_initialized
            && index.legacy_soar_lineage_claims.is_empty()
            && index.pending_soar_lineage_claims.is_empty()
        {
            return Ok(false);
        }

        let mut claims = std::mem::take(&mut index.legacy_soar_lineage_claims);
        claims.append(&mut index.pending_soar_lineage_claims);
        if !index.soar_lineage_index_initialized {
            for record in index.entries.clone() {
                let lookup = self.read_incident(record)?;
                for entry in &lookup.incident.feedback_audit_entries {
                    if entry.soar_lineage.is_none() || is_rejected_soar_audit(entry) {
                        continue;
                    }
                    let key = soar_lineage_index_key(entry).ok_or_else(|| {
                        IncidentStoreError::SoarLineageIndexConflict {
                            reason: "could not derive an index key from retained SOAR lineage"
                                .to_string(),
                        }
                    })?;
                    let candidate = SoarLineageIndexEntry::from_entry(
                        &lookup.incident.incident_id,
                        entry.clone(),
                    )?;
                    if let Some(existing) = claims.insert(key.clone(), candidate.clone())
                        && existing != candidate
                    {
                        return Err(IncidentStoreError::SoarLineageIndexConflict {
                            reason: format!(
                                "lineage `{key}` maps to conflicting retained audit entries"
                            ),
                        });
                    }
                }
            }
        }
        for (lineage_key, claim) in claims {
            self.reconcile_soar_lineage_claim(index, &lineage_key, &claim)?;
        }
        index.soar_lineage_index_initialized = true;
        Ok(true)
    }

    fn feedback_timestamp_high_water(
        &self,
        index: &IncidentIndex,
    ) -> Result<i64, IncidentStoreError> {
        if let Some(high_water) = index.feedback_timestamp_high_water_ms {
            return Ok(high_water);
        }
        let mut high_water = 0;
        for record in index.entries.clone() {
            let lookup = self.read_incident(record)?;
            high_water = high_water.max(incident_feedback_timestamp_high_water(&lookup.incident));
        }
        Ok(high_water)
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
        write_file_atomically(&path, raw.as_bytes())?;
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
        let incident: CorrelatedIncident = serde_json::from_str(&raw)
            .map_err(|source| IncidentStoreError::Parse { path, source })?;
        let record = IncidentRecord::from_incident(&incident, record.bundle_path);
        Ok(IncidentLookup { record, incident })
    }
}

/// Replace one incident-store document durably without ever exposing partial
/// JSON. The caller holds the cross-process store lock, so a unique sibling
/// temporary plus file and directory fsync establishes the commit boundary.
fn write_file_atomically(path: &Path, bytes: &[u8]) -> Result<(), IncidentStoreError> {
    let parent = path.parent().ok_or_else(|| IncidentStoreError::Write {
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "incident store path has no parent",
        ),
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("incident-store");
    let mut allocation = None;
    for _ in 0..32 {
        let suffix = INCIDENT_TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let candidate = parent.join(format!(
            ".{file_name}.tmp.{}.{}.{nonce}",
            std::process::id(),
            suffix
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => {
                allocation = Some((candidate, file));
                break;
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(IncidentStoreError::Write {
                    path: candidate,
                    source,
                });
            }
        }
    }
    let (temporary, mut file) = allocation.ok_or_else(|| IncidentStoreError::Write {
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique incident-store temporary file",
        ),
    })?;
    let result = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if let Err(source) = result {
        let _ = fs::remove_file(&temporary);
        return Err(IncidentStoreError::Write {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

/// Create each missing component and fsync the parent directory that names it.
/// `create_dir_all` does not make a newly created store root crash-durable.
fn create_dir_all_durably(path: &Path) -> Result<(), IncidentStoreError> {
    let mut missing = Vec::new();
    let mut cursor = path;
    while !cursor.exists() {
        missing.push(cursor.to_path_buf());
        cursor = cursor.parent().ok_or_else(|| IncidentStoreError::Write {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "incident store path has no existing ancestor",
            ),
        })?;
    }
    for directory in missing.into_iter().rev() {
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(IncidentStoreError::Write {
                    path: directory,
                    source,
                });
            }
        }
        let parent = directory
            .parent()
            .ok_or_else(|| IncidentStoreError::Write {
                path: directory.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "created incident store directory has no parent",
                ),
            })?;
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|source| IncidentStoreError::Write {
                path: directory.clone(),
                source,
            })?;
    }
    Ok(())
}

impl IncidentStore for FileIncidentStore {
    fn persist(&self, incident: &CorrelatedIncident) -> Result<IncidentRecord, IncidentStoreError> {
        let _guard = self.lock_mutation()?;
        let mut index = self.read_index()?;
        let _ = self.ensure_soar_lineage_index_initialized(&mut index)?;
        let mut incident = incident.clone();
        if let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.incident_id == incident.incident_id)
            .cloned()
        {
            let existing = self.read_incident(record)?;
            merge_incident_operational_state(&mut incident, &existing.incident);
        }
        let incident_path = self.incident_path(&incident.incident_id);
        let bundle_path = incident_path
            .strip_prefix(&self.root)
            .unwrap_or(&incident_path)
            .display()
            .to_string();
        let record = IncidentRecord::from_incident(&incident, bundle_path);
        let mut candidate_index = index.clone();
        candidate_index
            .entries
            .retain(|entry| entry.incident_id != incident.incident_id);
        candidate_index.entries.push(record.clone());
        candidate_index.feedback_timestamp_high_water_ms = Some(
            candidate_index
                .feedback_timestamp_high_water_ms
                .unwrap_or(0)
                .max(incident_feedback_timestamp_high_water(&incident)),
        );
        self.write_incident(&incident)?;
        self.write_index(&candidate_index)?;
        Ok(record)
    }

    fn upsert_external_reference(
        &self,
        incident_id: &str,
        external_reference: ExternalReference,
    ) -> Result<Option<IncidentRecord>, IncidentStoreError> {
        let _guard = self.lock_mutation()?;
        let mut index = self.read_index()?;
        let _ = self.ensure_soar_lineage_index_initialized(&mut index)?;
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
        if entry.soar_lineage.is_some() && !is_rejected_soar_audit(&entry) {
            return Err(IncidentStoreError::FeedbackOutcomeConflict {
                reason: "non-rejected SOAR audit entries must use the atomic claim path"
                    .to_string(),
            });
        }
        let _guard = self.lock_mutation()?;
        let mut index = self.read_index()?;
        let _ = self.ensure_soar_lineage_index_initialized(&mut index)?;
        let Some(entry_index) = index
            .entries
            .iter()
            .position(|candidate| candidate.incident_id == incident_id)
        else {
            return Ok(None);
        };
        let record = index.entries[entry_index].clone();
        let mut lookup = self.read_incident(record)?;
        let received_at_ms = entry.received_at_ms;
        lookup.incident.feedback_audit_entries.push(entry);
        let bundle_path = self.write_incident(&lookup.incident)?;
        let updated = IncidentRecord::from_incident(&lookup.incident, bundle_path);
        index.entries[entry_index] = updated.clone();
        index.feedback_timestamp_high_water_ms = Some(
            index
                .feedback_timestamp_high_water_ms
                .unwrap_or(0)
                .max(received_at_ms),
        );
        self.write_index(&index)?;
        Ok(Some(updated))
    }

    fn claim_soar_verdict(
        &self,
        incident_id: &str,
        mut entry: AnalystFeedbackAuditEntry,
    ) -> Result<Option<SoarVerdictClaimResult>, IncidentStoreError> {
        let Some(lineage_key) = soar_lineage_index_key(&entry) else {
            return Ok(Some(SoarVerdictClaimResult::Conflict));
        };
        validate_proposed_soar_claim(&entry)?;
        let _guard = self.lock_mutation()?;
        let mut index = self.read_index()?;
        if self.ensure_soar_lineage_index_initialized(&mut index)? {
            self.write_index(&index)?;
        }
        let Some(entry_index) = index
            .entries
            .iter()
            .position(|candidate| candidate.incident_id == incident_id)
        else {
            return Ok(None);
        };

        if let Some(indexed_claim) = self.read_soar_lineage_claim(&lineage_key)? {
            if !indexed_claim.matches_entry(&entry) || indexed_claim.incident_id != incident_id {
                return Ok(Some(SoarVerdictClaimResult::Conflict));
            }
            let Some(claimed_record_index) = index
                .entries
                .iter()
                .position(|record| record.incident_id == indexed_claim.incident_id)
            else {
                return Err(IncidentStoreError::SoarLineageIndexConflict {
                    reason: format!(
                        "lineage `{lineage_key}` references missing incident `{}`",
                        indexed_claim.incident_id
                    ),
                });
            };
            let record = index.entries[claimed_record_index].clone();
            let mut lookup = self.read_incident(record)?;
            if find_soar_verdict_entry(&lookup.incident, &entry).is_none() {
                // Recover an index-first claim whose process stopped before
                // the singular incident document was replaced.
                lookup
                    .incident
                    .feedback_audit_entries
                    .push(indexed_claim.entry.clone());
            }
            let existing = find_soar_verdict_entry_mut(&mut lookup.incident, &entry).ok_or_else(
                || IncidentStoreError::SoarLineageIndexConflict {
                    reason: format!(
                        "lineage `{lineage_key}` could not be reconciled into incident `{incident_id}`"
                    ),
                },
            )?;
            let result = claim_or_classify_soar_verdict(existing, &entry);
            if matches!(result, SoarVerdictClaimResult::Claimed(_))
                || indexed_claim.entry != *existing
            {
                let durable_entry = existing.clone();
                let bundle_path = self.write_incident(&lookup.incident)?;
                index.entries[claimed_record_index] =
                    IncidentRecord::from_incident(&lookup.incident, bundle_path);
                self.write_soar_lineage_claim(
                    &lineage_key,
                    &SoarLineageIndexEntry::from_entry(incident_id, durable_entry)?,
                )?;
                self.write_index(&index)?;
            }
            return Ok(Some(result));
        }

        let record = index.entries[entry_index].clone();
        let mut lookup = self.read_incident(record)?;

        let current = self.feedback_timestamp_high_water(&index)?;
        let reserved = current
            .checked_add(1)
            .map(|next| entry.received_at_ms.max(next))
            .ok_or(IncidentStoreError::FeedbackTimestampExhausted)?;
        entry.received_at_ms = reserved;

        // Commit a short-lived recovery intent before the claim becomes
        // observable. Store-open and every mutation reconcile this exact
        // entry into its incident and digest shard before clearing the intent.
        index.feedback_timestamp_high_water_ms = Some(reserved);
        let indexed_claim = SoarLineageIndexEntry::from_entry(incident_id, entry.clone())?;
        index
            .pending_soar_lineage_claims
            .insert(lineage_key.clone(), indexed_claim.clone());
        self.write_index(&index)?;
        self.write_soar_lineage_claim(&lineage_key, &indexed_claim)?;

        lookup.incident.feedback_audit_entries.push(entry.clone());
        let bundle_path = self.write_incident(&lookup.incident)?;
        index.entries[entry_index] = IncidentRecord::from_incident(&lookup.incident, bundle_path);
        index.pending_soar_lineage_claims.remove(&lineage_key);
        self.write_index(&index)?;
        Ok(Some(SoarVerdictClaimResult::Claimed(entry)))
    }

    fn load_soar_verdict_claim(
        &self,
        source_system: SoarSourceSystem,
        source_verdict_id: &str,
    ) -> Result<Option<AnalystFeedbackAuditEntry>, IncidentStoreError> {
        let lineage_key =
            soar_lineage_index_key_for(source_system, source_verdict_id).ok_or_else(|| {
                IncidentStoreError::SoarLineageIndexConflict {
                    reason: "could not derive a key for the requested SOAR lineage".to_string(),
                }
            })?;
        let _guard = self.lock_mutation()?;
        let mut index = self.read_index()?;
        if self.ensure_soar_lineage_index_initialized(&mut index)? {
            self.write_index(&index)?;
        }
        let Some(mut claim) = self.read_soar_lineage_claim(&lineage_key)? else {
            return Ok(None);
        };
        if claim.source_system != source_system || claim.source_verdict_id != source_verdict_id {
            return Err(IncidentStoreError::SoarLineageIndexConflict {
                reason: format!("lineage key `{lineage_key}` maps to a different source verdict"),
            });
        }
        let record = index
            .entries
            .iter()
            .find(|record| record.incident_id == claim.incident_id)
            .cloned()
            .ok_or_else(|| IncidentStoreError::SoarLineageIndexConflict {
                reason: format!(
                    "lineage key `{lineage_key}` references missing incident `{}`",
                    claim.incident_id
                ),
            })?;
        let lookup = self.read_incident(record)?;
        if let Some(durable) = find_soar_verdict_entry(&lookup.incident, &claim.entry)
            && durable != &claim.entry
        {
            claim = SoarLineageIndexEntry::from_entry(&claim.incident_id, durable.clone())?;
            self.write_soar_lineage_claim(&lineage_key, &claim)?;
        }
        Ok(Some(claim.entry.clone()))
    }

    fn record_feedback_outcome(
        &self,
        incident_id: &str,
        entry: AnalystFeedbackAuditEntry,
        measurement: FalsePositiveMeasurement,
    ) -> Result<Option<IncidentRecord>, IncidentStoreError> {
        let _guard = self.lock_mutation()?;
        let mut index = self.read_index()?;
        let _ = self.ensure_soar_lineage_index_initialized(&mut index)?;
        let Some(entry_index) = index
            .entries
            .iter()
            .position(|candidate| candidate.incident_id == incident_id)
        else {
            return Ok(None);
        };
        let record = index.entries[entry_index].clone();
        let mut lookup = self.read_incident(record)?;
        let received_at_ms = entry.received_at_ms;
        let completed_entry = entry.clone();
        commit_feedback_outcome(&mut lookup.incident, entry, measurement)?;
        let bundle_path = self.write_incident(&lookup.incident)?;
        let updated = IncidentRecord::from_incident(&lookup.incident, bundle_path);
        index.entries[entry_index] = updated.clone();
        index.feedback_timestamp_high_water_ms = Some(
            index
                .feedback_timestamp_high_water_ms
                .unwrap_or(0)
                .max(received_at_ms),
        );
        if let Some(lineage_key) = soar_lineage_index_key(&completed_entry) {
            self.write_soar_lineage_claim(
                &lineage_key,
                &SoarLineageIndexEntry::from_entry(incident_id, completed_entry)?,
            )?;
        }
        self.write_index(&index)?;
        Ok(Some(updated))
    }

    fn load_by_incident_id(
        &self,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, IncidentStoreError> {
        let _guard = self.lock_mutation()?;
        let mut index = self.read_index()?;
        if self.ensure_soar_lineage_index_initialized(&mut index)? {
            self.write_index(&index)?;
        }
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
        let _guard = self.lock_mutation()?;
        let mut index = self.read_index()?;
        if self.ensure_soar_lineage_index_initialized(&mut index)? {
            self.write_index(&index)?;
        }
        let mut entries = index.entries;
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
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
        let _guard = self.lock_mutation()?;
        let mut index = self.read_index()?;
        if self.ensure_soar_lineage_index_initialized(&mut index)? {
            self.write_index(&index)?;
        }
        let mut entries = index.entries;
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        entries.truncate(limit);
        entries
            .into_iter()
            .map(|record| self.read_incident(record).map(|lookup| lookup.record))
            .collect()
    }

    fn health(&self) -> Result<IncidentStoreHealth, IncidentStoreError> {
        let _guard = self.lock_mutation()?;
        create_dir_all_durably(&self.root)?;
        create_dir_all_durably(&self.incidents_dir())?;
        create_dir_all_durably(&self.soar_lineage_root())?;
        let stored_incidents = self.read_index()?.entries.len();
        Ok(IncidentStoreHealth {
            backend: "local_files".to_string(),
            durable: true,
            ready: true,
            stored_incidents,
            details: format!("incident directory at {}", self.root.display()),
        })
    }

    fn reserve_feedback_timestamp_ms(
        &self,
        observed_at_ms: i64,
    ) -> Result<i64, IncidentStoreError> {
        let _guard = self.lock_mutation()?;
        let mut index = self.read_index()?;
        let _ = self.ensure_soar_lineage_index_initialized(&mut index)?;
        // Legacy indexes predate the explicit high-water and are migrated by
        // scanning their incident documents exactly once. Every current
        // reservation is then O(1), independent of incident/deposit volume.
        let current = self.feedback_timestamp_high_water(&index)?;
        let next = current
            .checked_add(1)
            .map(|next| observed_at_ms.max(next))
            .ok_or(IncidentStoreError::FeedbackTimestampExhausted)?;
        index.feedback_timestamp_high_water_ms = Some(next);
        self.write_index(&index)?;
        Ok(next)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct IncidentIndex {
    entries: Vec<IncidentRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    feedback_timestamp_high_water_ms: Option<i64>,
    #[serde(default)]
    soar_lineage_index_initialized: bool,
    /// Read-only migration input for index.json files produced before lineage
    /// ownership moved into digest-sharded records.
    #[serde(default, rename = "soar_lineage_claims", skip_serializing)]
    legacy_soar_lineage_claims: BTreeMap<String, SoarLineageIndexEntry>,
    /// Crash-recovery intents only. Successful claims are removed immediately;
    /// lifetime lineage ownership resides in bounded individual shard files.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pending_soar_lineage_claims: BTreeMap<String, SoarLineageIndexEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct SoarLineageIndexEntry {
    incident_id: String,
    source_system: SoarSourceSystem,
    source_verdict_id: String,
    entry: AnalystFeedbackAuditEntry,
}

impl SoarLineageIndexEntry {
    fn from_entry(
        incident_id: &str,
        entry: AnalystFeedbackAuditEntry,
    ) -> Result<Self, IncidentStoreError> {
        let lineage = entry.soar_lineage.as_ref().ok_or_else(|| {
            IncidentStoreError::SoarLineageIndexConflict {
                reason: "indexed claim is missing SOAR lineage".to_string(),
            }
        })?;
        Ok(Self {
            incident_id: incident_id.to_string(),
            source_system: lineage.source_system,
            source_verdict_id: lineage.source_verdict_id.clone(),
            entry,
        })
    }

    fn matches_entry(&self, entry: &AnalystFeedbackAuditEntry) -> bool {
        entry.soar_lineage.as_ref().is_some_and(|lineage| {
            lineage.source_system == self.source_system
                && lineage.source_verdict_id == self.source_verdict_id
        })
    }
}

fn soar_lineage_index_key(entry: &AnalystFeedbackAuditEntry) -> Option<String> {
    let lineage = entry.soar_lineage.as_ref()?;
    soar_lineage_index_key_for(lineage.source_system, &lineage.source_verdict_id)
}

fn soar_lineage_index_key_for(
    source_system: SoarSourceSystem,
    source_verdict_id: &str,
) -> Option<String> {
    let encoded =
        serde_json::to_vec(&("swarm-soar-lineage-v1", source_system, source_verdict_id)).ok()?;
    Some(sha256_hex(&encoded))
}

fn is_rejected_soar_audit(entry: &AnalystFeedbackAuditEntry) -> bool {
    entry.outcome.get("status").and_then(Value::as_str) == Some("rejected")
}

fn find_soar_verdict_entry<'a>(
    incident: &'a CorrelatedIncident,
    proposed: &AnalystFeedbackAuditEntry,
) -> Option<&'a AnalystFeedbackAuditEntry> {
    let proposed_lineage = proposed.soar_lineage.as_ref()?;
    incident.feedback_audit_entries.iter().find(|existing| {
        !is_rejected_soar_audit(existing)
            && existing.soar_lineage.as_ref().is_some_and(|lineage| {
                lineage.source_system == proposed_lineage.source_system
                    && lineage.source_verdict_id == proposed_lineage.source_verdict_id
            })
    })
}

fn find_soar_verdict_entry_mut<'a>(
    incident: &'a mut CorrelatedIncident,
    proposed: &AnalystFeedbackAuditEntry,
) -> Option<&'a mut AnalystFeedbackAuditEntry> {
    let proposed_lineage = proposed.soar_lineage.as_ref()?;
    incident.feedback_audit_entries.iter_mut().find(|existing| {
        !is_rejected_soar_audit(existing)
            && existing.soar_lineage.as_ref().is_some_and(|lineage| {
                lineage.source_system == proposed_lineage.source_system
                    && lineage.source_verdict_id == proposed_lineage.source_verdict_id
            })
    })
}

fn claim_or_classify_soar_verdict(
    existing: &mut AnalystFeedbackAuditEntry,
    proposed: &AnalystFeedbackAuditEntry,
) -> SoarVerdictClaimResult {
    if !same_soar_verdict_request(existing, proposed) {
        return SoarVerdictClaimResult::Conflict;
    }
    if existing.evidence.is_some() {
        SoarVerdictClaimResult::CompletedExact(existing.clone())
    } else if proposed.soar_claim_lease.is_none()
        || existing.soar_claim_lease.as_ref().is_some_and(|lease| {
            soar_claim_lease_is_active(lease, existing.received_at_ms, proposed.received_at_ms)
        })
    {
        SoarVerdictClaimResult::PendingExact(existing.clone())
    } else {
        if existing.outcome.get("target").is_none()
            && let Some(target) = proposed.outcome.get("target")
        {
            existing.outcome["target"] = target.clone();
        }
        existing.soar_claim_lease = proposed.soar_claim_lease.clone();
        SoarVerdictClaimResult::Claimed(existing.clone())
    }
}

fn validate_proposed_soar_claim(
    entry: &AnalystFeedbackAuditEntry,
) -> Result<(), IncidentStoreError> {
    let Some(lease) = entry.soar_claim_lease.as_ref() else {
        return Ok(());
    };
    if lease.token.trim().is_empty()
        || lease
            .issued_at_ms
            .is_none_or(|issued_at_ms| issued_at_ms <= 0 || lease.expires_at_ms <= issued_at_ms)
    {
        return Err(IncidentStoreError::FeedbackOutcomeConflict {
            reason: "SOAR claim lease must have a non-empty token and a positive persisted clock interval"
                .to_string(),
        });
    }
    Ok(())
}

fn same_soar_verdict_request(
    left: &AnalystFeedbackAuditEntry,
    right: &AnalystFeedbackAuditEntry,
) -> bool {
    left.feedback_id == right.feedback_id
        && left.action == right.action
        && left.analyst_id == right.analyst_id
        && left.incident_id == right.incident_id
        && left.reason == right.reason
        && left.request_signature == right.request_signature
        && left.soar_lineage == right.soar_lineage
        && left.payload == right.payload
}

fn soar_claim_lease_is_active(
    lease: &SoarVerdictClaimLease,
    existing_received_at_ms: i64,
    observed_at_ms: i64,
) -> bool {
    match lease.issued_at_ms {
        Some(issued_at_ms) => {
            // A backwards clock discontinuity invalidates the old deadline.
            // Downstream operations are independently idempotent and the
            // replacement token fences a stale completion.
            observed_at_ms >= issued_at_ms && observed_at_ms < lease.expires_at_ms
        }
        None => {
            // Rolling-upgrade compatibility for leases written before
            // `issued_at_ms` existed. Those leases were incorrectly shifted
            // into the durable audit-timestamp domain, so an observation below
            // that timestamp proves the deadline cannot be trusted.
            observed_at_ms >= existing_received_at_ms && observed_at_ms < lease.expires_at_ms
        }
    }
}

fn commit_feedback_outcome(
    incident: &mut CorrelatedIncident,
    entry: AnalystFeedbackAuditEntry,
    measurement: FalsePositiveMeasurement,
) -> Result<(), IncidentStoreError> {
    if entry.soar_lineage.is_some() {
        let existing_index = incident
            .feedback_audit_entries
            .iter()
            .position(|existing| {
                if is_rejected_soar_audit(existing) {
                    return false;
                }
                let Some(existing_lineage) = existing.soar_lineage.as_ref() else {
                    return false;
                };
                let Some(proposed_lineage) = entry.soar_lineage.as_ref() else {
                    return false;
                };
                existing_lineage.source_system == proposed_lineage.source_system
                    && existing_lineage.source_verdict_id == proposed_lineage.source_verdict_id
            })
            .ok_or_else(|| IncidentStoreError::FeedbackOutcomeConflict {
                reason: "SOAR outcome has no prior source-verdict claim".to_string(),
            })?;
        let existing = &incident.feedback_audit_entries[existing_index];
        if !same_soar_verdict_request(existing, &entry)
            || existing.received_at_ms != entry.received_at_ms
            || existing.soar_claim_lease != entry.soar_claim_lease
        {
            return Err(IncidentStoreError::FeedbackOutcomeConflict {
                reason:
                    "SOAR outcome does not match the claimed request, timestamp, and fencing lease"
                        .to_string(),
            });
        }
        if existing.evidence.is_some() {
            if existing != &entry {
                return Err(IncidentStoreError::FeedbackOutcomeConflict {
                    reason: "SOAR source verdict already completed with a different outcome"
                        .to_string(),
                });
            }
        } else {
            incident.feedback_audit_entries[existing_index] = entry;
        }
    } else {
        incident.feedback_audit_entries.push(entry);
    }
    incident.upsert_false_positive_measurement(measurement);
    Ok(())
}

/// Preserve append-only operator state when a caller persists a correlation
/// snapshot that was loaded before concurrent feedback or callback handling.
/// Existing records win identity collisions because audit entries are
/// immutable once durable; latest timestamps win the mutable projections.
fn merge_incident_operational_state(
    candidate: &mut CorrelatedIncident,
    existing: &CorrelatedIncident,
) {
    for external_reference in existing.external_references.iter().cloned() {
        upsert_external_reference_list(&mut candidate.external_references, external_reference);
    }
    if existing
        .providence_reconciliation
        .as_ref()
        .is_some_and(|current| {
            candidate
                .providence_reconciliation
                .as_ref()
                .is_none_or(|proposed| current.reconciled_at_ms >= proposed.reconciled_at_ms)
        })
    {
        candidate.providence_reconciliation = existing.providence_reconciliation.clone();
    }
    for durable in &existing.providence_callback_audit_entries {
        match candidate
            .providence_callback_audit_entries
            .iter_mut()
            .find(|entry| entry.callback_id == durable.callback_id)
        {
            Some(proposed) => *proposed = durable.clone(),
            None => candidate
                .providence_callback_audit_entries
                .push(durable.clone()),
        }
    }
    candidate
        .providence_callback_audit_entries
        .sort_by(|left, right| {
            left.received_at_ms
                .cmp(&right.received_at_ms)
                .then_with(|| left.callback_id.cmp(&right.callback_id))
        });
    for durable in &existing.feedback_audit_entries {
        match candidate
            .feedback_audit_entries
            .iter_mut()
            .find(|entry| entry.feedback_id == durable.feedback_id)
        {
            Some(proposed) => *proposed = durable.clone(),
            None => candidate.feedback_audit_entries.push(durable.clone()),
        }
    }
    candidate.feedback_audit_entries.sort_by(|left, right| {
        left.received_at_ms
            .cmp(&right.received_at_ms)
            .then_with(|| left.feedback_id.cmp(&right.feedback_id))
    });
    for measurement in existing.false_positive_measurements.iter().cloned() {
        candidate.upsert_false_positive_measurement(measurement);
    }
}

fn incident_feedback_timestamp_high_water(incident: &CorrelatedIncident) -> i64 {
    incident
        .feedback_audit_entries
        .iter()
        .map(|entry| entry.received_at_ms)
        .max()
        .unwrap_or(0)
}

fn advance_feedback_timestamp_high_water(high_water: &AtomicI64, candidate: i64) {
    let _ = high_water.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
        (candidate > current).then_some(candidate)
    });
}

fn reserve_atomic_feedback_timestamp(
    high_water: &AtomicI64,
    observed_at_ms: i64,
) -> Result<i64, IncidentStoreError> {
    let previous = high_water
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
            current.checked_add(1).map(|next| observed_at_ms.max(next))
        })
        .map_err(|_| IncidentStoreError::FeedbackTimestampExhausted)?;
    previous
        .checked_add(1)
        .map(|next| observed_at_ms.max(next))
        .ok_or(IncidentStoreError::FeedbackTimestampExhausted)
}

fn sorted_recent_incidents(incidents: &[CorrelatedIncident]) -> Vec<CorrelatedIncident> {
    let mut ordered = incidents.to_vec();
    ordered.sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
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
        FalsePositiveMeasurement, FileIncidentStore, IncidentEvidenceLink, IncidentGraphDimension,
        IncidentMemberDecision, IncidentStore, IncidentStoreHealth, MemoryIncidentStore,
        SoarVerdictClaimLease, SoarVerdictClaimResult,
    };
    use swarm_core::config::BundleStoreConfig;
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::{
        ProvidenceFeedbackAction, ProvidenceFeedbackEvidence, Severity, SoarSourceSystem,
        SoarVerdictLineage,
    };

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

    fn sample_soar_claim(incident_id: &str, source_verdict_id: &str) -> AnalystFeedbackAuditEntry {
        AnalystFeedbackAuditEntry {
            feedback_id: format!("soar-verdict:{source_verdict_id}"),
            received_at_ms: 1_700_000_003_000,
            action: ProvidenceFeedbackAction::Dismiss,
            analyst_id: "soar:reviewer-1".to_string(),
            incident_id: incident_id.to_string(),
            finding_id: None,
            reason: Some("benign administration".to_string()),
            request_signature: "ed25519=deterministic".to_string(),
            evidence: None,
            soar_lineage: Some(SoarVerdictLineage {
                source_system: SoarSourceSystem::SplunkSoar,
                source_verdict_id: source_verdict_id.to_string(),
                verdict_at_ms: 1_700_000_002_900,
                source_case_id: Some("case-1".to_string()),
                source_case_url: None,
            }),
            payload: serde_json::json!({"source_verdict_id": source_verdict_id}),
            outcome: serde_json::json!({"status": "applying", "target": {"finding_id": "finding-1"}}),
            soar_claim_lease: None,
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
                    soar_lineage: None,
                    payload: serde_json::json!({
                        "action": "dismiss",
                        "incident_id": record.incident_id,
                        "finding_id": "finding-1"
                    }),
                    outcome: serde_json::json!({
                        "status": "pending_feedback"
                    }),
                    soar_claim_lease: None,
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
        assert_eq!(
            FileIncidentStore::open(&root)
                .unwrap()
                .reserve_feedback_timestamp_ms(1)
                .unwrap(),
            1_700_000_000_601,
            "the durable reservation must advance beyond the retained audit after restart"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn memory_store_reserves_unique_monotonic_feedback_timestamps() {
        let store = MemoryIncidentStore::default();
        assert_eq!(store.reserve_feedback_timestamp_ms(100).unwrap(), 100);
        assert_eq!(store.reserve_feedback_timestamp_ms(1).unwrap(), 101);

        let reservations = (0..32)
            .map(|_| {
                let store = store.clone();
                std::thread::spawn(move || store.reserve_feedback_timestamp_ms(1).unwrap())
            })
            .map(|reservation| reservation.join().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(reservations.len(), 32);
        assert_eq!(reservations.first().copied(), Some(102));
        assert_eq!(reservations.last().copied(), Some(133));
    }

    fn assert_stale_persist_preserves_feedback(store: &dyn IncidentStore) {
        let incident = sample_incident();
        store.persist(&incident).unwrap();
        let mut stale = store
            .load_by_incident_id(&incident.incident_id)
            .unwrap()
            .unwrap()
            .incident;
        store
            .record_feedback_outcome(
                &incident.incident_id,
                AnalystFeedbackAuditEntry {
                    feedback_id: "feedback:durable".to_string(),
                    received_at_ms: 1_700_000_002_000,
                    action: ProvidenceFeedbackAction::Dismiss,
                    analyst_id: "analyst:durable".to_string(),
                    incident_id: incident.incident_id.clone(),
                    finding_id: Some("finding:durable".to_string()),
                    reason: None,
                    request_signature: "sha256=durable".to_string(),
                    evidence: None,
                    soar_lineage: None,
                    payload: serde_json::json!({"source": "durable"}),
                    outcome: serde_json::json!({"status": "recorded"}),
                    soar_claim_lease: None,
                },
                FalsePositiveMeasurement {
                    finding_id: "finding:durable".to_string(),
                    hunt_id: "hunt:durable".to_string(),
                    strategy_id: "strategy:durable".to_string(),
                    host_id: None,
                    feedback_id: "feedback:durable".to_string(),
                    reviewed_at_ms: 1_700_000_002_000,
                    analyst_id: "analyst:durable".to_string(),
                    action: ProvidenceFeedbackAction::Dismiss,
                    reason: None,
                    soar_lineage: None,
                    false_positive: true,
                },
            )
            .unwrap()
            .unwrap();

        stale.summary = "refreshed correlation snapshot".to_string();
        store.persist(&stale).unwrap();
        let reloaded = store
            .load_by_incident_id(&incident.incident_id)
            .unwrap()
            .unwrap()
            .incident;
        assert_eq!(reloaded.summary, "refreshed correlation snapshot");
        assert_eq!(reloaded.feedback_audit_entries.len(), 1);
        assert_eq!(
            reloaded.feedback_audit_entries[0].feedback_id,
            "feedback:durable"
        );
        assert_eq!(reloaded.false_positive_measurements.len(), 1);
        assert_eq!(
            reloaded.false_positive_measurements[0].feedback_id,
            "feedback:durable"
        );
    }

    #[test]
    fn stale_correlation_persist_cannot_erase_concurrent_feedback() {
        assert_stale_persist_preserves_feedback(&MemoryIncidentStore::default());

        let root = std::env::temp_dir().join("swarm-spine-incidents-stale-persist");
        let _ = std::fs::remove_dir_all(&root);
        let store = FileIncidentStore::open(&root).unwrap();
        assert_stale_persist_preserves_feedback(&store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn file_store_records_concurrent_feedback_outcomes_without_lost_updates() {
        let root = std::env::temp_dir().join("swarm-spine-incidents-concurrent-feedback");
        let _ = std::fs::remove_dir_all(&root);
        let store = FileIncidentStore::open(&root).unwrap();
        let incident = sample_incident();
        store.persist(&incident).unwrap();

        let writers = (0..16_i64)
            .map(|index| {
                let root = root.clone();
                let incident_id = incident.incident_id.clone();
                std::thread::spawn(move || {
                    let store = FileIncidentStore::open(root).unwrap();
                    let feedback_id = format!("feedback-{index}");
                    let finding_id = format!("finding-{index}");
                    store
                        .record_feedback_outcome(
                            &incident_id,
                            AnalystFeedbackAuditEntry {
                                feedback_id: feedback_id.clone(),
                                received_at_ms: 1_700_000_001_000 + index,
                                action: ProvidenceFeedbackAction::Dismiss,
                                analyst_id: format!("analyst-{index}"),
                                incident_id: incident_id.clone(),
                                finding_id: Some(finding_id.clone()),
                                reason: None,
                                request_signature: format!("sha256={index}"),
                                evidence: None,
                                soar_lineage: None,
                                payload: serde_json::json!({"index": index}),
                                outcome: serde_json::json!({"status": "recorded"}),
                                soar_claim_lease: None,
                            },
                            FalsePositiveMeasurement {
                                finding_id,
                                hunt_id: format!("hunt-{index}"),
                                strategy_id: "strategy".to_string(),
                                host_id: None,
                                feedback_id,
                                reviewed_at_ms: 1_700_000_001_000 + index,
                                analyst_id: format!("analyst-{index}"),
                                action: ProvidenceFeedbackAction::Dismiss,
                                reason: None,
                                soar_lineage: None,
                                false_positive: true,
                            },
                        )
                        .unwrap()
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.join().unwrap();
        }

        let loaded = store
            .load_by_incident_id(&incident.incident_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.incident.feedback_audit_entries.len(), 16);
        assert_eq!(loaded.incident.false_positive_measurements.len(), 16);
        assert_eq!(
            store.reserve_feedback_timestamp_ms(1).unwrap(),
            1_700_000_001_016
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn file_store_atomically_claims_exact_soar_retries_across_instances() {
        let root = std::env::temp_dir().join(format!(
            "swarm-spine-soar-claims-{}-{}",
            std::process::id(),
            super::INCIDENT_TEMP_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = FileIncidentStore::open(&root).unwrap();
        let incident = sample_incident();
        store.persist(&incident).unwrap();
        let proposed = AnalystFeedbackAuditEntry {
            feedback_id: "soar-verdict:splunk_soar:verdict-1".to_string(),
            received_at_ms: 1_700_000_003_000,
            action: ProvidenceFeedbackAction::Dismiss,
            analyst_id: "soar:reviewer-1".to_string(),
            incident_id: incident.incident_id.clone(),
            finding_id: Some("finding-1".to_string()),
            reason: Some("benign administration".to_string()),
            request_signature: "ed25519=deterministic".to_string(),
            evidence: None,
            soar_lineage: Some(SoarVerdictLineage {
                source_system: SoarSourceSystem::SplunkSoar,
                source_verdict_id: "verdict-1".to_string(),
                verdict_at_ms: 1_700_000_002_900,
                source_case_id: Some("case-1".to_string()),
                source_case_url: None,
            }),
            payload: serde_json::json!({"source_verdict_id": "verdict-1"}),
            outcome: serde_json::json!({"status": "applying"}),
            soar_claim_lease: None,
        };

        let claims = (0..16)
            .map(|_| {
                let root = root.clone();
                let incident_id = incident.incident_id.clone();
                let proposed = proposed.clone();
                std::thread::spawn(move || {
                    FileIncidentStore::open(root)
                        .unwrap()
                        .claim_soar_verdict(&incident_id, proposed)
                        .unwrap()
                        .unwrap()
                })
            })
            .map(|claim| claim.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            claims
                .iter()
                .filter(|claim| matches!(claim, SoarVerdictClaimResult::Claimed(_)))
                .count(),
            1
        );
        assert_eq!(
            claims
                .iter()
                .filter(|claim| matches!(claim, SoarVerdictClaimResult::PendingExact(_)))
                .count(),
            15
        );
        let claimed = claims
            .into_iter()
            .find_map(|claim| match claim {
                SoarVerdictClaimResult::Claimed(entry) => Some(entry),
                _ => None,
            })
            .unwrap();
        let reloaded = FileIncidentStore::open(&root)
            .unwrap()
            .load_by_incident_id(&incident.incident_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            reloaded.incident.feedback_audit_entries,
            vec![claimed.clone()]
        );

        let mut completed = claimed.clone();
        completed.evidence = Some(ProvidenceFeedbackEvidence {
            schema: "swarm.providence.feedback.v1".to_string(),
            schema_version: 1,
            threat_class: ThreatClass::Execution,
            agent_id: "agent:feedback".to_string(),
            signed_at_ms: claimed.received_at_ms,
            signature_hex: "00".repeat(64),
        });
        completed.outcome = serde_json::json!({"status": "recorded"});
        store
            .record_feedback_outcome(
                &incident.incident_id,
                completed.clone(),
                FalsePositiveMeasurement {
                    finding_id: "finding-1".to_string(),
                    hunt_id: "hunt-1".to_string(),
                    strategy_id: "strategy-1".to_string(),
                    host_id: Some("host-1".to_string()),
                    feedback_id: completed.feedback_id.clone(),
                    reviewed_at_ms: completed.received_at_ms,
                    analyst_id: completed.analyst_id.clone(),
                    action: completed.action,
                    reason: completed.reason.clone(),
                    soar_lineage: completed.soar_lineage.clone(),
                    false_positive: true,
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            FileIncidentStore::open(&root)
                .unwrap()
                .claim_soar_verdict(&incident.incident_id, proposed.clone())
                .unwrap()
                .unwrap(),
            SoarVerdictClaimResult::CompletedExact(completed)
        );
        let mut conflict = proposed;
        conflict.reason = Some("different immutable request".to_string());
        assert_eq!(
            store
                .claim_soar_verdict(&incident.incident_id, conflict)
                .unwrap()
                .unwrap(),
            SoarVerdictClaimResult::Conflict
        );
        for directory in [&root, &root.join("incidents")] {
            assert!(std::fs::read_dir(directory).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".tmp.")
            }));
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn file_soar_lineage_is_sharded_and_index_metadata_stays_compact() {
        let root = std::env::temp_dir().join(format!(
            "swarm-spine-soar-sharded-index-{}-{}",
            std::process::id(),
            super::INCIDENT_TEMP_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = FileIncidentStore::open(&root).unwrap();
        let incident = sample_incident();
        store.persist(&incident).unwrap();
        let claim = sample_soar_claim(&incident.incident_id, "sharded-verdict");
        assert!(matches!(
            store
                .claim_soar_verdict(&incident.incident_id, claim.clone())
                .unwrap()
                .unwrap(),
            SoarVerdictClaimResult::Claimed(_)
        ));

        let lineage_key = super::soar_lineage_index_key(&claim).unwrap();
        let shard = store.soar_lineage_path(&lineage_key).unwrap();
        assert!(shard.exists());
        let index: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("index.json")).unwrap())
                .unwrap();
        assert_eq!(
            index["entries"][0]["feedback_audit_entries"],
            serde_json::json!([])
        );
        assert!(index.get("soar_lineage_claims").is_none());
        assert!(index.get("pending_soar_lineage_claims").is_none());
        assert!(
            !std::fs::read_to_string(root.join("index.json"))
                .unwrap()
                .contains("sharded-verdict")
        );

        let loaded = FileIncidentStore::open(&root)
            .unwrap()
            .load_soar_verdict_claim(SoarSourceSystem::SplunkSoar, "sharded-verdict")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.feedback_id, claim.feedback_id);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn correlation_refresh_recovers_an_index_first_soar_claim() {
        let root = std::env::temp_dir().join(format!(
            "swarm-spine-soar-index-first-refresh-{}-{}",
            std::process::id(),
            super::INCIDENT_TEMP_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = FileIncidentStore::open(&root).unwrap();
        let incident = sample_incident();
        store.persist(&incident).unwrap();
        let claim = sample_soar_claim(&incident.incident_id, "index-first-verdict");
        let lineage_key = super::soar_lineage_index_key(&claim).unwrap();
        {
            let _guard = store.lock_mutation().unwrap();
            let mut index = store.read_index().unwrap();
            index.pending_soar_lineage_claims.insert(
                lineage_key.clone(),
                super::SoarLineageIndexEntry::from_entry(&incident.incident_id, claim.clone())
                    .unwrap(),
            );
            store.write_index(&index).unwrap();
        }

        let mut refreshed = incident.clone();
        refreshed.summary = "new correlation snapshot".to_string();
        store.persist(&refreshed).unwrap();
        let loaded = store
            .load_by_incident_id(&incident.incident_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.incident.summary, "new correlation snapshot");
        assert_eq!(loaded.incident.feedback_audit_entries, vec![claim.clone()]);
        assert!(store.soar_lineage_path(&lineage_key).unwrap().exists());
        let index = store.read_index().unwrap();
        assert!(index.pending_soar_lineage_claims.is_empty());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn expired_soar_claim_is_recovered_and_fences_the_stale_worker() {
        let store = MemoryIncidentStore::default();
        let incident = sample_incident();
        store.persist(&incident).unwrap();

        let mut first = sample_soar_claim(&incident.incident_id, "recoverable-verdict");
        first.soar_claim_lease = Some(SoarVerdictClaimLease {
            token: "lease-a".to_string(),
            issued_at_ms: Some(first.received_at_ms),
            expires_at_ms: first.received_at_ms + 10,
        });
        let first = match store
            .claim_soar_verdict(&incident.incident_id, first)
            .unwrap()
            .unwrap()
        {
            SoarVerdictClaimResult::Claimed(entry) => entry,
            other => panic!("unexpected first claim: {other:?}"),
        };

        let mut reordered = sample_soar_claim(&incident.incident_id, "recoverable-verdict");
        reordered.finding_id = Some("finding-selected-after-reorder".to_string());
        reordered.outcome = serde_json::json!({
            "status": "applying",
            "target": {"finding_id": "finding-selected-after-reorder"}
        });
        reordered.soar_claim_lease = Some(SoarVerdictClaimLease {
            token: "lease-concurrent".to_string(),
            issued_at_ms: Some(reordered.received_at_ms),
            expires_at_ms: first.received_at_ms + 20,
        });
        let pending = store
            .claim_soar_verdict(&incident.incident_id, reordered)
            .unwrap()
            .unwrap();
        let SoarVerdictClaimResult::PendingExact(pending) = pending else {
            panic!("active exact retry did not observe the durable claim");
        };
        assert_eq!(
            pending.outcome["target"]["finding_id"], "finding-1",
            "incident reordering must not replace the originally claimed target"
        );

        let mut retry = sample_soar_claim(&incident.incident_id, "recoverable-verdict");
        retry.received_at_ms = first.soar_claim_lease.as_ref().unwrap().expires_at_ms;
        retry.soar_claim_lease = Some(SoarVerdictClaimLease {
            token: "lease-b".to_string(),
            issued_at_ms: Some(retry.received_at_ms),
            expires_at_ms: retry.received_at_ms + 10,
        });
        let recovered = match store
            .claim_soar_verdict(&incident.incident_id, retry)
            .unwrap()
            .unwrap()
        {
            SoarVerdictClaimResult::Claimed(entry) => entry,
            other => panic!("expired claim was not recovered: {other:?}"),
        };
        assert_eq!(
            recovered.soar_claim_lease.as_ref().unwrap().token,
            "lease-b"
        );

        let mut stale_completion = first;
        stale_completion.evidence = Some(ProvidenceFeedbackEvidence {
            schema: "swarm.providence.feedback.v1".to_string(),
            schema_version: 1,
            threat_class: ThreatClass::Execution,
            agent_id: "agent:feedback".to_string(),
            signed_at_ms: stale_completion.received_at_ms,
            signature_hex: "00".repeat(64),
        });
        stale_completion.outcome = serde_json::json!({"status": "recorded"});
        assert!(matches!(
            store.record_feedback_outcome(
                &incident.incident_id,
                stale_completion.clone(),
                FalsePositiveMeasurement {
                    finding_id: "finding-1".to_string(),
                    hunt_id: "hunt-1".to_string(),
                    strategy_id: "strategy-1".to_string(),
                    host_id: None,
                    feedback_id: stale_completion.feedback_id,
                    reviewed_at_ms: stale_completion.received_at_ms,
                    analyst_id: stale_completion.analyst_id,
                    action: stale_completion.action,
                    reason: stale_completion.reason,
                    soar_lineage: stale_completion.soar_lineage,
                    false_positive: true,
                },
            ),
            Err(super::IncidentStoreError::FeedbackOutcomeConflict { .. })
        ));
    }

    #[test]
    fn soar_lease_expiry_stays_in_its_persisted_clock_domain() {
        let store = MemoryIncidentStore::default();
        let mut incident = sample_incident();
        let mut future_audit = sample_soar_claim(&incident.incident_id, "rejected-future-audit");
        future_audit.received_at_ms = 9_000_000_000_000;
        future_audit.outcome = serde_json::json!({"status": "rejected"});
        incident.feedback_audit_entries.push(future_audit);
        store.persist(&incident).unwrap();

        let mut first = sample_soar_claim(&incident.incident_id, "durable-clock-verdict");
        first.received_at_ms = 1_700_000_003_000;
        first.soar_claim_lease = Some(SoarVerdictClaimLease {
            token: "wall-lease-a".to_string(),
            issued_at_ms: Some(first.received_at_ms),
            expires_at_ms: first.received_at_ms + 10,
        });
        let first = match store
            .claim_soar_verdict(&incident.incident_id, first)
            .unwrap()
            .unwrap()
        {
            SoarVerdictClaimResult::Claimed(entry) => entry,
            other => panic!("unexpected initial claim: {other:?}"),
        };
        assert!(first.received_at_ms > first.soar_claim_lease.as_ref().unwrap().expires_at_ms);

        let mut retry = sample_soar_claim(&incident.incident_id, "durable-clock-verdict");
        retry.received_at_ms = 1_700_000_003_010;
        retry.soar_claim_lease = Some(SoarVerdictClaimLease {
            token: "wall-lease-b".to_string(),
            issued_at_ms: Some(retry.received_at_ms),
            expires_at_ms: retry.received_at_ms + 10,
        });
        let recovered = store
            .claim_soar_verdict(&incident.incident_id, retry)
            .unwrap()
            .unwrap();
        assert!(matches!(
            recovered,
            SoarVerdictClaimResult::Claimed(entry)
                if entry.soar_claim_lease.as_ref().unwrap().token == "wall-lease-b"
        ));
    }

    #[test]
    fn rejected_soar_audit_does_not_reserve_lineage_for_corrected_redelivery() {
        let store = MemoryIncidentStore::default();
        let mut incident = sample_incident();
        let mut rejected = sample_soar_claim(&incident.incident_id, "corrected-verdict");
        rejected.outcome = serde_json::json!({"status": "rejected", "reason": "invalid action"});
        incident.feedback_audit_entries.push(rejected);
        store.persist(&incident).unwrap();

        let corrected = sample_soar_claim(&incident.incident_id, "corrected-verdict");
        assert!(matches!(
            store
                .claim_soar_verdict(&incident.incident_id, corrected)
                .unwrap()
                .unwrap(),
            SoarVerdictClaimResult::Claimed(_)
        ));
    }

    #[test]
    fn file_soar_lineage_index_does_not_parse_unrelated_incident_documents() {
        let root = std::env::temp_dir().join(format!(
            "swarm-spine-bounded-soar-index-{}-{}",
            std::process::id(),
            super::INCIDENT_TEMP_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let store = FileIncidentStore::open(&root).unwrap();
        let first = sample_incident();
        let mut unrelated = sample_incident();
        unrelated.incident_id = "incident:unrelated".to_string();
        store.persist(&first).unwrap();
        store.persist(&unrelated).unwrap();

        let proposed = sample_soar_claim(&first.incident_id, "bounded-verdict");
        assert!(matches!(
            store
                .claim_soar_verdict(&first.incident_id, proposed.clone())
                .unwrap()
                .unwrap(),
            SoarVerdictClaimResult::Claimed(_)
        ));
        std::fs::write(store.incident_path(&unrelated.incident_id), b"not-json").unwrap();
        assert!(matches!(
            store
                .claim_soar_verdict(&first.incident_id, proposed)
                .unwrap()
                .unwrap(),
            SoarVerdictClaimResult::PendingExact(_)
        ));
        let _ = std::fs::remove_dir_all(root);
    }
}
