use crate::evidence::{
    EvidenceError, FileEvidenceBundleStore, FileEvidenceVerificationStore,
    verify_bundle_with_stores,
};
use crate::governance_prep::{DefaultEvolutionGovernancePrepHarness, EvolutionGovernancePrepError};
use crate::operator_http::OperatorSurfacePaths;
use crate::portfolio::{
    DefaultEvolutionPortfolioHarness, EvolutionPortfolioDecisionAction, EvolutionPortfolioError,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Approved operator maintenance actions for the local authenticated surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum OperatorMaintenanceRequest {
    PortfolioEntryDecision {
        portfolio_id: String,
        entry_id: String,
        decision: EvolutionPortfolioDecisionAction,
        reason: String,
    },
    PacketSetSplit {
        parent_packet_set_id: String,
        name: String,
        packet_ids: Vec<String>,
        reason: String,
    },
    RefreshPortfolioHistory {
        packet_set_id: String,
        reason: String,
    },
    ReverifyEvidenceBundle {
        bundle_id: String,
        expected_key_id: Option<String>,
        reason: String,
    },
}

/// Final execution state for one persisted maintenance action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorMaintenanceStatus {
    Applied,
    Blocked,
    Failed,
}

/// One artifact produced or updated by a maintenance action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorMaintenanceArtifactRef {
    pub kind: String,
    pub id: String,
}

/// One durable maintenance action audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorMaintenanceRecord {
    pub action_id: String,
    pub actor: String,
    pub requested_at_ms: i64,
    pub completed_at_ms: i64,
    pub action: OperatorMaintenanceRequest,
    pub target_kind: String,
    pub target_id: String,
    pub reason: String,
    pub status: OperatorMaintenanceStatus,
    pub summary: String,
    pub artifacts: Vec<OperatorMaintenanceArtifactRef>,
    pub native_history_ref: Option<String>,
}

/// Index metadata for one persisted maintenance action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorMaintenanceRecordSummary {
    pub action_id: String,
    pub actor: String,
    pub target_kind: String,
    pub target_id: String,
    pub status: OperatorMaintenanceStatus,
    pub completed_at_ms: i64,
    pub bundle_path: String,
}

impl OperatorMaintenanceRecordSummary {
    fn from_record(record: &OperatorMaintenanceRecord, bundle_path: String) -> Self {
        Self {
            action_id: record.action_id.clone(),
            actor: record.actor.clone(),
            target_kind: record.target_kind.clone(),
            target_id: record.target_id.clone(),
            status: record.status,
            completed_at_ms: record.completed_at_ms,
            bundle_path,
        }
    }
}

/// Operator-facing maintenance action listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorMaintenanceList {
    pub total_count: usize,
    pub status: Option<OperatorMaintenanceStatus>,
    pub actions: Vec<OperatorMaintenanceRecordSummary>,
}

/// Persisted maintenance action loaded with metadata.
#[derive(Debug, Clone)]
pub struct OperatorMaintenanceLookup {
    pub summary: OperatorMaintenanceRecordSummary,
    pub record: OperatorMaintenanceRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OperatorMaintenanceIndex {
    entries: Vec<OperatorMaintenanceRecordSummary>,
}

/// Errors raised by the file-backed maintenance action store.
#[derive(Debug, thiserror::Error)]
pub enum OperatorMaintenanceStoreError {
    #[error("failed to read maintenance store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write maintenance store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse maintenance store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised while building the maintenance service.
#[derive(Debug, thiserror::Error)]
pub enum OperatorMaintenanceError {
    #[error(transparent)]
    Store(#[from] OperatorMaintenanceStoreError),

    #[error(transparent)]
    Portfolio(#[from] EvolutionPortfolioError),

    #[error(transparent)]
    GovernancePrep(#[from] EvolutionGovernancePrepError),

    #[error(transparent)]
    Evidence(#[from] EvidenceError),
}

/// File-backed store for maintenance action audit records.
#[derive(Debug, Clone)]
pub struct FileOperatorMaintenanceStore {
    root: PathBuf,
}

impl FileOperatorMaintenanceStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OperatorMaintenanceStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            OperatorMaintenanceStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, action_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(action_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<OperatorMaintenanceIndex, OperatorMaintenanceStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(OperatorMaintenanceIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| OperatorMaintenanceStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| OperatorMaintenanceStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &OperatorMaintenanceIndex,
    ) -> Result<(), OperatorMaintenanceStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            OperatorMaintenanceStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| OperatorMaintenanceStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        record: &OperatorMaintenanceRecord,
    ) -> Result<OperatorMaintenanceLookup, OperatorMaintenanceStoreError> {
        let path = self.report_path(&record.action_id);
        let raw = serde_json::to_string_pretty(record).map_err(|source| {
            OperatorMaintenanceStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| OperatorMaintenanceStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let summary =
            OperatorMaintenanceRecordSummary::from_record(record, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.action_id != summary.action_id);
        index.entries.push(summary.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.completed_at_ms));
        self.write_index(&index)?;
        Ok(OperatorMaintenanceLookup {
            summary,
            record: record.clone(),
        })
    }

    pub fn load(
        &self,
        action_id: &str,
    ) -> Result<Option<OperatorMaintenanceLookup>, OperatorMaintenanceStoreError> {
        let index = self.read_index()?;
        let Some(summary) = index
            .entries
            .iter()
            .find(|entry| entry.action_id == action_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&summary.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| OperatorMaintenanceStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let record = serde_json::from_str(&raw)
            .map_err(|source| OperatorMaintenanceStoreError::Parse { path, source })?;
        Ok(Some(OperatorMaintenanceLookup { summary, record }))
    }

    pub fn list(
        &self,
        status: Option<OperatorMaintenanceStatus>,
    ) -> Result<OperatorMaintenanceList, OperatorMaintenanceStoreError> {
        let mut actions = self.read_index()?.entries;
        if let Some(status) = status {
            actions.retain(|entry| entry.status == status);
        }
        Ok(OperatorMaintenanceList {
            total_count: actions.len(),
            status,
            actions,
        })
    }
}

/// Outcome of executing one operator maintenance action.
#[derive(Debug, Clone)]
pub enum OperatorMaintenanceExecution {
    Applied(OperatorMaintenanceLookup),
    Blocked(OperatorMaintenanceLookup),
    Failed(OperatorMaintenanceLookup),
}

impl OperatorMaintenanceExecution {
    pub fn lookup(&self) -> &OperatorMaintenanceLookup {
        match self {
            Self::Applied(lookup) | Self::Blocked(lookup) | Self::Failed(lookup) => lookup,
        }
    }
}

/// Bounded maintenance service for the local operator surface.
#[derive(Debug, Clone)]
pub struct OperatorMaintenanceService {
    portfolio: DefaultEvolutionPortfolioHarness,
    governance_prep: DefaultEvolutionGovernancePrepHarness,
    evidence_store: FileEvidenceBundleStore,
    evidence_verification_store: FileEvidenceVerificationStore,
    store: FileOperatorMaintenanceStore,
}

impl OperatorMaintenanceService {
    pub fn from_paths(paths: &OperatorSurfacePaths) -> Result<Self, OperatorMaintenanceError> {
        Ok(Self {
            portfolio: DefaultEvolutionPortfolioHarness::from_path(
                &paths.evolution_ranking_results_dir,
                &paths.evolution_selection_results_dir,
                &paths.evolution_portfolio_results_dir,
                &paths.evolution_governance_review_packet_results_dir,
            )?,
            governance_prep: DefaultEvolutionGovernancePrepHarness::from_path(
                &paths.evolution_governance_review_packet_results_dir,
                &paths.evolution_packet_set_results_dir,
                &paths.strategy_memory_results_dir,
                &paths.evolution_portfolio_history_results_dir,
            )?,
            evidence_store: FileEvidenceBundleStore::open(&paths.evidence_results_dir)
                .map_err(EvidenceError::from)?,
            evidence_verification_store: FileEvidenceVerificationStore::open(
                &paths.evidence_verification_results_dir,
            )
            .map_err(EvidenceError::from)?,
            store: FileOperatorMaintenanceStore::open(&paths.operator_maintenance_results_dir)?,
        })
    }

    pub fn execute(
        &self,
        actor: &str,
        request: OperatorMaintenanceRequest,
    ) -> Result<OperatorMaintenanceExecution, OperatorMaintenanceError> {
        let requested_at_ms = now_ms();
        let (action_kind, target_kind, target_id, reason) = request_metadata(&request);
        let reason = reason.to_string();
        if let Err(summary) = validate_request(&request) {
            return self.persist_error_record(
                base_record(
                    action_kind,
                    actor,
                    requested_at_ms,
                    target_kind,
                    target_id,
                    &reason,
                    request,
                ),
                OperatorMaintenanceStatus::Blocked,
                summary,
            );
        }

        match &request {
            OperatorMaintenanceRequest::PortfolioEntryDecision {
                portfolio_id,
                entry_id,
                decision,
                reason,
            } => match self
                .portfolio
                .record_decision(portfolio_id, entry_id, *decision, reason)
            {
                Ok(lookup) => Ok(OperatorMaintenanceExecution::Applied(
                    self.persist_record(
                        base_record(
                            "portfolio_entry_decision",
                            actor,
                            requested_at_ms,
                            "portfolio_entry",
                            format!("{portfolio_id}:{entry_id}"),
                            reason,
                            request.clone(),
                        )
                        .with_status(
                            OperatorMaintenanceStatus::Applied,
                            format!(
                                "recorded portfolio decision `{}` for entry `{}`",
                                decision_label(*decision),
                                entry_id
                            ),
                            vec![OperatorMaintenanceArtifactRef {
                                kind: "portfolio".to_string(),
                                id: lookup.report.portfolio_id,
                            }],
                            Some(format!("portfolio:{portfolio_id}/entry:{entry_id}")),
                        ),
                    )?,
                )),
                Err(error) => self.persist_error_record(
                    base_record(
                        "portfolio_entry_decision",
                        actor,
                        requested_at_ms,
                        "portfolio_entry",
                        format!("{portfolio_id}:{entry_id}"),
                        reason,
                        request.clone(),
                    ),
                    classify_portfolio_error(&error),
                    error.to_string(),
                ),
            },
            OperatorMaintenanceRequest::PacketSetSplit {
                parent_packet_set_id,
                name,
                packet_ids,
                reason,
            } => match self.governance_prep.split_packet_set(
                parent_packet_set_id,
                name,
                reason,
                packet_ids.clone(),
            ) {
                Ok(lookup) => Ok(OperatorMaintenanceExecution::Applied(
                    self.persist_record(
                        base_record(
                            "packet_set_split",
                            actor,
                            requested_at_ms,
                            "packet_set",
                            parent_packet_set_id.clone(),
                            reason,
                            request.clone(),
                        )
                        .with_status(
                            OperatorMaintenanceStatus::Applied,
                            format!(
                                "split packet set `{}` into child `{}`",
                                parent_packet_set_id, lookup.report.packet_set_id
                            ),
                            vec![OperatorMaintenanceArtifactRef {
                                kind: "packet_set".to_string(),
                                id: lookup.report.packet_set_id,
                            }],
                            Some(parent_packet_set_id.clone()),
                        ),
                    )?,
                )),
                Err(error) => self.persist_error_record(
                    base_record(
                        "packet_set_split",
                        actor,
                        requested_at_ms,
                        "packet_set",
                        parent_packet_set_id.clone(),
                        reason,
                        request.clone(),
                    ),
                    classify_governance_error(&error),
                    error.to_string(),
                ),
            },
            OperatorMaintenanceRequest::RefreshPortfolioHistory {
                packet_set_id,
                reason,
            } => match self.governance_prep.create_portfolio_history(packet_set_id) {
                Ok(lookup) => Ok(OperatorMaintenanceExecution::Applied(
                    self.persist_record(
                        base_record(
                            "refresh_portfolio_history",
                            actor,
                            requested_at_ms,
                            "packet_set",
                            packet_set_id.clone(),
                            reason,
                            request.clone(),
                        )
                        .with_status(
                            OperatorMaintenanceStatus::Applied,
                            format!(
                                "created refreshed portfolio history `{}` from packet set `{}`",
                                lookup.report.history_id, packet_set_id
                            ),
                            vec![OperatorMaintenanceArtifactRef {
                                kind: "portfolio_history".to_string(),
                                id: lookup.report.history_id,
                            }],
                            Some(packet_set_id.clone()),
                        ),
                    )?,
                )),
                Err(error) => self.persist_error_record(
                    base_record(
                        "refresh_portfolio_history",
                        actor,
                        requested_at_ms,
                        "packet_set",
                        packet_set_id.clone(),
                        reason,
                        request.clone(),
                    ),
                    classify_governance_error(&error),
                    error.to_string(),
                ),
            },
            OperatorMaintenanceRequest::ReverifyEvidenceBundle {
                bundle_id,
                expected_key_id,
                reason,
            } => match verify_bundle_with_stores(
                &self.evidence_store,
                &self.evidence_verification_store,
                bundle_id,
                expected_key_id.as_deref(),
            ) {
                Ok(lookup) => {
                    let status = match lookup.report.status {
                        crate::evidence::EvidenceVerificationStatus::Passed => {
                            OperatorMaintenanceStatus::Applied
                        }
                        crate::evidence::EvidenceVerificationStatus::Failed => {
                            OperatorMaintenanceStatus::Blocked
                        }
                    };
                    let summary = match lookup.report.status {
                        crate::evidence::EvidenceVerificationStatus::Passed => {
                            format!("re-verified evidence bundle `{}` successfully", bundle_id)
                        }
                        crate::evidence::EvidenceVerificationStatus::Failed => format!(
                            "re-verified evidence bundle `{}` but verification failed",
                            bundle_id
                        ),
                    };
                    self.persist_execution_record(
                        base_record(
                            "reverify_evidence_bundle",
                            actor,
                            requested_at_ms,
                            "evidence_bundle",
                            bundle_id.clone(),
                            reason,
                            request.clone(),
                        ),
                        status,
                        summary,
                        vec![OperatorMaintenanceArtifactRef {
                            kind: "evidence_verification".to_string(),
                            id: lookup.report.verification_id,
                        }],
                        Some(bundle_id.clone()),
                    )
                }
                Err(error) => self.persist_error_record(
                    base_record(
                        "reverify_evidence_bundle",
                        actor,
                        requested_at_ms,
                        "evidence_bundle",
                        bundle_id.clone(),
                        reason,
                        request.clone(),
                    ),
                    classify_evidence_error(&error),
                    error.to_string(),
                ),
            },
        }
    }

    pub fn load(
        &self,
        action_id: &str,
    ) -> Result<Option<OperatorMaintenanceLookup>, OperatorMaintenanceError> {
        Ok(self.store.load(action_id)?)
    }

    pub fn list(
        &self,
        status: Option<OperatorMaintenanceStatus>,
    ) -> Result<OperatorMaintenanceList, OperatorMaintenanceError> {
        Ok(self.store.list(status)?)
    }

    fn persist_record(
        &self,
        record: OperatorMaintenanceRecord,
    ) -> Result<OperatorMaintenanceLookup, OperatorMaintenanceError> {
        Ok(self.store.persist(&record)?)
    }

    fn persist_error_record(
        &self,
        record: OperatorMaintenanceRecordBuilder,
        status: OperatorMaintenanceStatus,
        summary: String,
    ) -> Result<OperatorMaintenanceExecution, OperatorMaintenanceError> {
        self.persist_execution_record(record, status, summary, Vec::new(), None)
    }

    fn persist_execution_record(
        &self,
        record: OperatorMaintenanceRecordBuilder,
        status: OperatorMaintenanceStatus,
        summary: String,
        artifacts: Vec<OperatorMaintenanceArtifactRef>,
        native_history_ref: Option<String>,
    ) -> Result<OperatorMaintenanceExecution, OperatorMaintenanceError> {
        let record = record.with_status(status, summary, artifacts, native_history_ref);
        let lookup = self.store.persist(&record)?;
        Ok(match status {
            OperatorMaintenanceStatus::Blocked => OperatorMaintenanceExecution::Blocked(lookup),
            OperatorMaintenanceStatus::Failed => OperatorMaintenanceExecution::Failed(lookup),
            OperatorMaintenanceStatus::Applied => OperatorMaintenanceExecution::Applied(lookup),
        })
    }
}

#[derive(Debug)]
struct OperatorMaintenanceRecordBuilder {
    action_id: String,
    actor: String,
    requested_at_ms: i64,
    completed_at_ms: i64,
    action: OperatorMaintenanceRequest,
    target_kind: String,
    target_id: String,
    reason: String,
}

impl OperatorMaintenanceRecordBuilder {
    fn with_status(
        self,
        status: OperatorMaintenanceStatus,
        summary: String,
        artifacts: Vec<OperatorMaintenanceArtifactRef>,
        native_history_ref: Option<String>,
    ) -> OperatorMaintenanceRecord {
        OperatorMaintenanceRecord {
            action_id: self.action_id,
            actor: self.actor,
            requested_at_ms: self.requested_at_ms,
            completed_at_ms: self.completed_at_ms,
            action: self.action,
            target_kind: self.target_kind,
            target_id: self.target_id,
            reason: self.reason,
            status,
            summary,
            artifacts,
            native_history_ref,
        }
    }
}

fn base_record(
    action_kind: &str,
    actor: &str,
    requested_at_ms: i64,
    target_kind: &str,
    target_id: String,
    reason: &str,
    action: OperatorMaintenanceRequest,
) -> OperatorMaintenanceRecordBuilder {
    OperatorMaintenanceRecordBuilder {
        action_id: format!(
            "maintenance:{}:{}",
            sanitize_id(action_kind),
            now_unix_nanos()
        ),
        actor: actor.to_string(),
        requested_at_ms,
        completed_at_ms: now_ms(),
        action,
        target_kind: target_kind.to_string(),
        target_id,
        reason: reason.to_string(),
    }
}

fn classify_portfolio_error(error: &EvolutionPortfolioError) -> OperatorMaintenanceStatus {
    match error {
        EvolutionPortfolioError::PortfolioNotFound { .. }
        | EvolutionPortfolioError::PortfolioEntryNotFound { .. }
        | EvolutionPortfolioError::InvalidDecision { .. }
        | EvolutionPortfolioError::InvalidPortfolioRequest { .. } => {
            OperatorMaintenanceStatus::Blocked
        }
        _ => OperatorMaintenanceStatus::Failed,
    }
}

fn classify_governance_error(error: &EvolutionGovernancePrepError) -> OperatorMaintenanceStatus {
    match error {
        EvolutionGovernancePrepError::PacketSetNotFound { .. }
        | EvolutionGovernancePrepError::InvalidPacketSetRequest { .. }
        | EvolutionGovernancePrepError::PacketNotInSet { .. }
        | EvolutionGovernancePrepError::InconsistentPacketEvidence { .. }
        | EvolutionGovernancePrepError::PortfolioHistoryNotFound { .. }
        | EvolutionGovernancePrepError::GovernancePacketNotFound { .. } => {
            OperatorMaintenanceStatus::Blocked
        }
        _ => OperatorMaintenanceStatus::Failed,
    }
}

fn classify_evidence_error(error: &EvidenceError) -> OperatorMaintenanceStatus {
    match error {
        EvidenceError::ArtifactNotFound { .. } => OperatorMaintenanceStatus::Blocked,
        _ => OperatorMaintenanceStatus::Failed,
    }
}

fn validate_request(request: &OperatorMaintenanceRequest) -> Result<(), String> {
    if request_reason(request).trim().is_empty() {
        return Err("maintenance reason cannot be empty".to_string());
    }
    Ok(())
}

fn request_reason(request: &OperatorMaintenanceRequest) -> &str {
    match request {
        OperatorMaintenanceRequest::PortfolioEntryDecision { reason, .. }
        | OperatorMaintenanceRequest::PacketSetSplit { reason, .. }
        | OperatorMaintenanceRequest::RefreshPortfolioHistory { reason, .. }
        | OperatorMaintenanceRequest::ReverifyEvidenceBundle { reason, .. } => reason,
    }
}

fn request_metadata(
    request: &OperatorMaintenanceRequest,
) -> (&'static str, &'static str, String, &str) {
    match request {
        OperatorMaintenanceRequest::PortfolioEntryDecision {
            portfolio_id,
            entry_id,
            reason,
            ..
        } => (
            "portfolio_entry_decision",
            "portfolio_entry",
            format!("{portfolio_id}:{entry_id}"),
            reason,
        ),
        OperatorMaintenanceRequest::PacketSetSplit {
            parent_packet_set_id,
            reason,
            ..
        } => (
            "packet_set_split",
            "packet_set",
            parent_packet_set_id.clone(),
            reason,
        ),
        OperatorMaintenanceRequest::RefreshPortfolioHistory {
            packet_set_id,
            reason,
        } => (
            "refresh_portfolio_history",
            "packet_set",
            packet_set_id.clone(),
            reason,
        ),
        OperatorMaintenanceRequest::ReverifyEvidenceBundle {
            bundle_id, reason, ..
        } => (
            "reverify_evidence_bundle",
            "evidence_bundle",
            bundle_id.clone(),
            reason,
        ),
    }
}

fn decision_label(value: EvolutionPortfolioDecisionAction) -> &'static str {
    match value {
        EvolutionPortfolioDecisionAction::Include => "include",
        EvolutionPortfolioDecisionAction::Defer => "defer",
        EvolutionPortfolioDecisionAction::Drop => "drop",
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn sanitize_id(value: &str) -> String {
    value
        .trim()
        .chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' => character.to_ascii_lowercase(),
            _ => '_',
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        FileOperatorMaintenanceStore, OperatorMaintenanceExecution, OperatorMaintenanceRecord,
        OperatorMaintenanceRequest, OperatorMaintenanceStatus,
    };
    use crate::portfolio::EvolutionPortfolioDecisionAction;

    fn sample_record(
        action_id: &str,
        status: OperatorMaintenanceStatus,
    ) -> OperatorMaintenanceRecord {
        OperatorMaintenanceRecord {
            action_id: action_id.to_string(),
            actor: "local-operator".to_string(),
            requested_at_ms: 1,
            completed_at_ms: 2,
            action: OperatorMaintenanceRequest::PortfolioEntryDecision {
                portfolio_id: "portfolio:red".to_string(),
                entry_id: "entry:red".to_string(),
                decision: EvolutionPortfolioDecisionAction::Include,
                reason: "include it".to_string(),
            },
            target_kind: "portfolio_entry".to_string(),
            target_id: "portfolio:red:entry:red".to_string(),
            reason: "include it".to_string(),
            status,
            summary: "applied".to_string(),
            artifacts: Vec::new(),
            native_history_ref: Some("portfolio:red/entry:red".to_string()),
        }
    }

    #[test]
    fn maintenance_store_round_trips_records() {
        let root = std::env::temp_dir().join("swarm-operator-maintenance-store-roundtrip");
        let _ = std::fs::remove_dir_all(&root);
        let store = FileOperatorMaintenanceStore::open(&root).unwrap();
        let record = sample_record("maintenance:test:1", OperatorMaintenanceStatus::Applied);

        let stored = store.persist(&record).unwrap();
        let loaded = store.load(&stored.record.action_id).unwrap().unwrap();
        assert_eq!(loaded.record.action_id, "maintenance:test:1");
        assert_eq!(loaded.record.status, OperatorMaintenanceStatus::Applied);
    }

    #[test]
    fn maintenance_request_round_trips_through_json() {
        let request = OperatorMaintenanceRequest::PacketSetSplit {
            parent_packet_set_id: "packet-set:parent".to_string(),
            name: "split-red".to_string(),
            packet_ids: vec!["packet-1".to_string(), "packet-2".to_string()],
            reason: "split for review".to_string(),
        };

        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: OperatorMaintenanceRequest = serde_json::from_str(&encoded).unwrap();
        match decoded {
            OperatorMaintenanceRequest::PacketSetSplit {
                parent_packet_set_id,
                name,
                packet_ids,
                reason,
            } => {
                assert_eq!(parent_packet_set_id, "packet-set:parent");
                assert_eq!(name, "split-red");
                assert_eq!(packet_ids.len(), 2);
                assert_eq!(reason, "split for review");
            }
            other => panic!("unexpected request variant: {other:?}"),
        }
    }

    #[test]
    fn maintenance_status_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&OperatorMaintenanceStatus::Applied).unwrap(),
            "\"applied\""
        );
        assert_eq!(
            serde_json::to_string(&OperatorMaintenanceStatus::Blocked).unwrap(),
            "\"blocked\""
        );
        assert_eq!(
            serde_json::to_string(&OperatorMaintenanceStatus::Failed).unwrap(),
            "\"failed\""
        );
    }

    #[test]
    fn maintenance_store_filters_by_status() {
        let root = std::env::temp_dir().join("swarm-operator-maintenance-store-filter");
        let _ = std::fs::remove_dir_all(&root);
        let store = FileOperatorMaintenanceStore::open(&root).unwrap();
        store
            .persist(&sample_record(
                "maintenance:test:applied",
                OperatorMaintenanceStatus::Applied,
            ))
            .unwrap();
        store
            .persist(&sample_record(
                "maintenance:test:blocked",
                OperatorMaintenanceStatus::Blocked,
            ))
            .unwrap();

        let filtered = store
            .list(Some(OperatorMaintenanceStatus::Blocked))
            .unwrap();
        assert_eq!(filtered.total_count, 1);
        assert_eq!(filtered.actions[0].action_id, "maintenance:test:blocked");
    }

    #[test]
    fn maintenance_execution_lookup_returns_inner_lookup() {
        let root = std::env::temp_dir().join("swarm-operator-maintenance-store-execution");
        let _ = std::fs::remove_dir_all(&root);
        let store = FileOperatorMaintenanceStore::open(&root).unwrap();
        let lookup = store
            .persist(&sample_record(
                "maintenance:test:execution",
                OperatorMaintenanceStatus::Applied,
            ))
            .unwrap();

        let execution = OperatorMaintenanceExecution::Applied(lookup.clone());
        assert_eq!(execution.lookup().record.action_id, lookup.record.action_id);
    }
}
