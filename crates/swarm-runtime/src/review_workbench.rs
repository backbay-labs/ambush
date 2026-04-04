use crate::evidence::{
    EvidenceBundleLookup, EvidenceRelatedRef, EvidenceSubjectKind, EvidenceVerificationCheck,
    EvidenceVerificationLookup, EvidenceVerificationStatus, OperatorEvidenceReadService,
    PromotionEvidenceAttachment, PromotionEvidenceBlockingReason, PromotionEvidencePacketLookup,
    PromotionEvidenceRecommendation,
};
use crate::operator_http::OperatorSurfacePaths;
use crate::operator_maintenance::{
    OperatorMaintenanceError, OperatorMaintenanceRequest, OperatorMaintenanceService,
    OperatorMaintenanceStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Artifact kinds that can participate in one local review session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewArtifactRefKind {
    EvidenceBundle,
    EvidenceVerification,
    PromotionEvidencePacket,
    PromotionReview,
    CanaryRun,
    ProductionPromotion,
}

impl ReviewArtifactRefKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EvidenceBundle => "evidence_bundle",
            Self::EvidenceVerification => "evidence_verification",
            Self::PromotionEvidencePacket => "promotion_evidence_packet",
            Self::PromotionReview => "promotion_review",
            Self::CanaryRun => "canary_run",
            Self::ProductionPromotion => "production_promotion",
        }
    }
}

impl std::fmt::Display for ReviewArtifactRefKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ReviewArtifactRefKind {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "evidence_bundle" => Ok(Self::EvidenceBundle),
            "evidence_verification" => Ok(Self::EvidenceVerification),
            "promotion_evidence_packet" => Ok(Self::PromotionEvidencePacket),
            "promotion_review" => Ok(Self::PromotionReview),
            "canary_run" => Ok(Self::CanaryRun),
            "production_promotion" => Ok(Self::ProductionPromotion),
            _ => Err(()),
        }
    }
}

/// Stable evidence lanes compared in one cross-lane review session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewLane {
    GovernancePrep,
    Canary,
    Production,
}

impl ReviewLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GovernancePrep => "governance_prep",
            Self::Canary => "canary",
            Self::Production => "production",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::GovernancePrep => "Governance Prep",
            Self::Canary => "Canary",
            Self::Production => "Production",
        }
    }
}

impl std::fmt::Display for ReviewLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Aggregate view of one lane inside a resolved review session or export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewLaneSummary {
    pub lane: ReviewLane,
    pub artifact_count: usize,
    pub evidence_bundle_count: usize,
    pub verification_count: usize,
    pub promotion_packet_count: usize,
    pub latest_source_created_at_ms: Option<i64>,
    pub latest_verified_at_ms: Option<i64>,
    pub subject_refs: Vec<String>,
}

/// One unresolved cross-lane evidence or consistency gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewLaneGap {
    pub lane: Option<ReviewLane>,
    pub code: String,
    pub details: String,
    pub references: Vec<String>,
}

/// One stable artifact reference selected into a review session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewArtifactRef {
    pub kind: ReviewArtifactRefKind,
    pub id: String,
}

/// Create request for one durable review session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSessionCreateRequest {
    pub title: Option<String>,
    pub notes: Option<String>,
    pub artifact_refs: Vec<ReviewArtifactRef>,
}

/// Persisted review session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSessionReport {
    pub session_id: String,
    pub title: Option<String>,
    pub notes: Option<String>,
    pub created_at_ms: i64,
    pub artifact_refs: Vec<ReviewArtifactRef>,
}

/// Summary metadata for one persisted review session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSessionRecord {
    pub session_id: String,
    pub created_at_ms: i64,
    pub title: Option<String>,
    pub artifact_count: usize,
    pub evidence_bundle_count: usize,
    pub verification_count: usize,
    pub promotion_packet_count: usize,
    pub bundle_path: String,
}

impl ReviewSessionRecord {
    fn from_report(report: &ReviewSessionReport, bundle_path: String) -> Self {
        let mut evidence_bundle_count = 0usize;
        let mut verification_count = 0usize;
        let mut promotion_packet_count = 0usize;
        for artifact in &report.artifact_refs {
            match artifact.kind {
                ReviewArtifactRefKind::EvidenceBundle => evidence_bundle_count += 1,
                ReviewArtifactRefKind::EvidenceVerification => verification_count += 1,
                ReviewArtifactRefKind::PromotionEvidencePacket => promotion_packet_count += 1,
                ReviewArtifactRefKind::PromotionReview
                | ReviewArtifactRefKind::CanaryRun
                | ReviewArtifactRefKind::ProductionPromotion => {}
            }
        }
        Self {
            session_id: report.session_id.clone(),
            created_at_ms: report.created_at_ms,
            title: report.title.clone(),
            artifact_count: report.artifact_refs.len(),
            evidence_bundle_count,
            verification_count,
            promotion_packet_count,
            bundle_path,
        }
    }
}

/// Persisted review session loaded with metadata.
#[derive(Debug, Clone)]
pub struct ReviewSessionLookup {
    pub record: ReviewSessionRecord,
    pub report: ReviewSessionReport,
}

/// Operator-facing review session listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSessionList {
    pub total_count: usize,
    pub sessions: Vec<ReviewSessionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ReviewSessionIndex {
    entries: Vec<ReviewSessionRecord>,
}

/// One evidence bundle preserved in an exported review session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSessionExportBundle {
    pub bundle_id: String,
    pub subject_kind: EvidenceSubjectKind,
    pub subject_id: String,
    pub payload_sha256: String,
    pub signer_id: String,
    pub signer_key_id: String,
    pub latest_verification_id: Option<String>,
    pub latest_verification_status: Option<EvidenceVerificationStatus>,
    pub related_refs: Vec<EvidenceRelatedRef>,
}

/// One evidence verification preserved in an exported review session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSessionExportVerification {
    pub verification_id: String,
    pub bundle_id: String,
    pub subject_kind: EvidenceSubjectKind,
    pub subject_id: String,
    pub status: EvidenceVerificationStatus,
    pub signer_id: String,
    pub signer_key_id: String,
    pub checks: Vec<EvidenceVerificationCheck>,
}

/// One promotion evidence packet preserved in an exported review session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSessionExportPromotionPacket {
    pub packet_id: String,
    pub promotion_id: String,
    pub recommendation: PromotionEvidenceRecommendation,
    pub promoted_strategy_id: String,
    pub fallback_strategy_id: String,
    pub canary_run_id: String,
    pub verification_id: String,
    pub shadow_id: String,
    pub supporting_evidence: Vec<PromotionEvidenceAttachment>,
    pub blocking_reasons: Vec<PromotionEvidenceBlockingReason>,
}

/// Persisted export snapshot for one review session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSessionExport {
    pub export_id: String,
    pub session_id: String,
    pub created_at_ms: i64,
    pub title: Option<String>,
    pub notes: Option<String>,
    pub artifact_refs: Vec<ReviewArtifactRef>,
    #[serde(default)]
    pub lane_summaries: Vec<ReviewLaneSummary>,
    #[serde(default)]
    pub unresolved_gaps: Vec<ReviewLaneGap>,
    pub evidence_bundles: Vec<ReviewSessionExportBundle>,
    pub evidence_verifications: Vec<ReviewSessionExportVerification>,
    pub promotion_packets: Vec<ReviewSessionExportPromotionPacket>,
}

/// Summary metadata for one review-session export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSessionExportRecord {
    pub export_id: String,
    pub session_id: String,
    pub created_at_ms: i64,
    pub artifact_count: usize,
    pub bundle_path: String,
}

impl ReviewSessionExportRecord {
    fn from_export(export: &ReviewSessionExport, bundle_path: String) -> Self {
        Self {
            export_id: export.export_id.clone(),
            session_id: export.session_id.clone(),
            created_at_ms: export.created_at_ms,
            artifact_count: export.artifact_refs.len(),
            bundle_path,
        }
    }
}

/// Persisted export loaded with metadata.
#[derive(Debug, Clone)]
pub struct ReviewSessionExportLookup {
    pub record: ReviewSessionExportRecord,
    pub export: ReviewSessionExport,
}

/// Operator-facing review-session export listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSessionExportList {
    pub total_count: usize,
    pub session_id: Option<String>,
    pub exports: Vec<ReviewSessionExportRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ReviewSessionExportIndex {
    entries: Vec<ReviewSessionExportRecord>,
}

/// Final advisory state derived from one cross-lane review session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewPromotionReadinessRecommendation {
    ReadyForAdvisoryPromotionReview,
    Blocked,
}

impl ReviewPromotionReadinessRecommendation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyForAdvisoryPromotionReview => "ready_for_advisory_promotion_review",
            Self::Blocked => "blocked",
        }
    }
}

/// Persisted promotion-readiness artifact derived from one review session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSessionPromotionReadiness {
    pub readiness_id: String,
    pub session_id: String,
    pub created_at_ms: i64,
    pub lane_summaries: Vec<ReviewLaneSummary>,
    pub unresolved_gaps: Vec<ReviewLaneGap>,
    pub recommendation: ReviewPromotionReadinessRecommendation,
    pub advisory_only: bool,
}

/// Metadata surfaced for one persisted promotion-readiness artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSessionPromotionReadinessRecord {
    pub readiness_id: String,
    pub session_id: String,
    pub created_at_ms: i64,
    pub recommendation: ReviewPromotionReadinessRecommendation,
    pub gap_count: usize,
    pub bundle_path: String,
}

impl ReviewSessionPromotionReadinessRecord {
    fn from_report(report: &ReviewSessionPromotionReadiness, bundle_path: String) -> Self {
        Self {
            readiness_id: report.readiness_id.clone(),
            session_id: report.session_id.clone(),
            created_at_ms: report.created_at_ms,
            recommendation: report.recommendation,
            gap_count: report.unresolved_gaps.len(),
            bundle_path,
        }
    }
}

/// Persisted promotion-readiness artifact loaded with metadata.
#[derive(Debug, Clone)]
pub struct ReviewSessionPromotionReadinessLookup {
    pub record: ReviewSessionPromotionReadinessRecord,
    pub report: ReviewSessionPromotionReadiness,
}

/// Operator-facing readiness listing for one session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSessionPromotionReadinessList {
    pub total_count: usize,
    pub session_id: Option<String>,
    pub readiness_reports: Vec<ReviewSessionPromotionReadinessRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ReviewSessionPromotionReadinessIndex {
    entries: Vec<ReviewSessionPromotionReadinessRecord>,
}

/// One underlying maintenance action launched from a review-session handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSessionMaintenanceActionResult {
    pub bundle_id: String,
    pub action_id: String,
    pub status: OperatorMaintenanceStatus,
    pub verification_id: Option<String>,
}

/// Persisted review-session maintenance handoff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSessionMaintenanceHandoff {
    pub handoff_id: String,
    pub session_id: String,
    pub created_at_ms: i64,
    pub selected_artifact_refs: Vec<ReviewArtifactRef>,
    pub derived_bundle_ids: Vec<String>,
    pub expected_key_id: Option<String>,
    pub reason: String,
    pub status: OperatorMaintenanceStatus,
    pub summary: String,
    pub action_results: Vec<ReviewSessionMaintenanceActionResult>,
}

/// Summary metadata for one review-session maintenance handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSessionMaintenanceHandoffRecord {
    pub handoff_id: String,
    pub session_id: String,
    pub created_at_ms: i64,
    pub status: OperatorMaintenanceStatus,
    pub action_count: usize,
    pub bundle_path: String,
}

impl ReviewSessionMaintenanceHandoffRecord {
    fn from_handoff(handoff: &ReviewSessionMaintenanceHandoff, bundle_path: String) -> Self {
        Self {
            handoff_id: handoff.handoff_id.clone(),
            session_id: handoff.session_id.clone(),
            created_at_ms: handoff.created_at_ms,
            status: handoff.status,
            action_count: handoff.action_results.len(),
            bundle_path,
        }
    }
}

/// Persisted handoff loaded with metadata.
#[derive(Debug, Clone)]
pub struct ReviewSessionMaintenanceHandoffLookup {
    pub record: ReviewSessionMaintenanceHandoffRecord,
    pub handoff: ReviewSessionMaintenanceHandoff,
}

/// Operator-facing maintenance-handoff listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSessionMaintenanceHandoffList {
    pub total_count: usize,
    pub session_id: Option<String>,
    pub handoffs: Vec<ReviewSessionMaintenanceHandoffRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ReviewSessionMaintenanceHandoffIndex {
    entries: Vec<ReviewSessionMaintenanceHandoffRecord>,
}

/// Request to re-verify all evidence bundles implied by a review session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSessionReverifyRequest {
    pub session_id: String,
    pub selected_artifact_refs: Vec<ReviewArtifactRef>,
    pub expected_key_id: Option<String>,
    pub reason: String,
}

/// Resolved session view used by the HTML workbench.
#[derive(Debug, Clone)]
pub struct ReviewSessionResolved {
    pub session: ReviewSessionLookup,
    pub evidence_bundles: Vec<EvidenceBundleLookup>,
    pub evidence_verifications: Vec<EvidenceVerificationLookup>,
    pub promotion_packets: Vec<PromotionEvidencePacketLookup>,
    pub lane_summaries: Vec<ReviewLaneSummary>,
    pub unresolved_gaps: Vec<ReviewLaneGap>,
}

/// Errors raised while persisting review sessions.
#[derive(Debug, thiserror::Error)]
pub enum ReviewSessionStoreError {
    #[error("failed to read review-session store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write review-session store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse review-session store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised while persisting review-session exports.
#[derive(Debug, thiserror::Error)]
pub enum ReviewSessionExportStoreError {
    #[error("failed to read review-session export store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write review-session export store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse review-session export store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised while persisting review-session handoffs.
#[derive(Debug, thiserror::Error)]
pub enum ReviewSessionMaintenanceHandoffStoreError {
    #[error("failed to read review-session handoff store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write review-session handoff store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse review-session handoff store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised while persisting review-session promotion-readiness artifacts.
#[derive(Debug, thiserror::Error)]
pub enum ReviewSessionPromotionReadinessStoreError {
    #[error("failed to read review-session readiness store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write review-session readiness store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse review-session readiness store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised while assembling workbench sessions and handoffs.
#[derive(Debug, thiserror::Error)]
pub enum ReviewWorkbenchError {
    #[error(transparent)]
    Evidence(#[from] crate::evidence::EvidenceError),

    #[error(transparent)]
    Maintenance(#[from] OperatorMaintenanceError),

    #[error(transparent)]
    SessionStore(#[from] ReviewSessionStoreError),

    #[error(transparent)]
    ExportStore(#[from] ReviewSessionExportStoreError),

    #[error(transparent)]
    HandoffStore(#[from] ReviewSessionMaintenanceHandoffStoreError),

    #[error(transparent)]
    ReadinessStore(#[from] ReviewSessionPromotionReadinessStoreError),

    #[error("invalid review session request: {0}")]
    InvalidRequest(String),

    #[error("review session `{session_id}` was not found")]
    SessionNotFound { session_id: String },

    #[error("review session export `{export_id}` was not found")]
    ExportNotFound { export_id: String },

    #[error("review session handoff `{handoff_id}` was not found")]
    HandoffNotFound { handoff_id: String },

    #[error("review session readiness `{readiness_id}` was not found")]
    ReadinessNotFound { readiness_id: String },
}

/// File-backed review-session store.
#[derive(Debug, Clone)]
pub struct FileReviewSessionStore {
    root: PathBuf,
}

impl FileReviewSessionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReviewSessionStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ReviewSessionStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, session_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(session_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ReviewSessionIndex, ReviewSessionStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReviewSessionIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| ReviewSessionStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| ReviewSessionStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &ReviewSessionIndex) -> Result<(), ReviewSessionStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            ReviewSessionStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| ReviewSessionStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &ReviewSessionReport,
    ) -> Result<ReviewSessionLookup, ReviewSessionStoreError> {
        let path = self.report_path(&report.session_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            ReviewSessionStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| ReviewSessionStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = ReviewSessionRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.session_id != record.session_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(ReviewSessionLookup {
            record,
            report: report.clone(),
        })
    }

    pub fn load(
        &self,
        session_id: &str,
    ) -> Result<Option<ReviewSessionLookup>, ReviewSessionStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.session_id == session_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| ReviewSessionStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report =
            serde_json::from_str(&raw).map_err(|source| ReviewSessionStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(ReviewSessionLookup { record, report }))
    }

    pub fn list(&self) -> Result<ReviewSessionList, ReviewSessionStoreError> {
        let sessions = self.read_index()?.entries;
        Ok(ReviewSessionList {
            total_count: sessions.len(),
            sessions,
        })
    }
}

/// File-backed export store for review sessions.
#[derive(Debug, Clone)]
pub struct FileReviewSessionExportStore {
    root: PathBuf,
}

impl FileReviewSessionExportStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReviewSessionExportStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ReviewSessionExportStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, export_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(export_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ReviewSessionExportIndex, ReviewSessionExportStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReviewSessionExportIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| ReviewSessionExportStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| ReviewSessionExportStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &ReviewSessionExportIndex,
    ) -> Result<(), ReviewSessionExportStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            ReviewSessionExportStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| ReviewSessionExportStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        export: &ReviewSessionExport,
    ) -> Result<ReviewSessionExportLookup, ReviewSessionExportStoreError> {
        let path = self.report_path(&export.export_id);
        let raw = serde_json::to_string_pretty(export).map_err(|source| {
            ReviewSessionExportStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| ReviewSessionExportStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = ReviewSessionExportRecord::from_export(export, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.export_id != record.export_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(ReviewSessionExportLookup {
            record,
            export: export.clone(),
        })
    }

    pub fn load(
        &self,
        export_id: &str,
    ) -> Result<Option<ReviewSessionExportLookup>, ReviewSessionExportStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.export_id == export_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| ReviewSessionExportStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let export =
            serde_json::from_str(&raw).map_err(|source| ReviewSessionExportStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(ReviewSessionExportLookup { record, export }))
    }

    pub fn list(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewSessionExportList, ReviewSessionExportStoreError> {
        let mut exports = self.read_index()?.entries;
        if let Some(session_id) = session_id {
            exports.retain(|entry| entry.session_id == session_id);
        }
        Ok(ReviewSessionExportList {
            total_count: exports.len(),
            session_id: session_id.map(ToString::to_string),
            exports,
        })
    }
}

/// File-backed promotion-readiness store for review sessions.
#[derive(Debug, Clone)]
pub struct FileReviewSessionPromotionReadinessStore {
    root: PathBuf,
}

impl FileReviewSessionPromotionReadinessStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReviewSessionPromotionReadinessStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, readiness_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(readiness_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<ReviewSessionPromotionReadinessIndex, ReviewSessionPromotionReadinessStoreError>
    {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReviewSessionPromotionReadinessIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| ReviewSessionPromotionReadinessStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &ReviewSessionPromotionReadinessIndex,
    ) -> Result<(), ReviewSessionPromotionReadinessStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| ReviewSessionPromotionReadinessStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &ReviewSessionPromotionReadiness,
    ) -> Result<ReviewSessionPromotionReadinessLookup, ReviewSessionPromotionReadinessStoreError>
    {
        let path = self.report_path(&report.readiness_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Write {
                path: path.clone(),
                source,
            }
        })?;

        let mut index = self.read_index()?;
        let record =
            ReviewSessionPromotionReadinessRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.readiness_id != record.readiness_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(ReviewSessionPromotionReadinessLookup {
            record,
            report: report.clone(),
        })
    }

    pub fn load(
        &self,
        readiness_id: &str,
    ) -> Result<
        Option<ReviewSessionPromotionReadinessLookup>,
        ReviewSessionPromotionReadinessStoreError,
    > {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.readiness_id == readiness_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw).map_err(|source| {
            ReviewSessionPromotionReadinessStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        Ok(Some(ReviewSessionPromotionReadinessLookup {
            record,
            report,
        }))
    }

    pub fn list(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewSessionPromotionReadinessList, ReviewSessionPromotionReadinessStoreError>
    {
        let mut readiness_reports = self.read_index()?.entries;
        if let Some(session_id) = session_id {
            readiness_reports.retain(|entry| entry.session_id == session_id);
        }
        Ok(ReviewSessionPromotionReadinessList {
            total_count: readiness_reports.len(),
            session_id: session_id.map(ToString::to_string),
            readiness_reports,
        })
    }
}

/// File-backed maintenance-handoff store for review sessions.
#[derive(Debug, Clone)]
pub struct FileReviewSessionMaintenanceHandoffStore {
    root: PathBuf,
}

impl FileReviewSessionMaintenanceHandoffStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReviewSessionMaintenanceHandoffStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, handoff_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(handoff_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<ReviewSessionMaintenanceHandoffIndex, ReviewSessionMaintenanceHandoffStoreError>
    {
        let path = self.index_path();
        if !path.exists() {
            return Ok(ReviewSessionMaintenanceHandoffIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| ReviewSessionMaintenanceHandoffStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &ReviewSessionMaintenanceHandoffIndex,
    ) -> Result<(), ReviewSessionMaintenanceHandoffStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| ReviewSessionMaintenanceHandoffStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        handoff: &ReviewSessionMaintenanceHandoff,
    ) -> Result<ReviewSessionMaintenanceHandoffLookup, ReviewSessionMaintenanceHandoffStoreError>
    {
        let path = self.report_path(&handoff.handoff_id);
        let raw = serde_json::to_string_pretty(handoff).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Write {
                path: path.clone(),
                source,
            }
        })?;

        let mut index = self.read_index()?;
        let record = ReviewSessionMaintenanceHandoffRecord::from_handoff(
            handoff,
            path.display().to_string(),
        );
        index
            .entries
            .retain(|entry| entry.handoff_id != record.handoff_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(ReviewSessionMaintenanceHandoffLookup {
            record,
            handoff: handoff.clone(),
        })
    }

    pub fn load(
        &self,
        handoff_id: &str,
    ) -> Result<
        Option<ReviewSessionMaintenanceHandoffLookup>,
        ReviewSessionMaintenanceHandoffStoreError,
    > {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.handoff_id == handoff_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let handoff = serde_json::from_str(&raw).map_err(|source| {
            ReviewSessionMaintenanceHandoffStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        Ok(Some(ReviewSessionMaintenanceHandoffLookup {
            record,
            handoff,
        }))
    }

    pub fn list(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewSessionMaintenanceHandoffList, ReviewSessionMaintenanceHandoffStoreError>
    {
        let mut handoffs = self.read_index()?.entries;
        if let Some(session_id) = session_id {
            handoffs.retain(|entry| entry.session_id == session_id);
        }
        Ok(ReviewSessionMaintenanceHandoffList {
            total_count: handoffs.len(),
            session_id: session_id.map(ToString::to_string),
            handoffs,
        })
    }
}

/// Repo-owned workbench harness above signed evidence and maintenance audit flows.
#[derive(Debug, Clone)]
pub struct DefaultReviewWorkbenchHarness {
    evidence: OperatorEvidenceReadService,
    maintenance: OperatorMaintenanceService,
    session_store: FileReviewSessionStore,
    export_store: FileReviewSessionExportStore,
    readiness_store: FileReviewSessionPromotionReadinessStore,
    handoff_store: FileReviewSessionMaintenanceHandoffStore,
}

impl DefaultReviewWorkbenchHarness {
    pub fn from_paths(
        actor: impl Into<String>,
        paths: &OperatorSurfacePaths,
    ) -> Result<Self, ReviewWorkbenchError> {
        Ok(Self {
            evidence: OperatorEvidenceReadService::from_store_paths(
                &paths.evidence_results_dir,
                &paths.evidence_verification_results_dir,
                &paths.promotion_evidence_results_dir,
            )?,
            maintenance: OperatorMaintenanceService::from_paths(actor, paths)?,
            session_store: FileReviewSessionStore::open(&paths.review_session_results_dir)?,
            export_store: FileReviewSessionExportStore::open(
                &paths.review_session_export_results_dir,
            )?,
            readiness_store: FileReviewSessionPromotionReadinessStore::open(
                &paths.review_session_readiness_results_dir,
            )?,
            handoff_store: FileReviewSessionMaintenanceHandoffStore::open(
                &paths.review_session_handoff_results_dir,
            )?,
        })
    }

    pub fn create_session(
        &self,
        request: ReviewSessionCreateRequest,
    ) -> Result<ReviewSessionLookup, ReviewWorkbenchError> {
        let artifact_refs = normalize_artifact_refs(request.artifact_refs);
        if artifact_refs.is_empty() {
            return Err(ReviewWorkbenchError::InvalidRequest(
                "review sessions require at least one artifact ref".to_string(),
            ));
        }
        for artifact in &artifact_refs {
            self.ensure_artifact_exists(artifact)?;
        }
        let report = ReviewSessionReport {
            session_id: format!("review_session:{}", now_unix_nanos()),
            title: normalize_optional_text(request.title),
            notes: normalize_optional_text(request.notes),
            created_at_ms: now_ms(),
            artifact_refs,
        };
        self.session_store.persist(&report).map_err(Into::into)
    }

    pub fn load_session(
        &self,
        session_id: &str,
    ) -> Result<Option<ReviewSessionLookup>, ReviewWorkbenchError> {
        self.session_store.load(session_id).map_err(Into::into)
    }

    pub fn list_sessions(&self) -> Result<ReviewSessionList, ReviewWorkbenchError> {
        self.session_store.list().map_err(Into::into)
    }

    pub fn resolve_session(
        &self,
        session_id: &str,
    ) -> Result<ReviewSessionResolved, ReviewWorkbenchError> {
        let session = self.load_session(session_id)?.ok_or_else(|| {
            ReviewWorkbenchError::SessionNotFound {
                session_id: session_id.to_string(),
            }
        })?;
        self.resolve_lookup(session)
    }

    pub fn export_session(
        &self,
        session_id: &str,
    ) -> Result<ReviewSessionExportLookup, ReviewWorkbenchError> {
        let resolved = self.resolve_session(session_id)?;
        let export = ReviewSessionExport {
            export_id: format!("review_session_export:{}", now_unix_nanos()),
            session_id: resolved.session.report.session_id.clone(),
            created_at_ms: now_ms(),
            title: resolved.session.report.title.clone(),
            notes: resolved.session.report.notes.clone(),
            artifact_refs: resolved.session.report.artifact_refs.clone(),
            lane_summaries: resolved.lane_summaries.clone(),
            unresolved_gaps: resolved.unresolved_gaps.clone(),
            evidence_bundles: resolved
                .evidence_bundles
                .iter()
                .map(|lookup| ReviewSessionExportBundle {
                    bundle_id: lookup.record.bundle_id.clone(),
                    subject_kind: lookup.record.subject_kind,
                    subject_id: lookup.record.subject_id.clone(),
                    payload_sha256: lookup.record.payload_sha256.clone(),
                    signer_id: lookup.record.signer_id.clone(),
                    signer_key_id: lookup.record.signer_key_id.clone(),
                    latest_verification_id: lookup.record.latest_verification_id.clone(),
                    latest_verification_status: lookup.record.latest_verification_status,
                    related_refs: lookup.bundle.subject.related_refs.clone(),
                })
                .collect(),
            evidence_verifications: resolved
                .evidence_verifications
                .iter()
                .map(|lookup| ReviewSessionExportVerification {
                    verification_id: lookup.report.verification_id.clone(),
                    bundle_id: lookup.report.bundle_id.clone(),
                    subject_kind: lookup.report.subject_kind,
                    subject_id: lookup.report.subject_id.clone(),
                    status: lookup.report.status,
                    signer_id: lookup.report.signer_id.clone(),
                    signer_key_id: lookup.report.signer_key_id.clone(),
                    checks: lookup.report.checks.clone(),
                })
                .collect(),
            promotion_packets: resolved
                .promotion_packets
                .iter()
                .map(|lookup| ReviewSessionExportPromotionPacket {
                    packet_id: lookup.packet.packet_id.clone(),
                    promotion_id: lookup.packet.promotion_id.clone(),
                    recommendation: lookup.packet.recommendation,
                    promoted_strategy_id: lookup.packet.promoted_strategy_id.clone(),
                    fallback_strategy_id: lookup.packet.fallback_strategy_id.clone(),
                    canary_run_id: lookup.packet.canary_run_id.clone(),
                    verification_id: lookup.packet.verification_id.clone(),
                    shadow_id: lookup.packet.shadow_id.clone(),
                    supporting_evidence: lookup.packet.supporting_evidence.clone(),
                    blocking_reasons: lookup.packet.blocking_reasons.clone(),
                })
                .collect(),
        };
        self.export_store.persist(&export).map_err(Into::into)
    }

    pub fn load_export(
        &self,
        export_id: &str,
    ) -> Result<Option<ReviewSessionExportLookup>, ReviewWorkbenchError> {
        self.export_store.load(export_id).map_err(Into::into)
    }

    pub fn list_exports(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewSessionExportList, ReviewWorkbenchError> {
        self.export_store.list(session_id).map_err(Into::into)
    }

    pub fn create_promotion_readiness_review(
        &self,
        session_id: &str,
    ) -> Result<ReviewSessionPromotionReadinessLookup, ReviewWorkbenchError> {
        let resolved = self.resolve_session(session_id)?;
        let report = ReviewSessionPromotionReadiness {
            readiness_id: format!("review_session_readiness:{}", now_unix_nanos()),
            session_id: resolved.session.report.session_id.clone(),
            created_at_ms: now_ms(),
            lane_summaries: resolved.lane_summaries.clone(),
            unresolved_gaps: resolved.unresolved_gaps.clone(),
            recommendation: promotion_readiness_recommendation(&resolved),
            advisory_only: true,
        };
        self.readiness_store.persist(&report).map_err(Into::into)
    }

    pub fn load_promotion_readiness(
        &self,
        readiness_id: &str,
    ) -> Result<Option<ReviewSessionPromotionReadinessLookup>, ReviewWorkbenchError> {
        self.readiness_store.load(readiness_id).map_err(Into::into)
    }

    pub fn list_promotion_readiness(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewSessionPromotionReadinessList, ReviewWorkbenchError> {
        self.readiness_store.list(session_id).map_err(Into::into)
    }

    pub fn create_reverify_handoff(
        &self,
        request: ReviewSessionReverifyRequest,
    ) -> Result<ReviewSessionMaintenanceHandoffLookup, ReviewWorkbenchError> {
        let resolved = self.resolve_session(&request.session_id)?;
        let selected_artifact_refs = if request.selected_artifact_refs.is_empty() {
            resolved.session.report.artifact_refs.clone()
        } else {
            normalize_artifact_refs(request.selected_artifact_refs)
        };
        if normalize_optional_text(Some(request.reason.clone())).is_none() {
            return Err(ReviewWorkbenchError::InvalidRequest(
                "review-driven maintenance handoffs require a non-empty reason".to_string(),
            ));
        }
        ensure_selected_refs_belong_to_session(
            &resolved.session.report.artifact_refs,
            &selected_artifact_refs,
        )?;
        let bundle_ids = derive_bundle_ids(&resolved, &selected_artifact_refs)?;
        if bundle_ids.is_empty() {
            return Err(ReviewWorkbenchError::InvalidRequest(
                "selected artifacts did not resolve to any evidence bundles".to_string(),
            ));
        }

        let mut action_results = Vec::new();
        for bundle_id in &bundle_ids {
            let execution =
                self.maintenance
                    .execute(OperatorMaintenanceRequest::ReverifyEvidenceBundle {
                        bundle_id: bundle_id.clone(),
                        expected_key_id: request.expected_key_id.clone(),
                        reason: request.reason.clone(),
                    })?;
            let lookup = execution.lookup();
            let verification_id = lookup
                .record
                .artifacts
                .iter()
                .find(|artifact| artifact.kind == "evidence_verification")
                .map(|artifact| artifact.id.clone());
            action_results.push(ReviewSessionMaintenanceActionResult {
                bundle_id: bundle_id.clone(),
                action_id: lookup.record.action_id.clone(),
                status: lookup.record.status,
                verification_id,
            });
        }

        let applied_count = action_results
            .iter()
            .filter(|result| result.status == OperatorMaintenanceStatus::Applied)
            .count();
        let blocked_count = action_results
            .iter()
            .filter(|result| result.status == OperatorMaintenanceStatus::Blocked)
            .count();
        let failed_count = action_results
            .iter()
            .filter(|result| result.status == OperatorMaintenanceStatus::Failed)
            .count();
        let status = if failed_count > 0 {
            OperatorMaintenanceStatus::Failed
        } else if blocked_count > 0 {
            OperatorMaintenanceStatus::Blocked
        } else {
            OperatorMaintenanceStatus::Applied
        };
        let summary = format!(
            "re-verified {} evidence bundle(s) from review session `{}` (applied={}, blocked={}, failed={})",
            bundle_ids.len(),
            resolved.session.report.session_id,
            applied_count,
            blocked_count,
            failed_count
        );
        let handoff = ReviewSessionMaintenanceHandoff {
            handoff_id: format!("review_handoff:{}", now_unix_nanos()),
            session_id: resolved.session.report.session_id.clone(),
            created_at_ms: now_ms(),
            selected_artifact_refs,
            derived_bundle_ids: bundle_ids,
            expected_key_id: request.expected_key_id,
            reason: request.reason,
            status,
            summary,
            action_results,
        };
        self.handoff_store.persist(&handoff).map_err(Into::into)
    }

    pub fn load_handoff(
        &self,
        handoff_id: &str,
    ) -> Result<Option<ReviewSessionMaintenanceHandoffLookup>, ReviewWorkbenchError> {
        self.handoff_store.load(handoff_id).map_err(Into::into)
    }

    pub fn list_handoffs(
        &self,
        session_id: Option<&str>,
    ) -> Result<ReviewSessionMaintenanceHandoffList, ReviewWorkbenchError> {
        self.handoff_store.list(session_id).map_err(Into::into)
    }

    fn resolve_lookup(
        &self,
        session: ReviewSessionLookup,
    ) -> Result<ReviewSessionResolved, ReviewWorkbenchError> {
        let mut evidence_bundles = Vec::new();
        let mut evidence_verifications = Vec::new();
        let mut promotion_packets = Vec::new();

        for artifact in &session.report.artifact_refs {
            match artifact.kind {
                ReviewArtifactRefKind::EvidenceBundle => {
                    let lookup = self.evidence.load_bundle(&artifact.id)?.ok_or_else(|| {
                        ReviewWorkbenchError::InvalidRequest(format!(
                            "evidence bundle `{}` no longer exists",
                            artifact.id
                        ))
                    })?;
                    push_unique_bundle(&mut evidence_bundles, lookup);
                }
                ReviewArtifactRefKind::EvidenceVerification => {
                    let lookup =
                        self.evidence
                            .load_verification(&artifact.id)?
                            .ok_or_else(|| {
                                ReviewWorkbenchError::InvalidRequest(format!(
                                    "evidence verification `{}` no longer exists",
                                    artifact.id
                                ))
                            })?;
                    if let Some(bundle_lookup) =
                        self.evidence.load_bundle(&lookup.report.bundle_id)?
                    {
                        push_unique_bundle(&mut evidence_bundles, bundle_lookup);
                    }
                    push_unique_verification(&mut evidence_verifications, lookup);
                }
                ReviewArtifactRefKind::PromotionEvidencePacket => {
                    let lookup = self
                        .evidence
                        .load_promotion_evidence_packet(&artifact.id)?
                        .ok_or_else(|| {
                            ReviewWorkbenchError::InvalidRequest(format!(
                                "promotion evidence packet `{}` no longer exists",
                                artifact.id
                            ))
                        })?;
                    push_unique_packet(&mut promotion_packets, lookup);
                }
                ReviewArtifactRefKind::PromotionReview => {
                    let bundle_lookup = self
                        .evidence
                        .find_bundle_by_subject(EvidenceSubjectKind::PromotionReview, &artifact.id)?
                        .ok_or_else(|| {
                            ReviewWorkbenchError::InvalidRequest(format!(
                                "promotion review `{}` does not have exported evidence",
                                artifact.id
                            ))
                        })?;
                    attach_bundle_dependencies(
                        &self.evidence,
                        &bundle_lookup,
                        &mut evidence_bundles,
                        &mut evidence_verifications,
                    )?;
                }
                ReviewArtifactRefKind::CanaryRun => {
                    let bundle_lookup = self
                        .evidence
                        .find_bundle_by_subject(EvidenceSubjectKind::CanaryRun, &artifact.id)?
                        .ok_or_else(|| {
                            ReviewWorkbenchError::InvalidRequest(format!(
                                "canary run `{}` does not have exported evidence",
                                artifact.id
                            ))
                        })?;
                    attach_bundle_dependencies(
                        &self.evidence,
                        &bundle_lookup,
                        &mut evidence_bundles,
                        &mut evidence_verifications,
                    )?;
                }
                ReviewArtifactRefKind::ProductionPromotion => {
                    let bundle_lookup = self
                        .evidence
                        .find_bundle_by_subject(
                            EvidenceSubjectKind::ProductionPromotion,
                            &artifact.id,
                        )?
                        .ok_or_else(|| {
                            ReviewWorkbenchError::InvalidRequest(format!(
                                "production promotion `{}` does not have exported evidence",
                                artifact.id
                            ))
                        })?;
                    attach_bundle_dependencies(
                        &self.evidence,
                        &bundle_lookup,
                        &mut evidence_bundles,
                        &mut evidence_verifications,
                    )?;
                    if let Some(packet_lookup) = self.evidence.load_promotion_evidence_packet(
                        &format!("promotion_evidence:{}", artifact.id),
                    )? {
                        push_unique_packet(&mut promotion_packets, packet_lookup);
                    }
                }
            }
        }

        let lane_summaries = build_lane_summaries(
            &evidence_bundles,
            &evidence_verifications,
            &promotion_packets,
        );
        let unresolved_gaps =
            collect_lane_gaps(&lane_summaries, &evidence_bundles, &promotion_packets);

        Ok(ReviewSessionResolved {
            session,
            evidence_bundles,
            evidence_verifications,
            promotion_packets,
            lane_summaries,
            unresolved_gaps,
        })
    }

    fn ensure_artifact_exists(
        &self,
        artifact: &ReviewArtifactRef,
    ) -> Result<(), ReviewWorkbenchError> {
        let exists = match artifact.kind {
            ReviewArtifactRefKind::EvidenceBundle => {
                self.evidence.load_bundle(&artifact.id)?.is_some()
            }
            ReviewArtifactRefKind::EvidenceVerification => {
                self.evidence.load_verification(&artifact.id)?.is_some()
            }
            ReviewArtifactRefKind::PromotionEvidencePacket => self
                .evidence
                .load_promotion_evidence_packet(&artifact.id)?
                .is_some(),
            ReviewArtifactRefKind::PromotionReview => self
                .evidence
                .find_bundle_by_subject(EvidenceSubjectKind::PromotionReview, &artifact.id)?
                .is_some(),
            ReviewArtifactRefKind::CanaryRun => self
                .evidence
                .find_bundle_by_subject(EvidenceSubjectKind::CanaryRun, &artifact.id)?
                .is_some(),
            ReviewArtifactRefKind::ProductionPromotion => self
                .evidence
                .find_bundle_by_subject(EvidenceSubjectKind::ProductionPromotion, &artifact.id)?
                .is_some(),
        };
        if exists {
            Ok(())
        } else {
            Err(ReviewWorkbenchError::InvalidRequest(format!(
                "{} `{}` was not found",
                artifact.kind, artifact.id
            )))
        }
    }
}

pub fn render_review_session_list(list: &ReviewSessionList) -> String {
    let mut lines = vec![
        "Swarm Team Six Review Sessions".to_string(),
        format!("Total: {}", list.total_count),
    ];
    for session in &list.sessions {
        lines.push(format!(
            "- {} | title={} | artifacts={} | bundles={} | verifications={} | packets={}",
            session.session_id,
            session.title.as_deref().unwrap_or("untitled"),
            session.artifact_count,
            session.evidence_bundle_count,
            session.verification_count,
            session.promotion_packet_count
        ));
    }
    lines.join("\n")
}

pub fn render_review_session(resolved: &ReviewSessionResolved) -> String {
    let mut lines = vec![
        "Swarm Team Six Review Session".to_string(),
        format!("Session ID: {}", resolved.session.report.session_id),
        format!(
            "Title: {}",
            resolved
                .session
                .report
                .title
                .as_deref()
                .unwrap_or("untitled")
        ),
        format!("Artifacts: {}", resolved.session.report.artifact_refs.len()),
        format!("Evidence bundles: {}", resolved.evidence_bundles.len()),
        format!(
            "Evidence verifications: {}",
            resolved.evidence_verifications.len()
        ),
        format!("Promotion packets: {}", resolved.promotion_packets.len()),
        format!("Cross-lane summaries: {}", resolved.lane_summaries.len()),
        format!("Unresolved gaps: {}", resolved.unresolved_gaps.len()),
    ];
    if let Some(notes) = resolved.session.report.notes.as_deref() {
        lines.push(format!("Notes: {}", notes));
    }
    if !resolved.lane_summaries.is_empty() {
        lines.push("Lane summaries:".to_string());
        for summary in &resolved.lane_summaries {
            lines.push(format!(
                "- {} | artifacts={} | bundles={} | verifications={} | packets={} | refs={}",
                summary.lane.title(),
                summary.artifact_count,
                summary.evidence_bundle_count,
                summary.verification_count,
                summary.promotion_packet_count,
                summary.subject_refs.len()
            ));
        }
    }
    if !resolved.unresolved_gaps.is_empty() {
        lines.push("Gaps:".to_string());
        for gap in &resolved.unresolved_gaps {
            lines.push(format!(
                "- {}:{} | {}",
                gap.lane.map(ReviewLane::as_str).unwrap_or("cross_lane"),
                gap.code,
                gap.details
            ));
        }
    }
    lines.join("\n")
}

pub fn render_review_session_export(export: &ReviewSessionExport) -> String {
    let mut lines = vec![
        "Swarm Team Six Review Session Export".to_string(),
        format!("Export ID: {}", export.export_id),
        format!("Session ID: {}", export.session_id),
        format!("Artifacts: {}", export.artifact_refs.len()),
        format!("Evidence bundles: {}", export.evidence_bundles.len()),
        format!(
            "Evidence verifications: {}",
            export.evidence_verifications.len()
        ),
        format!("Promotion packets: {}", export.promotion_packets.len()),
        format!("Lane summaries: {}", export.lane_summaries.len()),
        format!("Unresolved gaps: {}", export.unresolved_gaps.len()),
    ];
    for summary in &export.lane_summaries {
        lines.push(format!(
            "- {} | artifacts={} | bundles={} | verifications={} | packets={}",
            summary.lane.title(),
            summary.artifact_count,
            summary.evidence_bundle_count,
            summary.verification_count,
            summary.promotion_packet_count
        ));
    }
    lines.join("\n")
}

pub fn render_review_session_handoff(handoff: &ReviewSessionMaintenanceHandoff) -> String {
    let mut lines = vec![
        "Swarm Team Six Review Session Maintenance Handoff".to_string(),
        format!("Handoff ID: {}", handoff.handoff_id),
        format!("Session ID: {}", handoff.session_id),
        format!("Status: {}", maintenance_status_label(handoff.status)),
        format!("Selected refs: {}", handoff.selected_artifact_refs.len()),
        format!("Derived bundle ids: {}", handoff.derived_bundle_ids.len()),
    ];
    for result in &handoff.action_results {
        lines.push(format!(
            "- bundle={} | action={} | status={} | verification={}",
            result.bundle_id,
            result.action_id,
            maintenance_status_label(result.status),
            result.verification_id.as_deref().unwrap_or("none")
        ));
    }
    lines.join("\n")
}

pub fn render_review_session_promotion_readiness(
    readiness: &ReviewSessionPromotionReadiness,
) -> String {
    let mut lines = vec![
        "Swarm Team Six Promotion Readiness Review".to_string(),
        format!("Readiness ID: {}", readiness.readiness_id),
        format!("Session ID: {}", readiness.session_id),
        format!("Recommendation: {}", readiness.recommendation.as_str()),
        format!("Lane summaries: {}", readiness.lane_summaries.len()),
        format!("Unresolved gaps: {}", readiness.unresolved_gaps.len()),
        format!("Advisory only: {}", readiness.advisory_only),
    ];
    for summary in &readiness.lane_summaries {
        lines.push(format!(
            "- {} | artifacts={} | bundles={} | verifications={} | packets={}",
            summary.lane.title(),
            summary.artifact_count,
            summary.evidence_bundle_count,
            summary.verification_count,
            summary.promotion_packet_count
        ));
    }
    if !readiness.unresolved_gaps.is_empty() {
        lines.push("Blocking gaps:".to_string());
        for gap in &readiness.unresolved_gaps {
            lines.push(format!(
                "- {}:{} | {}",
                gap.lane.map(ReviewLane::as_str).unwrap_or("cross_lane"),
                gap.code,
                gap.details
            ));
        }
    }
    lines.join("\n")
}

fn normalize_artifact_refs(artifact_refs: Vec<ReviewArtifactRef>) -> Vec<ReviewArtifactRef> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::new();
    for artifact in artifact_refs {
        let id = artifact.id.trim();
        if id.is_empty() {
            continue;
        }
        let key = format!("{}:{}", artifact.kind.as_str(), id);
        if seen.insert(key) {
            normalized.push(ReviewArtifactRef {
                kind: artifact.kind,
                id: id.to_string(),
            });
        }
    }
    normalized
}

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn ensure_selected_refs_belong_to_session(
    session_refs: &[ReviewArtifactRef],
    selected_refs: &[ReviewArtifactRef],
) -> Result<(), ReviewWorkbenchError> {
    let allowed = session_refs
        .iter()
        .map(|artifact| format!("{}:{}", artifact.kind.as_str(), artifact.id))
        .collect::<BTreeSet<_>>();
    for artifact in selected_refs {
        let key = format!("{}:{}", artifact.kind.as_str(), artifact.id);
        if !allowed.contains(&key) {
            return Err(ReviewWorkbenchError::InvalidRequest(format!(
                "selected artifact `{}` does not belong to the review session",
                key
            )));
        }
    }
    Ok(())
}

fn derive_bundle_ids(
    resolved: &ReviewSessionResolved,
    selected_refs: &[ReviewArtifactRef],
) -> Result<Vec<String>, ReviewWorkbenchError> {
    let mut bundle_ids = BTreeSet::new();
    for artifact in selected_refs {
        match artifact.kind {
            ReviewArtifactRefKind::EvidenceBundle => {
                bundle_ids.insert(artifact.id.clone());
            }
            ReviewArtifactRefKind::EvidenceVerification => {
                let lookup = resolved
                    .evidence_verifications
                    .iter()
                    .find(|lookup| lookup.report.verification_id == artifact.id)
                    .ok_or_else(|| {
                        ReviewWorkbenchError::InvalidRequest(format!(
                            "verification `{}` is not available in the review session",
                            artifact.id
                        ))
                    })?;
                bundle_ids.insert(lookup.report.bundle_id.clone());
            }
            ReviewArtifactRefKind::PromotionEvidencePacket => {
                let lookup = resolved
                    .promotion_packets
                    .iter()
                    .find(|lookup| lookup.packet.packet_id == artifact.id)
                    .ok_or_else(|| {
                        ReviewWorkbenchError::InvalidRequest(format!(
                            "promotion evidence packet `{}` is not available in the review session",
                            artifact.id
                        ))
                    })?;
                for attachment in &lookup.packet.supporting_evidence {
                    if let Some(bundle_id) = attachment.bundle_id.as_ref() {
                        bundle_ids.insert(bundle_id.clone());
                    }
                }
            }
            ReviewArtifactRefKind::PromotionReview => {
                let bundle_lookup = resolved
                    .evidence_bundles
                    .iter()
                    .find(|lookup| {
                        lookup.record.subject_kind == EvidenceSubjectKind::PromotionReview
                            && lookup.record.subject_id == artifact.id
                    })
                    .ok_or_else(|| {
                        ReviewWorkbenchError::InvalidRequest(format!(
                            "promotion review `{}` is not available in the review session",
                            artifact.id
                        ))
                    })?;
                bundle_ids.insert(bundle_lookup.record.bundle_id.clone());
            }
            ReviewArtifactRefKind::CanaryRun => {
                let bundle_lookup = resolved
                    .evidence_bundles
                    .iter()
                    .find(|lookup| {
                        lookup.record.subject_kind == EvidenceSubjectKind::CanaryRun
                            && lookup.record.subject_id == artifact.id
                    })
                    .ok_or_else(|| {
                        ReviewWorkbenchError::InvalidRequest(format!(
                            "canary run `{}` is not available in the review session",
                            artifact.id
                        ))
                    })?;
                bundle_ids.insert(bundle_lookup.record.bundle_id.clone());
            }
            ReviewArtifactRefKind::ProductionPromotion => {
                let bundle_lookup = resolved
                    .evidence_bundles
                    .iter()
                    .find(|lookup| {
                        lookup.record.subject_kind == EvidenceSubjectKind::ProductionPromotion
                            && lookup.record.subject_id == artifact.id
                    })
                    .ok_or_else(|| {
                        ReviewWorkbenchError::InvalidRequest(format!(
                            "production promotion `{}` is not available in the review session",
                            artifact.id
                        ))
                    })?;
                bundle_ids.insert(bundle_lookup.record.bundle_id.clone());
            }
        }
    }
    Ok(bundle_ids.into_iter().collect())
}

fn push_unique_bundle(target: &mut Vec<EvidenceBundleLookup>, lookup: EvidenceBundleLookup) {
    if !target
        .iter()
        .any(|existing| existing.record.bundle_id == lookup.record.bundle_id)
    {
        target.push(lookup);
    }
}

fn push_unique_verification(
    target: &mut Vec<EvidenceVerificationLookup>,
    lookup: EvidenceVerificationLookup,
) {
    if !target
        .iter()
        .any(|existing| existing.report.verification_id == lookup.report.verification_id)
    {
        target.push(lookup);
    }
}

fn push_unique_packet(
    target: &mut Vec<PromotionEvidencePacketLookup>,
    lookup: PromotionEvidencePacketLookup,
) {
    if !target
        .iter()
        .any(|existing| existing.packet.packet_id == lookup.packet.packet_id)
    {
        target.push(lookup);
    }
}

fn attach_bundle_dependencies(
    evidence: &OperatorEvidenceReadService,
    bundle_lookup: &EvidenceBundleLookup,
    evidence_bundles: &mut Vec<EvidenceBundleLookup>,
    evidence_verifications: &mut Vec<EvidenceVerificationLookup>,
) -> Result<(), ReviewWorkbenchError> {
    push_unique_bundle(evidence_bundles, bundle_lookup.clone());
    if let Some(verification_id) = bundle_lookup.record.latest_verification_id.as_deref()
        && let Some(verification_lookup) = evidence.load_verification(verification_id)?
    {
        push_unique_verification(evidence_verifications, verification_lookup);
    }
    Ok(())
}

fn classify_subject_lane(subject_kind: EvidenceSubjectKind) -> Option<ReviewLane> {
    match subject_kind {
        EvidenceSubjectKind::PromotionReview
        | EvidenceSubjectKind::DetectorVerification
        | EvidenceSubjectKind::StrategyShadow => Some(ReviewLane::GovernancePrep),
        EvidenceSubjectKind::CanaryRun => Some(ReviewLane::Canary),
        EvidenceSubjectKind::ProductionPromotion => Some(ReviewLane::Production),
        _ => None,
    }
}

fn build_lane_summaries(
    evidence_bundles: &[EvidenceBundleLookup],
    evidence_verifications: &[EvidenceVerificationLookup],
    promotion_packets: &[PromotionEvidencePacketLookup],
) -> Vec<ReviewLaneSummary> {
    let mut by_lane = std::collections::BTreeMap::new();
    for lane in [
        ReviewLane::GovernancePrep,
        ReviewLane::Canary,
        ReviewLane::Production,
    ] {
        by_lane.insert(
            lane,
            ReviewLaneSummary {
                lane,
                artifact_count: 0,
                evidence_bundle_count: 0,
                verification_count: 0,
                promotion_packet_count: 0,
                latest_source_created_at_ms: None,
                latest_verified_at_ms: None,
                subject_refs: Vec::new(),
            },
        );
    }

    for bundle in evidence_bundles {
        if let Some(lane) = classify_subject_lane(bundle.record.subject_kind) {
            let summary = by_lane.get_mut(&lane).expect("lane summary exists");
            summary.artifact_count += 1;
            summary.evidence_bundle_count += 1;
            summary.latest_source_created_at_ms = Some(
                summary
                    .latest_source_created_at_ms
                    .map_or(bundle.record.source_created_at_ms, |current| {
                        current.max(bundle.record.source_created_at_ms)
                    }),
            );
            let subject_ref = format!(
                "{}:{}",
                bundle.record.subject_kind.as_str(),
                bundle.record.subject_id
            );
            if !summary.subject_refs.contains(&subject_ref) {
                summary.subject_refs.push(subject_ref);
            }
        }
    }

    for verification in evidence_verifications {
        if let Some(lane) = classify_subject_lane(verification.report.subject_kind) {
            let summary = by_lane.get_mut(&lane).expect("lane summary exists");
            summary.artifact_count += 1;
            summary.verification_count += 1;
            summary.latest_verified_at_ms = Some(
                summary
                    .latest_verified_at_ms
                    .map_or(verification.report.verified_at_ms, |current| {
                        current.max(verification.report.verified_at_ms)
                    }),
            );
        }
    }

    for packet in promotion_packets {
        let summary = by_lane
            .get_mut(&ReviewLane::Production)
            .expect("production summary exists");
        summary.artifact_count += 1;
        summary.promotion_packet_count += 1;
        let subject_ref = format!("promotion_evidence_packet:{}", packet.packet.promotion_id);
        if !summary.subject_refs.contains(&subject_ref) {
            summary.subject_refs.push(subject_ref);
        }
    }

    by_lane.into_values().collect()
}

fn collect_lane_gaps(
    lane_summaries: &[ReviewLaneSummary],
    evidence_bundles: &[EvidenceBundleLookup],
    promotion_packets: &[PromotionEvidencePacketLookup],
) -> Vec<ReviewLaneGap> {
    let mut gaps = Vec::new();
    for lane in [
        ReviewLane::GovernancePrep,
        ReviewLane::Canary,
        ReviewLane::Production,
    ] {
        let summary = lane_summaries
            .iter()
            .find(|summary| summary.lane == lane)
            .expect("lane summary exists");
        if summary.artifact_count == 0 {
            gaps.push(ReviewLaneGap {
                lane: Some(lane),
                code: "lane_missing".to_string(),
                details: format!(
                    "{} lane evidence is missing from the review session",
                    lane.title()
                ),
                references: Vec::new(),
            });
        }
    }

    for bundle in evidence_bundles {
        if let Some(lane) = classify_subject_lane(bundle.record.subject_kind)
            && bundle.record.latest_verification_status != Some(EvidenceVerificationStatus::Passed)
        {
            gaps.push(ReviewLaneGap {
                lane: Some(lane),
                code: "bundle_unverified".to_string(),
                details: format!(
                    "{} evidence `{}` is missing a passing verification result",
                    lane.title(),
                    bundle.record.bundle_id
                ),
                references: vec![bundle.record.bundle_id.clone()],
            });
        }
    }

    for packet in promotion_packets {
        for reason in &packet.packet.blocking_reasons {
            gaps.push(ReviewLaneGap {
                lane: Some(ReviewLane::Production),
                code: reason.name.clone(),
                details: reason.details.clone(),
                references: reason.references.clone(),
            });
        }
    }

    if promotion_packets.is_empty()
        && evidence_bundles
            .iter()
            .any(|bundle| bundle.record.subject_kind == EvidenceSubjectKind::ProductionPromotion)
    {
        gaps.push(ReviewLaneGap {
            lane: Some(ReviewLane::Production),
            code: "promotion_evidence_packet_missing".to_string(),
            details:
                "production lane is present but no promotion evidence packet was included or derived"
                    .to_string(),
            references: Vec::new(),
        });
    }

    gaps
}

fn promotion_readiness_recommendation(
    resolved: &ReviewSessionResolved,
) -> ReviewPromotionReadinessRecommendation {
    let has_all_lanes = [
        ReviewLane::GovernancePrep,
        ReviewLane::Canary,
        ReviewLane::Production,
    ]
    .iter()
    .all(|lane| {
        resolved
            .lane_summaries
            .iter()
            .find(|summary| &summary.lane == lane)
            .map(|summary| summary.artifact_count > 0)
            .unwrap_or(false)
    });
    if has_all_lanes && resolved.unresolved_gaps.is_empty() {
        ReviewPromotionReadinessRecommendation::ReadyForAdvisoryPromotionReview
    } else {
        ReviewPromotionReadinessRecommendation::Blocked
    }
}

fn maintenance_status_label(status: OperatorMaintenanceStatus) -> &'static str {
    match status {
        OperatorMaintenanceStatus::Applied => "applied",
        OperatorMaintenanceStatus::Blocked => "blocked",
        OperatorMaintenanceStatus::Failed => "failed",
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after UNIX_EPOCH")
        .as_millis() as i64
}

fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after UNIX_EPOCH")
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
