use crate::evidence::{
    EvidenceBundleLookup, EvidenceRelatedRef, EvidenceSignature, EvidenceSubjectKind,
    EvidenceVerificationCheck, EvidenceVerificationLookup, EvidenceVerificationStatus,
    PromotionEvidenceAttachment, PromotionEvidenceBlockingReason, PromotionEvidencePacketLookup,
    PromotionEvidenceRecommendation,
};
use crate::operator_maintenance::{OperatorMaintenanceError, OperatorMaintenanceStatus};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use swarm_crypto::CryptoError;

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
    pub(super) fn from_report(report: &ReviewSessionReport, bundle_path: String) -> Self {
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
pub(super) struct ReviewSessionIndex {
    pub(super) entries: Vec<ReviewSessionRecord>,
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
    pub(super) fn from_export(export: &ReviewSessionExport, bundle_path: String) -> Self {
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
pub(super) struct ReviewSessionExportIndex {
    pub(super) entries: Vec<ReviewSessionExportRecord>,
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
    pub(super) fn from_report(
        report: &ReviewSessionPromotionReadiness,
        bundle_path: String,
    ) -> Self {
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
pub(super) struct ReviewSessionPromotionReadinessIndex {
    pub(super) entries: Vec<ReviewSessionPromotionReadinessRecord>,
}

/// Persisted source kinds supported by signed portable review capsules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewCapsuleSourceKind {
    SessionExport,
    PromotionReadiness,
}

impl ReviewCapsuleSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionExport => "session_export",
            Self::PromotionReadiness => "promotion_readiness",
        }
    }
}

impl std::fmt::Display for ReviewCapsuleSourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum ReviewCapsulePayload {
    SessionExport(ReviewSessionExport),
    PromotionReadiness(ReviewCapsuleReadinessPayload),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ReviewCapsuleReadinessPayload {
    pub(super) readiness: ReviewSessionPromotionReadiness,
    pub(super) title: Option<String>,
    pub(super) notes: Option<String>,
    pub(super) artifact_refs: Vec<ReviewArtifactRef>,
    pub(super) related_refs: Vec<EvidenceRelatedRef>,
}

#[derive(Debug, Clone)]
pub(super) struct ReviewCapsuleBuildRequest {
    pub(super) session_id: String,
    pub(super) title: Option<String>,
    pub(super) notes: Option<String>,
    pub(super) source_kind: ReviewCapsuleSourceKind,
    pub(super) source_id: String,
    pub(super) artifact_refs: Vec<ReviewArtifactRef>,
    pub(super) lane_summaries: Vec<ReviewLaneSummary>,
    pub(super) unresolved_gaps: Vec<ReviewLaneGap>,
    pub(super) related_refs: Vec<EvidenceRelatedRef>,
    pub(super) payload: ReviewCapsulePayload,
}

/// Signed portable review capsule for external inspection across trust boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewCapsule {
    pub capsule_id: String,
    pub schema_version: String,
    pub created_at_ms: i64,
    pub session_id: String,
    pub title: Option<String>,
    pub notes: Option<String>,
    pub source_kind: ReviewCapsuleSourceKind,
    pub source_id: String,
    pub artifact_refs: Vec<ReviewArtifactRef>,
    pub lane_summaries: Vec<ReviewLaneSummary>,
    pub unresolved_gaps: Vec<ReviewLaneGap>,
    pub related_refs: Vec<EvidenceRelatedRef>,
    pub advisory_only: bool,
    pub payload_sha256: String,
    pub canonical_payload: String,
    pub signature: EvidenceSignature,
}

/// Summary metadata for one portable review capsule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewCapsuleRecord {
    pub capsule_id: String,
    pub session_id: String,
    pub source_kind: ReviewCapsuleSourceKind,
    pub source_id: String,
    pub created_at_ms: i64,
    pub signer_id: String,
    pub signer_key_id: String,
    pub gap_count: usize,
    pub bundle_path: String,
}

impl ReviewCapsuleRecord {
    pub(super) fn from_capsule(capsule: &ReviewCapsule, bundle_path: String) -> Self {
        Self {
            capsule_id: capsule.capsule_id.clone(),
            session_id: capsule.session_id.clone(),
            source_kind: capsule.source_kind,
            source_id: capsule.source_id.clone(),
            created_at_ms: capsule.created_at_ms,
            signer_id: capsule.signature.signer_id.clone(),
            signer_key_id: capsule.signature.key_id.clone(),
            gap_count: capsule.unresolved_gaps.len(),
            bundle_path,
        }
    }
}

/// Persisted capsule loaded with metadata.
#[derive(Debug, Clone)]
pub struct ReviewCapsuleLookup {
    pub record: ReviewCapsuleRecord,
    pub capsule: ReviewCapsule,
}

/// Operator-facing portable review capsule listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewCapsuleList {
    pub total_count: usize,
    pub session_id: Option<String>,
    pub capsules: Vec<ReviewCapsuleRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(super) struct ReviewCapsuleIndex {
    pub(super) entries: Vec<ReviewCapsuleRecord>,
}

/// Local trust status assigned to one imported portable review capsule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewCapsuleImportTrustStatus {
    Trusted,
    SignatureValidUntrusted,
    Invalid,
}

impl ReviewCapsuleImportTrustStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::SignatureValidUntrusted => "signature_valid_untrusted",
            Self::Invalid => "invalid",
        }
    }
}

/// Persisted result of importing a foreign portable review capsule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewCapsuleImport {
    pub import_id: String,
    pub imported_at_ms: i64,
    pub source_path: String,
    pub source_capsule_id: Option<String>,
    pub source_kind: Option<ReviewCapsuleSourceKind>,
    pub source_id: Option<String>,
    pub session_id: Option<String>,
    pub remote_signer_id: Option<String>,
    pub remote_signer_key_id: Option<String>,
    pub trusted_key_id: Option<String>,
    pub trust_status: ReviewCapsuleImportTrustStatus,
    pub checks: Vec<EvidenceVerificationCheck>,
    pub raw_document: String,
    pub capsule: Option<ReviewCapsule>,
}

/// Summary metadata for one imported portable review capsule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewCapsuleImportRecord {
    pub import_id: String,
    pub source_capsule_id: Option<String>,
    pub session_id: Option<String>,
    pub imported_at_ms: i64,
    pub trust_status: ReviewCapsuleImportTrustStatus,
    pub remote_signer_key_id: Option<String>,
    pub bundle_path: String,
}

impl ReviewCapsuleImportRecord {
    pub(super) fn from_import(import: &ReviewCapsuleImport, bundle_path: String) -> Self {
        Self {
            import_id: import.import_id.clone(),
            source_capsule_id: import.source_capsule_id.clone(),
            session_id: import.session_id.clone(),
            imported_at_ms: import.imported_at_ms,
            trust_status: import.trust_status,
            remote_signer_key_id: import.remote_signer_key_id.clone(),
            bundle_path,
        }
    }
}

/// Imported capsule loaded with metadata.
#[derive(Debug, Clone)]
pub struct ReviewCapsuleImportLookup {
    pub record: ReviewCapsuleImportRecord,
    pub import: ReviewCapsuleImport,
}

/// Operator-facing imported-capsule listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewCapsuleImportList {
    pub total_count: usize,
    pub imports: Vec<ReviewCapsuleImportRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(super) struct ReviewCapsuleImportIndex {
    pub(super) entries: Vec<ReviewCapsuleImportRecord>,
}

/// Source kinds supported by review delegation packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDelegationSourceKind {
    LocalCapsule,
    ImportedCapsule,
}

impl ReviewDelegationSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalCapsule => "local_capsule",
            Self::ImportedCapsule => "imported_capsule",
        }
    }
}

impl std::fmt::Display for ReviewDelegationSourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ReviewDelegationPayload {
    pub(super) session_id: String,
    pub(super) source_capsule_id: String,
    pub(super) source_import_id: Option<String>,
    pub(super) reason: String,
    pub(super) delegate_label: Option<String>,
    pub(super) imported_trust_status: Option<ReviewCapsuleImportTrustStatus>,
    pub(super) advisory_only: bool,
    pub(super) artifact_refs: Vec<ReviewArtifactRef>,
    pub(super) lane_summaries: Vec<ReviewLaneSummary>,
    pub(super) unresolved_gaps: Vec<ReviewLaneGap>,
    pub(super) related_refs: Vec<EvidenceRelatedRef>,
}

/// Signed advisory-only continuity packet derived from a portable review capsule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewDelegationPacket {
    pub delegation_id: String,
    pub schema_version: String,
    pub created_at_ms: i64,
    pub session_id: String,
    pub source_kind: ReviewDelegationSourceKind,
    pub source_capsule_id: String,
    pub source_import_id: Option<String>,
    pub source_signer_id: String,
    pub source_signer_key_id: String,
    pub imported_trust_status: Option<ReviewCapsuleImportTrustStatus>,
    pub reason: String,
    pub delegate_label: Option<String>,
    pub advisory_only: bool,
    pub artifact_refs: Vec<ReviewArtifactRef>,
    pub lane_summaries: Vec<ReviewLaneSummary>,
    pub unresolved_gaps: Vec<ReviewLaneGap>,
    pub related_refs: Vec<EvidenceRelatedRef>,
    pub payload_sha256: String,
    pub canonical_payload: String,
    pub signature: EvidenceSignature,
}

/// Summary metadata for one review delegation packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewDelegationPacketRecord {
    pub delegation_id: String,
    pub session_id: String,
    pub source_kind: ReviewDelegationSourceKind,
    pub source_capsule_id: String,
    pub source_import_id: Option<String>,
    pub created_at_ms: i64,
    pub signer_id: String,
    pub signer_key_id: String,
    pub gap_count: usize,
    pub bundle_path: String,
}

impl ReviewDelegationPacketRecord {
    pub(super) fn from_packet(packet: &ReviewDelegationPacket, bundle_path: String) -> Self {
        Self {
            delegation_id: packet.delegation_id.clone(),
            session_id: packet.session_id.clone(),
            source_kind: packet.source_kind,
            source_capsule_id: packet.source_capsule_id.clone(),
            source_import_id: packet.source_import_id.clone(),
            created_at_ms: packet.created_at_ms,
            signer_id: packet.signature.signer_id.clone(),
            signer_key_id: packet.signature.key_id.clone(),
            gap_count: packet.unresolved_gaps.len(),
            bundle_path,
        }
    }
}

/// Delegation packet loaded with metadata.
#[derive(Debug, Clone)]
pub struct ReviewDelegationPacketLookup {
    pub record: ReviewDelegationPacketRecord,
    pub packet: ReviewDelegationPacket,
}

/// Operator-facing delegation packet listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewDelegationPacketList {
    pub total_count: usize,
    pub session_id: Option<String>,
    pub delegations: Vec<ReviewDelegationPacketRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(super) struct ReviewDelegationPacketIndex {
    pub(super) entries: Vec<ReviewDelegationPacketRecord>,
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
    pub(super) fn from_handoff(
        handoff: &ReviewSessionMaintenanceHandoff,
        bundle_path: String,
    ) -> Self {
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
pub(super) struct ReviewSessionMaintenanceHandoffIndex {
    pub(super) entries: Vec<ReviewSessionMaintenanceHandoffRecord>,
}

/// Request to re-verify all evidence bundles implied by a review session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewSessionReverifyRequest {
    pub session_id: String,
    pub selected_artifact_refs: Vec<ReviewArtifactRef>,
    pub expected_key_id: Option<String>,
    pub reason: String,
}

/// Request to import a portable review capsule from disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewCapsuleImportRequest {
    pub source_path: String,
    pub expected_key_id: Option<String>,
}

/// Request to create one advisory-only delegation packet from a review capsule or import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewDelegationCreateRequest {
    pub capsule_id: Option<String>,
    pub import_id: Option<String>,
    pub reason: String,
    pub delegate_label: Option<String>,
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

/// Errors raised while persisting portable review capsules.
#[derive(Debug, thiserror::Error)]
pub enum ReviewCapsuleStoreError {
    #[error("failed to read review capsule store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write review capsule store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse review capsule store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised while persisting imported review capsules.
#[derive(Debug, thiserror::Error)]
pub enum ReviewCapsuleImportStoreError {
    #[error("failed to read imported review capsule store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write imported review capsule store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse imported review capsule store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised while persisting review delegation packets.
#[derive(Debug, thiserror::Error)]
pub enum ReviewDelegationPacketStoreError {
    #[error("failed to read review delegation store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write review delegation store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse review delegation store file `{path}`: {source}")]
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
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    SessionStore(#[from] ReviewSessionStoreError),

    #[error(transparent)]
    ExportStore(#[from] ReviewSessionExportStoreError),

    #[error(transparent)]
    CapsuleStore(#[from] ReviewCapsuleStoreError),

    #[error(transparent)]
    CapsuleImportStore(#[from] ReviewCapsuleImportStoreError),

    #[error(transparent)]
    DelegationStore(#[from] ReviewDelegationPacketStoreError),

    #[error(transparent)]
    HandoffStore(#[from] ReviewSessionMaintenanceHandoffStoreError),

    #[error(transparent)]
    ReadinessStore(#[from] ReviewSessionPromotionReadinessStoreError),

    #[error("invalid review session request: {0}")]
    InvalidRequest(String),

    #[error("failed to read portable review capsule source `{path}`: {source}")]
    ReadSource {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("review signing key env `{env_name}` is missing or empty")]
    MissingSigningKey { env_name: String },

    #[error("review session `{session_id}` was not found")]
    SessionNotFound { session_id: String },

    #[error("review session export `{export_id}` was not found")]
    ExportNotFound { export_id: String },

    #[error("review capsule `{capsule_id}` was not found")]
    CapsuleNotFound { capsule_id: String },

    #[error("review capsule import `{import_id}` was not found")]
    CapsuleImportNotFound { import_id: String },

    #[error("review delegation `{delegation_id}` was not found")]
    DelegationNotFound { delegation_id: String },

    #[error("review session handoff `{handoff_id}` was not found")]
    HandoffNotFound { handoff_id: String },

    #[error("review session readiness `{readiness_id}` was not found")]
    ReadinessNotFound { readiness_id: String },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        ReviewArtifactRef, ReviewArtifactRefKind, ReviewCapsuleImportTrustStatus,
        ReviewSessionRecord, ReviewSessionReport,
    };

    #[test]
    fn review_artifact_ref_kind_round_trips() {
        let kinds = [
            (ReviewArtifactRefKind::EvidenceBundle, "evidence_bundle"),
            (
                ReviewArtifactRefKind::EvidenceVerification,
                "evidence_verification",
            ),
            (
                ReviewArtifactRefKind::PromotionEvidencePacket,
                "promotion_evidence_packet",
            ),
            (ReviewArtifactRefKind::PromotionReview, "promotion_review"),
            (ReviewArtifactRefKind::CanaryRun, "canary_run"),
            (
                ReviewArtifactRefKind::ProductionPromotion,
                "production_promotion",
            ),
        ];

        for (kind, value) in kinds {
            assert_eq!(kind.as_str(), value);
            assert_eq!(kind.to_string(), value);
            assert_eq!(value.parse::<ReviewArtifactRefKind>().unwrap(), kind);
        }
    }

    #[test]
    fn review_session_record_counts_artifact_types() {
        let report = ReviewSessionReport {
            session_id: "session:red".to_string(),
            title: Some("Office Loader".to_string()),
            notes: Some("cross-lane review".to_string()),
            created_at_ms: 1_700_000_000_000,
            artifact_refs: vec![
                ReviewArtifactRef {
                    kind: ReviewArtifactRefKind::EvidenceBundle,
                    id: "bundle-1".to_string(),
                },
                ReviewArtifactRef {
                    kind: ReviewArtifactRefKind::EvidenceVerification,
                    id: "verification-1".to_string(),
                },
                ReviewArtifactRef {
                    kind: ReviewArtifactRefKind::PromotionEvidencePacket,
                    id: "packet-1".to_string(),
                },
            ],
        };

        let record = ReviewSessionRecord::from_report(&report, "bundle.json".to_string());
        assert_eq!(record.artifact_count, 3);
        assert_eq!(record.evidence_bundle_count, 1);
        assert_eq!(record.verification_count, 1);
        assert_eq!(record.promotion_packet_count, 1);
    }

    #[test]
    fn review_capsule_import_trust_status_strings_are_stable() {
        assert_eq!(ReviewCapsuleImportTrustStatus::Trusted.as_str(), "trusted");
        assert_eq!(
            ReviewCapsuleImportTrustStatus::SignatureValidUntrusted.as_str(),
            "signature_valid_untrusted"
        );
        assert_eq!(ReviewCapsuleImportTrustStatus::Invalid.as_str(), "invalid");
    }
}
