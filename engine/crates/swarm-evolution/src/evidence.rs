use crate::canary::{CanaryRunLookup, FileCanaryStore};
use crate::config::{RuntimeConfigError, load_config};
use crate::control::{
    ControlError, DefaultControlPlane, IncidentArtifactView, IncidentLookupSelector,
    InvestigationArtifactView, InvestigationLookupSelector, ReplayArtifactView,
    ReplayLookupSelector,
};
use crate::operator_maintenance::{
    FileOperatorMaintenanceStore, OperatorMaintenanceLookup, OperatorMaintenanceStoreError,
};
use crate::promotion::{
    FileProductionPromotionStore, ProductionPromotionLookup, ProductionPromotionStatus,
    ProductionPromotionStoreError,
};
use crate::replay::{
    DetectorVerificationLookup, FilePromotionReviewStore, FileShadowStore, FileVerificationStore,
    PromotionReviewLookup, PromotionReviewStoreError, ShadowStoreError, StrategyShadowLookup,
    VerificationStoreError,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::SwarmConfig;
use swarm_crypto::{
    CryptoError, DetachedSignature, Ed25519Signer, canonical_json_bytes, normalize_canonical_json,
    sha256_hex, verify_detached_signature,
};
/// Result directories required to export and verify evidence artifacts.
#[derive(Debug, Clone)]
pub struct EvidenceHarnessPaths {
    pub verification_results_dir: PathBuf,
    pub shadow_results_dir: PathBuf,
    pub promotion_review_results_dir: PathBuf,
    pub canary_results_dir: PathBuf,
    pub promotion_results_dir: PathBuf,
    pub operator_maintenance_results_dir: PathBuf,
    pub evidence_results_dir: PathBuf,
    pub evidence_verification_results_dir: PathBuf,
    pub promotion_evidence_results_dir: PathBuf,
}

/// Read-only evidence store bundle used by the operator surface.
#[derive(Debug, Clone)]
pub struct OperatorEvidenceReadService {
    bundle_store: FileEvidenceBundleStore,
    verification_store: FileEvidenceVerificationStore,
    promotion_evidence_store: FilePromotionEvidencePacketStore,
}

impl OperatorEvidenceReadService {
    pub fn from_paths(paths: &EvidenceHarnessPaths) -> Result<Self, EvidenceError> {
        Self::from_store_paths(
            &paths.evidence_results_dir,
            &paths.evidence_verification_results_dir,
            &paths.promotion_evidence_results_dir,
        )
    }

    pub fn from_store_paths(
        evidence_results_dir: impl AsRef<Path>,
        evidence_verification_results_dir: impl AsRef<Path>,
        promotion_evidence_results_dir: impl AsRef<Path>,
    ) -> Result<Self, EvidenceError> {
        Ok(Self {
            bundle_store: FileEvidenceBundleStore::open(evidence_results_dir)?,
            verification_store: FileEvidenceVerificationStore::open(
                evidence_verification_results_dir,
            )?,
            promotion_evidence_store: FilePromotionEvidencePacketStore::open(
                promotion_evidence_results_dir,
            )?,
        })
    }

    pub fn load_bundle(
        &self,
        bundle_id: &str,
    ) -> Result<Option<EvidenceBundleLookup>, EvidenceError> {
        self.bundle_store.load(bundle_id).map_err(Into::into)
    }

    pub fn find_bundle_by_subject(
        &self,
        subject_kind: EvidenceSubjectKind,
        subject_id: &str,
    ) -> Result<Option<EvidenceBundleLookup>, EvidenceError> {
        self.bundle_store
            .find_by_subject(subject_kind, subject_id)
            .map_err(Into::into)
    }

    pub fn list_bundles(
        &self,
        subject_kind: Option<EvidenceSubjectKind>,
    ) -> Result<EvidenceBundleList, EvidenceError> {
        self.bundle_store.list(subject_kind).map_err(Into::into)
    }

    pub fn load_verification(
        &self,
        verification_id: &str,
    ) -> Result<Option<EvidenceVerificationLookup>, EvidenceError> {
        self.verification_store
            .load(verification_id)
            .map_err(Into::into)
    }

    pub fn load_promotion_evidence_packet(
        &self,
        packet_id: &str,
    ) -> Result<Option<PromotionEvidencePacketLookup>, EvidenceError> {
        self.promotion_evidence_store
            .load(packet_id)
            .map_err(Into::into)
    }

    pub fn list_promotion_evidence_packets(
        &self,
    ) -> Result<PromotionEvidencePacketList, EvidenceError> {
        self.promotion_evidence_store.list().map_err(Into::into)
    }
}

/// Persisted subject kinds supported by signed evidence export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSubjectKind {
    ReplayBundle,
    InvestigationBundle,
    CorrelatedIncident,
    CanaryRun,
    ProductionPromotion,
    OperatorMaintenanceAction,
    DetectorVerification,
    StrategyShadow,
    PromotionReview,
}

impl EvidenceSubjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayBundle => "replay_bundle",
            Self::InvestigationBundle => "investigation_bundle",
            Self::CorrelatedIncident => "correlated_incident",
            Self::CanaryRun => "canary_run",
            Self::ProductionPromotion => "production_promotion",
            Self::OperatorMaintenanceAction => "operator_maintenance_action",
            Self::DetectorVerification => "detector_verification",
            Self::StrategyShadow => "strategy_shadow",
            Self::PromotionReview => "promotion_review",
        }
    }
}

impl std::fmt::Display for EvidenceSubjectKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for EvidenceSubjectKind {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "replay_bundle" => Ok(Self::ReplayBundle),
            "investigation_bundle" => Ok(Self::InvestigationBundle),
            "correlated_incident" => Ok(Self::CorrelatedIncident),
            "canary_run" => Ok(Self::CanaryRun),
            "production_promotion" => Ok(Self::ProductionPromotion),
            "operator_maintenance_action" => Ok(Self::OperatorMaintenanceAction),
            "detector_verification" => Ok(Self::DetectorVerification),
            "strategy_shadow" => Ok(Self::StrategyShadow),
            "promotion_review" => Ok(Self::PromotionReview),
            _ => Err(()),
        }
    }
}

/// One stable related reference preserved in signed evidence metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRelatedRef {
    pub kind: String,
    pub id: String,
}

/// Stable metadata for one signed evidence subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSubjectMetadata {
    pub kind: EvidenceSubjectKind,
    pub stable_id: String,
    pub display_name: String,
    pub source_created_at_ms: i64,
    pub receipt_chain_refs: Vec<String>,
    pub related_refs: Vec<EvidenceRelatedRef>,
}

/// Detached signature plus local signer identity metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSignature {
    pub signer_id: String,
    pub algorithm: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

impl EvidenceSignature {
    fn from_detached(signer_id: String, detached: DetachedSignature) -> Self {
        Self {
            signer_id,
            algorithm: detached.algorithm,
            key_id: detached.key_id,
            public_key_hex: detached.public_key_hex,
            signature_hex: detached.signature_hex,
        }
    }

    fn detached(&self) -> DetachedSignature {
        DetachedSignature {
            algorithm: self.algorithm.clone(),
            key_id: self.key_id.clone(),
            public_key_hex: self.public_key_hex.clone(),
            signature_hex: self.signature_hex.clone(),
        }
    }
}

/// Persisted signed evidence bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub bundle_id: String,
    pub schema_version: String,
    pub config_name: String,
    pub exported_at_ms: i64,
    pub subject: EvidenceSubjectMetadata,
    pub payload_sha256: String,
    pub canonical_payload: String,
    pub signature: EvidenceSignature,
}

/// Metadata surfaced for one persisted evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundleRecord {
    pub bundle_id: String,
    pub subject_kind: EvidenceSubjectKind,
    pub subject_id: String,
    pub source_created_at_ms: i64,
    pub exported_at_ms: i64,
    pub payload_sha256: String,
    pub signer_id: String,
    pub signer_key_id: String,
    pub latest_verification_id: Option<String>,
    pub latest_verification_status: Option<EvidenceVerificationStatus>,
    pub bundle_path: String,
}

impl EvidenceBundleRecord {
    fn from_bundle(bundle: &EvidenceBundle, bundle_path: String) -> Self {
        Self {
            bundle_id: bundle.bundle_id.clone(),
            subject_kind: bundle.subject.kind,
            subject_id: bundle.subject.stable_id.clone(),
            source_created_at_ms: bundle.subject.source_created_at_ms,
            exported_at_ms: bundle.exported_at_ms,
            payload_sha256: bundle.payload_sha256.clone(),
            signer_id: bundle.signature.signer_id.clone(),
            signer_key_id: bundle.signature.key_id.clone(),
            latest_verification_id: None,
            latest_verification_status: None,
            bundle_path,
        }
    }
}

/// Persisted evidence bundle loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvidenceBundleLookup {
    pub record: EvidenceBundleRecord,
    pub bundle: EvidenceBundle,
}

/// Operator-facing evidence bundle listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundleList {
    pub total_count: usize,
    pub subject_kind: Option<EvidenceSubjectKind>,
    pub bundles: Vec<EvidenceBundleRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct EvidenceBundleIndex {
    entries: Vec<EvidenceBundleRecord>,
}

/// Verification status for one persisted evidence bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceVerificationStatus {
    Passed,
    Failed,
}

impl EvidenceVerificationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for EvidenceVerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One explicit verification check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceVerificationCheck {
    pub name: String,
    pub passed: bool,
    pub details: String,
}

/// Persisted verification report for one evidence bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceVerificationReport {
    pub verification_id: String,
    pub bundle_id: String,
    pub subject_kind: EvidenceSubjectKind,
    pub subject_id: String,
    pub verified_at_ms: i64,
    pub status: EvidenceVerificationStatus,
    pub signer_id: String,
    pub signer_key_id: String,
    pub expected_key_id: Option<String>,
    pub checks: Vec<EvidenceVerificationCheck>,
}

/// Metadata surfaced for one persisted evidence verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceVerificationRecord {
    pub verification_id: String,
    pub bundle_id: String,
    pub verified_at_ms: i64,
    pub status: EvidenceVerificationStatus,
    pub bundle_path: String,
}

impl EvidenceVerificationRecord {
    fn from_report(report: &EvidenceVerificationReport, bundle_path: String) -> Self {
        Self {
            verification_id: report.verification_id.clone(),
            bundle_id: report.bundle_id.clone(),
            verified_at_ms: report.verified_at_ms,
            status: report.status,
            bundle_path,
        }
    }
}

/// Persisted evidence verification loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvidenceVerificationLookup {
    pub record: EvidenceVerificationRecord,
    pub report: EvidenceVerificationReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct EvidenceVerificationIndex {
    entries: Vec<EvidenceVerificationRecord>,
}

/// One signed supporting bundle attached to a promotion evidence packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionEvidenceAttachment {
    pub subject_kind: EvidenceSubjectKind,
    pub subject_id: String,
    pub bundle_id: Option<String>,
    pub verification_id: Option<String>,
    pub verification_status: Option<EvidenceVerificationStatus>,
    pub details: String,
}

/// One blocking reason preserved in a promotion evidence packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionEvidenceBlockingReason {
    pub name: String,
    pub details: String,
    pub references: Vec<String>,
}

/// Final advisory state for one promotion evidence packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionEvidenceRecommendation {
    ReadyForExternalReview,
    Blocked,
}

impl PromotionEvidenceRecommendation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyForExternalReview => "ready_for_external_review",
            Self::Blocked => "blocked",
        }
    }
}

impl std::fmt::Display for PromotionEvidenceRecommendation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Durable packet joining rollout outcome with signed supporting evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionEvidencePacket {
    pub packet_id: String,
    pub promotion_id: String,
    pub created_at_ms: i64,
    pub window_id: String,
    pub promotion_status: ProductionPromotionStatus,
    pub promoted_strategy_id: String,
    pub fallback_strategy_id: String,
    pub canary_run_id: String,
    pub verification_id: String,
    pub shadow_id: String,
    pub supporting_evidence: Vec<PromotionEvidenceAttachment>,
    pub blocking_reasons: Vec<PromotionEvidenceBlockingReason>,
    pub recommendation: PromotionEvidenceRecommendation,
    pub advisory_only: bool,
}

/// Metadata surfaced for one persisted promotion evidence packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionEvidencePacketRecord {
    pub packet_id: String,
    pub promotion_id: String,
    pub created_at_ms: i64,
    pub ready_for_external_review: bool,
    pub bundle_path: String,
}

impl PromotionEvidencePacketRecord {
    fn from_packet(packet: &PromotionEvidencePacket, bundle_path: String) -> Self {
        Self {
            packet_id: packet.packet_id.clone(),
            promotion_id: packet.promotion_id.clone(),
            created_at_ms: packet.created_at_ms,
            ready_for_external_review: packet.recommendation
                == PromotionEvidenceRecommendation::ReadyForExternalReview,
            bundle_path,
        }
    }
}

/// Persisted promotion evidence packet loaded with metadata.
#[derive(Debug, Clone)]
pub struct PromotionEvidencePacketLookup {
    pub record: PromotionEvidencePacketRecord,
    pub packet: PromotionEvidencePacket,
}

/// Operator-facing promotion evidence packet listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionEvidencePacketList {
    pub total_count: usize,
    pub packets: Vec<PromotionEvidencePacketRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PromotionEvidencePacketIndex {
    entries: Vec<PromotionEvidencePacketRecord>,
}

/// Evidence export request bound to one stable artifact id.
#[derive(Debug, Clone)]
pub struct EvidenceExportRequest {
    pub subject_kind: EvidenceSubjectKind,
    pub stable_id: String,
    pub signer_id: String,
    pub secret_material: String,
}

#[derive(Debug, Clone)]
struct ExportableArtifact {
    subject: EvidenceSubjectMetadata,
    payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct EvidenceSignatureStatement<'a> {
    bundle_id: &'a str,
    schema_version: &'a str,
    config_name: &'a str,
    exported_at_ms: i64,
    subject: &'a EvidenceSubjectMetadata,
    payload_sha256: &'a str,
}

/// Errors raised while persisting evidence bundles.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceBundleStoreError {
    #[error("failed to read evidence store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evidence store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evidence store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed signed evidence store.
#[derive(Debug, Clone)]
pub struct FileEvidenceBundleStore {
    root: PathBuf,
}

impl FileEvidenceBundleStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvidenceBundleStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvidenceBundleStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, bundle_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(bundle_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvidenceBundleIndex, EvidenceBundleStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvidenceBundleIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| EvidenceBundleStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvidenceBundleStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &EvidenceBundleIndex) -> Result<(), EvidenceBundleStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvidenceBundleStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvidenceBundleStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        bundle: &EvidenceBundle,
    ) -> Result<EvidenceBundleLookup, EvidenceBundleStoreError> {
        let path = self.report_path(&bundle.bundle_id);
        let raw = serde_json::to_string_pretty(bundle).map_err(|source| {
            EvidenceBundleStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvidenceBundleStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvidenceBundleRecord::from_bundle(bundle, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.bundle_id != record.bundle_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.exported_at_ms));
        self.write_index(&index)?;
        Ok(EvidenceBundleLookup {
            record,
            bundle: bundle.clone(),
        })
    }

    pub fn load(
        &self,
        bundle_id: &str,
    ) -> Result<Option<EvidenceBundleLookup>, EvidenceBundleStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.bundle_id == bundle_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| EvidenceBundleStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let bundle =
            serde_json::from_str(&raw).map_err(|source| EvidenceBundleStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(EvidenceBundleLookup { record, bundle }))
    }

    pub fn list(
        &self,
        subject_kind: Option<EvidenceSubjectKind>,
    ) -> Result<EvidenceBundleList, EvidenceBundleStoreError> {
        let mut bundles = self.read_index()?.entries;
        if let Some(subject_kind) = subject_kind {
            bundles.retain(|entry| entry.subject_kind == subject_kind);
        }
        Ok(EvidenceBundleList {
            total_count: bundles.len(),
            subject_kind,
            bundles,
        })
    }

    pub fn find_by_subject(
        &self,
        subject_kind: EvidenceSubjectKind,
        subject_id: &str,
    ) -> Result<Option<EvidenceBundleLookup>, EvidenceBundleStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.subject_kind == subject_kind && entry.subject_id == subject_id)
            .cloned()
        else {
            return Ok(None);
        };
        self.load(&record.bundle_id)
    }

    pub fn attach_verification(
        &self,
        verification: &EvidenceVerificationRecord,
        bundle_id: &str,
    ) -> Result<(), EvidenceBundleStoreError> {
        let mut index = self.read_index()?;
        let Some(entry) = index
            .entries
            .iter_mut()
            .find(|entry| entry.bundle_id == bundle_id)
        else {
            return Ok(());
        };
        entry.latest_verification_id = Some(verification.verification_id.clone());
        entry.latest_verification_status = Some(verification.status);
        self.write_index(&index)
    }
}

/// Errors raised while persisting evidence verification reports.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceVerificationStoreError {
    #[error("failed to read evidence verification store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evidence verification store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evidence verification store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed store for evidence verification reports.
#[derive(Debug, Clone)]
pub struct FileEvidenceVerificationStore {
    root: PathBuf,
}

impl FileEvidenceVerificationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvidenceVerificationStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvidenceVerificationStoreError::Write {
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

    fn read_index(&self) -> Result<EvidenceVerificationIndex, EvidenceVerificationStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvidenceVerificationIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| EvidenceVerificationStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvidenceVerificationStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvidenceVerificationIndex,
    ) -> Result<(), EvidenceVerificationStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvidenceVerificationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvidenceVerificationStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvidenceVerificationReport,
    ) -> Result<EvidenceVerificationLookup, EvidenceVerificationStoreError> {
        let path = self.report_path(&report.verification_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvidenceVerificationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvidenceVerificationStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvidenceVerificationRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.verification_id != record.verification_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.verified_at_ms));
        self.write_index(&index)?;
        Ok(EvidenceVerificationLookup {
            record,
            report: report.clone(),
        })
    }

    pub fn load(
        &self,
        verification_id: &str,
    ) -> Result<Option<EvidenceVerificationLookup>, EvidenceVerificationStoreError> {
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
        let raw =
            fs::read_to_string(&path).map_err(|source| EvidenceVerificationStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report =
            serde_json::from_str(&raw).map_err(|source| EvidenceVerificationStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Some(EvidenceVerificationLookup { record, report }))
    }
}

/// Errors raised while persisting promotion evidence packets.
#[derive(Debug, thiserror::Error)]
pub enum PromotionEvidencePacketStoreError {
    #[error("failed to read promotion evidence store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write promotion evidence store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse promotion evidence store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed store for promotion evidence packets.
#[derive(Debug, Clone)]
pub struct FilePromotionEvidencePacketStore {
    root: PathBuf,
}

impl FilePromotionEvidencePacketStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PromotionEvidencePacketStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            PromotionEvidencePacketStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, packet_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(packet_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(
        &self,
    ) -> Result<PromotionEvidencePacketIndex, PromotionEvidencePacketStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(PromotionEvidencePacketIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            PromotionEvidencePacketStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| PromotionEvidencePacketStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &PromotionEvidencePacketIndex,
    ) -> Result<(), PromotionEvidencePacketStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            PromotionEvidencePacketStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| PromotionEvidencePacketStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        packet: &PromotionEvidencePacket,
    ) -> Result<PromotionEvidencePacketLookup, PromotionEvidencePacketStoreError> {
        let path = self.report_path(&packet.packet_id);
        let raw = serde_json::to_string_pretty(packet).map_err(|source| {
            PromotionEvidencePacketStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| PromotionEvidencePacketStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = PromotionEvidencePacketRecord::from_packet(packet, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.packet_id != record.packet_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(PromotionEvidencePacketLookup {
            record,
            packet: packet.clone(),
        })
    }

    pub fn load(
        &self,
        packet_id: &str,
    ) -> Result<Option<PromotionEvidencePacketLookup>, PromotionEvidencePacketStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.packet_id == packet_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            PromotionEvidencePacketStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let packet = serde_json::from_str(&raw).map_err(|source| {
            PromotionEvidencePacketStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        Ok(Some(PromotionEvidencePacketLookup { record, packet }))
    }

    pub fn list(&self) -> Result<PromotionEvidencePacketList, PromotionEvidencePacketStoreError> {
        let packets = self.read_index()?.entries;
        Ok(PromotionEvidencePacketList {
            total_count: packets.len(),
            packets,
        })
    }
}

/// Errors surfaced while exporting or verifying evidence.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Control(#[from] ControlError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    EvidenceStore(#[from] EvidenceBundleStoreError),

    #[error(transparent)]
    EvidenceVerificationStore(#[from] EvidenceVerificationStoreError),

    #[error(transparent)]
    PromotionEvidenceStore(#[from] PromotionEvidencePacketStoreError),

    #[error(transparent)]
    VerificationStore(#[from] VerificationStoreError),

    #[error(transparent)]
    ShadowStore(#[from] ShadowStoreError),

    #[error(transparent)]
    PromotionReviewStore(#[from] PromotionReviewStoreError),

    #[error(transparent)]
    CanaryStore(#[from] crate::canary::CanaryStoreError),

    #[error(transparent)]
    PromotionStore(#[from] ProductionPromotionStoreError),

    #[error(transparent)]
    MaintenanceStore(#[from] OperatorMaintenanceStoreError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    #[error("canonical evidence payload for bundle `{bundle_id}` was not valid UTF-8: {source}")]
    CanonicalPayloadUtf8 {
        bundle_id: String,
        #[source]
        source: std::string::FromUtf8Error,
    },

    #[error("artifact `{kind}` with id `{id}` was not found")]
    ArtifactNotFound { kind: &'static str, id: String },
}

/// Repo-owned harness for signed evidence export and verification.
pub struct DefaultEvidenceHarness {
    control: Arc<DefaultControlPlane>,
    verification_results_dir: PathBuf,
    shadow_results_dir: PathBuf,
    promotion_review_results_dir: PathBuf,
    canary_store: FileCanaryStore,
    promotion_store: FileProductionPromotionStore,
    maintenance_store: FileOperatorMaintenanceStore,
    evidence_store: FileEvidenceBundleStore,
    evidence_verification_store: FileEvidenceVerificationStore,
    promotion_evidence_store: FilePromotionEvidencePacketStore,
}

impl DefaultEvidenceHarness {
    pub fn from_control(
        control: Arc<DefaultControlPlane>,
        paths: EvidenceHarnessPaths,
    ) -> Result<Self, EvidenceError> {
        Ok(Self {
            control,
            verification_results_dir: paths.verification_results_dir,
            shadow_results_dir: paths.shadow_results_dir,
            promotion_review_results_dir: paths.promotion_review_results_dir,
            canary_store: FileCanaryStore::open(paths.canary_results_dir)?,
            promotion_store: FileProductionPromotionStore::open(paths.promotion_results_dir)?,
            maintenance_store: FileOperatorMaintenanceStore::open(
                paths.operator_maintenance_results_dir,
            )?,
            evidence_store: FileEvidenceBundleStore::open(paths.evidence_results_dir)?,
            evidence_verification_store: FileEvidenceVerificationStore::open(
                paths.evidence_verification_results_dir,
            )?,
            promotion_evidence_store: FilePromotionEvidencePacketStore::open(
                paths.promotion_evidence_results_dir,
            )?,
        })
    }

    pub fn from_config(
        config_path: impl Into<PathBuf>,
        config: SwarmConfig,
        paths: EvidenceHarnessPaths,
    ) -> Result<Self, EvidenceError> {
        Self::from_control(
            Arc::new(DefaultControlPlane::from_config(config_path, config)?),
            paths,
        )
    }

    pub fn from_path(
        config_path: impl AsRef<Path>,
        paths: EvidenceHarnessPaths,
    ) -> Result<Self, EvidenceError> {
        let config_path = config_path.as_ref();
        let config = load_config(config_path)?;
        Self::from_config(config_path.to_path_buf(), config, paths)
    }

    pub fn export_bundle(
        &self,
        request: EvidenceExportRequest,
    ) -> Result<EvidenceBundleLookup, EvidenceError> {
        let artifact = self.load_exportable_artifact(request.subject_kind, &request.stable_id)?;
        let payload_bytes = canonical_json_bytes(&artifact.payload)?;
        let payload_sha256 = sha256_hex(&payload_bytes);
        let exported_at_ms = now_ms();
        let bundle_id = evidence_bundle_id(
            artifact.subject.kind,
            &artifact.subject.stable_id,
            &request.signer_id,
        );
        let signer = Ed25519Signer::from_secret_material(&request.secret_material);
        let subject = artifact.subject;
        let statement_bytes = signature_statement_bytes(
            &bundle_id,
            "v1",
            &self.control.stack.service.config.name,
            exported_at_ms,
            &payload_sha256,
            &subject,
        )?;
        let canonical_payload = String::from_utf8(payload_bytes).map_err(|source| {
            EvidenceError::CanonicalPayloadUtf8 {
                bundle_id: bundle_id.clone(),
                source,
            }
        })?;
        let signed_bundle = EvidenceBundle {
            bundle_id,
            schema_version: "v1".to_string(),
            config_name: self.control.stack.service.config.name.clone(),
            exported_at_ms,
            subject,
            payload_sha256,
            canonical_payload,
            signature: EvidenceSignature::from_detached(
                request.signer_id,
                signer.sign(&statement_bytes),
            ),
        };
        self.evidence_store
            .persist(&signed_bundle)
            .map_err(Into::into)
    }

    pub fn load_bundle(
        &self,
        bundle_id: &str,
    ) -> Result<Option<EvidenceBundleLookup>, EvidenceError> {
        self.evidence_store.load(bundle_id).map_err(Into::into)
    }

    pub fn list_bundles(
        &self,
        subject_kind: Option<EvidenceSubjectKind>,
    ) -> Result<EvidenceBundleList, EvidenceError> {
        self.evidence_store.list(subject_kind).map_err(Into::into)
    }

    pub fn verify_bundle(
        &self,
        bundle_id: &str,
        expected_key_id: Option<&str>,
    ) -> Result<EvidenceVerificationLookup, EvidenceError> {
        verify_bundle_with_stores(
            &self.evidence_store,
            &self.evidence_verification_store,
            bundle_id,
            expected_key_id,
        )
    }

    pub fn load_verification(
        &self,
        verification_id: &str,
    ) -> Result<Option<EvidenceVerificationLookup>, EvidenceError> {
        self.evidence_verification_store
            .load(verification_id)
            .map_err(Into::into)
    }

    pub fn create_promotion_evidence_packet(
        &self,
        promotion_id: &str,
    ) -> Result<PromotionEvidencePacketLookup, EvidenceError> {
        let promotion = self.promotion_store.load(promotion_id)?.ok_or_else(|| {
            EvidenceError::ArtifactNotFound {
                kind: "production promotion",
                id: promotion_id.to_string(),
            }
        })?;
        let report = &promotion.report;
        let mut attachments = Vec::new();
        let mut blocking_reasons = Vec::new();

        attachments.push(self.supporting_attachment(
            EvidenceSubjectKind::ProductionPromotion,
            &report.promotion_id,
            "production promotion evidence",
            &mut blocking_reasons,
        )?);
        attachments.push(self.supporting_attachment(
            EvidenceSubjectKind::CanaryRun,
            &report.assignment.canary_run_id,
            "source canary evidence",
            &mut blocking_reasons,
        )?);
        attachments.push(self.supporting_attachment(
            EvidenceSubjectKind::DetectorVerification,
            &report.assignment.canary_report.assignment.verification_id,
            "verification evidence",
            &mut blocking_reasons,
        )?);
        attachments.push(self.supporting_attachment(
            EvidenceSubjectKind::StrategyShadow,
            &report.assignment.canary_report.assignment.shadow_id,
            "shadow evidence",
            &mut blocking_reasons,
        )?);

        if report.status == ProductionPromotionStatus::Active {
            blocking_reasons.push(PromotionEvidenceBlockingReason {
                name: "promotion_still_active".to_string(),
                details: "promotion evidence packets require a finalized production outcome"
                    .to_string(),
                references: vec![report.promotion_id.clone()],
            });
        }

        let packet = PromotionEvidencePacket {
            packet_id: format!("promotion_evidence:{}", report.promotion_id),
            promotion_id: report.promotion_id.clone(),
            created_at_ms: now_ms(),
            window_id: report.window_id.clone(),
            promotion_status: report.status,
            promoted_strategy_id: report.assignment.promoted_strategy_id.clone(),
            fallback_strategy_id: report.assignment.previous_production_strategy_id.clone(),
            canary_run_id: report.assignment.canary_run_id.clone(),
            verification_id: report
                .assignment
                .canary_report
                .assignment
                .verification_id
                .clone(),
            shadow_id: report.assignment.canary_report.assignment.shadow_id.clone(),
            supporting_evidence: attachments,
            recommendation: if blocking_reasons.is_empty() {
                PromotionEvidenceRecommendation::ReadyForExternalReview
            } else {
                PromotionEvidenceRecommendation::Blocked
            },
            blocking_reasons,
            advisory_only: true,
        };
        self.promotion_evidence_store
            .persist(&packet)
            .map_err(Into::into)
    }

    pub fn load_promotion_evidence_packet(
        &self,
        packet_id: &str,
    ) -> Result<Option<PromotionEvidencePacketLookup>, EvidenceError> {
        self.promotion_evidence_store
            .load(packet_id)
            .map_err(Into::into)
    }

    fn supporting_attachment(
        &self,
        subject_kind: EvidenceSubjectKind,
        subject_id: &str,
        description: &str,
        blocking_reasons: &mut Vec<PromotionEvidenceBlockingReason>,
    ) -> Result<PromotionEvidenceAttachment, EvidenceError> {
        let lookup = self
            .evidence_store
            .find_by_subject(subject_kind, subject_id)?;
        match lookup {
            Some(lookup) => {
                let verification_status = lookup.record.latest_verification_status;
                let verification_id = lookup.record.latest_verification_id.clone();
                if verification_status != Some(EvidenceVerificationStatus::Passed) {
                    blocking_reasons.push(PromotionEvidenceBlockingReason {
                        name: "supporting_evidence_unverified".to_string(),
                        details: format!("{description} is missing a passing verification result"),
                        references: vec![lookup.record.bundle_id.clone()],
                    });
                }
                Ok(PromotionEvidenceAttachment {
                    subject_kind,
                    subject_id: subject_id.to_string(),
                    bundle_id: Some(lookup.record.bundle_id),
                    verification_id,
                    verification_status,
                    details: description.to_string(),
                })
            }
            None => {
                blocking_reasons.push(PromotionEvidenceBlockingReason {
                    name: "supporting_evidence_missing".to_string(),
                    details: format!("{description} has not been exported as signed evidence"),
                    references: vec![subject_id.to_string()],
                });
                Ok(PromotionEvidenceAttachment {
                    subject_kind,
                    subject_id: subject_id.to_string(),
                    bundle_id: None,
                    verification_id: None,
                    verification_status: None,
                    details: description.to_string(),
                })
            }
        }
    }

    fn load_exportable_artifact(
        &self,
        subject_kind: EvidenceSubjectKind,
        stable_id: &str,
    ) -> Result<ExportableArtifact, EvidenceError> {
        match subject_kind {
            EvidenceSubjectKind::ReplayBundle => {
                let lookup = self
                    .control
                    .replay_lookup(ReplayLookupSelector::BundleId(stable_id))?;
                export_replay_view(&lookup.data)
            }
            EvidenceSubjectKind::InvestigationBundle => {
                let lookup = self.control.investigation_lookup(
                    InvestigationLookupSelector::InvestigationId(stable_id),
                )?;
                export_investigation_view(&lookup.data)
            }
            EvidenceSubjectKind::CorrelatedIncident => {
                let lookup = self
                    .control
                    .incident_lookup(IncidentLookupSelector::IncidentId(stable_id))?;
                export_incident_view(&lookup.data)
            }
            EvidenceSubjectKind::CanaryRun => {
                let lookup = self.canary_store.load(stable_id)?.ok_or_else(|| {
                    EvidenceError::ArtifactNotFound {
                        kind: "canary run",
                        id: stable_id.to_string(),
                    }
                })?;
                export_canary_lookup(&lookup)
            }
            EvidenceSubjectKind::ProductionPromotion => {
                let lookup = self.promotion_store.load(stable_id)?.ok_or_else(|| {
                    EvidenceError::ArtifactNotFound {
                        kind: "production promotion",
                        id: stable_id.to_string(),
                    }
                })?;
                export_promotion_lookup(&lookup)
            }
            EvidenceSubjectKind::OperatorMaintenanceAction => {
                let lookup = self.maintenance_store.load(stable_id)?.ok_or_else(|| {
                    EvidenceError::ArtifactNotFound {
                        kind: "operator maintenance action",
                        id: stable_id.to_string(),
                    }
                })?;
                export_maintenance_lookup(&lookup)
            }
            EvidenceSubjectKind::DetectorVerification => {
                let store = FileVerificationStore::open(&self.verification_results_dir)?;
                let lookup =
                    store
                        .load(stable_id)?
                        .ok_or_else(|| EvidenceError::ArtifactNotFound {
                            kind: "detector verification",
                            id: stable_id.to_string(),
                        })?;
                export_verification_lookup(&lookup)
            }
            EvidenceSubjectKind::StrategyShadow => {
                let store = FileShadowStore::open(&self.shadow_results_dir)?;
                let lookup =
                    store
                        .load(stable_id)?
                        .ok_or_else(|| EvidenceError::ArtifactNotFound {
                            kind: "strategy shadow",
                            id: stable_id.to_string(),
                        })?;
                export_shadow_lookup(&lookup)
            }
            EvidenceSubjectKind::PromotionReview => {
                let store = FilePromotionReviewStore::open(&self.promotion_review_results_dir)?;
                let lookup =
                    store
                        .load(stable_id)?
                        .ok_or_else(|| EvidenceError::ArtifactNotFound {
                            kind: "promotion review",
                            id: stable_id.to_string(),
                        })?;
                export_promotion_review_lookup(&lookup)
            }
        }
    }
}

pub fn render_evidence_bundle(bundle: &EvidenceBundle) -> String {
    [
        "Ambush Engine Evidence Bundle".to_string(),
        format!("Bundle ID: {}", bundle.bundle_id),
        format!(
            "Subject: {} {}",
            bundle.subject.kind.as_str(),
            bundle.subject.stable_id
        ),
        format!(
            "Signer: {} ({})",
            bundle.signature.signer_id, bundle.signature.key_id
        ),
        format!("Payload SHA-256: {}", bundle.payload_sha256),
        format!("Receipt refs: {}", bundle.subject.receipt_chain_refs.len()),
    ]
    .join("\n")
}

pub fn render_evidence_bundle_list(list: &EvidenceBundleList) -> String {
    let mut lines = vec![
        "Ambush Engine Evidence Bundles".to_string(),
        format!("Total: {}", list.total_count),
    ];
    for bundle in &list.bundles {
        lines.push(format!(
            "- {} | {} {} | signer={} | verification={}",
            bundle.bundle_id,
            bundle.subject_kind.as_str(),
            bundle.subject_id,
            bundle.signer_key_id,
            bundle
                .latest_verification_status
                .map(|status| match status {
                    EvidenceVerificationStatus::Passed => "passed",
                    EvidenceVerificationStatus::Failed => "failed",
                })
                .unwrap_or("none")
        ));
    }
    lines.join("\n")
}

pub fn render_evidence_verification(report: &EvidenceVerificationReport) -> String {
    let mut lines = vec![
        "Ambush Engine Evidence Verification".to_string(),
        format!("Verification ID: {}", report.verification_id),
        format!("Bundle ID: {}", report.bundle_id),
        format!(
            "Status: {}",
            match report.status {
                EvidenceVerificationStatus::Passed => "passed",
                EvidenceVerificationStatus::Failed => "failed",
            }
        ),
    ];
    lines.push("Checks:".to_string());
    for check in &report.checks {
        lines.push(format!(
            "- {}: {} ({})",
            check.name,
            if check.passed { "passed" } else { "failed" },
            check.details
        ));
    }
    lines.join("\n")
}

pub fn render_promotion_evidence_packet(packet: &PromotionEvidencePacket) -> String {
    let mut lines = vec![
        "Ambush Engine Promotion Evidence Packet".to_string(),
        format!("Packet ID: {}", packet.packet_id),
        format!("Promotion ID: {}", packet.promotion_id),
        format!(
            "Recommendation: {}",
            match packet.recommendation {
                PromotionEvidenceRecommendation::ReadyForExternalReview => {
                    "ready_for_external_review"
                }
                PromotionEvidenceRecommendation::Blocked => "blocked",
            }
        ),
        format!(
            "Strategies: promoted={} fallback={}",
            packet.promoted_strategy_id, packet.fallback_strategy_id
        ),
    ];
    if packet.blocking_reasons.is_empty() {
        lines.push("Blocking reasons: none".to_string());
    } else {
        lines.push("Blocking reasons:".to_string());
        for reason in &packet.blocking_reasons {
            lines.push(format!("- {} | {}", reason.name, reason.details));
        }
    }
    lines.push("Supporting evidence:".to_string());
    for attachment in &packet.supporting_evidence {
        lines.push(format!(
            "- {} {} | bundle={} | verification={}",
            attachment.subject_kind.as_str(),
            attachment.subject_id,
            attachment.bundle_id.as_deref().unwrap_or("missing"),
            attachment
                .verification_status
                .map(|status| match status {
                    EvidenceVerificationStatus::Passed => "passed",
                    EvidenceVerificationStatus::Failed => "failed",
                })
                .unwrap_or("none")
        ));
    }
    lines.join("\n")
}

fn export_replay_view(view: &ReplayArtifactView) -> Result<ExportableArtifact, EvidenceError> {
    Ok(ExportableArtifact {
        subject: EvidenceSubjectMetadata {
            kind: EvidenceSubjectKind::ReplayBundle,
            stable_id: view.record.bundle_id.clone(),
            display_name: format!("replay bundle {}", view.record.bundle_id),
            source_created_at_ms: view.record.created_at_ms,
            receipt_chain_refs: view.record.related_receipt_ids.clone(),
            related_refs: collect_non_empty_refs([
                Some(("hunt", view.record.hunt_id.clone())),
                Some(("trail", view.record.trail_id.clone())),
                view.record
                    .response_receipt_id
                    .clone()
                    .map(|id| ("response_receipt", id)),
            ]),
        },
        payload: serde_json::to_value(view)?,
    })
}

fn export_investigation_view(
    view: &InvestigationArtifactView,
) -> Result<ExportableArtifact, EvidenceError> {
    Ok(ExportableArtifact {
        subject: EvidenceSubjectMetadata {
            kind: EvidenceSubjectKind::InvestigationBundle,
            stable_id: view.record.investigation_id.clone(),
            display_name: format!("investigation bundle {}", view.record.investigation_id),
            source_created_at_ms: view.record.last_updated_ms,
            receipt_chain_refs: view.record.related_receipt_ids.clone(),
            related_refs: collect_non_empty_refs([
                Some(("source_bundle", view.record.source_bundle_id.clone())),
                Some(("hunt", view.record.hunt_id.clone())),
                Some(("trail", view.record.trail_id.clone())),
            ]),
        },
        payload: serde_json::to_value(view)?,
    })
}

fn export_incident_view(view: &IncidentArtifactView) -> Result<ExportableArtifact, EvidenceError> {
    Ok(ExportableArtifact {
        subject: EvidenceSubjectMetadata {
            kind: EvidenceSubjectKind::CorrelatedIncident,
            stable_id: view.record.incident_id.clone(),
            display_name: format!("incident {}", view.record.incident_id),
            source_created_at_ms: view.record.created_at_ms,
            receipt_chain_refs: view.record.related_receipt_ids.clone(),
            related_refs: view
                .record
                .included_hunt_ids
                .iter()
                .cloned()
                .map(|id| EvidenceRelatedRef {
                    kind: "hunt".to_string(),
                    id,
                })
                .chain(
                    view.record
                        .included_investigation_ids
                        .iter()
                        .cloned()
                        .map(|id| EvidenceRelatedRef {
                            kind: "investigation_bundle".to_string(),
                            id,
                        }),
                )
                .collect(),
        },
        payload: serde_json::to_value(view)?,
    })
}

fn export_canary_lookup(lookup: &CanaryRunLookup) -> Result<ExportableArtifact, EvidenceError> {
    Ok(ExportableArtifact {
        subject: EvidenceSubjectMetadata {
            kind: EvidenceSubjectKind::CanaryRun,
            stable_id: lookup.record.run_id.clone(),
            display_name: format!("canary run {}", lookup.record.run_id),
            source_created_at_ms: lookup.record.updated_at_ms,
            receipt_chain_refs: Vec::new(),
            related_refs: collect_non_empty_refs([
                Some(("experiment", lookup.record.experiment_id.clone())),
                Some((
                    "verification",
                    lookup.report.assignment.verification_id.clone(),
                )),
                Some(("shadow", lookup.report.assignment.shadow_id.clone())),
            ]),
        },
        payload: serde_json::to_value(&lookup.report)?,
    })
}

fn export_promotion_lookup(
    lookup: &ProductionPromotionLookup,
) -> Result<ExportableArtifact, EvidenceError> {
    Ok(ExportableArtifact {
        subject: EvidenceSubjectMetadata {
            kind: EvidenceSubjectKind::ProductionPromotion,
            stable_id: lookup.record.promotion_id.clone(),
            display_name: format!("production promotion {}", lookup.record.promotion_id),
            source_created_at_ms: lookup.record.updated_at_ms,
            receipt_chain_refs: Vec::new(),
            related_refs: collect_non_empty_refs([
                Some(("canary_run", lookup.report.assignment.canary_run_id.clone())),
                Some(("experiment", lookup.report.assignment.experiment_id.clone())),
                Some((
                    "fallback_strategy",
                    lookup
                        .report
                        .assignment
                        .previous_production_strategy_id
                        .clone(),
                )),
                Some((
                    "promoted_strategy",
                    lookup.report.assignment.promoted_strategy_id.clone(),
                )),
            ]),
        },
        payload: serde_json::to_value(&lookup.report)?,
    })
}

fn export_maintenance_lookup(
    lookup: &OperatorMaintenanceLookup,
) -> Result<ExportableArtifact, EvidenceError> {
    Ok(ExportableArtifact {
        subject: EvidenceSubjectMetadata {
            kind: EvidenceSubjectKind::OperatorMaintenanceAction,
            stable_id: lookup.summary.action_id.clone(),
            display_name: format!("operator maintenance action {}", lookup.summary.action_id),
            source_created_at_ms: lookup.summary.completed_at_ms,
            receipt_chain_refs: Vec::new(),
            related_refs: lookup
                .record
                .artifacts
                .iter()
                .map(|artifact| EvidenceRelatedRef {
                    kind: artifact.kind.clone(),
                    id: artifact.id.clone(),
                })
                .collect(),
        },
        payload: serde_json::to_value(&lookup.record)?,
    })
}

fn export_verification_lookup(
    lookup: &DetectorVerificationLookup,
) -> Result<ExportableArtifact, EvidenceError> {
    Ok(ExportableArtifact {
        subject: EvidenceSubjectMetadata {
            kind: EvidenceSubjectKind::DetectorVerification,
            stable_id: lookup.record.verification_id.clone(),
            display_name: format!("detector verification {}", lookup.record.verification_id),
            source_created_at_ms: lookup.record.created_at_ms,
            receipt_chain_refs: Vec::new(),
            related_refs: collect_non_empty_refs([
                Some(("experiment", lookup.record.experiment_id.clone())),
                Some((
                    "candidate_strategy",
                    lookup.record.candidate_strategy_id.clone(),
                )),
            ]),
        },
        payload: serde_json::to_value(&lookup.report)?,
    })
}

fn export_shadow_lookup(
    lookup: &StrategyShadowLookup,
) -> Result<ExportableArtifact, EvidenceError> {
    Ok(ExportableArtifact {
        subject: EvidenceSubjectMetadata {
            kind: EvidenceSubjectKind::StrategyShadow,
            stable_id: lookup.record.shadow_id.clone(),
            display_name: format!("strategy shadow {}", lookup.record.shadow_id),
            source_created_at_ms: lookup.record.created_at_ms,
            receipt_chain_refs: Vec::new(),
            related_refs: collect_non_empty_refs([
                Some(("experiment", lookup.record.experiment_id.clone())),
                Some((
                    "candidate_strategy",
                    lookup.record.candidate_strategy_id.clone(),
                )),
            ]),
        },
        payload: serde_json::to_value(&lookup.report)?,
    })
}

fn export_promotion_review_lookup(
    lookup: &PromotionReviewLookup,
) -> Result<ExportableArtifact, EvidenceError> {
    Ok(ExportableArtifact {
        subject: EvidenceSubjectMetadata {
            kind: EvidenceSubjectKind::PromotionReview,
            stable_id: lookup.record.review_id.clone(),
            display_name: format!("promotion review {}", lookup.record.review_id),
            source_created_at_ms: lookup.record.created_at_ms,
            receipt_chain_refs: Vec::new(),
            related_refs: collect_non_empty_refs([
                Some(("experiment", lookup.record.experiment_id.clone())),
                Some((
                    "candidate_strategy",
                    lookup.record.candidate_strategy_id.clone(),
                )),
            ]),
        },
        payload: serde_json::to_value(&lookup.packet)?,
    })
}

fn collect_non_empty_refs<const N: usize>(
    refs: [Option<(&'static str, String)>; N],
) -> Vec<EvidenceRelatedRef> {
    refs.into_iter()
        .flatten()
        .filter_map(|(kind, id)| {
            if id.trim().is_empty() {
                None
            } else {
                Some(EvidenceRelatedRef {
                    kind: kind.to_string(),
                    id,
                })
            }
        })
        .collect()
}

fn evidence_bundle_id(kind: EvidenceSubjectKind, stable_id: &str, signer_id: &str) -> String {
    format!("evidence:{}:{}:{}", kind.as_str(), stable_id, signer_id)
}

pub(crate) fn verify_bundle_with_stores(
    evidence_store: &FileEvidenceBundleStore,
    evidence_verification_store: &FileEvidenceVerificationStore,
    bundle_id: &str,
    expected_key_id: Option<&str>,
) -> Result<EvidenceVerificationLookup, EvidenceError> {
    let lookup =
        evidence_store
            .load(bundle_id)?
            .ok_or_else(|| EvidenceError::ArtifactNotFound {
                kind: "evidence bundle",
                id: bundle_id.to_string(),
            })?;
    let verified_at_ms = now_ms();
    let mut checks = Vec::new();

    let normalized_payload = normalize_canonical_json(&lookup.bundle.canonical_payload);
    let normalized_payload = match normalized_payload {
        Ok(payload) => {
            let passed = payload == lookup.bundle.canonical_payload;
            checks.push(EvidenceVerificationCheck {
                name: "canonical_payload".to_string(),
                passed,
                details: if passed {
                    "canonical payload bytes normalized cleanly".to_string()
                } else {
                    "canonical payload bytes changed after normalization".to_string()
                },
            });
            payload
        }
        Err(error) => {
            checks.push(EvidenceVerificationCheck {
                name: "canonical_payload".to_string(),
                passed: false,
                details: error.to_string(),
            });
            String::new()
        }
    };

    let payload_hash = if normalized_payload.is_empty() {
        None
    } else {
        Some(sha256_hex(normalized_payload.as_bytes()))
    };
    let hash_passed = payload_hash
        .as_deref()
        .map(|value| value == lookup.bundle.payload_sha256)
        .unwrap_or(false);
    checks.push(EvidenceVerificationCheck {
        name: "payload_sha256".to_string(),
        passed: hash_passed,
        details: if hash_passed {
            "payload hash matches canonical payload bytes".to_string()
        } else {
            format!(
                "expected `{}`, recalculated `{}`",
                lookup.bundle.payload_sha256,
                payload_hash.unwrap_or_else(|| "unavailable".to_string())
            )
        },
    });

    let statement_bytes = signature_statement_bytes(
        &lookup.bundle.bundle_id,
        &lookup.bundle.schema_version,
        &lookup.bundle.config_name,
        lookup.bundle.exported_at_ms,
        &lookup.bundle.payload_sha256,
        &lookup.bundle.subject,
    )?;
    let signature_passed =
        verify_detached_signature(&statement_bytes, &lookup.bundle.signature.detached()).is_ok();
    checks.push(EvidenceVerificationCheck {
        name: "detached_signature".to_string(),
        passed: signature_passed,
        details: if signature_passed {
            "signature verified against signed statement".to_string()
        } else {
            "signature verification failed".to_string()
        },
    });

    let key_id_passed = expected_key_id
        .map(|expected| expected == lookup.bundle.signature.key_id)
        .unwrap_or(true);
    checks.push(EvidenceVerificationCheck {
        name: "expected_key_id".to_string(),
        passed: key_id_passed,
        details: if let Some(expected_key_id) = expected_key_id {
            if key_id_passed {
                format!("matched expected signer key id `{expected_key_id}`")
            } else {
                format!(
                    "expected signer key id `{expected_key_id}`, found `{}`",
                    lookup.bundle.signature.key_id
                )
            }
        } else {
            "no expected key id supplied".to_string()
        },
    });

    let status = if checks.iter().all(|check| check.passed) {
        EvidenceVerificationStatus::Passed
    } else {
        EvidenceVerificationStatus::Failed
    };
    let report = EvidenceVerificationReport {
        verification_id: format!("evidence_verification:{}", lookup.bundle.bundle_id),
        bundle_id: lookup.bundle.bundle_id.clone(),
        subject_kind: lookup.bundle.subject.kind,
        subject_id: lookup.bundle.subject.stable_id.clone(),
        verified_at_ms,
        status,
        signer_id: lookup.bundle.signature.signer_id.clone(),
        signer_key_id: lookup.bundle.signature.key_id.clone(),
        expected_key_id: expected_key_id.map(ToString::to_string),
        checks,
    };
    let verification = evidence_verification_store.persist(&report)?;
    evidence_store.attach_verification(&verification.record, &lookup.bundle.bundle_id)?;
    Ok(verification)
}

pub(crate) fn signature_statement_bytes(
    bundle_id: &str,
    schema_version: &str,
    config_name: &str,
    exported_at_ms: i64,
    payload_sha256: &str,
    subject: &EvidenceSubjectMetadata,
) -> Result<Vec<u8>, CryptoError> {
    canonical_json_bytes(&EvidenceSignatureStatement {
        bundle_id,
        schema_version,
        config_name,
        exported_at_ms,
        subject,
        payload_sha256,
    })
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => ch,
            _ => '_',
        })
        .collect()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DefaultEvidenceHarness, EvidenceBundle, EvidenceExportRequest, EvidenceHarnessPaths,
        EvidenceRelatedRef, EvidenceSignature, EvidenceSubjectKind, EvidenceSubjectMetadata,
        EvidenceVerificationReport, EvidenceVerificationStatus, FileEvidenceBundleStore,
        FileEvidenceVerificationStore, PromotionEvidenceRecommendation,
    };
    use crate::RuntimeMode;
    use crate::canary::{
        CanaryAssignment, CanaryMetrics, CanaryRecommendation, CanaryRunReport, CanaryRunStatus,
    };
    use crate::control::DefaultControlPlane;
    use crate::promotion::{
        FileProductionPromotionStore, ProductionPromotionAssignment, ProductionPromotionMetrics,
        ProductionPromotionRecommendation, ProductionPromotionReport, ProductionPromotionStatus,
    };
    use crate::replay::{DetectorCandidateManifest, ExperimentLineage};
    use crate::service::EventExecutionContext;
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use swarm_core::config::{
        AuditConfig, BundleStoreConfig, CanaryConfig, CorrelationConfig, DetectionConfig,
        DetectorProfilesConfig, InvestigationConfig, OperatorSurfaceConfig, PheromoneBackendConfig,
        PheromoneConfig, PolicyConfig, PromotionConfig, RuntimeSettings, SwarmConfig,
        TelemetrySourceConfig,
    };
    use swarm_core::types::{AgentId, Severity};
    use swarm_policy::ApprovalContext;
    use swarm_whisker::{
        ProcessStartEvent, SuspiciousProcessTreeDetector, SuspiciousProcessTreeProfile,
        TelemetryEvent, TelemetryPayload,
    };

    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn evidence_paths(root: &std::path::Path) -> EvidenceHarnessPaths {
        EvidenceHarnessPaths {
            verification_results_dir: root.join("verifications"),
            shadow_results_dir: root.join("shadows"),
            promotion_review_results_dir: root.join("promotion-reviews"),
            canary_results_dir: root.join("canaries"),
            promotion_results_dir: root.join("promotions"),
            operator_maintenance_results_dir: root.join("maintenance"),
            evidence_results_dir: root.join("evidence-bundles"),
            evidence_verification_results_dir: root.join("evidence-verifications"),
            promotion_evidence_results_dir: root.join("promotion-evidence-packets"),
        }
    }

    fn config(root: &std::path::Path) -> SwarmConfig {
        SwarmConfig {
            schema_version: 1,
            name: "evidence-test".to_string(),
            description: "evidence harness test config".to_string(),
            runtime: RuntimeSettings {
                mode: RuntimeMode::DetectOnly,
                demo_mode: false,
                telemetry_sources: vec![TelemetrySourceConfig {
                    name: "synthetic".to_string(),
                    subject: "telemetry.synthetic.process".to_string(),
                    bridge: None,
                }],
                max_in_flight_actions: 2,
                drain_timeout_ms: 30_000,
                require_durable_live_response: false,
                max_heap_pressure: 0.90,
                secret_dir: None,
                anti_tamper: Default::default(),
                temporal_event_window: swarm_core::config::TemporalEventWindowConfig::default(),
                agent_tick_timeout_ms: 500,
                governance_degraded_tick_threshold: 3,
                partition_contingency_lease_ttl_ms: 300_000,
                partition_contingency_blast_radius_cap: 1,
                max_dead_letter_bytes: None,
            },
            detection: DetectionConfig {
                strategy: "suspicious_process_tree".to_string(),
                strategies: Vec::new(),
                high_confidence_threshold: 0.9,
                medium_confidence_threshold: 0.7,
                profiles: DetectorProfilesConfig::default(),
            },
            pheromone: PheromoneConfig {
                default_half_life_secs: 3600.0,
                evaporation_threshold: 0.01,
                min_sources_for_escalation: 2,
                alert_threshold: 2.0,
                incident_threshold: 5.0,
                deescalation_cooldown_secs: 300,
                response_playbook: Default::default(),
                backend: PheromoneBackendConfig::InMemory,
            },
            policy: PolicyConfig {
                human_gate_severity: Severity::High,
                lease_ttl_ms: 60_000,
                ..PolicyConfig::default()
            },
            response_adapter: swarm_core::config::ResponseAdapterConfig::Sandbox,
            siem_forward: None,
            notification_channels: std::collections::BTreeMap::new(),
            notification_routing: swarm_core::config::NotificationRoutingConfig::default(),
            audit: AuditConfig {
                bundle_store: BundleStoreConfig::LocalFiles {
                    directory: root.join("replay-bundles").display().to_string(),
                },
                recent_decisions_limit: 10,
            },
            investigation: InvestigationConfig {
                enabled: true,
                worker_count: 1,
                max_pending_jobs: 4,
                time_budget_ms: 250,
                bundle_store: BundleStoreConfig::LocalFiles {
                    directory: root.join("investigations").display().to_string(),
                },
                ..InvestigationConfig::default()
            },
            correlation: CorrelationConfig {
                enabled: true,
                time_window_ms: 60_000,
                min_shared_keys: 1,
                candidate_limit: 8,
                incident_store: BundleStoreConfig::LocalFiles {
                    directory: root.join("incidents").display().to_string(),
                },
            },
            canary: CanaryConfig::default(),
            promotion: PromotionConfig::default(),
            evolution: swarm_core::config::EvolutionConfig::default(),
            deception: swarm_core::config::DeceptionConfig::default(),
            memory: swarm_core::config::MemoryConfig::default(),
            identity: swarm_core::config::IdentityConfig::default(),
            platform_api: Default::default(),
            operator: OperatorSurfaceConfig::default(),
            tls: None,
        }
    }

    fn write_config(root: &std::path::Path) -> PathBuf {
        let path = root.join("config.yaml");
        fs::write(&path, serde_yaml::to_string(&config(root)).unwrap()).unwrap();
        swarm_runtime::config::write_debug_test_config_signature(&path).unwrap();
        path
    }

    fn event(event_id: &str) -> TelemetryEvent {
        TelemetryEvent {
            source: "synthetic".to_string(),
            event_id: event_id.to_string(),
            timestamp: 1_710_000_000,
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
        }
    }

    fn approval_context(now_ms: i64) -> ApprovalContext {
        ApprovalContext {
            live_mode: false,
            receipt_chain: vec![format!("receipt-upstream-{now_ms}")],
            correlation_id: None,
            now_ms,
        }
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let suffix = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "swarm-runtime-evidence-{label}-{}-{suffix}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn sample_candidate(strategy_id: &str, description: &str) -> DetectorCandidateManifest {
        DetectorCandidateManifest::SuspiciousProcessTree {
            strategy_id: strategy_id.to_string(),
            description: description.to_string(),
            profile: SuspiciousProcessTreeProfile::default(),
        }
    }

    fn sample_canary_report() -> CanaryRunReport {
        CanaryRunReport {
            run_id: "canary:red".to_string(),
            slot_id: "canary-primary".to_string(),
            created_at_ms: 1_710_000_000_000,
            updated_at_ms: 1_710_000_000_100,
            status: CanaryRunStatus::Completed,
            recommendation: CanaryRecommendation::ReadyForPromotionReview,
            assignment: CanaryAssignment {
                experiment_id: "experiment:red".to_string(),
                experiment_name: "red experiment".to_string(),
                experiment_path: "experiments/red.yaml".to_string(),
                suite_name: "office".to_string(),
                corpus_version: "v1".to_string(),
                baseline_strategy_id: "office_control_v1".to_string(),
                candidate_strategy_id: "office_red_ready_v1".to_string(),
                candidate_description: "red candidate".to_string(),
                candidate: sample_candidate("office_red_ready_v1", "red candidate"),
                lineage: ExperimentLineage {
                    parent_strategy_id: "office_control_v1".to_string(),
                    mutation: "none".to_string(),
                    rationale: "seed".to_string(),
                },
                verification_id: "verification:red".to_string(),
                verification_passed: true,
                shadow_id: "shadow:red".to_string(),
                shadow_passed: true,
                assurance: None,
                canary: CanaryConfig::default(),
            },
            metrics: CanaryMetrics::default(),
            threshold_results: vec![],
            recent_candidate_findings: vec![],
            rollback_history: vec![],
        }
    }

    fn sample_promotion_report() -> ProductionPromotionReport {
        ProductionPromotionReport {
            promotion_id: "promotion:red".to_string(),
            window_id: "production-primary".to_string(),
            created_at_ms: 1_710_000_000_200,
            updated_at_ms: 1_710_000_000_300,
            status: ProductionPromotionStatus::Completed,
            recommendation: ProductionPromotionRecommendation::StableInProduction,
            assignment: ProductionPromotionAssignment {
                canary_run_id: "canary:red".to_string(),
                canary_report: sample_canary_report(),
                experiment_id: "experiment:red".to_string(),
                experiment_name: "red experiment".to_string(),
                suite_name: "office".to_string(),
                corpus_version: "v1".to_string(),
                previous_production_strategy_id: "office_control_v1".to_string(),
                promoted_strategy_id: "office_red_ready_v1".to_string(),
                promoted_description: "red candidate".to_string(),
                previous_production_candidate: sample_candidate(
                    "office_control_v1",
                    "control candidate",
                ),
                promoted_candidate: sample_candidate("office_red_ready_v1", "red candidate"),
                lineage: ExperimentLineage {
                    parent_strategy_id: "office_control_v1".to_string(),
                    mutation: "none".to_string(),
                    rationale: "seed".to_string(),
                },
                assurance: None,
                promotion: PromotionConfig::default(),
            },
            metrics: ProductionPromotionMetrics::default(),
            threshold_results: vec![],
            recent_promoted_findings: vec![],
            rollback_history: vec![],
            pending_review: None,
            approval_votes: vec![],
            consensus_receipt: None,
            approval_severity: None,
            quorum_gate_config: None,
        }
    }

    fn sample_bundle(kind: EvidenceSubjectKind, stable_id: &str) -> EvidenceBundle {
        EvidenceBundle {
            bundle_id: format!(
                "evidence:{}:{}:local-evidence-signer",
                kind.as_str(),
                stable_id
            ),
            schema_version: "v1".to_string(),
            config_name: "evidence-test".to_string(),
            exported_at_ms: 1_710_000_000_400,
            subject: EvidenceSubjectMetadata {
                kind,
                stable_id: stable_id.to_string(),
                display_name: format!("{} {}", kind.as_str(), stable_id),
                source_created_at_ms: 1_710_000_000_350,
                receipt_chain_refs: vec![],
                related_refs: vec![EvidenceRelatedRef {
                    kind: "seed".to_string(),
                    id: stable_id.to_string(),
                }],
            },
            payload_sha256: format!("payload-{stable_id}"),
            canonical_payload: format!(r#"{{"stable_id":"{stable_id}"}}"#),
            signature: EvidenceSignature {
                signer_id: "local-evidence-signer".to_string(),
                algorithm: "ed25519".to_string(),
                key_id: "key:red".to_string(),
                public_key_hex: "11".repeat(32),
                signature_hex: "22".repeat(64),
            },
        }
    }

    fn sample_verification(
        bundle_id: &str,
        subject_kind: EvidenceSubjectKind,
        subject_id: &str,
    ) -> EvidenceVerificationReport {
        EvidenceVerificationReport {
            verification_id: format!("evidence_verification:{bundle_id}"),
            bundle_id: bundle_id.to_string(),
            subject_kind,
            subject_id: subject_id.to_string(),
            verified_at_ms: 1_710_000_000_500,
            status: EvidenceVerificationStatus::Passed,
            signer_id: "local-evidence-signer".to_string(),
            signer_key_id: "key:red".to_string(),
            expected_key_id: Some("key:red".to_string()),
            checks: vec![],
        }
    }

    async fn seed_runtime_artifacts(config_path: &PathBuf) -> String {
        let plane = DefaultControlPlane::from_path(config_path).unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let agent_id = AgentId::from_verifying_key(&signing_key.verifying_key());
        let processed = plane
            .stack
            .process_event(
                &SuspiciousProcessTreeDetector::default(),
                &event("evt-evidence-1"),
                EventExecutionContext {
                    agent_id: &agent_id,
                    approval: &approval_context(1_710_000_000_001),
                    signing_key: &signing_key,
                },
                |_finding| {
                    Some(swarm_core::types::ResponseAction::DeployDecoy {
                        decoy_type: "honeypot".to_string(),
                        target_zone: "dmz".to_string(),
                    })
                },
            )
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let _ = plane.stack.correlate_hunt("evt-evidence-1").unwrap();
        processed.replay.record.bundle_id
    }

    #[tokio::test]
    async fn replay_bundle_exports_as_signed_evidence() {
        let root = unique_temp_dir("export-replay");
        let config_path = write_config(&root);
        let replay_bundle_id = seed_runtime_artifacts(&config_path).await;
        let evidence =
            DefaultEvidenceHarness::from_path(&config_path, evidence_paths(&root)).unwrap();

        let lookup = evidence
            .export_bundle(EvidenceExportRequest {
                subject_kind: EvidenceSubjectKind::ReplayBundle,
                stable_id: replay_bundle_id.clone(),
                signer_id: "local-evidence-signer".to_string(),
                secret_material: "phase56-test-key".to_string(),
            })
            .unwrap();

        assert_eq!(
            lookup.bundle.subject.kind,
            EvidenceSubjectKind::ReplayBundle
        );
        assert_eq!(lookup.bundle.subject.stable_id, replay_bundle_id);
        assert!(!lookup.bundle.signature.signature_hex.is_empty());

        let list = evidence
            .list_bundles(Some(EvidenceSubjectKind::ReplayBundle))
            .unwrap();
        assert_eq!(list.total_count, 1);
        assert_eq!(list.bundles[0].latest_verification_status, None);
    }

    #[tokio::test]
    async fn verification_fails_when_canonical_payload_is_tampered() {
        let root = unique_temp_dir("verify-tamper");
        let config_path = write_config(&root);
        let replay_bundle_id = seed_runtime_artifacts(&config_path).await;
        let evidence =
            DefaultEvidenceHarness::from_path(&config_path, evidence_paths(&root)).unwrap();

        let lookup = evidence
            .export_bundle(EvidenceExportRequest {
                subject_kind: EvidenceSubjectKind::ReplayBundle,
                stable_id: replay_bundle_id,
                signer_id: "local-evidence-signer".to_string(),
                secret_material: "phase56-test-key".to_string(),
            })
            .unwrap();

        let report_path = PathBuf::from(&lookup.record.bundle_path);
        let mut raw: Value =
            serde_json::from_str(&fs::read_to_string(&report_path).unwrap()).unwrap();
        raw["canonical_payload"] = Value::String(r#"{"tampered":true}"#.to_string());
        fs::write(&report_path, serde_json::to_string_pretty(&raw).unwrap()).unwrap();

        let verification = evidence
            .verify_bundle(&lookup.bundle.bundle_id, None)
            .unwrap();
        assert_eq!(
            verification.report.status,
            EvidenceVerificationStatus::Failed
        );
        assert!(verification.report.checks.iter().any(|check| !check.passed));
    }

    #[tokio::test]
    async fn promotion_evidence_packet_uses_supporting_bundle_verifications() {
        let root = unique_temp_dir("promotion-packet");
        let config_path = write_config(&root);
        let paths = evidence_paths(&root);
        let evidence = DefaultEvidenceHarness::from_path(&config_path, paths.clone()).unwrap();

        FileProductionPromotionStore::open(&paths.promotion_results_dir)
            .unwrap()
            .persist(&sample_promotion_report())
            .unwrap();

        let bundle_store = FileEvidenceBundleStore::open(&paths.evidence_results_dir).unwrap();
        let verification_store =
            FileEvidenceVerificationStore::open(&paths.evidence_verification_results_dir).unwrap();
        for (kind, stable_id) in [
            (EvidenceSubjectKind::ProductionPromotion, "promotion:red"),
            (EvidenceSubjectKind::CanaryRun, "canary:red"),
            (
                EvidenceSubjectKind::DetectorVerification,
                "verification:red",
            ),
            (EvidenceSubjectKind::StrategyShadow, "shadow:red"),
        ] {
            let bundle = sample_bundle(kind, stable_id);
            let bundle_lookup = bundle_store.persist(&bundle).unwrap();
            let verification =
                sample_verification(&bundle_lookup.record.bundle_id, kind, stable_id);
            let verification_lookup = verification_store.persist(&verification).unwrap();
            bundle_store
                .attach_verification(&verification_lookup.record, &bundle_lookup.record.bundle_id)
                .unwrap();
        }

        let packet = evidence
            .create_promotion_evidence_packet("promotion:red")
            .unwrap();
        assert_eq!(
            packet.packet.recommendation,
            PromotionEvidenceRecommendation::ReadyForExternalReview
        );
        assert!(packet.packet.blocking_reasons.is_empty());
        assert_eq!(packet.packet.supporting_evidence.len(), 4);
    }
}
