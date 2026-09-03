use chrono::{DateTime, SecondsFormat, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{Arc, Barrier, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_crypto::{
    CryptoError, DetachedSignature, Ed25519Signer, Keypair, canonical_json_bytes, sha256,
    sha256_hex, verify_detached_signature,
};
use swarm_spine::{AuditTrail, SpineError, build_signed_envelope, verify_envelope};

/// Maximum accepted lead of a voter-authenticated timestamp over host time.
pub const MAX_APPROVAL_VOTE_FUTURE_SKEW_MS: i64 = 30_000;
/// Current durable approval-ledger wire schema.
pub const CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION: u32 = 2;
const LEGACY_APPROVAL_LEDGER_SCHEMA_VERSION: u32 = 1;
/// Current durable approval-verdict wire schema.
pub const CURRENT_APPROVAL_VERDICT_SCHEMA_VERSION: u32 = 2;
const LEGACY_APPROVAL_VERDICT_SCHEMA_VERSION: u32 = 1;

const fn legacy_approval_ledger_schema_version() -> u32 {
    LEGACY_APPROVAL_LEDGER_SCHEMA_VERSION
}

const fn legacy_approval_verdict_schema_version() -> u32 {
    LEGACY_APPROVAL_VERDICT_SCHEMA_VERSION
}

/// Signature payload generation used by a portable approval receipt pack.
///
/// Missing values deserialize as `LegacyV1` so a pre-versioning pack can be
/// classified as verified-retired or authenticated-core-only quarantine. V1
/// packs are never accepted as current approval authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalReceiptPackSignatureVersion {
    #[default]
    LegacyV1,
    V2,
}

/// Signature payload generation used by one approval entry.
///
/// Missing values deserialize as `LegacyV1` so pre-versioning artifacts can be
/// retained as audit history without ever being counted as approval authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalVoteSignatureVersion {
    #[default]
    LegacyV1,
    IntentV2,
}

/// Approval vote persisted on a ledger entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalVote {
    #[default]
    Approve,
    Reject,
}

impl ApprovalVote {
    fn is_approve(self) -> bool {
        matches!(self, Self::Approve)
    }
}

/// Threshold rule used to determine whether a ledger has quorum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdRule {
    AtLeast { required: usize },
    Majority,
    Unanimous,
}

impl ThresholdRule {
    pub fn is_met(&self, count: usize) -> bool {
        count >= self.required_count()
    }

    pub fn required_count(&self) -> usize {
        match self {
            Self::AtLeast { required } => *required,
            Self::Majority | Self::Unanimous => 0,
        }
    }

    pub fn required_count_for(&self, eligible_count: usize) -> usize {
        match self {
            Self::AtLeast { required } => *required,
            Self::Majority => (eligible_count / 2) + 1,
            Self::Unanimous => eligible_count,
        }
    }

    pub fn is_met_for(
        &self,
        approve_count: usize,
        reject_count: usize,
        eligible_count: usize,
    ) -> bool {
        match self {
            Self::AtLeast { required } => approve_count >= *required,
            Self::Majority => approve_count >= self.required_count_for(eligible_count),
            Self::Unanimous => reject_count == 0 && approve_count == eligible_count,
        }
    }
}

/// Durable approval-set artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSetReport {
    pub set_id: String,
    pub eligible_voters: Vec<String>,
    pub threshold: ThresholdRule,
    pub promotion_evidence_ref: String,
    pub created_at_ms: i64,
}

/// Lightweight metadata for a persisted approval set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSetRecord {
    pub set_id: String,
    pub report_digest: String,
    pub voter_count: usize,
    pub threshold: ThresholdRule,
    pub promotion_evidence_ref: String,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl ApprovalSetRecord {
    fn from_report(report: &ApprovalSetReport, bundle_path: String) -> Result<Self, CryptoError> {
        Ok(Self {
            set_id: report.set_id.clone(),
            report_digest: approval_set_report_digest(report)?,
            voter_count: report.eligible_voters.len(),
            threshold: report.threshold.clone(),
            promotion_evidence_ref: report.promotion_evidence_ref.clone(),
            created_at_ms: report.created_at_ms,
            bundle_path,
        })
    }
}

/// One signed vote entry appended to an approval ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalLedgerEntry {
    pub entry_id: String,
    pub voter_id: String,
    #[serde(default)]
    pub vote: ApprovalVote,
    #[serde(default)]
    pub signature_version: ApprovalVoteSignatureVersion,
    pub signature: DetachedSignature,
    pub timestamp_ms: i64,
    #[serde(default)]
    pub previous_envelope_hash: Option<String>,
    pub envelope_hash: String,
}

/// Canonical, voter-authenticated intent for one append-only ledger entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalVoteIntent {
    pub signature_version: ApprovalVoteSignatureVersion,
    pub approval_set_id: String,
    pub ledger_id: String,
    pub entry_id: String,
    pub voter_id: String,
    pub vote: ApprovalVote,
    pub timestamp_ms: i64,
    pub previous_envelope_hash: Option<String>,
}

/// Durable approval-ledger artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalLedgerReport {
    #[serde(default = "legacy_approval_ledger_schema_version")]
    pub schema_version: u32,
    pub ledger_id: String,
    pub approval_set_id: String,
    pub entries: Vec<ApprovalLedgerEntry>,
    pub created_at_ms: i64,
}

/// Lightweight metadata for a persisted approval ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalLedgerRecord {
    pub ledger_id: String,
    pub approval_set_id: String,
    pub vote_count: usize,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl ApprovalLedgerRecord {
    fn from_report(report: &ApprovalLedgerReport, bundle_path: String) -> Self {
        Self {
            ledger_id: report.ledger_id.clone(),
            approval_set_id: report.approval_set_id.clone(),
            vote_count: report.entries.len(),
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Current quorum state for one approval ledger against its owning approval set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalLedgerQuorumState {
    pub votes_received: usize,
    pub votes_required: usize,
    pub voters_remaining: Vec<String>,
    pub quorum_met: bool,
}

impl ApprovalLedgerQuorumState {
    pub fn from_ledger_and_set(ledger: &ApprovalLedgerReport, set: &ApprovalSetReport) -> Self {
        let approved_voters = ledger
            .entries
            .iter()
            .filter(|entry| {
                entry.signature_version == ApprovalVoteSignatureVersion::IntentV2
                    && entry.vote.is_approve()
            })
            .map(|entry| entry.voter_id.as_str())
            .collect::<HashSet<_>>();
        let reject_count = ledger
            .entries
            .iter()
            .filter(|entry| {
                entry.signature_version == ApprovalVoteSignatureVersion::IntentV2
                    && !entry.vote.is_approve()
            })
            .count();
        let votes_received = approved_voters.len();
        let votes_required = set.threshold.required_count_for(set.eligible_voters.len());
        let voters_remaining = set
            .eligible_voters
            .iter()
            .filter(|voter_id| !approved_voters.contains(voter_id.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let quorum_met =
            set.threshold
                .is_met_for(votes_received, reject_count, set.eligible_voters.len());

        Self {
            votes_received,
            votes_required,
            voters_remaining,
            quorum_met,
        }
    }
}

/// Persisted approval set loaded with metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalSetLookup {
    pub record: ApprovalSetRecord,
    pub report: ApprovalSetReport,
}

/// Persisted approval ledger loaded with metadata and computed quorum state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalLedgerLookup {
    pub record: ApprovalLedgerRecord,
    pub report: ApprovalLedgerReport,
    pub quorum_state: ApprovalLedgerQuorumState,
}

/// The durable transition identity returned by one signed-vote append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalLedgerVoteTransition {
    Pending,
    QuorumCrossed,
    ExactDuplicatePending,
    ExactDuplicateOfQuorum,
}

/// The exact ledger image and transition identity committed by one vote call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalLedgerVoteOutcome {
    pub ledger: ApprovalLedgerLookup,
    pub transition: ApprovalLedgerVoteTransition,
}

/// Operator-facing approval-set listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSetList {
    pub total_count: usize,
    pub sets: Vec<ApprovalSetRecord>,
}

/// Operator-facing approval-ledger listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalLedgerList {
    pub total_count: usize,
    pub approval_set_id: Option<String>,
    pub ledgers: Vec<ApprovalLedgerRecord>,
}

/// Deterministic verdict status computed from an approval ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalVerdictStatus {
    Approved,
    NotApproved,
}

/// Durable approval verdict artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalVerdictReport {
    #[serde(default = "legacy_approval_verdict_schema_version")]
    pub schema_version: u32,
    pub verdict_id: String,
    pub approval_set_id: String,
    pub ledger_id: String,
    pub status: ApprovalVerdictStatus,
    pub approve_count: usize,
    pub reject_count: usize,
    pub threshold_required: String,
    pub threshold_required_count: usize,
    pub eligible_count: usize,
    pub missing_voters: Vec<String>,
    pub evaluated_at_ms: i64,
}

/// Lightweight metadata for a persisted approval verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalVerdictRecord {
    pub verdict_id: String,
    pub approval_set_id: String,
    pub ledger_id: String,
    pub status: ApprovalVerdictStatus,
    pub approve_count: usize,
    pub reject_count: usize,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl ApprovalVerdictRecord {
    fn from_report(report: &ApprovalVerdictReport, bundle_path: String) -> Self {
        Self {
            verdict_id: report.verdict_id.clone(),
            approval_set_id: report.approval_set_id.clone(),
            ledger_id: report.ledger_id.clone(),
            status: report.status,
            approve_count: report.approve_count,
            reject_count: report.reject_count,
            created_at_ms: report.evaluated_at_ms,
            bundle_path,
        }
    }
}

/// Persisted approval verdict loaded with metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalVerdictLookup {
    pub record: ApprovalVerdictRecord,
    pub report: ApprovalVerdictReport,
}

/// Operator-facing approval verdict listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalVerdictList {
    pub total_count: usize,
    pub verdicts: Vec<ApprovalVerdictRecord>,
}

/// Signed, portable receipt pack bundling approval lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalReceiptPackReport {
    #[serde(default)]
    pub signature_version: ApprovalReceiptPackSignatureVersion,
    pub pack_id: String,
    pub signer_id: String,
    pub approval_set: ApprovalSetReport,
    pub ledger: ApprovalLedgerReport,
    pub verdict: ApprovalVerdictReport,
    pub audit_refs: Vec<String>,
    pub content_hash: String,
    pub signature: DetachedSignature,
    pub created_at_ms: i64,
}

/// Lightweight metadata for a persisted approval receipt pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalReceiptPackRecord {
    pub pack_id: String,
    pub verdict_id: String,
    pub approval_set_id: String,
    pub ledger_id: String,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl ApprovalReceiptPackRecord {
    fn from_report(report: &ApprovalReceiptPackReport, bundle_path: String) -> Self {
        Self {
            pack_id: report.pack_id.clone(),
            verdict_id: report.verdict.verdict_id.clone(),
            approval_set_id: report.approval_set.set_id.clone(),
            ledger_id: report.ledger.ledger_id.clone(),
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted approval receipt pack loaded with metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalReceiptPackLookup {
    pub record: ApprovalReceiptPackRecord,
    pub report: ApprovalReceiptPackReport,
}

/// Observable, non-authoritative receipt artifact whose signed V1 core is
/// intact but whose surrounding identity and time metadata was never signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalReceiptPackQuarantineRecord {
    pub observed_pack_id: String,
    pub observed_signer_id: String,
    pub observed_created_at_ms: i64,
    pub signature_key_id: String,
    pub authenticated_core_hash: String,
    pub observed_bundle_path: String,
    pub reason: String,
}

/// Operator-facing approval receipt-pack listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalReceiptPackList {
    pub total_count: usize,
    pub packs: Vec<ApprovalReceiptPackRecord>,
    pub quarantined_count: usize,
    pub quarantined: Vec<ApprovalReceiptPackQuarantineRecord>,
}

/// Errors raised by the persisted approval-set store.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalSetStoreError {
    #[error("failed to read approval set store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write approval set store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse approval set store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("invalid persisted approval set: {reason}")]
    Invalid { reason: String },

    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Errors raised by the persisted approval-ledger store.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalLedgerStoreError {
    #[error("failed to read approval ledger store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write approval ledger store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse approval ledger store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted approval-verdict store.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalVerdictStoreError {
    #[error(
        "refusing to persist approval verdict `{verdict_id}` with non-current schema `{schema_version}`"
    )]
    UnsupportedSchema {
        verdict_id: String,
        schema_version: u32,
    },

    #[error("refusing to persist nonterminal approval verdict `{verdict_id}`")]
    NonTerminalVerdict { verdict_id: String },

    #[error("failed to read approval verdict store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write approval verdict store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse approval verdict store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted approval receipt-pack store.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalReceiptPackStoreError {
    #[error("refusing to persist receipt pack `{pack_id}` with a legacy signature payload")]
    LegacySignaturePayload { pack_id: String },

    #[error("failed to read approval receipt-pack store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write approval receipt-pack store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse approval receipt-pack store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("approval resume outcome for receipt pack `{pack_id}` conflicts with durable state")]
    ResumeOutcomeConflict { pack_id: String },
}

/// Errors surfaced by approval workflows.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("approval set `{set_id}` was not found")]
    ApprovalSetNotFound { set_id: String },

    #[error("approval ledger `{ledger_id}` was not found")]
    ApprovalLedgerNotFound { ledger_id: String },

    #[error("approval verdict `{verdict_id}` was not found")]
    ApprovalVerdictNotFound { verdict_id: String },

    #[error("approval receipt pack `{pack_id}` was not found")]
    ApprovalReceiptPackNotFound { pack_id: String },

    #[error("approval set `{set_id}` does not have a ledger")]
    MissingLedgerForSet { set_id: String },

    #[error("approval set `{set_id}` has {count} ledgers; expected exactly one")]
    AmbiguousLedgerForSet { set_id: String, count: usize },

    #[error("invalid approval set request: {reason}")]
    InvalidApprovalSetRequest { reason: String },

    #[error("invalid approval ledger request: {reason}")]
    InvalidLedgerRequest { reason: String },

    #[error("invalid approval verdict request: {reason}")]
    InvalidVerdictRequest { reason: String },

    #[error("invalid approval receipt pack: {reason}")]
    InvalidReceiptPack { reason: String },

    #[error("approval evidence `{evidence_ref}` has {count} persisted sets; expected at most one")]
    AmbiguousApprovalEvidence { evidence_ref: String, count: usize },

    #[error(
        "persisted approval evidence `{evidence_ref}` conflicts with the requested voters or threshold"
    )]
    ApprovalEvidenceConflict { evidence_ref: String },

    #[error("approval set `{set_id}` cannot recover its ledger: {reason}")]
    LedgerRecoveryConflict { set_id: String, reason: String },

    #[error("approval verdict stores are not configured")]
    VerdictStoreNotConfigured,

    #[error("approval receipt-pack stores are not configured")]
    ReceiptPackStoreNotConfigured,

    #[error("signing key env `{env_name}` is missing or empty")]
    MissingSigningKey { env_name: String },

    #[error("failed to acquire approval workflow lock `{path}`: {source}")]
    WorkflowLock {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("approval ledger `{ledger_id}` already met quorum")]
    QuorumAlreadyMet { ledger_id: String },

    #[error("duplicate vote from voter `{voter_id}`")]
    DuplicateVoter { voter_id: String },

    #[error("ineligible voter `{voter_id}`")]
    IneligibleVoter { voter_id: String },

    #[error("invalid signature for voter `{voter_id}`: {reason}")]
    InvalidSignature { voter_id: String, reason: String },

    #[error(transparent)]
    SetStore(#[from] ApprovalSetStoreError),

    #[error(transparent)]
    LedgerStore(#[from] ApprovalLedgerStoreError),

    #[error(transparent)]
    VerdictStore(#[from] ApprovalVerdictStoreError),

    #[error(transparent)]
    ReceiptPackStore(#[from] ApprovalReceiptPackStoreError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Spine(#[from] SpineError),
}

/// Cross-process lock covering the approval ledger and its derived artifacts.
///
/// Approval handlers may be constructed more than once, including in separate
/// processes. The lock therefore lives in the artifact directory and uses the
/// operating system's advisory file-lock primitive rather than process-local
/// state. Every read/modify/write transition that can mint approval artifacts
/// holds this lock for its complete durable transition.
struct ApprovalWorkflowLock {
    file: File,
    path: PathBuf,
    identity: String,
}

impl ApprovalWorkflowLock {
    fn acquire(path: PathBuf) -> Result<Self, ApprovalError> {
        match fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(workflow_lock_error(
                    &path,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "workflow lock must be a regular non-symlink file",
                    ),
                ));
            }
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(workflow_lock_error(&path, source));
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| workflow_lock_error(&path, source))?;

        let identity = verify_workflow_lock_path(&path, &file)
            .map_err(|source| workflow_lock_error(&path, source))?;

        file.lock()
            .map_err(|source| workflow_lock_error(&path, source))?;

        let locked_identity = verify_workflow_lock_path(&path, &file)
            .map_err(|source| workflow_lock_error(&path, source))?;
        if locked_identity != identity {
            return Err(workflow_lock_error(
                &path,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "workflow lock identity changed while acquiring",
                ),
            ));
        }
        bind_workflow_lock_identity(&path, &identity)
            .map_err(|source| workflow_lock_error(&path, source))?;

        let lock = Self {
            file,
            path,
            identity,
        };
        lock.verify()?;
        Ok(lock)
    }

    fn verify(&self) -> Result<(), ApprovalError> {
        let identity = verify_workflow_lock_path(&self.path, &self.file)
            .map_err(|source| workflow_lock_error(&self.path, source))?;
        if identity != self.identity {
            return Err(workflow_lock_error(
                &self.path,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "workflow lock identity changed during transition",
                ),
            ));
        }
        verify_workflow_lock_binding(&self.path, &self.identity)
            .map_err(|source| workflow_lock_error(&self.path, source))
    }
}

impl Drop for ApprovalWorkflowLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn workflow_lock_error(path: &Path, source: io::Error) -> ApprovalError {
    ApprovalError::WorkflowLock {
        path: path.to_path_buf(),
        source,
    }
}

fn workflow_lock_identity_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("approval-workflow.lock");
    path.with_file_name(format!("{name}.identity"))
}

fn verify_workflow_lock_path(path: &Path, file: &File) -> io::Result<String> {
    let descriptor_metadata = file.metadata()?;
    if !descriptor_metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workflow lock descriptor is not a regular file",
        ));
    }
    let named_metadata = fs::symlink_metadata(path)?;
    if !named_metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workflow lock path is not a regular non-symlink file",
        ));
    }
    let identity = workflow_lock_file_identity(&descriptor_metadata);
    if identity != workflow_lock_file_identity(&named_metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workflow lock path changed while opening",
        ));
    }
    let final_named_metadata = fs::symlink_metadata(path)?;
    if !final_named_metadata.file_type().is_file()
        || identity != workflow_lock_file_identity(&final_named_metadata)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workflow lock path changed while verifying",
        ));
    }
    Ok(identity)
}

#[cfg(unix)]
fn workflow_lock_file_identity(metadata: &fs::Metadata) -> String {
    format!("unix:{}:{}", metadata.dev(), metadata.ino())
}

#[cfg(windows)]
fn workflow_lock_file_identity(metadata: &fs::Metadata) -> String {
    format!(
        "windows:{}:{}",
        metadata.volume_serial_number().unwrap_or_default(),
        metadata.file_index().unwrap_or_default()
    )
}

#[cfg(not(any(unix, windows)))]
fn workflow_lock_file_identity(metadata: &fs::Metadata) -> String {
    let modified_ms = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_millis())
        .unwrap_or_default();
    format!("other:{}:{modified_ms}", metadata.len())
}

fn bind_workflow_lock_identity(path: &Path, identity: &str) -> io::Result<()> {
    let binding_path = workflow_lock_identity_path(path);
    match fs::symlink_metadata(&binding_path) {
        Ok(metadata) if !metadata.file_type().is_file() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workflow lock identity must be a regular non-symlink file",
        )),
        Ok(_) => verify_workflow_lock_binding(path, identity),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&binding_path)?;
            file.write_all(identity.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            verify_workflow_lock_binding(path, identity)
        }
        Err(source) => Err(source),
    }
}

fn verify_workflow_lock_binding(path: &Path, identity: &str) -> io::Result<()> {
    let binding_path = workflow_lock_identity_path(path);
    let file = File::open(&binding_path)?;
    let descriptor_metadata = file.metadata()?;
    if !descriptor_metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workflow lock identity is not a regular non-symlink file",
        ));
    }
    let named_metadata = fs::symlink_metadata(&binding_path)?;
    if !named_metadata.file_type().is_file()
        || workflow_lock_file_identity(&descriptor_metadata)
            != workflow_lock_file_identity(&named_metadata)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workflow lock identity path changed while opening",
        ));
    }
    let mut file = file;
    let mut stored = String::new();
    file.read_to_string(&mut stored)?;
    if stored.trim() != identity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workflow lock identity binding changed",
        ));
    }
    let final_named_metadata = fs::symlink_metadata(&binding_path)?;
    if !final_named_metadata.file_type().is_file()
        || workflow_lock_file_identity(&descriptor_metadata)
            != workflow_lock_file_identity(&final_named_metadata)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workflow lock identity path changed while verifying",
        ));
    }
    Ok(())
}

/// Identity-aware snapshot for every file participating in an approval
/// transition. Store bytes alone are not sufficient: restoring through a
/// pathname that was replaced after the lock precheck could overwrite an
/// unrelated file. The lock and its identity sidecar are captured explicitly
/// and are restored only while their original identities and ownership remain
/// bound to the names held by the transition.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ApprovalWorkflowFileSnapshot {
    bytes: Vec<u8>,
    identity: String,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
}

impl ApprovalWorkflowFileSnapshot {
    fn matches_metadata(&self, metadata: &fs::Metadata) -> bool {
        metadata.file_type().is_file()
            && workflow_lock_file_identity(metadata) == self.identity
            && self.matches_ownership(metadata)
    }

    #[cfg(unix)]
    fn matches_ownership(&self, metadata: &fs::Metadata) -> bool {
        metadata.permissions().mode() == self.mode
            && metadata.uid() == self.uid
            && metadata.gid() == self.gid
    }

    #[cfg(not(unix))]
    fn matches_ownership(&self, _metadata: &fs::Metadata) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
struct ApprovalWorkflowSnapshot {
    roots: Vec<PathBuf>,
    files: BTreeMap<PathBuf, ApprovalWorkflowFileSnapshot>,
    lock_paths: [PathBuf; 2],
}

impl ApprovalWorkflowSnapshot {
    fn capture(roots: Vec<PathBuf>, lock_path: PathBuf) -> io::Result<Self> {
        let lock_identity_path = workflow_lock_identity_path(&lock_path);
        let lock_paths = [lock_path, lock_identity_path];
        let mut files = BTreeMap::new();
        for root in &roots {
            capture_snapshot_store_files(root, &mut files)?;
        }
        for path in &lock_paths {
            let snapshot = capture_workflow_snapshot_file(path)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("workflow lock artifact `{}` disappeared", path.display()),
                )
            })?;
            files.insert(path.clone(), snapshot);
        }
        Ok(Self {
            roots,
            files,
            lock_paths,
        })
    }

    fn verify_lock_state(&self) -> io::Result<()> {
        for path in &self.lock_paths {
            let expected = self.files.get(path).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("workflow lock snapshot omitted `{}`", path.display()),
                )
            })?;
            let actual = capture_workflow_snapshot_file(path)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("workflow lock artifact `{}` disappeared", path.display()),
                )
            })?;
            if actual != *expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "workflow lock artifact `{}` changed during transition",
                        path.display()
                    ),
                ));
            }
        }
        Ok(())
    }

    fn restore(&self) -> io::Result<()> {
        let mut current = BTreeMap::new();
        for root in &self.roots {
            capture_snapshot_store_files(root, &mut current)?;
        }
        let mut first_error = None;
        for path in current.keys() {
            if !self.files.contains_key(path) {
                let metadata = fs::symlink_metadata(path)?;
                if !metadata.file_type().is_file() {
                    remember_snapshot_error(
                        &mut first_error,
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "cannot remove non-regular approval artifact `{}`",
                                path.display()
                            ),
                        ),
                    );
                    continue;
                }
                if let Err(error) = fs::remove_file(path) {
                    remember_snapshot_error(&mut first_error, error);
                }
            }
        }
        for (path, expected) in &self.files {
            if self.lock_paths.iter().any(|lock_path| lock_path == path) {
                continue;
            }
            if let Err(error) = restore_workflow_snapshot_file(path, expected) {
                remember_snapshot_error(&mut first_error, error);
            }
        }
        for path in &self.lock_paths {
            let expected = self.files.get(path).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("workflow lock snapshot omitted `{}`", path.display()),
                )
            })?;
            match capture_workflow_snapshot_file(path)? {
                Some(actual) if actual.identity == expected.identity => {
                    if let Err(error) = restore_workflow_snapshot_file(path, expected) {
                        remember_snapshot_error(&mut first_error, error);
                    }
                }
                Some(_) | None => remember_snapshot_error(
                    &mut first_error,
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "workflow lock artifact `{}` identity changed during rollback",
                            path.display()
                        ),
                    ),
                ),
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn remember_snapshot_error(first_error: &mut Option<io::Error>, error: io::Error) {
    if first_error.is_none() {
        *first_error = Some(error);
    }
}

fn capture_snapshot_store_files(
    root: &Path,
    files: &mut BTreeMap<PathBuf, ApprovalWorkflowFileSnapshot>,
) -> io::Result<()> {
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "approval store root `{}` is not a regular directory",
                root.display()
            ),
        ));
    }
    capture_snapshot_store_file(&root.join("index.json"), files)?;
    let reports = root.join("reports");
    let reports_metadata = fs::symlink_metadata(&reports)?;
    if !reports_metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "approval report directory `{}` is not a regular directory",
                reports.display()
            ),
        ));
    }
    for entry in fs::read_dir(&reports)? {
        capture_snapshot_store_file(&entry?.path(), files)?;
    }
    let resume_outcomes = root.join("resume-outcomes");
    match fs::symlink_metadata(&resume_outcomes) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            for entry in fs::read_dir(&resume_outcomes)? {
                capture_snapshot_store_file(&entry?.path(), files)?;
            }
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "approval resume-outcome directory `{}` is not a regular directory",
                    resume_outcomes.display()
                ),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

fn capture_snapshot_store_file(
    path: &Path,
    files: &mut BTreeMap<PathBuf, ApprovalWorkflowFileSnapshot>,
) -> io::Result<()> {
    if let Some(snapshot) = capture_workflow_snapshot_file(path)? {
        files.insert(path.to_path_buf(), snapshot);
    }
    Ok(())
}

fn capture_workflow_snapshot_file(path: &Path) -> io::Result<Option<ApprovalWorkflowFileSnapshot>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "approval artifact `{}` is not a regular file",
                path.display()
            ),
        ));
    }
    let bytes = fs::read(path)?;
    let final_metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || workflow_lock_file_identity(&metadata) != workflow_lock_file_identity(&final_metadata)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "approval artifact `{}` changed while being snapshotted",
                path.display()
            ),
        ));
    }
    Ok(Some(ApprovalWorkflowFileSnapshot {
        bytes,
        identity: workflow_lock_file_identity(&final_metadata),
        #[cfg(unix)]
        mode: final_metadata.permissions().mode(),
        #[cfg(unix)]
        uid: final_metadata.uid(),
        #[cfg(unix)]
        gid: final_metadata.gid(),
    }))
}

fn restore_workflow_snapshot_file(
    path: &Path,
    expected: &ApprovalWorkflowFileSnapshot,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "approval artifact `{}` disappeared during rollback",
                    path.display()
                ),
            )
        } else {
            error
        }
    })?;
    if !expected.matches_metadata(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "approval artifact `{}` identity or ownership changed during rollback",
                path.display()
            ),
        ));
    }
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let descriptor_metadata = file.metadata()?;
    let named_metadata = fs::symlink_metadata(path)?;
    if !expected.matches_metadata(&descriptor_metadata)
        || !expected.matches_metadata(&named_metadata)
        || workflow_lock_file_identity(&descriptor_metadata)
            != workflow_lock_file_identity(&named_metadata)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "approval artifact `{}` changed before rollback write",
                path.display()
            ),
        ));
    }
    file.set_len(0)?;
    file.write_all(&expected.bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(expected.mode))?;
    let restored = capture_workflow_snapshot_file(path)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "approval artifact `{}` disappeared after rollback",
                path.display()
            ),
        )
    })?;
    if restored != *expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "approval artifact `{}` did not restore exactly",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn capture_store_files(root: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) -> io::Result<()> {
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "approval store root `{}` is not a regular directory",
                root.display()
            ),
        ));
    }
    capture_store_file(&root.join("index.json"), files)?;
    let reports = root.join("reports");
    let reports_metadata = fs::symlink_metadata(&reports)?;
    if !reports_metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "approval report directory `{}` is not a regular directory",
                reports.display()
            ),
        ));
    }
    for entry in fs::read_dir(&reports)? {
        let path = entry?.path();
        capture_store_file(&path, files)?;
    }
    let resume_outcomes = root.join("resume-outcomes");
    match fs::symlink_metadata(&resume_outcomes) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            for entry in fs::read_dir(&resume_outcomes)? {
                capture_store_file(&entry?.path(), files)?;
            }
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "approval resume-outcome directory `{}` is not a regular directory",
                    resume_outcomes.display()
                ),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

#[cfg(test)]
fn capture_store_file(path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "approval artifact `{}` is not a regular file",
                path.display()
            ),
        ));
    }
    files.insert(path.to_path_buf(), fs::read(path)?);
    Ok(())
}

#[cfg(test)]
struct WorkflowTestHook {
    lock_path: PathBuf,
    reached: Arc<Barrier>,
    release: Arc<Barrier>,
}

#[cfg(test)]
static WORKFLOW_TEST_HOOK: OnceLock<Mutex<Option<WorkflowTestHook>>> = OnceLock::new();

#[cfg(test)]
fn workflow_test_hook_cell() -> &'static Mutex<Option<WorkflowTestHook>> {
    WORKFLOW_TEST_HOOK.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn install_workflow_test_hook(lock_path: PathBuf, reached: Arc<Barrier>, release: Arc<Barrier>) {
    let mut hook = match workflow_test_hook_cell().lock() {
        Ok(hook) => hook,
        Err(poisoned) => poisoned.into_inner(),
    };
    *hook = Some(WorkflowTestHook {
        lock_path,
        reached,
        release,
    });
}

#[cfg(test)]
fn wait_for_workflow_test_hook(lock_path: &Path) {
    let hook = match workflow_test_hook_cell().lock() {
        Ok(mut hook)
            if hook
                .as_ref()
                .is_some_and(|candidate| candidate.lock_path == lock_path) =>
        {
            hook.take()
        }
        Err(poisoned) => {
            let mut hook = poisoned.into_inner();
            if hook
                .as_ref()
                .is_some_and(|candidate| candidate.lock_path == lock_path)
            {
                hook.take()
            } else {
                None
            }
        }
        Ok(_) => None,
    };
    if let Some(hook) = hook {
        hook.reached.wait();
        hook.release.wait();
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ApprovalSetIndex {
    entries: Vec<ApprovalSetRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ApprovalLedgerIndex {
    entries: Vec<ApprovalLedgerRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ApprovalVerdictIndex {
    entries: Vec<ApprovalVerdictRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ApprovalReceiptPackIndex {
    entries: Vec<ApprovalReceiptPackRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalResumeOutcome {
    schema_version: u32,
    receipt_pack_id: String,
    audit: AuditTrail,
}

/// File-backed store for approval sets.
#[derive(Debug, Clone)]
pub struct FileApprovalSetStore {
    root: PathBuf,
}

impl FileApprovalSetStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApprovalSetStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ApprovalSetStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, set_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(set_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ApprovalSetIndex, ApprovalSetStoreError> {
        read_json_or_default::<ApprovalSetIndex, ApprovalSetStoreError>(
            &self.index_path(),
            |path, source| ApprovalSetStoreError::Read { path, source },
            |path, source| ApprovalSetStoreError::Parse { path, source },
        )
    }

    fn write_index(&self, index: &ApprovalSetIndex) -> Result<(), ApprovalSetStoreError> {
        write_pretty_json(
            &self.index_path(),
            index,
            |path, source| ApprovalSetStoreError::Write { path, source },
            |path, source| ApprovalSetStoreError::Parse { path, source },
        )
    }

    pub fn persist(
        &self,
        report: &ApprovalSetReport,
    ) -> Result<ApprovalSetRecord, ApprovalSetStoreError> {
        let path = self.report_path(&report.set_id);
        write_pretty_json(
            &path,
            report,
            |path, source| ApprovalSetStoreError::Write { path, source },
            |path, source| ApprovalSetStoreError::Parse { path, source },
        )?;

        let record = ApprovalSetRecord::from_report(report, path.display().to_string())?;
        let mut index = self.read_index()?;
        index.entries.retain(|entry| entry.set_id != record.set_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    /// Reconcile reports that became durable before their index update. This
    /// runs only while the workflow lock is held, so a retry observes the
    /// original canonical set instead of minting a sibling after a crash.
    fn reconcile_unindexed_reports(&self) -> Result<(), ApprovalSetStoreError> {
        let mut index = self.read_index()?;
        let mut records = BTreeMap::new();
        for record in &index.entries {
            if records
                .insert(record.set_id.clone(), record.clone())
                .is_some()
            {
                return Err(ApprovalSetStoreError::Invalid {
                    reason: format!(
                        "approval set index contains duplicate record `{}`",
                        record.set_id
                    ),
                });
            }
        }

        let reports_dir = self.root.join("reports");
        let entries = fs::read_dir(&reports_dir).map_err(|source| ApprovalSetStoreError::Read {
            path: reports_dir.clone(),
            source,
        })?;
        let mut changed = false;
        for entry in entries {
            let entry = entry.map_err(|source| ApprovalSetStoreError::Read {
                path: reports_dir.clone(),
                source,
            })?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|source| ApprovalSetStoreError::Read {
                    path: path.clone(),
                    source,
                })?;
            if !file_type.is_file() || file_type.is_symlink() {
                return Err(ApprovalSetStoreError::Invalid {
                    reason: format!(
                        "approval set report entry `{}` is not a regular file",
                        path.display()
                    ),
                });
            }
            let report = read_json::<ApprovalSetReport, ApprovalSetStoreError>(
                &path,
                |path, source| ApprovalSetStoreError::Read { path, source },
                |path, source| ApprovalSetStoreError::Parse { path, source },
            )?;
            let expected_path = self.report_path(&report.set_id);
            if path != expected_path {
                return Err(ApprovalSetStoreError::Invalid {
                    reason: format!(
                        "approval set report `{}` is not stored at its canonical path `{}`",
                        path.display(),
                        expected_path.display()
                    ),
                });
            }
            let record =
                ApprovalSetRecord::from_report(&report, expected_path.display().to_string())?;
            validate_approval_set_record(self, &record, &report)?;
            match records.get(&record.set_id) {
                Some(indexed) if indexed != &record => {
                    return Err(ApprovalSetStoreError::Invalid {
                        reason: format!(
                            "approval set index record `{}` conflicts with its durable report",
                            record.set_id
                        ),
                    });
                }
                Some(_) => {}
                None => {
                    records.insert(record.set_id.clone(), record);
                    changed = true;
                }
            }
        }

        if changed {
            index.entries = records.into_values().collect();
            index
                .entries
                .sort_by_key(|entry| Reverse(entry.created_at_ms));
            self.write_index(&index)?;
        }
        Ok(())
    }

    fn validated(&self) -> Result<Vec<ApprovalSetLookup>, ApprovalSetStoreError> {
        let index = self.read_index()?;
        let mut seen_set_ids = HashSet::new();
        let mut verified = Vec::with_capacity(index.entries.len());
        for record in index.entries {
            if !seen_set_ids.insert(record.set_id.clone()) {
                return Err(ApprovalSetStoreError::Invalid {
                    reason: format!(
                        "approval set index contains duplicate record `{}`",
                        record.set_id
                    ),
                });
            }
            let report = read_json::<ApprovalSetReport, ApprovalSetStoreError>(
                &self.report_path(&record.set_id),
                |path, source| ApprovalSetStoreError::Read { path, source },
                |path, source| ApprovalSetStoreError::Parse { path, source },
            )?;
            validate_approval_set_record(self, &record, &report)?;
            verified.push(ApprovalSetLookup { record, report });
        }
        Ok(verified)
    }

    pub fn load(&self, set_id: &str) -> Result<Option<ApprovalSetLookup>, ApprovalSetStoreError> {
        Ok(self
            .validated()?
            .into_iter()
            .find(|lookup| lookup.report.set_id == set_id))
    }

    pub fn list(&self) -> Result<ApprovalSetList, ApprovalSetStoreError> {
        let mut sets = self
            .validated()?
            .into_iter()
            .map(|lookup| lookup.record)
            .collect::<Vec<_>>();
        sets.sort_by_key(|entry| Reverse(entry.created_at_ms));
        Ok(ApprovalSetList {
            total_count: sets.len(),
            sets,
        })
    }
}

fn validate_approval_set_record(
    store: &FileApprovalSetStore,
    record: &ApprovalSetRecord,
    report: &ApprovalSetReport,
) -> Result<(), ApprovalSetStoreError> {
    if report.eligible_voters.is_empty() {
        return Err(ApprovalSetStoreError::Invalid {
            reason: format!("approval set `{}` has no eligible voters", report.set_id),
        });
    }
    if !approval_set_voters_are_canonical(&report.eligible_voters) {
        return Err(ApprovalSetStoreError::Invalid {
            reason: format!(
                "approval set `{}` eligible voters are not an exact sorted unique set",
                report.set_id
            ),
        });
    }
    let required = report
        .threshold
        .required_count_for(report.eligible_voters.len());
    if required == 0 || required > report.eligible_voters.len() {
        return Err(ApprovalSetStoreError::Invalid {
            reason: format!(
                "approval set `{}` has an invalid threshold for its eligible voters",
                report.set_id
            ),
        });
    }
    let expected_set_id =
        canonical_approval_set_id(report).map_err(|source| ApprovalSetStoreError::Invalid {
            reason: format!(
                "approval set `{}` canonical ID could not be computed: {source}",
                report.set_id
            ),
        })?;
    let expected_report_digest =
        approval_set_report_digest(report).map_err(|source| ApprovalSetStoreError::Invalid {
            reason: format!(
                "approval set `{}` digest could not be computed: {source}",
                report.set_id
            ),
        })?;
    let expected_bundle_path = store.report_path(&report.set_id).display().to_string();
    if record.set_id != report.set_id
        || record.report_digest != expected_report_digest
        || report.set_id != expected_set_id
        || record.voter_count != report.eligible_voters.len()
        || record.threshold != report.threshold
        || record.promotion_evidence_ref != report.promotion_evidence_ref
        || record.created_at_ms != report.created_at_ms
        || record.bundle_path != expected_bundle_path
    {
        return Err(ApprovalSetStoreError::Invalid {
            reason: format!(
                "approval set index record `{}` does not match its canonical persisted report",
                record.set_id
            ),
        });
    }
    Ok(())
}

/// File-backed store for approval ledgers.
#[derive(Debug, Clone)]
pub struct FileApprovalLedgerStore {
    root: PathBuf,
}

impl FileApprovalLedgerStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApprovalLedgerStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ApprovalLedgerStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, ledger_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(ledger_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ApprovalLedgerIndex, ApprovalLedgerStoreError> {
        read_json_or_default::<ApprovalLedgerIndex, ApprovalLedgerStoreError>(
            &self.index_path(),
            |path, source| ApprovalLedgerStoreError::Read { path, source },
            |path, source| ApprovalLedgerStoreError::Parse { path, source },
        )
    }

    fn write_index(&self, index: &ApprovalLedgerIndex) -> Result<(), ApprovalLedgerStoreError> {
        write_pretty_json(
            &self.index_path(),
            index,
            |path, source| ApprovalLedgerStoreError::Write { path, source },
            |path, source| ApprovalLedgerStoreError::Parse { path, source },
        )
    }

    pub fn persist(
        &self,
        report: &ApprovalLedgerReport,
    ) -> Result<ApprovalLedgerRecord, ApprovalLedgerStoreError> {
        let path = self.report_path(&report.ledger_id);
        write_pretty_json(
            &path,
            report,
            |path, source| ApprovalLedgerStoreError::Write { path, source },
            |path, source| ApprovalLedgerStoreError::Parse { path, source },
        )?;

        let record = ApprovalLedgerRecord::from_report(report, path.display().to_string());
        let mut index = self.read_index()?;
        index
            .entries
            .retain(|entry| entry.ledger_id != record.ledger_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn list(
        &self,
        approval_set_id: Option<&str>,
    ) -> Result<ApprovalLedgerList, ApprovalLedgerStoreError> {
        let mut index = self.read_index()?;
        index
            .entries
            .sort_by_key(|entry| Reverse(entry.created_at_ms));
        let ledgers = index
            .entries
            .into_iter()
            .filter(|entry| {
                approval_set_id.is_none_or(|set_id| entry.approval_set_id.as_str() == set_id)
            })
            .collect::<Vec<_>>();
        Ok(ApprovalLedgerList {
            total_count: ledgers.len(),
            approval_set_id: approval_set_id.map(str::to_string),
            ledgers,
        })
    }
}

/// File-backed store for approval verdicts.
#[derive(Debug, Clone)]
pub struct FileApprovalVerdictStore {
    root: PathBuf,
}

impl FileApprovalVerdictStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApprovalVerdictStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ApprovalVerdictStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, verdict_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(verdict_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<ApprovalVerdictIndex, ApprovalVerdictStoreError> {
        read_json_or_default::<ApprovalVerdictIndex, ApprovalVerdictStoreError>(
            &self.index_path(),
            |path, source| ApprovalVerdictStoreError::Read { path, source },
            |path, source| ApprovalVerdictStoreError::Parse { path, source },
        )
    }

    fn write_index(&self, index: &ApprovalVerdictIndex) -> Result<(), ApprovalVerdictStoreError> {
        write_pretty_json(
            &self.index_path(),
            index,
            |path, source| ApprovalVerdictStoreError::Write { path, source },
            |path, source| ApprovalVerdictStoreError::Parse { path, source },
        )
    }

    pub fn persist(
        &self,
        report: &ApprovalVerdictReport,
    ) -> Result<ApprovalVerdictRecord, ApprovalVerdictStoreError> {
        if report.schema_version != CURRENT_APPROVAL_VERDICT_SCHEMA_VERSION {
            return Err(ApprovalVerdictStoreError::UnsupportedSchema {
                verdict_id: report.verdict_id.clone(),
                schema_version: report.schema_version,
            });
        }
        // A not-approved evaluation is a view of a mutable ledger, not a
        // durable terminal artifact. Persisting it would make its counts and
        // missing-voter set unverifiable after the next valid vote.
        if report.status != ApprovalVerdictStatus::Approved {
            return Err(ApprovalVerdictStoreError::NonTerminalVerdict {
                verdict_id: report.verdict_id.clone(),
            });
        }
        let path = self.report_path(&report.verdict_id);
        write_pretty_json(
            &path,
            report,
            |path, source| ApprovalVerdictStoreError::Write { path, source },
            |path, source| ApprovalVerdictStoreError::Parse { path, source },
        )?;
        let record = ApprovalVerdictRecord::from_report(report, path.display().to_string());
        let mut index = self.read_index()?;
        index
            .entries
            .retain(|entry| entry.verdict_id != record.verdict_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        verdict_id: &str,
    ) -> Result<Option<ApprovalVerdictLookup>, ApprovalVerdictStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .into_iter()
            .find(|entry| entry.verdict_id == verdict_id)
        else {
            return Ok(None);
        };
        let report = read_json::<ApprovalVerdictReport, ApprovalVerdictStoreError>(
            &self.report_path(verdict_id),
            |path, source| ApprovalVerdictStoreError::Read { path, source },
            |path, source| ApprovalVerdictStoreError::Parse { path, source },
        )?;
        Ok(Some(ApprovalVerdictLookup { record, report }))
    }

    pub fn list(&self) -> Result<ApprovalVerdictList, ApprovalVerdictStoreError> {
        let mut index = self.read_index()?;
        index
            .entries
            .sort_by_key(|entry| Reverse(entry.created_at_ms));
        Ok(ApprovalVerdictList {
            total_count: index.entries.len(),
            verdicts: index.entries,
        })
    }
}

/// File-backed store for approval receipt packs.
#[derive(Debug, Clone)]
pub struct FileApprovalReceiptPackStore {
    root: PathBuf,
}

impl FileApprovalReceiptPackStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApprovalReceiptPackStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            ApprovalReceiptPackStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        fs::create_dir_all(root.join("resume-outcomes")).map_err(|source| {
            ApprovalReceiptPackStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, pack_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(pack_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn resume_outcome_path(&self, pack_id: &str) -> PathBuf {
        self.root
            .join("resume-outcomes")
            .join(format!("{}.json", sanitize_id(pack_id)))
    }

    fn load_resume_outcome(
        &self,
        pack_id: &str,
    ) -> Result<Option<AuditTrail>, ApprovalReceiptPackStoreError> {
        let path = self.resume_outcome_path(pack_id);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => {
                return Err(ApprovalReceiptPackStoreError::ResumeOutcomeConflict {
                    pack_id: pack_id.to_string(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(ApprovalReceiptPackStoreError::Read { path, source });
            }
        }
        let outcome = read_json::<ApprovalResumeOutcome, ApprovalReceiptPackStoreError>(
            &path,
            |path, source| ApprovalReceiptPackStoreError::Read { path, source },
            |path, source| ApprovalReceiptPackStoreError::Parse { path, source },
        )?;
        if outcome.schema_version != 1 || outcome.receipt_pack_id != pack_id {
            return Err(ApprovalReceiptPackStoreError::ResumeOutcomeConflict {
                pack_id: pack_id.to_string(),
            });
        }
        Ok(Some(outcome.audit))
    }

    fn persist_resume_outcome(
        &self,
        pack_id: &str,
        audit: &AuditTrail,
    ) -> Result<(), ApprovalReceiptPackStoreError> {
        let path = self.resume_outcome_path(pack_id);
        if let Some(existing) = self.load_resume_outcome(pack_id)? {
            let existing = serde_json::to_value(existing).map_err(|source| {
                ApprovalReceiptPackStoreError::Parse {
                    path: path.clone(),
                    source,
                }
            })?;
            let proposed = serde_json::to_value(audit).map_err(|source| {
                ApprovalReceiptPackStoreError::Parse {
                    path: path.clone(),
                    source,
                }
            })?;
            return if existing == proposed {
                Ok(())
            } else {
                Err(ApprovalReceiptPackStoreError::ResumeOutcomeConflict {
                    pack_id: pack_id.to_string(),
                })
            };
        }
        write_pretty_json(
            &path,
            &ApprovalResumeOutcome {
                schema_version: 1,
                receipt_pack_id: pack_id.to_string(),
                audit: audit.clone(),
            },
            |path, source| ApprovalReceiptPackStoreError::Write { path, source },
            |path, source| ApprovalReceiptPackStoreError::Parse { path, source },
        )
    }

    fn read_index(&self) -> Result<ApprovalReceiptPackIndex, ApprovalReceiptPackStoreError> {
        read_json_or_default::<ApprovalReceiptPackIndex, ApprovalReceiptPackStoreError>(
            &self.index_path(),
            |path, source| ApprovalReceiptPackStoreError::Read { path, source },
            |path, source| ApprovalReceiptPackStoreError::Parse { path, source },
        )
    }

    fn write_index(
        &self,
        index: &ApprovalReceiptPackIndex,
    ) -> Result<(), ApprovalReceiptPackStoreError> {
        write_pretty_json(
            &self.index_path(),
            index,
            |path, source| ApprovalReceiptPackStoreError::Write { path, source },
            |path, source| ApprovalReceiptPackStoreError::Parse { path, source },
        )
    }

    pub fn persist(
        &self,
        report: &ApprovalReceiptPackReport,
    ) -> Result<ApprovalReceiptPackRecord, ApprovalReceiptPackStoreError> {
        if report.signature_version != ApprovalReceiptPackSignatureVersion::V2 {
            return Err(ApprovalReceiptPackStoreError::LegacySignaturePayload {
                pack_id: report.pack_id.clone(),
            });
        }
        let path = self.report_path(&report.pack_id);
        write_pretty_json(
            &path,
            report,
            |path, source| ApprovalReceiptPackStoreError::Write { path, source },
            |path, source| ApprovalReceiptPackStoreError::Parse { path, source },
        )?;
        let record = ApprovalReceiptPackRecord::from_report(report, path.display().to_string());
        let mut index = self.read_index()?;
        index
            .entries
            .retain(|entry| entry.pack_id != record.pack_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        pack_id: &str,
    ) -> Result<Option<ApprovalReceiptPackLookup>, ApprovalReceiptPackStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .into_iter()
            .find(|entry| entry.pack_id == pack_id)
        else {
            return Ok(None);
        };
        let report = read_json::<ApprovalReceiptPackReport, ApprovalReceiptPackStoreError>(
            &self.report_path(pack_id),
            |path, source| ApprovalReceiptPackStoreError::Read { path, source },
            |path, source| ApprovalReceiptPackStoreError::Parse { path, source },
        )?;
        Ok(Some(ApprovalReceiptPackLookup { record, report }))
    }

    pub fn list(&self) -> Result<ApprovalReceiptPackList, ApprovalReceiptPackStoreError> {
        let mut index = self.read_index()?;
        index
            .entries
            .sort_by_key(|entry| Reverse(entry.created_at_ms));
        Ok(ApprovalReceiptPackList {
            total_count: index.entries.len(),
            packs: index.entries,
            quarantined_count: 0,
            quarantined: Vec::new(),
        })
    }
}

fn validate_verdict_record(
    store: &FileApprovalVerdictStore,
    record: &ApprovalVerdictRecord,
    report: &ApprovalVerdictReport,
) -> Result<(), ApprovalError> {
    let expected_id = canonical_approval_verdict_id(report)?;
    let expected_bundle_path = store.report_path(&report.verdict_id).display().to_string();
    if record.verdict_id != report.verdict_id
        || report.verdict_id != expected_id
        || record.approval_set_id != report.approval_set_id
        || record.ledger_id != report.ledger_id
        || record.status != report.status
        || record.approve_count != report.approve_count
        || record.reject_count != report.reject_count
        || record.created_at_ms != report.evaluated_at_ms
        || record.bundle_path != expected_bundle_path
    {
        return Err(ApprovalError::InvalidVerdictRequest {
            reason: format!(
                "approval verdict index record `{}` does not match its canonical persisted report",
                record.verdict_id
            ),
        });
    }
    Ok(())
}

fn validate_receipt_pack_record(
    store: &FileApprovalReceiptPackStore,
    record: &ApprovalReceiptPackRecord,
    report: &ApprovalReceiptPackReport,
) -> Result<(), ApprovalError> {
    let expected_id = canonical_receipt_pack_id(report)?;
    let expected_bundle_path = store.report_path(&report.pack_id).display().to_string();
    if record.pack_id != report.pack_id
        || report.pack_id != expected_id
        || record.verdict_id != report.verdict.verdict_id
        || record.approval_set_id != report.approval_set.set_id
        || record.ledger_id != report.ledger.ledger_id
        || record.created_at_ms != report.created_at_ms
        || record.bundle_path != expected_bundle_path
    {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: format!(
                "receipt pack index record `{}` does not match its canonical persisted report",
                record.pack_id
            ),
        });
    }
    Ok(())
}

fn validate_ledger_record(
    store: &FileApprovalLedgerStore,
    record: &ApprovalLedgerRecord,
    report: &ApprovalLedgerReport,
) -> Result<(), ApprovalError> {
    let expected_ledger_id = approval_ledger_id(&report.approval_set_id, report.created_at_ms);
    let expected_bundle_path = store.report_path(&report.ledger_id).display().to_string();
    if record.ledger_id != report.ledger_id
        || report.ledger_id != expected_ledger_id
        || record.approval_set_id != report.approval_set_id
        || record.vote_count != report.entries.len()
        || record.created_at_ms != report.created_at_ms
        || record.bundle_path != expected_bundle_path
    {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: format!(
                "approval ledger index record `{}` does not match its canonical persisted report",
                record.ledger_id
            ),
        });
    }
    Ok(())
}

fn validate_ledger_report(
    report: &ApprovalLedgerReport,
    set: &ApprovalSetReport,
) -> Result<(), ApprovalError> {
    if report.schema_version != CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: format!(
                "approval ledger `{}` uses unsupported schema version `{}`",
                report.ledger_id, report.schema_version
            ),
        });
    }
    if report.approval_set_id != set.set_id {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: format!(
                "approval ledger `{}` is bound to approval set `{}` not `{}`",
                report.ledger_id, report.approval_set_id, set.set_id
            ),
        });
    }
    if report.created_at_ms < set.created_at_ms {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: format!(
                "approval ledger `{}` predates its approval set",
                report.ledger_id
            ),
        });
    }

    let mut replayed = ApprovalLedgerReport {
        schema_version: CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION,
        ledger_id: report.ledger_id.clone(),
        approval_set_id: report.approval_set_id.clone(),
        entries: Vec::new(),
        created_at_ms: report.created_at_ms,
    };
    let observed_now_ms = now_ms();
    let mut observed_current_vote = false;
    for entry in &report.entries {
        match entry.signature_version {
            ApprovalVoteSignatureVersion::LegacyV1 => {
                if observed_current_vote {
                    return Err(ApprovalError::InvalidLedgerRequest {
                        reason: format!(
                            "approval ledger `{}` places legacy audit history after current votes",
                            report.ledger_id
                        ),
                    });
                }
                validate_legacy_approval_entry(&replayed, set, entry).map_err(|error| {
                    ApprovalError::InvalidLedgerRequest {
                        reason: format!(
                            "approval ledger `{}` contains invalid legacy audit history: {error}",
                            report.ledger_id
                        ),
                    }
                })?;
                replayed.entries.push(entry.clone());
            }
            ApprovalVoteSignatureVersion::IntentV2 => {
                observed_current_vote = true;
                let intent = approval_vote_intent_from_entry(report, entry);
                verify_approval_vote_signature_raw(&intent, &entry.signature).map_err(|error| {
                    ApprovalError::InvalidLedgerRequest {
                        reason: format!(
                            "approval ledger `{}` contains an invalid current signed vote: {error}",
                            report.ledger_id
                        ),
                    }
                })?;
                validate_and_append_vote_at(
                    &mut replayed,
                    set,
                    &intent,
                    &entry.signature,
                    observed_now_ms,
                )
                .map_err(|error| ApprovalError::InvalidLedgerRequest {
                    reason: format!(
                        "approval ledger `{}` contains an invalid current signed vote: {error}",
                        report.ledger_id
                    ),
                })?;
            }
        }
        if replayed
            .entries
            .last()
            .is_none_or(|replayed_entry| replayed_entry != entry)
        {
            return Err(ApprovalError::InvalidLedgerRequest {
                reason: format!(
                    "approval ledger `{}` contains an invalid vote chain",
                    report.ledger_id
                ),
            });
        }
    }
    if replayed != *report {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: format!(
                "approval ledger `{}` could not be replayed exactly",
                report.ledger_id
            ),
        });
    }
    Ok(())
}

fn validate_legacy_ledger_report(
    report: &ApprovalLedgerReport,
    set: &ApprovalSetReport,
) -> Result<(), ApprovalError> {
    if report.schema_version != LEGACY_APPROVAL_LEDGER_SCHEMA_VERSION
        || report.approval_set_id != set.set_id
        || report.created_at_ms < set.created_at_ms
    {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: format!(
                "legacy approval ledger `{}` is not bound to its persisted approval set",
                report.ledger_id
            ),
        });
    }
    let mut replayed = ApprovalLedgerReport {
        schema_version: LEGACY_APPROVAL_LEDGER_SCHEMA_VERSION,
        ledger_id: report.ledger_id.clone(),
        approval_set_id: report.approval_set_id.clone(),
        entries: Vec::new(),
        created_at_ms: report.created_at_ms,
    };
    for entry in &report.entries {
        validate_legacy_approval_entry(&replayed, set, entry).map_err(|error| {
            ApprovalError::InvalidLedgerRequest {
                reason: format!(
                    "legacy approval ledger `{}` contains invalid audit history: {error}",
                    report.ledger_id
                ),
            }
        })?;
        replayed.entries.push(entry.clone());
    }
    Ok(())
}

fn validate_legacy_approval_entry(
    replayed: &ApprovalLedgerReport,
    set: &ApprovalSetReport,
    entry: &ApprovalLedgerEntry,
) -> Result<(), ApprovalError> {
    if entry.signature_version != ApprovalVoteSignatureVersion::LegacyV1
        || entry.vote != ApprovalVote::Approve
        || entry.previous_envelope_hash.is_some()
    {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: "legacy entries must retain the original approve-only V1 wire shape"
                .to_string(),
        });
    }
    if entry.timestamp_ms < replayed.created_at_ms
        || replayed
            .entries
            .last()
            .is_some_and(|previous| entry.timestamp_ms < previous.timestamp_ms)
    {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: "legacy entry timestamp is outside its historical audit lineage".to_string(),
        });
    }
    if !set
        .eligible_voters
        .iter()
        .any(|eligible| eligible == &entry.voter_id)
        || replayed
            .entries
            .iter()
            .any(|previous| previous.voter_id == entry.voter_id)
    {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: format!(
                "legacy voter `{}` is ineligible or duplicated",
                entry.voter_id
            ),
        });
    }
    let payload =
        legacy_approval_vote_payload_bytes(&set.set_id, &replayed.ledger_id, &entry.voter_id)?;
    verify_detached_signature(&payload, &entry.signature).map_err(|error| {
        ApprovalError::InvalidSignature {
            voter_id: entry.voter_id.clone(),
            reason: error.to_string(),
        }
    })?;
    if voter_id_from_public_key(&entry.signature.public_key_hex) != entry.voter_id {
        return Err(ApprovalError::InvalidSignature {
            voter_id: entry.voter_id.clone(),
            reason: "signature public key does not match the legacy voter ID".to_string(),
        });
    }
    let expected_entry_id =
        next_approval_ledger_entry_id(&replayed.ledger_id, replayed.entries.len());
    let expected_envelope_hash = build_legacy_vote_envelope_hash(
        replayed,
        &expected_entry_id,
        &entry.voter_id,
        &entry.signature,
        entry.timestamp_ms,
    )?;
    if entry.entry_id != expected_entry_id || entry.envelope_hash != expected_envelope_hash {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: "legacy entry does not match its deterministic audit envelope".to_string(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyReceiptPackDisposition {
    VerifiedRetired,
    AuthenticatedCoreOnly,
}

#[derive(Default)]
struct ValidatedReceiptPackProjection {
    authoritative: Vec<ApprovalReceiptPackLookup>,
    quarantined: Vec<ApprovalReceiptPackQuarantineRecord>,
}

/// Domain harness for approval-set and ledger workflows.
#[derive(Debug, Clone)]
pub struct DefaultApprovalHarness {
    set_store: FileApprovalSetStore,
    ledger_store: FileApprovalLedgerStore,
    verdict_store: Option<FileApprovalVerdictStore>,
    receipt_pack_store: Option<FileApprovalReceiptPackStore>,
}

impl DefaultApprovalHarness {
    pub fn from_paths(
        approval_set_results_dir: impl AsRef<Path>,
        approval_ledger_results_dir: impl AsRef<Path>,
    ) -> Result<Self, ApprovalError> {
        Ok(Self {
            set_store: FileApprovalSetStore::open(approval_set_results_dir)?,
            ledger_store: FileApprovalLedgerStore::open(approval_ledger_results_dir)?,
            verdict_store: None,
            receipt_pack_store: None,
        })
    }

    pub fn from_path(
        _config_path: impl AsRef<Path>,
        approval_verdict_results_dir: impl AsRef<Path>,
        approval_receipt_pack_results_dir: impl AsRef<Path>,
        approval_set_results_dir: impl AsRef<Path>,
        approval_ledger_results_dir: impl AsRef<Path>,
    ) -> Result<Self, ApprovalError> {
        Ok(Self {
            set_store: FileApprovalSetStore::open(approval_set_results_dir)?,
            ledger_store: FileApprovalLedgerStore::open(approval_ledger_results_dir)?,
            verdict_store: Some(FileApprovalVerdictStore::open(
                approval_verdict_results_dir,
            )?),
            receipt_pack_store: Some(FileApprovalReceiptPackStore::open(
                approval_receipt_pack_results_dir,
            )?),
        })
    }

    pub fn create_approval_set(
        &self,
        eligible_voters: Vec<String>,
        threshold: ThresholdRule,
        promotion_evidence_ref: &str,
    ) -> Result<ApprovalSetRecord, ApprovalError> {
        self.with_workflow_lock(|| {
            self.create_approval_set_unlocked(eligible_voters, threshold, promotion_evidence_ref)
        })
    }

    /// Return the one approval set bound to this exact evidence reference, or
    /// create it once. The workflow lock spans lookup, set persistence, ledger
    /// recovery, and validation so retries cannot mint sibling approval sets.
    pub fn create_or_load_approval_set(
        &self,
        eligible_voters: Vec<String>,
        threshold: ThresholdRule,
        promotion_evidence_ref: &str,
    ) -> Result<ApprovalSetRecord, ApprovalError> {
        self.with_workflow_lock(|| {
            let eligible_voters = normalize_voter_ids(eligible_voters);
            self.set_store.reconcile_unindexed_reports()?;
            let existing = self
                .set_store
                .validated()?
                .into_iter()
                .filter(|lookup| lookup.report.promotion_evidence_ref == promotion_evidence_ref)
                .collect::<Vec<_>>();
            match existing.as_slice() {
                [] => self.create_approval_set_unlocked(
                    eligible_voters,
                    threshold,
                    promotion_evidence_ref,
                ),
                [lookup] => {
                    if lookup.report.eligible_voters != eligible_voters
                        || lookup.report.threshold != threshold
                    {
                        return Err(ApprovalError::ApprovalEvidenceConflict {
                            evidence_ref: promotion_evidence_ref.to_string(),
                        });
                    }
                    self.load_or_repair_stored_ledger_for_set(&lookup.report)?;
                    Ok(lookup.record.clone())
                }
                lookups => Err(ApprovalError::AmbiguousApprovalEvidence {
                    evidence_ref: promotion_evidence_ref.to_string(),
                    count: lookups.len(),
                }),
            }
        })
    }

    fn create_approval_set_unlocked(
        &self,
        eligible_voters: Vec<String>,
        threshold: ThresholdRule,
        promotion_evidence_ref: &str,
    ) -> Result<ApprovalSetRecord, ApprovalError> {
        let eligible_voters = normalize_voter_ids(eligible_voters);
        if eligible_voters.is_empty() {
            return Err(ApprovalError::InvalidApprovalSetRequest {
                reason: "approval sets require at least one eligible voter".to_string(),
            });
        }

        let required = threshold.required_count_for(eligible_voters.len());
        if required == 0 {
            return Err(ApprovalError::InvalidApprovalSetRequest {
                reason: "approval threshold must require at least one vote".to_string(),
            });
        }
        if required > eligible_voters.len() {
            return Err(ApprovalError::InvalidApprovalSetRequest {
                reason: format!(
                    "approval threshold requires {required} votes but only {} eligible voters were provided",
                    eligible_voters.len()
                ),
            });
        }

        let created_at_ms = now_ms();
        let set_id = canonical_approval_set_id_fields(
            &eligible_voters,
            &threshold,
            promotion_evidence_ref,
            created_at_ms,
        )?;
        let report = ApprovalSetReport {
            set_id: set_id.clone(),
            eligible_voters,
            threshold,
            promotion_evidence_ref: promotion_evidence_ref.to_string(),
            created_at_ms,
        };
        let record = self.set_store.persist(&report)?;

        let ledger_id = approval_ledger_id(&set_id, created_at_ms);
        let ledger = ApprovalLedgerReport {
            schema_version: CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION,
            ledger_id,
            approval_set_id: set_id,
            entries: Vec::new(),
            created_at_ms,
        };
        self.ledger_store.persist(&ledger)?;
        Ok(record)
    }

    pub fn append_vote(
        &self,
        set_id: &str,
        voter_id: &str,
        signer: &Ed25519Signer,
    ) -> Result<ApprovalLedgerQuorumState, ApprovalError> {
        self.with_workflow_lock(|| {
            let set = self.load_approval_set(set_id)?.ok_or_else(|| {
                ApprovalError::ApprovalSetNotFound {
                    set_id: set_id.to_string(),
                }
            })?;
            let mut ledger = self.load_stored_ledger_for_set(set_id)?;
            if !ledger.report.entries.iter().any(|entry| {
                entry.signature_version == ApprovalVoteSignatureVersion::IntentV2
                    && entry.voter_id == voter_id
            }) && ApprovalLedgerQuorumState::from_ledger_and_set(&ledger.report, &set.report)
                .quorum_met
            {
                return Err(ApprovalError::QuorumAlreadyMet {
                    ledger_id: ledger.report.ledger_id.clone(),
                });
            }
            let timestamp_ms = next_approval_vote_timestamp_ms(&ledger.report, now_ms());
            let intent = build_approval_vote_intent(
                &ledger.report,
                voter_id,
                ApprovalVote::Approve,
                timestamp_ms,
            );
            let signature = signer.sign(&approval_vote_payload_bytes(&intent)?);
            validate_and_append_vote(&mut ledger.report, &set.report, &intent, &signature)?;
            let quorum_state =
                ApprovalLedgerQuorumState::from_ledger_and_set(&ledger.report, &set.report);
            self.ledger_store.persist(&ledger.report)?;
            Ok(quorum_state)
        })
    }

    pub fn append_signed_vote(
        &self,
        intent: &ApprovalVoteIntent,
        signature: &DetachedSignature,
    ) -> Result<ApprovalLedgerQuorumState, ApprovalError> {
        match self.append_signed_vote_outcome(intent, signature)? {
            ApprovalLedgerVoteOutcome {
                ledger,
                transition:
                    ApprovalLedgerVoteTransition::Pending | ApprovalLedgerVoteTransition::QuorumCrossed,
            } => Ok(ledger.quorum_state),
            ApprovalLedgerVoteOutcome {
                transition:
                    ApprovalLedgerVoteTransition::ExactDuplicatePending
                    | ApprovalLedgerVoteTransition::ExactDuplicateOfQuorum,
                ..
            } => Err(ApprovalError::DuplicateVoter {
                voter_id: intent.voter_id.clone(),
            }),
        }
    }

    pub fn append_signed_vote_outcome(
        &self,
        intent: &ApprovalVoteIntent,
        signature: &DetachedSignature,
    ) -> Result<ApprovalLedgerVoteOutcome, ApprovalError> {
        validate_persistable_vote_intent(intent)?;
        self.with_workflow_lock(|| {
            let mut ledger = self
                .load_ledger_unlocked(&intent.ledger_id)?
                .ok_or_else(|| ApprovalError::ApprovalLedgerNotFound {
                    ledger_id: intent.ledger_id.clone(),
                })?;
            let set = self
                .load_approval_set(&ledger.report.approval_set_id)?
                .ok_or_else(|| ApprovalError::ApprovalSetNotFound {
                    set_id: ledger.report.approval_set_id.clone(),
                })?;
            if ledger.report.ledger_id != intent.ledger_id
                || ledger.record.ledger_id != ledger.report.ledger_id
                || ledger.report.approval_set_id != set.report.set_id
                || intent.approval_set_id != set.report.set_id
            {
                return Err(ApprovalError::InvalidLedgerRequest {
                    reason:
                        "approval vote is not bound to the exact persisted approval set and ledger"
                            .to_string(),
                });
            }
            verify_approval_vote_signature(intent, signature)?;
            if let Some(existing) = ledger.report.entries.iter().find(|entry| {
                entry.signature_version == ApprovalVoteSignatureVersion::IntentV2
                    && entry.voter_id == intent.voter_id
            }) {
                let existing_intent = approval_vote_intent_from_entry(&ledger.report, existing);
                if existing_intent == *intent && existing.signature == *signature {
                    let transition = if ledger.quorum_state.quorum_met {
                        ApprovalLedgerVoteTransition::ExactDuplicateOfQuorum
                    } else {
                        ApprovalLedgerVoteTransition::ExactDuplicatePending
                    };
                    return Ok(ApprovalLedgerVoteOutcome { ledger, transition });
                }
                return Err(ApprovalError::DuplicateVoter {
                    voter_id: intent.voter_id.clone(),
                });
            }
            if ledger.quorum_state.quorum_met {
                return Err(ApprovalError::QuorumAlreadyMet {
                    ledger_id: ledger.report.ledger_id.clone(),
                });
            }
            validate_and_append_vote(&mut ledger.report, &set.report, intent, signature)?;
            let quorum_state =
                ApprovalLedgerQuorumState::from_ledger_and_set(&ledger.report, &set.report);
            let transition = if !ledger.quorum_state.quorum_met && quorum_state.quorum_met {
                ApprovalLedgerVoteTransition::QuorumCrossed
            } else {
                ApprovalLedgerVoteTransition::Pending
            };
            let record = self.ledger_store.persist(&ledger.report)?;
            Ok(ApprovalLedgerVoteOutcome {
                ledger: ApprovalLedgerLookup {
                    record,
                    report: ledger.report,
                    quorum_state,
                },
                transition,
            })
        })
    }

    pub fn load_approval_set(
        &self,
        set_id: &str,
    ) -> Result<Option<ApprovalSetLookup>, ApprovalError> {
        self.set_store.load(set_id).map_err(Into::into)
    }

    pub fn load_ledger(
        &self,
        ledger_id: &str,
    ) -> Result<Option<ApprovalLedgerLookup>, ApprovalError> {
        self.with_workflow_lock(|| self.load_ledger_unlocked(ledger_id))
    }

    fn validated_ledgers_unlocked(&self) -> Result<Vec<ApprovalLedgerLookup>, ApprovalError> {
        let index = self.ledger_store.read_index()?;
        let mut seen_ledger_ids = HashSet::new();
        let mut verified = Vec::with_capacity(index.entries.len());
        for record in index.entries {
            if !seen_ledger_ids.insert(record.ledger_id.clone()) {
                return Err(ApprovalError::InvalidLedgerRequest {
                    reason: format!(
                        "approval ledger index contains duplicate record `{}`",
                        record.ledger_id
                    ),
                });
            }
            let report = read_json::<ApprovalLedgerReport, ApprovalLedgerStoreError>(
                &self.ledger_store.report_path(&record.ledger_id),
                |path, source| ApprovalLedgerStoreError::Read { path, source },
                |path, source| ApprovalLedgerStoreError::Parse { path, source },
            )?;
            validate_ledger_record(&self.ledger_store, &record, &report)?;
            let set = self
                .set_store
                .load(&report.approval_set_id)?
                .ok_or_else(|| ApprovalError::ApprovalSetNotFound {
                    set_id: report.approval_set_id.clone(),
                })?;
            if set.report.set_id != report.approval_set_id {
                return Err(ApprovalError::InvalidLedgerRequest {
                    reason: format!(
                        "approval ledger `{}` is not bound to its persisted approval set",
                        report.ledger_id
                    ),
                });
            }
            validate_ledger_report(&report, &set.report)?;
            let quorum_state = ApprovalLedgerQuorumState::from_ledger_and_set(&report, &set.report);
            verified.push(ApprovalLedgerLookup {
                record,
                report,
                quorum_state,
            });
        }
        Ok(verified)
    }

    fn load_ledger_unlocked(
        &self,
        ledger_id: &str,
    ) -> Result<Option<ApprovalLedgerLookup>, ApprovalError> {
        Ok(self
            .validated_ledgers_unlocked()?
            .into_iter()
            .find(|lookup| lookup.report.ledger_id == ledger_id))
    }

    pub fn list_approval_sets(&self) -> Result<ApprovalSetList, ApprovalError> {
        self.set_store.list().map_err(Into::into)
    }

    pub fn list_ledgers(
        &self,
        approval_set_id: Option<&str>,
    ) -> Result<ApprovalLedgerList, ApprovalError> {
        self.with_workflow_lock(|| {
            let ledgers = self
                .validated_ledgers_unlocked()?
                .into_iter()
                .filter(|lookup| {
                    approval_set_id
                        .is_none_or(|set_id| lookup.report.approval_set_id.as_str() == set_id)
                })
                .map(|lookup| lookup.record)
                .collect::<Vec<_>>();
            Ok(ApprovalLedgerList {
                total_count: ledgers.len(),
                approval_set_id: approval_set_id.map(str::to_string),
                ledgers,
            })
        })
    }

    fn validated_verdicts_unlocked(&self) -> Result<Vec<ApprovalVerdictLookup>, ApprovalError> {
        let verdict_store = self.verdict_store()?;
        let index = verdict_store.read_index()?;
        let mut seen_verdict_ids = HashSet::new();
        let mut seen_approved_ledgers = HashSet::new();
        let mut verified = Vec::with_capacity(index.entries.len());
        for record in index.entries {
            if !seen_verdict_ids.insert(record.verdict_id.clone()) {
                return Err(ApprovalError::InvalidVerdictRequest {
                    reason: format!(
                        "approval verdict index contains duplicate record `{}`",
                        record.verdict_id
                    ),
                });
            }
            let report = read_json::<ApprovalVerdictReport, ApprovalVerdictStoreError>(
                &verdict_store.report_path(&record.verdict_id),
                |path, source| ApprovalVerdictStoreError::Read { path, source },
                |path, source| ApprovalVerdictStoreError::Parse { path, source },
            )?;
            validate_verdict_record(verdict_store, &record, &report)?;

            let set = self
                .set_store
                .load(&report.approval_set_id)?
                .ok_or_else(|| ApprovalError::ApprovalSetNotFound {
                    set_id: report.approval_set_id.clone(),
                })?;
            let ledger = self
                .load_ledger_unlocked(&report.ledger_id)?
                .ok_or_else(|| ApprovalError::ApprovalLedgerNotFound {
                    ledger_id: report.ledger_id.clone(),
                })?;
            if ledger.report.approval_set_id != report.approval_set_id {
                return Err(ApprovalError::InvalidVerdictRequest {
                    reason: format!(
                        "approval verdict `{}` is not bound to its ledger's approval set",
                        report.verdict_id
                    ),
                });
            }
            if report.evaluated_at_ms < set.report.created_at_ms
                || report.evaluated_at_ms < ledger.report.created_at_ms
            {
                return Err(ApprovalError::InvalidVerdictRequest {
                    reason: format!(
                        "approval verdict `{}` has an evaluation timestamp before its lineage",
                        report.verdict_id
                    ),
                });
            }
            if report.schema_version == LEGACY_APPROVAL_VERDICT_SCHEMA_VERSION {
                validate_legacy_verdict_for_retirement(&report, &set.report, &ledger.report)?;
                // A positively reconstructed V1 verdict remains on disk as
                // audit evidence but is never projected as current authority.
                continue;
            }
            if report.schema_version != CURRENT_APPROVAL_VERDICT_SCHEMA_VERSION {
                return Err(ApprovalError::InvalidVerdictRequest {
                    reason: format!(
                        "approval verdict `{}` uses unsupported schema version `{}`",
                        report.verdict_id, report.schema_version
                    ),
                });
            }
            let expected = evaluate_verdict(&set.report, &ledger.report, report.evaluated_at_ms);
            match expected {
                Ok(expected) if report == expected => {}
                Ok(_) => {
                    return Err(ApprovalError::InvalidVerdictRequest {
                        reason: format!(
                            "approval verdict `{}` does not match its persisted set and ledger",
                            report.verdict_id
                        ),
                    });
                }
                Err(error) => return Err(error),
            }
            if report.status == ApprovalVerdictStatus::Approved
                && !seen_approved_ledgers
                    .insert((report.approval_set_id.clone(), report.ledger_id.clone()))
            {
                return Err(ApprovalError::InvalidVerdictRequest {
                    reason: format!(
                        "approval ledger `{}` has multiple approved verdicts",
                        report.ledger_id
                    ),
                });
            }
            verified.push(ApprovalVerdictLookup { record, report });
        }
        Ok(verified)
    }

    fn validated_receipt_packs_unlocked(
        &self,
    ) -> Result<ValidatedReceiptPackProjection, ApprovalError> {
        let receipt_pack_store = self.receipt_pack_store()?;
        let verdicts = self.validated_verdicts_unlocked()?;
        let index = receipt_pack_store.read_index()?;
        let mut seen_pack_ids = HashSet::new();
        let mut seen_approved_ledgers = HashSet::new();
        let mut projection = ValidatedReceiptPackProjection {
            authoritative: Vec::with_capacity(index.entries.len()),
            quarantined: Vec::new(),
        };
        for record in index.entries {
            if !seen_pack_ids.insert(record.pack_id.clone()) {
                return Err(ApprovalError::InvalidReceiptPack {
                    reason: format!(
                        "approval receipt-pack index contains duplicate record `{}`",
                        record.pack_id
                    ),
                });
            }
            let report = read_json::<ApprovalReceiptPackReport, ApprovalReceiptPackStoreError>(
                &receipt_pack_store.report_path(&record.pack_id),
                |path, source| ApprovalReceiptPackStoreError::Read { path, source },
                |path, source| ApprovalReceiptPackStoreError::Parse { path, source },
            )?;
            validate_receipt_pack_record(receipt_pack_store, &record, &report)?;
            if report.signature_version == ApprovalReceiptPackSignatureVersion::LegacyV1 {
                let disposition = validate_legacy_receipt_pack_for_retirement(&report)?;
                let set = self
                    .set_store
                    .load(&report.approval_set.set_id)?
                    .ok_or_else(|| ApprovalError::ApprovalSetNotFound {
                        set_id: report.approval_set.set_id.clone(),
                    })?;
                let ledger = self
                    .load_ledger_unlocked(&report.ledger.ledger_id)?
                    .ok_or_else(|| ApprovalError::ApprovalLedgerNotFound {
                        ledger_id: report.ledger.ledger_id.clone(),
                    })?;
                let persisted_legacy = legacy_ledger_prefix(&ledger.report)?;
                if set.report != report.approval_set || persisted_legacy != report.ledger {
                    return Err(ApprovalError::InvalidReceiptPack {
                        reason: format!(
                            "legacy receipt pack `{}` does not match its persisted V1 lineage",
                            report.pack_id
                        ),
                    });
                }
                if disposition == LegacyReceiptPackDisposition::AuthenticatedCoreOnly {
                    projection
                        .quarantined
                        .push(ApprovalReceiptPackQuarantineRecord {
                            observed_pack_id: report.pack_id.clone(),
                            observed_signer_id: report.signer_id.clone(),
                            observed_created_at_ms: report.created_at_ms,
                            signature_key_id: report.signature.key_id.clone(),
                            authenticated_core_hash: report.content_hash.clone(),
                            observed_bundle_path: record.bundle_path,
                            reason: "V1 signature authenticates only set, ledger, verdict, and audit references; observed pack identity, signer, and creation time are non-authoritative"
                                .to_string(),
                        });
                }
                // Full-metadata V1 packs are verified-but-retired; oldest V1
                // packs are observable quarantine records. Neither enters the
                // authoritative collection or blocks creation of a V2 pack.
                continue;
            }
            verify_receipt_pack(&report)?;

            let set = self
                .set_store
                .load(&report.approval_set.set_id)?
                .ok_or_else(|| ApprovalError::ApprovalSetNotFound {
                    set_id: report.approval_set.set_id.clone(),
                })?;
            let ledger = self
                .load_ledger_unlocked(&report.ledger.ledger_id)?
                .ok_or_else(|| ApprovalError::ApprovalLedgerNotFound {
                    ledger_id: report.ledger.ledger_id.clone(),
                })?;
            let verdict = verdicts
                .iter()
                .find(|lookup| lookup.report.verdict_id == report.verdict.verdict_id)
                .ok_or_else(|| ApprovalError::InvalidReceiptPack {
                    reason: format!(
                        "receipt pack `{}` references a missing or unverified verdict",
                        report.pack_id
                    ),
                })?;
            if set.report != report.approval_set
                || ledger.report != report.ledger
                || verdict.report != report.verdict
                || report.verdict.status != ApprovalVerdictStatus::Approved
            {
                return Err(ApprovalError::InvalidReceiptPack {
                    reason: format!(
                        "receipt pack `{}` does not match its persisted approval artifacts",
                        report.pack_id
                    ),
                });
            }
            if !seen_approved_ledgers.insert((
                report.approval_set.set_id.clone(),
                report.ledger.ledger_id.clone(),
            )) {
                return Err(ApprovalError::InvalidReceiptPack {
                    reason: format!(
                        "approval ledger `{}` has multiple persisted receipt packs",
                        report.ledger.ledger_id
                    ),
                });
            }
            projection
                .authoritative
                .push(ApprovalReceiptPackLookup { record, report });
        }
        Ok(projection)
    }

    pub fn create_verdict(
        &self,
        approval_set_id: &str,
        ledger_id: &str,
    ) -> Result<ApprovalVerdictLookup, ApprovalError> {
        self.with_workflow_lock(|| self.create_verdict_unlocked(approval_set_id, ledger_id))
    }

    fn create_verdict_unlocked(
        &self,
        approval_set_id: &str,
        ledger_id: &str,
    ) -> Result<ApprovalVerdictLookup, ApprovalError> {
        let verdict_store = self.verdict_store()?;
        let set = self.load_approval_set(approval_set_id)?.ok_or_else(|| {
            ApprovalError::ApprovalSetNotFound {
                set_id: approval_set_id.to_string(),
            }
        })?;
        let ledger = self.load_ledger_unlocked(ledger_id)?.ok_or_else(|| {
            ApprovalError::ApprovalLedgerNotFound {
                ledger_id: ledger_id.to_string(),
            }
        })?;
        let existing = self
            .validated_verdicts_unlocked()?
            .into_iter()
            .filter(|lookup| {
                lookup.report.approval_set_id == approval_set_id
                    && lookup.report.ledger_id == ledger_id
                    && lookup.report.status == ApprovalVerdictStatus::Approved
            })
            .collect::<Vec<_>>();
        if existing.len() > 1 {
            return Err(ApprovalError::InvalidVerdictRequest {
                reason: format!("approval ledger `{ledger_id}` has multiple approved verdicts"),
            });
        }
        if let Some(lookup) = existing.into_iter().next() {
            return Ok(lookup);
        }
        let evaluated_at_ms = approval_verdict_timestamp_ms(&ledger.report, now_ms());
        let report = evaluate_verdict(&set.report, &ledger.report, evaluated_at_ms)?;
        if report.status != ApprovalVerdictStatus::Approved {
            return Err(ApprovalError::InvalidVerdictRequest {
                reason: format!(
                    "approval ledger `{ledger_id}` has not reached an approved terminal verdict"
                ),
            });
        }
        let record = verdict_store.persist(&report)?;
        Ok(ApprovalVerdictLookup { record, report })
    }

    pub fn load_verdict(
        &self,
        verdict_id: &str,
    ) -> Result<Option<ApprovalVerdictLookup>, ApprovalError> {
        self.with_workflow_lock(|| self.load_verdict_unlocked(verdict_id))
    }

    fn load_verdict_unlocked(
        &self,
        verdict_id: &str,
    ) -> Result<Option<ApprovalVerdictLookup>, ApprovalError> {
        Ok(self
            .validated_verdicts_unlocked()?
            .into_iter()
            .find(|lookup| lookup.report.verdict_id == verdict_id))
    }

    pub fn list_verdicts(&self) -> Result<ApprovalVerdictList, ApprovalError> {
        self.with_workflow_lock(|| {
            let verdicts = self
                .validated_verdicts_unlocked()?
                .into_iter()
                .map(|lookup| lookup.record)
                .collect::<Vec<_>>();
            Ok(ApprovalVerdictList {
                total_count: verdicts.len(),
                verdicts,
            })
        })
    }

    pub fn export_receipt_pack(
        &self,
        verdict_id: &str,
        signer_id: &str,
        signing_key_env: &str,
    ) -> Result<ApprovalReceiptPackLookup, ApprovalError> {
        self.with_workflow_lock(|| {
            self.export_receipt_pack_unlocked(verdict_id, signer_id, signing_key_env)
        })
    }

    fn export_receipt_pack_unlocked(
        &self,
        verdict_id: &str,
        signer_id: &str,
        signing_key_env: &str,
    ) -> Result<ApprovalReceiptPackLookup, ApprovalError> {
        let receipt_pack_store = self.receipt_pack_store()?;
        let verdict = self.load_verdict_unlocked(verdict_id)?.ok_or_else(|| {
            ApprovalError::ApprovalVerdictNotFound {
                verdict_id: verdict_id.to_string(),
            }
        })?;
        let set = self
            .load_approval_set(&verdict.report.approval_set_id)?
            .ok_or_else(|| ApprovalError::ApprovalSetNotFound {
                set_id: verdict.report.approval_set_id.clone(),
            })?;
        let ledger = self
            .load_ledger_unlocked(&verdict.report.ledger_id)?
            .ok_or_else(|| ApprovalError::ApprovalLedgerNotFound {
                ledger_id: verdict.report.ledger_id.clone(),
            })?;
        let existing = self
            .validated_receipt_packs_unlocked()?
            .authoritative
            .into_iter()
            .filter(|lookup| {
                lookup.report.approval_set.set_id == set.report.set_id
                    && lookup.report.ledger.ledger_id == ledger.report.ledger_id
            })
            .collect::<Vec<_>>();
        if existing.len() > 1 {
            return Err(ApprovalError::InvalidReceiptPack {
                reason: format!(
                    "approval ledger `{}` has multiple persisted receipt packs",
                    ledger.report.ledger_id
                ),
            });
        }
        if let Some(lookup) = existing.into_iter().next() {
            if lookup.report.approval_set != set.report
                || lookup.report.ledger != ledger.report
                || lookup.report.verdict != verdict.report
            {
                return Err(ApprovalError::InvalidReceiptPack {
                    reason: format!(
                        "receipt pack `{}` does not match the persisted approval artifacts",
                        lookup.report.pack_id
                    ),
                });
            }
            verify_receipt_pack(&lookup.report)?;
            return Ok(lookup);
        }
        let secret_material = std::env::var(signing_key_env)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ApprovalError::MissingSigningKey {
                env_name: signing_key_env.to_string(),
            })?;
        let signer = Ed25519Signer::from_secret_material(&secret_material);
        let created_at_ms = approval_receipt_timestamp_ms(&verdict.report, now_ms());
        let report = build_receipt_pack(
            &set.report,
            &ledger.report,
            &verdict.report,
            vec![set.report.promotion_evidence_ref.clone()],
            &signer,
            signer_id,
            created_at_ms,
        )?;
        let record = receipt_pack_store.persist(&report)?;
        Ok(ApprovalReceiptPackLookup { record, report })
    }

    pub fn ensure_approved_receipt_pack(
        &self,
        approval_set_id: &str,
        ledger_id: &str,
        signer_id: &str,
        signing_key_env: &str,
    ) -> Result<ApprovalReceiptPackLookup, ApprovalError> {
        self.with_workflow_lock(|| {
            let verdict = self.create_verdict_unlocked(approval_set_id, ledger_id)?;
            if verdict.report.status != ApprovalVerdictStatus::Approved {
                return Err(ApprovalError::InvalidVerdictRequest {
                    reason: format!(
                        "approval ledger `{ledger_id}` does not have an approved verdict"
                    ),
                });
            }
            self.export_receipt_pack_unlocked(
                &verdict.report.verdict_id,
                signer_id,
                signing_key_env,
            )
        })
    }

    pub fn load_receipt_pack(
        &self,
        pack_id: &str,
    ) -> Result<Option<ApprovalReceiptPackLookup>, ApprovalError> {
        self.with_workflow_lock(|| self.load_receipt_pack_unlocked(pack_id))
    }

    fn load_receipt_pack_unlocked(
        &self,
        pack_id: &str,
    ) -> Result<Option<ApprovalReceiptPackLookup>, ApprovalError> {
        Ok(self
            .validated_receipt_packs_unlocked()?
            .authoritative
            .into_iter()
            .find(|lookup| lookup.report.pack_id == pack_id))
    }

    pub fn list_receipt_packs(&self) -> Result<ApprovalReceiptPackList, ApprovalError> {
        self.with_workflow_lock(|| {
            let projection = self.validated_receipt_packs_unlocked()?;
            let packs = projection
                .authoritative
                .into_iter()
                .map(|lookup| lookup.record)
                .collect::<Vec<_>>();
            Ok(ApprovalReceiptPackList {
                total_count: packs.len(),
                packs,
                quarantined_count: projection.quarantined.len(),
                quarantined: projection.quarantined,
            })
        })
    }

    pub fn load_human_resume_outcome(
        &self,
        pack_id: &str,
    ) -> Result<Option<AuditTrail>, ApprovalError> {
        self.with_workflow_lock(|| {
            if self.load_receipt_pack_unlocked(pack_id)?.is_none() {
                return Err(ApprovalError::ApprovalReceiptPackNotFound {
                    pack_id: pack_id.to_string(),
                });
            }
            self.receipt_pack_store()?
                .load_resume_outcome(pack_id)
                .map_err(Into::into)
        })
    }

    pub fn persist_human_resume_outcome(
        &self,
        pack_id: &str,
        audit: &AuditTrail,
    ) -> Result<(), ApprovalError> {
        self.with_workflow_lock(|| {
            if self.load_receipt_pack_unlocked(pack_id)?.is_none() {
                return Err(ApprovalError::ApprovalReceiptPackNotFound {
                    pack_id: pack_id.to_string(),
                });
            }
            self.receipt_pack_store()?
                .persist_resume_outcome(pack_id, audit)?;
            Ok(())
        })
    }

    pub fn verify_receipt_pack(&self, pack_id: &str) -> Result<bool, ApprovalError> {
        let pack = self.load_receipt_pack(pack_id)?.ok_or_else(|| {
            ApprovalError::ApprovalReceiptPackNotFound {
                pack_id: pack_id.to_string(),
            }
        })?;
        verify_receipt_pack(&pack.report)?;
        Ok(true)
    }

    /// Upgrade pre-versioning ledgers in place without granting their V1 votes
    /// any authority. The workflow lock makes the rewrite single-writer across
    /// processes; retaining every V1 entry keeps the original append-only audit
    /// chain visible while the current quorum projection requires fresh V2
    /// votes from the same eligible operators.
    fn migrate_legacy_ledgers_unlocked(&self) -> Result<(), ApprovalError> {
        let index = self.ledger_store.read_index()?;
        for record in index.entries {
            let path = self.ledger_store.report_path(&record.ledger_id);
            let mut report = read_json::<ApprovalLedgerReport, ApprovalLedgerStoreError>(
                &path,
                |path, source| ApprovalLedgerStoreError::Read { path, source },
                |path, source| ApprovalLedgerStoreError::Parse { path, source },
            )?;
            validate_ledger_record(&self.ledger_store, &record, &report)?;
            match report.schema_version {
                CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION => {}
                LEGACY_APPROVAL_LEDGER_SCHEMA_VERSION => {
                    let set = self
                        .set_store
                        .load(&report.approval_set_id)?
                        .ok_or_else(|| ApprovalError::ApprovalSetNotFound {
                            set_id: report.approval_set_id.clone(),
                        })?;
                    validate_legacy_ledger_report(&report, &set.report)?;
                    report.schema_version = CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION;
                    self.ledger_store.persist(&report)?;
                }
                version => {
                    return Err(ApprovalError::InvalidLedgerRequest {
                        reason: format!(
                            "approval ledger `{}` uses unsupported schema version `{version}`",
                            report.ledger_id
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    fn load_stored_ledger_for_set(
        &self,
        set_id: &str,
    ) -> Result<ApprovalLedgerLookup, ApprovalError> {
        let ledgers = self
            .validated_ledgers_unlocked()?
            .into_iter()
            .filter(|lookup| lookup.report.approval_set_id == set_id)
            .collect::<Vec<_>>();
        match ledgers.len() {
            0 => Err(ApprovalError::MissingLedgerForSet {
                set_id: set_id.to_string(),
            }),
            1 => {
                let lookup = ledgers.into_iter().next().ok_or_else(|| {
                    ApprovalError::MissingLedgerForSet {
                        set_id: set_id.to_string(),
                    }
                })?;
                Ok(lookup)
            }
            count => Err(ApprovalError::AmbiguousLedgerForSet {
                set_id: set_id.to_string(),
                count,
            }),
        }
    }

    fn load_or_repair_stored_ledger_for_set(
        &self,
        set: &ApprovalSetReport,
    ) -> Result<ApprovalLedgerLookup, ApprovalError> {
        match self.load_stored_ledger_for_set(&set.set_id) {
            Ok(ledger) => return Ok(ledger),
            Err(ApprovalError::MissingLedgerForSet { .. }) => {}
            Err(error) => return Err(error),
        }

        // Set persistence precedes initial-ledger persistence. If a process
        // exits between those writes, recover only the deterministic ledger
        // identity. Preserve an already-written report (and all of its votes)
        // when only the index replacement was interrupted.
        let ledger_id = approval_ledger_id(&set.set_id, set.created_at_ms);
        let report_path = self.ledger_store.report_path(&ledger_id);
        let mut ledger = match fs::symlink_metadata(&report_path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                read_json::<ApprovalLedgerReport, ApprovalLedgerStoreError>(
                    &report_path,
                    |path, source| ApprovalLedgerStoreError::Read { path, source },
                    |path, source| ApprovalLedgerStoreError::Parse { path, source },
                )?
            }
            Ok(_) => {
                return Err(ApprovalError::LedgerRecoveryConflict {
                    set_id: set.set_id.clone(),
                    reason: "the deterministic ledger path is not a regular file".to_string(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => ApprovalLedgerReport {
                schema_version: CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION,
                ledger_id: ledger_id.clone(),
                approval_set_id: set.set_id.clone(),
                entries: Vec::new(),
                created_at_ms: set.created_at_ms,
            },
            Err(source) => {
                return Err(ApprovalLedgerStoreError::Read {
                    path: report_path,
                    source,
                }
                .into());
            }
        };
        if ledger.ledger_id != ledger_id
            || ledger.approval_set_id != set.set_id
            || ledger.created_at_ms != set.created_at_ms
        {
            return Err(ApprovalError::LedgerRecoveryConflict {
                set_id: set.set_id.clone(),
                reason: "the durable ledger report does not match the deterministic initial ledger identity"
                .to_string(),
            });
        }
        if ledger.schema_version == LEGACY_APPROVAL_LEDGER_SCHEMA_VERSION {
            validate_legacy_ledger_report(&ledger, set)?;
            ledger.schema_version = CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION;
        }
        validate_ledger_report(&ledger, set)?;
        self.ledger_store.persist(&ledger)?;
        self.load_stored_ledger_for_set(&set.set_id)
    }

    fn verdict_store(&self) -> Result<&FileApprovalVerdictStore, ApprovalError> {
        self.verdict_store
            .as_ref()
            .ok_or(ApprovalError::VerdictStoreNotConfigured)
    }

    fn receipt_pack_store(&self) -> Result<&FileApprovalReceiptPackStore, ApprovalError> {
        self.receipt_pack_store
            .as_ref()
            .ok_or(ApprovalError::ReceiptPackStoreNotConfigured)
    }

    fn workflow_lock(&self) -> Result<ApprovalWorkflowLock, ApprovalError> {
        ApprovalWorkflowLock::acquire(self.ledger_store.root.join(".approval-workflow.lock"))
    }

    fn workflow_snapshot(&self) -> Result<ApprovalWorkflowSnapshot, ApprovalError> {
        let mut roots = vec![self.set_store.root.clone(), self.ledger_store.root.clone()];
        if let Some(store) = &self.verdict_store {
            roots.push(store.root.clone());
        }
        if let Some(store) = &self.receipt_pack_store {
            roots.push(store.root.clone());
        }
        ApprovalWorkflowSnapshot::capture(
            roots,
            self.ledger_store.root.join(".approval-workflow.lock"),
        )
        .map_err(|source| {
            workflow_lock_error(
                &self.ledger_store.root.join(".approval-workflow.lock"),
                source,
            )
        })
    }

    fn with_workflow_lock<T>(
        &self,
        transition: impl FnOnce() -> Result<T, ApprovalError>,
    ) -> Result<T, ApprovalError> {
        let lock = self.workflow_lock()?;
        lock.verify()?;
        let snapshot = self.workflow_snapshot()?;
        #[cfg(test)]
        wait_for_workflow_test_hook(&lock.path);
        let result = self
            .migrate_legacy_ledgers_unlocked()
            .and_then(|()| transition());
        let lock_result = lock.verify();
        let snapshot_lock_result = snapshot.verify_lock_state();
        match (result, lock_result, snapshot_lock_result) {
            (Ok(value), Ok(()), Ok(())) => Ok(value),
            (result, lock_result, snapshot_lock_result) => {
                let snapshot_failure = snapshot_lock_result.err().map(|source| {
                    workflow_lock_error(
                        &self.ledger_store.root.join(".approval-workflow.lock"),
                        source,
                    )
                });
                let failure = lock_result
                    .err()
                    .or(snapshot_failure)
                    .or_else(|| result.err())
                    .ok_or_else(|| {
                        workflow_lock_error(
                            &self.ledger_store.root.join(".approval-workflow.lock"),
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "approval transition failed without an error",
                            ),
                        )
                    })?;
                snapshot.restore().map_err(|source| {
                    workflow_lock_error(
                        &self.ledger_store.root.join(".approval-workflow.lock"),
                        source,
                    )
                })?;
                Err(failure)
            }
        }
    }
}

pub fn validate_and_append_vote(
    ledger: &mut ApprovalLedgerReport,
    set: &ApprovalSetReport,
    intent: &ApprovalVoteIntent,
    signature: &DetachedSignature,
) -> Result<(), ApprovalError> {
    validate_and_append_vote_at(ledger, set, intent, signature, now_ms())
}

fn validate_persistable_vote_intent(intent: &ApprovalVoteIntent) -> Result<(), ApprovalError> {
    if intent.signature_version != ApprovalVoteSignatureVersion::IntentV2 {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: "approval vote intent must use the current V2 signature payload".to_string(),
        });
    }
    if intent.vote != ApprovalVote::Approve {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: "durable approval ledgers do not yet support denial votes".to_string(),
        });
    }
    Ok(())
}

fn validate_and_append_vote_at(
    ledger: &mut ApprovalLedgerReport,
    set: &ApprovalSetReport,
    intent: &ApprovalVoteIntent,
    signature: &DetachedSignature,
    observed_now_ms: i64,
) -> Result<(), ApprovalError> {
    if ledger.schema_version != CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: "current votes require a migrated V2 approval ledger".to_string(),
        });
    }
    validate_persistable_vote_intent(intent)?;
    verify_approval_vote_signature(intent, signature)?;
    let expected_voter_id = voter_id_from_public_key(&signature.public_key_hex);
    if intent.voter_id != expected_voter_id {
        return Err(ApprovalError::InvalidSignature {
            voter_id: intent.voter_id.clone(),
            reason: format!(
                "signature public key resolves to `{expected_voter_id}` instead of requested voter"
            ),
        });
    }
    if intent.approval_set_id != set.set_id
        || intent.ledger_id != ledger.ledger_id
        || ledger.approval_set_id != set.set_id
    {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: "approval vote intent is not bound to the target set and ledger".to_string(),
        });
    }
    if !set
        .eligible_voters
        .iter()
        .any(|eligible| eligible == &intent.voter_id)
    {
        return Err(ApprovalError::IneligibleVoter {
            voter_id: intent.voter_id.clone(),
        });
    }
    if ledger.entries.iter().any(|entry| {
        entry.signature_version == ApprovalVoteSignatureVersion::IntentV2
            && entry.voter_id == intent.voter_id
    }) {
        return Err(ApprovalError::DuplicateVoter {
            voter_id: intent.voter_id.clone(),
        });
    }
    let expected_entry_id = next_approval_ledger_entry_id(&ledger.ledger_id, ledger.entries.len());
    let expected_previous_envelope_hash = ledger
        .entries
        .last()
        .map(|entry| entry.envelope_hash.clone());
    if intent.entry_id != expected_entry_id
        || intent.previous_envelope_hash != expected_previous_envelope_hash
    {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: "approval vote intent does not extend the current ledger head".to_string(),
        });
    }
    if intent.timestamp_ms < ledger.created_at_ms
        || ledger
            .entries
            .iter()
            .rev()
            .find(|entry| entry.signature_version == ApprovalVoteSignatureVersion::IntentV2)
            .is_some_and(|previous| intent.timestamp_ms < previous.timestamp_ms)
    {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: "approval vote timestamp predates the current ledger head".to_string(),
        });
    }
    if intent.timestamp_ms > observed_now_ms.saturating_add(MAX_APPROVAL_VOTE_FUTURE_SKEW_MS) {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: "approval vote timestamp exceeds the allowed future clock skew".to_string(),
        });
    }

    let envelope_hash = build_vote_envelope_hash(ledger, intent, signature)?;

    ledger.entries.push(ApprovalLedgerEntry {
        entry_id: intent.entry_id.clone(),
        voter_id: intent.voter_id.clone(),
        vote: intent.vote,
        signature_version: intent.signature_version,
        signature: signature.clone(),
        timestamp_ms: intent.timestamp_ms,
        previous_envelope_hash: intent.previous_envelope_hash.clone(),
        envelope_hash,
    });
    Ok(())
}

pub fn evaluate_verdict(
    approval_set: &ApprovalSetReport,
    ledger: &ApprovalLedgerReport,
    evaluated_at_ms: i64,
) -> Result<ApprovalVerdictReport, ApprovalError> {
    if ledger.approval_set_id != approval_set.set_id {
        return Err(ApprovalError::InvalidVerdictRequest {
            reason: format!(
                "ledger `{}` belongs to approval set `{}` not `{}`",
                ledger.ledger_id, ledger.approval_set_id, approval_set.set_id
            ),
        });
    }

    let eligible = approval_set
        .eligible_voters
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if evaluated_at_ms < approval_set.created_at_ms
        || evaluated_at_ms < ledger.created_at_ms
        || ledger.entries.iter().any(|entry| {
            entry.signature_version == ApprovalVoteSignatureVersion::IntentV2
                && eligible.contains(entry.voter_id.as_str())
                && entry.timestamp_ms > evaluated_at_ms
        })
    {
        return Err(ApprovalError::InvalidVerdictRequest {
            reason: format!(
                "verdict evaluation for ledger `{}` predates its lineage or a counted vote",
                ledger.ledger_id
            ),
        });
    }
    let approve_count = ledger
        .entries
        .iter()
        .filter(|entry| {
            entry.signature_version == ApprovalVoteSignatureVersion::IntentV2
                && eligible.contains(entry.voter_id.as_str())
                && entry.vote.is_approve()
        })
        .count();
    let reject_count = ledger
        .entries
        .iter()
        .filter(|entry| {
            entry.signature_version == ApprovalVoteSignatureVersion::IntentV2
                && eligible.contains(entry.voter_id.as_str())
                && !entry.vote.is_approve()
        })
        .count();
    let seen_voters = ledger
        .entries
        .iter()
        .filter(|entry| {
            entry.signature_version == ApprovalVoteSignatureVersion::IntentV2
                && eligible.contains(entry.voter_id.as_str())
        })
        .map(|entry| entry.voter_id.as_str())
        .collect::<HashSet<_>>();
    let missing_voters = approval_set
        .eligible_voters
        .iter()
        .filter(|voter_id| !seen_voters.contains(voter_id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let eligible_count = approval_set.eligible_voters.len();
    let threshold_required_count = approval_set.threshold.required_count_for(eligible_count);
    let status = if approval_set
        .threshold
        .is_met_for(approve_count, reject_count, eligible_count)
    {
        ApprovalVerdictStatus::Approved
    } else {
        ApprovalVerdictStatus::NotApproved
    };
    let seed = ApprovalVerdictIdSeed {
        schema_version: CURRENT_APPROVAL_VERDICT_SCHEMA_VERSION,
        approval_set_id: &approval_set.set_id,
        ledger_id: &ledger.ledger_id,
        status,
        approve_count,
        reject_count,
        threshold_required_count,
        eligible_count,
        missing_voters: &missing_voters,
        evaluated_at_ms,
    };
    let verdict_id = approval_verdict_id(evaluated_at_ms, &canonical_json_bytes(&seed)?);

    Ok(ApprovalVerdictReport {
        schema_version: CURRENT_APPROVAL_VERDICT_SCHEMA_VERSION,
        verdict_id,
        approval_set_id: approval_set.set_id.clone(),
        ledger_id: ledger.ledger_id.clone(),
        status,
        approve_count,
        reject_count,
        threshold_required: render_threshold_rule_with_eligible(
            &approval_set.threshold,
            eligible_count,
        ),
        threshold_required_count,
        eligible_count,
        missing_voters,
        evaluated_at_ms,
    })
}

pub fn build_receipt_pack(
    approval_set: &ApprovalSetReport,
    ledger: &ApprovalLedgerReport,
    verdict: &ApprovalVerdictReport,
    audit_refs: Vec<String>,
    signer: &Ed25519Signer,
    signer_id: &str,
    created_at_ms: i64,
) -> Result<ApprovalReceiptPackReport, ApprovalError> {
    if ledger.schema_version != CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "receipt packs require the current approval-ledger schema".to_string(),
        });
    }
    if verdict.schema_version != CURRENT_APPROVAL_VERDICT_SCHEMA_VERSION {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "receipt packs require the current approval-verdict schema".to_string(),
        });
    }
    if created_at_ms < approval_set.created_at_ms
        || created_at_ms < ledger.created_at_ms
        || created_at_ms < verdict.evaluated_at_ms
    {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "receipt pack creation timestamp predates its approval lineage".to_string(),
        });
    }
    if ledger.entries.iter().any(|entry| {
        entry.signature_version == ApprovalVoteSignatureVersion::IntentV2
            && entry.timestamp_ms > verdict.evaluated_at_ms
    }) {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "receipt pack verdict predates a persisted approval vote".to_string(),
        });
    }
    if evaluate_verdict(approval_set, ledger, verdict.evaluated_at_ms)? != *verdict {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "receipt pack verdict does not match current authenticated votes".to_string(),
        });
    }
    let content = ApprovalReceiptPackContentRef {
        signature_version: ApprovalReceiptPackSignatureVersion::V2,
        signer_id,
        approval_set,
        ledger,
        verdict,
        audit_refs: audit_refs.as_slice(),
        created_at_ms,
    };
    let content_bytes = canonical_json_bytes(&content)?;
    let content_hash = sha256_hex(&content_bytes);
    let signature = signer.sign(&content_bytes);
    let seed = ApprovalReceiptPackIdSeed {
        signer_id,
        content_hash: &content_hash,
        signature_key_id: &signature.key_id,
        created_at_ms,
    };
    let pack_id = approval_receipt_pack_id(created_at_ms, &canonical_json_bytes(&seed)?);

    Ok(ApprovalReceiptPackReport {
        signature_version: ApprovalReceiptPackSignatureVersion::V2,
        pack_id,
        signer_id: signer_id.to_string(),
        approval_set: approval_set.clone(),
        ledger: ledger.clone(),
        verdict: verdict.clone(),
        audit_refs,
        content_hash,
        signature,
        created_at_ms,
    })
}

fn legacy_ledger_prefix(
    ledger: &ApprovalLedgerReport,
) -> Result<ApprovalLedgerReport, ApprovalError> {
    let legacy_len = ledger
        .entries
        .iter()
        .take_while(|entry| entry.signature_version == ApprovalVoteSignatureVersion::LegacyV1)
        .count();
    if ledger.entries[legacy_len..]
        .iter()
        .any(|entry| entry.signature_version == ApprovalVoteSignatureVersion::LegacyV1)
    {
        return Err(ApprovalError::InvalidLedgerRequest {
            reason: format!(
                "approval ledger `{}` places legacy audit history after current votes",
                ledger.ledger_id
            ),
        });
    }
    Ok(ApprovalLedgerReport {
        schema_version: LEGACY_APPROVAL_LEDGER_SCHEMA_VERSION,
        ledger_id: ledger.ledger_id.clone(),
        approval_set_id: ledger.approval_set_id.clone(),
        entries: ledger.entries[..legacy_len].to_vec(),
        created_at_ms: ledger.created_at_ms,
    })
}

fn evaluate_legacy_verdict(
    approval_set: &ApprovalSetReport,
    ledger: &ApprovalLedgerReport,
    evaluated_at_ms: i64,
) -> Result<ApprovalVerdictReport, ApprovalError> {
    if ledger.schema_version != LEGACY_APPROVAL_LEDGER_SCHEMA_VERSION
        || ledger.approval_set_id != approval_set.set_id
        || ledger.entries.iter().any(|entry| {
            entry.signature_version != ApprovalVoteSignatureVersion::LegacyV1
                || entry.timestamp_ms > evaluated_at_ms
        })
        || evaluated_at_ms < approval_set.created_at_ms
        || evaluated_at_ms < ledger.created_at_ms
    {
        return Err(ApprovalError::InvalidVerdictRequest {
            reason: "legacy approval verdict does not have a valid V1 lineage".to_string(),
        });
    }
    let eligible = approval_set
        .eligible_voters
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let approve_count = ledger
        .entries
        .iter()
        .filter(|entry| eligible.contains(entry.voter_id.as_str()) && entry.vote.is_approve())
        .count();
    let reject_count = ledger
        .entries
        .iter()
        .filter(|entry| eligible.contains(entry.voter_id.as_str()) && !entry.vote.is_approve())
        .count();
    let seen_voters = ledger
        .entries
        .iter()
        .filter(|entry| eligible.contains(entry.voter_id.as_str()))
        .map(|entry| entry.voter_id.as_str())
        .collect::<HashSet<_>>();
    let missing_voters = approval_set
        .eligible_voters
        .iter()
        .filter(|voter_id| !seen_voters.contains(voter_id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let eligible_count = approval_set.eligible_voters.len();
    let threshold_required_count = approval_set.threshold.required_count_for(eligible_count);
    let status = if approval_set
        .threshold
        .is_met_for(approve_count, reject_count, eligible_count)
    {
        ApprovalVerdictStatus::Approved
    } else {
        ApprovalVerdictStatus::NotApproved
    };
    let seed = LegacyApprovalVerdictIdSeed {
        approval_set_id: &approval_set.set_id,
        ledger_id: &ledger.ledger_id,
        status,
        approve_count,
        reject_count,
        threshold_required_count,
        eligible_count,
        missing_voters: &missing_voters,
        evaluated_at_ms,
    };
    let verdict_id = approval_verdict_id(evaluated_at_ms, &canonical_json_bytes(&seed)?);
    Ok(ApprovalVerdictReport {
        schema_version: LEGACY_APPROVAL_VERDICT_SCHEMA_VERSION,
        verdict_id,
        approval_set_id: approval_set.set_id.clone(),
        ledger_id: ledger.ledger_id.clone(),
        status,
        approve_count,
        reject_count,
        threshold_required: render_threshold_rule_with_eligible(
            &approval_set.threshold,
            eligible_count,
        ),
        threshold_required_count,
        eligible_count,
        missing_voters,
        evaluated_at_ms,
    })
}

fn validate_legacy_verdict_for_retirement(
    report: &ApprovalVerdictReport,
    approval_set: &ApprovalSetReport,
    ledger: &ApprovalLedgerReport,
) -> Result<(), ApprovalError> {
    if report.schema_version != LEGACY_APPROVAL_VERDICT_SCHEMA_VERSION
        || report.status != ApprovalVerdictStatus::Approved
    {
        return Err(ApprovalError::InvalidVerdictRequest {
            reason: format!(
                "approval verdict `{}` is not a retireable V1 terminal artifact",
                report.verdict_id
            ),
        });
    }
    let legacy = legacy_ledger_prefix(ledger)?;
    validate_legacy_ledger_report(&legacy, approval_set)?;
    if evaluate_legacy_verdict(approval_set, &legacy, report.evaluated_at_ms)? != *report {
        return Err(ApprovalError::InvalidVerdictRequest {
            reason: format!(
                "legacy approval verdict `{}` does not match its verified V1 lineage",
                report.verdict_id
            ),
        });
    }
    Ok(())
}

fn legacy_ledger_content_ref(ledger: &ApprovalLedgerReport) -> LegacyApprovalLedgerReportRef<'_> {
    LegacyApprovalLedgerReportRef {
        ledger_id: &ledger.ledger_id,
        approval_set_id: &ledger.approval_set_id,
        entries: ledger
            .entries
            .iter()
            .map(|entry| LegacyApprovalLedgerEntryRef {
                entry_id: &entry.entry_id,
                voter_id: &entry.voter_id,
                vote: entry.vote,
                signature: &entry.signature,
                timestamp_ms: entry.timestamp_ms,
                envelope_hash: &entry.envelope_hash,
            })
            .collect(),
        created_at_ms: ledger.created_at_ms,
    }
}

fn legacy_verdict_content_ref(
    verdict: &ApprovalVerdictReport,
) -> LegacyApprovalVerdictReportRef<'_> {
    LegacyApprovalVerdictReportRef {
        verdict_id: &verdict.verdict_id,
        approval_set_id: &verdict.approval_set_id,
        ledger_id: &verdict.ledger_id,
        status: verdict.status,
        approve_count: verdict.approve_count,
        reject_count: verdict.reject_count,
        threshold_required: &verdict.threshold_required,
        threshold_required_count: verdict.threshold_required_count,
        eligible_count: verdict.eligible_count,
        missing_voters: &verdict.missing_voters,
        evaluated_at_ms: verdict.evaluated_at_ms,
    }
}

fn validate_legacy_receipt_pack_for_retirement(
    pack: &ApprovalReceiptPackReport,
) -> Result<LegacyReceiptPackDisposition, ApprovalError> {
    if pack.signature_version != ApprovalReceiptPackSignatureVersion::LegacyV1
        || pack.ledger.schema_version != LEGACY_APPROVAL_LEDGER_SCHEMA_VERSION
        || pack.verdict.schema_version != LEGACY_APPROVAL_VERDICT_SCHEMA_VERSION
        || pack
            .ledger
            .entries
            .iter()
            .any(|entry| entry.signature_version != ApprovalVoteSignatureVersion::LegacyV1)
    {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "self-declared legacy receipt pack does not have the V1 wire shape".to_string(),
        });
    }
    if !approval_set_voters_are_canonical(&pack.approval_set.eligible_voters)
        || pack.approval_set.set_id != canonical_approval_set_id(&pack.approval_set)?
    {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "legacy receipt pack contains a non-canonical approval set".to_string(),
        });
    }
    validate_legacy_ledger_report(&pack.ledger, &pack.approval_set)?;
    validate_legacy_verdict_for_retirement(&pack.verdict, &pack.approval_set, &pack.ledger)?;
    let later_v1_content = LegacyApprovalReceiptPackContentRef {
        signer_id: &pack.signer_id,
        approval_set: &pack.approval_set,
        ledger: legacy_ledger_content_ref(&pack.ledger),
        verdict: legacy_verdict_content_ref(&pack.verdict),
        audit_refs: &pack.audit_refs,
        created_at_ms: pack.created_at_ms,
    };
    let full_metadata_payload = canonical_json_bytes(&later_v1_content)?;
    if sha256_hex(&full_metadata_payload) == pack.content_hash
        && verify_detached_signature(&full_metadata_payload, &pack.signature).is_ok()
    {
        if pack.created_at_ms < pack.verdict.evaluated_at_ms {
            return Err(ApprovalError::InvalidReceiptPack {
                reason: "legacy receipt pack predates its verified V1 verdict".to_string(),
            });
        }
        let expected_pack_id = canonical_receipt_pack_id(pack)?;
        if pack.pack_id != expected_pack_id {
            return Err(ApprovalError::InvalidReceiptPack {
                reason: format!(
                    "legacy pack ID mismatch: expected {}, observed {}",
                    expected_pack_id, pack.pack_id
                ),
            });
        }
        return Ok(LegacyReceiptPackDisposition::VerifiedRetired);
    }

    let signed_core = OriginalApprovalReceiptPackContentRef {
        approval_set: &pack.approval_set,
        ledger: legacy_ledger_content_ref(&pack.ledger),
        verdict: legacy_verdict_content_ref(&pack.verdict),
        audit_refs: &pack.audit_refs,
    };
    let signed_core_payload = canonical_json_bytes(&signed_core)?;
    if sha256_hex(&signed_core_payload) != pack.content_hash {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "legacy receipt content hash does not match a known V1 payload".to_string(),
        });
    }
    verify_detached_signature(&signed_core_payload, &pack.signature).map_err(|error| {
        ApprovalError::InvalidReceiptPack {
            reason: format!("legacy receipt core signature did not verify: {error}"),
        }
    })?;
    Ok(LegacyReceiptPackDisposition::AuthenticatedCoreOnly)
}

pub fn verify_receipt_pack(pack: &ApprovalReceiptPackReport) -> Result<(), ApprovalError> {
    if pack.signature_version == ApprovalReceiptPackSignatureVersion::LegacyV1 {
        let disposition = validate_legacy_receipt_pack_for_retirement(pack)?;
        return Err(ApprovalError::InvalidReceiptPack {
            reason: match disposition {
                LegacyReceiptPackDisposition::VerifiedRetired => {
                    "legacy approval receipt packs are retired and cannot authorize execution"
                        .to_string()
                }
                LegacyReceiptPackDisposition::AuthenticatedCoreOnly => {
                    "legacy approval receipt pack is quarantined because signer, creation time, and pack identity are unauthenticated"
                        .to_string()
                }
            },
        });
    }
    if pack.ledger.schema_version != CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION
        || pack.verdict.schema_version != CURRENT_APPROVAL_VERDICT_SCHEMA_VERSION
    {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "current receipt pack contains a non-current approval artifact".to_string(),
        });
    }
    let content = ApprovalReceiptPackContentRef {
        signature_version: pack.signature_version,
        signer_id: &pack.signer_id,
        approval_set: &pack.approval_set,
        ledger: &pack.ledger,
        verdict: &pack.verdict,
        audit_refs: pack.audit_refs.as_slice(),
        created_at_ms: pack.created_at_ms,
    };
    let content_bytes = canonical_json_bytes(&content)?;
    let computed_hash = sha256_hex(&content_bytes);
    if computed_hash != pack.content_hash {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: format!(
                "content hash mismatch: expected {}, computed {}",
                pack.content_hash, computed_hash
            ),
        });
    }
    verify_detached_signature(&content_bytes, &pack.signature).map_err(|error| {
        ApprovalError::InvalidReceiptPack {
            reason: error.to_string(),
        }
    })?;
    if pack.ledger.approval_set_id != pack.approval_set.set_id
        || pack.verdict.approval_set_id != pack.approval_set.set_id
        || pack.verdict.ledger_id != pack.ledger.ledger_id
        || pack.ledger.created_at_ms < pack.approval_set.created_at_ms
        || pack.ledger.entries.iter().any(|entry| {
            entry.signature_version == ApprovalVoteSignatureVersion::IntentV2
                && entry.timestamp_ms < pack.ledger.created_at_ms
        })
        || pack.ledger.entries.iter().any(|entry| {
            entry.signature_version == ApprovalVoteSignatureVersion::IntentV2
                && entry.timestamp_ms > pack.verdict.evaluated_at_ms
        })
        || pack.verdict.evaluated_at_ms < pack.ledger.created_at_ms
        || pack.created_at_ms < pack.verdict.evaluated_at_ms
    {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "receipt pack lineage or timestamps are inconsistent".to_string(),
        });
    }
    let expected_set_id = canonical_approval_set_id(&pack.approval_set)?;
    if !approval_set_voters_are_canonical(&pack.approval_set.eligible_voters)
        || pack.approval_set.set_id != expected_set_id
    {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "approval set or ledger identifier is not canonical".to_string(),
        });
    }
    if evaluate_verdict(
        &pack.approval_set,
        &pack.ledger,
        pack.verdict.evaluated_at_ms,
    )? != pack.verdict
    {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "receipt pack verdict does not match current authenticated votes".to_string(),
        });
    }
    let expected_pack_id = canonical_receipt_pack_id(pack)?;
    if pack.pack_id != expected_pack_id {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: format!(
                "pack ID mismatch: expected {}, observed {}",
                expected_pack_id, pack.pack_id
            ),
        });
    }
    Ok(())
}

/// Canonical digest used to bind a governance human hold to the exact approval
/// set persisted before any votes are accepted.
pub fn approval_set_digest(report: &ApprovalSetReport) -> Result<String, ApprovalError> {
    Ok(approval_set_report_digest(report)?)
}

fn approval_set_report_digest(report: &ApprovalSetReport) -> Result<String, CryptoError> {
    Ok(sha256_hex(&canonical_json_bytes(report)?))
}

/// Verify the complete locally persisted human-approval artifact against one
/// governed hold. The caller must separately prove `pack` is byte-for-byte the
/// pack loaded from its durable store; this function validates its cryptographic
/// and internal lineage plus the exact hold binding.
pub fn verify_governed_human_receipt_pack(
    pack: &ApprovalReceiptPackReport,
    expected_set_id: &str,
    expected_set_digest: &str,
    expected_evidence_ref: &str,
    hold_created_at_ms: i64,
    now_ms: i64,
) -> Result<(), ApprovalError> {
    const MAX_HUMAN_APPROVAL_AGE_MS: i64 = 300_000;
    const MAX_HUMAN_APPROVAL_FUTURE_SKEW_MS: i64 = 30_000;

    verify_receipt_pack(pack)?;
    if pack.approval_set.set_id != expected_set_id
        || approval_set_digest(&pack.approval_set)? != expected_set_digest
    {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "approval set does not match the persisted governance hold".into(),
        });
    }
    if pack.approval_set.promotion_evidence_ref != expected_evidence_ref
        || !pack
            .audit_refs
            .iter()
            .any(|reference| reference == expected_evidence_ref)
    {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "approval receipt pack is not bound to the governed request".into(),
        });
    }
    if pack.approval_set.created_at_ms < hold_created_at_ms
        || pack.verdict.evaluated_at_ms < hold_created_at_ms
        || pack.created_at_ms < pack.verdict.evaluated_at_ms
    {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "approval receipt pack predates the governance hold".into(),
        });
    }
    if pack.created_at_ms > now_ms.saturating_add(MAX_HUMAN_APPROVAL_FUTURE_SKEW_MS) {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "approval receipt pack was created too far in the future".into(),
        });
    }
    if now_ms.saturating_sub(pack.created_at_ms) > MAX_HUMAN_APPROVAL_AGE_MS {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "approval receipt pack is stale".into(),
        });
    }
    if pack.ledger.approval_set_id != pack.approval_set.set_id
        || pack.verdict.approval_set_id != pack.approval_set.set_id
        || pack.verdict.ledger_id != pack.ledger.ledger_id
        || pack.ledger.ledger_id
            != approval_ledger_id(&pack.approval_set.set_id, pack.approval_set.created_at_ms)
    {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "approval set, ledger, and verdict lineage do not agree".into(),
        });
    }

    validate_ledger_report(&pack.ledger, &pack.approval_set).map_err(|error| {
        ApprovalError::InvalidReceiptPack {
            reason: format!("approval vote ledger could not be replayed exactly: {error}"),
        }
    })?;
    if pack.ledger.entries.iter().any(|entry| {
        entry.signature_version == ApprovalVoteSignatureVersion::IntentV2
            && entry.vote != ApprovalVote::Approve
    }) {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "governed execution requires explicit approve votes".into(),
        });
    }

    let expected_verdict = evaluate_verdict(
        &pack.approval_set,
        &pack.ledger,
        pack.verdict.evaluated_at_ms,
    )?;
    if expected_verdict != pack.verdict || pack.verdict.status != ApprovalVerdictStatus::Approved {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "approval verdict is not an internally valid approval".into(),
        });
    }
    let expected_pack_id = approval_receipt_pack_id(
        pack.created_at_ms,
        &canonical_json_bytes(&ApprovalReceiptPackIdSeed {
            signer_id: &pack.signer_id,
            content_hash: &pack.content_hash,
            signature_key_id: &pack.signature.key_id,
            created_at_ms: pack.created_at_ms,
        })?,
    );
    if pack.pack_id != expected_pack_id {
        return Err(ApprovalError::InvalidReceiptPack {
            reason: "approval receipt-pack identifier is not canonical".into(),
        });
    }
    Ok(())
}

pub fn render_approval_set(report: &ApprovalSetReport) -> String {
    let mut lines = vec![
        format!("Approval Set: {}", report.set_id),
        format!("Created: {}", report.created_at_ms),
        format!(
            "Threshold: {}",
            render_threshold_rule_with_eligible(&report.threshold, report.eligible_voters.len())
        ),
        format!("Promotion Evidence: {}", report.promotion_evidence_ref),
        format!("Eligible Voters ({})", report.eligible_voters.len()),
    ];
    lines.extend(
        report
            .eligible_voters
            .iter()
            .map(|voter_id| format!("  - {voter_id}")),
    );
    lines.join("\n")
}

pub fn render_approval_ledger(
    report: &ApprovalLedgerReport,
    quorum: &ApprovalLedgerQuorumState,
) -> String {
    let mut lines = vec![
        format!("Approval Ledger: {}", report.ledger_id),
        format!("Schema Version: {}", report.schema_version),
        format!("Approval Set: {}", report.approval_set_id),
        format!("Created: {}", report.created_at_ms),
        format!(
            "Quorum: {}/{} {}",
            quorum.votes_received,
            quorum.votes_required,
            if quorum.quorum_met {
                "(met)"
            } else {
                "(missing)"
            }
        ),
    ];
    if quorum.voters_remaining.is_empty() {
        lines.push("Remaining Voters: none".to_string());
    } else {
        lines.push(format!(
            "Remaining Voters: {}",
            quorum.voters_remaining.join(", ")
        ));
    }

    if report.entries.is_empty() {
        lines.push("Votes: none".to_string());
    } else {
        lines.push(format!("Votes ({})", report.entries.len()));
        lines.extend(report.entries.iter().map(|entry| {
            let authority = match entry.signature_version {
                ApprovalVoteSignatureVersion::LegacyV1 => "retired legacy audit",
                ApprovalVoteSignatureVersion::IntentV2 => "current authority",
            };
            format!(
                "  - {} at {} [{}; {authority}]",
                entry.voter_id, entry.timestamp_ms, entry.entry_id,
            )
        }));
    }

    lines.join("\n")
}

pub fn render_approval_set_list(list: &ApprovalSetList) -> String {
    let mut lines = vec![format!("Approval Sets ({})", list.total_count)];
    if list.sets.is_empty() {
        lines.push("none".to_string());
        return lines.join("\n");
    }

    lines.extend(list.sets.iter().map(|record| {
        format!(
            "- {} voters={} threshold={} created={}",
            record.set_id,
            record.voter_count,
            render_threshold_rule_with_eligible(&record.threshold, record.voter_count),
            record.created_at_ms
        )
    }));
    lines.join("\n")
}

pub fn render_approval_ledger_list(list: &ApprovalLedgerList) -> String {
    let title = if let Some(set_id) = &list.approval_set_id {
        format!("Approval Ledgers for {set_id} ({})", list.total_count)
    } else {
        format!("Approval Ledgers ({})", list.total_count)
    };
    let mut lines = vec![title];
    if list.ledgers.is_empty() {
        lines.push("none".to_string());
        return lines.join("\n");
    }

    lines.extend(list.ledgers.iter().map(|record| {
        format!(
            "- {} set={} votes={} created={}",
            record.ledger_id, record.approval_set_id, record.vote_count, record.created_at_ms
        )
    }));
    lines.join("\n")
}

pub fn render_approval_verdict(report: &ApprovalVerdictReport) -> String {
    let mut lines = vec![
        format!("Approval Verdict: {}", report.verdict_id),
        format!("Schema Version: {}", report.schema_version),
        format!("Approval Set: {}", report.approval_set_id),
        format!("Ledger: {}", report.ledger_id),
        format!("Status: {:?}", report.status),
        format!("Approvals: {}", report.approve_count),
        format!("Rejects: {}", report.reject_count),
        format!("Threshold: {}", report.threshold_required),
        format!("Eligible Voters: {}", report.eligible_count),
        format!("Evaluated: {}", report.evaluated_at_ms),
    ];
    if report.missing_voters.is_empty() {
        lines.push("Missing Voters: none".to_string());
    } else {
        lines.push(format!(
            "Missing Voters: {}",
            report.missing_voters.join(", ")
        ));
    }
    lines.join("\n")
}

pub fn render_approval_verdict_list(list: &ApprovalVerdictList) -> String {
    let mut lines = vec![format!("Approval Verdicts ({})", list.total_count)];
    if list.verdicts.is_empty() {
        lines.push("none".to_string());
        return lines.join("\n");
    }

    lines.extend(list.verdicts.iter().map(|record| {
        format!(
            "- {} status={:?} approvals={} rejects={} created={}",
            record.verdict_id,
            record.status,
            record.approve_count,
            record.reject_count,
            record.created_at_ms
        )
    }));
    lines.join("\n")
}

pub fn render_approval_receipt_pack(report: &ApprovalReceiptPackReport) -> String {
    [
        format!("Approval Receipt Pack: {}", report.pack_id),
        format!("Signature Version: {:?}", report.signature_version),
        format!("Signer: {}", report.signer_id),
        format!("Approval Set: {}", report.approval_set.set_id),
        format!("Ledger: {}", report.ledger.ledger_id),
        format!(
            "Verdict: {} ({:?})",
            report.verdict.verdict_id, report.verdict.status
        ),
        format!("Content Hash: {}", report.content_hash),
        format!("Signature Key: {}", report.signature.key_id),
        format!("Created: {}", report.created_at_ms),
        format!("Audit Refs: {}", report.audit_refs.join(", ")),
    ]
    .join("\n")
}

pub fn render_approval_receipt_pack_list(list: &ApprovalReceiptPackList) -> String {
    let mut lines = vec![format!("Approval Receipt Packs ({})", list.total_count)];
    if list.packs.is_empty() {
        lines.push("none".to_string());
    } else {
        lines.extend(list.packs.iter().map(|record| {
            format!(
                "- {} verdict={} set={} created={}",
                record.pack_id, record.verdict_id, record.approval_set_id, record.created_at_ms
            )
        }));
    }
    lines.push(format!(
        "Quarantined Legacy Receipt Packs ({})",
        list.quarantined_count
    ));
    if list.quarantined.is_empty() {
        lines.push("none".to_string());
    } else {
        lines.extend(list.quarantined.iter().map(|record| {
            format!(
                "- observed_id={} signature_key={} core_hash={} reason={}",
                record.observed_pack_id,
                record.signature_key_id,
                record.authenticated_core_hash,
                record.reason
            )
        }));
    }
    lines.join("\n")
}

#[derive(Serialize)]
struct ApprovalSetIdSeed<'a> {
    eligible_voters: &'a [String],
    threshold: &'a ThresholdRule,
    promotion_evidence_ref: &'a str,
    created_at_ms: i64,
}

#[derive(Serialize)]
struct ApprovalVerdictIdSeed<'a> {
    schema_version: u32,
    approval_set_id: &'a str,
    ledger_id: &'a str,
    status: ApprovalVerdictStatus,
    approve_count: usize,
    reject_count: usize,
    threshold_required_count: usize,
    eligible_count: usize,
    missing_voters: &'a [String],
    evaluated_at_ms: i64,
}

#[derive(Serialize)]
struct LegacyApprovalVerdictIdSeed<'a> {
    approval_set_id: &'a str,
    ledger_id: &'a str,
    status: ApprovalVerdictStatus,
    approve_count: usize,
    reject_count: usize,
    threshold_required_count: usize,
    eligible_count: usize,
    missing_voters: &'a [String],
    evaluated_at_ms: i64,
}

#[derive(Serialize)]
struct ApprovalReceiptPackIdSeed<'a> {
    signer_id: &'a str,
    content_hash: &'a str,
    signature_key_id: &'a str,
    created_at_ms: i64,
}

#[derive(Serialize)]
struct ApprovalReceiptPackContentRef<'a> {
    signature_version: ApprovalReceiptPackSignatureVersion,
    signer_id: &'a str,
    approval_set: &'a ApprovalSetReport,
    ledger: &'a ApprovalLedgerReport,
    verdict: &'a ApprovalVerdictReport,
    audit_refs: &'a [String],
    created_at_ms: i64,
}

#[derive(Serialize)]
struct LegacyApprovalLedgerEntryRef<'a> {
    entry_id: &'a str,
    voter_id: &'a str,
    vote: ApprovalVote,
    signature: &'a DetachedSignature,
    timestamp_ms: i64,
    envelope_hash: &'a str,
}

#[derive(Serialize)]
struct LegacyApprovalLedgerReportRef<'a> {
    ledger_id: &'a str,
    approval_set_id: &'a str,
    entries: Vec<LegacyApprovalLedgerEntryRef<'a>>,
    created_at_ms: i64,
}

#[derive(Serialize)]
struct LegacyApprovalVerdictReportRef<'a> {
    verdict_id: &'a str,
    approval_set_id: &'a str,
    ledger_id: &'a str,
    status: ApprovalVerdictStatus,
    approve_count: usize,
    reject_count: usize,
    threshold_required: &'a str,
    threshold_required_count: usize,
    eligible_count: usize,
    missing_voters: &'a [String],
    evaluated_at_ms: i64,
}

#[derive(Serialize)]
struct LegacyApprovalReceiptPackContentRef<'a> {
    signer_id: &'a str,
    approval_set: &'a ApprovalSetReport,
    ledger: LegacyApprovalLedgerReportRef<'a>,
    verdict: LegacyApprovalVerdictReportRef<'a>,
    audit_refs: &'a [String],
    created_at_ms: i64,
}

#[derive(Serialize)]
struct OriginalApprovalReceiptPackContentRef<'a> {
    approval_set: &'a ApprovalSetReport,
    ledger: LegacyApprovalLedgerReportRef<'a>,
    verdict: LegacyApprovalVerdictReportRef<'a>,
    audit_refs: &'a [String],
}

fn approval_set_id(created_at_ms: i64, seed_bytes: &[u8]) -> String {
    let digest = sha256_hex(seed_bytes);
    format!("approval-set:{created_at_ms}:{}", &digest[..12])
}

fn canonical_approval_set_id_fields(
    eligible_voters: &[String],
    threshold: &ThresholdRule,
    promotion_evidence_ref: &str,
    created_at_ms: i64,
) -> Result<String, CryptoError> {
    let seed = ApprovalSetIdSeed {
        eligible_voters,
        threshold,
        promotion_evidence_ref,
        created_at_ms,
    };
    Ok(approval_set_id(
        created_at_ms,
        &canonical_json_bytes(&seed)?,
    ))
}

fn canonical_approval_set_id(report: &ApprovalSetReport) -> Result<String, CryptoError> {
    canonical_approval_set_id_fields(
        &report.eligible_voters,
        &report.threshold,
        &report.promotion_evidence_ref,
        report.created_at_ms,
    )
}

fn approval_set_voters_are_canonical(eligible_voters: &[String]) -> bool {
    !eligible_voters.is_empty()
        && eligible_voters
            .iter()
            .all(|voter_id| voter_id.trim() == voter_id && !voter_id.is_empty())
        && eligible_voters.windows(2).all(|pair| pair[0] < pair[1])
}

fn approval_ledger_id(set_id: &str, created_at_ms: i64) -> String {
    let digest = sha256_hex(set_id.as_bytes());
    format!("approval-ledger:{created_at_ms}:{}", &digest[..12])
}

fn approval_verdict_id(created_at_ms: i64, seed_bytes: &[u8]) -> String {
    let digest = sha256_hex(seed_bytes);
    format!("approval-verdict:{created_at_ms}:{}", &digest[..12])
}

fn canonical_receipt_pack_id(pack: &ApprovalReceiptPackReport) -> Result<String, ApprovalError> {
    let seed = ApprovalReceiptPackIdSeed {
        signer_id: &pack.signer_id,
        content_hash: &pack.content_hash,
        signature_key_id: &pack.signature.key_id,
        created_at_ms: pack.created_at_ms,
    };
    Ok(approval_receipt_pack_id(
        pack.created_at_ms,
        &canonical_json_bytes(&seed)?,
    ))
}

fn canonical_approval_verdict_id(report: &ApprovalVerdictReport) -> Result<String, ApprovalError> {
    let seed_bytes = match report.schema_version {
        LEGACY_APPROVAL_VERDICT_SCHEMA_VERSION => {
            canonical_json_bytes(&LegacyApprovalVerdictIdSeed {
                approval_set_id: &report.approval_set_id,
                ledger_id: &report.ledger_id,
                status: report.status,
                approve_count: report.approve_count,
                reject_count: report.reject_count,
                threshold_required_count: report.threshold_required_count,
                eligible_count: report.eligible_count,
                missing_voters: &report.missing_voters,
                evaluated_at_ms: report.evaluated_at_ms,
            })?
        }
        CURRENT_APPROVAL_VERDICT_SCHEMA_VERSION => canonical_json_bytes(&ApprovalVerdictIdSeed {
            schema_version: report.schema_version,
            approval_set_id: &report.approval_set_id,
            ledger_id: &report.ledger_id,
            status: report.status,
            approve_count: report.approve_count,
            reject_count: report.reject_count,
            threshold_required_count: report.threshold_required_count,
            eligible_count: report.eligible_count,
            missing_voters: &report.missing_voters,
            evaluated_at_ms: report.evaluated_at_ms,
        })?,
        unsupported => {
            return Err(ApprovalError::InvalidVerdictRequest {
                reason: format!("unsupported approval verdict schema version `{unsupported}`"),
            });
        }
    };
    Ok(approval_verdict_id(report.evaluated_at_ms, &seed_bytes))
}

fn approval_receipt_pack_id(created_at_ms: i64, seed_bytes: &[u8]) -> String {
    let digest = sha256_hex(seed_bytes);
    format!("approval-receipt-pack:{created_at_ms}:{}", &digest[..12])
}

fn next_approval_ledger_entry_id(ledger_id: &str, current_len: usize) -> String {
    format!(
        "approval-ledger-entry:{}:{}",
        sanitize_id(ledger_id),
        current_len + 1
    )
}

fn normalize_voter_ids(voter_ids: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for voter_id in voter_ids {
        let voter_id = voter_id.trim().to_string();
        if voter_id.is_empty() || !seen.insert(voter_id.clone()) {
            continue;
        }
        normalized.push(voter_id);
    }
    normalized.sort();
    normalized
}

fn render_threshold_rule_with_eligible(rule: &ThresholdRule, eligible_count: usize) -> String {
    match rule {
        ThresholdRule::AtLeast { required } => format!("at least {required}"),
        ThresholdRule::Majority => {
            if eligible_count == 0 {
                "majority".to_string()
            } else {
                format!("majority ({})", rule.required_count_for(eligible_count))
            }
        }
        ThresholdRule::Unanimous => {
            if eligible_count == 0 {
                "unanimous".to_string()
            } else {
                format!("unanimous ({eligible_count})")
            }
        }
    }
}

fn voter_id_from_public_key(public_key_hex: &str) -> String {
    format!("swarm:ed25519:{public_key_hex}")
}

fn legacy_approval_vote_payload_bytes(
    approval_set_id: &str,
    ledger_id: &str,
    voter_id: &str,
) -> Result<Vec<u8>, ApprovalError> {
    canonical_json_bytes(&json!({
        "approval_set_id": approval_set_id,
        "ledger_id": ledger_id,
        "voter_id": voter_id,
    }))
    .map_err(Into::into)
}

fn build_legacy_vote_envelope_hash(
    ledger: &ApprovalLedgerReport,
    entry_id: &str,
    voter_id: &str,
    signature: &DetachedSignature,
    timestamp_ms: i64,
) -> Result<String, ApprovalError> {
    let published_at = DateTime::<Utc>::from_timestamp_millis(timestamp_ms)
        .ok_or_else(|| ApprovalError::InvalidLedgerRequest {
            reason: format!("legacy approval vote timestamp `{timestamp_ms}` is out of range"),
        })?
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    let keypair = Keypair::from_seed(
        sha256(format!("approval-ledger-envelope:{}", ledger.ledger_id).as_bytes()).as_bytes(),
    );
    let envelope = build_signed_envelope(
        &keypair,
        (ledger.entries.len() + 1) as u64,
        ledger
            .entries
            .last()
            .map(|entry| entry.envelope_hash.clone()),
        json!({
            "type": "approval_vote",
            "approval_set_id": ledger.approval_set_id,
            "ledger_id": ledger.ledger_id,
            "entry_id": entry_id,
            "voter_id": voter_id,
            "timestamp_ms": timestamp_ms,
            "signature": signature,
        }),
        published_at,
    )?;
    if !verify_envelope(&envelope)? {
        return Err(ApprovalError::InvalidSignature {
            voter_id: voter_id.to_string(),
            reason: "legacy spine envelope did not verify".to_string(),
        });
    }
    envelope
        .get("envelope_hash")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or(SpineError::MissingField("envelope_hash").into())
}

pub fn build_approval_vote_intent(
    ledger: &ApprovalLedgerReport,
    voter_id: &str,
    vote: ApprovalVote,
    timestamp_ms: i64,
) -> ApprovalVoteIntent {
    ApprovalVoteIntent {
        signature_version: ApprovalVoteSignatureVersion::IntentV2,
        approval_set_id: ledger.approval_set_id.clone(),
        ledger_id: ledger.ledger_id.clone(),
        entry_id: next_approval_ledger_entry_id(&ledger.ledger_id, ledger.entries.len()),
        voter_id: voter_id.to_string(),
        vote,
        timestamp_ms,
        previous_envelope_hash: ledger
            .entries
            .last()
            .map(|entry| entry.envelope_hash.clone()),
    }
}

pub fn approval_vote_payload_bytes(intent: &ApprovalVoteIntent) -> Result<Vec<u8>, ApprovalError> {
    canonical_json_bytes(intent).map_err(Into::into)
}

fn approval_vote_intent_from_entry(
    ledger: &ApprovalLedgerReport,
    entry: &ApprovalLedgerEntry,
) -> ApprovalVoteIntent {
    ApprovalVoteIntent {
        signature_version: entry.signature_version,
        approval_set_id: ledger.approval_set_id.clone(),
        ledger_id: ledger.ledger_id.clone(),
        entry_id: entry.entry_id.clone(),
        voter_id: entry.voter_id.clone(),
        vote: entry.vote,
        timestamp_ms: entry.timestamp_ms,
        previous_envelope_hash: entry.previous_envelope_hash.clone(),
    }
}

fn verify_approval_vote_signature(
    intent: &ApprovalVoteIntent,
    signature: &DetachedSignature,
) -> Result<(), ApprovalError> {
    validate_persistable_vote_intent(intent)?;
    verify_approval_vote_signature_raw(intent, signature)
}

fn verify_approval_vote_signature_raw(
    intent: &ApprovalVoteIntent,
    signature: &DetachedSignature,
) -> Result<(), ApprovalError> {
    verify_detached_signature(&approval_vote_payload_bytes(intent)?, signature).map_err(|error| {
        ApprovalError::InvalidSignature {
            voter_id: intent.voter_id.clone(),
            reason: error.to_string(),
        }
    })
}

fn build_vote_envelope_hash(
    ledger: &ApprovalLedgerReport,
    intent: &ApprovalVoteIntent,
    signature: &DetachedSignature,
) -> Result<String, ApprovalError> {
    let published_at = DateTime::<Utc>::from_timestamp_millis(intent.timestamp_ms)
        .ok_or_else(|| ApprovalError::InvalidReceiptPack {
            reason: format!(
                "approval vote timestamp `{}` is out of range",
                intent.timestamp_ms
            ),
        })?
        // Preserve the historical seconds-precision wire value while deriving it
        // from the persisted vote timestamp instead of verification wall clock.
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    let keypair = Keypair::from_seed(
        sha256(format!("approval-ledger-envelope:{}", ledger.ledger_id).as_bytes()).as_bytes(),
    );
    let envelope = build_signed_envelope(
        &keypair,
        (ledger.entries.len() + 1) as u64,
        intent.previous_envelope_hash.clone(),
        json!({
            "type": "approval_vote",
            "signature_version": intent.signature_version,
            "approval_set_id": intent.approval_set_id,
            "ledger_id": intent.ledger_id,
            "entry_id": intent.entry_id,
            "voter_id": intent.voter_id,
            "vote": intent.vote,
            "timestamp_ms": intent.timestamp_ms,
            "previous_envelope_hash": intent.previous_envelope_hash,
            "signature": signature,
        }),
        published_at,
    )?;

    if !verify_envelope(&envelope)? {
        return Err(ApprovalError::InvalidSignature {
            voter_id: intent.voter_id.clone(),
            reason: "generated spine envelope did not verify".to_string(),
        });
    }

    envelope
        .get("envelope_hash")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or(SpineError::MissingField("envelope_hash").into())
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn next_approval_vote_timestamp_ms(ledger: &ApprovalLedgerReport, observed_now_ms: i64) -> i64 {
    ledger
        .entries
        .iter()
        .filter(|entry| entry.signature_version == ApprovalVoteSignatureVersion::IntentV2)
        .fold(
            observed_now_ms.max(ledger.created_at_ms),
            |latest, entry| latest.max(entry.timestamp_ms),
        )
}

fn approval_verdict_timestamp_ms(ledger: &ApprovalLedgerReport, observed_now_ms: i64) -> i64 {
    ledger
        .entries
        .iter()
        .filter(|entry| entry.signature_version == ApprovalVoteSignatureVersion::IntentV2)
        .fold(
            observed_now_ms.max(ledger.created_at_ms),
            |latest, entry| latest.max(entry.timestamp_ms),
        )
}

fn approval_receipt_timestamp_ms(verdict: &ApprovalVerdictReport, observed_now_ms: i64) -> i64 {
    observed_now_ms.max(verdict.evaluated_at_ms)
}

fn read_json<T, E>(
    path: &Path,
    read_error: impl Fn(PathBuf, std::io::Error) -> E,
    parse_error: impl Fn(PathBuf, serde_json::Error) -> E,
) -> Result<T, E>
where
    T: DeserializeOwned,
{
    let raw = fs::read_to_string(path).map_err(|source| read_error(path.to_path_buf(), source))?;
    serde_json::from_str(&raw).map_err(|source| parse_error(path.to_path_buf(), source))
}

fn read_json_or_default<T, E>(
    path: &Path,
    read_error: impl Fn(PathBuf, std::io::Error) -> E,
    parse_error: impl Fn(PathBuf, serde_json::Error) -> E,
) -> Result<T, E>
where
    T: DeserializeOwned + Default,
{
    if !path.exists() {
        return Ok(T::default());
    }
    read_json(path, read_error, parse_error)
}

fn write_pretty_json<T, E>(
    path: &Path,
    value: &T,
    write_error: impl Fn(PathBuf, std::io::Error) -> E,
    parse_error: impl Fn(PathBuf, serde_json::Error) -> E,
) -> Result<(), E>
where
    T: Serialize,
{
    let json = serde_json::to_vec_pretty(value)
        .map_err(|source| parse_error(path.to_path_buf(), source))?;
    fs::write(path, json).map_err(|source| write_error(path.to_path_buf(), source))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "swarm-runtime-approval-{label}-{}-{}",
                std::process::id(),
                now_ms()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn child(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn capture_store_tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut files = BTreeMap::new();
        capture_store_files(root, &mut files).unwrap();
        files
    }

    fn install_legacy_wire_ledger(
        set_root: &Path,
        ledger_root: &Path,
        set: &ApprovalSetReport,
        ledger_bytes: &[u8],
    ) -> ApprovalLedgerReport {
        let set_store = FileApprovalSetStore::open(set_root).unwrap();
        set_store.persist(set).unwrap();
        let ledger_store = FileApprovalLedgerStore::open(ledger_root).unwrap();
        let report: ApprovalLedgerReport = serde_json::from_slice(ledger_bytes).unwrap();
        assert_eq!(report.schema_version, LEGACY_APPROVAL_LEDGER_SCHEMA_VERSION);
        let path = ledger_store.report_path(&report.ledger_id);
        fs::write(&path, ledger_bytes).unwrap();
        ledger_store
            .write_index(&ApprovalLedgerIndex {
                entries: vec![ApprovalLedgerRecord::from_report(
                    &report,
                    path.display().to_string(),
                )],
            })
            .unwrap();
        report
    }

    fn capture_workflow_lock_file(path: &Path) -> (Vec<u8>, String) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.file_type().is_file());
        (
            fs::read(path).unwrap(),
            workflow_lock_file_identity(&metadata),
        )
    }

    fn capture_workflow_lock_identity(path: &Path) -> (Vec<u8>, String) {
        let identity_path = workflow_lock_identity_path(path);
        let metadata = fs::symlink_metadata(&identity_path).unwrap();
        assert!(metadata.file_type().is_file());
        (
            fs::read(identity_path).unwrap(),
            workflow_lock_file_identity(&metadata),
        )
    }

    fn wait_for_file(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for child readiness/release file `{}`",
                path.display()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn voter(secret: &str) -> (String, Ed25519Signer) {
        let signer = Ed25519Signer::from_secret_material(secret);
        (format!("swarm:ed25519:{}", signer.public_key_hex()), signer)
    }

    struct ScopedEnv {
        name: String,
        previous: Option<std::ffi::OsString>,
    }

    impl ScopedEnv {
        fn set(name: impl Into<String>, value: &str) -> Self {
            let name = name.into();
            let previous = std::env::var_os(&name);
            unsafe { std::env::set_var(&name, value) };
            Self { name, previous }
        }
    }

    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => unsafe { std::env::set_var(&self.name, value) },
                None => unsafe { std::env::remove_var(&self.name) },
            }
        }
    }

    fn sample_set(voter_ids: Vec<String>, required: usize) -> ApprovalSetReport {
        let eligible_voters = normalize_voter_ids(voter_ids);
        let threshold = ThresholdRule::AtLeast { required };
        let created_at_ms = 1_700_000_000_000;
        let set_id = canonical_approval_set_id_fields(
            &eligible_voters,
            &threshold,
            "promotion-evidence:test",
            created_at_ms,
        )
        .unwrap();
        ApprovalSetReport {
            set_id,
            eligible_voters,
            threshold,
            promotion_evidence_ref: "promotion-evidence:test".to_string(),
            created_at_ms,
        }
    }

    fn sample_ledger(set_id: &str) -> ApprovalLedgerReport {
        ApprovalLedgerReport {
            schema_version: CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION,
            ledger_id: "approval-ledger:test".to_string(),
            approval_set_id: set_id.to_string(),
            entries: Vec::new(),
            created_at_ms: 1_700_000_000_100,
        }
    }

    fn signed_entry(
        ledger_id: &str,
        set_id: &str,
        voter_id: &str,
        signer: &Ed25519Signer,
        index: usize,
    ) -> ApprovalLedgerEntry {
        signed_entry_with_vote(
            ledger_id,
            set_id,
            voter_id,
            signer,
            ApprovalVote::Approve,
            index,
        )
    }

    fn signed_entry_with_vote(
        ledger_id: &str,
        set_id: &str,
        voter_id: &str,
        signer: &Ed25519Signer,
        vote: ApprovalVote,
        index: usize,
    ) -> ApprovalLedgerEntry {
        let timestamp_ms = 1_700_000_000_200 + index as i64;
        let previous_envelope_hash = (index > 0).then(|| format!("0xhash{:02}", index));
        let intent = ApprovalVoteIntent {
            signature_version: ApprovalVoteSignatureVersion::IntentV2,
            approval_set_id: set_id.to_string(),
            ledger_id: ledger_id.to_string(),
            entry_id: next_approval_ledger_entry_id(ledger_id, index),
            voter_id: voter_id.to_string(),
            vote,
            timestamp_ms,
            previous_envelope_hash: previous_envelope_hash.clone(),
        };
        let signature = signer.sign(&approval_vote_payload_bytes(&intent).unwrap());
        ApprovalLedgerEntry {
            entry_id: intent.entry_id,
            voter_id: voter_id.to_string(),
            vote,
            signature_version: ApprovalVoteSignatureVersion::IntentV2,
            signature,
            timestamp_ms,
            previous_envelope_hash,
            envelope_hash: format!("0xhash{:02}", index + 1),
        }
    }

    fn signed_vote_intent(
        ledger: &ApprovalLedgerReport,
        voter_id: &str,
        signer: &Ed25519Signer,
        timestamp_ms: i64,
    ) -> (ApprovalVoteIntent, DetachedSignature) {
        let intent =
            build_approval_vote_intent(ledger, voter_id, ApprovalVote::Approve, timestamp_ms);
        let signature = signer.sign(&approval_vote_payload_bytes(&intent).unwrap());
        (intent, signature)
    }

    #[test]
    fn threshold_rule_reports_met_counts() {
        let rule = ThresholdRule::AtLeast { required: 2 };

        assert!(!rule.is_met(1));
        assert!(rule.is_met(2));
        assert!(rule.is_met(3));
        assert_eq!(rule.required_count(), 2);
    }

    #[test]
    fn quorum_state_tracks_partial_and_full_quorum() {
        let (voter_a, signer_a) = voter("alpha");
        let (voter_b, signer_b) = voter("bravo");
        let (voter_c, _) = voter("charlie");
        let set = sample_set(vec![voter_a.clone(), voter_b.clone(), voter_c.clone()], 2);

        let mut partial = sample_ledger(&set.set_id);
        partial.entries.push(signed_entry(
            &partial.ledger_id,
            &set.set_id,
            &voter_a,
            &signer_a,
            0,
        ));
        let quorum = ApprovalLedgerQuorumState::from_ledger_and_set(&partial, &set);
        assert_eq!(quorum.votes_received, 1);
        assert_eq!(quorum.votes_required, 2);
        assert_eq!(
            quorum.voters_remaining,
            vec![voter_b.clone(), voter_c.clone()]
        );
        assert!(!quorum.quorum_met);

        let mut full = partial.clone();
        full.entries.push(signed_entry(
            &full.ledger_id,
            &set.set_id,
            &voter_b,
            &signer_b,
            1,
        ));
        let quorum = ApprovalLedgerQuorumState::from_ledger_and_set(&full, &set);
        assert_eq!(quorum.votes_received, 2);
        assert!(quorum.quorum_met);
        assert_eq!(quorum.voters_remaining, vec![voter_c]);
    }

    #[test]
    fn validate_and_append_vote_accepts_valid_signature() {
        let (voter_id, signer) = voter("alpha");
        let set = sample_set(vec![voter_id.clone()], 1);
        let mut ledger = sample_ledger(&set.set_id);
        let (intent, signature) =
            signed_vote_intent(&ledger, &voter_id, &signer, 1_700_000_000_300);

        validate_and_append_vote(&mut ledger, &set, &intent, &signature).unwrap();

        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(ledger.entries[0].voter_id, voter_id);
        assert_eq!(
            ledger.entries[0].entry_id,
            "approval-ledger-entry:approval-ledger_test:1"
        );
    }

    #[test]
    fn append_signed_vote_accepts_valid_signature() {
        let dir = TestDir::new("signed-vote");
        let harness = DefaultApprovalHarness::from_paths(
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, signer) = voter("alpha");
        let set_record = harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "promotion://packet/001",
            )
            .expect("approval set");
        let ledger = harness
            .load_stored_ledger_for_set(&set_record.set_id)
            .expect("load ledger");
        let (intent, signature) = signed_vote_intent(&ledger.report, &voter_id, &signer, now_ms());

        let quorum_state = harness
            .append_signed_vote(&intent, &signature)
            .expect("signed vote should append");

        assert!(quorum_state.quorum_met);
        let updated = harness
            .load_ledger(&ledger.report.ledger_id)
            .expect("load updated ledger")
            .expect("updated ledger");
        assert_eq!(updated.report.entries.len(), 1);
        assert_eq!(updated.report.entries[0].voter_id, voter_id);
        assert_eq!(updated.report.entries[0].signature, signature);
    }

    #[test]
    fn concurrent_create_or_load_binds_one_set_and_ledger_to_exact_evidence() {
        let dir = TestDir::new("create-or-load-concurrent");
        let first = DefaultApprovalHarness::from_paths(
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let second = DefaultApprovalHarness::from_paths(
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, _) = voter("create-or-load-voter");
        let barrier = Arc::new(Barrier::new(17));
        let handles = (0..16)
            .map(|index| {
                let harness = if index % 2 == 0 {
                    first.clone()
                } else {
                    second.clone()
                };
                let barrier = Arc::clone(&barrier);
                let voter_id = voter_id.clone();
                thread::spawn(move || {
                    barrier.wait();
                    harness
                        .create_or_load_approval_set(
                            vec![voter_id],
                            ThresholdRule::AtLeast { required: 1 },
                            "governed-hold:concurrent",
                        )
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let records = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();

        assert!(
            records
                .iter()
                .all(|record| record.set_id == records[0].set_id)
        );
        assert_eq!(first.list_approval_sets().unwrap().total_count, 1);
        assert_eq!(first.list_ledgers(None).unwrap().total_count, 1);
        assert!(matches!(
            second.create_or_load_approval_set(
                vec![voter_id],
                ThresholdRule::Unanimous,
                "governed-hold:concurrent",
            ),
            Err(ApprovalError::ApprovalEvidenceConflict { .. })
        ));
    }

    #[test]
    fn create_or_load_recovers_report_persisted_before_set_index() {
        let dir = TestDir::new("create-or-load-orphan-report");
        let set_root = dir.child("approval-sets");
        let harness =
            DefaultApprovalHarness::from_paths(&set_root, dir.child("approval-ledgers")).unwrap();
        let (voter_id, _) = voter("create-or-load-orphan-voter");
        let eligible_voters = vec![voter_id.clone()];
        let threshold = ThresholdRule::AtLeast { required: 1 };
        let evidence_ref = "governed-hold:orphan-report";
        let created_at_ms = now_ms();
        let set_id = canonical_approval_set_id_fields(
            &eligible_voters,
            &threshold,
            evidence_ref,
            created_at_ms,
        )
        .unwrap();
        let report = ApprovalSetReport {
            set_id: set_id.clone(),
            eligible_voters: eligible_voters.clone(),
            threshold: threshold.clone(),
            promotion_evidence_ref: evidence_ref.to_string(),
            created_at_ms,
        };
        let orphan = harness.set_store.persist(&report).unwrap();
        fs::remove_file(set_root.join("index.json")).unwrap();

        let recovered = harness
            .create_or_load_approval_set(eligible_voters, threshold, evidence_ref)
            .unwrap();

        assert_eq!(recovered, orphan);
        assert_eq!(recovered.set_id, set_id);
        assert_eq!(harness.list_approval_sets().unwrap().total_count, 1);
        assert_eq!(harness.list_ledgers(Some(&set_id)).unwrap().total_count, 1);
    }

    #[test]
    fn create_or_load_repairs_only_the_deterministic_ledger_without_losing_votes() {
        let dir = TestDir::new("create-or-load-ledger-recovery");
        let harness = DefaultApprovalHarness::from_paths(
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, signer) = voter("create-or-load-recovery-voter");
        let threshold = ThresholdRule::AtLeast { required: 1 };
        let evidence_ref = "governed-hold:recovery";
        let set = harness
            .create_approval_set(vec![voter_id.clone()], threshold.clone(), evidence_ref)
            .unwrap();
        let persisted_set = harness.load_approval_set(&set.set_id).unwrap().unwrap();
        let ledger_id = approval_ledger_id(&set.set_id, persisted_set.report.created_at_ms);
        fs::remove_file(harness.ledger_store.report_path(&ledger_id)).unwrap();
        fs::remove_file(harness.ledger_store.index_path()).unwrap();

        let recovered = harness
            .create_or_load_approval_set(vec![voter_id.clone()], threshold.clone(), evidence_ref)
            .unwrap();
        assert_eq!(recovered.set_id, set.set_id);
        assert!(
            harness
                .load_ledger(&ledger_id)
                .unwrap()
                .unwrap()
                .report
                .entries
                .is_empty()
        );

        harness
            .append_vote(&set.set_id, &voter_id, &signer)
            .unwrap();
        fs::remove_file(harness.ledger_store.index_path()).unwrap();
        harness
            .create_or_load_approval_set(vec![voter_id], threshold, evidence_ref)
            .unwrap();
        assert_eq!(
            harness
                .load_ledger(&ledger_id)
                .unwrap()
                .unwrap()
                .report
                .entries
                .len(),
            1
        );
    }

    #[test]
    fn human_resume_outcome_is_durable_idempotent_and_conflict_detecting() {
        let dir = TestDir::new("human-resume-outcome");
        let signing_key_env = format!("SWARM_RUNTIME_APPROVAL_RESUME_KEY_{}", std::process::id());
        let _signing_key = ScopedEnv::set(&signing_key_env, "resume-outcome-key");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, signer) = voter("resume-outcome-voter");
        let set = harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "governed-hold:resume-outcome",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        harness
            .append_vote(&set.set_id, &voter_id, &signer)
            .unwrap();
        let pack = harness
            .ensure_approved_receipt_pack(
                &set.set_id,
                &ledger_id,
                "resume-outcome-signer",
                &signing_key_env,
            )
            .unwrap();
        let audit = serde_json::from_value::<AuditTrail>(json!({
            "trail_id": "trail:resume-outcome",
            "hunt_id": "hunt:resume-outcome",
            "related_receipt_ids": [pack.report.pack_id.clone()],
            "detection": {
                "finding_id": "finding:resume-outcome",
                "event_id": "event:resume-outcome",
                "threat_class": "execution",
                "severity": "HIGH",
                "confidence": 0.99,
                "evidence": {},
                "strategy_id": "strategy:resume-outcome"
            },
            "policy": {
                "verdict": "allow",
                "rule_name": "human.resume.approved",
                "reason": "approved by durable quorum",
                "lease": null
            },
            "response": {
                "kind": "skipped",
                "reason": "test response"
            },
            "created_at_ms": 1_700_000_000_500_i64
        }))
        .unwrap();

        assert!(
            harness
                .load_human_resume_outcome(&pack.report.pack_id)
                .unwrap()
                .is_none()
        );
        harness
            .persist_human_resume_outcome(&pack.report.pack_id, &audit)
            .unwrap();
        harness
            .persist_human_resume_outcome(&pack.report.pack_id, &audit)
            .unwrap();
        let loaded = harness
            .load_human_resume_outcome(&pack.report.pack_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(loaded).unwrap(),
            serde_json::to_value(&audit).unwrap()
        );

        let mut conflicting = serde_json::to_value(&audit).unwrap();
        conflicting["trail_id"] = json!("trail:conflicting-resume");
        let conflicting = serde_json::from_value::<AuditTrail>(conflicting).unwrap();
        assert!(matches!(
            harness.persist_human_resume_outcome(&pack.report.pack_id, &conflicting),
            Err(ApprovalError::ReceiptPackStore(
                ApprovalReceiptPackStoreError::ResumeOutcomeConflict { .. }
            ))
        ));
        assert!(matches!(
            harness.load_human_resume_outcome("approval-receipt-pack:missing"),
            Err(ApprovalError::ApprovalReceiptPackNotFound { .. })
        ));
    }

    #[test]
    fn concurrent_identical_quorum_votes_share_one_canonical_pack_across_restart() {
        let dir = TestDir::new("concurrent-identical-quorum-votes");
        let signing_key_env = format!(
            "SWARM_RUNTIME_APPROVAL_CONCURRENT_KEY_{}",
            std::process::id()
        );
        let _signing_key = ScopedEnv::set(&signing_key_env, "concurrent-approval-key");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, signer) = voter("concurrent-identical-voter");
        let set = harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "swarm.governance.human-authorization.v1:concurrent-identical",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        let ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let (intent, signature) = signed_vote_intent(&ledger.report, &voter_id, &signer, now_ms());
        let barrier = Arc::new(Barrier::new(2));
        let start = |harness: DefaultApprovalHarness| {
            let barrier = barrier.clone();
            let set_id = set.set_id.clone();
            let ledger_id = ledger_id.clone();
            let intent = intent.clone();
            let signature = signature.clone();
            let signing_key_env = signing_key_env.clone();
            thread::spawn(move || {
                barrier.wait();
                let append = harness.append_signed_vote(&intent, &signature);
                let pack = harness.ensure_approved_receipt_pack(
                    &set_id,
                    &ledger_id,
                    "concurrent-test-signer",
                    &signing_key_env,
                );
                (append, pack)
            })
        };
        let first = start(harness.clone());
        let second = start(harness.clone());
        let (first_append, first_pack) = first.join().unwrap();
        let (second_append, second_pack) = second.join().unwrap();
        assert!(first_append.is_ok() ^ second_append.is_ok());
        assert!(matches!(
            &first_append,
            Ok(_) | Err(ApprovalError::DuplicateVoter { .. })
        ));
        assert!(matches!(
            &second_append,
            Ok(_) | Err(ApprovalError::DuplicateVoter { .. })
        ));
        let first_pack = first_pack.unwrap();
        let second_pack = second_pack.unwrap();
        assert_eq!(first_pack.report.pack_id, second_pack.report.pack_id);
        assert_eq!(
            harness
                .load_ledger(&ledger_id)
                .unwrap()
                .unwrap()
                .report
                .entries
                .len(),
            1
        );
        assert_eq!(harness.list_verdicts().unwrap().total_count, 1);
        assert_eq!(harness.list_receipt_packs().unwrap().total_count, 1);

        drop(harness);
        let reopened = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let restarted_pack = reopened
            .ensure_approved_receipt_pack(
                &set.set_id,
                &ledger_id,
                "concurrent-test-signer",
                &signing_key_env,
            )
            .unwrap();
        assert_eq!(restarted_pack.report.pack_id, first_pack.report.pack_id);
        assert_eq!(reopened.list_verdicts().unwrap().total_count, 1);
        assert_eq!(reopened.list_receipt_packs().unwrap().total_count, 1);
    }

    #[test]
    fn separate_process_identical_quorum_votes_share_one_canonical_pack() {
        const CHILD_ENV: &str = "SWARM_RUNTIME_APPROVAL_SEPARATE_PROCESS_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let harness = DefaultApprovalHarness::from_path(
                std::env::var_os("SWARM_RUNTIME_APPROVAL_CHILD_CONFIG").unwrap(),
                std::env::var_os("SWARM_RUNTIME_APPROVAL_CHILD_VERDICTS").unwrap(),
                std::env::var_os("SWARM_RUNTIME_APPROVAL_CHILD_PACKS").unwrap(),
                std::env::var_os("SWARM_RUNTIME_APPROVAL_CHILD_SETS").unwrap(),
                std::env::var_os("SWARM_RUNTIME_APPROVAL_CHILD_LEDGERS").unwrap(),
            )
            .unwrap();
            let signature: DetachedSignature = serde_json::from_str(
                &std::env::var("SWARM_RUNTIME_APPROVAL_CHILD_SIGNATURE").unwrap(),
            )
            .unwrap();
            let intent: ApprovalVoteIntent = serde_json::from_str(
                &std::env::var("SWARM_RUNTIME_APPROVAL_CHILD_INTENT").unwrap(),
            )
            .unwrap();
            let ledger_id = intent.ledger_id.clone();
            let set_id = std::env::var("SWARM_RUNTIME_APPROVAL_CHILD_SET").unwrap();
            let ready_path = std::env::var("SWARM_RUNTIME_APPROVAL_CHILD_READY").unwrap();
            let release_path = std::env::var("SWARM_RUNTIME_APPROVAL_CHILD_RELEASE").unwrap();
            fs::write(&ready_path, b"ready").unwrap();
            wait_for_file(Path::new(&release_path));
            let outcome = match harness.append_signed_vote(&intent, &signature) {
                Ok(_) => "ok",
                Err(ApprovalError::DuplicateVoter { .. }) => "duplicate",
                Err(error) => panic!("unexpected separate-process vote outcome: {error}"),
            };
            fs::write(
                std::env::var("SWARM_RUNTIME_APPROVAL_CHILD_RESULT").unwrap(),
                outcome,
            )
            .unwrap();
            harness
                .ensure_approved_receipt_pack(
                    &set_id,
                    &ledger_id,
                    "separate-process-test-signer",
                    &std::env::var("SWARM_RUNTIME_APPROVAL_CHILD_KEY_ENV").unwrap(),
                )
                .unwrap();
            return;
        }

        let dir = TestDir::new("separate-process-identical-quorum-votes");
        let signing_key_env = format!(
            "SWARM_RUNTIME_APPROVAL_SEPARATE_PROCESS_KEY_{}",
            std::process::id()
        );
        let _signing_key = ScopedEnv::set(&signing_key_env, "separate-process-approval-key");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, signer) = voter("separate-process-voter");
        let set = harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "swarm.governance.human-authorization.v1:separate-process",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        let ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let (intent, signature) = signed_vote_intent(&ledger.report, &voter_id, &signer, now_ms());
        let first_ready = dir.child("first-child-ready");
        let second_ready = dir.child("second-child-ready");
        let release = dir.child("children-release");
        let first_result = dir.child("first-child-result");
        let second_result = dir.child("second-child-result");
        let child = |set_id: &str, ready_path: &Path, result_path: &Path| {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("approval::tests::separate_process_identical_quorum_votes_share_one_canonical_pack")
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .env(
                    "SWARM_RUNTIME_APPROVAL_CHILD_CONFIG",
                    dir.child("config-placeholder").display().to_string(),
                )
                .env(
                    "SWARM_RUNTIME_APPROVAL_CHILD_VERDICTS",
                    dir.child("approval-verdicts").display().to_string(),
                )
                .env(
                    "SWARM_RUNTIME_APPROVAL_CHILD_PACKS",
                    dir.child("approval-receipt-packs").display().to_string(),
                )
                .env(
                    "SWARM_RUNTIME_APPROVAL_CHILD_SETS",
                    dir.child("approval-sets").display().to_string(),
                )
                .env(
                    "SWARM_RUNTIME_APPROVAL_CHILD_LEDGERS",
                    dir.child("approval-ledgers").display().to_string(),
                )
                .env("SWARM_RUNTIME_APPROVAL_CHILD_SET", set_id)
                .env(
                    "SWARM_RUNTIME_APPROVAL_CHILD_INTENT",
                    serde_json::to_string(&intent).unwrap(),
                )
                .env(
                    "SWARM_RUNTIME_APPROVAL_CHILD_SIGNATURE",
                    serde_json::to_string(&signature).unwrap(),
                )
                .env("SWARM_RUNTIME_APPROVAL_CHILD_KEY_ENV", &signing_key_env);
            command.env(
                "SWARM_RUNTIME_APPROVAL_CHILD_RESULT",
                result_path.display().to_string(),
            );
            command.env(
                "SWARM_RUNTIME_APPROVAL_CHILD_READY",
                ready_path.display().to_string(),
            );
            command.env(
                "SWARM_RUNTIME_APPROVAL_CHILD_RELEASE",
                release.display().to_string(),
            );
            command.spawn().unwrap()
        };
        let first = child(&set.set_id, &first_ready, &first_result);
        let second = child(&set.set_id, &second_ready, &second_result);
        wait_for_file(&first_ready);
        wait_for_file(&second_ready);
        fs::write(&release, b"release").unwrap();
        let first = first.wait_with_output().unwrap();
        let second = second.wait_with_output().unwrap();
        assert!(
            first.status.success(),
            "first child failed: {}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert!(
            second.status.success(),
            "second child failed: {}",
            String::from_utf8_lossy(&second.stderr)
        );
        let mut outcomes = [
            fs::read_to_string(first_result).unwrap(),
            fs::read_to_string(second_result).unwrap(),
        ];
        outcomes.sort();
        assert_eq!(outcomes, ["duplicate", "ok"]);
        assert_eq!(
            harness
                .load_ledger(&ledger_id)
                .unwrap()
                .unwrap()
                .report
                .entries
                .len(),
            1
        );
        assert_eq!(harness.list_verdicts().unwrap().total_count, 1);
        assert_eq!(harness.list_receipt_packs().unwrap().total_count, 1);
    }

    #[test]
    fn separate_process_lockless_snapshot_control_reaches_two_winners() {
        const CHILD_ENV: &str = "SWARM_RUNTIME_APPROVAL_LOCKLESS_CONTROL_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            // Mutation control: each child reads the same empty ledger before
            // the release barrier, then performs the exact append validation
            // without the workflow lock. Both stale snapshots therefore reach
            // the side effect that a lockless implementation would trigger.
            let set_id = std::env::var("SWARM_RUNTIME_APPROVAL_CONTROL_SET").unwrap();
            let ledger_id = std::env::var("SWARM_RUNTIME_APPROVAL_CONTROL_LEDGER").unwrap();
            let set_root =
                PathBuf::from(std::env::var("SWARM_RUNTIME_APPROVAL_CONTROL_SETS").unwrap());
            let ledger_root =
                PathBuf::from(std::env::var("SWARM_RUNTIME_APPROVAL_CONTROL_LEDGERS").unwrap());
            let set: ApprovalSetReport = serde_json::from_slice(
                &fs::read(
                    set_root
                        .join("reports")
                        .join(format!("{}.json", sanitize_id(&set_id))),
                )
                .unwrap(),
            )
            .unwrap();
            let ledger: ApprovalLedgerReport = serde_json::from_slice(
                &fs::read(
                    ledger_root
                        .join("reports")
                        .join(format!("{}.json", sanitize_id(&ledger_id))),
                )
                .unwrap(),
            )
            .unwrap();
            let intent: ApprovalVoteIntent = serde_json::from_str(
                &std::env::var("SWARM_RUNTIME_APPROVAL_CONTROL_INTENT").unwrap(),
            )
            .unwrap();
            let signature: DetachedSignature = serde_json::from_str(
                &std::env::var("SWARM_RUNTIME_APPROVAL_CONTROL_SIGNATURE").unwrap(),
            )
            .unwrap();
            let ready_path = std::env::var("SWARM_RUNTIME_APPROVAL_CONTROL_READY").unwrap();
            let release_path = std::env::var("SWARM_RUNTIME_APPROVAL_CONTROL_RELEASE").unwrap();
            fs::write(&ready_path, b"ready").unwrap();
            wait_for_file(Path::new(&release_path));

            let mut candidate = ledger;
            validate_and_append_vote(&mut candidate, &set, &intent, &signature).unwrap();
            fs::write(
                std::env::var("SWARM_RUNTIME_APPROVAL_CONTROL_RESULT").unwrap(),
                b"winner",
            )
            .unwrap();
            return;
        }

        let dir = TestDir::new("separate-process-lockless-snapshot-control");
        let harness = DefaultApprovalHarness::from_paths(
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, signer) = voter("separate-process-lockless-control-voter");
        let set = harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:separate-process-lockless-control",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        let ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let (intent, signature) = signed_vote_intent(&ledger.report, &voter_id, &signer, now_ms());
        let first_ready = dir.child("first-control-ready");
        let second_ready = dir.child("second-control-ready");
        let release = dir.child("control-release");
        let first_result = dir.child("first-control-result");
        let second_result = dir.child("second-control-result");
        let child = |ready_path: &Path, result_path: &Path| {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("approval::tests::separate_process_lockless_snapshot_control_reaches_two_winners")
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .env("SWARM_RUNTIME_APPROVAL_CONTROL_SET", &set.set_id)
                .env("SWARM_RUNTIME_APPROVAL_CONTROL_LEDGER", &ledger_id)
                .env(
                    "SWARM_RUNTIME_APPROVAL_CONTROL_INTENT",
                    serde_json::to_string(&intent).unwrap(),
                )
                .env(
                    "SWARM_RUNTIME_APPROVAL_CONTROL_SIGNATURE",
                    serde_json::to_string(&signature).unwrap(),
                )
                .env(
                    "SWARM_RUNTIME_APPROVAL_CONTROL_SETS",
                    dir.child("approval-sets").display().to_string(),
                )
                .env(
                    "SWARM_RUNTIME_APPROVAL_CONTROL_LEDGERS",
                    dir.child("approval-ledgers").display().to_string(),
                )
                .env(
                    "SWARM_RUNTIME_APPROVAL_CONTROL_READY",
                    ready_path.display().to_string(),
                )
                .env(
                    "SWARM_RUNTIME_APPROVAL_CONTROL_RELEASE",
                    release.display().to_string(),
                )
                .env(
                    "SWARM_RUNTIME_APPROVAL_CONTROL_RESULT",
                    result_path.display().to_string(),
                );
            command.spawn().unwrap()
        };
        let first = child(&first_ready, &first_result);
        let second = child(&second_ready, &second_result);
        wait_for_file(&first_ready);
        wait_for_file(&second_ready);
        fs::write(&release, b"release").unwrap();
        let first = first.wait_with_output().unwrap();
        let second = second.wait_with_output().unwrap();
        assert!(
            first.status.success(),
            "first lockless control child failed: {}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert!(
            second.status.success(),
            "second lockless control child failed: {}",
            String::from_utf8_lossy(&second.stderr)
        );
        let mut outcomes = [
            fs::read_to_string(first_result).unwrap(),
            fs::read_to_string(second_result).unwrap(),
        ];
        outcomes.sort();
        assert_eq!(outcomes, ["winner", "winner"]);
        assert!(
            harness
                .load_ledger(&ledger_id)
                .unwrap()
                .unwrap()
                .report
                .entries
                .is_empty()
        );
    }

    #[test]
    fn workflow_lock_path_replacement_is_refused_before_mutation() {
        let dir = TestDir::new("workflow-lock-path-replacement");
        let harness = DefaultApprovalHarness::from_paths(
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, _) = voter("workflow-lock-path-replacement-voter");
        harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:workflow-lock-path-replacement",
            )
            .unwrap();
        let lock_path = dir.child("approval-ledgers/.approval-workflow.lock");
        let original_lock_path = dir.child("approval-ledgers/.approval-workflow.lock.original");
        fs::rename(&lock_path, &original_lock_path).unwrap();
        fs::write(&lock_path, b"replacement").unwrap();

        let before_sets = harness.list_approval_sets().unwrap().total_count;
        let ledger_index_path = dir.child("approval-ledgers/index.json");
        let before_ledger_index = fs::read(&ledger_index_path).unwrap();
        let error = harness
            .create_approval_set(
                vec![voter_id],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:rejected-lock-replacement",
            )
            .unwrap_err();
        assert!(matches!(error, ApprovalError::WorkflowLock { .. }));
        assert_eq!(
            harness.list_approval_sets().unwrap().total_count,
            before_sets
        );
        assert_eq!(fs::read(&ledger_index_path).unwrap(), before_ledger_index);
    }

    #[cfg(unix)]
    #[test]
    fn workflow_lock_replacement_after_precheck_rolls_back_exact_store_bytes() {
        let dir = TestDir::new("workflow-lock-replacement-rollback");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (initial_voter, initial_signer) = voter("workflow-lock-rollback-initial-voter");
        let set = harness
            .create_approval_set(
                vec![initial_voter.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:workflow-lock-rollback-initial",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        let ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let (intent, signature) =
            signed_vote_intent(&ledger.report, &initial_voter, &initial_signer, now_ms());
        harness.append_signed_vote(&intent, &signature).unwrap();
        let signing_key_env = format!(
            "SWARM_RUNTIME_APPROVAL_LOCK_ROLLBACK_KEY_{}",
            std::process::id()
        );
        let _signing_key = ScopedEnv::set(&signing_key_env, "workflow-lock-rollback-key");
        let set_root = dir.child("approval-sets");
        let ledger_root = dir.child("approval-ledgers");
        let verdict_root = dir.child("approval-verdicts");
        let pack_root = dir.child("approval-receipt-packs");
        let before_sets = capture_store_tree(&set_root);
        let before_ledgers = capture_store_tree(&ledger_root);
        let before_verdicts = capture_store_tree(&verdict_root);
        let before_packs = capture_store_tree(&pack_root);
        let lock_path = ledger_root.join(".approval-workflow.lock");
        let before_lock_file = capture_workflow_lock_file(&lock_path);
        let before_lock_identity = capture_workflow_lock_identity(&lock_path);

        let reached = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        install_workflow_test_hook(
            ledger_root.join(".approval-workflow.lock"),
            reached.clone(),
            release.clone(),
        );
        let worker = {
            let harness = harness.clone();
            let set_id = set.set_id.clone();
            let ledger_id = ledger_id.clone();
            let signing_key_env = signing_key_env.clone();
            thread::spawn(move || {
                harness.ensure_approved_receipt_pack(
                    &set_id,
                    &ledger_id,
                    "workflow-lock-rollback-signer",
                    &signing_key_env,
                )
            })
        };
        reached.wait();

        let original_lock_path = ledger_root.join(".approval-workflow.lock.original");
        fs::rename(&lock_path, &original_lock_path).unwrap();
        fs::write(&lock_path, b"replacement-after-precheck").unwrap();
        let replacement_lock_file = capture_workflow_lock_file(&lock_path);
        release.wait();

        assert!(matches!(
            worker.join().unwrap(),
            Err(ApprovalError::WorkflowLock { .. })
        ));
        assert_eq!(capture_store_tree(&set_root), before_sets);
        assert_eq!(capture_store_tree(&ledger_root), before_ledgers);
        assert_eq!(capture_store_tree(&verdict_root), before_verdicts);
        assert_eq!(capture_store_tree(&pack_root), before_packs);
        assert_eq!(
            capture_workflow_lock_file(&original_lock_path),
            before_lock_file
        );
        assert_eq!(
            capture_workflow_lock_identity(&lock_path),
            before_lock_identity
        );
        assert_ne!(replacement_lock_file.1, before_lock_file.1);
    }

    #[cfg(unix)]
    #[test]
    fn workflow_lock_content_mutation_after_precheck_rolls_back_identity_aware_snapshot() {
        let dir = TestDir::new("workflow-lock-content-rollback");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, signer) = voter("workflow-lock-content-voter");
        let set = harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:workflow-lock-content",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        let ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let (intent, signature) = signed_vote_intent(&ledger.report, &voter_id, &signer, now_ms());
        harness.append_signed_vote(&intent, &signature).unwrap();
        let signing_key_env = format!(
            "SWARM_RUNTIME_APPROVAL_LOCK_CONTENT_KEY_{}",
            std::process::id()
        );
        let _signing_key = ScopedEnv::set(&signing_key_env, "workflow-lock-content-key");
        let set_root = dir.child("approval-sets");
        let ledger_root = dir.child("approval-ledgers");
        let verdict_root = dir.child("approval-verdicts");
        let pack_root = dir.child("approval-receipt-packs");
        let before_sets = capture_store_tree(&set_root);
        let before_ledgers = capture_store_tree(&ledger_root);
        let before_verdicts = capture_store_tree(&verdict_root);
        let before_packs = capture_store_tree(&pack_root);
        let lock_path = ledger_root.join(".approval-workflow.lock");
        let before_lock_file = capture_workflow_lock_file(&lock_path);
        let before_lock_identity = capture_workflow_lock_identity(&lock_path);

        let reached = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        install_workflow_test_hook(lock_path.clone(), reached.clone(), release.clone());
        let worker = {
            let harness = harness.clone();
            let set_id = set.set_id.clone();
            let ledger_id = ledger_id.clone();
            let signing_key_env = signing_key_env.clone();
            thread::spawn(move || {
                harness.ensure_approved_receipt_pack(
                    &set_id,
                    &ledger_id,
                    "workflow-lock-content-signer",
                    &signing_key_env,
                )
            })
        };
        reached.wait();
        fs::write(&lock_path, b"mutated-without-replacement").unwrap();
        release.wait();

        assert!(matches!(
            worker.join().unwrap(),
            Err(ApprovalError::WorkflowLock { .. })
        ));
        assert_eq!(capture_store_tree(&set_root), before_sets);
        assert_eq!(capture_store_tree(&ledger_root), before_ledgers);
        assert_eq!(capture_store_tree(&verdict_root), before_verdicts);
        assert_eq!(capture_store_tree(&pack_root), before_packs);
        assert_eq!(capture_workflow_lock_file(&lock_path), before_lock_file);
        assert_eq!(
            capture_workflow_lock_identity(&lock_path),
            before_lock_identity
        );
    }

    #[test]
    fn cross_ledger_index_tamper_fails_closed_before_vote_or_verdict_mutation() {
        let dir = TestDir::new("cross-ledger-index-tamper");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_a, signer_a) = voter("cross-ledger-tamper-a");
        let (voter_b, _) = voter("cross-ledger-tamper-b");
        let set_a = harness
            .create_approval_set(
                vec![voter_a.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:cross-ledger-tamper-a",
            )
            .unwrap();
        let set_b = harness
            .create_approval_set(
                vec![voter_b],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:cross-ledger-tamper-b",
            )
            .unwrap();
        let ledger_a = harness.list_ledgers(Some(&set_a.set_id)).unwrap().ledgers[0].clone();
        let ledger_b = harness.list_ledgers(Some(&set_b.set_id)).unwrap().ledgers[0].clone();
        let ledger_root = dir.child("approval-ledgers");
        let ledger_index_path = ledger_root.join("index.json");
        let original_index = fs::read(&ledger_index_path).unwrap();
        let baseline_ledger_tree = capture_store_tree(&ledger_root);
        let baseline_verdict_tree = capture_store_tree(&dir.child("approval-verdicts"));
        // Keep a unique, canonical index record and canonical path for A, but
        // route that path to the other valid ledger report. This reaches the
        // record/report binding validator instead of the duplicate-ID guard.
        let ledger_a_report_path = ledger_root
            .join("reports")
            .join(format!("{}.json", sanitize_id(&ledger_a.ledger_id)));
        let ledger_b_report_path = ledger_root
            .join("reports")
            .join(format!("{}.json", sanitize_id(&ledger_b.ledger_id)));
        let routed_report_bytes = fs::read(&ledger_b_report_path).unwrap();
        fs::write(&ledger_a_report_path, &routed_report_bytes).unwrap();

        let ledger_a_lookup = harness.load_ledger(&ledger_a.ledger_id).unwrap_err();
        assert!(matches!(
            ledger_a_lookup,
            ApprovalError::InvalidLedgerRequest { .. }
        ));
        let intent = ApprovalVoteIntent {
            signature_version: ApprovalVoteSignatureVersion::IntentV2,
            approval_set_id: set_a.set_id.clone(),
            ledger_id: ledger_a.ledger_id.clone(),
            entry_id: next_approval_ledger_entry_id(&ledger_a.ledger_id, 0),
            voter_id: voter_a.clone(),
            vote: ApprovalVote::Approve,
            timestamp_ms: now_ms(),
            previous_envelope_hash: None,
        };
        let signature = signer_a.sign(&approval_vote_payload_bytes(&intent).unwrap());
        let append_error = harness.append_signed_vote(&intent, &signature).unwrap_err();
        let append_reason = match append_error {
            ApprovalError::InvalidLedgerRequest { reason } => reason,
            other => panic!("expected exact ledger binding failure, got {other:?}"),
        };
        assert!(append_reason.contains("does not match its canonical persisted report"));
        let verdict_error = harness
            .create_verdict(&set_a.set_id, &ledger_a.ledger_id)
            .unwrap_err();
        let verdict_reason = match verdict_error {
            ApprovalError::InvalidLedgerRequest { reason } => reason,
            other => panic!("expected exact ledger binding failure, got {other:?}"),
        };
        assert!(verdict_reason.contains("does not match its canonical persisted report"));
        assert_eq!(fs::read(&ledger_index_path).unwrap(), original_index);
        let mut expected_ledger_tree = baseline_ledger_tree;
        expected_ledger_tree.insert(ledger_a_report_path, routed_report_bytes);
        assert_eq!(capture_store_tree(&ledger_root), expected_ledger_tree);
        assert_eq!(
            capture_store_tree(&dir.child("approval-verdicts")),
            baseline_verdict_tree
        );
    }

    #[cfg(unix)]
    #[test]
    fn workflow_lock_symlink_is_refused_before_mutation() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new("workflow-lock-symlink");
        let harness = DefaultApprovalHarness::from_paths(
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, _) = voter("workflow-lock-symlink-voter");
        harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:workflow-lock-symlink",
            )
            .unwrap();
        let lock_path = dir.child("approval-ledgers/.approval-workflow.lock");
        let original_lock_path = dir.child("approval-ledgers/.approval-workflow.lock.original");
        fs::rename(&lock_path, &original_lock_path).unwrap();
        symlink(&original_lock_path, &lock_path).unwrap();

        let before_sets = harness.list_approval_sets().unwrap().total_count;
        let ledger_index_path = dir.child("approval-ledgers/index.json");
        let before_ledger_index = fs::read(&ledger_index_path).unwrap();
        let error = harness
            .create_approval_set(
                vec![voter_id],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:rejected-lock-symlink",
            )
            .unwrap_err();
        assert!(matches!(error, ApprovalError::WorkflowLock { .. }));
        assert_eq!(
            harness.list_approval_sets().unwrap().total_count,
            before_sets
        );
        assert_eq!(fs::read(&ledger_index_path).unwrap(), before_ledger_index);
    }

    #[test]
    fn distinct_vote_after_quorum_is_rejected_without_mutation_or_new_pack() {
        let dir = TestDir::new("post-quorum-distinct-vote");
        let signing_key_env = format!(
            "SWARM_RUNTIME_APPROVAL_POST_QUORUM_KEY_{}",
            std::process::id()
        );
        let _signing_key = ScopedEnv::set(&signing_key_env, "post-quorum-approval-key");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_a, signer_a) = voter("post-quorum-voter-a");
        let (voter_b, signer_b) = voter("post-quorum-voter-b");
        let set = harness
            .create_approval_set(
                vec![voter_a.clone(), voter_b.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "swarm.governance.human-authorization.v1:post-quorum",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        let empty_ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let (intent_a, signature_a) =
            signed_vote_intent(&empty_ledger.report, &voter_a, &signer_a, now_ms());
        assert!(
            harness
                .append_signed_vote(&intent_a, &signature_a)
                .unwrap()
                .quorum_met
        );
        let canonical_pack = harness
            .ensure_approved_receipt_pack(
                &set.set_id,
                &ledger_id,
                "post-quorum-test-signer",
                &signing_key_env,
            )
            .unwrap();
        let before_ledger = harness.load_ledger(&ledger_id).unwrap().unwrap().report;
        let before_verdicts = harness.list_verdicts().unwrap().total_count;
        let before_packs = harness.list_receipt_packs().unwrap().total_count;
        let (intent_b, signature_b) =
            signed_vote_intent(&before_ledger, &voter_b, &signer_b, now_ms());
        let barrier = Arc::new(Barrier::new(2));
        let retry_thread = {
            let harness = harness.clone();
            let barrier = barrier.clone();
            let set_id = set.set_id.clone();
            let ledger_id = ledger_id.clone();
            let intent = intent_a.clone();
            let signature = signature_a.clone();
            let signing_key_env = signing_key_env.clone();
            thread::spawn(move || {
                barrier.wait();
                let append = harness.append_signed_vote(&intent, &signature);
                let pack = harness.ensure_approved_receipt_pack(
                    &set_id,
                    &ledger_id,
                    "post-quorum-test-signer",
                    &signing_key_env,
                );
                (append, pack)
            })
        };
        let distinct_thread = {
            let harness = harness.clone();
            let barrier = barrier.clone();
            let intent = intent_b.clone();
            let signature = signature_b.clone();
            thread::spawn(move || {
                barrier.wait();
                harness.append_signed_vote(&intent, &signature)
            })
        };
        let (retry_append, retry_pack) = retry_thread.join().unwrap();
        let distinct_append = distinct_thread.join().unwrap();
        assert!(matches!(
            retry_append,
            Err(ApprovalError::DuplicateVoter { .. })
        ));
        assert_eq!(
            retry_pack.unwrap().report.pack_id,
            canonical_pack.report.pack_id
        );
        assert!(matches!(
            distinct_append,
            Err(ApprovalError::QuorumAlreadyMet { .. })
        ));
        assert_eq!(
            harness.load_ledger(&ledger_id).unwrap().unwrap().report,
            before_ledger
        );
        assert_eq!(
            harness.list_verdicts().unwrap().total_count,
            before_verdicts
        );
        assert_eq!(
            harness.list_receipt_packs().unwrap().total_count,
            before_packs
        );

        drop(harness);
        let reopened = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        assert!(matches!(
            reopened.append_signed_vote(&intent_b, &signature_b),
            Err(ApprovalError::QuorumAlreadyMet { .. })
        ));
        let restarted_pack = reopened
            .ensure_approved_receipt_pack(
                &set.set_id,
                &ledger_id,
                "post-quorum-test-signer",
                &signing_key_env,
            )
            .unwrap();
        assert_eq!(restarted_pack.report.pack_id, canonical_pack.report.pack_id);
        assert_eq!(
            reopened.list_verdicts().unwrap().total_count,
            before_verdicts
        );
        assert_eq!(
            reopened.list_receipt_packs().unwrap().total_count,
            before_packs
        );
    }

    #[test]
    fn tampered_persisted_vote_intent_fails_cryptographically_without_derivatives() {
        let dir = TestDir::new("tampered-persisted-vote-intent");
        let set_root = dir.child("approval-sets");
        let ledger_root = dir.child("approval-ledgers");
        let verdict_root = dir.child("approval-verdicts");
        let pack_root = dir.child("approval-receipt-packs");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            &verdict_root,
            &pack_root,
            &set_root,
            &ledger_root,
        )
        .unwrap();
        let (voter_a, signer_a) = voter("tampered-persisted-vote-a");
        let (voter_b, signer_b) = voter("tampered-persisted-vote-b");
        let set = harness
            .create_approval_set(
                vec![voter_a.clone(), voter_b.clone()],
                ThresholdRule::AtLeast { required: 2 },
                "promotion-evidence:tampered-persisted-vote-intent",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        harness
            .append_vote(&set.set_id, &voter_a, &signer_a)
            .unwrap();
        harness
            .append_vote(&set.set_id, &voter_b, &signer_b)
            .unwrap();

        let ledger_path = harness.ledger_store.report_path(&ledger_id);
        let original_ledger_bytes = fs::read(&ledger_path).unwrap();
        let original_report: serde_json::Value =
            serde_json::from_slice(&original_ledger_bytes).unwrap();
        let expected_sets = capture_store_tree(&set_root);
        let expected_verdicts = capture_store_tree(&verdict_root);
        let expected_packs = capture_store_tree(&pack_root);
        drop(harness);

        let mut mutations = Vec::new();
        let mut vote = original_report.clone();
        vote["entries"][0]["vote"] = json!("reject");
        mutations.push(vote);
        let mut signature_version = original_report.clone();
        signature_version["entries"][0]["signature_version"] = json!("legacy_v1");
        mutations.push(signature_version);
        let mut timestamp = original_report.clone();
        timestamp["entries"][0]["timestamp_ms"] =
            json!(timestamp["entries"][0]["timestamp_ms"].as_i64().unwrap() + 1);
        mutations.push(timestamp);
        let mut entry_id = original_report.clone();
        entry_id["entries"][0]["entry_id"] = json!("approval-ledger-entry:tampered");
        mutations.push(entry_id);
        let mut predecessor = original_report.clone();
        predecessor["entries"][1]["previous_envelope_hash"] = json!("0xtampered-predecessor");
        mutations.push(predecessor);

        for mutated in mutations {
            fs::write(&ledger_path, serde_json::to_vec_pretty(&mutated).unwrap()).unwrap();
            let expected_ledgers = capture_store_tree(&ledger_root);
            let reopened = DefaultApprovalHarness::from_path(
                dir.child("config-placeholder"),
                &verdict_root,
                &pack_root,
                &set_root,
                &ledger_root,
            )
            .unwrap();
            for result in [
                reopened.load_ledger(&ledger_id).map(|_| ()),
                reopened.list_ledgers(Some(&set.set_id)).map(|_| ()),
                reopened.create_verdict(&set.set_id, &ledger_id).map(|_| ()),
            ] {
                assert!(matches!(
                    result,
                    Err(ApprovalError::InvalidLedgerRequest { reason })
                        if reason.contains("invalid signature")
                ));
            }
            assert_eq!(capture_store_tree(&set_root), expected_sets);
            assert_eq!(capture_store_tree(&ledger_root), expected_ledgers);
            assert_eq!(capture_store_tree(&verdict_root), expected_verdicts);
            assert_eq!(capture_store_tree(&pack_root), expected_packs);
            fs::write(&ledger_path, &original_ledger_bytes).unwrap();
        }
    }

    #[test]
    fn tampered_approval_set_authority_fails_closed_before_derivatives() {
        let dir = TestDir::new("tampered-approval-set-authority");
        let signing_key_env = format!(
            "SWARM_RUNTIME_APPROVAL_SET_TAMPER_KEY_{}",
            std::process::id()
        );
        let _signing_key = ScopedEnv::set(&signing_key_env, "tampered-approval-set-key");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_a, signer_a) = voter("tampered-set-a");
        let (voter_b, _) = voter("tampered-set-b");
        let set = harness
            .create_approval_set(
                vec![voter_a.clone(), voter_b.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:tampered-set",
            )
            .unwrap();
        let other_set = harness
            .create_approval_set(
                vec![voter_b.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:other-set",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        let set_root = dir.child("approval-sets");
        let ledger_root = dir.child("approval-ledgers");
        let verdict_root = dir.child("approval-verdicts");
        let pack_root = dir.child("approval-receipt-packs");
        let set_index_path = set_root.join("index.json");
        let set_report_path = set_root
            .join("reports")
            .join(format!("{}.json", sanitize_id(&set.set_id)));
        let original_index_bytes = fs::read(&set_index_path).unwrap();
        let original_report_bytes = fs::read(&set_report_path).unwrap();
        let original_report: serde_json::Value =
            serde_json::from_slice(&original_report_bytes).unwrap();
        let other_report_path = set_root
            .join("reports")
            .join(format!("{}.json", sanitize_id(&other_set.set_id)));
        let other_report_bytes = fs::read(&other_report_path).unwrap();
        let baseline_set_tree = capture_store_tree(&set_root);
        let baseline_ledger_tree = capture_store_tree(&ledger_root);
        let baseline_verdict_tree = capture_store_tree(&verdict_root);
        let baseline_pack_tree = capture_store_tree(&pack_root);
        let ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let (intent, signature) = signed_vote_intent(&ledger.report, &voter_a, &signer_a, now_ms());
        let mut sorted_voters = vec![voter_a.clone(), voter_b.clone()];
        sorted_voters.sort();
        let mut reordered_voters = sorted_voters.clone();
        reordered_voters.reverse();

        let assert_rejected = |expected_set_tree: BTreeMap<PathBuf, Vec<u8>>| {
            let reopened = DefaultApprovalHarness::from_path(
                dir.child("config-placeholder"),
                &verdict_root,
                &pack_root,
                &set_root,
                &ledger_root,
            )
            .unwrap();
            let append_error = reopened.append_signed_vote(&intent, &signature);
            assert!(
                matches!(append_error, Err(ApprovalError::SetStore(_))),
                "{append_error:?}"
            );
            assert!(matches!(
                reopened.create_verdict(&set.set_id, &ledger_id),
                Err(ApprovalError::SetStore(_))
            ));
            assert!(matches!(
                reopened.ensure_approved_receipt_pack(
                    &set.set_id,
                    &ledger_id,
                    "tampered-set-signer",
                    &signing_key_env,
                ),
                Err(ApprovalError::SetStore(_))
            ));
            assert_eq!(capture_store_tree(&set_root), expected_set_tree);
            assert_eq!(capture_store_tree(&ledger_root), baseline_ledger_tree);
            assert_eq!(capture_store_tree(&verdict_root), baseline_verdict_tree);
            assert_eq!(capture_store_tree(&pack_root), baseline_pack_tree);
        };

        let mut report_mutations = Vec::new();
        for (label, voters) in [
            (
                "added-voter",
                json!([voter_a.clone(), voter_b.clone(), "swarm:ed25519:added"]),
            ),
            ("removed-voter", json!([voter_a.clone()])),
            ("reordered-voters", json!(reordered_voters)),
            (
                "duplicate-voter",
                json!([voter_a.clone(), voter_a.clone(), voter_b.clone()]),
            ),
        ] {
            let mut tampered = original_report.clone();
            tampered["eligible_voters"] = voters;
            report_mutations.push((label, tampered));
        }
        let mut tampered = original_report.clone();
        tampered["threshold"] = json!({"at_least": {"required": 2}});
        report_mutations.push(("threshold", tampered));
        let mut tampered = original_report.clone();
        tampered["promotion_evidence_ref"] =
            json!("swarm.governance.human-authorization.v1:tampered-classification");
        report_mutations.push(("evidence-ref", tampered));
        let mut tampered = original_report.clone();
        tampered["created_at_ms"] = json!(original_report["created_at_ms"].as_i64().unwrap() + 1);
        report_mutations.push(("created-at", tampered));
        let mut tampered = original_report.clone();
        tampered["set_id"] = json!("approval-set:legacy-old-id");
        report_mutations.push(("old-set-id", tampered));
        for (_label, tampered) in report_mutations {
            let tampered_report_bytes = serde_json::to_vec_pretty(&tampered).unwrap();
            fs::write(&set_report_path, &tampered_report_bytes).unwrap();
            let mut expected_set_tree = baseline_set_tree.clone();
            expected_set_tree.insert(set_report_path.clone(), tampered_report_bytes);
            assert_rejected(expected_set_tree);
            fs::write(&set_report_path, &original_report_bytes).unwrap();
        }

        for (field, value) in [
            ("report_digest", json!("tampered-report-digest")),
            ("voter_count", json!(99)),
            ("threshold", json!({"at_least": {"required": 2}})),
            (
                "promotion_evidence_ref",
                json!("tampered-index-classification"),
            ),
            (
                "created_at_ms",
                json!(original_report["created_at_ms"].as_i64().unwrap() + 1),
            ),
            (
                "bundle_path",
                json!(other_report_path.display().to_string()),
            ),
            ("set_id", json!("approval-set:legacy-index-id")),
        ] {
            let mut tampered: serde_json::Value =
                serde_json::from_slice(&original_index_bytes).unwrap();
            tampered["entries"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|entry| entry["set_id"] == json!(set.set_id))
                .unwrap()[field] = value;
            let tampered_index_bytes = serde_json::to_vec_pretty(&tampered).unwrap();
            fs::write(&set_index_path, &tampered_index_bytes).unwrap();
            let mut expected_set_tree = baseline_set_tree.clone();
            expected_set_tree.insert(set_index_path.clone(), tampered_index_bytes);
            assert_rejected(expected_set_tree);
            fs::write(&set_index_path, &original_index_bytes).unwrap();
        }

        let mut legacy_index: serde_json::Value =
            serde_json::from_slice(&original_index_bytes).unwrap();
        legacy_index["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("report_digest");
        let legacy_index_bytes = serde_json::to_vec_pretty(&legacy_index).unwrap();
        fs::write(&set_index_path, &legacy_index_bytes).unwrap();
        let mut expected_set_tree = baseline_set_tree.clone();
        expected_set_tree.insert(set_index_path.clone(), legacy_index_bytes);
        assert_rejected(expected_set_tree);
        fs::write(&set_index_path, &original_index_bytes).unwrap();

        fs::write(&set_report_path, &other_report_bytes).unwrap();
        let mut expected_set_tree = baseline_set_tree.clone();
        expected_set_tree.insert(set_report_path.clone(), other_report_bytes);
        assert_rejected(expected_set_tree);
    }

    #[test]
    fn tampered_persisted_pack_fails_closed_after_restart_without_replacement() {
        let dir = TestDir::new("tampered-persisted-pack");
        let signing_key_env = format!("SWARM_RUNTIME_APPROVAL_TAMPER_KEY_{}", std::process::id());
        let _signing_key = ScopedEnv::set(&signing_key_env, "tampered-approval-key");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, signer) = voter("tampered-pack-voter");
        let set = harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "swarm.governance.human-authorization.v1:tampered-pack",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        let ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let (intent, signature) = signed_vote_intent(&ledger.report, &voter_id, &signer, now_ms());
        harness.append_signed_vote(&intent, &signature).unwrap();
        let pack = harness
            .ensure_approved_receipt_pack(
                &set.set_id,
                &ledger_id,
                "tamper-test-signer",
                &signing_key_env,
            )
            .unwrap();
        let pack_path = PathBuf::from(&pack.record.bundle_path);
        let original_bytes = fs::read(&pack_path).unwrap();
        drop(harness);

        let assert_tampered = |mutated: serde_json::Value| {
            fs::write(&pack_path, serde_json::to_vec_pretty(&mutated).unwrap()).unwrap();
            let before_sets = capture_store_tree(&dir.child("approval-sets"));
            let before_ledgers = capture_store_tree(&dir.child("approval-ledgers"));
            let before_verdicts = capture_store_tree(&dir.child("approval-verdicts"));
            let before_packs = capture_store_tree(&dir.child("approval-receipt-packs"));
            let reopened = DefaultApprovalHarness::from_path(
                dir.child("config-placeholder"),
                dir.child("approval-verdicts"),
                dir.child("approval-receipt-packs"),
                dir.child("approval-sets"),
                dir.child("approval-ledgers"),
            )
            .unwrap();
            assert!(matches!(
                reopened.ensure_approved_receipt_pack(
                    &set.set_id,
                    &ledger_id,
                    "tamper-test-signer",
                    &signing_key_env,
                ),
                Err(ApprovalError::InvalidReceiptPack { .. })
            ));
            assert_eq!(reopened.list_verdicts().unwrap().total_count, 1);
            assert!(matches!(
                reopened.list_receipt_packs(),
                Err(ApprovalError::InvalidReceiptPack { .. })
            ));
            assert_eq!(capture_store_tree(&dir.child("approval-sets")), before_sets);
            assert_eq!(
                capture_store_tree(&dir.child("approval-ledgers")),
                before_ledgers
            );
            assert_eq!(
                capture_store_tree(&dir.child("approval-verdicts")),
                before_verdicts
            );
            assert_eq!(
                capture_store_tree(&dir.child("approval-receipt-packs")),
                before_packs
            );
        };

        let mut tampered: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();
        tampered["audit_refs"] = json!(["audit://tampered"]);
        assert_tampered(tampered);

        let mut tampered: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();
        tampered["created_at_ms"] = json!(pack.report.created_at_ms + 1);
        assert_tampered(tampered);

        let mut tampered: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();
        tampered["pack_id"] = json!("approval-receipt-pack:tampered");
        assert_tampered(tampered);

        let mut tampered: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();
        tampered["ledger"]["schema_version"] = json!(LEGACY_APPROVAL_LEDGER_SCHEMA_VERSION);
        assert_tampered(tampered);

        assert_ne!(fs::read(&pack_path).unwrap(), original_bytes);
    }

    #[test]
    fn receipt_timestamp_repack_with_old_signature_fails_closed_after_restart() {
        let dir = TestDir::new("tampered-receipt-freshness");
        let signing_key_env = format!(
            "SWARM_RUNTIME_APPROVAL_TAMPER_FRESHNESS_KEY_{}",
            std::process::id()
        );
        let _signing_key = ScopedEnv::set(&signing_key_env, "tampered-freshness-key");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, signer) = voter("tampered-freshness-voter");
        let set = harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "swarm.governance.human-authorization.v1:tampered-freshness",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        let ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let (intent, signature) = signed_vote_intent(&ledger.report, &voter_id, &signer, now_ms());
        harness.append_signed_vote(&intent, &signature).unwrap();
        let pack = harness
            .ensure_approved_receipt_pack(
                &set.set_id,
                &ledger_id,
                "tampered-freshness-signer",
                &signing_key_env,
            )
            .unwrap();
        let pack_root = dir.child("approval-receipt-packs");
        let pack_index_path = pack_root.join("index.json");
        let old_pack_path = PathBuf::from(&pack.record.bundle_path);
        let mut tampered_report = pack.report.clone();
        tampered_report.created_at_ms = tampered_report.created_at_ms.saturating_add(1);
        tampered_report.pack_id = canonical_receipt_pack_id(&tampered_report).unwrap();
        let new_pack_path = pack_root
            .join("reports")
            .join(format!("{}.json", sanitize_id(&tampered_report.pack_id)));
        assert_ne!(new_pack_path, old_pack_path);
        fs::rename(&old_pack_path, &new_pack_path).unwrap();
        let mut tampered_index: serde_json::Value =
            serde_json::from_slice(&fs::read(&pack_index_path).unwrap()).unwrap();
        tampered_index["entries"][0]["pack_id"] = json!(tampered_report.pack_id);
        tampered_index["entries"][0]["created_at_ms"] = json!(tampered_report.created_at_ms);
        tampered_index["entries"][0]["bundle_path"] = json!(new_pack_path.display().to_string());
        let tampered_index_bytes = serde_json::to_vec_pretty(&tampered_index).unwrap();
        fs::write(&pack_index_path, &tampered_index_bytes).unwrap();
        fs::write(
            &new_pack_path,
            serde_json::to_vec_pretty(&tampered_report).unwrap(),
        )
        .unwrap();
        drop(harness);

        let reopened = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            &pack_root,
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        assert!(matches!(
            reopened.ensure_approved_receipt_pack(
                &set.set_id,
                &ledger_id,
                "tampered-freshness-signer",
                &signing_key_env,
            ),
            Err(ApprovalError::InvalidReceiptPack { .. })
        ));
        assert_eq!(fs::read(&pack_index_path).unwrap(), tampered_index_bytes);
        assert_eq!(fs::read_dir(pack_root.join("reports")).unwrap().count(), 1);
        assert_eq!(
            fs::read(&new_pack_path).unwrap(),
            serde_json::to_vec_pretty(&tampered_report).unwrap()
        );
    }

    #[test]
    fn tampered_verdict_and_pack_index_records_fail_closed_after_restart() {
        let dir = TestDir::new("tampered-approval-index-records");
        let signing_key_env = format!(
            "SWARM_RUNTIME_APPROVAL_TAMPER_INDEX_KEY_{}",
            std::process::id()
        );
        let _signing_key = ScopedEnv::set(&signing_key_env, "tampered-index-approval-key");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, signer) = voter("tampered-index-voter");
        let set = harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "swarm.governance.human-authorization.v1:tampered-index",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        let ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let (intent, signature) = signed_vote_intent(&ledger.report, &voter_id, &signer, now_ms());
        harness.append_signed_vote(&intent, &signature).unwrap();
        harness
            .ensure_approved_receipt_pack(
                &set.set_id,
                &ledger_id,
                "tampered-index-signer",
                &signing_key_env,
            )
            .unwrap();

        let verdict_root = dir.child("approval-verdicts");
        let pack_root = dir.child("approval-receipt-packs");
        let verdict_index_path = verdict_root.join("index.json");
        let pack_index_path = pack_root.join("index.json");
        let original_verdict_index = fs::read(&verdict_index_path).unwrap();
        let original_pack_index = fs::read(&pack_index_path).unwrap();
        let baseline_verdict_tree = capture_store_tree(&verdict_root);
        let baseline_pack_tree = capture_store_tree(&pack_root);
        let baseline_set_tree = capture_store_tree(&dir.child("approval-sets"));
        let baseline_ledger_tree = capture_store_tree(&dir.child("approval-ledgers"));

        let assert_unchanged_except = |verdict_index: &[u8], pack_index: &[u8]| {
            let mut expected_verdict_tree = baseline_verdict_tree.clone();
            expected_verdict_tree.insert(verdict_index_path.clone(), verdict_index.to_vec());
            let mut expected_pack_tree = baseline_pack_tree.clone();
            expected_pack_tree.insert(pack_index_path.clone(), pack_index.to_vec());
            assert_eq!(capture_store_tree(&verdict_root), expected_verdict_tree);
            assert_eq!(capture_store_tree(&pack_root), expected_pack_tree);
            assert_eq!(
                capture_store_tree(&dir.child("approval-sets")),
                baseline_set_tree
            );
            assert_eq!(
                capture_store_tree(&dir.child("approval-ledgers")),
                baseline_ledger_tree
            );
            let verdict_entries: serde_json::Value = serde_json::from_slice(verdict_index).unwrap();
            let pack_entries: serde_json::Value = serde_json::from_slice(pack_index).unwrap();
            assert_eq!(verdict_entries["entries"].as_array().unwrap().len(), 1);
            assert_eq!(pack_entries["entries"].as_array().unwrap().len(), 1);
        };

        for (field, value) in [
            ("approval_set_id", json!("tampered-approval-set")),
            ("ledger_id", json!("tampered-ledger")),
            ("status", json!("not_approved")),
        ] {
            let mut tampered: serde_json::Value =
                serde_json::from_slice(&original_verdict_index).unwrap();
            tampered["entries"][0][field] = value;
            let tampered_bytes = serde_json::to_vec_pretty(&tampered).unwrap();
            fs::write(&verdict_index_path, &tampered_bytes).unwrap();
            let reopened = DefaultApprovalHarness::from_path(
                dir.child("config-placeholder"),
                &verdict_root,
                &pack_root,
                dir.child("approval-sets"),
                dir.child("approval-ledgers"),
            )
            .unwrap();
            assert!(matches!(
                reopened.ensure_approved_receipt_pack(
                    &set.set_id,
                    &ledger_id,
                    "tampered-index-signer",
                    &signing_key_env,
                ),
                Err(ApprovalError::InvalidVerdictRequest { .. })
            ));
            assert_unchanged_except(&tampered_bytes, &original_pack_index);
            drop(reopened);
            fs::write(&verdict_index_path, &original_verdict_index).unwrap();
        }

        for (field, value) in [
            ("approval_set_id", json!("tampered-approval-set")),
            ("ledger_id", json!("tampered-ledger")),
        ] {
            let mut tampered: serde_json::Value =
                serde_json::from_slice(&original_pack_index).unwrap();
            tampered["entries"][0][field] = value;
            let tampered_bytes = serde_json::to_vec_pretty(&tampered).unwrap();
            fs::write(&pack_index_path, &tampered_bytes).unwrap();
            let reopened = DefaultApprovalHarness::from_path(
                dir.child("config-placeholder"),
                &verdict_root,
                &pack_root,
                dir.child("approval-sets"),
                dir.child("approval-ledgers"),
            )
            .unwrap();
            assert!(matches!(
                reopened.ensure_approved_receipt_pack(
                    &set.set_id,
                    &ledger_id,
                    "tampered-index-signer",
                    &signing_key_env,
                ),
                Err(ApprovalError::InvalidReceiptPack { .. })
            ));
            assert_unchanged_except(&original_verdict_index, &tampered_bytes);
            drop(reopened);
            fs::write(&pack_index_path, &original_pack_index).unwrap();
        }
    }

    #[test]
    fn vote_envelope_hash_is_bound_to_the_persisted_vote_timestamp() {
        let (voter_id, signer) = voter("stable-envelope-time");
        let ledger = sample_ledger("approval-set:stable-envelope-time");
        let timestamp_ms = 1_700_000_000_300;
        let (intent, signature) = signed_vote_intent(&ledger, &voter_id, &signer, timestamp_ms);

        let actual = build_vote_envelope_hash(&ledger, &intent, &signature).unwrap();
        let keypair = Keypair::from_seed(
            sha256(format!("approval-ledger-envelope:{}", ledger.ledger_id).as_bytes()).as_bytes(),
        );
        let expected = build_signed_envelope(
            &keypair,
            1,
            None,
            json!({
            "type": "approval_vote",
            "signature_version": intent.signature_version,
            "approval_set_id": ledger.approval_set_id,
                "ledger_id": ledger.ledger_id,
                "entry_id": intent.entry_id,
                "voter_id": voter_id,
                "vote": "approve",
                "timestamp_ms": timestamp_ms,
                "previous_envelope_hash": null,
                "signature": signature,
            }),
            "2023-11-14T22:13:20Z".to_string(),
        )
        .unwrap()["envelope_hash"]
            .as_str()
            .unwrap()
            .to_string();

        assert_eq!(actual, expected);
    }

    #[test]
    fn validate_and_append_vote_rejects_duplicate_voter() {
        let (voter_id, signer) = voter("alpha");
        let set = sample_set(vec![voter_id.clone()], 1);
        let mut ledger = sample_ledger(&set.set_id);
        let (intent, signature) =
            signed_vote_intent(&ledger, &voter_id, &signer, 1_700_000_000_300);
        validate_and_append_vote(&mut ledger, &set, &intent, &signature).unwrap();

        let error = validate_and_append_vote(&mut ledger, &set, &intent, &signature).unwrap_err();
        assert!(matches!(error, ApprovalError::DuplicateVoter { .. }));
    }

    #[test]
    fn validate_and_append_vote_rejects_ineligible_voter() {
        let (eligible_voter, _) = voter("eligible");
        let (ineligible_voter, signer) = voter("ineligible");
        let set = sample_set(vec![eligible_voter], 1);
        let mut ledger = sample_ledger(&set.set_id);
        let (intent, signature) =
            signed_vote_intent(&ledger, &ineligible_voter, &signer, 1_700_000_000_300);

        let error = validate_and_append_vote(&mut ledger, &set, &intent, &signature).unwrap_err();
        assert!(matches!(error, ApprovalError::IneligibleVoter { .. }));
    }

    #[test]
    fn validate_and_append_vote_rejects_invalid_signature() {
        let (voter_id, _) = voter("eligible");
        let (_, wrong_signer) = voter("wrong");
        let set = sample_set(vec![voter_id.clone()], 1);
        let mut ledger = sample_ledger(&set.set_id);
        let (intent, signature) =
            signed_vote_intent(&ledger, &voter_id, &wrong_signer, 1_700_000_000_300);

        let error = validate_and_append_vote(&mut ledger, &set, &intent, &signature).unwrap_err();
        assert!(matches!(error, ApprovalError::InvalidSignature { .. }));
    }

    #[test]
    fn harness_persists_sets_ledgers_and_votes() {
        let dir = TestDir::new("harness");
        let harness = DefaultApprovalHarness::from_paths(
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, signer) = voter("alpha");

        let record = harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:test",
            )
            .unwrap();
        let set = harness.load_approval_set(&record.set_id).unwrap().unwrap();
        assert_eq!(set.report.eligible_voters, vec![voter_id.clone()]);

        let ledgers = harness.list_ledgers(Some(&record.set_id)).unwrap();
        assert_eq!(ledgers.total_count, 1);
        let quorum = harness
            .append_vote(&record.set_id, &voter_id, &signer)
            .unwrap();
        assert!(quorum.quorum_met);

        let ledger = harness
            .load_ledger(&ledgers.ledgers[0].ledger_id)
            .unwrap()
            .unwrap();
        assert_eq!(ledger.report.entries.len(), 1);
        assert_eq!(ledger.quorum_state.votes_received, 1);
        assert!(ledger.report.entries[0].envelope_hash.starts_with("0x"));
    }

    #[test]
    fn tracked_legacy_fixture_quarantines_partial_pack_without_losing_ledger_audit() {
        const LEGACY_SET: &str = include_str!(
            "../../../data/approval-sets/reports/approval-set_1775999389010_78f831a60ffb.json"
        );
        const LEGACY_LEDGER: &str = include_str!(
            "../../../data/approval-ledgers/reports/approval-ledger_1775999389010_af0e7ffe9869.json"
        );
        const LEGACY_VERDICT: &str = include_str!(
            "../../../data/approval-verdicts/reports/approval-verdict_1775999389015_1b6903d82da2.json"
        );
        const LEGACY_PACK: &str = include_str!(
            "../../../data/approval-receipt-packs/reports/approval-receipt-pack_1775999389017_653e5fa1dbc5.json"
        );

        let dir = TestDir::new("tracked-legacy-golden");
        let set_root = dir.child("approval-sets");
        let ledger_root = dir.child("approval-ledgers");
        let verdict_root = dir.child("approval-verdicts");
        let pack_root = dir.child("approval-receipt-packs");
        let set: ApprovalSetReport = serde_json::from_str(LEGACY_SET).unwrap();
        let legacy =
            install_legacy_wire_ledger(&set_root, &ledger_root, &set, LEGACY_LEDGER.as_bytes());
        assert_eq!(legacy.entries.len(), 1);
        assert_eq!(
            legacy.entries[0].signature_version,
            ApprovalVoteSignatureVersion::LegacyV1
        );
        validate_legacy_ledger_report(&legacy, &set).unwrap();

        let verdict: ApprovalVerdictReport = serde_json::from_str(LEGACY_VERDICT).unwrap();
        let verdict_store = FileApprovalVerdictStore::open(&verdict_root).unwrap();
        let verdict_path = verdict_store.report_path(&verdict.verdict_id);
        fs::write(&verdict_path, LEGACY_VERDICT).unwrap();
        verdict_store
            .write_index(&ApprovalVerdictIndex {
                entries: vec![ApprovalVerdictRecord::from_report(
                    &verdict,
                    verdict_path.display().to_string(),
                )],
            })
            .unwrap();
        let legacy_pack: ApprovalReceiptPackReport = serde_json::from_str(LEGACY_PACK).unwrap();
        let pack_store = FileApprovalReceiptPackStore::open(&pack_root).unwrap();
        let pack_path = pack_store.report_path(&legacy_pack.pack_id);
        fs::write(&pack_path, LEGACY_PACK).unwrap();
        pack_store
            .write_index(&ApprovalReceiptPackIndex {
                entries: vec![ApprovalReceiptPackRecord::from_report(
                    &legacy_pack,
                    pack_path.display().to_string(),
                )],
            })
            .unwrap();

        let legacy_pack_error = verify_receipt_pack(&legacy_pack).unwrap_err();
        assert!(
            matches!(
                &legacy_pack_error,
                ApprovalError::InvalidReceiptPack { reason }
                    if reason.contains("is quarantined")
            ),
            "unexpected oldest-V1 rejection: {legacy_pack_error}"
        );

        // The later V1 payload covered signer identity and creation time. It
        // can be positively verified and retired without being authorization.
        let later_v1_signer = Ed25519Signer::from_secret_material("later-v1-receipt-key");
        let later_v1_signer_id = "later-v1-receipt-signer";
        let later_v1_created_at_ms = legacy_pack.created_at_ms;
        let later_v1_content = LegacyApprovalReceiptPackContentRef {
            signer_id: later_v1_signer_id,
            approval_set: &set,
            ledger: legacy_ledger_content_ref(&legacy),
            verdict: legacy_verdict_content_ref(&verdict),
            audit_refs: &legacy_pack.audit_refs,
            created_at_ms: later_v1_created_at_ms,
        };
        let later_v1_payload = canonical_json_bytes(&later_v1_content).unwrap();
        let later_v1_content_hash = sha256_hex(&later_v1_payload);
        let later_v1_signature = later_v1_signer.sign(&later_v1_payload);
        let later_v1_pack_id = approval_receipt_pack_id(
            later_v1_created_at_ms,
            &canonical_json_bytes(&ApprovalReceiptPackIdSeed {
                signer_id: later_v1_signer_id,
                content_hash: &later_v1_content_hash,
                signature_key_id: &later_v1_signature.key_id,
                created_at_ms: later_v1_created_at_ms,
            })
            .unwrap(),
        );
        let later_v1_pack = ApprovalReceiptPackReport {
            signature_version: ApprovalReceiptPackSignatureVersion::LegacyV1,
            pack_id: later_v1_pack_id,
            signer_id: later_v1_signer_id.to_string(),
            approval_set: set.clone(),
            ledger: legacy.clone(),
            verdict: verdict.clone(),
            audit_refs: legacy_pack.audit_refs.clone(),
            content_hash: later_v1_content_hash,
            signature: later_v1_signature,
            created_at_ms: later_v1_created_at_ms,
        };
        assert!(matches!(
            verify_receipt_pack(&later_v1_pack),
            Err(ApprovalError::InvalidReceiptPack { reason })
                if reason.contains("legacy approval receipt packs are retired")
        ));
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            &verdict_root,
            &pack_root,
            &set_root,
            &ledger_root,
        )
        .unwrap();
        let migrated = harness.load_ledger(&legacy.ledger_id).unwrap().unwrap();
        assert_eq!(
            migrated.report.schema_version,
            CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION
        );
        assert_eq!(migrated.report.entries, legacy.entries);
        assert_eq!(migrated.quorum_state.votes_received, 0);
        assert!(!migrated.quorum_state.quorum_met);
        assert_eq!(migrated.quorum_state.voters_remaining, set.eligible_voters);
        let rendered = render_approval_ledger(&migrated.report, &migrated.quorum_state);
        assert!(rendered.contains("Schema Version: 2"));
        assert!(rendered.contains("retired legacy audit"));
        assert!(harness.list_verdicts().unwrap().verdicts.is_empty());
        let packs = harness.list_receipt_packs().unwrap();
        assert_eq!(packs.total_count, 0);
        assert!(packs.packs.is_empty());
        assert_eq!(packs.quarantined_count, 1);
        assert_eq!(packs.quarantined[0].observed_pack_id, legacy_pack.pack_id);
        assert!(packs.quarantined[0].reason.contains("non-authoritative"));
        assert!(
            harness
                .load_receipt_pack(&legacy_pack.pack_id)
                .unwrap()
                .is_none()
        );

        let mut invalid_legacy_pack = later_v1_pack;
        invalid_legacy_pack
            .audit_refs
            .push("audit:tampered".to_string());
        let invalid_legacy_pack_error = verify_receipt_pack(&invalid_legacy_pack).unwrap_err();
        assert!(matches!(
            invalid_legacy_pack_error,
            ApprovalError::InvalidReceiptPack { reason }
                if !reason.contains("are retired")
        ));

        let mut invalid_legacy_verdict: serde_json::Value =
            serde_json::from_str(LEGACY_VERDICT).unwrap();
        invalid_legacy_verdict["threshold_required"] = json!("tampered V1 projection");
        fs::write(
            &verdict_path,
            serde_json::to_vec_pretty(&invalid_legacy_verdict).unwrap(),
        )
        .unwrap();
        let invalid_verdict_tree = capture_store_tree(&verdict_root);
        assert!(matches!(
            harness.list_verdicts(),
            Err(ApprovalError::InvalidVerdictRequest { reason })
                if reason.contains("does not match its verified V1 lineage")
        ));
        assert_eq!(capture_store_tree(&verdict_root), invalid_verdict_tree);
        fs::write(&verdict_path, LEGACY_VERDICT).unwrap();

        assert_eq!(fs::read_to_string(verdict_path).unwrap(), LEGACY_VERDICT);
        assert_eq!(fs::read_to_string(&pack_path).unwrap(), LEGACY_PACK);

        // The oldest V1 signature omitted signer_id and created_at_ms. An
        // attacker can therefore coordinate those mutations with a new
        // canonical ID, report path, and index record without breaking that
        // partial signature. Such an artifact must remain quarantined and
        // non-authoritative, never misclassified as verified retired audit.
        let mut coordinated = legacy_pack;
        coordinated.signer_id = "coordinated-attacker".to_string();
        coordinated.created_at_ms = coordinated.created_at_ms.saturating_add(10_000);
        coordinated.pack_id = canonical_receipt_pack_id(&coordinated).unwrap();
        let coordinated_path = pack_store.report_path(&coordinated.pack_id);
        fs::rename(&pack_path, &coordinated_path).unwrap();
        fs::write(
            &coordinated_path,
            serde_json::to_vec_pretty(&coordinated).unwrap(),
        )
        .unwrap();
        pack_store
            .write_index(&ApprovalReceiptPackIndex {
                entries: vec![ApprovalReceiptPackRecord::from_report(
                    &coordinated,
                    coordinated_path.display().to_string(),
                )],
            })
            .unwrap();
        let coordinated_sets = capture_store_tree(&set_root);
        let coordinated_ledgers = capture_store_tree(&ledger_root);
        let coordinated_verdicts = capture_store_tree(&verdict_root);
        let coordinated_packs = capture_store_tree(&pack_root);
        let coordinated_projection = harness.list_receipt_packs().unwrap();
        assert_eq!(coordinated_projection.total_count, 0);
        assert!(coordinated_projection.packs.is_empty());
        assert_eq!(coordinated_projection.quarantined_count, 1);
        assert_eq!(
            coordinated_projection.quarantined[0].observed_pack_id,
            coordinated.pack_id
        );
        assert_eq!(
            coordinated_projection.quarantined[0].observed_signer_id,
            "coordinated-attacker"
        );
        assert!(
            coordinated_projection.quarantined[0]
                .reason
                .contains("non-authoritative")
        );
        assert_eq!(capture_store_tree(&set_root), coordinated_sets);
        assert_eq!(capture_store_tree(&ledger_root), coordinated_ledgers);
        assert_eq!(capture_store_tree(&verdict_root), coordinated_verdicts);
        assert_eq!(capture_store_tree(&pack_root), coordinated_packs);
    }

    #[test]
    fn legacy_wire_migration_is_concurrent_idempotent_and_requires_v2_revote_after_restart() {
        const TRACKED_LEGACY_LEDGER: &str = include_str!(
            "../../../data/approval-ledgers/reports/approval-ledger_1775999389010_af0e7ffe9869.json"
        );
        let dir = TestDir::new("legacy-revote-restart");
        let set_root = dir.child("approval-sets");
        let ledger_root = dir.child("approval-ledgers");
        let verdict_root = dir.child("approval-verdicts");
        let pack_root = dir.child("approval-receipt-packs");
        let (voter_id, signer) = voter("legacy-revote-voter");
        let created_at_ms = now_ms().saturating_sub(100);
        let threshold = ThresholdRule::AtLeast { required: 1 };
        let evidence_ref = "swarm.governance.human-authorization.v1:legacy-revote";
        let set_id = canonical_approval_set_id_fields(
            std::slice::from_ref(&voter_id),
            &threshold,
            evidence_ref,
            created_at_ms,
        )
        .unwrap();
        let set = ApprovalSetReport {
            set_id: set_id.clone(),
            eligible_voters: vec![voter_id.clone()],
            threshold,
            promotion_evidence_ref: evidence_ref.to_string(),
            created_at_ms,
        };
        let ledger_id = approval_ledger_id(&set_id, created_at_ms);
        let legacy_timestamp_ms = now_ms().saturating_add(3_600_000);
        let legacy_signature = signer
            .sign(&legacy_approval_vote_payload_bytes(&set_id, &ledger_id, &voter_id).unwrap());
        let mut legacy = ApprovalLedgerReport {
            schema_version: LEGACY_APPROVAL_LEDGER_SCHEMA_VERSION,
            ledger_id: ledger_id.clone(),
            approval_set_id: set_id.clone(),
            entries: Vec::new(),
            created_at_ms,
        };
        let entry_id = next_approval_ledger_entry_id(&ledger_id, 0);
        let envelope_hash = build_legacy_vote_envelope_hash(
            &legacy,
            &entry_id,
            &voter_id,
            &legacy_signature,
            legacy_timestamp_ms,
        )
        .unwrap();
        legacy.entries.push(ApprovalLedgerEntry {
            entry_id,
            voter_id: voter_id.clone(),
            vote: ApprovalVote::Approve,
            signature_version: ApprovalVoteSignatureVersion::LegacyV1,
            signature: legacy_signature,
            timestamp_ms: legacy_timestamp_ms,
            previous_envelope_hash: None,
            envelope_hash,
        });

        let tracked_shape: serde_json::Value = serde_json::from_str(TRACKED_LEGACY_LEDGER).unwrap();
        let tracked_entry_keys = tracked_shape["entries"][0]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<HashSet<_>>();
        let mut legacy_wire = serde_json::to_value(&legacy).unwrap();
        legacy_wire
            .as_object_mut()
            .unwrap()
            .remove("schema_version");
        let legacy_wire_entry = legacy_wire["entries"][0].as_object_mut().unwrap();
        legacy_wire_entry.remove("signature_version");
        legacy_wire_entry.remove("previous_envelope_hash");
        assert_eq!(
            legacy_wire_entry.keys().cloned().collect::<HashSet<_>>(),
            tracked_entry_keys,
            "the generated migration fixture must retain the tracked V1 wire shape"
        );
        let legacy_wire_bytes = serde_json::to_vec_pretty(&legacy_wire).unwrap();
        install_legacy_wire_ledger(&set_root, &ledger_root, &set, &legacy_wire_bytes);

        let legacy_verdict =
            evaluate_legacy_verdict(&set, &legacy, legacy_timestamp_ms.saturating_add(1)).unwrap();
        let mut legacy_verdict_wire = serde_json::to_value(&legacy_verdict).unwrap();
        legacy_verdict_wire
            .as_object_mut()
            .unwrap()
            .remove("schema_version");
        let legacy_verdict_bytes = serde_json::to_vec_pretty(&legacy_verdict_wire).unwrap();
        let legacy_verdict_store = FileApprovalVerdictStore::open(&verdict_root).unwrap();
        let legacy_verdict_path = legacy_verdict_store.report_path(&legacy_verdict.verdict_id);
        fs::write(&legacy_verdict_path, &legacy_verdict_bytes).unwrap();
        legacy_verdict_store
            .write_index(&ApprovalVerdictIndex {
                entries: vec![ApprovalVerdictRecord::from_report(
                    &legacy_verdict,
                    legacy_verdict_path.display().to_string(),
                )],
            })
            .unwrap();

        let oldest_pack_signer = Ed25519Signer::from_secret_material("oldest-v1-pack-key");
        let oldest_pack_signer_id = "oldest-v1-observed-signer";
        let oldest_pack_created_at_ms = legacy_verdict.evaluated_at_ms.saturating_add(1);
        let oldest_audit_refs = vec![evidence_ref.to_string()];
        let oldest_signed_core = OriginalApprovalReceiptPackContentRef {
            approval_set: &set,
            ledger: legacy_ledger_content_ref(&legacy),
            verdict: legacy_verdict_content_ref(&legacy_verdict),
            audit_refs: &oldest_audit_refs,
        };
        let oldest_payload = canonical_json_bytes(&oldest_signed_core).unwrap();
        let oldest_content_hash = sha256_hex(&oldest_payload);
        let oldest_signature = oldest_pack_signer.sign(&oldest_payload);
        let oldest_pack_id = approval_receipt_pack_id(
            oldest_pack_created_at_ms,
            &canonical_json_bytes(&ApprovalReceiptPackIdSeed {
                signer_id: oldest_pack_signer_id,
                content_hash: &oldest_content_hash,
                signature_key_id: &oldest_signature.key_id,
                created_at_ms: oldest_pack_created_at_ms,
            })
            .unwrap(),
        );
        let oldest_pack = ApprovalReceiptPackReport {
            signature_version: ApprovalReceiptPackSignatureVersion::LegacyV1,
            pack_id: oldest_pack_id,
            signer_id: oldest_pack_signer_id.to_string(),
            approval_set: set.clone(),
            ledger: legacy.clone(),
            verdict: legacy_verdict,
            audit_refs: oldest_audit_refs,
            content_hash: oldest_content_hash,
            signature: oldest_signature,
            created_at_ms: oldest_pack_created_at_ms,
        };
        let mut oldest_pack_wire = serde_json::to_value(&oldest_pack).unwrap();
        oldest_pack_wire
            .as_object_mut()
            .unwrap()
            .remove("signature_version");
        oldest_pack_wire["ledger"]
            .as_object_mut()
            .unwrap()
            .remove("schema_version");
        oldest_pack_wire["ledger"]["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("signature_version");
        oldest_pack_wire["ledger"]["entries"][0]
            .as_object_mut()
            .unwrap()
            .remove("previous_envelope_hash");
        oldest_pack_wire["verdict"]
            .as_object_mut()
            .unwrap()
            .remove("schema_version");
        let oldest_pack_bytes = serde_json::to_vec_pretty(&oldest_pack_wire).unwrap();
        let oldest_pack_store = FileApprovalReceiptPackStore::open(&pack_root).unwrap();
        let oldest_pack_path = oldest_pack_store.report_path(&oldest_pack.pack_id);
        fs::write(&oldest_pack_path, &oldest_pack_bytes).unwrap();
        oldest_pack_store
            .write_index(&ApprovalReceiptPackIndex {
                entries: vec![ApprovalReceiptPackRecord::from_report(
                    &oldest_pack,
                    oldest_pack_path.display().to_string(),
                )],
            })
            .unwrap();

        let harness = Arc::new(
            DefaultApprovalHarness::from_path(
                dir.child("config-placeholder"),
                &verdict_root,
                &pack_root,
                &set_root,
                &ledger_root,
            )
            .unwrap(),
        );
        let start = Arc::new(Barrier::new(3));
        let mut migrations = Vec::new();
        for _ in 0..2 {
            let harness = harness.clone();
            let ledger_id = ledger_id.clone();
            let start = start.clone();
            migrations.push(thread::spawn(move || {
                start.wait();
                harness.load_ledger(&ledger_id).unwrap().unwrap()
            }));
        }
        start.wait();
        for migrated in migrations.into_iter().map(|worker| worker.join().unwrap()) {
            assert_eq!(
                migrated.report.schema_version,
                CURRENT_APPROVAL_LEDGER_SCHEMA_VERSION
            );
            assert_eq!(migrated.report.entries.len(), 1);
            assert!(!migrated.quorum_state.quorum_met);
        }
        let migrated_tree = capture_store_tree(&ledger_root);
        drop(harness);

        let reopened = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            &verdict_root,
            &pack_root,
            &set_root,
            &ledger_root,
        )
        .unwrap();
        let migrated = reopened.load_ledger(&ledger_id).unwrap().unwrap();
        assert_eq!(capture_store_tree(&ledger_root), migrated_tree);
        assert_eq!(migrated.quorum_state.votes_received, 0);
        let current_timestamp_ms = now_ms();
        assert!(current_timestamp_ms < legacy_timestamp_ms);
        let (intent, signature) =
            signed_vote_intent(&migrated.report, &voter_id, &signer, current_timestamp_ms);
        reopened.append_signed_vote(&intent, &signature).unwrap();
        let approved = reopened.load_ledger(&ledger_id).unwrap().unwrap();
        assert_eq!(approved.report.entries.len(), 2);
        assert_eq!(
            approved.report.entries[0].signature_version,
            ApprovalVoteSignatureVersion::LegacyV1
        );
        assert_eq!(
            approved.report.entries[1].signature_version,
            ApprovalVoteSignatureVersion::IntentV2
        );
        assert!(approved.report.entries[1].timestamp_ms < approved.report.entries[0].timestamp_ms);
        assert_eq!(approved.quorum_state.votes_received, 1);
        assert!(approved.quorum_state.quorum_met);

        let signing_key_env = format!("SWARM_RUNTIME_LEGACY_REVOTE_KEY_{}", std::process::id());
        let _signing_key = ScopedEnv::set(&signing_key_env, "legacy-revote-pack-key");
        let pack = reopened
            .ensure_approved_receipt_pack(
                &set_id,
                &ledger_id,
                "legacy-revote-pack-signer",
                &signing_key_env,
            )
            .unwrap();
        verify_governed_human_receipt_pack(
            &pack.report,
            &set_id,
            &approval_set_digest(&set).unwrap(),
            evidence_ref,
            created_at_ms,
            now_ms(),
        )
        .unwrap();
        let retried_pack = reopened
            .ensure_approved_receipt_pack(
                &set_id,
                &ledger_id,
                "legacy-revote-pack-signer",
                &signing_key_env,
            )
            .unwrap();
        assert_eq!(retried_pack, pack);
        let projection = reopened.list_receipt_packs().unwrap();
        assert_eq!(projection.total_count, 1);
        assert_eq!(projection.packs.len(), 1);
        assert_eq!(projection.packs[0].pack_id, pack.report.pack_id);
        assert_eq!(projection.quarantined_count, 1);
        assert_eq!(projection.quarantined.len(), 1);
        assert_eq!(
            projection.quarantined[0].observed_pack_id,
            oldest_pack.pack_id
        );
        assert!(
            projection.quarantined[0]
                .reason
                .contains("non-authoritative")
        );
        assert!(
            render_approval_receipt_pack_list(&projection)
                .contains("Quarantined Legacy Receipt Packs (1)")
        );
        assert_eq!(fs::read(&oldest_pack_path).unwrap(), oldest_pack_bytes);
        drop(reopened);

        let restarted = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            &verdict_root,
            &pack_root,
            &set_root,
            &ledger_root,
        )
        .unwrap();
        let after_restart = restarted.load_ledger(&ledger_id).unwrap().unwrap();
        assert_eq!(after_restart.report, approved.report);
        assert!(after_restart.quorum_state.quorum_met);
        assert_eq!(
            restarted
                .load_receipt_pack(&pack.report.pack_id)
                .unwrap()
                .unwrap()
                .report,
            pack.report
        );
        assert_eq!(
            pack.report.signature_version,
            ApprovalReceiptPackSignatureVersion::V2
        );
        assert_eq!(
            pack.report.verdict.schema_version,
            CURRENT_APPROVAL_VERDICT_SCHEMA_VERSION
        );
        let restarted_projection = restarted.list_receipt_packs().unwrap();
        assert_eq!(restarted_projection.total_count, 1);
        assert_eq!(restarted_projection.quarantined_count, 1);
        assert_eq!(fs::read(&oldest_pack_path).unwrap(), oldest_pack_bytes);

        // A V2 verdict on a ledger that retains V1 audit history must still
        // fail closed when a field outside the index and ID seed is changed.
        // Legacy history is not a blanket reason to hide a malformed report.
        let verdict_path = PathBuf::from(
            restarted
                .load_verdict(&pack.report.verdict.verdict_id)
                .unwrap()
                .unwrap()
                .record
                .bundle_path,
        );
        let mut tampered_verdict: serde_json::Value =
            serde_json::from_slice(&fs::read(&verdict_path).unwrap()).unwrap();
        tampered_verdict["threshold_required"] = json!("tampered V2 projection");
        fs::write(
            &verdict_path,
            serde_json::to_vec_pretty(&tampered_verdict).unwrap(),
        )
        .unwrap();
        let before_sets = capture_store_tree(&set_root);
        let before_ledgers = capture_store_tree(&ledger_root);
        let before_verdicts = capture_store_tree(&verdict_root);
        let before_packs = capture_store_tree(&pack_root);
        assert!(matches!(
            restarted.list_verdicts(),
            Err(ApprovalError::InvalidVerdictRequest { reason })
                if reason.contains("does not match its persisted set and ledger")
        ));
        assert!(matches!(
            restarted.ensure_approved_receipt_pack(
                &set_id,
                &ledger_id,
                "legacy-revote-pack-signer",
                &signing_key_env,
            ),
            Err(ApprovalError::InvalidVerdictRequest { .. })
        ));
        assert_eq!(capture_store_tree(&set_root), before_sets);
        assert_eq!(capture_store_tree(&ledger_root), before_ledgers);
        assert_eq!(capture_store_tree(&verdict_root), before_verdicts);
        assert_eq!(capture_store_tree(&pack_root), before_packs);
    }

    #[test]
    fn durable_reject_vote_is_refused_before_any_store_mutation() {
        let dir = TestDir::new("reject-vote-no-mutation");
        let set_root = dir.child("approval-sets");
        let ledger_root = dir.child("approval-ledgers");
        let harness = DefaultApprovalHarness::from_paths(&set_root, &ledger_root).unwrap();
        let (voter_id, signer) = voter("reject-vote-voter");
        let set = harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:reject-vote",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        let ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let intent =
            build_approval_vote_intent(&ledger.report, &voter_id, ApprovalVote::Reject, now_ms());
        let signature = signer.sign(&approval_vote_payload_bytes(&intent).unwrap());
        let set_before = capture_store_tree(&set_root);
        let ledger_before = capture_store_tree(&ledger_root);

        assert!(matches!(
            harness.append_signed_vote_outcome(&intent, &signature),
            Err(ApprovalError::InvalidLedgerRequest { reason })
                if reason.contains("do not yet support denial votes")
        ));
        assert_eq!(capture_store_tree(&set_root), set_before);
        assert_eq!(capture_store_tree(&ledger_root), ledger_before);
        assert_eq!(harness.load_ledger(&ledger_id).unwrap().unwrap(), ledger);
    }

    #[test]
    fn monotonic_approval_timestamps_clamp_an_injected_backward_clock() {
        let (voter_id, signer) = voter("backward-clock-voter");
        let set = sample_set(vec![voter_id.clone()], 1);
        let mut ledger = sample_ledger(&set.set_id);
        let authenticated_vote_ms = 1_700_000_000_300;
        let observed_backward_clock_ms = 1_700_000_000_250;
        let (intent, signature) =
            signed_vote_intent(&ledger, &voter_id, &signer, authenticated_vote_ms);
        validate_and_append_vote_at(
            &mut ledger,
            &set,
            &intent,
            &signature,
            observed_backward_clock_ms,
        )
        .unwrap();

        assert_eq!(
            next_approval_vote_timestamp_ms(&ledger, observed_backward_clock_ms),
            authenticated_vote_ms
        );
        assert_eq!(
            approval_verdict_timestamp_ms(&ledger, observed_backward_clock_ms),
            authenticated_vote_ms
        );
        let verdict = evaluate_verdict(&set, &ledger, authenticated_vote_ms).unwrap();
        assert_eq!(
            approval_receipt_timestamp_ms(&verdict, observed_backward_clock_ms),
            authenticated_vote_ms
        );
    }

    #[test]
    fn signed_future_vote_is_rejected_on_append_and_persisted_replay() {
        let dir = TestDir::new("future-vote-skew");
        let harness = DefaultApprovalHarness::from_paths(
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, signer) = voter("future-vote-voter");
        let set_record = harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:future-vote-skew",
            )
            .unwrap();
        let set = harness
            .load_approval_set(&set_record.set_id)
            .unwrap()
            .unwrap()
            .report;
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        let ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let observed_now_ms = now_ms();
        let poisoned_timestamp_ms = observed_now_ms.saturating_add(3_600_000);
        let (intent, signature) =
            signed_vote_intent(&ledger.report, &voter_id, &signer, poisoned_timestamp_ms);
        let before_append = capture_store_tree(&dir.child("approval-ledgers"));

        assert!(matches!(
            harness.append_signed_vote(&intent, &signature),
            Err(ApprovalError::InvalidLedgerRequest { reason })
                if reason.contains("allowed future clock skew")
        ));
        assert_eq!(
            capture_store_tree(&dir.child("approval-ledgers")),
            before_append
        );

        let mut poisoned_ledger = ledger.report;
        validate_and_append_vote_at(
            &mut poisoned_ledger,
            &set,
            &intent,
            &signature,
            poisoned_timestamp_ms,
        )
        .unwrap();
        harness.ledger_store.persist(&poisoned_ledger).unwrap();
        assert!(matches!(
            harness.load_ledger(&ledger_id),
            Err(ApprovalError::InvalidLedgerRequest { reason })
                if reason.contains("allowed future clock skew")
        ));
    }

    #[test]
    fn evaluate_verdict_supports_count_majority_and_unanimous_rules() {
        let (voter_a, signer_a) = voter("alpha");
        let (voter_b, signer_b) = voter("bravo");
        let (voter_c, signer_c) = voter("charlie");
        let voters = vec![voter_a.clone(), voter_b.clone(), voter_c.clone()];

        let count_set = sample_set(voters.clone(), 2);
        let mut count_ledger = sample_ledger(&count_set.set_id);
        count_ledger.entries.push(signed_entry(
            &count_ledger.ledger_id,
            &count_set.set_id,
            &voter_a,
            &signer_a,
            0,
        ));
        count_ledger.entries.push(signed_entry(
            &count_ledger.ledger_id,
            &count_set.set_id,
            &voter_b,
            &signer_b,
            1,
        ));
        let count_verdict = evaluate_verdict(&count_set, &count_ledger, 1_700_000_000_400).unwrap();
        assert_eq!(count_verdict.status, ApprovalVerdictStatus::Approved);
        assert_eq!(count_verdict.approve_count, 2);
        assert_eq!(count_verdict.reject_count, 0);

        let majority_set = ApprovalSetReport {
            threshold: ThresholdRule::Majority,
            ..count_set.clone()
        };
        let majority_verdict =
            evaluate_verdict(&majority_set, &count_ledger, 1_700_000_000_401).unwrap();
        assert_eq!(majority_verdict.status, ApprovalVerdictStatus::Approved);
        assert_eq!(majority_verdict.threshold_required_count, 2);

        let unanimous_set = ApprovalSetReport {
            threshold: ThresholdRule::Unanimous,
            ..count_set
        };
        let mut unanimous_ledger = sample_ledger(&unanimous_set.set_id);
        unanimous_ledger.entries.push(signed_entry(
            &unanimous_ledger.ledger_id,
            &unanimous_set.set_id,
            &voter_a,
            &signer_a,
            0,
        ));
        unanimous_ledger.entries.push(signed_entry_with_vote(
            &unanimous_ledger.ledger_id,
            &unanimous_set.set_id,
            &voter_b,
            &signer_b,
            ApprovalVote::Reject,
            1,
        ));
        unanimous_ledger.entries.push(signed_entry(
            &unanimous_ledger.ledger_id,
            &unanimous_set.set_id,
            &voter_c,
            &signer_c,
            2,
        ));
        let unanimous_verdict =
            evaluate_verdict(&unanimous_set, &unanimous_ledger, 1_700_000_000_402).unwrap();
        assert_eq!(unanimous_verdict.status, ApprovalVerdictStatus::NotApproved);
        assert_eq!(unanimous_verdict.approve_count, 2);
        assert_eq!(unanimous_verdict.reject_count, 1);
        assert!(unanimous_verdict.missing_voters.is_empty());
    }

    #[test]
    fn evaluate_verdict_is_deterministic() {
        let (voter_a, signer_a) = voter("alpha");
        let (voter_b, signer_b) = voter("bravo");
        let set = sample_set(vec![voter_a.clone(), voter_b.clone()], 2);
        let mut ledger = sample_ledger(&set.set_id);
        ledger.entries.push(signed_entry(
            &ledger.ledger_id,
            &set.set_id,
            &voter_a,
            &signer_a,
            0,
        ));
        ledger.entries.push(signed_entry(
            &ledger.ledger_id,
            &set.set_id,
            &voter_b,
            &signer_b,
            1,
        ));

        let first = evaluate_verdict(&set, &ledger, 1_700_000_000_500).unwrap();
        let second = evaluate_verdict(&set, &ledger, 1_700_000_000_500).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            canonical_json_bytes(&first).unwrap(),
            canonical_json_bytes(&second).unwrap()
        );
    }

    #[test]
    fn evaluate_verdict_rejects_evaluation_before_a_counted_vote() {
        let (voter_a, signer_a) = voter("chronology-alpha");
        let (voter_b, signer_b) = voter("chronology-bravo");
        let set = sample_set(vec![voter_a.clone(), voter_b.clone()], 2);
        let mut ledger = sample_ledger(&set.set_id);
        ledger.entries.push(signed_entry(
            &ledger.ledger_id,
            &set.set_id,
            &voter_a,
            &signer_a,
            0,
        ));
        ledger.entries.push(signed_entry(
            &ledger.ledger_id,
            &set.set_id,
            &voter_b,
            &signer_b,
            1,
        ));

        let error = evaluate_verdict(
            &set,
            &ledger,
            ledger.entries[1].timestamp_ms.saturating_sub(1),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ApprovalError::InvalidVerdictRequest { reason }
                if reason.contains("predates its lineage or a counted vote")
        ));
    }

    #[test]
    fn receipt_pack_verification_detects_tamper() {
        let (voter_a, signer_a) = voter("alpha");
        let (voter_b, signer_b) = voter("bravo");
        let set = sample_set(vec![voter_a.clone(), voter_b.clone()], 2);
        let mut ledger = sample_ledger(&set.set_id);
        ledger.entries.push(signed_entry(
            &ledger.ledger_id,
            &set.set_id,
            &voter_a,
            &signer_a,
            0,
        ));
        ledger.entries.push(signed_entry(
            &ledger.ledger_id,
            &set.set_id,
            &voter_b,
            &signer_b,
            1,
        ));
        let verdict = evaluate_verdict(&set, &ledger, 1_700_000_000_600).unwrap();
        let signer = Ed25519Signer::from_secret_material("receipt-signer");
        let pack = build_receipt_pack(
            &set,
            &ledger,
            &verdict,
            vec!["audit:1".to_string(), "audit:2".to_string()],
            &signer,
            "local-approval-signer",
            1_700_000_000_601,
        )
        .unwrap();

        verify_receipt_pack(&pack).unwrap();

        let mut tampered = pack.clone();
        tampered.audit_refs.push("audit:tampered".to_string());
        assert!(matches!(
            verify_receipt_pack(&tampered),
            Err(ApprovalError::InvalidReceiptPack { .. })
        ));

        let mut predating_verdict = verdict;
        predating_verdict.evaluated_at_ms = ledger.entries[1].timestamp_ms.saturating_sub(1);
        predating_verdict.verdict_id = canonical_approval_verdict_id(&predating_verdict).unwrap();
        let mut predating_pack = pack;
        predating_pack.verdict = predating_verdict;
        let predating_content = ApprovalReceiptPackContentRef {
            signature_version: predating_pack.signature_version,
            signer_id: &predating_pack.signer_id,
            approval_set: &predating_pack.approval_set,
            ledger: &predating_pack.ledger,
            verdict: &predating_pack.verdict,
            audit_refs: &predating_pack.audit_refs,
            created_at_ms: predating_pack.created_at_ms,
        };
        let predating_content_bytes = canonical_json_bytes(&predating_content).unwrap();
        predating_pack.content_hash = sha256_hex(&predating_content_bytes);
        predating_pack.signature = signer.sign(&predating_content_bytes);
        predating_pack.pack_id = canonical_receipt_pack_id(&predating_pack).unwrap();
        assert!(matches!(
            verify_receipt_pack(&predating_pack),
            Err(ApprovalError::InvalidReceiptPack { reason })
                if reason.contains("lineage or timestamps are inconsistent")
        ));
    }

    #[test]
    fn receipt_pack_builder_rejects_creation_before_approval_lineage() {
        let (voter_id, signer) = voter("receipt-lineage-voter");
        let set = sample_set(vec![voter_id.clone()], 1);
        let mut ledger = sample_ledger(&set.set_id);
        ledger.entries.push(signed_entry(
            &ledger.ledger_id,
            &set.set_id,
            &voter_id,
            &signer,
            0,
        ));
        let verdict = evaluate_verdict(&set, &ledger, 1_700_000_000_300).unwrap();
        let pack_signer = Ed25519Signer::from_secret_material("receipt-lineage-pack-signer");

        for created_at_ms in [
            set.created_at_ms.saturating_sub(1),
            ledger.created_at_ms.saturating_sub(1),
            verdict.evaluated_at_ms.saturating_sub(1),
        ] {
            assert!(matches!(
                build_receipt_pack(
                    &set,
                    &ledger,
                    &verdict,
                    vec!["audit:lineage".to_string()],
                    &pack_signer,
                    "receipt-lineage-pack-signer",
                    created_at_ms,
                ),
                Err(ApprovalError::InvalidReceiptPack { reason })
                    if reason.contains("creation timestamp predates")
            ));
        }

        let mut vote_predating_verdict = verdict;
        vote_predating_verdict.evaluated_at_ms = ledger.entries[0].timestamp_ms.saturating_sub(1);
        vote_predating_verdict.verdict_id =
            canonical_approval_verdict_id(&vote_predating_verdict).unwrap();
        assert!(matches!(
            build_receipt_pack(
                &set,
                &ledger,
                &vote_predating_verdict,
                vec!["audit:lineage".to_string()],
                &pack_signer,
                "receipt-lineage-pack-signer",
                1_700_000_000_400,
            ),
            Err(ApprovalError::InvalidReceiptPack { reason })
                if reason.contains("verdict predates a persisted approval vote")
        ));
    }

    #[test]
    fn verdict_and_receipt_pack_stores_round_trip() {
        let dir = TestDir::new("verdict-store");
        let verdict_store = FileApprovalVerdictStore::open(dir.child("approval-verdicts")).unwrap();
        let pack_store =
            FileApprovalReceiptPackStore::open(dir.child("approval-receipt-packs")).unwrap();
        let (voter_a, signer_a) = voter("alpha");
        let (voter_b, signer_b) = voter("bravo");
        let set = sample_set(vec![voter_a.clone(), voter_b.clone()], 2);
        let mut ledger = sample_ledger(&set.set_id);
        ledger.entries.push(signed_entry(
            &ledger.ledger_id,
            &set.set_id,
            &voter_a,
            &signer_a,
            0,
        ));
        ledger.entries.push(signed_entry(
            &ledger.ledger_id,
            &set.set_id,
            &voter_b,
            &signer_b,
            1,
        ));
        let verdict = evaluate_verdict(&set, &ledger, 1_700_000_000_700).unwrap();
        let verdict_record = verdict_store.persist(&verdict).unwrap();
        let loaded_verdict = verdict_store
            .load(&verdict_record.verdict_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded_verdict.report, verdict);
        assert_eq!(verdict_store.list().unwrap().total_count, 1);

        let signer = Ed25519Signer::from_secret_material("receipt-signer");
        let pack = build_receipt_pack(
            &set,
            &ledger,
            &loaded_verdict.report,
            vec!["audit:1".to_string()],
            &signer,
            "local-approval-signer",
            1_700_000_000_701,
        )
        .unwrap();
        let pack_record = pack_store.persist(&pack).unwrap();
        let loaded_pack = pack_store.load(&pack_record.pack_id).unwrap().unwrap();
        assert_eq!(loaded_pack.report, pack);
        assert_eq!(pack_store.list().unwrap().total_count, 1);
    }

    #[test]
    fn harness_creates_and_lists_verdicts() {
        let dir = TestDir::new("approval-harness-verdicts");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_a, signer_a) = voter("alpha");
        let (voter_b, signer_b) = voter("bravo");
        let record = harness
            .create_approval_set(
                vec![voter_a.clone(), voter_b.clone()],
                ThresholdRule::AtLeast { required: 2 },
                "promotion-evidence:test",
            )
            .unwrap();
        harness
            .append_vote(&record.set_id, &voter_a, &signer_a)
            .unwrap();
        harness
            .append_vote(&record.set_id, &voter_b, &signer_b)
            .unwrap();
        let ledger_id = harness
            .list_ledgers(Some(&record.set_id))
            .unwrap()
            .ledgers
            .into_iter()
            .next()
            .unwrap()
            .ledger_id;

        let verdict = harness.create_verdict(&record.set_id, &ledger_id).unwrap();
        assert_eq!(verdict.report.status, ApprovalVerdictStatus::Approved);
        let list = harness.list_verdicts().unwrap();
        assert_eq!(list.total_count, 1);
    }

    #[test]
    fn harness_persists_chronological_verdict_and_receipt_for_authenticated_vote() {
        let dir = TestDir::new("approval-harness-authenticated-chronology");
        let signing_key_env = format!(
            "SWARM_RUNTIME_APPROVAL_BACKWARD_CLOCK_KEY_{}",
            std::process::id()
        );
        let _signing_key = ScopedEnv::set(&signing_key_env, "backward-clock-pack-key");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            dir.child("approval-verdicts"),
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_id, signer) = voter("backward-clock-voter");
        let set = harness
            .create_approval_set(
                vec![voter_id.clone()],
                ThresholdRule::AtLeast { required: 1 },
                "promotion-evidence:backward-clock",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        let empty_ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let vote_timestamp_ms = now_ms();
        let (intent, signature) =
            signed_vote_intent(&empty_ledger.report, &voter_id, &signer, vote_timestamp_ms);
        harness.append_signed_vote(&intent, &signature).unwrap();

        let verdict = harness.create_verdict(&set.set_id, &ledger_id).unwrap();
        assert!(verdict.report.evaluated_at_ms >= vote_timestamp_ms);
        assert_eq!(verdict.report.status, ApprovalVerdictStatus::Approved);
        let pack = harness
            .ensure_approved_receipt_pack(
                &set.set_id,
                &ledger_id,
                "backward-clock-pack-signer",
                &signing_key_env,
            )
            .unwrap();
        assert!(pack.report.created_at_ms >= verdict.report.evaluated_at_ms);
        verify_receipt_pack(&pack.report).unwrap();
    }

    #[test]
    fn harness_persists_only_terminal_verdicts_across_later_votes() {
        let dir = TestDir::new("approval-harness-terminal-verdicts");
        let verdict_root = dir.child("approval-verdicts");
        let harness = DefaultApprovalHarness::from_path(
            dir.child("config-placeholder"),
            &verdict_root,
            dir.child("approval-receipt-packs"),
            dir.child("approval-sets"),
            dir.child("approval-ledgers"),
        )
        .unwrap();
        let (voter_a, signer_a) = voter("terminal-alpha");
        let (voter_b, signer_b) = voter("terminal-bravo");
        let set = harness
            .create_approval_set(
                vec![voter_a.clone(), voter_b.clone()],
                ThresholdRule::AtLeast { required: 2 },
                "promotion-evidence:terminal-only",
            )
            .unwrap();
        let ledger_id = harness.list_ledgers(Some(&set.set_id)).unwrap().ledgers[0]
            .ledger_id
            .clone();
        harness
            .append_vote(&set.set_id, &voter_a, &signer_a)
            .unwrap();
        let before = capture_store_tree(&verdict_root);
        let pending_ledger = harness.load_ledger(&ledger_id).unwrap().unwrap();
        let approval_set = harness.load_approval_set(&set.set_id).unwrap().unwrap();
        let pending =
            evaluate_verdict(&approval_set.report, &pending_ledger.report, now_ms()).unwrap();
        let verdict_store = FileApprovalVerdictStore::open(&verdict_root).unwrap();

        assert!(matches!(
            verdict_store.persist(&pending),
            Err(ApprovalVerdictStoreError::NonTerminalVerdict { verdict_id })
                if verdict_id == pending.verdict_id
        ));
        assert_eq!(capture_store_tree(&verdict_root), before);

        assert!(matches!(
            harness.create_verdict(&set.set_id, &ledger_id),
            Err(ApprovalError::InvalidVerdictRequest { reason })
                if reason.contains("has not reached an approved terminal verdict")
        ));
        assert_eq!(capture_store_tree(&verdict_root), before);
        assert_eq!(harness.list_verdicts().unwrap().total_count, 0);

        harness
            .append_vote(&set.set_id, &voter_b, &signer_b)
            .unwrap();
        let approved = harness.create_verdict(&set.set_id, &ledger_id).unwrap();
        assert_eq!(approved.report.status, ApprovalVerdictStatus::Approved);
        assert_eq!(harness.list_verdicts().unwrap().total_count, 1);
    }
}
