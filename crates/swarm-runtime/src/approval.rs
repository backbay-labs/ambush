use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cmp::Reverse;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_crypto::{
    CryptoError, DetachedSignature, Ed25519Signer, Keypair, canonical_json_bytes, sha256,
    sha256_hex, verify_detached_signature,
};
use swarm_spine::{SpineError, build_signed_envelope, now_rfc3339, verify_envelope};

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
    pub voter_count: usize,
    pub threshold: ThresholdRule,
    pub promotion_evidence_ref: String,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl ApprovalSetRecord {
    fn from_report(report: &ApprovalSetReport, bundle_path: String) -> Self {
        Self {
            set_id: report.set_id.clone(),
            voter_count: report.eligible_voters.len(),
            threshold: report.threshold.clone(),
            promotion_evidence_ref: report.promotion_evidence_ref.clone(),
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// One signed vote entry appended to an approval ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalLedgerEntry {
    pub entry_id: String,
    pub voter_id: String,
    #[serde(default)]
    pub vote: ApprovalVote,
    pub signature: DetachedSignature,
    pub timestamp_ms: i64,
    pub envelope_hash: String,
}

/// Durable approval-ledger artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalLedgerReport {
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
            .filter(|entry| entry.vote.is_approve())
            .map(|entry| entry.voter_id.as_str())
            .collect::<HashSet<_>>();
        let reject_count = ledger
            .entries
            .iter()
            .filter(|entry| !entry.vote.is_approve())
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

/// Operator-facing approval receipt-pack listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalReceiptPackList {
    pub total_count: usize,
    pub packs: Vec<ApprovalReceiptPackRecord>,
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

    #[error("invalid approval verdict request: {reason}")]
    InvalidVerdictRequest { reason: String },

    #[error("invalid approval receipt pack: {reason}")]
    InvalidReceiptPack { reason: String },

    #[error("approval verdict stores are not configured")]
    VerdictStoreNotConfigured,

    #[error("approval receipt-pack stores are not configured")]
    ReceiptPackStoreNotConfigured,

    #[error("signing key env `{env_name}` is missing or empty")]
    MissingSigningKey { env_name: String },

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

#[derive(Debug, Clone)]
struct StoredApprovalLedger {
    record: ApprovalLedgerRecord,
    report: ApprovalLedgerReport,
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

        let record = ApprovalSetRecord::from_report(report, path.display().to_string());
        let mut index = self.read_index()?;
        index.entries.retain(|entry| entry.set_id != record.set_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(&self, set_id: &str) -> Result<Option<ApprovalSetLookup>, ApprovalSetStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .into_iter()
            .find(|entry| entry.set_id == set_id)
        else {
            return Ok(None);
        };
        let report = read_json::<ApprovalSetReport, ApprovalSetStoreError>(
            &self.report_path(set_id),
            |path, source| ApprovalSetStoreError::Read { path, source },
            |path, source| ApprovalSetStoreError::Parse { path, source },
        )?;
        Ok(Some(ApprovalSetLookup { record, report }))
    }

    pub fn list(&self) -> Result<ApprovalSetList, ApprovalSetStoreError> {
        let mut index = self.read_index()?;
        index
            .entries
            .sort_by_key(|entry| Reverse(entry.created_at_ms));
        Ok(ApprovalSetList {
            total_count: index.entries.len(),
            sets: index.entries,
        })
    }
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

    fn load_stored(
        &self,
        ledger_id: &str,
    ) -> Result<Option<StoredApprovalLedger>, ApprovalLedgerStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .into_iter()
            .find(|entry| entry.ledger_id == ledger_id)
        else {
            return Ok(None);
        };
        let report = read_json::<ApprovalLedgerReport, ApprovalLedgerStoreError>(
            &self.report_path(ledger_id),
            |path, source| ApprovalLedgerStoreError::Read { path, source },
            |path, source| ApprovalLedgerStoreError::Parse { path, source },
        )?;
        Ok(Some(StoredApprovalLedger { record, report }))
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
        })
    }
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
        let seed = ApprovalSetIdSeed {
            eligible_voters: eligible_voters.as_slice(),
            threshold: &threshold,
            promotion_evidence_ref,
            created_at_ms,
        };
        let seed_bytes = canonical_json_bytes(&seed)?;
        let set_id = approval_set_id(created_at_ms, &seed_bytes);
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
        let set =
            self.load_approval_set(set_id)?
                .ok_or_else(|| ApprovalError::ApprovalSetNotFound {
                    set_id: set_id.to_string(),
                })?;
        let mut ledger = self.load_stored_ledger_for_set(set_id)?;
        let signature = signer.sign(&vote_payload_bytes(
            &set.report.set_id,
            &ledger.report.ledger_id,
            voter_id,
        )?);
        let timestamp_ms = now_ms();
        let entry_id =
            next_approval_ledger_entry_id(&ledger.report.ledger_id, ledger.report.entries.len());
        let envelope_hash = build_vote_envelope_hash(
            &ledger.report,
            &entry_id,
            voter_id,
            &signature,
            timestamp_ms,
        )?;
        validate_and_append_vote(
            &mut ledger.report,
            &set.report,
            voter_id,
            &signature,
            timestamp_ms,
            &envelope_hash,
        )?;
        let quorum_state =
            ApprovalLedgerQuorumState::from_ledger_and_set(&ledger.report, &set.report);
        self.ledger_store.persist(&ledger.report)?;
        Ok(quorum_state)
    }

    pub fn append_signed_vote(
        &self,
        ledger_id: &str,
        voter_id: &str,
        signature: &DetachedSignature,
    ) -> Result<ApprovalLedgerQuorumState, ApprovalError> {
        let mut ledger =
            self.load_ledger(ledger_id)?
                .ok_or_else(|| ApprovalError::ApprovalLedgerNotFound {
                    ledger_id: ledger_id.to_string(),
                })?;
        let set = self
            .load_approval_set(&ledger.report.approval_set_id)?
            .ok_or_else(|| ApprovalError::ApprovalSetNotFound {
                set_id: ledger.report.approval_set_id.clone(),
            })?;
        let timestamp_ms = now_ms();
        let entry_id =
            next_approval_ledger_entry_id(&ledger.report.ledger_id, ledger.report.entries.len());
        let envelope_hash =
            build_vote_envelope_hash(&ledger.report, &entry_id, voter_id, signature, timestamp_ms)?;
        validate_and_append_vote(
            &mut ledger.report,
            &set.report,
            voter_id,
            signature,
            timestamp_ms,
            &envelope_hash,
        )?;
        let quorum_state =
            ApprovalLedgerQuorumState::from_ledger_and_set(&ledger.report, &set.report);
        self.ledger_store.persist(&ledger.report)?;
        Ok(quorum_state)
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
        let Some(ledger) = self.ledger_store.load_stored(ledger_id)? else {
            return Ok(None);
        };
        let set = self
            .set_store
            .load(&ledger.report.approval_set_id)?
            .ok_or_else(|| ApprovalError::ApprovalSetNotFound {
                set_id: ledger.report.approval_set_id.clone(),
            })?;
        let quorum_state =
            ApprovalLedgerQuorumState::from_ledger_and_set(&ledger.report, &set.report);
        Ok(Some(ApprovalLedgerLookup {
            record: ledger.record,
            report: ledger.report,
            quorum_state,
        }))
    }

    pub fn list_approval_sets(&self) -> Result<ApprovalSetList, ApprovalError> {
        self.set_store.list().map_err(Into::into)
    }

    pub fn list_ledgers(
        &self,
        approval_set_id: Option<&str>,
    ) -> Result<ApprovalLedgerList, ApprovalError> {
        self.ledger_store.list(approval_set_id).map_err(Into::into)
    }

    pub fn create_verdict(
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
        let ledger =
            self.load_ledger(ledger_id)?
                .ok_or_else(|| ApprovalError::ApprovalLedgerNotFound {
                    ledger_id: ledger_id.to_string(),
                })?;
        let report = evaluate_verdict(&set.report, &ledger.report, now_ms())?;
        let record = verdict_store.persist(&report)?;
        Ok(ApprovalVerdictLookup { record, report })
    }

    pub fn load_verdict(
        &self,
        verdict_id: &str,
    ) -> Result<Option<ApprovalVerdictLookup>, ApprovalError> {
        self.verdict_store()?.load(verdict_id).map_err(Into::into)
    }

    pub fn list_verdicts(&self) -> Result<ApprovalVerdictList, ApprovalError> {
        self.verdict_store()?.list().map_err(Into::into)
    }

    pub fn export_receipt_pack(
        &self,
        verdict_id: &str,
        signer_id: &str,
        signing_key_env: &str,
    ) -> Result<ApprovalReceiptPackLookup, ApprovalError> {
        let receipt_pack_store = self.receipt_pack_store()?;
        let verdict = self.load_verdict(verdict_id)?.ok_or_else(|| {
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
            .load_ledger(&verdict.report.ledger_id)?
            .ok_or_else(|| ApprovalError::ApprovalLedgerNotFound {
                ledger_id: verdict.report.ledger_id.clone(),
            })?;
        let secret_material = std::env::var(signing_key_env)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ApprovalError::MissingSigningKey {
                env_name: signing_key_env.to_string(),
            })?;
        let signer = Ed25519Signer::from_secret_material(&secret_material);
        let report = build_receipt_pack(
            &set.report,
            &ledger.report,
            &verdict.report,
            vec![set.report.promotion_evidence_ref.clone()],
            &signer,
            signer_id,
            now_ms(),
        )?;
        let record = receipt_pack_store.persist(&report)?;
        Ok(ApprovalReceiptPackLookup { record, report })
    }

    pub fn load_receipt_pack(
        &self,
        pack_id: &str,
    ) -> Result<Option<ApprovalReceiptPackLookup>, ApprovalError> {
        self.receipt_pack_store()?.load(pack_id).map_err(Into::into)
    }

    pub fn list_receipt_packs(&self) -> Result<ApprovalReceiptPackList, ApprovalError> {
        self.receipt_pack_store()?.list().map_err(Into::into)
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

    fn load_stored_ledger_for_set(
        &self,
        set_id: &str,
    ) -> Result<StoredApprovalLedger, ApprovalError> {
        let ledgers = self.ledger_store.list(Some(set_id))?;
        match ledgers.ledgers.len() {
            0 => Err(ApprovalError::MissingLedgerForSet {
                set_id: set_id.to_string(),
            }),
            1 => {
                let ledger_id = &ledgers.ledgers[0].ledger_id;
                self.ledger_store.load_stored(ledger_id)?.ok_or_else(|| {
                    ApprovalError::ApprovalLedgerNotFound {
                        ledger_id: ledger_id.clone(),
                    }
                })
            }
            count => Err(ApprovalError::AmbiguousLedgerForSet {
                set_id: set_id.to_string(),
                count,
            }),
        }
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
}

pub fn validate_and_append_vote(
    ledger: &mut ApprovalLedgerReport,
    set: &ApprovalSetReport,
    voter_id: &str,
    signature: &DetachedSignature,
    timestamp_ms: i64,
    envelope_hash: &str,
) -> Result<(), ApprovalError> {
    if !set
        .eligible_voters
        .iter()
        .any(|eligible| eligible == voter_id)
    {
        return Err(ApprovalError::IneligibleVoter {
            voter_id: voter_id.to_string(),
        });
    }
    if ledger
        .entries
        .iter()
        .any(|entry| entry.voter_id == voter_id)
    {
        return Err(ApprovalError::DuplicateVoter {
            voter_id: voter_id.to_string(),
        });
    }

    let payload_bytes = vote_payload_bytes(&set.set_id, &ledger.ledger_id, voter_id)?;
    verify_detached_signature(&payload_bytes, signature).map_err(|error| {
        ApprovalError::InvalidSignature {
            voter_id: voter_id.to_string(),
            reason: error.to_string(),
        }
    })?;

    let expected_voter_id = voter_id_from_public_key(&signature.public_key_hex);
    if voter_id != expected_voter_id {
        return Err(ApprovalError::InvalidSignature {
            voter_id: voter_id.to_string(),
            reason: format!(
                "signature public key resolves to `{expected_voter_id}` instead of requested voter"
            ),
        });
    }

    ledger.entries.push(ApprovalLedgerEntry {
        entry_id: next_approval_ledger_entry_id(&ledger.ledger_id, ledger.entries.len()),
        voter_id: voter_id.to_string(),
        vote: ApprovalVote::Approve,
        signature: signature.clone(),
        timestamp_ms,
        envelope_hash: envelope_hash.to_string(),
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
    let seed = ApprovalVerdictIdSeed {
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
    let content = ApprovalReceiptPackContentRef {
        approval_set,
        ledger,
        verdict,
        audit_refs: audit_refs.as_slice(),
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

pub fn verify_receipt_pack(pack: &ApprovalReceiptPackReport) -> Result<(), ApprovalError> {
    let content = ApprovalReceiptPackContentRef {
        approval_set: &pack.approval_set,
        ledger: &pack.ledger,
        verdict: &pack.verdict,
        audit_refs: pack.audit_refs.as_slice(),
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
            format!(
                "  - {} at {} [{}]",
                entry.voter_id, entry.timestamp_ms, entry.entry_id
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
        return lines.join("\n");
    }

    lines.extend(list.packs.iter().map(|record| {
        format!(
            "- {} verdict={} set={} created={}",
            record.pack_id, record.verdict_id, record.approval_set_id, record.created_at_ms
        )
    }));
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
struct ApprovalVoteSignaturePayload<'a> {
    approval_set_id: &'a str,
    ledger_id: &'a str,
    voter_id: &'a str,
}

#[derive(Serialize)]
struct ApprovalVerdictIdSeed<'a> {
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
    approval_set: &'a ApprovalSetReport,
    ledger: &'a ApprovalLedgerReport,
    verdict: &'a ApprovalVerdictReport,
    audit_refs: &'a [String],
}

fn approval_set_id(created_at_ms: i64, seed_bytes: &[u8]) -> String {
    let digest = sha256_hex(seed_bytes);
    format!("approval-set:{created_at_ms}:{}", &digest[..12])
}

fn approval_ledger_id(set_id: &str, created_at_ms: i64) -> String {
    let digest = sha256_hex(set_id.as_bytes());
    format!("approval-ledger:{created_at_ms}:{}", &digest[..12])
}

fn approval_verdict_id(created_at_ms: i64, seed_bytes: &[u8]) -> String {
    let digest = sha256_hex(seed_bytes);
    format!("approval-verdict:{created_at_ms}:{}", &digest[..12])
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

fn vote_payload_bytes(
    approval_set_id: &str,
    ledger_id: &str,
    voter_id: &str,
) -> Result<Vec<u8>, ApprovalError> {
    canonical_json_bytes(&ApprovalVoteSignaturePayload {
        approval_set_id,
        ledger_id,
        voter_id,
    })
    .map_err(Into::into)
}

fn build_vote_envelope_hash(
    ledger: &ApprovalLedgerReport,
    entry_id: &str,
    voter_id: &str,
    signature: &DetachedSignature,
    timestamp_ms: i64,
) -> Result<String, ApprovalError> {
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
        now_rfc3339(),
    )?;

    if !verify_envelope(&envelope)? {
        return Err(ApprovalError::InvalidSignature {
            voter_id: voter_id.to_string(),
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

    fn voter(secret: &str) -> (String, Ed25519Signer) {
        let signer = Ed25519Signer::from_secret_material(secret);
        (format!("swarm:ed25519:{}", signer.public_key_hex()), signer)
    }

    fn sample_set(voter_ids: Vec<String>, required: usize) -> ApprovalSetReport {
        ApprovalSetReport {
            set_id: "approval-set:test".to_string(),
            eligible_voters: voter_ids,
            threshold: ThresholdRule::AtLeast { required },
            promotion_evidence_ref: "promotion-evidence:test".to_string(),
            created_at_ms: 1_700_000_000_000,
        }
    }

    fn sample_ledger(set_id: &str) -> ApprovalLedgerReport {
        ApprovalLedgerReport {
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
        let signature = signer.sign(&vote_payload_bytes(set_id, ledger_id, voter_id).unwrap());
        ApprovalLedgerEntry {
            entry_id: next_approval_ledger_entry_id(ledger_id, index),
            voter_id: voter_id.to_string(),
            vote,
            signature,
            timestamp_ms: 1_700_000_000_200 + index as i64,
            envelope_hash: format!("0xhash{:02}", index + 1),
        }
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
        let signature =
            signer.sign(&vote_payload_bytes(&set.set_id, &ledger.ledger_id, &voter_id).unwrap());

        validate_and_append_vote(
            &mut ledger,
            &set,
            &voter_id,
            &signature,
            1_700_000_000_300,
            "0xenvelopehash",
        )
        .unwrap();

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
        let signature = signer.sign(
            &vote_payload_bytes(&set_record.set_id, &ledger.report.ledger_id, &voter_id)
                .expect("payload bytes"),
        );

        let quorum_state = harness
            .append_signed_vote(&ledger.report.ledger_id, &voter_id, &signature)
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
    fn validate_and_append_vote_rejects_duplicate_voter() {
        let (voter_id, signer) = voter("alpha");
        let set = sample_set(vec![voter_id.clone()], 1);
        let mut ledger = sample_ledger(&set.set_id);
        let signature =
            signer.sign(&vote_payload_bytes(&set.set_id, &ledger.ledger_id, &voter_id).unwrap());
        validate_and_append_vote(
            &mut ledger,
            &set,
            &voter_id,
            &signature,
            1_700_000_000_300,
            "0xfirst",
        )
        .unwrap();

        let error = validate_and_append_vote(
            &mut ledger,
            &set,
            &voter_id,
            &signature,
            1_700_000_000_301,
            "0xsecond",
        )
        .unwrap_err();
        assert!(matches!(error, ApprovalError::DuplicateVoter { .. }));
    }

    #[test]
    fn validate_and_append_vote_rejects_ineligible_voter() {
        let (eligible_voter, _) = voter("eligible");
        let (ineligible_voter, signer) = voter("ineligible");
        let set = sample_set(vec![eligible_voter], 1);
        let mut ledger = sample_ledger(&set.set_id);
        let signature = signer
            .sign(&vote_payload_bytes(&set.set_id, &ledger.ledger_id, &ineligible_voter).unwrap());

        let error = validate_and_append_vote(
            &mut ledger,
            &set,
            &ineligible_voter,
            &signature,
            1_700_000_000_300,
            "0xhash",
        )
        .unwrap_err();
        assert!(matches!(error, ApprovalError::IneligibleVoter { .. }));
    }

    #[test]
    fn validate_and_append_vote_rejects_invalid_signature() {
        let (voter_id, _) = voter("eligible");
        let (_, wrong_signer) = voter("wrong");
        let set = sample_set(vec![voter_id.clone()], 1);
        let mut ledger = sample_ledger(&set.set_id);
        let signature = wrong_signer
            .sign(&vote_payload_bytes(&set.set_id, &ledger.ledger_id, &voter_id).unwrap());

        let error = validate_and_append_vote(
            &mut ledger,
            &set,
            &voter_id,
            &signature,
            1_700_000_000_300,
            "0xhash",
        )
        .unwrap_err();
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
}
