//! Enabled-runtime composition for collective hypothesis reasoning.
//!
//! Critical-path detection and replay persistence happen before this service
//! is invoked. Graph failures are therefore visible degradation of the
//! reasoning lane; they never roll back a persisted detection or grant
//! response authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};
use swarm_core::ThreatIntelEntry;
use swarm_core::config::{BundleStoreConfig, HypothesisGraphConfig};
use swarm_core::hypothesis_graph::{
    AssetNode, CausalEdge, CausalRelation, DecisionKind, DecisionRecord, EdgeState, EvidenceId,
    EvidenceScope, GraphAdmissionError, GraphId, GraphLogicalTime, GraphNode, GraphNodeId,
    GraphProducerRole, Hypothesis, HypothesisDelta, HypothesisId, HypothesisStatus, MemoryOutcome,
    MemoryProvenance, SchedulerBudget, StrategyMemory, StrategyMemoryExpiryEnvelope,
    TaskCapabilityProof, TaskClaimRequest, TaskCompletion, TaskCompletionKind, TaskDecisionLink,
    TaskId, TaskKind, TaskRecord, TaskState, TaskTarget, TaskTerminalEnvelope,
};
use swarm_core::types::AgentId;
use swarm_crypto::{
    DetachedSignature, Keypair, canonical_json_bytes, sha256_hex, verify_detached_signature,
};
use swarm_spine::hypothesis_graph_store::{
    ConfiguredHypothesisGraphStore, GRAPH_STATE_MIGRATION_HYPOTHESES, GRAPH_STATE_MIGRATION_LEGACY,
    GraphStoreError, GraphStoreSnapshot, GraphStoreState, HypothesisGraphStore,
    ReasoningStateUpdate,
};
use swarm_spine::{
    FileStrategyMemoryStore, MemoryStrategyMemoryStore, ReplayBundle, StrategyMemoryRecord,
    StrategyMemoryStore, StrategyMemoryStoreError,
};

use super::clock::FixedGraphClock;
use super::hypotheses::{
    HypothesisDisposition, HypothesisSeedAssessment, HypothesisSeedInput, coordination_task_targets,
};
use super::inference::{InferredCausalRelation, infer_causal_relations};
use super::memory::{MemoryPriorityProjection, MemoryProjectionReport, StrategyMemoryProjector};
use super::normalize::{
    normalize_telemetry_event_for_graph, normalize_threat_intel_entry_for_graph,
};
use super::tasks::GraphSeedRecords;
use super::{DurableHypothesisCoordinator, KeypairGraphRecordSigner, TaskClaim, WitnessAdmission};
use crate::detection::metrics::CriticalPathMetrics;

const GRAPH_LEASE_MS: u64 = 30_000;
const CAMPAIGN_HEAD_SCHEMA_VERSION: u32 = 1;
const CAMPAIGN_HEAD_STATE_KIND: &str = "collective-hypothesis-campaign-head";
const CAMPAIGN_HEAD_FILE: &str = "campaign-head.json";
const MAX_CAMPAIGN_HEAD_BYTES: u64 = 64 * 1024;
const MAX_REPLAY_THREAT_INTEL_MATCHES: usize = 64;
static NEXT_CAMPAIGN_HEAD_TEMP: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
const CAMPAIGN_HEAD_O_NOFOLLOW: i32 = 0x20000;
#[cfg(target_os = "macos")]
const CAMPAIGN_HEAD_O_NOFOLLOW: i32 = 0x100;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const CAMPAIGN_HEAD_O_NOFOLLOW: i32 = 0;

#[derive(Debug, thiserror::Error)]
pub enum GraphServiceError {
    #[error(transparent)]
    Admission(#[from] GraphAdmissionError),

    #[error(transparent)]
    Store(#[from] GraphStoreError),

    #[error(transparent)]
    Memory(#[from] StrategyMemoryStoreError),

    #[error("collective hypothesis service mutex poisoned")]
    Poisoned,

    #[error(
        "an enabled shipped collective hypothesis service requires a durable local-files store"
    )]
    NonDurableEnabledStore,

    #[error("worker lacks the required `{0:?}` graph capability")]
    MissingCapability(TaskKind),

    #[error("no worker identity is registered for `{0:?}` graph tasks")]
    MissingWorkerRegistration(TaskKind),

    #[error("a graph worker must register at least one capability")]
    EmptyWorkerCapabilities,

    #[error(
        "graph capability `{kind:?}` is already bound to `{existing}` and cannot be rebound to `{observed}`"
    )]
    WorkerCapabilityConflict {
        kind: TaskKind,
        existing: AgentId,
        observed: AgentId,
    },

    #[error("graph worker identity `{observed}` does not match agent identity `{expected}`")]
    WorkerIdentityMismatch {
        expected: AgentId,
        observed: AgentId,
    },

    #[error("graph task `{0}` is not available for this worker")]
    TaskUnavailable(TaskId),

    #[error("graph `{observed}` does not match configured graph `{expected}`")]
    GraphMismatch {
        expected: GraphId,
        observed: GraphId,
    },

    #[error("graph collection cursor does not identify a retained campaign")]
    InvalidCollectionCursor,

    #[error(
        "graph campaign `{graph_id}` reached capacity with {outstanding_tasks} outstanding tasks"
    )]
    CampaignRotationBlocked {
        graph_id: GraphId,
        outstanding_tasks: usize,
    },

    #[error("graph campaign index exhausted")]
    CampaignIndexExhausted,

    #[error("invalid graph campaign entry `{path}`")]
    InvalidCampaignEntry { path: PathBuf },

    #[error("graph campaign high-water head is missing at `{path}`")]
    MissingCampaignHead { path: PathBuf },

    #[error("graph campaign high-water head is invalid at `{path}`: {reason}")]
    InvalidCampaignHead { path: PathBuf, reason: String },

    #[error(
        "graph campaign set does not match authenticated high-water {latest_index}: observed {observed_indexes:?}"
    )]
    CampaignIndexMismatch {
        latest_index: u64,
        observed_indexes: Vec<u64>,
    },

    #[error("graph campaign I/O failed at `{path}`: {source}")]
    CampaignIo {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSubmission {
    pub graph_id: GraphId,
    pub evidence_id: EvidenceId,
    pub hypothesis_ids: Vec<HypothesisId>,
    pub task_ids: Vec<TaskId>,
    pub generation: u64,
    pub idempotent: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphServiceMetricsSnapshot {
    pub submissions: u64,
    pub submission_failures: u64,
    pub completed_acquisitions: u64,
    pub completed_challenges: u64,
    pub completed_falsifications: u64,
    pub falsification_no_findings: u64,
    pub memory_records_projected: u64,
    pub memory_projection_failures: u64,
    pub campaign_rotations: u64,
}

#[derive(Debug, Clone, Default)]
struct GraphServiceMetrics {
    snapshot: GraphServiceMetricsSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphOperatorProjection {
    pub graph_id: GraphId,
    pub generation: u64,
    pub digest: String,
    pub graph: swarm_core::hypothesis_graph::HypothesisGraph,
    pub hypotheses: BTreeMap<HypothesisId, Hypothesis>,
    pub tasks: Vec<TaskRecord>,
    pub terminal_publications: usize,
    pub memory: Vec<StrategyMemoryRecord>,
    pub logical_time_high_water: GraphLogicalTime,
    pub metrics: GraphServiceMetricsSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSummaryProjection {
    pub graph_id: GraphId,
    pub generation: u64,
    pub graph_version: u64,
    pub evidence_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub contradiction_count: usize,
    pub hypothesis_count: usize,
    pub pending_task_count: usize,
    pub completed_task_count: usize,
    pub memory_count: usize,
    pub logical_time_high_water: GraphLogicalTime,
    pub metrics: GraphServiceMetricsSnapshot,
}

struct CollectiveHypothesisState {
    coordinator: DurableHypothesisCoordinator,
    metrics: GraphServiceMetrics,
    /// Authenticated evidence directory rebuilt from durable campaign
    /// snapshots at startup and updated immediately after each graph commit.
    /// Replay admission can therefore locate one archived campaign without
    /// opening every retained graph on the hot path.
    evidence_campaigns: BTreeMap<EvidenceId, u64>,
    worker_claimants: BTreeMap<TaskKind, AgentId>,
    pending_worker_publications: BTreeMap<(u64, TaskId), PendingWorkerPublication>,
    pending_stalker_acquisition_hunts: BTreeSet<String>,
    pending_stalker_falsification_hunts: BTreeSet<String>,
    /// Campaign index to the last failure epoch observed for that projection.
    /// The epoch prevents a successful repair of an older snapshot from
    /// clearing a concurrent failure for a later committed terminal.
    dirty_memory_campaigns: BTreeMap<u64, u64>,
    memory_projection_failure_epoch: u64,
}

#[derive(Clone)]
struct HypothesisCampaign {
    index: u64,
    graph_id: GraphId,
    store: Arc<dyn HypothesisGraphStore>,
    memory: StrategyMemoryProjector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingWorkerPublication {
    campaign_index: u64,
    graph_id: GraphId,
    task_id: TaskId,
    hunt_id: String,
    task_kind: TaskKind,
    completion_kind: TaskCompletionKind,
    evidence_ids: BTreeSet<EvidenceId>,
    retry_exhaustion_failure_summary: Option<String>,
}

struct CampaignRegistry {
    campaigns: Vec<HypothesisCampaign>,
}

impl CampaignRegistry {
    fn active(&self) -> Option<&HypothesisCampaign> {
        self.campaigns.last()
    }

    fn find(&self, graph_id: &GraphId) -> Option<&HypothesisCampaign> {
        self.campaigns
            .iter()
            .find(|campaign| &campaign.graph_id == graph_id)
    }
}

pub struct CollectiveHypothesisService {
    config: HypothesisGraphConfig,
    campaigns: RwLock<CampaignRegistry>,
    campaign_root: Option<PathBuf>,
    replay_consumer_graph_id: GraphId,
    active_campaign_index: AtomicU64,
    signer: Keypair,
    /// Serialize shipped graph mutations across replay admission and worker
    /// terminal publication. The durable store remains the final CAS/fencing
    /// authority; this guard prevents a newer replay from advancing logical
    /// high-water between a worker's time clamp and its signed terminal.
    operation: Mutex<()>,
    state: Mutex<CollectiveHypothesisState>,
    prometheus: Option<CriticalPathMetrics>,
}

/// Promote a freshly created or authenticated legacy graph envelope before
/// the service accepts replay work. The promotion changes no graph content;
/// it only installs the current reasoning marker and config-bound scheduler
/// budget. Every later replay can therefore publish graph records,
/// hypotheses, and tasks through one ordinary CAS.
fn initialize_reasoning_store(
    store: &dyn HypothesisGraphStore,
    config: &HypothesisGraphConfig,
) -> Result<GraphStoreSnapshot, GraphServiceError> {
    let initial = store.snapshot()?;
    if initial.state().migration_marker == GRAPH_STATE_MIGRATION_HYPOTHESES {
        return Ok(initial);
    }
    if initial.state().migration_marker != GRAPH_STATE_MIGRATION_LEGACY {
        return Err(GraphStoreError::InvalidState {
            reason: "unsupported hypothesis graph reasoning migration marker".to_string(),
        }
        .into());
    }
    let scheduler_budget =
        SchedulerBudget::new_with_config(config, initial.state().logical_time_high_water)?;
    let update = ReasoningStateUpdate::migration_to_hypotheses(
        config.resource_limits(),
        initial.state().logical_time_high_water,
    )
    .with_scheduler_budget(scheduler_budget);
    let mut candidate = GraphStoreState::with_reasoning_state(initial.state().clone(), update)?;
    candidate.generation = initial.revision().generation;
    candidate.predecessor_digest = initial.state().predecessor_digest.clone();
    Ok(store.compare_and_swap(initial.revision(), candidate)?)
}

fn open_campaign(
    index: u64,
    config: &HypothesisGraphConfig,
    signer: &Keypair,
    graph_root: Option<&Path>,
    memory_root: Option<&Path>,
) -> Result<HypothesisCampaign, GraphServiceError> {
    let graph_id = graph_id_for_campaign(signer, index);
    let graph = swarm_core::hypothesis_graph::HypothesisGraph::new(
        graph_id.clone(),
        config.resource_limits(),
    )?;
    let (store, memory_store): (Arc<dyn HypothesisGraphStore>, Arc<dyn StrategyMemoryStore>) =
        match (graph_root, memory_root) {
            (Some(graph_root), Some(memory_root)) => (
                Arc::new(ConfiguredHypothesisGraphStore::local_files_with_config(
                    graph_root,
                    graph,
                    signer.clone(),
                    config,
                )?),
                Arc::new(FileStrategyMemoryStore::new_with_config(
                    memory_root,
                    signer.clone(),
                    config,
                )?),
            ),
            (None, None) => (
                Arc::new(ConfiguredHypothesisGraphStore::memory_with_config(
                    graph,
                    signer.clone(),
                    config,
                )?),
                Arc::new(MemoryStrategyMemoryStore::new_with_config(
                    signer.clone(),
                    config,
                )?),
            ),
            _ => {
                return Err(GraphStoreError::InvalidState {
                    reason: "graph and memory campaign backends must use the same durability mode"
                        .to_string(),
                }
                .into());
            }
        };
    initialize_reasoning_store(store.as_ref(), config)?;
    Ok(HypothesisCampaign {
        index,
        graph_id,
        store,
        memory: StrategyMemoryProjector::new(memory_store),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedCampaignHead {
    schema_version: u32,
    state_kind: String,
    stream_id: String,
    latest_index: u64,
    signature: DetachedSignature,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CampaignHeadSigningMaterial<'a> {
    schema_version: u32,
    state_kind: &'a str,
    stream_id: &'a str,
    latest_index: u64,
}

fn campaign_head_stream_id(root: &Path, signer: &Keypair) -> Result<String, GraphServiceError> {
    let canonical_root =
        fs::canonicalize(root).map_err(|source| GraphServiceError::CampaignIo {
            path: root.to_path_buf(),
            source,
        })?;
    Ok(format!(
        "{}:{}",
        graph_id_for_campaign(signer, 0),
        sha256_hex(canonical_root.to_string_lossy().as_bytes())
    ))
}

fn sign_campaign_head(
    root: &Path,
    signer: &Keypair,
    latest_index: u64,
) -> Result<SignedCampaignHead, GraphServiceError> {
    let stream_id = campaign_head_stream_id(root, signer)?;
    let material = CampaignHeadSigningMaterial {
        schema_version: CAMPAIGN_HEAD_SCHEMA_VERSION,
        state_kind: CAMPAIGN_HEAD_STATE_KIND,
        stream_id: &stream_id,
        latest_index,
    };
    let bytes = canonical_json_bytes(&material).map_err(|error| {
        GraphServiceError::InvalidCampaignHead {
            path: PathBuf::from(CAMPAIGN_HEAD_FILE),
            reason: error.to_string(),
        }
    })?;
    Ok(SignedCampaignHead {
        schema_version: CAMPAIGN_HEAD_SCHEMA_VERSION,
        state_kind: CAMPAIGN_HEAD_STATE_KIND.to_string(),
        stream_id,
        latest_index,
        signature: DetachedSignature {
            algorithm: "ed25519".to_string(),
            key_id: sha256_hex(signer.public_key().as_bytes()),
            public_key_hex: signer.public_key().to_hex(),
            signature_hex: signer.sign(&bytes).to_hex(),
        },
    })
}

fn verify_campaign_head(
    root: &Path,
    path: &Path,
    head: &SignedCampaignHead,
    signer: &Keypair,
) -> Result<(), GraphServiceError> {
    let expected_stream_id = campaign_head_stream_id(root, signer)?;
    if head.schema_version != CAMPAIGN_HEAD_SCHEMA_VERSION
        || head.state_kind != CAMPAIGN_HEAD_STATE_KIND
        || head.stream_id != expected_stream_id
    {
        return Err(GraphServiceError::InvalidCampaignHead {
            path: path.to_path_buf(),
            reason: "schema, state kind, or stream identity mismatch".to_string(),
        });
    }
    let material = CampaignHeadSigningMaterial {
        schema_version: head.schema_version,
        state_kind: &head.state_kind,
        stream_id: &head.stream_id,
        latest_index: head.latest_index,
    };
    let bytes = canonical_json_bytes(&material).map_err(|error| {
        GraphServiceError::InvalidCampaignHead {
            path: path.to_path_buf(),
            reason: error.to_string(),
        }
    })?;
    verify_detached_signature(&bytes, &head.signature).map_err(|error| {
        GraphServiceError::InvalidCampaignHead {
            path: path.to_path_buf(),
            reason: error.to_string(),
        }
    })?;
    let expected_signer = AgentId::from_public_key_hex(&signer.public_key().to_hex());
    let observed_signer = AgentId::from_public_key_hex(&head.signature.public_key_hex);
    if observed_signer != expected_signer {
        return Err(GraphServiceError::InvalidCampaignHead {
            path: path.to_path_buf(),
            reason: format!(
                "signer mismatch: expected `{expected_signer}`, observed `{observed_signer}`"
            ),
        });
    }
    Ok(())
}

fn load_campaign_head(
    path: &Path,
    signer: &Keypair,
) -> Result<SignedCampaignHead, GraphServiceError> {
    let root = path
        .parent()
        .ok_or_else(|| GraphServiceError::InvalidCampaignHead {
            path: path.to_path_buf(),
            reason: "campaign head has no state-store parent".to_string(),
        })?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(CAMPAIGN_HEAD_O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|source| GraphServiceError::CampaignIo {
            path: path.to_path_buf(),
            source,
        })?;
    let descriptor_metadata = file
        .metadata()
        .map_err(|source| GraphServiceError::CampaignIo {
            path: path.to_path_buf(),
            source,
        })?;
    let named_metadata =
        fs::symlink_metadata(path).map_err(|source| GraphServiceError::CampaignIo {
            path: path.to_path_buf(),
            source,
        })?;
    let descriptor_identity = campaign_head_file_identity(&descriptor_metadata);
    if !descriptor_metadata.file_type().is_file()
        || !named_metadata.file_type().is_file()
        || descriptor_identity != campaign_head_file_identity(&named_metadata)
    {
        return Err(GraphServiceError::InvalidCampaignHead {
            path: path.to_path_buf(),
            reason: "head must remain bound to one regular non-symlink file".to_string(),
        });
    }
    if descriptor_metadata.len() > MAX_CAMPAIGN_HEAD_BYTES {
        return Err(GraphServiceError::InvalidCampaignHead {
            path: path.to_path_buf(),
            reason: format!("head exceeds the {MAX_CAMPAIGN_HEAD_BYTES}-byte persistence limit"),
        });
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_CAMPAIGN_HEAD_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| GraphServiceError::CampaignIo {
            path: path.to_path_buf(),
            source,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CAMPAIGN_HEAD_BYTES {
        return Err(GraphServiceError::InvalidCampaignHead {
            path: path.to_path_buf(),
            reason: format!("head exceeds the {MAX_CAMPAIGN_HEAD_BYTES}-byte persistence limit"),
        });
    }
    let final_named_metadata =
        fs::symlink_metadata(path).map_err(|source| GraphServiceError::CampaignIo {
            path: path.to_path_buf(),
            source,
        })?;
    if !final_named_metadata.file_type().is_file()
        || descriptor_identity != campaign_head_file_identity(&final_named_metadata)
    {
        return Err(GraphServiceError::InvalidCampaignHead {
            path: path.to_path_buf(),
            reason: "head path changed while it was being authenticated".to_string(),
        });
    }
    let head: SignedCampaignHead =
        serde_json::from_slice(&bytes).map_err(|error| GraphServiceError::InvalidCampaignHead {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    verify_campaign_head(root, path, &head, signer)?;
    Ok(head)
}

#[cfg(unix)]
fn campaign_head_file_identity(metadata: &fs::Metadata) -> String {
    format!("unix:{}:{}", metadata.dev(), metadata.ino())
}

#[cfg(windows)]
fn campaign_head_file_identity(metadata: &fs::Metadata) -> String {
    format!(
        "windows:{}:{}",
        metadata.volume_serial_number().unwrap_or_default(),
        metadata.file_index().unwrap_or_default()
    )
}

#[cfg(not(any(unix, windows)))]
fn campaign_head_file_identity(metadata: &fs::Metadata) -> String {
    format!("other:{}:{:?}", metadata.len(), metadata.modified().ok())
}

fn persist_campaign_head(
    root: &Path,
    signer: &Keypair,
    latest_index: u64,
) -> Result<(), GraphServiceError> {
    fs::create_dir_all(root).map_err(|source| GraphServiceError::CampaignIo {
        path: root.to_path_buf(),
        source,
    })?;
    let path = root.join(CAMPAIGN_HEAD_FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(GraphServiceError::InvalidCampaignHead {
                    path,
                    reason: "head must be a regular non-symlink file".to_string(),
                });
            }
            let current = load_campaign_head(&path, signer)?;
            let advances_once = current.latest_index.checked_add(1) == Some(latest_index);
            if current.latest_index != latest_index && !advances_once {
                return Err(GraphServiceError::InvalidCampaignHead {
                    path,
                    reason: format!(
                        "campaign high-water must remain at {} or advance exactly once, observed {latest_index}",
                        current.latest_index
                    ),
                });
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(GraphServiceError::CampaignIo {
                path: path.clone(),
                source,
            });
        }
    }
    let head = sign_campaign_head(root, signer, latest_index)?;
    let bytes =
        serde_json::to_vec(&head).map_err(|error| GraphServiceError::InvalidCampaignHead {
            path: path.clone(),
            reason: error.to_string(),
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CAMPAIGN_HEAD_BYTES {
        return Err(GraphServiceError::InvalidCampaignHead {
            path,
            reason: format!("head exceeds the {MAX_CAMPAIGN_HEAD_BYTES}-byte persistence limit"),
        });
    }
    let (temp_path, mut file) = loop {
        let nonce = NEXT_CAMPAIGN_HEAD_TEMP.fetch_add(1, Ordering::Relaxed);
        let candidate = root.join(format!(
            ".{CAMPAIGN_HEAD_FILE}.tmp-{}-{nonce}",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => break (candidate, file),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(GraphServiceError::CampaignIo {
                    path: candidate,
                    source,
                });
            }
        }
    };
    let write_result = (|| -> Result<(), io::Error> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp_path, &path)?;
        fs::File::open(root)?.sync_all()?;
        Ok(())
    })();
    if let Err(source) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(GraphServiceError::CampaignIo { path, source });
    }
    let persisted = load_campaign_head(&path, signer)?;
    if persisted.latest_index != latest_index {
        return Err(GraphServiceError::InvalidCampaignHead {
            path,
            reason: format!(
                "post-commit campaign high-water mismatch: expected {latest_index}, observed {}",
                persisted.latest_index
            ),
        });
    }
    Ok(())
}

fn validate_campaign_indexes(
    latest_index: u64,
    indexes: &[u64],
) -> Result<Option<u64>, GraphServiceError> {
    let committed_len =
        usize::try_from(latest_index).map_err(|_| GraphServiceError::CampaignIndexMismatch {
            latest_index,
            observed_indexes: indexes.to_vec(),
        })?;
    let committed_contiguous = indexes.len() >= committed_len
        && indexes[..committed_len]
            .iter()
            .copied()
            .enumerate()
            .all(|(offset, index)| {
                u64::try_from(offset)
                    .ok()
                    .and_then(|value| value.checked_add(1))
                    == Some(index)
            });
    let trailing = match indexes.get(committed_len..).unwrap_or_default() {
        [] => None,
        [index] if latest_index.checked_add(1) == Some(*index) => Some(*index),
        _ => {
            return Err(GraphServiceError::CampaignIndexMismatch {
                latest_index,
                observed_indexes: indexes.to_vec(),
            });
        }
    };
    if !committed_contiguous {
        return Err(GraphServiceError::CampaignIndexMismatch {
            latest_index,
            observed_indexes: indexes.to_vec(),
        });
    }
    Ok(trailing)
}

fn validate_unactivated_campaign(
    campaign: &HypothesisCampaign,
    campaign_directory: &Path,
    config: &HypothesisGraphConfig,
) -> Result<(), GraphServiceError> {
    let snapshot = campaign.store.snapshot()?;
    let state = snapshot.state();
    let graph = snapshot.graph();
    let expected_budget = SchedulerBudget::new_with_config(config, GraphLogicalTime::new(0))?;
    let pristine = snapshot.revision().generation == 1
        && state.generation == 1
        && state
            .predecessor_digest
            .as_deref()
            .is_some_and(|digest| !digest.is_empty())
        && state.migration_marker == GRAPH_STATE_MIGRATION_HYPOTHESES
        && state.scheduler_budget.as_ref() == Some(&expected_budget)
        && state.logical_time_high_water == GraphLogicalTime::new(0)
        && graph.version == 0
        && graph.nodes.is_empty()
        && graph.evidence.is_empty()
        && graph.edges.is_empty()
        && graph.contradictions.is_empty()
        && graph.conflicts.is_empty()
        && state.hypotheses.is_empty()
        && state.tasks.is_empty()
        && state.logical_task_descriptors.is_empty()
        && state.task_tombstones.is_empty()
        && state.terminal_outbox.is_empty()
        && state.fencing_counter == 0
        && state.cross_graph_links.is_empty()
        && state.result_projection_digest.is_none()
        && state.operator_projection_digest.is_none()
        && campaign
            .memory
            .store()
            .list(1)
            .map_err(GraphServiceError::Memory)?
            .is_empty();
    if !pristine {
        return Err(GraphServiceError::InvalidCampaignEntry {
            path: campaign_directory.to_path_buf(),
        });
    }
    Ok(())
}

fn load_campaigns(
    config: &HypothesisGraphConfig,
    signer: &Keypair,
) -> Result<(Vec<HypothesisCampaign>, Option<PathBuf>), GraphServiceError> {
    match &config.state_store {
        BundleStoreConfig::Memory => {
            Ok((vec![open_campaign(0, config, signer, None, None)?], None))
        }
        BundleStoreConfig::LocalFiles { directory } => {
            let root = Path::new(directory);
            let campaign_root = root.join("campaigns");
            let mut indexes = Vec::new();
            match fs::read_dir(&campaign_root) {
                Ok(entries) => {
                    for entry in entries {
                        let entry = entry.map_err(|source| GraphServiceError::CampaignIo {
                            path: campaign_root.clone(),
                            source,
                        })?;
                        let path = entry.path();
                        let file_type =
                            entry
                                .file_type()
                                .map_err(|source| GraphServiceError::CampaignIo {
                                    path: path.clone(),
                                    source,
                                })?;
                        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                            return Err(GraphServiceError::InvalidCampaignEntry { path });
                        };
                        let Ok(index) = name.parse::<u64>() else {
                            return Err(GraphServiceError::InvalidCampaignEntry { path });
                        };
                        if index == 0
                            || name != index.to_string()
                            || !file_type.is_dir()
                            || file_type.is_symlink()
                        {
                            return Err(GraphServiceError::InvalidCampaignEntry { path });
                        }
                        indexes.push(index);
                    }
                }
                Err(source) if source.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(GraphServiceError::CampaignIo {
                        path: campaign_root.clone(),
                        source,
                    });
                }
            }
            indexes.sort_unstable();
            let head_path = root.join(CAMPAIGN_HEAD_FILE);
            let initial_store_exists = fs::symlink_metadata(root.join("graph")).is_ok()
                || fs::symlink_metadata(root.join("strategy-memory")).is_ok();
            let head = match fs::symlink_metadata(&head_path) {
                Ok(_) => Some(load_campaign_head(&head_path, signer)?),
                Err(source) if source.kind() == io::ErrorKind::NotFound => {
                    if !indexes.is_empty() {
                        return Err(GraphServiceError::MissingCampaignHead { path: head_path });
                    }
                    None
                }
                Err(source) => {
                    return Err(GraphServiceError::CampaignIo {
                        path: head_path,
                        source,
                    });
                }
            };
            let latest_index = head.as_ref().map_or(0, |head| head.latest_index);
            let unactivated_index = validate_campaign_indexes(latest_index, &indexes)?;

            let mut campaigns = vec![open_campaign(
                0,
                config,
                signer,
                Some(&root.join("graph")),
                Some(&root.join("strategy-memory")),
            )?];
            if head.is_none() {
                // Initial activation has the same crash window as campaign
                // rotation: opening the durable stores can commit generation
                // one before the signed head is installed.  An unheaded base
                // store is recoverable only when the complete graph and
                // strategy-memory pair authenticates as pristine.  This
                // rejects populated, partially reused, or tampered state while
                // allowing the interrupted first activation to finish.
                if initial_store_exists {
                    validate_unactivated_campaign(&campaigns[0], root, config)?;
                }
                persist_campaign_head(root, signer, 0)?;
            }
            for index in indexes
                .into_iter()
                .take_while(|index| *index <= latest_index)
            {
                let campaign_directory = campaign_root.join(index.to_string());
                campaigns.push(open_campaign(
                    index,
                    config,
                    signer,
                    Some(&campaign_directory.join("graph")),
                    Some(&campaign_directory.join("strategy-memory")),
                )?);
            }
            if let Some(index) = unactivated_index {
                let campaign_directory = campaign_root.join(index.to_string());
                let unactivated = open_campaign(
                    index,
                    config,
                    signer,
                    Some(&campaign_directory.join("graph")),
                    Some(&campaign_directory.join("strategy-memory")),
                )?;
                // `campaign-head.json` is the activation authority. A crash can
                // leave exactly one initialized successor directory before the
                // head advances. Authenticate it and require pristine state,
                // then leave it in place for the next serialized rotation to
                // reuse. Any populated or noncontiguous trailing directory is
                // still rejected as possible rollback/tamper.
                validate_unactivated_campaign(&unactivated, &campaign_directory, config)?;
            }
            Ok((campaigns, Some(campaign_root)))
        }
    }
}

impl CollectiveHypothesisService {
    /// Construct only when the feature is enabled. The caller retains an
    /// explicit `None` for the legacy path rather than a partially active
    /// service with hidden global state.
    pub fn from_config(
        config: &HypothesisGraphConfig,
        signer: Keypair,
        prometheus: Option<CriticalPathMetrics>,
    ) -> Result<Option<Arc<Self>>, GraphServiceError> {
        if !config.enabled {
            return Ok(None);
        }
        if matches!(&config.state_store, BundleStoreConfig::Memory) {
            return Err(GraphServiceError::NonDurableEnabledStore);
        }
        Self::new(config, signer, prometheus).map(|service| Some(Arc::new(service)))
    }

    pub fn new(
        config: &HypothesisGraphConfig,
        signer: Keypair,
        prometheus: Option<CriticalPathMetrics>,
    ) -> Result<Self, GraphServiceError> {
        config.resource_limits().validate()?;
        config.validate_reasoning_limits()?;
        let (campaigns, campaign_root) = load_campaigns(config, &signer)?;
        let replay_consumer_graph_id = match campaign_root.as_deref() {
            Some(campaign_root) => {
                let state_root = campaign_root.parent().ok_or_else(|| {
                    GraphServiceError::InvalidCampaignHead {
                        path: campaign_root.to_path_buf(),
                        reason: "campaign directory has no state-store parent".to_string(),
                    }
                })?;
                GraphId::new(format!(
                    "graph:runtime-replay-consumer:{}",
                    sha256_hex(campaign_head_stream_id(state_root, &signer)?.as_bytes())
                ))
            }
            None => graph_id_for_campaign(&signer, 0),
        };
        let active = campaigns
            .last()
            .cloned()
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "collective hypothesis service has no graph campaign".to_string(),
            })?;
        let admission = WitnessAdmission::from_key(&signer);
        let record_signer = KeypairGraphRecordSigner::with_admission(signer.clone(), &admission)?;
        let initial = active.store.snapshot()?;
        let coordinator = DurableHypothesisCoordinator::new_with_store(
            config,
            initial.state().logical_time_high_water,
            active.store.as_ref(),
            record_signer,
        )?;
        let mut service_metrics = GraphServiceMetrics::default();
        service_metrics.snapshot.campaign_rotations = active.index;
        let evidence_campaigns = evidence_campaign_index(&campaigns)?;
        let pending_worker_publications = pending_worker_publications(&campaigns)?;
        let pending_stalker_acquisition_hunts = pending_worker_publications
            .values()
            .filter(|publication| publication.task_kind == TaskKind::AcquireEvidence)
            .map(|publication| publication.hunt_id.clone())
            .collect();
        let pending_stalker_falsification_hunts = pending_worker_publications
            .values()
            .filter(|publication| publication.task_kind == TaskKind::FalsifyHypothesis)
            .map(|publication| publication.hunt_id.clone())
            .collect();
        let service = Self {
            config: config.clone(),
            campaigns: RwLock::new(CampaignRegistry { campaigns }),
            campaign_root,
            replay_consumer_graph_id,
            active_campaign_index: AtomicU64::new(active.index),
            signer,
            operation: Mutex::new(()),
            state: Mutex::new(CollectiveHypothesisState {
                coordinator,
                metrics: service_metrics,
                evidence_campaigns,
                worker_claimants: BTreeMap::new(),
                pending_worker_publications,
                pending_stalker_acquisition_hunts,
                pending_stalker_falsification_hunts,
                dirty_memory_campaigns: BTreeMap::new(),
                memory_projection_failure_epoch: 0,
            }),
            prometheus,
        };
        for campaign in service.campaigns()? {
            let snapshot = campaign.store.snapshot()?;
            service.record_startup_memory_projection(
                campaign.index,
                campaign.memory.project_committed(&snapshot),
            )?;
        }
        service.observe_state(initial.state());
        Ok(service)
    }

    fn campaigns(&self) -> Result<Vec<HypothesisCampaign>, GraphServiceError> {
        Ok(self
            .campaigns
            .read()
            .map_err(|_| GraphServiceError::Poisoned)?
            .campaigns
            .clone())
    }

    fn active_campaign(&self) -> Result<HypothesisCampaign, GraphServiceError> {
        self.campaigns
            .read()
            .map_err(|_| GraphServiceError::Poisoned)?
            .active()
            .cloned()
            .ok_or_else(|| {
                GraphStoreError::InvalidState {
                    reason: "collective hypothesis service has no active campaign".to_string(),
                }
                .into()
            })
    }

    fn campaign_at(&self, index: u64) -> Result<HypothesisCampaign, GraphServiceError> {
        self.campaigns
            .read()
            .map_err(|_| GraphServiceError::Poisoned)?
            .campaigns
            .iter()
            .find(|campaign| campaign.index == index)
            .cloned()
            .ok_or_else(|| {
                GraphStoreError::InvalidState {
                    reason: format!("worker publication references missing campaign {index}"),
                }
                .into()
            })
    }

    pub fn graph_id(&self) -> GraphId {
        graph_id_for_campaign(
            &self.signer,
            self.active_campaign_index.load(Ordering::Acquire),
        )
    }

    /// Stable identity for durable replay admission checkpoints. Campaign
    /// rotation changes the active graph ID, but it must not reset a replay
    /// consumer and rescan the lifetime store. The durable campaign stream
    /// binds both the signing identity and canonical graph-store root, so a
    /// replacement store resets the cursor even when it reuses the signer.
    pub fn replay_consumer_graph_id(&self) -> GraphId {
        self.replay_consumer_graph_id.clone()
    }

    pub fn store(&self) -> Result<Arc<dyn HypothesisGraphStore>, GraphServiceError> {
        Ok(self.active_campaign()?.store)
    }

    /// Prove the enabled service has every production worker identity before
    /// the daemon begins accepting telemetry. An admitted-but-inert graph is
    /// a startup failure, not a runtime mode.
    pub fn ensure_workers_registered(&self) -> Result<(), GraphServiceError> {
        let state = self.state.lock().map_err(|_| GraphServiceError::Poisoned)?;
        for kind in required_worker_kinds() {
            if !state.worker_claimants.contains_key(&kind) {
                return Err(GraphServiceError::MissingWorkerRegistration(kind));
            }
        }
        Ok(())
    }

    pub fn worker(
        self: &Arc<Self>,
        capabilities: impl IntoIterator<Item = TaskKind>,
        signer: Keypair,
    ) -> Result<GraphWorkerAdapter, GraphServiceError> {
        let registration_time = self
            .active_campaign()?
            .store
            .snapshot()?
            .state()
            .logical_time_high_water;
        self.worker_at(capabilities, signer, registration_time)
    }

    pub fn worker_at(
        self: &Arc<Self>,
        capabilities: impl IntoIterator<Item = TaskKind>,
        signer: Keypair,
        registration_time: GraphLogicalTime,
    ) -> Result<GraphWorkerAdapter, GraphServiceError> {
        registration_time.validate()?;
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        if capabilities.is_empty() {
            return Err(GraphServiceError::EmptyWorkerCapabilities);
        }
        let claimant = AgentId::from_public_key_hex(&signer.public_key().to_hex());
        let campaign = self.active_campaign()?;
        let mut state = self.state.lock().map_err(|_| GraphServiceError::Poisoned)?;
        let snapshot = campaign.store.snapshot()?;
        for kind in &capabilities {
            if let Some(existing) = state.worker_claimants.get(kind)
                && existing != &claimant
            {
                return Err(GraphServiceError::WorkerCapabilityConflict {
                    kind: *kind,
                    existing: existing.clone(),
                    observed: claimant.clone(),
                });
            }
            if let Some(existing) = snapshot
                .tasks()
                .find(|task| {
                    task.task.request.kind == *kind
                        && task_blocks_worker_rebind_at(
                            task.task.state,
                            task.task.lease.as_ref().map(|lease| lease.expires_at),
                            registration_time,
                        )
                        && task.task.request.claimant != claimant
                })
                .map(|task| &task.task.request.claimant)
            {
                return Err(GraphServiceError::WorkerCapabilityConflict {
                    kind: *kind,
                    existing: existing.clone(),
                    observed: claimant.clone(),
                });
            }
        }
        for kind in &capabilities {
            state.worker_claimants.insert(*kind, claimant.clone());
        }
        drop(state);
        Ok(GraphWorkerAdapter {
            service: Arc::clone(self),
            capabilities,
            claimant,
            signer,
        })
    }

    /// Admit normalized evidence, a minimal evidence-linked edge, competing
    /// alternatives, and bounded reasoning tasks. The replay has already
    /// crossed the critical-path persistence boundary before this call.
    pub fn submit_replay(
        &self,
        replay: &ReplayBundle,
    ) -> Result<GraphSubmission, GraphServiceError> {
        self.submit_replay_at(replay, false)
    }

    /// Retry one already-durable replay on the next graph logical tick.
    /// Reusing an exhausted tick would make scheduler-budget failures
    /// permanent even though their durable disposition is retryable.
    pub fn retry_persisted_replay(
        &self,
        replay: &ReplayBundle,
    ) -> Result<GraphSubmission, GraphServiceError> {
        self.submit_replay_at(replay, true)
    }

    fn submit_replay_at(
        &self,
        replay: &ReplayBundle,
        advance_logical_tick: bool,
    ) -> Result<GraphSubmission, GraphServiceError> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let _memory_projection_available = self.repair_memory_projection_for_work()?;
        let minimum_logical_time = if advance_logical_tick {
            Some(
                self.active_campaign()?
                    .store
                    .snapshot()?
                    .state()
                    .logical_time_high_water
                    .checked_add(1)
                    .ok_or_else(|| GraphAdmissionError::InvalidField {
                        field: "replay.retry_at".to_string(),
                        reason: "logical retry tick overflow".to_string(),
                    })?,
            )
        } else {
            None
        };
        let result = self.submit_replay_inner(replay, minimum_logical_time);
        let mut state = self.state.lock().map_err(|_| GraphServiceError::Poisoned)?;
        match &result {
            Ok(_) => {
                state.metrics.snapshot.submissions =
                    state.metrics.snapshot.submissions.saturating_add(1);
                if let Some(metrics) = &self.prometheus {
                    metrics.observe_hypothesis_graph_submission(true);
                }
            }
            Err(_) => {
                state.metrics.snapshot.submission_failures =
                    state.metrics.snapshot.submission_failures.saturating_add(1);
                if let Some(metrics) = &self.prometheus {
                    metrics.observe_hypothesis_graph_submission(false);
                }
            }
        }
        result
    }

    fn submit_replay_inner(
        &self,
        replay: &ReplayBundle,
        minimum_logical_time: Option<GraphLogicalTime>,
    ) -> Result<GraphSubmission, GraphServiceError> {
        let replay_ingested_at = GraphLogicalTime::new(replay.audit.created_at_ms);
        replay_ingested_at.validate()?;
        // Evidence identity must remain stable when the same durable replay is
        // retried after later task decisions advance graph logical time. The
        // high-water mark orders coordination; it is not the replay's ingest
        // timestamp.
        let clock = FixedGraphClock::new(replay_ingested_at);
        let normalized = normalize_telemetry_event_for_graph(
            &replay.event,
            &clock,
            &self.signer,
            GraphProducerRole::Normalizer,
            "runtime-replay-normalizer",
        )?;
        let evidence = normalized.evidence;
        let evidence_id = evidence.evidence_id.clone();
        if let Some(existing) = self.existing_submission(&evidence_id)? {
            return Ok(existing);
        }

        let confidence_basis_points = replay
            .findings
            .iter()
            .map(|finding| (finding.confidence.clamp(0.0, 1.0) * 10_000.0).round() as u16)
            .max()
            .unwrap_or(5_000);
        let inferred = infer_causal_relations(&evidence.payload)?;
        let (mut nodes, mut edges) = if inferred.is_empty() {
            fallback_observation_records(
                normalized.nodes,
                replay,
                &evidence,
                &self.signer,
                confidence_basis_points,
            )?
        } else {
            inferred_causal_records(
                normalized.nodes,
                inferred,
                &evidence,
                &self.signer,
                confidence_basis_points,
            )?
        };
        let mut evidence_records = vec![evidence.clone()];
        for (match_digest, entry) in persisted_threat_intel_matches(replay)? {
            let source_record_id = format!(
                "runtime-threat-intel:{}",
                sha256_hex(format!("{evidence_id}:{match_digest}").as_bytes())
            );
            let normalized_match = normalize_threat_intel_entry_for_graph(
                &entry,
                source_record_id,
                evidence.clock.observed_at,
                &clock,
                &self.signer,
                GraphProducerRole::Normalizer,
                "runtime-replay-threat-intel-normalizer",
            )?;
            let match_evidence = normalized_match.evidence;
            let match_confidence_basis_points = match &match_evidence.payload {
                swarm_core::hypothesis_graph::TypedEvidencePayload::ThreatIntelligence {
                    confidence_basis_points,
                    ..
                } => *confidence_basis_points,
                _ => {
                    return Err(GraphAdmissionError::InvalidTransition {
                        reason: "threat-intelligence normalizer returned an incompatible payload"
                            .to_string(),
                    }
                    .into());
                }
            };
            let match_inferred = infer_causal_relations(&match_evidence.payload)?;
            let (match_nodes, match_edges) = inferred_causal_records(
                normalized_match.nodes,
                match_inferred,
                &match_evidence,
                &self.signer,
                match_confidence_basis_points,
            )?;
            nodes.extend(match_nodes);
            edges.extend(match_edges);
            evidence_records.push(match_evidence);
        }
        let evidence_ids = evidence_records
            .iter()
            .map(|evidence| evidence.evidence_id.clone())
            .collect::<BTreeSet<_>>();
        let source_families = evidence_records
            .iter()
            .map(|evidence| evidence.source_family)
            .collect::<BTreeSet<_>>();
        let scope_node_ids = nodes
            .iter()
            .map(|node| node.id().clone())
            .collect::<BTreeSet<_>>();
        let malicious = scoped_hypothesis_id("malicious-activity", &evidence_id);
        let benign = scoped_hypothesis_id("benign-authorized-activity", &evidence_id);
        let mut state = self.state.lock().map_err(|_| GraphServiceError::Poisoned)?;
        for kind in required_worker_kinds() {
            if !state.worker_claimants.contains_key(&kind) {
                return Err(GraphServiceError::MissingWorkerRegistration(kind));
            }
        }
        let worker_claimants = state.worker_claimants.clone();
        let mut campaign = self.active_campaign()?;
        let mut initial = campaign.store.snapshot()?;
        let initial_logical_time = replay_seed_logical_time(
            replay.audit.created_at_ms,
            initial.state().logical_time_high_water,
            minimum_logical_time,
        )?;
        let initial_seed = replay_hypothesis_seed(
            campaign.graph_id.clone(),
            &malicious,
            &benign,
            &evidence_ids,
            &evidence_id,
            initial_logical_time,
        )?;
        let candidate_edge_ids = edges
            .iter()
            .map(|edge| edge.edge_id.clone())
            .collect::<BTreeSet<_>>();
        let task_target_count =
            coordination_task_targets(&initial_seed, &candidate_edge_ids)?.len();
        let max_seed_work_units =
            usize::try_from(self.config.max_work_units_per_tick).unwrap_or(usize::MAX);
        if task_target_count > max_seed_work_units {
            return Err(GraphAdmissionError::ResourceLimitExceeded {
                resource: "replay.task_targets".to_string(),
                limit: max_seed_work_units,
            }
            .into());
        }
        if campaign_requires_rotation(
            &initial,
            &evidence_records,
            &scope_node_ids,
            &edges,
            task_target_count,
        )? {
            let outstanding_tasks = initial
                .tasks()
                .filter(|task| !task_is_terminal(task.task.state))
                .count();
            if outstanding_tasks > 0 {
                return Err(GraphServiceError::CampaignRotationBlocked {
                    graph_id: campaign.graph_id,
                    outstanding_tasks,
                });
            }
            campaign = self.rotate_campaign(&mut state, &campaign)?;
            initial = campaign.store.snapshot()?;
        }
        let graph_records = GraphSeedRecords::new(evidence_records.clone(), nodes, edges);
        let scope = EvidenceScope::new(source_families, evidence_ids.clone(), scope_node_ids)?;
        let mut retried_persisted_capacity = false;
        let result = loop {
            let logical_time = replay_seed_logical_time(
                replay.audit.created_at_ms,
                initial.state().logical_time_high_water,
                minimum_logical_time,
            )?;
            let seed = replay_hypothesis_seed(
                campaign.graph_id.clone(),
                &malicious,
                &benign,
                &evidence_ids,
                &evidence_id,
                logical_time,
            )?;
            match state.coordinator.coordinate_graph_seed_for_claimants(
                campaign.store.as_ref(),
                initial.revision(),
                &seed,
                &worker_claimants,
                scope.clone(),
                graph_records.clone(),
            ) {
                Ok(result) => break result,
                Err(GraphStoreError::ResourceLimit { resource, limit })
                    if resource == "persisted_file_bytes" && !retried_persisted_capacity =>
                {
                    // The complete signed envelope contains descriptors,
                    // tombstones, and terminal outbox copies that the cheap
                    // preflight cannot safely estimate. CAS is atomic, so a
                    // persisted-file limit leaves the old campaign unchanged;
                    // rotate a terminal campaign and retry the exact replay
                    // once against a fresh store.
                    let retained = !initial.state().graph.evidence.is_empty()
                        || !initial.state().hypotheses.is_empty()
                        || !initial.state().tasks.is_empty();
                    if !retained {
                        return Err(GraphStoreError::ResourceLimit { resource, limit }.into());
                    }
                    let outstanding_tasks = initial
                        .tasks()
                        .filter(|task| !task_is_terminal(task.task.state))
                        .count();
                    if outstanding_tasks > 0 {
                        return Err(GraphServiceError::CampaignRotationBlocked {
                            graph_id: campaign.graph_id,
                            outstanding_tasks,
                        });
                    }
                    campaign = self.rotate_campaign(&mut state, &campaign)?;
                    initial = campaign.store.snapshot()?;
                    retried_persisted_capacity = true;
                }
                Err(error) => return Err(error.into()),
            }
        };
        for admitted_evidence_id in evidence_ids {
            let replaced_campaign = state
                .evidence_campaigns
                .insert(admitted_evidence_id, campaign.index);
            debug_assert!(
                replaced_campaign.is_none(),
                "serialized replay admission replaced an existing evidence campaign"
            );
        }
        self.observe_state(result.snapshot.state());
        Ok(GraphSubmission {
            graph_id: campaign.graph_id,
            evidence_id,
            hypothesis_ids: result.hypothesis_ids,
            task_ids: result.task_ids,
            generation: result.snapshot.revision().generation,
            idempotent: false,
        })
    }

    fn existing_submission(
        &self,
        evidence_id: &EvidenceId,
    ) -> Result<Option<GraphSubmission>, GraphServiceError> {
        let campaign_index = self
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?
            .evidence_campaigns
            .get(evidence_id)
            .copied();
        let Some(campaign_index) = campaign_index else {
            return Ok(None);
        };
        let campaign = self.campaign_at(campaign_index)?;
        let snapshot = campaign.store.snapshot()?;
        if !snapshot.graph().evidence.contains_key(evidence_id) {
            return Err(GraphStoreError::InvalidState {
                reason: format!(
                    "evidence campaign index maps `{evidence_id}` to campaign {campaign_index}, which does not contain it"
                ),
            }
            .into());
        }
        let task_ids = snapshot
            .tasks()
            .filter(|task| {
                task.task
                    .request
                    .evidence_scope
                    .evidence_ids
                    .contains(evidence_id)
            })
            .map(|task| task.task.request.task_id.clone())
            .collect();
        Ok(Some(GraphSubmission {
            graph_id: campaign.graph_id,
            evidence_id: evidence_id.clone(),
            hypothesis_ids: vec![
                scoped_hypothesis_id("malicious-activity", evidence_id),
                scoped_hypothesis_id("benign-authorized-activity", evidence_id),
            ],
            task_ids,
            generation: snapshot.revision().generation,
            idempotent: true,
        }))
    }

    fn rotate_campaign(
        &self,
        state: &mut CollectiveHypothesisState,
        current: &HypothesisCampaign,
    ) -> Result<HypothesisCampaign, GraphServiceError> {
        let index = current
            .index
            .checked_add(1)
            .ok_or(GraphServiceError::CampaignIndexExhausted)?;
        let campaign = match &self.campaign_root {
            Some(root) => {
                fs::create_dir_all(root).map_err(|source| GraphServiceError::CampaignIo {
                    path: root.clone(),
                    source,
                })?;
                let campaign_root = root.join(index.to_string());
                match fs::create_dir(&campaign_root) {
                    Ok(()) => {
                        let directory = fs::File::open(root).map_err(|source| {
                            GraphServiceError::CampaignIo {
                                path: root.clone(),
                                source,
                            }
                        })?;
                        directory
                            .sync_all()
                            .map_err(|source| GraphServiceError::CampaignIo {
                                path: root.clone(),
                                source,
                            })?;
                    }
                    Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(source) => {
                        return Err(GraphServiceError::CampaignIo {
                            path: campaign_root,
                            source,
                        });
                    }
                }
                open_campaign(
                    index,
                    &self.config,
                    &self.signer,
                    Some(&campaign_root.join("graph")),
                    Some(&campaign_root.join("strategy-memory")),
                )?
            }
            None => open_campaign(index, &self.config, &self.signer, None, None)?,
        };
        let snapshot = campaign.store.snapshot()?;
        let admission = WitnessAdmission::from_key(&self.signer);
        let record_signer =
            KeypairGraphRecordSigner::with_admission(self.signer.clone(), &admission)?;
        let coordinator = DurableHypothesisCoordinator::new_with_store(
            &self.config,
            snapshot.state().logical_time_high_water,
            campaign.store.as_ref(),
            record_signer,
        )?;
        if let Some(campaign_root) = &self.campaign_root {
            let state_root =
                campaign_root
                    .parent()
                    .ok_or_else(|| GraphServiceError::InvalidCampaignHead {
                        path: campaign_root.clone(),
                        reason: "campaign directory has no state-store parent".to_string(),
                    })?;
            // The signed head is the durable activation point. It lives
            // outside the numbered campaign directory, so deletion or rollback
            // of the newest campaign is detected before an older index can be
            // reactivated or reused on restart.
            persist_campaign_head(state_root, &self.signer, index)?;
        }
        {
            let mut campaigns = self
                .campaigns
                .write()
                .map_err(|_| GraphServiceError::Poisoned)?;
            let observed = campaigns
                .active()
                .ok_or_else(|| GraphStoreError::InvalidState {
                    reason: "collective hypothesis service has no active campaign".to_string(),
                })?;
            if observed.index != current.index {
                return Err(GraphStoreError::InvalidState {
                    reason: "active graph campaign changed during serialized rotation".to_string(),
                }
                .into());
            }
            campaigns.campaigns.push(campaign.clone());
        }
        state.coordinator = coordinator;
        state.metrics.snapshot.campaign_rotations =
            state.metrics.snapshot.campaign_rotations.saturating_add(1);
        self.active_campaign_index.store(index, Ordering::Release);
        self.observe_state(snapshot.state());
        Ok(campaign)
    }

    pub fn summary(&self) -> Result<GraphSummaryProjection, GraphServiceError> {
        let campaign = self.active_campaign()?;
        self.repair_memory_projection_for_campaign(campaign.index)?;
        self.summary_for_campaign(&campaign)
    }

    pub fn summaries(&self) -> Result<Vec<GraphSummaryProjection>, GraphServiceError> {
        Ok(self
            .summary_page(None, usize::MAX)?
            .into_iter()
            .map(|(_, summary)| summary)
            .collect())
    }

    /// Return a bounded newest-first page over immutable campaign indexes.
    /// Only selected campaigns are authenticated and summarized, so retained
    /// history cannot make a single collection request load every graph.
    pub fn summary_page(
        &self,
        after: Option<(u64, &str)>,
        limit: usize,
    ) -> Result<Vec<(u64, GraphSummaryProjection)>, GraphServiceError> {
        if limit == 0 {
            return Err(GraphStoreError::InvalidState {
                reason: "operator graph summary page limit must be positive".to_string(),
            }
            .into());
        }
        let campaigns = self
            .campaigns
            .read()
            .map_err(|_| GraphServiceError::Poisoned)?;
        if let Some((index, graph_id)) = after
            && !campaigns
                .campaigns
                .iter()
                .any(|campaign| campaign.index == index && campaign.graph_id.as_str() == graph_id)
        {
            return Err(GraphServiceError::InvalidCollectionCursor);
        }
        let selected = campaigns
            .campaigns
            .iter()
            .rev()
            .filter(|campaign| after.is_none_or(|(index, _)| campaign.index < index))
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        drop(campaigns);
        selected
            .into_iter()
            .map(|campaign| {
                self.repair_memory_projection_for_campaign(campaign.index)?;
                self.summary_for_campaign(&campaign)
                    .map(|summary| (campaign.index, summary))
            })
            .collect()
    }

    fn summary_for_campaign(
        &self,
        campaign: &HypothesisCampaign,
    ) -> Result<GraphSummaryProjection, GraphServiceError> {
        let snapshot = campaign.store.snapshot()?;
        let memory_count = campaign
            .memory
            .store()
            .list(self.config.max_memory_records)?
            .len();
        let metrics = self
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?
            .metrics
            .snapshot;
        let pending_task_count = snapshot
            .tasks()
            .filter(|task| task.task.state == TaskState::Pending)
            .count();
        let completed_task_count = snapshot
            .tasks()
            .filter(|task| task.task.state == TaskState::Completed)
            .count();
        Ok(GraphSummaryProjection {
            graph_id: campaign.graph_id.clone(),
            generation: snapshot.revision().generation,
            graph_version: snapshot.graph().version,
            evidence_count: snapshot.graph().evidence.len(),
            node_count: snapshot.graph().nodes.len(),
            edge_count: snapshot.graph().edges.len(),
            contradiction_count: snapshot.graph().contradictions.len()
                + snapshot.graph().conflicts.len(),
            hypothesis_count: snapshot.hypotheses().len(),
            pending_task_count,
            completed_task_count,
            memory_count,
            logical_time_high_water: snapshot.state().logical_time_high_water,
            metrics,
        })
    }

    pub fn operator_projection(&self) -> Result<GraphOperatorProjection, GraphServiceError> {
        let campaign = self.active_campaign()?;
        self.repair_memory_projection_for_campaign(campaign.index)?;
        self.operator_projection_for_campaign(&campaign)
    }

    fn operator_projection_for_campaign(
        &self,
        campaign: &HypothesisCampaign,
    ) -> Result<GraphOperatorProjection, GraphServiceError> {
        let snapshot = campaign.store.snapshot()?;
        let memory = campaign
            .memory
            .store()
            .list(self.config.max_memory_records)?;
        let metrics = self
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?
            .metrics
            .snapshot;
        Ok(GraphOperatorProjection {
            graph_id: campaign.graph_id.clone(),
            generation: snapshot.revision().generation,
            digest: snapshot.revision().digest.clone(),
            graph: snapshot.graph().clone(),
            hypotheses: snapshot.hypotheses().clone(),
            tasks: snapshot.tasks().map(|task| task.task.clone()).collect(),
            terminal_publications: snapshot
                .terminal_outbox()
                .len()
                .saturating_add(snapshot.retry_exhaustion_outbox().len()),
            memory,
            logical_time_high_water: snapshot.state().logical_time_high_water,
            metrics,
        })
    }

    pub fn operator_projection_for(
        &self,
        graph_id: &GraphId,
    ) -> Result<GraphOperatorProjection, GraphServiceError> {
        let campaign = self.campaign_for(graph_id)?;
        self.repair_memory_projection_for_campaign(campaign.index)?;
        self.operator_projection_for_campaign(&campaign)
    }

    pub fn operator_tasks_for(
        &self,
        graph_id: &GraphId,
    ) -> Result<Vec<TaskRecord>, GraphServiceError> {
        let campaign = self.campaign_for(graph_id)?;
        Ok(campaign
            .store
            .snapshot()?
            .tasks()
            .map(|task| task.task.clone())
            .collect())
    }

    pub fn operator_task_page_for(
        &self,
        graph_id: &GraphId,
        after: Option<(GraphLogicalTime, &str)>,
        limit: usize,
    ) -> Result<Vec<TaskRecord>, GraphServiceError> {
        let campaign = self.campaign_for(graph_id)?;
        Ok(campaign.store.task_page(after, limit)?)
    }

    pub fn operator_memory_for(
        &self,
        graph_id: &GraphId,
    ) -> Result<Vec<StrategyMemoryRecord>, GraphServiceError> {
        let campaign = self.campaign_for(graph_id)?;
        self.repair_memory_projection_for_campaign(campaign.index)?;
        Ok(campaign
            .memory
            .store()
            .list(self.config.max_memory_records)?)
    }

    pub fn operator_memory_page_for(
        &self,
        graph_id: &GraphId,
        after: Option<(u64, &str)>,
        limit: usize,
    ) -> Result<Vec<StrategyMemoryRecord>, GraphServiceError> {
        let campaign = self.campaign_for(graph_id)?;
        self.repair_memory_projection_for_campaign(campaign.index)?;
        Ok(campaign.memory.store().list_page(after, limit)?)
    }

    fn campaign_for(&self, graph_id: &GraphId) -> Result<HypothesisCampaign, GraphServiceError> {
        self.campaigns
            .read()
            .map_err(|_| GraphServiceError::Poisoned)?
            .find(graph_id)
            .cloned()
            .ok_or_else(|| GraphServiceError::GraphMismatch {
                expected: self.graph_id(),
                observed: graph_id.clone(),
            })
    }

    fn repair_memory_projection_for_campaign(
        &self,
        campaign_index: u64,
    ) -> Result<(), GraphServiceError> {
        let Some(failure_epoch) = self
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?
            .dirty_memory_campaigns
            .get(&campaign_index)
            .copied()
        else {
            return Ok(());
        };
        let campaign = self.campaign_at(campaign_index)?;
        let snapshot = campaign.store.snapshot()?;
        let projection = match campaign.memory.project_committed(&snapshot) {
            Ok(projection) => projection,
            Err(error) => {
                self.record_advisory_memory_failure(campaign_index, &error)?;
                return Err(GraphServiceError::Memory(error));
            }
        };
        let mut state = self.state.lock().map_err(|_| GraphServiceError::Poisoned)?;
        state.metrics.snapshot.memory_records_projected = state
            .metrics
            .snapshot
            .memory_records_projected
            .saturating_add(u64::try_from(projection.inserted).unwrap_or(u64::MAX));
        if state.dirty_memory_campaigns.get(&campaign_index) == Some(&failure_epoch) {
            state.dirty_memory_campaigns.remove(&campaign_index);
        }
        Ok(())
    }

    fn repair_memory_projection_for_work(&self) -> Result<bool, GraphServiceError> {
        let campaign_index = self.active_campaign_index.load(Ordering::Acquire);
        match self.repair_memory_projection_for_campaign(campaign_index) {
            Ok(()) => Ok(true),
            Err(GraphServiceError::Memory(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn record_advisory_memory_failure(
        &self,
        campaign_index: u64,
        error: &StrategyMemoryStoreError,
    ) -> Result<(), GraphServiceError> {
        let mut state = self.state.lock().map_err(|_| GraphServiceError::Poisoned)?;
        state.memory_projection_failure_epoch = state
            .memory_projection_failure_epoch
            .checked_add(1)
            .ok_or_else(|| GraphStoreError::InvalidState {
                reason: "strategy-memory projection failure epoch exhausted".to_string(),
            })?;
        let failure_epoch = state.memory_projection_failure_epoch;
        state
            .dirty_memory_campaigns
            .insert(campaign_index, failure_epoch);
        state.metrics.snapshot.memory_projection_failures = state
            .metrics
            .snapshot
            .memory_projection_failures
            .saturating_add(1);
        drop(state);
        if let Some(metrics) = &self.prometheus {
            metrics.observe_hypothesis_graph_memory_projection_failure();
        }
        tracing::warn!(
            reason = %error,
            campaign_index,
            "strategy-memory projection is degraded; collective reasoning is continuing with base task priorities"
        );
        Ok(())
    }

    fn record_post_commit_memory_projection(
        &self,
        campaign_index: u64,
        result: Result<MemoryProjectionReport, StrategyMemoryStoreError>,
    ) -> Result<usize, GraphServiceError> {
        let mut state = self.state.lock().map_err(|_| GraphServiceError::Poisoned)?;
        match result {
            Ok(projection) => {
                state.metrics.snapshot.memory_records_projected = state
                    .metrics
                    .snapshot
                    .memory_records_projected
                    .saturating_add(u64::try_from(projection.inserted).unwrap_or(u64::MAX));
                Ok(projection.inserted)
            }
            Err(error) => {
                drop(state);
                self.record_advisory_memory_failure(campaign_index, &error)?;
                // The graph terminal and its embedded memory have already
                // committed atomically. Treat the external memory index as a
                // repairable projection: returning an error here would make
                // the worker report failure for work that cannot be retried.
                Ok(0)
            }
        }
    }

    fn record_startup_memory_projection(
        &self,
        campaign_index: u64,
        result: Result<MemoryProjectionReport, StrategyMemoryStoreError>,
    ) -> Result<(), GraphServiceError> {
        // Startup replays the same repairable projection as a live terminal.
        // The signed graph remains authoritative, so an unavailable derived
        // memory index starts dirty/degraded rather than taking down ingest.
        self.record_post_commit_memory_projection(campaign_index, result)?;
        Ok(())
    }

    fn observe_state(&self, state: &swarm_spine::GraphStoreState) {
        if let Some(metrics) = &self.prometheus {
            let pending = state
                .tasks
                .values()
                .filter(|task| task.task.state == TaskState::Pending)
                .count();
            metrics.observe_hypothesis_graph_state(
                state.hypotheses.len(),
                pending,
                state.terminal_outbox.len(),
            );
        }
    }

    fn priority_for_task(
        &self,
        campaign: &HypothesisCampaign,
        task: &TaskRecord,
        snapshot: &GraphStoreSnapshot,
        now: GraphLogicalTime,
    ) -> Result<MemoryPriorityProjection, GraphServiceError> {
        let base = base_task_priority(task.request.kind);
        let candidates: Vec<HypothesisId> = match &task.request.target {
            TaskTarget::Hypothesis { hypothesis_id } => vec![hypothesis_id.clone()],
            TaskTarget::Evidence { .. } | TaskTarget::Edge { .. } => {
                snapshot.hypotheses().keys().cloned().collect()
            }
        };
        let mut best = MemoryPriorityProjection::unchanged(base);
        for hypothesis_id in candidates {
            let projected = campaign.memory.priority_for_context(
                &campaign.graph_id,
                &hypothesis_id,
                &task.request.evidence_scope.evidence_ids,
                now,
                base,
            )?;
            if projected.adjusted_priority_basis_points > best.adjusted_priority_basis_points
                || (projected.adjusted_priority_basis_points == best.adjusted_priority_basis_points
                    && projected.memory_id < best.memory_id)
            {
                best = projected;
            }
        }
        Ok(best)
    }

    fn priority_projections_for_tasks(
        &self,
        campaign: &HypothesisCampaign,
        tasks: &[TaskRecord],
        snapshot: &GraphStoreSnapshot,
        now: GraphLogicalTime,
        use_memory_priority: bool,
    ) -> Result<Vec<MemoryPriorityProjection>, GraphServiceError> {
        let base_priorities = || {
            tasks
                .iter()
                .map(|task| {
                    MemoryPriorityProjection::unchanged(base_task_priority(task.request.kind))
                })
                .collect::<Vec<_>>()
        };
        if !use_memory_priority {
            return Ok(base_priorities());
        }
        let attempted = tasks
            .iter()
            .map(|task| self.priority_for_task(campaign, task, snapshot, now))
            .collect::<Result<Vec<_>, GraphServiceError>>();
        self.resolve_advisory_priorities(campaign.index, base_priorities(), attempted)
    }

    fn resolve_advisory_priorities(
        &self,
        campaign_index: u64,
        base_priorities: Vec<MemoryPriorityProjection>,
        attempted: Result<Vec<MemoryPriorityProjection>, GraphServiceError>,
    ) -> Result<Vec<MemoryPriorityProjection>, GraphServiceError> {
        match attempted {
            Ok(priorities) => Ok(priorities),
            Err(GraphServiceError::Memory(error)) => {
                self.record_advisory_memory_failure(campaign_index, &error)?;
                Ok(base_priorities)
            }
            Err(error) => Err(error),
        }
    }

    fn nonretrograde_time(
        &self,
        requested: GraphLogicalTime,
    ) -> Result<GraphLogicalTime, GraphServiceError> {
        requested.validate()?;
        Ok(requested.max(
            self.active_campaign()?
                .store
                .snapshot()?
                .state()
                .logical_time_high_water,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ClaimedGraphTask {
    pub claim: TaskClaim,
    pub request: swarm_core::hypothesis_graph::TaskClaimRequest,
    pub task_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphChallengeContext {
    pub graph_id: GraphId,
    pub task_id: TaskId,
    pub hunt_id: String,
    pub evidence_ids: BTreeSet<EvidenceId>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StalkerGraphCompletion {
    pub acquisitions: usize,
    pub acquisition_no_findings: usize,
    pub falsifications: usize,
    pub falsification_no_findings: usize,
    pub memory_records_projected: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StalkerGraphPublication {
    pub graph_id: GraphId,
    pub completion: StalkerGraphCompletion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeaverGraphPublication {
    pub graph_id: GraphId,
    pub task_id: TaskId,
    pub hunt_id: String,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub no_finding: bool,
    /// Present only for a store-authenticated retry-exhaustion terminal. This
    /// distinguishes scheduler failure from a worker-authored no-finding.
    pub retry_exhaustion_failure_summary: Option<String>,
}

struct TerminalPublication {
    kind: TaskCompletionKind,
    evidence: Vec<swarm_core::hypothesis_graph::EvidenceEnvelope>,
    decision: Option<DecisionRecord>,
    memory: Option<(StrategyMemory, StrategyMemoryExpiryEnvelope)>,
}

#[derive(Clone)]
pub struct GraphWorkerAdapter {
    service: Arc<CollectiveHypothesisService>,
    capabilities: BTreeSet<TaskKind>,
    claimant: AgentId,
    signer: Keypair,
}

impl GraphWorkerAdapter {
    pub fn graph_id(&self) -> GraphId {
        self.service.graph_id()
    }

    pub fn capabilities(&self) -> &BTreeSet<TaskKind> {
        &self.capabilities
    }

    pub fn claimant(&self) -> &AgentId {
        &self.claimant
    }

    /// Reconcile an already durable replay through the same idempotent graph
    /// admission used by live ingest. Stalker calls this before consuming a
    /// hunt so a transient post-persistence graph failure cannot strand the
    /// replay outside collective reasoning.
    pub fn ensure_replay_admitted(
        &self,
        replay: &ReplayBundle,
    ) -> Result<GraphSubmission, GraphServiceError> {
        if !self.capabilities.contains(&TaskKind::AcquireEvidence) {
            return Err(GraphServiceError::MissingCapability(
                TaskKind::AcquireEvidence,
            ));
        }
        self.service.submit_replay(replay)
    }

    /// Return durable Stalker work independently of the ephemeral pheromone
    /// window. This is the restart/recovery trigger used when a replay and its
    /// graph tasks survive longer than the detection deposit that created
    /// them.
    pub fn outstanding_stalker_hunts(&self) -> Result<Vec<String>, GraphServiceError> {
        let now = self
            .service
            .active_campaign()?
            .store
            .snapshot()?
            .state()
            .logical_time_high_water;
        self.outstanding_stalker_hunts_at(now)
    }

    pub fn outstanding_stalker_hunts_at(
        &self,
        now: GraphLogicalTime,
    ) -> Result<Vec<String>, GraphServiceError> {
        now.validate()?;
        if !self.capabilities.contains(&TaskKind::AcquireEvidence)
            && !self.capabilities.contains(&TaskKind::FalsifyHypothesis)
        {
            return Err(GraphServiceError::MissingCapability(
                TaskKind::AcquireEvidence,
            ));
        }
        let state = self
            .service
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let limit =
            usize::try_from(self.service.config.max_work_units_per_tick).unwrap_or(usize::MAX);
        let mut hunts = if self.capabilities.contains(&TaskKind::AcquireEvidence)
            && self.capabilities.contains(&TaskKind::FalsifyHypothesis)
        {
            state
                .pending_stalker_acquisition_hunts
                .union(&state.pending_stalker_falsification_hunts)
                .take(limit)
                .cloned()
                .collect::<BTreeSet<_>>()
        } else if self.capabilities.contains(&TaskKind::AcquireEvidence) {
            state
                .pending_stalker_acquisition_hunts
                .iter()
                .take(limit)
                .cloned()
                .collect::<BTreeSet<_>>()
        } else {
            state
                .pending_stalker_falsification_hunts
                .iter()
                .take(limit)
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        drop(state);
        // Campaign rotation refuses outstanding tasks, so live recovery only
        // needs to inspect the active graph. Archived campaigns are consulted
        // exclusively through the bounded pending-publication index above.
        let campaign = self.service.active_campaign()?;
        let snapshot = campaign.store.snapshot()?;
        for task in snapshot.tasks().filter(|task| {
            self.capabilities.contains(&task.task.request.kind)
                && task_is_visible_to_claimant(
                    task.task.state,
                    &task.task.request.claimant,
                    task.task.lease.as_ref().map(|lease| lease.expires_at),
                    &self.claimant,
                    now,
                )
                && !task_is_terminal(task.task.state)
        }) {
            if hunts.len() >= limit {
                break;
            }
            if let Some(hunt_id) = hunt_for_evidence_scope(
                &task.task.request.evidence_scope.evidence_ids,
                snapshot.graph(),
            ) {
                hunts.insert(hunt_id);
            }
        }
        Ok(hunts.into_iter().collect())
    }

    pub fn committed_stalker_publication(
        &self,
        hunt_id: &str,
    ) -> Result<Option<StalkerGraphPublication>, GraphServiceError> {
        let campaign_indexes = self
            .service
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?
            .pending_worker_publications
            .values()
            .filter(|publication| {
                publication.hunt_id == hunt_id
                    && self.capabilities.contains(&publication.task_kind)
                    && matches!(
                        publication.task_kind,
                        TaskKind::AcquireEvidence | TaskKind::FalsifyHypothesis
                    )
            })
            .map(|publication| publication.campaign_index)
            .collect::<BTreeSet<_>>();
        for campaign_index in campaign_indexes.into_iter().rev() {
            let campaign = self.service.campaign_at(campaign_index)?;
            let snapshot = campaign.store.snapshot()?;
            let tasks = snapshot
                .tasks()
                .filter(|task| {
                    self.capabilities.contains(&task.task.request.kind)
                        && matches!(
                            task.task.request.kind,
                            TaskKind::AcquireEvidence | TaskKind::FalsifyHypothesis
                        )
                        && task_matches_hunt(&task.task, hunt_id, &snapshot)
                })
                .collect::<Vec<_>>();
            if tasks.is_empty() {
                continue;
            }
            if tasks.iter().any(|task| !task_is_terminal(task.task.state)) {
                return Ok(None);
            }
            let mut completion = StalkerGraphCompletion::default();
            for task in tasks {
                let task_id = &task.task.request.task_id;
                let worker_publication = snapshot
                    .terminal_outbox()
                    .get(task_id)
                    .filter(|publication| publication.publication_acknowledged == Some(false));
                let terminal_kind = worker_publication
                    .map(|publication| publication.envelope.completion.kind.clone())
                    .or_else(|| {
                        snapshot
                            .retry_exhaustion_outbox()
                            .get(task_id)
                            .is_some_and(|publication| !publication.publication_acknowledged)
                            .then_some(TaskCompletionKind::NoFinding)
                    });
                let Some(terminal_kind) = terminal_kind else {
                    continue;
                };
                match (task.task.request.kind, terminal_kind) {
                    (TaskKind::AcquireEvidence, TaskCompletionKind::EvidenceAdded) => {
                        completion.acquisitions = completion.acquisitions.saturating_add(1);
                    }
                    (TaskKind::AcquireEvidence, TaskCompletionKind::NoFinding) => {
                        completion.acquisition_no_findings =
                            completion.acquisition_no_findings.saturating_add(1);
                    }
                    (TaskKind::FalsifyHypothesis, TaskCompletionKind::HypothesisFalsified) => {
                        completion.falsifications = completion.falsifications.saturating_add(1);
                    }
                    (TaskKind::FalsifyHypothesis, TaskCompletionKind::NoFinding) => {
                        completion.falsification_no_findings =
                            completion.falsification_no_findings.saturating_add(1);
                    }
                    _ => {}
                }
                if worker_publication.is_some_and(|publication| publication.memory.is_some()) {
                    completion.memory_records_projected =
                        completion.memory_records_projected.saturating_add(1);
                }
            }
            let terminal_count = completion
                .acquisitions
                .saturating_add(completion.acquisition_no_findings)
                .saturating_add(completion.falsifications)
                .saturating_add(completion.falsification_no_findings);
            return Ok((terminal_count > 0).then_some(StalkerGraphPublication {
                graph_id: campaign.graph_id,
                completion,
            }));
        }
        Ok(None)
    }

    pub fn outstanding_weaver_publications(
        &self,
    ) -> Result<Vec<WeaverGraphPublication>, GraphServiceError> {
        if !self.capabilities.contains(&TaskKind::ChallengeEdge) {
            return Err(GraphServiceError::MissingCapability(
                TaskKind::ChallengeEdge,
            ));
        }
        let state = self
            .service
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let limit =
            usize::try_from(self.service.config.max_work_units_per_tick).unwrap_or(usize::MAX);
        Ok(state
            .pending_worker_publications
            .values()
            .filter(|publication| publication.task_kind == TaskKind::ChallengeEdge)
            .take(limit)
            .map(|publication| WeaverGraphPublication {
                graph_id: publication.graph_id.clone(),
                task_id: publication.task_id.clone(),
                hunt_id: publication.hunt_id.clone(),
                evidence_ids: publication.evidence_ids.clone(),
                no_finding: publication.completion_kind == TaskCompletionKind::NoFinding,
                retry_exhaustion_failure_summary: publication
                    .retry_exhaustion_failure_summary
                    .clone(),
            })
            .collect())
    }

    pub fn acknowledge_stalker_publication(&self, hunt_id: &str) -> Result<(), GraphServiceError> {
        if !self.capabilities.contains(&TaskKind::AcquireEvidence)
            && !self.capabilities.contains(&TaskKind::FalsifyHypothesis)
        {
            return Err(GraphServiceError::MissingCapability(
                TaskKind::AcquireEvidence,
            ));
        }
        self.acknowledge_publications(|publication| {
            publication.hunt_id == hunt_id
                && matches!(
                    publication.task_kind,
                    TaskKind::AcquireEvidence | TaskKind::FalsifyHypothesis
                )
                && self.capabilities.contains(&publication.task_kind)
        })
    }

    pub fn acknowledge_weaver_publication(
        &self,
        task_id: &TaskId,
    ) -> Result<(), GraphServiceError> {
        if !self.capabilities.contains(&TaskKind::ChallengeEdge) {
            return Err(GraphServiceError::MissingCapability(
                TaskKind::ChallengeEdge,
            ));
        }
        self.acknowledge_publications(|publication| {
            publication.task_kind == TaskKind::ChallengeEdge && &publication.task_id == task_id
        })
    }

    fn acknowledge_publications(
        &self,
        predicate: impl Fn(&PendingWorkerPublication) -> bool,
    ) -> Result<(), GraphServiceError> {
        let _operation = self
            .service
            .operation
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let selected = self
            .service
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?
            .pending_worker_publications
            .iter()
            .filter(|(_, publication)| predicate(publication))
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let mut by_campaign = BTreeMap::<u64, BTreeSet<TaskId>>::new();
        for (campaign_index, task_id) in &selected {
            by_campaign
                .entry(*campaign_index)
                .or_default()
                .insert(task_id.clone());
        }
        for (campaign_index, task_ids) in by_campaign {
            let campaign = self.service.campaign_at(campaign_index)?;
            let snapshot = campaign.store.snapshot()?;
            let mut next = snapshot.state().clone();
            let mut changed = false;
            for task_id in task_ids {
                if let Some(publication) = next.terminal_outbox.get_mut(&task_id) {
                    if publication.publication_acknowledged == Some(false) {
                        publication.publication_acknowledged = Some(true);
                        changed = true;
                    }
                } else if let Some(publication) = next.retry_exhaustion_outbox.get_mut(&task_id) {
                    if !publication.publication_acknowledged {
                        publication.publication_acknowledged = true;
                        changed = true;
                    }
                } else {
                    return Err(GraphStoreError::InvalidState {
                        reason: "pending worker publication references an unknown outbox entry"
                            .to_string(),
                    }
                    .into());
                }
            }
            if changed {
                next.generation = snapshot.revision().generation;
                next.predecessor_digest = snapshot.state().predecessor_digest.clone();
                campaign.store.compare_and_swap(snapshot.revision(), next)?;
            }
        }
        let mut state = self
            .service
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        for key in selected {
            if let Some(publication) = state.pending_worker_publications.remove(&key) {
                match publication.task_kind {
                    TaskKind::AcquireEvidence => {
                        state
                            .pending_stalker_acquisition_hunts
                            .remove(&publication.hunt_id);
                    }
                    TaskKind::FalsifyHypothesis => {
                        state
                            .pending_stalker_falsification_hunts
                            .remove(&publication.hunt_id);
                    }
                    TaskKind::ChallengeEdge => {}
                }
            }
        }
        Ok(())
    }

    pub fn claim_next(
        &self,
        now: GraphLogicalTime,
    ) -> Result<Option<ClaimedGraphTask>, GraphServiceError> {
        // Repair the advisory index before beginning new work. Terminal
        // completion paths intentionally bypass this preflight: once a graph
        // terminal commits, a still-failing projection must not prevent the
        // adapter from returning that completion to its agent.
        let memory_priority_available = self.service.repair_memory_projection_for_work()?;
        self.claim_matching(now, memory_priority_available, |_, _| true)
    }

    fn claim_matching<F>(
        &self,
        now: GraphLogicalTime,
        use_memory_priority: bool,
        predicate: F,
    ) -> Result<Option<ClaimedGraphTask>, GraphServiceError>
    where
        F: Fn(&TaskRecord, &GraphStoreSnapshot) -> bool,
    {
        let campaign = self.service.active_campaign()?;
        loop {
            let snapshot = campaign.store.snapshot()?;
            let eligible = snapshot
                .tasks()
                .filter(|task| {
                    task_is_claimable_at(&task.task, now)
                        && self.capabilities.contains(&task.task.request.kind)
                        && predicate(&task.task, &snapshot)
                })
                .map(|task| (task.task.clone(), task.generation))
                .collect::<Vec<_>>();
            let eligible_tasks = eligible
                .iter()
                .map(|(task, _)| task.clone())
                .collect::<Vec<_>>();
            let priorities = self.service.priority_projections_for_tasks(
                &campaign,
                &eligible_tasks,
                &snapshot,
                now,
                use_memory_priority,
            )?;
            let mut candidates = eligible
                .into_iter()
                .zip(priorities)
                .map(|((task, generation), priority)| {
                    let key = swarm_core::hypothesis_graph::GraphSchedulerKey::new(
                        task.request.requested_at,
                        task.request.kind,
                        priority.adjusted_priority_basis_points,
                        task.request.task_id.clone(),
                    )?;
                    Ok((key, task, generation))
                })
                .collect::<Result<Vec<_>, GraphServiceError>>()?;
            candidates.sort_by(|left, right| left.0.cmp(&right.0));
            let Some((_, task, task_generation)) = candidates.into_iter().next() else {
                return Ok(None);
            };
            let elapsed_lease = task.state == TaskState::Expired
                || (task.state == TaskState::Claimed
                    && task
                        .lease
                        .as_ref()
                        .is_some_and(|lease| now >= lease.expires_at));
            if elapsed_lease && task.attempts >= snapshot.state().limits.max_task_retries {
                let exhausted = campaign.store.expire_task(
                    task.request.task_id.as_str(),
                    task_generation,
                    now,
                )?;
                let exhausted_snapshot = campaign.store.snapshot()?;
                self.service.observe_state(exhausted_snapshot.state());
                if exhausted.task.state != TaskState::Failed {
                    return Err(GraphStoreError::InvalidState {
                        reason: "retry exhaustion did not produce a terminal failed task"
                            .to_string(),
                    }
                    .into());
                }
                if let Some(publication) = pending_worker_publication_for_retry_exhaustion(
                    &campaign,
                    &exhausted_snapshot,
                    &task.request.task_id,
                )? {
                    let mut state = self
                        .service
                        .state
                        .lock()
                        .map_err(|_| GraphServiceError::Poisoned)?;
                    match publication.task_kind {
                        TaskKind::AcquireEvidence => {
                            state
                                .pending_stalker_acquisition_hunts
                                .insert(publication.hunt_id.clone());
                        }
                        TaskKind::FalsifyHypothesis => {
                            state
                                .pending_stalker_falsification_hunts
                                .insert(publication.hunt_id.clone());
                        }
                        TaskKind::ChallengeEdge => {}
                    }
                    state.pending_worker_publications.insert(
                        (publication.campaign_index, publication.task_id.clone()),
                        publication,
                    );
                }
                continue;
            }
            let request = if task.request.claimant == self.claimant {
                task.request.clone()
            } else if task.state == TaskState::Expired
                || (task.state == TaskState::Claimed
                    && task
                        .lease
                        .as_ref()
                        .is_some_and(|lease| now >= lease.expires_at))
            {
                TaskClaimRequest::new(
                    task.request.task_id.clone(),
                    task.request.kind,
                    task.request.target.clone(),
                    task.request.role,
                    self.claimant.clone(),
                    task.request.evidence_scope.clone(),
                    task.request.requested_at,
                )?
            } else {
                return Err(GraphServiceError::WorkerIdentityMismatch {
                    expected: task.request.claimant,
                    observed: self.claimant.clone(),
                });
            };
            let proof = TaskCapabilityProof::new(
                request.task_id.clone(),
                request.claimant.clone(),
                request.role,
                request.kind,
                request.canonical_digest()?,
                &self.signer,
                worker_scope(request.kind),
            )?;
            let lease_ms = GRAPH_LEASE_MS.min(self.service.config.max_lease_ms).max(1);
            let mut state = self
                .service
                .state
                .lock()
                .map_err(|_| GraphServiceError::Poisoned)?;
            // Priority lookup intentionally happens outside the coordinator
            // mutex so an advisory-memory failure can record degradation
            // without recursively locking service state. Revalidate the
            // selected durable generation after acquiring the claim mutex;
            // another worker may have won while priorities were computed.
            let current_snapshot = campaign.store.snapshot()?;
            let still_current = current_snapshot
                .state()
                .tasks
                .get(&request.task_id)
                .is_some_and(|record| {
                    record.generation == task_generation && task_is_claimable_at(&record.task, now)
                });
            if !still_current {
                drop(state);
                continue;
            }
            let claim = state.coordinator.ledger_mut().claim_or_reclaim_task(
                campaign.store.as_ref(),
                request.clone(),
                now,
                lease_ms,
                proof,
            )?;
            let claimed_snapshot = campaign.store.snapshot()?;
            let task_generation = claimed_snapshot
                .state()
                .tasks
                .get(&claim.task_id)
                .ok_or_else(|| GraphServiceError::TaskUnavailable(claim.task_id.clone()))?
                .generation;
            self.service.observe_state(claimed_snapshot.state());
            return Ok(Some(ClaimedGraphTask {
                claim,
                request,
                task_generation,
            }));
        }
    }

    pub fn renew(
        &self,
        claimed: &mut ClaimedGraphTask,
        now: GraphLogicalTime,
    ) -> Result<(), GraphServiceError> {
        if !self.capabilities.contains(&claimed.request.kind) {
            return Err(GraphServiceError::MissingCapability(claimed.request.kind));
        }
        let _guard = self
            .service
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let campaign = self.service.active_campaign()?;
        let renewed = campaign.store.renew_task(
            claimed.claim.task_id.as_str(),
            claimed.task_generation,
            &claimed.claim.lease_id,
            claimed.claim.fencing_token,
            now,
            GRAPH_LEASE_MS.min(self.service.config.max_lease_ms).max(1),
        )?;
        claimed.task_generation = renewed.task_generation;
        Ok(())
    }

    pub fn complete_stalker_hunt(
        &self,
        hunt_id: &str,
        completed_at: GraphLogicalTime,
        final_confidence_basis_points: u16,
        ambiguous: bool,
        selected_malicious_interpretation: bool,
    ) -> Result<StalkerGraphCompletion, GraphServiceError> {
        let _operation = self
            .service
            .operation
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let completed_at = self.service.nonretrograde_time(completed_at)?;
        if !self.capabilities.contains(&TaskKind::AcquireEvidence) {
            return Err(GraphServiceError::MissingCapability(
                TaskKind::AcquireEvidence,
            ));
        }
        let mut report = StalkerGraphCompletion::default();
        while let Some(claimed) = self.claim_matching(completed_at, false, |task, snapshot| {
            task.request.kind == TaskKind::AcquireEvidence
                && task_matches_hunt(task, hunt_id, snapshot)
        })? {
            let projected = self.complete_acquisition(claimed, completed_at)?;
            report.acquisitions = report.acquisitions.saturating_add(1);
            report.memory_records_projected =
                report.memory_records_projected.saturating_add(projected);
        }
        if selected_malicious_interpretation
            && !ambiguous
            && final_confidence_basis_points >= 7_000
            && self.capabilities.contains(&TaskKind::FalsifyHypothesis)
        {
            while let Some(claimed) =
                self.claim_matching(completed_at, false, |task, snapshot| {
                    task.request.kind == TaskKind::FalsifyHypothesis
                        && task_matches_hunt(task, hunt_id, snapshot)
                })?
            {
                let projected = self.complete_falsification(claimed, completed_at)?;
                report.falsifications = report.falsifications.saturating_add(1);
                report.memory_records_projected =
                    report.memory_records_projected.saturating_add(projected);
            }
        } else if self.capabilities.contains(&TaskKind::FalsifyHypothesis) {
            while let Some(claimed) =
                self.claim_matching(completed_at, false, |task, snapshot| {
                    task.request.kind == TaskKind::FalsifyHypothesis
                        && task_matches_hunt(task, hunt_id, snapshot)
                })?
            {
                let projected = self.complete_falsification_no_finding(claimed, completed_at)?;
                report.falsification_no_findings =
                    report.falsification_no_findings.saturating_add(1);
                report.memory_records_projected =
                    report.memory_records_projected.saturating_add(projected);
            }
        }
        Ok(report)
    }

    /// Close Stalker-owned graph work when its durable investigation reached
    /// a terminal failure and cannot produce a semantic finding. These signed
    /// no-finding publications keep failed jobs from remaining claimable on
    /// every subsequent tick and restart.
    pub fn close_failed_stalker_hunt(
        &self,
        hunt_id: &str,
        completed_at: GraphLogicalTime,
    ) -> Result<StalkerGraphCompletion, GraphServiceError> {
        let _operation = self
            .service
            .operation
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let completed_at = self.service.nonretrograde_time(completed_at)?;
        if !self.capabilities.contains(&TaskKind::AcquireEvidence) {
            return Err(GraphServiceError::MissingCapability(
                TaskKind::AcquireEvidence,
            ));
        }
        let mut report = StalkerGraphCompletion::default();
        while let Some(claimed) = self.claim_matching(completed_at, false, |task, snapshot| {
            task.request.kind == TaskKind::AcquireEvidence
                && task_matches_hunt(task, hunt_id, snapshot)
        })? {
            let projected = self.complete_acquisition_no_finding(claimed, completed_at)?;
            report.acquisition_no_findings = report.acquisition_no_findings.saturating_add(1);
            report.memory_records_projected =
                report.memory_records_projected.saturating_add(projected);
        }
        if self.capabilities.contains(&TaskKind::FalsifyHypothesis) {
            while let Some(claimed) =
                self.claim_matching(completed_at, false, |task, snapshot| {
                    task.request.kind == TaskKind::FalsifyHypothesis
                        && task_matches_hunt(task, hunt_id, snapshot)
                })?
            {
                let projected = self.complete_falsification_no_finding(claimed, completed_at)?;
                report.falsification_no_findings =
                    report.falsification_no_findings.saturating_add(1);
                report.memory_records_projected =
                    report.memory_records_projected.saturating_add(projected);
            }
        }
        Ok(report)
    }

    pub fn next_challenge_context(
        &self,
        now: GraphLogicalTime,
    ) -> Result<Option<GraphChallengeContext>, GraphServiceError> {
        if !self.capabilities.contains(&TaskKind::ChallengeEdge) {
            return Err(GraphServiceError::MissingCapability(
                TaskKind::ChallengeEdge,
            ));
        }
        let memory_priority_available = self.service.repair_memory_projection_for_work()?;
        let campaign = self.service.active_campaign()?;
        let snapshot = campaign.store.snapshot()?;
        let eligible = snapshot
            .tasks()
            .filter(|task| {
                task_is_claimable_at(&task.task, now)
                    && task.task.request.kind == TaskKind::ChallengeEdge
            })
            .map(|task| task.task.clone())
            .collect::<Vec<_>>();
        let priorities = self.service.priority_projections_for_tasks(
            &campaign,
            &eligible,
            &snapshot,
            now,
            memory_priority_available,
        )?;
        let mut candidates = eligible
            .into_iter()
            .zip(priorities)
            .map(|(task, priority)| {
                let key = swarm_core::hypothesis_graph::GraphSchedulerKey::new(
                    task.request.requested_at,
                    task.request.kind,
                    priority.adjusted_priority_basis_points,
                    task.request.task_id.clone(),
                )?;
                Ok((key, task))
            })
            .collect::<Result<Vec<_>, GraphServiceError>>()?;
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        let Some((_, task)) = candidates.into_iter().next() else {
            return Ok(None);
        };
        let hunt_id =
            hunt_for_evidence_scope(&task.request.evidence_scope.evidence_ids, snapshot.graph())
                .unwrap_or_else(|| task.request.task_id.to_string());
        Ok(Some(GraphChallengeContext {
            graph_id: campaign.graph_id,
            task_id: task.request.task_id,
            hunt_id,
            evidence_ids: task.request.evidence_scope.evidence_ids,
        }))
    }

    pub fn complete_challenge(
        &self,
        task_id: &TaskId,
        completed_at: GraphLogicalTime,
    ) -> Result<bool, GraphServiceError> {
        let _operation = self
            .service
            .operation
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let completed_at = self.service.nonretrograde_time(completed_at)?;
        let Some(claimed) = self.claim_matching(completed_at, false, |task, _| {
            task.request.kind == TaskKind::ChallengeEdge && &task.request.task_id == task_id
        })?
        else {
            return Ok(false);
        };
        self.complete_edge_challenge(claimed, completed_at)?;
        Ok(true)
    }

    /// Complete a challenge without a semantic finding when its durable
    /// investigation terminated unsuccessfully. The scoped evidence remains
    /// attached to the signed terminal so validation can prove what was
    /// investigated without manufacturing a challenge decision.
    pub fn complete_challenge_no_finding(
        &self,
        task_id: &TaskId,
        completed_at: GraphLogicalTime,
    ) -> Result<bool, GraphServiceError> {
        let _operation = self
            .service
            .operation
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let completed_at = self.service.nonretrograde_time(completed_at)?;
        let Some(claimed) = self.claim_matching(completed_at, false, |task, _| {
            task.request.kind == TaskKind::ChallengeEdge && &task.request.task_id == task_id
        })?
        else {
            return Ok(false);
        };
        let evidence_ids = claimed.request.evidence_scope.evidence_ids.clone();
        let evidence = evidence_for_scope(
            &evidence_ids,
            &self.service.active_campaign()?.store.snapshot()?,
        )?;
        self.accept_terminal(
            claimed,
            completed_at,
            TerminalPublication {
                kind: TaskCompletionKind::NoFinding,
                evidence,
                decision: None,
                memory: None,
            },
        )?;
        Ok(true)
    }

    fn complete_acquisition(
        &self,
        claimed: ClaimedGraphTask,
        completed_at: GraphLogicalTime,
    ) -> Result<usize, GraphServiceError> {
        let TaskTarget::Evidence { evidence_id } = &claimed.request.target else {
            return Err(GraphServiceError::TaskUnavailable(claimed.claim.task_id));
        };
        let snapshot = self.service.active_campaign()?.store.snapshot()?;
        let evidence = snapshot
            .graph()
            .evidence
            .get(evidence_id)
            .cloned()
            .ok_or(GraphAdmissionError::UnknownEvidence)?;
        self.accept_terminal(
            claimed,
            completed_at,
            TerminalPublication {
                kind: TaskCompletionKind::EvidenceAdded,
                evidence: vec![evidence],
                decision: None,
                memory: None,
            },
        )
    }

    fn complete_acquisition_no_finding(
        &self,
        claimed: ClaimedGraphTask,
        completed_at: GraphLogicalTime,
    ) -> Result<usize, GraphServiceError> {
        let TaskTarget::Evidence { .. } = &claimed.request.target else {
            return Err(GraphServiceError::TaskUnavailable(claimed.claim.task_id));
        };
        self.accept_terminal(
            claimed,
            completed_at,
            TerminalPublication {
                kind: TaskCompletionKind::NoFinding,
                evidence: Vec::new(),
                decision: None,
                memory: None,
            },
        )
    }

    fn complete_edge_challenge(
        &self,
        claimed: ClaimedGraphTask,
        completed_at: GraphLogicalTime,
    ) -> Result<usize, GraphServiceError> {
        let evidence_ids = claimed.request.evidence_scope.evidence_ids.clone();
        let evidence = evidence_for_scope(
            &evidence_ids,
            &self.service.active_campaign()?.store.snapshot()?,
        )?;
        let evidence_id = evidence_ids
            .iter()
            .next()
            .ok_or(GraphAdmissionError::UnknownEvidence)?;
        let decision = DecisionRecord::new(
            DecisionKind::Challenge,
            scoped_hypothesis_id("malicious-activity", evidence_id),
            evidence_ids.iter().cloned(),
            GraphProducerRole::Challenger,
            claimed.request.claimant.clone(),
            completed_at,
            "correlation review challenged the event-to-asset causal edge",
        )?
        .signed_with(&self.signer, "weaver-edge-challenge-adjudication")?;
        self.accept_terminal(
            claimed,
            completed_at,
            TerminalPublication {
                kind: TaskCompletionKind::EdgeChallenged,
                evidence,
                decision: Some(decision),
                memory: None,
            },
        )
    }

    fn complete_falsification(
        &self,
        claimed: ClaimedGraphTask,
        completed_at: GraphLogicalTime,
    ) -> Result<usize, GraphServiceError> {
        let TaskTarget::Hypothesis { hypothesis_id } = &claimed.request.target else {
            return Err(GraphServiceError::TaskUnavailable(claimed.claim.task_id));
        };
        let evidence_ids = claimed.request.evidence_scope.evidence_ids.clone();
        let decision = DecisionRecord::new(
            DecisionKind::Falsify,
            hypothesis_id.clone(),
            evidence_ids.iter().cloned(),
            GraphProducerRole::Falsifier,
            claimed.request.claimant.clone(),
            completed_at,
            "completed investigation falsified the benign authorized alternative",
        )?
        .with_resulting_status(HypothesisStatus::Falsified)?
        .signed_with(&self.signer, "stalker-hypothesis-falsifier-adjudication")?;
        let provenance = MemoryProvenance::new(
            claimed.request.claimant.clone(),
            evidence_ids.iter().cloned(),
        )
        .signed_with(
            &self.signer,
            GraphProducerRole::Falsifier,
            "stalker-memory-provenance",
        )?;
        let campaign = self.service.active_campaign()?;
        let snapshot = campaign.store.snapshot()?;
        let evidence = evidence_for_scope(&evidence_ids, &snapshot)?;
        let evidence_id = evidence_ids
            .iter()
            .next()
            .ok_or(GraphAdmissionError::UnknownEvidence)?;
        let related_edges = snapshot
            .graph()
            .edges
            .values()
            .filter(|edge| !edge.source_evidence_ids.is_disjoint(&evidence_ids))
            .map(|edge| edge.edge_id.clone())
            .collect::<Vec<_>>();
        let memory = StrategyMemory::new(
            campaign.graph_id,
            scoped_hypothesis_id("malicious-activity", evidence_id),
            HypothesisDelta::new(related_edges, [], []),
            evidence_ids.iter().cloned().map(|evidence_id| {
                swarm_core::hypothesis_graph::EvidenceUtility::new(evidence_id, 9_000)
            }),
            [hypothesis_id.clone()],
            MemoryOutcome::Confirmed,
            provenance,
        )?
        .signed_with(
            &self.signer,
            GraphProducerRole::Falsifier,
            "stalker-strategy-memory",
        )?;
        let expiry = StrategyMemoryExpiryEnvelope::new_with_config(
            &memory,
            completed_at,
            self.service.config.max_memory_ttl_ticks,
            &self.service.config,
            &self.signer,
        )?;
        self.accept_terminal(
            claimed,
            completed_at,
            TerminalPublication {
                kind: TaskCompletionKind::HypothesisFalsified,
                evidence,
                decision: Some(decision),
                memory: Some((memory, expiry)),
            },
        )
    }

    fn complete_falsification_no_finding(
        &self,
        claimed: ClaimedGraphTask,
        completed_at: GraphLogicalTime,
    ) -> Result<usize, GraphServiceError> {
        let TaskTarget::Hypothesis { .. } = &claimed.request.target else {
            return Err(GraphServiceError::TaskUnavailable(claimed.claim.task_id));
        };
        let evidence_ids = claimed.request.evidence_scope.evidence_ids.clone();
        let evidence = evidence_for_scope(
            &evidence_ids,
            &self.service.active_campaign()?.store.snapshot()?,
        )?;
        self.accept_terminal(
            claimed,
            completed_at,
            TerminalPublication {
                kind: TaskCompletionKind::NoFinding,
                evidence,
                decision: None,
                memory: None,
            },
        )
    }

    fn accept_terminal(
        &self,
        claimed: ClaimedGraphTask,
        completed_at: GraphLogicalTime,
        publication: TerminalPublication,
    ) -> Result<usize, GraphServiceError> {
        let TerminalPublication {
            kind,
            evidence,
            decision,
            memory,
        } = publication;
        let completion_kind = kind.clone();
        if !self.capabilities.contains(&claimed.request.kind) {
            return Err(GraphServiceError::MissingCapability(claimed.request.kind));
        }
        let task_id = claimed.claim.task_id.clone();
        let task_kind = claimed.request.kind;
        let campaign = self.service.active_campaign()?;
        let mut state = self
            .service
            .state
            .lock()
            .map_err(|_| GraphServiceError::Poisoned)?;
        let snapshot = campaign.store.snapshot()?;
        let evidence_ids = match kind {
            TaskCompletionKind::EvidenceAdded => evidence
                .iter()
                .map(|item| item.evidence_id.clone())
                .collect::<BTreeSet<_>>(),
            TaskCompletionKind::EdgeChallenged | TaskCompletionKind::HypothesisFalsified => {
                claimed.request.evidence_scope.evidence_ids.clone()
            }
            TaskCompletionKind::NoFinding if claimed.request.kind == TaskKind::AcquireEvidence => {
                BTreeSet::new()
            }
            TaskCompletionKind::NoFinding => claimed.request.evidence_scope.evidence_ids.clone(),
        };
        let summary_digest = sha256_hex(format!("{:?}:{}", kind, claimed.claim.task_id).as_bytes());
        let completion = TaskCompletion::new(
            kind,
            claimed.request.claimant.clone(),
            completed_at,
            evidence_ids.iter().cloned(),
            summary_digest,
        )?;
        let decision_link = decision
            .as_ref()
            .map(|decision| {
                TaskDecisionLink::new(
                    claimed.claim.task_id.clone(),
                    claimed.request.target.clone(),
                    evidence_ids.iter().cloned(),
                    Some(decision.decision_id.clone()),
                )
            })
            .transpose()?;
        let envelope = TaskTerminalEnvelope::new(
            claimed.claim.task_id.clone(),
            claimed.claim.idempotency_key.clone(),
            claimed.claim.lease_id.clone(),
            claimed.claim.fencing_token,
            completion,
            decision_link,
            claimed.request.claimant.clone(),
            claimed.claim.capability_proof.clone(),
        )?
        .signed_with(&self.signer, worker_terminal_scope(claimed.request.kind))?;
        let (memory, memory_expiry) = memory
            .map(|(memory, expiry)| (Some(memory), Some(expiry)))
            .unwrap_or((None, None));
        let committed = state.coordinator.ledger_mut().accept_terminal_once(
            campaign.store.as_ref(),
            snapshot.revision(),
            &claimed.claim,
            envelope,
            evidence,
            decision,
            memory,
            memory_expiry,
        )?;
        match task_kind {
            TaskKind::AcquireEvidence => {
                state.metrics.snapshot.completed_acquisitions = state
                    .metrics
                    .snapshot
                    .completed_acquisitions
                    .saturating_add(1);
            }
            TaskKind::ChallengeEdge => {
                state.metrics.snapshot.completed_challenges = state
                    .metrics
                    .snapshot
                    .completed_challenges
                    .saturating_add(1);
            }
            TaskKind::FalsifyHypothesis => {
                state.metrics.snapshot.completed_falsifications = state
                    .metrics
                    .snapshot
                    .completed_falsifications
                    .saturating_add(1);
                if completion_kind == TaskCompletionKind::NoFinding {
                    state.metrics.snapshot.falsification_no_findings = state
                        .metrics
                        .snapshot
                        .falsification_no_findings
                        .saturating_add(1);
                }
            }
        }
        if let Some(publication) =
            pending_worker_publication_for_task(&campaign, &committed, &task_id)?
        {
            match publication.task_kind {
                TaskKind::AcquireEvidence => {
                    state
                        .pending_stalker_acquisition_hunts
                        .insert(publication.hunt_id.clone());
                }
                TaskKind::FalsifyHypothesis => {
                    state
                        .pending_stalker_falsification_hunts
                        .insert(publication.hunt_id.clone());
                }
                TaskKind::ChallengeEdge => {}
            }
            state.pending_worker_publications.insert(
                (publication.campaign_index, publication.task_id.clone()),
                publication,
            );
        }
        drop(state);
        if let Some(metrics) = &self.service.prometheus {
            metrics.observe_hypothesis_graph_completion(task_kind, &completion_kind);
        }

        let projected = self.service.record_post_commit_memory_projection(
            campaign.index,
            campaign.memory.project_committed_task(&committed, &task_id),
        )?;
        let current = campaign.store.snapshot()?;
        self.service.observe_state(current.state());
        Ok(projected)
    }
}

fn task_blocks_worker_rebind_at(
    state: TaskState,
    lease_expires_at: Option<GraphLogicalTime>,
    now: GraphLogicalTime,
) -> bool {
    state == TaskState::Pending
        || (state == TaskState::Claimed && lease_expires_at.is_none_or(|expiry| now < expiry))
}

fn task_is_visible_to_claimant(
    state: TaskState,
    persisted_claimant: &AgentId,
    lease_expires_at: Option<GraphLogicalTime>,
    current_claimant: &AgentId,
    now: GraphLogicalTime,
) -> bool {
    match state {
        // Expiry releases the prior claimant. A replacement worker registered
        // after restart must rediscover the task so its next claim can issue a
        // fresh claimant-bound request and fencing token.
        TaskState::Expired => true,
        TaskState::Claimed if lease_expires_at.is_some_and(|expiry| now >= expiry) => true,
        TaskState::Pending | TaskState::Claimed => persisted_claimant == current_claimant,
        TaskState::Completed | TaskState::Failed => false,
    }
}

const fn base_task_priority(kind: TaskKind) -> u16 {
    match kind {
        TaskKind::AcquireEvidence => 7_000,
        TaskKind::ChallengeEdge => 6_000,
        TaskKind::FalsifyHypothesis => 8_000,
    }
}

fn task_is_terminal(state: TaskState) -> bool {
    matches!(state, TaskState::Completed | TaskState::Failed)
}

fn signed_runtime_edge(
    from: &GraphNodeId,
    to: &GraphNodeId,
    relation: CausalRelation,
    evidence: &swarm_core::hypothesis_graph::EvidenceEnvelope,
    signer: &Keypair,
    confidence_basis_points: u16,
    signer_scope: &str,
) -> Result<CausalEdge, GraphServiceError> {
    Ok(CausalEdge::new(
        from,
        to,
        relation,
        confidence_basis_points,
        [evidence.evidence_id.clone()],
        GraphProducerRole::Hunter,
        AgentId::from_public_key_hex(&signer.public_key().to_hex()),
        evidence.clock.observed_at,
        EdgeState::Proposed,
    )?
    .signed_with(signer, signer_scope)?)
}

fn inferred_causal_records(
    normalized_nodes: Vec<GraphNode>,
    inferred: Vec<InferredCausalRelation>,
    evidence: &swarm_core::hypothesis_graph::EvidenceEnvelope,
    signer: &Keypair,
    confidence_basis_points: u16,
) -> Result<(Vec<GraphNode>, Vec<CausalEdge>), GraphServiceError> {
    let mut required_node_ids = inferred
        .iter()
        .flat_map(|candidate| [candidate.from.clone(), candidate.to.clone()])
        .collect::<BTreeSet<_>>();
    required_node_ids.extend(evidence.entity_ids());
    required_node_ids.extend(normalized_nodes.iter().filter_map(|node| match node {
        GraphNode::Process(process) => process.parent_node_id.clone(),
        _ => None,
    }));
    let available_node_ids = normalized_nodes
        .iter()
        .map(|node| node.id().clone())
        .collect::<BTreeSet<_>>();
    if let Some(node_id) = required_node_ids.difference(&available_node_ids).next() {
        return Err(GraphServiceError::Admission(
            GraphAdmissionError::InvalidField {
                field: "inference.entity_ids".to_string(),
                reason: format!("evidence entity `{node_id}` has no normalized graph node"),
            },
        ));
    }
    let edges = inferred
        .into_iter()
        .map(|candidate| {
            signed_runtime_edge(
                &candidate.from,
                &candidate.to,
                candidate.relation,
                evidence,
                signer,
                confidence_basis_points,
                "runtime-replay-inferred-edge",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((normalized_nodes, edges))
}

fn fallback_observation_records(
    mut normalized_nodes: Vec<GraphNode>,
    replay: &ReplayBundle,
    evidence: &swarm_core::hypothesis_graph::EvidenceEnvelope,
    signer: &Keypair,
    confidence_basis_points: u16,
) -> Result<(Vec<GraphNode>, Vec<CausalEdge>), GraphServiceError> {
    let available_node_ids = normalized_nodes
        .iter()
        .map(|node| node.id().clone())
        .collect::<BTreeSet<_>>();
    if let Some(node_id) = evidence
        .entity_ids()
        .into_iter()
        .find(|node_id| !available_node_ids.contains(node_id))
    {
        return Err(GraphAdmissionError::InvalidField {
            field: "evidence.entity_ids".to_string(),
            reason: format!("evidence entity `{node_id}` has no normalized graph node"),
        }
        .into());
    }
    let existing_event_node_id = normalized_nodes.iter().find_map(|node| match node {
        GraphNode::Event(event) => Some(event.node_id.clone()),
        _ => None,
    });
    let event_node_id = match existing_event_node_id {
        Some(node_id) => node_id,
        None => {
            // Normalizers currently emit an event node for every telemetry
            // family. Preserve a fail-closed fallback for future typed inputs
            // without duplicating an already-normalized event identity.
            let event_node = swarm_core::hypothesis_graph::EventNode::new(
                "runtime_replay",
                replay.event.event_id.clone(),
                evidence.clock.observed_at,
            )?;
            let node_id = event_node.node_id.clone();
            normalized_nodes.push(GraphNode::Event(event_node));
            node_id
        }
    };
    let asset_node_id = if let Some(node_id) = normalized_nodes.iter().find_map(|node| match node {
        GraphNode::Asset(asset) => Some(asset.node_id.clone()),
        _ => None,
    }) {
        node_id
    } else {
        let asset_kind = if replay.event.host_id.is_some() {
            "host"
        } else {
            "telemetry_source"
        };
        let asset_material = replay
            .event
            .host_id
            .as_deref()
            .unwrap_or(replay.event.source.as_str());
        let asset_node = AssetNode::new(sha256_hex(asset_material.as_bytes()), asset_kind)?;
        let node_id = asset_node.node_id.clone();
        normalized_nodes.push(GraphNode::Asset(asset_node));
        node_id
    };
    let edge = signed_runtime_edge(
        &event_node_id,
        &asset_node_id,
        CausalRelation::ObservedIn,
        evidence,
        signer,
        confidence_basis_points,
        "runtime-replay-observation-edge",
    )?;
    Ok((normalized_nodes, vec![edge]))
}

fn persisted_threat_intel_matches(
    replay: &ReplayBundle,
) -> Result<Vec<(String, ThreatIntelEntry)>, GraphAdmissionError> {
    let mut matches = BTreeMap::<String, ThreatIntelEntry>::new();
    let mut examined_matches = 0_usize;
    for finding in &replay.findings {
        let Some(value) = finding.evidence.get("threat_intel_matches") else {
            continue;
        };
        let values = value
            .as_array()
            .ok_or_else(|| GraphAdmissionError::InvalidField {
                field: "replay.findings.evidence.threat_intel_matches".to_string(),
                reason: "must be an array of persisted threat-intelligence entries".to_string(),
            })?;
        for value in values {
            examined_matches = examined_matches.saturating_add(1);
            if examined_matches > MAX_REPLAY_THREAT_INTEL_MATCHES {
                return Err(GraphAdmissionError::ResourceLimitExceeded {
                    resource: "replay.threat_intel_matches".to_string(),
                    limit: MAX_REPLAY_THREAT_INTEL_MATCHES,
                });
            }
            let entry: ThreatIntelEntry =
                serde_json::from_value(value.clone()).map_err(|error| {
                    GraphAdmissionError::InvalidField {
                        field: "replay.findings.evidence.threat_intel_matches".to_string(),
                        reason: format!("contains an invalid persisted entry: {error}"),
                    }
                })?;
            let bytes = canonical_json_bytes(&entry).map_err(|error| {
                GraphAdmissionError::InvalidField {
                    field: "replay.findings.evidence.threat_intel_matches".to_string(),
                    reason: format!("cannot canonicalize a persisted entry: {error}"),
                }
            })?;
            matches.entry(sha256_hex(&bytes)).or_insert(entry);
        }
    }
    Ok(matches.into_iter().collect())
}

fn replay_seed_logical_time(
    replay_created_at_ms: i64,
    logical_time_high_water: GraphLogicalTime,
    minimum_logical_time: Option<GraphLogicalTime>,
) -> Result<GraphLogicalTime, GraphAdmissionError> {
    let logical_time = GraphLogicalTime::new(
        replay_created_at_ms
            .max(logical_time_high_water.as_millis())
            .max(minimum_logical_time.map_or(i64::MIN, GraphLogicalTime::as_millis)),
    );
    logical_time.validate()?;
    Ok(logical_time)
}

fn replay_hypothesis_seed(
    graph_id: GraphId,
    malicious: &HypothesisId,
    benign: &HypothesisId,
    evidence_ids: &BTreeSet<EvidenceId>,
    provenance: &EvidenceId,
    logical_time: GraphLogicalTime,
) -> Result<HypothesisSeedInput, GraphAdmissionError> {
    let assessments = vec![
        HypothesisSeedAssessment {
            hypothesis_id: malicious.clone(),
            evidence_ids: evidence_ids.iter().cloned().collect(),
            disposition: HypothesisDisposition::Unresolved,
            provenance: provenance.clone(),
        },
        HypothesisSeedAssessment {
            hypothesis_id: benign.clone(),
            evidence_ids: evidence_ids.iter().cloned().collect(),
            disposition: HypothesisDisposition::Contradicts,
            provenance: provenance.clone(),
        },
    ];
    HypothesisSeedInput::new(
        graph_id,
        vec![malicious.clone(), benign.clone()],
        assessments,
        logical_time,
    )
}

fn campaign_requires_rotation(
    snapshot: &GraphStoreSnapshot,
    evidence: &[swarm_core::hypothesis_graph::EvidenceEnvelope],
    candidate_node_ids: &BTreeSet<GraphNodeId>,
    candidate_edges: &[CausalEdge],
    task_target_count: usize,
) -> Result<bool, GraphServiceError> {
    let state = snapshot.state();
    let has_retained_work =
        !state.graph.evidence.is_empty() || !state.hypotheses.is_empty() || !state.tasks.is_empty();
    if !has_retained_work {
        // Let ordinary admission return the precise configuration error when
        // a single replay cannot fit even in an empty campaign.
        return Ok(false);
    }
    let limits = &state.limits;
    let retained_evidence_bytes = state
        .graph
        .evidence
        .values()
        .map(|item| item.canonical_bytes().map(|bytes| bytes.len()))
        .try_fold(0_usize, |total, size| {
            size.map(|size| total.saturating_add(size))
        })?;
    let added_evidence_bytes = evidence
        .iter()
        .map(|item| item.canonical_bytes().map(|bytes| bytes.len()))
        .try_fold(0_usize, |total, size| {
            size.map(|size| total.saturating_add(size))
        })?;
    let added_node_count = candidate_node_ids
        .iter()
        .filter(|node_id| !state.graph.nodes.contains_key(*node_id))
        .count();
    let added_edge_count = candidate_edges
        .iter()
        .map(|edge| &edge.edge_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|edge_id| !state.graph.edges.contains_key(*edge_id))
        .count();
    // Every admitted replay creates one falsification task, and a successful
    // falsification can append one strategy-memory record. Count committed
    // memories plus only nonterminal reservations: no-finding and exhausted
    // terminal tasks cannot publish memory and must release their capacity.
    let committed_memory_records = state
        .terminal_outbox
        .values()
        .filter(|entry| entry.memory.is_some())
        .count();
    let pending_memory_reservations = state
        .tasks
        .values()
        .filter(|task| {
            task.task.request.kind == TaskKind::FalsifyHypothesis
                && !task_is_terminal(task.task.state)
        })
        .count();
    Ok(
        state.graph.evidence.len().saturating_add(evidence.len()) > limits.max_nodes
            || state.graph.nodes.len().saturating_add(added_node_count) > limits.max_nodes
            || state.graph.edges.len().saturating_add(added_edge_count) > limits.max_edges
            || retained_evidence_bytes.saturating_add(added_evidence_bytes)
                > limits.max_evidence_bytes
            || state.hypotheses.len().saturating_add(2) > limits.max_hypotheses
            || state.tasks.len().saturating_add(task_target_count) > limits.max_tasks
            || committed_memory_records
                .saturating_add(pending_memory_reservations)
                .saturating_add(1)
                > limits.max_memory_records
            || topology_requires_rotation(state, candidate_edges),
    )
}

fn topology_requires_rotation(state: &GraphStoreState, candidate_edges: &[CausalEdge]) -> bool {
    let limits = &state.limits;
    // A candidate that cannot fit an empty campaign must reach ordinary
    // admission so the operator receives the precise topology error.
    if !topology_within_limits(
        candidate_edges.iter(),
        limits.max_graph_fan_out,
        limits.max_graph_depth,
    ) {
        return false;
    }
    !topology_within_limits(
        state.graph.edges.values().chain(candidate_edges),
        limits.max_graph_fan_out,
        limits.max_graph_depth,
    )
}

fn topology_within_limits<'a>(
    edges: impl IntoIterator<Item = &'a CausalEdge>,
    max_fan_out: usize,
    max_depth: usize,
) -> bool {
    let mut edge_ids = BTreeSet::new();
    let mut outgoing = BTreeMap::<GraphNodeId, usize>::new();
    let mut adjacency = BTreeMap::<GraphNodeId, BTreeSet<GraphNodeId>>::new();
    for edge in edges {
        if !edge_ids.insert(edge.edge_id.clone()) {
            continue;
        }
        let count = outgoing.entry(edge.from.clone()).or_default();
        *count = count.saturating_add(1);
        if *count > max_fan_out {
            return false;
        }
        adjacency
            .entry(edge.from.clone())
            .or_default()
            .insert(edge.to.clone());
    }
    topology_depth(&adjacency).is_some_and(|depth| depth <= max_depth)
}

fn topology_depth(adjacency: &BTreeMap<GraphNodeId, BTreeSet<GraphNodeId>>) -> Option<usize> {
    fn visit(
        node: &GraphNodeId,
        adjacency: &BTreeMap<GraphNodeId, BTreeSet<GraphNodeId>>,
        visiting: &mut BTreeSet<GraphNodeId>,
        memo: &mut BTreeMap<GraphNodeId, usize>,
    ) -> Option<usize> {
        if let Some(depth) = memo.get(node) {
            return Some(*depth);
        }
        if !visiting.insert(node.clone()) {
            return None;
        }
        let mut depth = 1_usize;
        if let Some(children) = adjacency.get(node) {
            for child in children {
                depth = depth.max(visit(child, adjacency, visiting, memo)?.saturating_add(1));
            }
        }
        visiting.remove(node);
        memo.insert(node.clone(), depth);
        Some(depth)
    }

    let mut memo = BTreeMap::new();
    let mut maximum = 0_usize;
    for node in adjacency.keys() {
        maximum = maximum.max(visit(node, adjacency, &mut BTreeSet::new(), &mut memo)?);
    }
    Some(maximum)
}

fn task_is_claimable_at(task: &TaskRecord, now: GraphLogicalTime) -> bool {
    task.state == TaskState::Pending
        || task.state == TaskState::Expired
        || (task.state == TaskState::Claimed
            && task
                .lease
                .as_ref()
                .is_some_and(|lease| now >= lease.expires_at))
}

fn required_worker_kinds() -> [TaskKind; 3] {
    [
        TaskKind::AcquireEvidence,
        TaskKind::ChallengeEdge,
        TaskKind::FalsifyHypothesis,
    ]
}

fn graph_id_for_campaign(key: &Keypair, index: u64) -> GraphId {
    let family = format!("graph:runtime:{}", sha256_hex(key.public_key().as_bytes()));
    if index == 0 {
        GraphId::new(family)
    } else {
        GraphId::new(format!("{family}:campaign:{index}"))
    }
}

fn scoped_hypothesis_id(kind: &str, evidence_id: &EvidenceId) -> HypothesisId {
    HypothesisId::new(format!(
        "hypothesis:{kind}:{}",
        sha256_hex(evidence_id.as_str().as_bytes())
    ))
}

fn worker_scope(kind: TaskKind) -> &'static str {
    match kind {
        TaskKind::AcquireEvidence => "stalker-acquire-capability",
        TaskKind::ChallengeEdge => "weaver-challenge-capability",
        TaskKind::FalsifyHypothesis => "stalker-falsify-capability",
    }
}

fn worker_terminal_scope(kind: TaskKind) -> &'static str {
    match kind {
        TaskKind::AcquireEvidence => "stalker-acquire-terminal",
        TaskKind::ChallengeEdge => "weaver-challenge-terminal",
        TaskKind::FalsifyHypothesis => "stalker-falsify-terminal",
    }
}

fn task_matches_hunt(task: &TaskRecord, hunt_id: &str, snapshot: &GraphStoreSnapshot) -> bool {
    task.request
        .evidence_scope
        .evidence_ids
        .iter()
        .filter_map(|evidence_id| snapshot.graph().evidence.get(evidence_id))
        .any(|evidence| evidence.lineage.source_record_id == hunt_id)
}

fn hunt_for_evidence_scope(
    evidence_ids: &BTreeSet<EvidenceId>,
    graph: &swarm_core::hypothesis_graph::HypothesisGraph,
) -> Option<String> {
    evidence_ids
        .iter()
        .filter_map(|evidence_id| graph.evidence.get(evidence_id))
        .map(|evidence| evidence.lineage.source_record_id.clone())
        .next()
}

fn pending_worker_publication_for_task(
    campaign: &HypothesisCampaign,
    snapshot: &GraphStoreSnapshot,
    task_id: &TaskId,
) -> Result<Option<PendingWorkerPublication>, GraphServiceError> {
    let Some(task) = snapshot.state().tasks.get(task_id).map(|task| &task.task) else {
        return Err(GraphStoreError::InvalidState {
            reason: "terminal publication index references an unknown task".to_string(),
        }
        .into());
    };
    let Some(outbox) = snapshot.terminal_outbox().get(task_id) else {
        return Ok(None);
    };
    // Legacy outbox entries have no delivery marker and were emitted by the
    // pre-replay worker path. Only terminals that reserved pending delivery
    // state in their atomic commit participate in crash replay.
    if outbox.publication_acknowledged != Some(false) {
        return Ok(None);
    }
    let Some(hunt_id) =
        hunt_for_evidence_scope(&task.request.evidence_scope.evidence_ids, snapshot.graph())
    else {
        return Ok(None);
    };
    Ok(Some(PendingWorkerPublication {
        campaign_index: campaign.index,
        graph_id: campaign.graph_id.clone(),
        task_id: task_id.clone(),
        hunt_id,
        task_kind: task.request.kind,
        completion_kind: outbox.envelope.completion.kind.clone(),
        evidence_ids: task.request.evidence_scope.evidence_ids.clone(),
        retry_exhaustion_failure_summary: None,
    }))
}

fn pending_worker_publication_for_retry_exhaustion(
    campaign: &HypothesisCampaign,
    snapshot: &GraphStoreSnapshot,
    task_id: &TaskId,
) -> Result<Option<PendingWorkerPublication>, GraphServiceError> {
    let Some(task) = snapshot.state().tasks.get(task_id).map(|task| &task.task) else {
        return Err(GraphStoreError::InvalidState {
            reason: "retry-exhaustion publication index references an unknown task".to_string(),
        }
        .into());
    };
    let Some(outbox) = snapshot.retry_exhaustion_outbox().get(task_id) else {
        return Ok(None);
    };
    if outbox.publication_acknowledged {
        return Ok(None);
    }
    let Some(hunt_id) =
        hunt_for_evidence_scope(&task.request.evidence_scope.evidence_ids, snapshot.graph())
    else {
        return Ok(None);
    };
    Ok(Some(PendingWorkerPublication {
        campaign_index: campaign.index,
        graph_id: campaign.graph_id.clone(),
        task_id: task_id.clone(),
        hunt_id,
        task_kind: task.request.kind,
        completion_kind: TaskCompletionKind::NoFinding,
        evidence_ids: task.request.evidence_scope.evidence_ids.clone(),
        retry_exhaustion_failure_summary: Some(outbox.failure_summary_digest.clone()),
    }))
}

fn evidence_campaign_index(
    campaigns: &[HypothesisCampaign],
) -> Result<BTreeMap<EvidenceId, u64>, GraphServiceError> {
    let mut evidence_campaigns = BTreeMap::new();
    for campaign in campaigns {
        // A store snapshot verifies the signed graph envelope before any
        // derived lookup entry is trusted.
        let snapshot = campaign.store.snapshot()?;
        for evidence_id in snapshot.graph().evidence.keys() {
            if let Some(previous) = evidence_campaigns.insert(evidence_id.clone(), campaign.index) {
                return Err(GraphStoreError::InvalidState {
                    reason: format!(
                        "evidence `{evidence_id}` is present in campaigns {previous} and {}",
                        campaign.index
                    ),
                }
                .into());
            }
        }
    }
    Ok(evidence_campaigns)
}

fn pending_worker_publications(
    campaigns: &[HypothesisCampaign],
) -> Result<BTreeMap<(u64, TaskId), PendingWorkerPublication>, GraphServiceError> {
    let mut pending = BTreeMap::new();
    for campaign in campaigns {
        let snapshot = campaign.store.snapshot()?;
        for task_id in snapshot.terminal_outbox().keys() {
            if let Some(publication) =
                pending_worker_publication_for_task(campaign, &snapshot, task_id)?
            {
                pending.insert((campaign.index, task_id.clone()), publication);
            }
        }
        for task_id in snapshot.retry_exhaustion_outbox().keys() {
            if let Some(publication) =
                pending_worker_publication_for_retry_exhaustion(campaign, &snapshot, task_id)?
            {
                pending.insert((campaign.index, task_id.clone()), publication);
            }
        }
    }
    Ok(pending)
}

fn evidence_for_scope(
    evidence_ids: &BTreeSet<EvidenceId>,
    snapshot: &GraphStoreSnapshot,
) -> Result<Vec<swarm_core::hypothesis_graph::EvidenceEnvelope>, GraphServiceError> {
    evidence_ids
        .iter()
        .map(|evidence_id| {
            snapshot
                .graph()
                .evidence
                .get(evidence_id)
                .cloned()
                .ok_or_else(|| GraphAdmissionError::UnknownEvidence.into())
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn topology_edge(from: &str, to: &str) -> CausalEdge {
        CausalEdge::new(
            &GraphNodeId::new(from),
            &GraphNodeId::new(to),
            CausalRelation::DependsOn,
            5_000,
            [],
            GraphProducerRole::Hunter,
            AgentId("agent:topology-test".to_string()),
            GraphLogicalTime::new(1),
            EdgeState::Unresolved,
        )
        .unwrap()
    }

    #[test]
    fn topology_preflight_bounds_candidate_edges_with_retained_graph() {
        let first = topology_edge("node:a", "node:b");
        let depth_extension = topology_edge("node:b", "node:c");
        let fan_out_extension = topology_edge("node:a", "node:d");

        assert!(topology_within_limits([&first], 1, 2));
        assert!(topology_within_limits([&depth_extension], 1, 2));
        assert!(!topology_within_limits([&first, &depth_extension], 1, 2));
        assert!(topology_within_limits([&fan_out_extension], 1, 2));
        assert!(!topology_within_limits([&first, &fan_out_extension], 1, 2));
    }

    #[test]
    fn disabled_config_constructs_no_service() {
        let config = HypothesisGraphConfig::default();
        let service =
            CollectiveHypothesisService::from_config(&config, Keypair::from_seed(&[1; 32]), None)
                .unwrap();
        assert!(service.is_none());
    }

    #[test]
    fn shipped_factory_rejects_enabled_memory_store() {
        let config = HypothesisGraphConfig {
            enabled: true,
            ..HypothesisGraphConfig::default()
        };
        assert!(matches!(
            CollectiveHypothesisService::from_config(&config, Keypair::from_seed(&[11; 32]), None,),
            Err(GraphServiceError::NonDurableEnabledStore)
        ));
    }

    #[test]
    fn worker_capabilities_are_key_bound_and_cannot_be_reassigned() {
        let config = HypothesisGraphConfig {
            enabled: true,
            ..HypothesisGraphConfig::default()
        };
        let service = Arc::new(
            CollectiveHypothesisService::new(&config, Keypair::from_seed(&[2; 32]), None).unwrap(),
        );
        assert!(matches!(
            service.ensure_workers_registered(),
            Err(GraphServiceError::MissingWorkerRegistration(
                TaskKind::AcquireEvidence
            ))
        ));
        assert!(matches!(
            service.worker([], Keypair::from_seed(&[3; 32])),
            Err(GraphServiceError::EmptyWorkerCapabilities)
        ));
        let first = service
            .worker([TaskKind::ChallengeEdge], Keypair::from_seed(&[4; 32]))
            .unwrap();
        let retry = service
            .worker([TaskKind::ChallengeEdge], Keypair::from_seed(&[4; 32]))
            .unwrap();
        assert_eq!(first.claimant(), retry.claimant());
        assert!(matches!(
            service.worker([TaskKind::ChallengeEdge], Keypair::from_seed(&[5; 32])),
            Err(GraphServiceError::WorkerCapabilityConflict {
                kind: TaskKind::ChallengeEdge,
                ..
            })
        ));
        service
            .worker(
                [TaskKind::AcquireEvidence, TaskKind::FalsifyHypothesis],
                Keypair::from_seed(&[6; 32]),
            )
            .unwrap();
        service.ensure_workers_registered().unwrap();
    }

    #[test]
    fn only_outstanding_tasks_block_worker_rebind_after_restart() {
        let now = GraphLogicalTime::new(200);
        assert!(task_blocks_worker_rebind_at(TaskState::Pending, None, now));
        assert!(task_blocks_worker_rebind_at(
            TaskState::Claimed,
            Some(GraphLogicalTime::new(201)),
            now
        ));
        assert!(!task_blocks_worker_rebind_at(
            TaskState::Claimed,
            Some(now),
            now
        ));
        assert!(!task_blocks_worker_rebind_at(
            TaskState::Completed,
            None,
            now
        ));
        assert!(!task_blocks_worker_rebind_at(TaskState::Failed, None, now));
        assert!(!task_blocks_worker_rebind_at(TaskState::Expired, None, now));
    }

    #[test]
    fn expired_tasks_are_visible_after_claimant_rebinding() {
        let prior = AgentId::new("agent", "prior");
        let replacement = AgentId::new("agent", "replacement");

        assert!(task_is_visible_to_claimant(
            TaskState::Expired,
            &prior,
            None,
            &replacement,
            GraphLogicalTime::new(200),
        ));
        assert!(!task_is_visible_to_claimant(
            TaskState::Pending,
            &prior,
            None,
            &replacement,
            GraphLogicalTime::new(200),
        ));
        assert!(!task_is_visible_to_claimant(
            TaskState::Claimed,
            &prior,
            Some(GraphLogicalTime::new(201)),
            &replacement,
            GraphLogicalTime::new(200),
        ));
        assert!(task_is_visible_to_claimant(
            TaskState::Claimed,
            &prior,
            Some(GraphLogicalTime::new(200)),
            &replacement,
            GraphLogicalTime::new(200),
        ));
    }

    #[test]
    fn post_commit_memory_failure_returns_completion_and_marks_repair_dirty() {
        let config = HypothesisGraphConfig {
            enabled: true,
            ..HypothesisGraphConfig::default()
        };
        let service =
            CollectiveHypothesisService::new(&config, Keypair::from_seed(&[12; 32]), None).unwrap();

        let projected = service
            .record_post_commit_memory_projection(
                0,
                Err(StrategyMemoryStoreError::InvalidState {
                    reason: "injected transient projection failure".to_string(),
                }),
            )
            .unwrap();

        assert_eq!(projected, 0);
        let state = service.state.lock().unwrap();
        assert!(state.dirty_memory_campaigns.contains_key(&0));
        assert_eq!(state.metrics.snapshot.memory_projection_failures, 1);
        assert_eq!(state.metrics.snapshot.memory_records_projected, 0);
    }

    #[test]
    fn startup_memory_projection_failure_starts_dirty_instead_of_aborting() {
        let config = HypothesisGraphConfig {
            enabled: true,
            ..HypothesisGraphConfig::default()
        };
        let service =
            CollectiveHypothesisService::new(&config, Keypair::from_seed(&[16; 32]), None).unwrap();

        service
            .record_startup_memory_projection(
                0,
                Err(StrategyMemoryStoreError::InvalidState {
                    reason: "injected startup projection outage".to_string(),
                }),
            )
            .unwrap();

        let state = service.state.lock().unwrap();
        assert!(state.dirty_memory_campaigns.contains_key(&0));
        assert_eq!(state.metrics.snapshot.memory_projection_failures, 1);
        assert_eq!(state.metrics.snapshot.memory_records_projected, 0);
    }

    #[test]
    fn memory_priority_failure_falls_back_to_base_priority() {
        let config = HypothesisGraphConfig {
            enabled: true,
            ..HypothesisGraphConfig::default()
        };
        let service =
            CollectiveHypothesisService::new(&config, Keypair::from_seed(&[13; 32]), None).unwrap();
        let base = vec![MemoryPriorityProjection::unchanged(4_200)];
        let resolved = service
            .resolve_advisory_priorities(
                0,
                base.clone(),
                Err(GraphServiceError::Memory(
                    StrategyMemoryStoreError::InvalidState {
                        reason: "injected priority lookup outage".to_string(),
                    },
                )),
            )
            .unwrap();

        assert_eq!(resolved, base);
        let state = service.state.lock().unwrap();
        assert!(state.dirty_memory_campaigns.contains_key(&0));
        assert_eq!(state.metrics.snapshot.memory_projection_failures, 1);
    }

    #[test]
    fn campaign_rotation_preserves_and_repairs_archived_memory_projection_state() {
        let config = HypothesisGraphConfig {
            enabled: true,
            ..HypothesisGraphConfig::default()
        };
        let service =
            CollectiveHypothesisService::new(&config, Keypair::from_seed(&[15; 32]), None).unwrap();
        service
            .record_post_commit_memory_projection(
                0,
                Err(StrategyMemoryStoreError::InvalidState {
                    reason: "injected pre-rotation projection failure".to_string(),
                }),
            )
            .unwrap();
        let current = service.active_campaign().unwrap();
        let rotated = {
            let mut state = service.state.lock().unwrap();
            service.rotate_campaign(&mut state, &current).unwrap()
        };
        assert_eq!(rotated.index, 1);
        assert!(
            service
                .state
                .lock()
                .unwrap()
                .dirty_memory_campaigns
                .contains_key(&0),
            "rotation must retain the archived campaign repair target"
        );

        assert!(
            service
                .operator_memory_for(&current.graph_id)
                .unwrap()
                .is_empty()
        );
        assert!(
            service
                .state
                .lock()
                .unwrap()
                .dirty_memory_campaigns
                .is_empty(),
            "repair must target and clear the archived campaign marker"
        );
    }

    #[test]
    fn restart_authenticates_and_recovers_pristine_unactivated_campaign() {
        let root = std::env::temp_dir().join(format!(
            "swarm-phase286-unactivated-campaign-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let config = HypothesisGraphConfig {
            enabled: true,
            state_store: BundleStoreConfig::LocalFiles {
                directory: root.display().to_string(),
            },
            ..HypothesisGraphConfig::default()
        };
        let signer = Keypair::from_seed(&[14; 32]);
        let initial = CollectiveHypothesisService::new(&config, signer.clone(), None).unwrap();
        let initial_graph_id = initial.graph_id();
        drop(initial);

        let campaign_directory = root.join("campaigns").join("1");
        fs::create_dir_all(&campaign_directory).unwrap();
        let unactivated = open_campaign(
            1,
            &config,
            &signer,
            Some(&campaign_directory.join("graph")),
            Some(&campaign_directory.join("strategy-memory")),
        )
        .unwrap();
        validate_unactivated_campaign(&unactivated, &campaign_directory, &config).unwrap();
        drop(unactivated);

        let restarted = CollectiveHypothesisService::new(&config, signer, None).unwrap();
        assert_eq!(restarted.graph_id(), initial_graph_id);
        assert_eq!(restarted.summaries().unwrap().len(), 1);
        assert_eq!(
            load_campaign_head(&root.join(CAMPAIGN_HEAD_FILE), &restarted.signer)
                .unwrap()
                .latest_index,
            0
        );
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restart_recovers_pristine_initial_campaign_before_head_activation() {
        let root = std::env::temp_dir().join(format!(
            "swarm-phase286-unheaded-initial-campaign-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let config = HypothesisGraphConfig {
            enabled: true,
            state_store: BundleStoreConfig::LocalFiles {
                directory: root.display().to_string(),
            },
            ..HypothesisGraphConfig::default()
        };
        let signer = Keypair::from_seed(&[15; 32]);
        let initial = CollectiveHypothesisService::new(&config, signer.clone(), None).unwrap();
        let expected_graph_id = initial.graph_id();
        drop(initial);

        fs::remove_file(root.join(CAMPAIGN_HEAD_FILE)).unwrap();
        let restarted = CollectiveHypothesisService::new(&config, signer, None).unwrap();

        assert_eq!(restarted.graph_id(), expected_graph_id);
        assert_eq!(restarted.summaries().unwrap().len(), 1);
        assert_eq!(
            load_campaign_head(&root.join(CAMPAIGN_HEAD_FILE), &restarted.signer)
                .unwrap()
                .latest_index,
            0
        );
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restart_rejects_populated_initial_campaign_without_head() {
        let root = std::env::temp_dir().join(format!(
            "swarm-phase286-unheaded-populated-campaign-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        let config = HypothesisGraphConfig {
            enabled: true,
            state_store: BundleStoreConfig::LocalFiles {
                directory: root.display().to_string(),
            },
            ..HypothesisGraphConfig::default()
        };
        let signer = Keypair::from_seed(&[16; 32]);
        let initial = CollectiveHypothesisService::new(&config, signer.clone(), None).unwrap();
        let store = initial.store().unwrap();
        let snapshot = store.snapshot().unwrap();
        let mut populated = snapshot.state().clone();
        populated.logical_time_high_water = GraphLogicalTime::new(1);
        populated.generation = snapshot.revision().generation;
        populated.predecessor_digest = snapshot.state().predecessor_digest.clone();
        store
            .compare_and_swap(snapshot.revision(), populated)
            .unwrap();
        drop(store);
        drop(initial);
        fs::remove_file(root.join(CAMPAIGN_HEAD_FILE)).unwrap();

        assert!(matches!(
            CollectiveHypothesisService::new(&config, signer, None),
            Err(GraphServiceError::InvalidCampaignEntry { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
