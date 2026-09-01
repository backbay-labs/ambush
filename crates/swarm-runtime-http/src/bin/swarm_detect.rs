use clap::Parser;
use notify::{EventKind, RecursiveMode, Watcher};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use swarm_agents::pounce_agent::PounceAgent;
use swarm_agents::stalker_agent::StalkerAgent;
use swarm_agents::tom_agent::{
    GovernanceAuthority, GovernanceAuthorityPairGuard, GovernanceCleanupArtifactExpectation,
    GovernanceCleanupPoolRetentionGuard, GovernanceCleanupPoolRetentionOutcome, GovernancePolicy,
    GovernancePolicyConfig, TomAgent,
};
use swarm_agents::weaver_agent::WeaverAgent;
use swarm_agents::whisker_agent::WhiskerAgent;
use swarm_core::agent::{AgentRole, SwarmAgent, SwarmModeState};
use swarm_core::types::AgentId;
use swarm_crypto::sha256_hex;
use swarm_ingest_runtime::anti_tamper::{AntiTamperFailure, AntiTamperMonitor};
use swarm_ingest_runtime::bridge_runtime::BridgeRuntimeRegistry;
use swarm_ingest_runtime::control::build_composite_detector;
use swarm_ingest_runtime::ingest::{IngestState, detect_http_router};
use swarm_policy::ApprovalContext;
use swarm_runtime::agent_identity::{
    AgentKeyLoadStatus, FileAgentIdentityRegistry, FileAgentKeyStore, PersistedAgentIdentity,
    RegistryAdmission, resolve_agent_key_dir, resolve_identity_registry_dir,
};
use swarm_runtime::approval::DefaultApprovalHarness;
use swarm_runtime::calico_agent::CalicoAgent;
use swarm_runtime::config::load_config;
use swarm_runtime::dispatcher::{AgentDispatcher, AgentDispatcherConfig, AgentRestartFactory};
use swarm_runtime::escalation::ConcentrationMonitor;
use swarm_runtime::investigation::SummaryInvestigator;
use swarm_runtime::kitten_agent::KittenAgent;
use swarm_runtime::replay::{ReplayScenarioInput, load_scenario_manifest, scenario_paths_in_dir};
use swarm_runtime::runtime_events::{DEFAULT_RUNTIME_EVENT_CAPACITY, RuntimeEventBroadcaster};
use swarm_runtime::service::{ConfiguredRuntimeStack, EventExecutionContext};
use swarm_runtime::sphinx_agent::SphinxAgent;
use swarm_runtime::startup_attestation::{StartupAttestationFailure, StartupAttestationReport};
use swarm_runtime::threat_intel_runtime::ThreatIntelFeedRuntimeRegistry;
use swarm_runtime_http::serve::serve_with_listener;

const RELOAD_DEBOUNCE_MS: u64 = 500;
const GRACEFUL_SHUTDOWN_TIMEOUT_SECS: u64 = 30;
const CONCENTRATION_MONITOR_INTERVAL_MS: u64 = 100;

// Keep the detector crate independent of a direct libc dependency while still
// requesting the descriptor protections required for artifact reads and
// directory-bound publication.  These values are the stable Darwin/Linux
// fcntl constants; unsupported Unix targets get no extra flags and fail the
// subsequent identity checks closed.
#[cfg(target_os = "linux")]
const GOVERNANCE_O_NOFOLLOW: i32 = 0x20000;
#[cfg(target_os = "linux")]
const GOVERNANCE_O_CLOEXEC: i32 = 0x80000;
#[cfg(target_os = "linux")]
const GOVERNANCE_O_DIRECTORY: i32 = 0x10000;
#[cfg(target_os = "linux")]
const GOVERNANCE_O_RDWR: i32 = 0x2;
#[cfg(target_os = "linux")]
const GOVERNANCE_O_CREAT: i32 = 0x40;
#[cfg(target_os = "linux")]
const GOVERNANCE_O_EXCL: i32 = 0x80;
#[cfg(target_os = "macos")]
const GOVERNANCE_O_NOFOLLOW: i32 = 0x100;
#[cfg(target_os = "macos")]
const GOVERNANCE_O_CLOEXEC: i32 = 0x1000000;
#[cfg(target_os = "macos")]
const GOVERNANCE_O_DIRECTORY: i32 = 0x100000;
#[cfg(target_os = "macos")]
const GOVERNANCE_O_RDWR: i32 = 0x2;
#[cfg(target_os = "macos")]
const GOVERNANCE_O_CREAT: i32 = 0x200;
#[cfg(target_os = "macos")]
const GOVERNANCE_O_EXCL: i32 = 0x800;
#[cfg(target_os = "linux")]
const GOVERNANCE_RENAME_NOREPLACE: u32 = 1;
#[cfg(target_os = "macos")]
const GOVERNANCE_RENAME_EXCL: u32 = 0x0004;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const GOVERNANCE_O_NOFOLLOW: i32 = 0;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const GOVERNANCE_O_CLOEXEC: i32 = 0;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const GOVERNANCE_O_DIRECTORY: i32 = 0;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const GOVERNANCE_O_RDWR: i32 = 0;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const GOVERNANCE_O_CREAT: i32 = 0;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const GOVERNANCE_O_EXCL: i32 = 0;

#[cfg(any(target_os = "linux", target_os = "macos"))]
unsafe extern "C" {
    fn linkat(
        source_directory_fd: std::os::raw::c_int,
        source_name: *const std::os::raw::c_char,
        destination_directory_fd: std::os::raw::c_int,
        destination_name: *const std::os::raw::c_char,
        flags: std::os::raw::c_int,
    ) -> std::os::raw::c_int;
    fn openat(
        directory_fd: std::os::raw::c_int,
        name: *const std::os::raw::c_char,
        flags: std::os::raw::c_int,
        ...
    ) -> std::os::raw::c_int;
    #[cfg(target_os = "linux")]
    fn renameat2(
        source_directory_fd: std::os::raw::c_int,
        source_name: *const std::os::raw::c_char,
        destination_directory_fd: std::os::raw::c_int,
        destination_name: *const std::os::raw::c_char,
        flags: std::os::raw::c_uint,
    ) -> std::os::raw::c_int;
    #[cfg(target_os = "macos")]
    fn renameatx_np(
        source_directory_fd: std::os::raw::c_int,
        source_name: *const std::os::raw::c_char,
        destination_directory_fd: std::os::raw::c_int,
        destination_name: *const std::os::raw::c_char,
        flags: std::os::raw::c_uint,
    ) -> std::os::raw::c_int;
}

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, default_value = "rulesets/default.yaml")]
    config: PathBuf,
    #[arg(long)]
    scenarios_dir: Option<PathBuf>,
    #[arg(long)]
    scenario: Vec<PathBuf>,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    otlp_endpoint: Option<String>,
    #[arg(long)]
    serve: bool,
    /// Archive all existing governance state and create an empty signed stream.
    /// Run only while the daemon is stopped; legacy leases and authorizations
    /// are deliberately discarded rather than migrated as trusted state.
    #[arg(
        long,
        conflicts_with = "serve",
        conflicts_with = "scenario",
        conflicts_with = "scenarios_dir"
    )]
    reinitialize_governance_state: bool,
    #[arg(long, default_value = "127.0.0.1:9090")]
    bind: String,
    #[arg(long, default_value = "data/approval-sets")]
    approval_set_results_dir: PathBuf,
    #[arg(long, default_value = "data/approval-ledgers")]
    approval_ledger_results_dir: PathBuf,
    #[arg(long, default_value = "data/approval-verdicts")]
    approval_verdict_results_dir: PathBuf,
    #[arg(long, default_value = "data/approval-receipt-packs")]
    approval_receipt_pack_results_dir: PathBuf,
}

fn build_approval_harness(
    cli: &Cli,
) -> Result<DefaultApprovalHarness, swarm_runtime::approval::ApprovalError> {
    DefaultApprovalHarness::from_path(
        &cli.config,
        &cli.approval_verdict_results_dir,
        &cli.approval_receipt_pack_results_dir,
        &cli.approval_set_results_dir,
        &cli.approval_ledger_results_dir,
    )
}

fn response_kind(value: &swarm_spine::AuditResponseRecord) -> &'static str {
    match value {
        swarm_spine::AuditResponseRecord::Success(_) => "success",
        swarm_spine::AuditResponseRecord::Failure(_) => "failure",
        swarm_spine::AuditResponseRecord::Skipped { .. } => "skipped",
        swarm_spine::AuditResponseRecord::GuardRejected { .. } => "guard_rejected",
    }
}

fn register_optional_sphinx_agent(
    dispatcher: &mut AgentDispatcher,
    config_path: &std::path::Path,
    config: &swarm_core::config::SwarmConfig,
    state: &IngestState,
    identity_store: &FileAgentKeyStore,
    identity_registry: &FileAgentIdentityRegistry,
    now_ms: i64,
) -> Result<Option<AgentId>, std::io::Error> {
    if !config.memory.enabled {
        return Ok(None);
    }
    register_persisted_runtime_agent(
        dispatcher,
        identity_store,
        identity_registry,
        AgentRole::Sphinx,
        "primary",
        now_ms,
        {
            let config_path = config_path.to_path_buf();
            let config = config.clone();
            let state = state.clone();
            move |identity| {
                build_restartable_agent(move || {
                    SphinxAgent::new_with_signing_key(
                        identity.id.clone(),
                        identity.signing_key.clone(),
                        config_path.clone(),
                        config.clone(),
                        state.current_substrate(),
                    )
                    .map(|agent| Box::new(agent) as Box<dyn SwarmAgent>)
                    .map_err(|error| error.to_string())
                })
            }
        },
    )
}

fn register_optional_calico_agent(
    dispatcher: &mut AgentDispatcher,
    config_path: &std::path::Path,
    config: &swarm_core::config::SwarmConfig,
    state: &IngestState,
    identity_store: &FileAgentKeyStore,
    identity_registry: &FileAgentIdentityRegistry,
    now_ms: i64,
) -> Result<Option<AgentId>, std::io::Error> {
    if !config.deception.enabled {
        return Ok(None);
    }
    register_persisted_runtime_agent(
        dispatcher,
        identity_store,
        identity_registry,
        AgentRole::Calico,
        "primary",
        now_ms,
        {
            let config_path = config_path.to_path_buf();
            let config = config.clone();
            let state = state.clone();
            move |identity| {
                build_restartable_agent(move || {
                    CalicoAgent::new_with_signing_key(
                        identity.id.clone(),
                        identity.signing_key.clone(),
                        config_path.clone(),
                        config.clone(),
                        state.current_substrate(),
                    )
                    .map(|agent| Box::new(agent) as Box<dyn SwarmAgent>)
                    .map_err(|error| error.to_string())
                })
            }
        },
    )
}

#[derive(Debug, Clone, Copy)]
enum ReloadTrigger {
    FileChange,
    SecretChange,
    Signal(&'static str),
}

struct RetargetableWatcher {
    path: PathBuf,
    stop_tx: tokio::sync::watch::Sender<bool>,
    join_handle: tokio::task::JoinHandle<()>,
}

impl RetargetableWatcher {
    fn stop(self) {
        let _ = self.stop_tx.send(true);
        self.join_handle.abort();
    }
}

fn watch_paths_differ(current: Option<&PathBuf>, next: Option<&PathBuf>) -> bool {
    current != next
}

fn load_persisted_agent_identity(
    store: &FileAgentKeyStore,
    role: AgentRole,
    slot: &str,
) -> Result<PersistedAgentIdentity, std::io::Error> {
    store
        .load_or_create(role, slot)
        .map_err(std::io::Error::other)
}

fn default_partition_governance_state_path(
    config_path: &std::path::Path,
    identity: &swarm_core::config::IdentityConfig,
) -> PathBuf {
    let agent_key_dir = resolve_agent_key_dir(config_path, identity);
    agent_key_dir
        .parent()
        .unwrap_or(agent_key_dir.as_path())
        .join("governance-partition-state.json")
}

fn legacy_partition_governance_state_path(config_path: &std::path::Path) -> PathBuf {
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    if config_dir
        .file_name()
        .is_some_and(|name| name == "rulesets")
    {
        config_dir
            .parent()
            .unwrap_or(config_dir)
            .join("data/governance-partition-state.json")
    } else {
        config_dir.join("governance-partition-state.json")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GovernanceArtifactSet {
    Absent,
    Complete,
    LockOnly,
    RecoverablePartial,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GovernanceArtifactIdentity {
    regular_file: bool,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GovernanceArtifactRecord {
    bytes: Vec<u8>,
    identity: GovernanceArtifactIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GovernanceArtifactSnapshot {
    state: Option<GovernanceArtifactRecord>,
    sequence: Option<GovernanceArtifactRecord>,
    lock: Option<GovernanceArtifactRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GovernanceArtifactMutation {
    Preserve,
    Created,
    Replaced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GovernanceArtifactOwnership {
    state: GovernanceArtifactMutation,
    sequence: GovernanceArtifactMutation,
    lock: GovernanceArtifactMutation,
    /// Exact artifact snapshot revalidated immediately before the policy
    /// constructor was entered.  Rollback is valid only for the transition
    /// from this snapshot to `expected_after`; a later snapshot cannot prove
    /// that a foreign constructor did not win the race first.
    constructor_before: Option<GovernanceArtifactSnapshot>,
    /// Exact records captured immediately after this invocation's policy
    /// constructor returned. Rollback must use these identities, never a
    /// later snapshot that could describe a foreign replacement.
    expected_after: GovernanceArtifactSnapshot,
}

impl GovernanceArtifactOwnership {
    fn new(
        state: GovernanceArtifactMutation,
        sequence: GovernanceArtifactMutation,
        lock: GovernanceArtifactMutation,
    ) -> Self {
        Self {
            state,
            sequence,
            lock,
            constructor_before: None,
            expected_after: GovernanceArtifactSnapshot {
                state: None,
                sequence: None,
                lock: None,
            },
        }
    }

    fn preserve() -> Self {
        Self::new(
            GovernanceArtifactMutation::Preserve,
            GovernanceArtifactMutation::Preserve,
            GovernanceArtifactMutation::Preserve,
        )
    }

    fn with_expected_after(mut self, expected_after: GovernanceArtifactSnapshot) -> Self {
        self.expected_after = expected_after;
        self
    }

    fn with_constructor_before(mut self, constructor_before: GovernanceArtifactSnapshot) -> Self {
        self.constructor_before = Some(constructor_before);
        self
    }
}

fn governance_artifact_set_from_presence(
    state: bool,
    sequence: bool,
    lock: bool,
) -> GovernanceArtifactSet {
    match (state, sequence, lock) {
        (false, false, false) => GovernanceArtifactSet::Absent,
        (true, true, true) => GovernanceArtifactSet::Complete,
        (false, false, true) => GovernanceArtifactSet::LockOnly,
        (true, false, true) => GovernanceArtifactSet::RecoverablePartial,
        _ => GovernanceArtifactSet::Partial,
    }
}

impl GovernanceArtifactSnapshot {
    fn artifact_set(&self) -> GovernanceArtifactSet {
        governance_artifact_set_from_presence(
            self.state.is_some(),
            self.sequence.is_some(),
            self.lock.is_some(),
        )
    }
}

fn governance_artifact_identity_from_metadata(
    metadata: &std::fs::Metadata,
) -> Option<GovernanceArtifactIdentity> {
    if !metadata.file_type().is_file() {
        return None;
    }
    Some(GovernanceArtifactIdentity {
        regular_file: true,
        #[cfg(unix)]
        device: {
            use std::os::unix::fs::MetadataExt;
            metadata.dev()
        },
        #[cfg(unix)]
        inode: {
            use std::os::unix::fs::MetadataExt;
            metadata.ino()
        },
    })
}

fn governance_artifact_record(
    path: &std::path::Path,
) -> Result<Option<GovernanceArtifactRecord>, std::io::Error> {
    // Bind the read to an O_NOFOLLOW descriptor.  The pathname is only used
    // for identity checks; bytes are never read by reopening the name after
    // an untrusted metadata check.
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(GOVERNANCE_O_NOFOLLOW | GOVERNANCE_O_CLOEXEC);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let identity =
        governance_artifact_identity_from_metadata(&file.metadata()?).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance artifact `{}` is not a regular non-symlink file",
                    path.display()
                ),
            )
        })?;
    let named_before = std::fs::symlink_metadata(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "cannot bind governance artifact `{}`: {error}",
                path.display()
            ),
        )
    })?;
    if governance_artifact_identity_from_metadata(&named_before).as_ref() != Some(&identity) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "governance artifact `{}` changed identity while opening",
                path.display()
            ),
        ));
    }
    #[cfg(test)]
    pause_before_governance_artifact_read();
    use std::io::Read;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let held_after = file.metadata()?;
    if governance_artifact_identity_from_metadata(&held_after).as_ref() != Some(&identity)
        || held_after.len() != bytes.len() as u64
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "governance artifact `{}` changed identity or length while reading",
                path.display()
            ),
        ));
    }
    let named_after = std::fs::symlink_metadata(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "cannot verify governance artifact `{}`: {error}",
                path.display()
            ),
        )
    })?;
    if governance_artifact_identity_from_metadata(&named_after).as_ref() != Some(&identity) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "governance artifact `{}` changed identity while reading",
                path.display()
            ),
        ));
    }
    Ok(Some(GovernanceArtifactRecord { bytes, identity }))
}

fn governance_artifact_snapshot(
    state_path: &std::path::Path,
) -> Result<GovernanceArtifactSnapshot, std::io::Error> {
    let sequence_path = GovernancePolicy::persistence_sequence_path(state_path);
    let lock_path = GovernancePolicy::persistence_lock_path(state_path);
    Ok(GovernanceArtifactSnapshot {
        state: governance_artifact_record(state_path)?,
        sequence: governance_artifact_record(&sequence_path)?,
        lock: governance_artifact_record(&lock_path)?,
    })
}

fn governance_artifact_set(
    state_path: &std::path::Path,
) -> Result<GovernanceArtifactSet, std::io::Error> {
    let sequence_path = GovernancePolicy::persistence_sequence_path(state_path);
    let lock_path = GovernancePolicy::persistence_lock_path(state_path);
    let present = [state_path, sequence_path.as_path(), lock_path.as_path()]
        .into_iter()
        .map(|path| match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => Ok(true),
            Ok(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance artifact `{}` is not a regular file",
                    path.display()
                ),
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(governance_artifact_set_from_presence(
        present[0], present[1], present[2],
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GovernancePathResolutionMode {
    Bootstrap,
    Reinitialize,
}

fn governance_selection_lock_path(current_path: &std::path::Path) -> PathBuf {
    current_path.with_extension("selection.lock")
}

#[derive(Debug)]
struct GovernancePathSelectionLock {
    path: PathBuf,
    file: std::fs::File,
}

impl GovernancePathSelectionLock {
    fn acquire(path: PathBuf) -> Result<Self, std::io::Error> {
        let file = open_governance_selection_lock(&path)?;
        let selection_lock = Self { path, file };
        selection_lock.verify_path_identity()?;
        match selection_lock.file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    format!(
                        "governance path-selection lock `{}` is held by another process",
                        selection_lock.path.display()
                    ),
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
        selection_lock.verify_path_identity()?;
        Ok(selection_lock)
    }

    fn verify_path_identity(&self) -> Result<(), std::io::Error> {
        let named = std::fs::symlink_metadata(&self.path).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("cannot verify governance path-selection lock: {error}"),
            )
        })?;
        if !named.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance path-selection lock `{}` is not a regular file",
                    self.path.display()
                ),
            ));
        }
        let held = self.file.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if held.dev() != named.dev() || held.ino() != named.ino() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "governance path-selection lock `{}` changed identity while held",
                        self.path.display()
                    ),
                ));
            }
        }
        Ok(())
    }
}

fn open_governance_selection_lock(path: &std::path::Path) -> Result<std::fs::File, std::io::Error> {
    for _ in 0..2 {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)?;
                return Ok(file);
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "governance path-selection lock `{}` is not a regular file",
                        path.display()
                    ),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(path)
                {
                    Ok(file) => {
                        file.sync_all()?;
                        if let Some(parent) = path.parent() {
                            std::fs::File::open(parent)?.sync_all()?;
                        }
                        return Ok(file);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "governance path-selection lock `{}` changed during open",
            path.display()
        ),
    ))
}

fn governance_authority_sidecar_exists(path: &std::path::Path) -> Result<bool, std::io::Error> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn validate_governance_authority_sidecar(
    state_path: &std::path::Path,
) -> Result<swarm_agents::tom_agent::GovernanceAuthorityLockIdentity, std::io::Error> {
    GovernancePolicy::persistence_authority_lock_identity(state_path).map_err(std::io::Error::other)
}

#[derive(Debug)]
struct GovernanceCreatedAuthoritySidecar {
    path: PathBuf,
    file: std::fs::File,
    parent: GovernanceHeldParent,
    identity: swarm_agents::tom_agent::GovernanceAuthorityLockIdentity,
}

fn create_governance_authority_sidecar(
    path: &std::path::Path,
) -> Result<Option<GovernanceCreatedAuthoritySidecar>, std::io::Error> {
    if governance_authority_sidecar_exists(path)? {
        return Ok(None);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let parent = open_governance_quarantine_parent(path)?;
    let name = governance_entry_name(path)?;
    let entry = governance_parent_entry_path(&parent, name)?;
    // Create relative to the retained parent descriptor.  A pathname
    // `create_new` here would be redirected if the parent directory were
    // retargeted between `open_governance_quarantine_parent` and creation.
    let file = match governance_create_new_at(&parent, name) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(None),
        Err(error) => return Err(error),
    };
    let identity = governance_authority_sidecar_identity_from_metadata(&file.metadata()?)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "created authority sidecar `{}` is not regular",
                    path.display()
                ),
            )
        })?;
    if governance_authority_sidecar_identity_if_regular(&entry) != Some(identity) {
        return Err(governance_artifact_identity_error(
            path,
            "record a changed authority sidecar",
        ));
    }
    #[cfg(test)]
    pause_after_governance_authority_sidecar_create();
    verify_governance_quarantine_parent(&parent.path, &parent, parent.identity)?;
    if governance_authority_sidecar_identity_from_metadata(&file.metadata()?) != Some(identity)
        || governance_authority_sidecar_identity_if_regular(&entry) != Some(identity)
    {
        return Err(governance_artifact_identity_error(
            path,
            "record a replaced authority sidecar",
        ));
    }
    file.sync_all()?;
    parent.file.sync_all()?;
    Ok(Some(GovernanceCreatedAuthoritySidecar {
        path: path.to_path_buf(),
        file,
        parent,
        identity,
    }))
}

fn remove_created_governance_authority_sidecar(
    created: &GovernanceCreatedAuthoritySidecar,
) -> Result<(), std::io::Error> {
    let expected = created.identity;
    if governance_authority_sidecar_identity_from_metadata(&created.file.metadata()?)
        != Some(expected)
        || governance_authority_sidecar_identity_if_regular(&created.path) != Some(expected)
    {
        // Without the exact held descriptor and named-path identity, removal
        // would be a path-only operation and could unlink a foreign artifact.
        return Ok(());
    }
    let name = governance_entry_name(&created.path)?;
    let Some(expected_record) = governance_artifact_record_at(&created.parent, name)? else {
        return Ok(());
    };
    if !expected_record.identity.regular_file {
        return Ok(());
    }
    let Some(quarantine) = quarantine_governance_artifact_with_parent(
        None,
        &created.path,
        &expected_record,
        &created.parent,
    )?
    else {
        return Ok(());
    };
    let quarantine_name = governance_entry_name(&quarantine)?;
    let moved_record = match governance_artifact_record_at(&created.parent, quarantine_name) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return Err(governance_artifact_identity_error(
                &quarantine,
                "remove a missing authority sidecar",
            ));
        }
        Err(error) => {
            let _ =
                restore_governance_quarantine_entry_no_replace(&quarantine, &created.path, None);
            return Err(error);
        }
    };
    if governance_authority_sidecar_identity_from_metadata(&created.file.metadata()?)
        != Some(expected)
        || moved_record != expected_record
    {
        return Err(governance_artifact_identity_error(
            &quarantine,
            "remove a changed authority sidecar",
        ));
    }
    remove_private_governance_quarantine_with_parent(&quarantine, &expected_record, &created.parent)
}

fn governance_authority_sidecar_identity_if_regular(
    path: &std::path::Path,
) -> Option<swarm_agents::tom_agent::GovernanceAuthorityLockIdentity> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(swarm_agents::tom_agent::GovernanceAuthorityLockIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

fn governance_authority_sidecar_identity_from_metadata(
    metadata: &std::fs::Metadata,
) -> Option<swarm_agents::tom_agent::GovernanceAuthorityLockIdentity> {
    if !metadata.file_type().is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(swarm_agents::tom_agent::GovernanceAuthorityLockIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// Establish one authority sidecar inode for the current and legacy logical
/// state paths. Existing sidecars are validated before a missing peer is
/// created, so malformed or mismatched authority cannot be silently repaired.
/// The caller must hold the durable path-selection lock for the whole operation.
fn ensure_governance_authority_lock_pair(
    current_path: &std::path::Path,
    legacy_path: &std::path::Path,
) -> Result<swarm_agents::tom_agent::GovernanceAuthorityLockIdentity, std::io::Error> {
    let current_sidecar = GovernancePolicy::persistence_authority_lock_path(current_path);
    let legacy_sidecar = GovernancePolicy::persistence_authority_lock_path(legacy_path);
    if current_sidecar == legacy_sidecar {
        let created = if !governance_authority_sidecar_exists(&current_sidecar)? {
            create_governance_authority_sidecar(&current_sidecar)?
        } else {
            None
        };
        let result = validate_governance_authority_sidecar(current_path);
        if result.is_err()
            && let Some(created) = created.as_ref()
        {
            let _ = remove_created_governance_authority_sidecar(created);
        }
        return result;
    }

    let current_present = governance_authority_sidecar_exists(&current_sidecar)?;
    let legacy_present = governance_authority_sidecar_exists(&legacy_sidecar)?;
    if current_present {
        validate_governance_authority_sidecar(current_path)?;
    }
    if legacy_present {
        validate_governance_authority_sidecar(legacy_path)?;
    }
    if current_present && legacy_present {
        return GovernancePolicy::persistence_authority_lock_pair_identity(
            current_path,
            legacy_path,
        )
        .map_err(std::io::Error::other);
    }

    let mut created: Vec<GovernanceCreatedAuthoritySidecar> = Vec::new();
    let result = (|| {
        if !current_present && !legacy_present {
            if let Some(created_sidecar) = create_governance_authority_sidecar(&current_sidecar)? {
                // The helper captured the create FD and identity before it
                // returned. Retain that capability before any named-path
                // validation can race with a foreign replacement.
                created.push(created_sidecar);
            }
            validate_governance_authority_sidecar(current_path)?;
        }

        let (source, target, target_state_path) = if current_present || !legacy_present {
            (&current_sidecar, &legacy_sidecar, legacy_path)
        } else {
            (&legacy_sidecar, &current_sidecar, current_path)
        };
        if !governance_authority_sidecar_exists(target)? {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let source_parent = open_governance_quarantine_parent(source)?;
            let target_parent = open_governance_quarantine_parent(target)?;
            let source_name = governance_entry_name(source)?;
            let target_name = governance_entry_name(target)?;
            let source_entry = governance_parent_entry_path(&source_parent, source_name)?;
            let target_entry = governance_parent_entry_path(&target_parent, target_name)?;
            verify_governance_quarantine_parent(
                &source_parent.path,
                &source_parent,
                source_parent.identity,
            )?;
            verify_governance_quarantine_parent(
                &target_parent.path,
                &target_parent,
                target_parent.identity,
            )?;
            if std::fs::symlink_metadata(&target_entry).is_ok() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "governance authority target `{}` appeared",
                        target.display()
                    ),
                ));
            }
            // Pin the source by descriptor and identity before linking it.
            // The relative source and target names are resolved through the
            // held O_DIRECTORY descriptors, so a parent retarget cannot
            // redirect either side of publication.
            let source_initial_identity = governance_authority_sidecar_identity_if_regular(
                &source_entry,
            )
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "governance authority source `{}` is not a regular non-symlink file",
                        source.display()
                    ),
                )
            })?;
            #[cfg(test)]
            pause_before_governance_authority_source_open();
            let mut source_options = std::fs::OpenOptions::new();
            source_options.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                source_options.custom_flags(GOVERNANCE_O_NOFOLLOW | GOVERNANCE_O_CLOEXEC);
            }
            let source_file = source_options.open(&source_entry)?;
            let source_fd_identity = governance_authority_sidecar_identity_from_metadata(
                &source_file.metadata()?,
            )
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "governance authority source `{}` is not a regular non-symlink file",
                        source.display()
                    ),
                )
            })?;
            let source_named_identity = governance_authority_sidecar_identity_if_regular(
                &source_entry,
            )
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "governance authority source `{}` changed before hard-link creation",
                        source.display()
                    ),
                )
            })?;
            if source_initial_identity != source_named_identity
                || source_initial_identity != source_fd_identity
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "governance authority source `{}` changed identity before hard-link source open",
                        source.display()
                    ),
                ));
            }
            #[cfg(test)]
            pause_before_governance_authority_hard_link(source, source_fd_identity)?;
            match governance_hard_link_at(&source_parent, source_name, &target_parent, target_name)
            {
                Ok(()) => {
                    // hard_link has created the target at this point.  Pause
                    // before bookkeeping so a target replacement at the
                    // exact seam cannot be mistaken for invocation ownership.
                    #[cfg(test)]
                    pause_after_governance_authority_hard_link_identity_capture();
                    // Capture invocation ownership from the pinned source
                    // descriptor, never by rereading the target pathname.
                    // `hard_link` guarantees that the newly published target
                    // was the source inode at the instant of publication;
                    // cleanup therefore removes only this identity and keeps
                    // any replacement that won the seam.
                    created.push(GovernanceCreatedAuthoritySidecar {
                        path: target.to_path_buf(),
                        file: source_file.try_clone()?,
                        parent: target_parent.clone_handle()?,
                        identity: source_fd_identity,
                    });
                    let source_after =
                        governance_authority_sidecar_identity_if_regular(&source_entry);
                    let source_fd_after = governance_authority_sidecar_identity_from_metadata(
                        &source_file.metadata()?,
                    );
                    let target_after =
                        governance_authority_sidecar_identity_if_regular(&target_entry);
                    if source_after != Some(source_fd_identity)
                        || source_fd_after != Some(source_fd_identity)
                        || target_after != Some(source_fd_identity)
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "governance authority source or hard-link target `{}` changed identity",
                                target.display()
                            ),
                        ));
                    }
                    verify_governance_quarantine_parent(
                        &source_parent.path,
                        &source_parent,
                        source_parent.identity,
                    )?;
                    verify_governance_quarantine_parent(
                        &target_parent.path,
                        &target_parent,
                        target_parent.identity,
                    )?;
                    validate_governance_authority_sidecar(target_state_path)?;
                    target_parent.file.sync_all()?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let source_after =
                        governance_authority_sidecar_identity_if_regular(&source_entry);
                    let source_fd_after = governance_authority_sidecar_identity_from_metadata(
                        &source_file.metadata()?,
                    );
                    let target_after =
                        governance_authority_sidecar_identity_if_regular(&target_entry);
                    if source_after != Some(source_fd_identity)
                        || source_fd_after != Some(source_fd_identity)
                        || target_after != Some(source_fd_identity)
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "governance authority source or existing target `{}` changed identity",
                                target.display()
                            ),
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        GovernancePolicy::persistence_authority_lock_pair_identity(current_path, legacy_path)
            .map_err(std::io::Error::other)
    })();
    if result.is_err() {
        for created_sidecar in created.iter().rev() {
            let _ = remove_created_governance_authority_sidecar(created_sidecar);
        }
    }
    result
}

#[derive(Debug)]
struct GovernancePathSelection {
    path: PathBuf,
    initial_artifacts: GovernanceArtifactSnapshot,
    authority_pair_identity: swarm_agents::tom_agent::GovernanceAuthorityLockIdentity,
    /// The authenticated fixed-pool retention capability is held only while
    /// the selector owns the external path-selection lock.  Mutable policy
    /// constructors receive no copy of this guard; rollback reacquires it
    /// after the constructor has released its state lock.
    cleanup_pool_retention_guard: Option<GovernanceCleanupPoolRetentionGuard>,
    /// A selector-held authority capability is acquired immediately before a
    /// mutable constructor's preflight and consumed by that constructor.  A
    /// loaded existing stream does not need this transfer because its ordinary
    /// loader acquires the lifetime authority lock itself without creating or
    /// replacing signed artifacts.
    authority_pair_guard: Option<GovernanceAuthorityPairGuard>,
    /// Keep both authority sidecar descriptors pinned from selection through
    /// policy construction.  The serving policy then acquires its own
    /// lifetime lock before this selection object is dropped.
    _authority_pair_descriptors: GovernanceAuthorityPairDescriptors,
    _selection_lock: GovernancePathSelectionLock,
}

#[cfg(test)]
type GovernanceDestinationBarrier = (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Mutex<Option<PathBuf>>>,
);

#[cfg(test)]
thread_local! {
    static GOVERNANCE_ROLLBACK_BARRIER: std::cell::RefCell<
        Option<(std::sync::Arc<std::sync::Barrier>, std::sync::Arc<std::sync::Barrier>)>,
    > = const { std::cell::RefCell::new(None) };
    static GOVERNANCE_ROLLBACK_FINAL_MUTATION_BARRIER: std::cell::RefCell<
        Option<(std::sync::Arc<std::sync::Barrier>, std::sync::Arc<std::sync::Barrier>)>,
    > = const { std::cell::RefCell::new(None) };
    static GOVERNANCE_ROLLBACK_PRIVATE_STAGE_BARRIER: std::cell::RefCell<
        Option<(std::sync::Arc<std::sync::Barrier>, std::sync::Arc<std::sync::Barrier>)>,
    > = const { std::cell::RefCell::new(None) };
    static GOVERNANCE_ROLLBACK_INSTALL_BARRIER: std::cell::RefCell<
        Option<(std::sync::Arc<std::sync::Barrier>, std::sync::Arc<std::sync::Barrier>)>,
    > = const { std::cell::RefCell::new(None) };
    static GOVERNANCE_ROLLBACK_JOURNAL_BARRIER: std::cell::RefCell<
        Option<(std::sync::Arc<std::sync::Barrier>, std::sync::Arc<std::sync::Barrier>)>,
    > = const { std::cell::RefCell::new(None) };
    static GOVERNANCE_ROLLBACK_AFTER_RESERVATION_BARRIER: std::cell::RefCell<
        Option<GovernanceDestinationBarrier>,
    > = const { std::cell::RefCell::new(None) };
    static GOVERNANCE_ROLLBACK_CLEANUP_FAILURE_CALL: std::cell::RefCell<Option<usize>> =
        const { std::cell::RefCell::new(None) };
    static GOVERNANCE_AUTHORITY_HARD_LINK_BARRIER: std::cell::RefCell<
        Option<(std::sync::Arc<std::sync::Barrier>, std::sync::Arc<std::sync::Barrier>)>,
    > = const { std::cell::RefCell::new(None) };
    static GOVERNANCE_AUTHORITY_SOURCE_PIN_BARRIER: std::cell::RefCell<
        Option<(std::sync::Arc<std::sync::Barrier>, std::sync::Arc<std::sync::Barrier>)>,
    > = const { std::cell::RefCell::new(None) };
    static GOVERNANCE_AUTHORITY_SOURCE_OPEN_BARRIER: std::cell::RefCell<
        Option<(std::sync::Arc<std::sync::Barrier>, std::sync::Arc<std::sync::Barrier>)>,
    > = const { std::cell::RefCell::new(None) };
    static GOVERNANCE_AUTHORITY_SIDECAR_CREATE_BARRIER: std::cell::RefCell<
        Option<(std::sync::Arc<std::sync::Barrier>, std::sync::Arc<std::sync::Barrier>)>,
    > = const { std::cell::RefCell::new(None) };
    static GOVERNANCE_ARTIFACT_READ_BARRIER: std::cell::RefCell<
        Option<(std::sync::Arc<std::sync::Barrier>, std::sync::Arc<std::sync::Barrier>)>,
    > = const { std::cell::RefCell::new(None) };
    static GOVERNANCE_PARENT_MUTATION_BARRIER: std::cell::RefCell<
        Option<(std::sync::Arc<std::sync::Barrier>, std::sync::Arc<std::sync::Barrier>)>,
    > = const { std::cell::RefCell::new(None) };
    static GOVERNANCE_RETAINED_MOVE_BARRIER: std::cell::RefCell<
        Option<(std::sync::Arc<std::sync::Barrier>, std::sync::Arc<std::sync::Barrier>)>,
    > = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn install_governance_rollback_barrier() -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
) {
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let resumed = std::sync::Arc::new(std::sync::Barrier::new(2));
    GOVERNANCE_ROLLBACK_BARRIER.with(|barrier| {
        *barrier.borrow_mut() = Some((Arc::clone(&reached), Arc::clone(&resumed)));
    });
    (reached, resumed)
}

#[cfg(test)]
fn pause_before_governance_artifact_identity_recheck() {
    GOVERNANCE_ROLLBACK_BARRIER.with(|barrier| {
        if let Some((reached, resumed)) = barrier.borrow_mut().take() {
            reached.wait();
            resumed.wait();
        }
    });
}

#[cfg(test)]
fn install_governance_final_mutation_barrier() -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
) {
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let resumed = std::sync::Arc::new(std::sync::Barrier::new(2));
    GOVERNANCE_ROLLBACK_FINAL_MUTATION_BARRIER.with(|barrier| {
        *barrier.borrow_mut() = Some((Arc::clone(&reached), Arc::clone(&resumed)));
    });
    (reached, resumed)
}

#[cfg(test)]
fn pause_before_governance_artifact_mutation() {
    GOVERNANCE_ROLLBACK_FINAL_MUTATION_BARRIER.with(|barrier| {
        if let Some((reached, resumed)) = barrier.borrow_mut().take() {
            reached.wait();
            resumed.wait();
        }
    });
}

#[cfg(test)]
fn install_governance_private_quarantine_stage_barrier() -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
) {
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let resumed = std::sync::Arc::new(std::sync::Barrier::new(2));
    GOVERNANCE_ROLLBACK_PRIVATE_STAGE_BARRIER.with(|barrier| {
        *barrier.borrow_mut() = Some((Arc::clone(&reached), Arc::clone(&resumed)));
    });
    (reached, resumed)
}

#[cfg(test)]
fn pause_before_governance_private_quarantine_stage() {
    GOVERNANCE_ROLLBACK_PRIVATE_STAGE_BARRIER.with(|barrier| {
        if let Some((reached, resumed)) = barrier.borrow_mut().take() {
            reached.wait();
            resumed.wait();
        }
    });
}

#[cfg(test)]
fn install_governance_rollback_install_barrier() -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
) {
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let resumed = std::sync::Arc::new(std::sync::Barrier::new(2));
    GOVERNANCE_ROLLBACK_INSTALL_BARRIER.with(|barrier| {
        *barrier.borrow_mut() = Some((Arc::clone(&reached), Arc::clone(&resumed)));
    });
    (reached, resumed)
}

#[cfg(test)]
fn pause_before_governance_artifact_install() {
    GOVERNANCE_ROLLBACK_INSTALL_BARRIER.with(|barrier| {
        if let Some((reached, resumed)) = barrier.borrow_mut().take() {
            reached.wait();
            resumed.wait();
        }
    });
}

#[cfg(test)]
fn install_governance_rollback_journal_barrier() -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
) {
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let resumed = std::sync::Arc::new(std::sync::Barrier::new(2));
    GOVERNANCE_ROLLBACK_JOURNAL_BARRIER.with(|barrier| {
        *barrier.borrow_mut() = Some((Arc::clone(&reached), Arc::clone(&resumed)));
    });
    (reached, resumed)
}

#[cfg(test)]
fn pause_after_governance_rollback_journal_entry() {
    GOVERNANCE_ROLLBACK_JOURNAL_BARRIER.with(|barrier| {
        if let Some((reached, resumed)) = barrier.borrow_mut().take() {
            reached.wait();
            resumed.wait();
        }
    });
}

#[cfg(test)]
fn install_governance_rollback_after_reservation_barrier() -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Mutex<Option<PathBuf>>>,
) {
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let resumed = std::sync::Arc::new(std::sync::Barrier::new(2));
    let destination = std::sync::Arc::new(std::sync::Mutex::new(None));
    GOVERNANCE_ROLLBACK_AFTER_RESERVATION_BARRIER.with(|barrier| {
        *barrier.borrow_mut() = Some((
            Arc::clone(&reached),
            Arc::clone(&resumed),
            Arc::clone(&destination),
        ));
    });
    (reached, resumed, destination)
}

#[cfg(test)]
fn pause_after_governance_rollback_quarantine_reservation(destination: &std::path::Path) {
    GOVERNANCE_ROLLBACK_AFTER_RESERVATION_BARRIER.with(|barrier| {
        if let Some((reached, resumed, published_destination)) = barrier.borrow_mut().take() {
            if let Ok(mut published_destination) = published_destination.lock() {
                *published_destination = Some(destination.to_path_buf());
            }
            reached.wait();
            resumed.wait();
        }
    });
}

#[cfg(test)]
fn inject_governance_rollback_cleanup_failure_on_call(call: usize) {
    GOVERNANCE_ROLLBACK_CLEANUP_FAILURE_CALL.with(|remaining| {
        *remaining.borrow_mut() = Some(call);
    });
}

#[cfg(test)]
fn take_governance_rollback_cleanup_failure_on_call() -> bool {
    GOVERNANCE_ROLLBACK_CLEANUP_FAILURE_CALL.with(|remaining| {
        let mut remaining = remaining.borrow_mut();
        match *remaining {
            Some(1) => {
                *remaining = None;
                true
            }
            Some(value) => {
                *remaining = Some(value.saturating_sub(1));
                false
            }
            None => false,
        }
    })
}

#[cfg(test)]
fn install_governance_authority_hard_link_barrier() -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
) {
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let resumed = std::sync::Arc::new(std::sync::Barrier::new(2));
    GOVERNANCE_AUTHORITY_HARD_LINK_BARRIER.with(|barrier| {
        *barrier.borrow_mut() = Some((Arc::clone(&reached), Arc::clone(&resumed)));
    });
    (reached, resumed)
}

#[cfg(test)]
fn install_governance_authority_source_pin_barrier() -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
) {
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let resumed = std::sync::Arc::new(std::sync::Barrier::new(2));
    GOVERNANCE_AUTHORITY_SOURCE_PIN_BARRIER.with(|barrier| {
        *barrier.borrow_mut() = Some((Arc::clone(&reached), Arc::clone(&resumed)));
    });
    (reached, resumed)
}

#[cfg(test)]
fn install_governance_authority_source_open_barrier() -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
) {
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let resumed = std::sync::Arc::new(std::sync::Barrier::new(2));
    GOVERNANCE_AUTHORITY_SOURCE_OPEN_BARRIER.with(|barrier| {
        *barrier.borrow_mut() = Some((Arc::clone(&reached), Arc::clone(&resumed)));
    });
    (reached, resumed)
}

#[cfg(test)]
fn install_governance_authority_sidecar_create_barrier() -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
) {
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let resumed = std::sync::Arc::new(std::sync::Barrier::new(2));
    GOVERNANCE_AUTHORITY_SIDECAR_CREATE_BARRIER.with(|barrier| {
        *barrier.borrow_mut() = Some((Arc::clone(&reached), Arc::clone(&resumed)));
    });
    (reached, resumed)
}

#[cfg(test)]
fn pause_before_governance_authority_source_open() {
    GOVERNANCE_AUTHORITY_SOURCE_OPEN_BARRIER.with(|barrier| {
        if let Some((reached, resumed)) = barrier.borrow_mut().take() {
            reached.wait();
            resumed.wait();
        }
    });
}

#[cfg(test)]
fn pause_after_governance_authority_sidecar_create() {
    GOVERNANCE_AUTHORITY_SIDECAR_CREATE_BARRIER.with(|barrier| {
        if let Some((reached, resumed)) = barrier.borrow_mut().take() {
            reached.wait();
            resumed.wait();
        }
    });
}

#[cfg(test)]
fn pause_before_governance_authority_hard_link(
    _source: &std::path::Path,
    _expected: swarm_agents::tom_agent::GovernanceAuthorityLockIdentity,
) -> Result<(), std::io::Error> {
    GOVERNANCE_AUTHORITY_SOURCE_PIN_BARRIER.with(|barrier| {
        if let Some((reached, resumed)) = barrier.borrow_mut().take() {
            reached.wait();
            resumed.wait();
        }
    });
    Ok(())
}

#[cfg(test)]
fn install_governance_artifact_read_barrier() -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
) {
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let resumed = std::sync::Arc::new(std::sync::Barrier::new(2));
    GOVERNANCE_ARTIFACT_READ_BARRIER.with(|barrier| {
        *barrier.borrow_mut() = Some((Arc::clone(&reached), Arc::clone(&resumed)));
    });
    (reached, resumed)
}

#[cfg(test)]
fn pause_before_governance_artifact_read() {
    GOVERNANCE_ARTIFACT_READ_BARRIER.with(|barrier| {
        if let Some((reached, resumed)) = barrier.borrow_mut().take() {
            reached.wait();
            resumed.wait();
        }
    });
}

#[cfg(test)]
fn install_governance_parent_mutation_barrier() -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
) {
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let resumed = std::sync::Arc::new(std::sync::Barrier::new(2));
    GOVERNANCE_PARENT_MUTATION_BARRIER.with(|barrier| {
        *barrier.borrow_mut() = Some((Arc::clone(&reached), Arc::clone(&resumed)));
    });
    (reached, resumed)
}

#[cfg(test)]
fn pause_before_governance_parent_mutation() {
    GOVERNANCE_PARENT_MUTATION_BARRIER.with(|barrier| {
        if let Some((reached, resumed)) = barrier.borrow_mut().take() {
            reached.wait();
            resumed.wait();
        }
    });
}

#[cfg(test)]
fn install_governance_retained_move_barrier() -> (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
) {
    let reached = std::sync::Arc::new(std::sync::Barrier::new(2));
    let resumed = std::sync::Arc::new(std::sync::Barrier::new(2));
    GOVERNANCE_RETAINED_MOVE_BARRIER.with(|barrier| {
        *barrier.borrow_mut() = Some((Arc::clone(&reached), Arc::clone(&resumed)));
    });
    (reached, resumed)
}

#[cfg(test)]
fn pause_before_governance_retained_move() {
    GOVERNANCE_RETAINED_MOVE_BARRIER.with(|barrier| {
        if let Some((reached, resumed)) = barrier.borrow_mut().take() {
            reached.wait();
            resumed.wait();
        }
    });
}

#[cfg(test)]
fn pause_after_governance_authority_hard_link_identity_capture() {
    GOVERNANCE_AUTHORITY_HARD_LINK_BARRIER.with(|barrier| {
        if let Some((reached, resumed)) = barrier.borrow_mut().take() {
            reached.wait();
            resumed.wait();
        }
    });
}

impl GovernancePathSelection {
    fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn initial_artifacts(&self) -> &GovernanceArtifactSnapshot {
        &self.initial_artifacts
    }

    fn authority_pair_identity(&self) -> swarm_agents::tom_agent::GovernanceAuthorityLockIdentity {
        self.authority_pair_identity
    }

    fn acquire_cleanup_pool_retention_guard(
        &mut self,
        identity: &PersistedAgentIdentity,
    ) -> Result<bool, std::io::Error> {
        if self.cleanup_pool_retention_guard.is_some() {
            return Ok(true);
        }
        // Governance's pre-construction retention namespace intentionally
        // rejects a mixed state/checkpoint pair. Explicit reinitialize is the
        // one supported repair path for that pair; acquire the guard after
        // construction, once the stream is complete.
        if self.initial_artifacts.artifact_set() == GovernanceArtifactSet::RecoverablePartial
            && governance_artifact_snapshot(&self.path)?.artifact_set()
                != GovernanceArtifactSet::Complete
        {
            return Ok(false);
        }
        self.verify_lock()?;
        let guard = swarm_agents::tom_agent::acquire_governance_cleanup_pool_retention_guard(
            &self.path,
            identity.id.clone(),
            identity.id.clone(),
            identity.signing_key.clone(),
        )
        .map_err(std::io::Error::other)?;
        self.verify_lock()?;
        self.cleanup_pool_retention_guard = Some(guard);
        Ok(true)
    }

    fn take_cleanup_pool_retention_guard(
        &mut self,
    ) -> Result<GovernanceCleanupPoolRetentionGuard, std::io::Error> {
        self.cleanup_pool_retention_guard.take().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "governance constructor did not receive a selector cleanup retention guard",
            )
        })
    }

    fn cleanup_pool_retention_guard(&self) -> Option<&GovernanceCleanupPoolRetentionGuard> {
        self.cleanup_pool_retention_guard.as_ref()
    }

    fn acquire_authority_pair_guard(
        &mut self,
        config_path: &std::path::Path,
        identity: &swarm_core::config::IdentityConfig,
    ) -> Result<(), std::io::Error> {
        if self.authority_pair_guard.is_some() {
            return Ok(());
        }
        self.verify_lock()?;
        let current = default_partition_governance_state_path(config_path, identity);
        let legacy = legacy_partition_governance_state_path(config_path);
        let guard =
            swarm_agents::tom_agent::acquire_governance_authority_pair_guard(&current, &legacy)
                .map_err(std::io::Error::other)?;
        guard.verify().map_err(std::io::Error::other)?;
        if guard.identity() != self.authority_pair_identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "governance authority guard identity changed after selection",
            ));
        }
        self._authority_pair_descriptors.verify()?;
        self.verify_lock()?;
        self.authority_pair_guard = Some(guard);
        Ok(())
    }

    fn take_authority_pair_guard(
        &mut self,
    ) -> Result<GovernanceAuthorityPairGuard, std::io::Error> {
        self.authority_pair_guard.take().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "governance constructor did not receive the selector-held authority guard",
            )
        })
    }

    fn verify_lock(&self) -> Result<(), std::io::Error> {
        self._selection_lock.verify_path_identity()
    }

    fn verify_rollback_guards(&self) -> Result<(), std::io::Error> {
        self.verify_lock()?;
        self._authority_pair_descriptors.verify()?;
        if let Some(guard) = self.authority_pair_guard.as_ref() {
            guard.verify().map_err(std::io::Error::other)?;
        }
        self.verify_lock()
    }

    fn verify_initial_artifacts(
        &self,
        config_path: &std::path::Path,
        identity: &swarm_core::config::IdentityConfig,
    ) -> Result<(), std::io::Error> {
        self.verify_lock()?;
        let observed = governance_artifact_snapshot(&self.path)?;
        self.verify_lock()?;
        if observed != self.initial_artifacts {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance artifacts at `{}` changed after selection; refusing to open or mutate a foreign stream",
                    self.path.display()
                ),
            ));
        }
        self.verify_authority_pair_identity(config_path, identity)
    }

    /// Reclassify the selected stream immediately before entering a policy
    /// constructor.  The durable selection lock is not a protocol that a
    /// direct GovernancePolicy caller necessarily participates in; this last
    /// exact snapshot therefore prevents a foreign initializer/reinitializer
    /// that completed after selection (and released its authority lock) from
    /// being mistaken for this invocation's constructor transition.
    fn capture_constructor_preflight(
        &self,
        config_path: &std::path::Path,
        identity: &swarm_core::config::IdentityConfig,
        mode: GovernancePathResolutionMode,
    ) -> Result<GovernanceArtifactSnapshot, std::io::Error> {
        self.verify_initial_artifacts(config_path, identity)?;
        let observed = governance_artifact_snapshot(&self.path)?;
        self.verify_lock()?;
        if observed != self.initial_artifacts {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance constructor preflight at `{}` changed after selection; refusing an unproven foreign transition",
                    self.path.display()
                ),
            ));
        }
        if mode == GovernancePathResolutionMode::Reinitialize
            && observed.artifact_set() == GovernanceArtifactSet::Complete
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "complete governance stream at `{}` appeared before reinitialize construction; refusing a foreign archive transition",
                    self.path.display()
                ),
            ));
        }
        self.verify_authority_pair_identity(config_path, identity)?;
        Ok(observed)
    }

    fn capture_constructor_artifacts(
        &self,
        constructor_before: &GovernanceArtifactSnapshot,
        mode: GovernancePathResolutionMode,
    ) -> Result<GovernanceArtifactSnapshot, std::io::Error> {
        self.verify_lock()?;
        self._authority_pair_descriptors.verify()?;
        let observed = governance_artifact_snapshot(&self.path)?;
        self.verify_lock()?;
        self._authority_pair_descriptors.verify()?;
        if observed.artifact_set() != GovernanceArtifactSet::Complete {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance constructor did not produce one complete artifact stream at `{}`",
                    self.path.display()
                ),
            ));
        }
        match mode {
            GovernancePathResolutionMode::Bootstrap
                if constructor_before.artifact_set() == GovernanceArtifactSet::Complete
                    && observed != *constructor_before =>
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "governance bootstrap constructor changed an existing stream at `{}`; refusing an unproven transition",
                        self.path.display()
                    ),
                ));
            }
            GovernancePathResolutionMode::Reinitialize => {
                if constructor_before
                    .lock
                    .as_ref()
                    .map(|record| &record.identity)
                    != observed.lock.as_ref().map(|record| &record.identity)
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "governance reinitialize constructor changed the permanent lock at `{}`",
                            self.path.display()
                        ),
                    ));
                }
                if constructor_before.state.as_ref().is_some_and(|before| {
                    observed
                        .state
                        .as_ref()
                        .is_some_and(|after| after.identity == before.identity)
                }) || constructor_before.sequence.as_ref().is_some_and(|before| {
                    observed
                        .sequence
                        .as_ref()
                        .is_some_and(|after| after.identity == before.identity)
                }) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "governance reinitialize constructor did not prove replacement identities at `{}`",
                            self.path.display()
                        ),
                    ));
                }
            }
            GovernancePathResolutionMode::Bootstrap => {}
        }
        Ok(observed)
    }

    fn verify_authority_pair_identity(
        &self,
        config_path: &std::path::Path,
        identity: &swarm_core::config::IdentityConfig,
    ) -> Result<(), std::io::Error> {
        self.verify_lock()?;
        self._authority_pair_descriptors.verify()?;
        let current = default_partition_governance_state_path(config_path, identity);
        let legacy = legacy_partition_governance_state_path(config_path);
        // Validation must never repair a missing peer after selection. The
        // resolver establishes the pair once; every later check is strictly
        // observational so a removed/replaced sidecar cannot be silently
        // recreated under the pinned authority identity.
        let observed =
            GovernancePolicy::persistence_authority_lock_pair_identity(&current, &legacy)
                .map_err(std::io::Error::other)?;
        self.verify_lock()?;
        if observed != self.authority_pair_identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance authority sidecar pair changed after selection; refusing to open or serve `{}`",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }

    fn verify_artifacts(
        &self,
        config_path: &std::path::Path,
        identity: &swarm_core::config::IdentityConfig,
        mode: GovernancePathResolutionMode,
    ) -> Result<(), std::io::Error> {
        self.verify_authority_pair_identity(config_path, identity)?;
        let observed =
            resolve_partition_governance_state_path_unlocked(config_path, identity, mode)?;
        self.verify_lock()?;
        if observed != self.path {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance authority path changed from `{}` to `{}` while held",
                    self.path.display(),
                    observed.display()
                ),
            ));
        }
        Ok(())
    }

    fn verify_artifacts_exact(
        &self,
        config_path: &std::path::Path,
        identity: &swarm_core::config::IdentityConfig,
        mode: GovernancePathResolutionMode,
        expected: &GovernanceArtifactSnapshot,
    ) -> Result<(), std::io::Error> {
        self.verify_artifacts(config_path, identity, mode)?;
        self.verify_lock()?;
        let observed = governance_artifact_snapshot(&self.path)?;
        self.verify_lock()?;
        if &observed != expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance artifacts at `{}` changed after constructor; refusing a foreign stream",
                    self.path.display()
                ),
            ));
        }
        if observed.artifact_set() != GovernanceArtifactSet::Complete {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance artifacts at `{}` are no longer a complete stream",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }
}

fn resolve_partition_governance_state_path_unlocked(
    config_path: &std::path::Path,
    identity: &swarm_core::config::IdentityConfig,
    mode: GovernancePathResolutionMode,
) -> Result<PathBuf, std::io::Error> {
    let current = default_partition_governance_state_path(config_path, identity);
    let legacy = legacy_partition_governance_state_path(config_path);
    let current_set = governance_artifact_set(&current)?;
    if current == legacy {
        if mode == GovernancePathResolutionMode::Bootstrap
            && matches!(
                current_set,
                GovernanceArtifactSet::LockOnly
                    | GovernanceArtifactSet::RecoverablePartial
                    | GovernanceArtifactSet::Partial
            )
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance state path `{}` is partial or competing; refusing startup",
                    current.display()
                ),
            ));
        }
        if mode == GovernancePathResolutionMode::Reinitialize
            && matches!(current_set, GovernanceArtifactSet::Partial)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance state path `{}` is missing its lock or state anchor; refusing recovery",
                    current.display()
                ),
            ));
        }
        return Ok(current);
    }

    let legacy_set = governance_artifact_set(&legacy)?;
    if mode == GovernancePathResolutionMode::Bootstrap {
        if current_set != GovernanceArtifactSet::Absent
            && current_set != GovernanceArtifactSet::Complete
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance state path transition is incomplete at `{}`; refusing startup",
                    current.display()
                ),
            ));
        }
        if legacy_set != GovernanceArtifactSet::Absent
            && legacy_set != GovernanceArtifactSet::Complete
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "legacy governance state path is incomplete at `{}`; refusing startup",
                    legacy.display()
                ),
            ));
        }
    } else {
        if current_set == GovernanceArtifactSet::Partial {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance state path `{}` is missing its lock or state anchor; refusing recovery",
                    current.display()
                ),
            ));
        }
        if legacy_set == GovernanceArtifactSet::Partial {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "legacy governance state path `{}` is missing its lock or state anchor; refusing recovery",
                    legacy.display()
                ),
            ));
        }
    }

    let current_present = current_set != GovernanceArtifactSet::Absent;
    let legacy_present = legacy_set != GovernanceArtifactSet::Absent;
    match (current_present, legacy_present) {
        (true, true) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "governance authority exists at both `{}` and legacy path `{}`; refusing to choose a fork",
                current.display(),
                legacy.display()
            ),
        )),
        (false, true) => {
            tracing::warn!(
                current_path = %current.display(),
                legacy_path = %legacy.display(),
                "using the legacy governance authority during path transition"
            );
            Ok(legacy)
        }
        _ => Ok(current),
    }
}

#[derive(Debug)]
struct GovernanceAuthorityPairDescriptors {
    current_path: PathBuf,
    legacy_path: PathBuf,
    current: std::fs::File,
    legacy: std::fs::File,
    identity: swarm_agents::tom_agent::GovernanceAuthorityLockIdentity,
}

impl GovernanceAuthorityPairDescriptors {
    fn open(
        current_path: &std::path::Path,
        legacy_path: &std::path::Path,
        identity: swarm_agents::tom_agent::GovernanceAuthorityLockIdentity,
    ) -> Result<Self, std::io::Error> {
        let current_sidecar = GovernancePolicy::persistence_authority_lock_path(current_path);
        let legacy_sidecar = GovernancePolicy::persistence_authority_lock_path(legacy_path);
        let current = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&current_sidecar)?;
        let legacy = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&legacy_sidecar)?;
        let descriptors = Self {
            current_path: current_sidecar,
            legacy_path: legacy_sidecar,
            current,
            legacy,
            identity,
        };
        descriptors.verify()?;
        Ok(descriptors)
    }

    fn verify(&self) -> Result<(), std::io::Error> {
        let current_named = governance_authority_sidecar_identity_if_regular(&self.current_path);
        let legacy_named = governance_authority_sidecar_identity_if_regular(&self.legacy_path);
        let current_held =
            governance_authority_sidecar_identity_from_metadata(&self.current.metadata()?);
        let legacy_held =
            governance_authority_sidecar_identity_from_metadata(&self.legacy.metadata()?);
        if current_named != Some(self.identity)
            || legacy_named != Some(self.identity)
            || current_held != Some(self.identity)
            || legacy_held != Some(self.identity)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance authority sidecar descriptor changed after selection for `{}` or `{}`",
                    self.current_path.display(),
                    self.legacy_path.display()
                ),
            ));
        }
        Ok(())
    }
}

/// Resolve the authority stream across the config-relative to stable-volume path
/// transition while holding a durable OS advisory lock over the scan. A complete
/// legacy stream remains authoritative until an operator performs an explicit
/// offline relocation; it is never copied into a second stream. Ordinary startup
/// rejects every partial artifact set; explicit reinitialization may select only
/// a state-plus-lock stream whose checkpoint is the sole missing artifact, or
/// a lock-only stream left by an interrupted first initialization.
fn resolve_partition_governance_state_path(
    config_path: &std::path::Path,
    identity: &swarm_core::config::IdentityConfig,
    mode: GovernancePathResolutionMode,
) -> Result<GovernancePathSelection, std::io::Error> {
    let current = default_partition_governance_state_path(config_path, identity);
    let selection_lock =
        GovernancePathSelectionLock::acquire(governance_selection_lock_path(&current))?;
    let legacy = legacy_partition_governance_state_path(config_path);
    let path = resolve_partition_governance_state_path_unlocked(config_path, identity, mode)?;
    let initial_artifacts = governance_artifact_snapshot(&path)?;
    if mode == GovernancePathResolutionMode::Reinitialize
        && initial_artifacts.artifact_set() == GovernanceArtifactSet::Complete
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "complete governance stream at `{}` requires an explicit offline archival migration; refusing reinitialize",
                path.display()
            ),
        ));
    }
    let authority_pair_identity = ensure_governance_authority_lock_pair(&current, &legacy)?;
    let authority_pair_descriptors =
        GovernanceAuthorityPairDescriptors::open(&current, &legacy, authority_pair_identity)?;
    selection_lock.verify_path_identity()?;
    Ok(GovernancePathSelection {
        path,
        initial_artifacts,
        authority_pair_identity,
        cleanup_pool_retention_guard: None,
        authority_pair_guard: None,
        _authority_pair_descriptors: authority_pair_descriptors,
        _selection_lock: selection_lock,
    })
}

fn bootstrap_artifact_ownership(
    initial: &GovernanceArtifactSnapshot,
    key_status: AgentKeyLoadStatus,
) -> GovernanceArtifactOwnership {
    if key_status == AgentKeyLoadStatus::Created
        && initial.artifact_set() == GovernanceArtifactSet::Absent
    {
        GovernanceArtifactOwnership::new(
            GovernanceArtifactMutation::Created,
            GovernanceArtifactMutation::Created,
            GovernanceArtifactMutation::Created,
        )
    } else {
        GovernanceArtifactOwnership::preserve()
    }
}

fn reinitialize_artifact_ownership(
    initial: &GovernanceArtifactSnapshot,
) -> GovernanceArtifactOwnership {
    match initial.artifact_set() {
        GovernanceArtifactSet::LockOnly => GovernanceArtifactOwnership::new(
            GovernanceArtifactMutation::Created,
            GovernanceArtifactMutation::Created,
            GovernanceArtifactMutation::Preserve,
        ),
        GovernanceArtifactSet::RecoverablePartial => GovernanceArtifactOwnership::new(
            GovernanceArtifactMutation::Replaced,
            GovernanceArtifactMutation::Created,
            GovernanceArtifactMutation::Preserve,
        ),
        _ => GovernanceArtifactOwnership::preserve(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GovernanceDirectoryIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

/// A directory descriptor is the capability used for every detector-side
/// rollback mutation.  The pathname is retained only for diagnostics and for
/// the final identity check; mutation paths are derived from the held
/// descriptor, so a later parent-directory replacement cannot redirect the
/// operation into the replacement directory.
#[derive(Debug)]
struct GovernanceHeldParent {
    path: PathBuf,
    file: std::fs::File,
    identity: GovernanceDirectoryIdentity,
}

impl GovernanceHeldParent {
    fn clone_handle(&self) -> Result<Self, std::io::Error> {
        Ok(Self {
            path: self.path.clone(),
            file: self.file.try_clone()?,
            identity: self.identity,
        })
    }
}

fn governance_directory_identity_from_metadata(
    metadata: &std::fs::Metadata,
) -> Option<GovernanceDirectoryIdentity> {
    if !metadata.file_type().is_dir() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(GovernanceDirectoryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Some(GovernanceDirectoryIdentity {})
    }
}

fn open_governance_quarantine_parent(
    path: &std::path::Path,
) -> Result<GovernanceHeldParent, std::io::Error> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("governance artifact `{}` has no parent", path.display()),
        )
    })?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(GOVERNANCE_O_DIRECTORY | GOVERNANCE_O_NOFOLLOW | GOVERNANCE_O_CLOEXEC);
    }
    let parent_file = options.open(parent)?;
    let parent_identity = governance_directory_identity_from_metadata(&parent_file.metadata()?)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance quarantine parent `{}` is not a directory",
                    parent.display()
                ),
            )
        })?;
    let held_parent = GovernanceHeldParent {
        path: parent.to_path_buf(),
        file: parent_file,
        identity: parent_identity,
    };
    verify_governance_quarantine_parent(parent, &held_parent, parent_identity)?;
    Ok(held_parent)
}

fn verify_governance_quarantine_parent(
    parent: &std::path::Path,
    parent_file: &GovernanceHeldParent,
    expected: GovernanceDirectoryIdentity,
) -> Result<(), std::io::Error> {
    let named = std::fs::symlink_metadata(parent).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "cannot verify governance quarantine parent `{}`: {error}",
                parent.display()
            ),
        )
    })?;
    let named_identity = governance_directory_identity_from_metadata(&named).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "governance quarantine parent `{}` is not a directory",
                parent.display()
            ),
        )
    })?;
    let held_identity = governance_directory_identity_from_metadata(&parent_file.file.metadata()?)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "governance quarantine parent `{}` changed type",
                    parent.display()
                ),
            )
        })?;
    if named_identity != expected || held_identity != expected || parent_file.identity != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "governance quarantine parent `{}` changed identity",
                parent.display()
            ),
        ));
    }
    Ok(())
}

fn governance_parent_entry_path(
    parent: &GovernanceHeldParent,
    name: &std::ffi::OsStr,
) -> Result<PathBuf, std::io::Error> {
    use std::path::{Component, Path};

    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid directory-relative governance entry `{name:?}`"),
        ));
    }
    Ok(parent.path.join(name))
}

fn governance_create_new_at(
    parent: &GovernanceHeldParent,
    name: &std::ffi::OsStr,
) -> Result<std::fs::File, std::io::Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "governance entry name contains an interior NUL",
            )
        })?;
        let flags = GOVERNANCE_O_RDWR
            | GOVERNANCE_O_CREAT
            | GOVERNANCE_O_EXCL
            | GOVERNANCE_O_NOFOLLOW
            | GOVERNANCE_O_CLOEXEC;
        // SAFETY: `parent.file` is a live O_DIRECTORY|O_NOFOLLOW descriptor
        // retained by this invocation, and `name` is a validated single
        // directory-entry name copied into a NUL-terminated string.  The
        // returned descriptor is owned by this invocation exactly once.
        let descriptor =
            unsafe { openat(parent.file.as_raw_fd(), name.as_ptr(), flags, 0o600_i32) };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `descriptor` is the newly-created file descriptor returned
        // by openat and is transferred into File exactly once.
        Ok(unsafe { std::fs::File::from_raw_fd(descriptor) })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (parent, name);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "directory-relative governance creation is unavailable on this platform",
        ))
    }
}

fn governance_artifact_record_at(
    parent: &GovernanceHeldParent,
    name: &std::ffi::OsStr,
) -> Result<Option<GovernanceArtifactRecord>, std::io::Error> {
    let path = governance_parent_entry_path(parent, name)?;
    governance_artifact_record(&path)
}

fn governance_hard_link_at(
    source_parent: &GovernanceHeldParent,
    source_name: &std::ffi::OsStr,
    destination_parent: &GovernanceHeldParent,
    destination_name: &std::ffi::OsStr,
) -> Result<(), std::io::Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::AsRawFd;
        let source_name = std::ffi::CString::new(source_name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "governance source name contains an interior NUL",
            )
        })?;
        let destination_name =
            std::ffi::CString::new(destination_name.as_bytes()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "governance destination name contains an interior NUL",
                )
            })?;
        #[cfg(test)]
        pause_before_governance_parent_mutation();
        // SAFETY: both descriptors are live O_DIRECTORY|O_NOFOLLOW handles
        // owned by this invocation, and both C strings are NUL-terminated
        // copies of validated single directory-entry names. flags=0 gives
        // linkat's atomic no-replace semantics for the destination.
        let result = unsafe {
            linkat(
                source_parent.file.as_raw_fd(),
                source_name.as_ptr(),
                destination_parent.file.as_raw_fd(),
                destination_name.as_ptr(),
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (
            source_parent,
            source_name,
            destination_parent,
            destination_name,
        );
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "directory-relative governance publication is unavailable on this platform",
        ))
    }
}

/// Move one directory entry to an absent destination through held parent
/// descriptors.  The no-replace primitive is the final publication guard for
/// rollback quarantine; a destination that wins the race is never replaced.
fn governance_rename_no_replace_at(
    parent: &GovernanceHeldParent,
    source_name: &std::ffi::OsStr,
    destination_name: &std::ffi::OsStr,
) -> Result<(), std::io::Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::AsRawFd;
        let source_name = std::ffi::CString::new(source_name.as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "governance rename source contains an interior NUL",
            )
        })?;
        let destination_name =
            std::ffi::CString::new(destination_name.as_bytes()).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "governance rename destination contains an interior NUL",
                )
            })?;
        #[cfg(test)]
        pause_before_governance_parent_mutation();
        #[cfg(target_os = "linux")]
        // SAFETY: both descriptors are live O_DIRECTORY|O_NOFOLLOW handles
        // retained by this invocation, and both names are validated single
        // directory entries. RENAME_NOREPLACE prevents destination overwrite.
        let result = unsafe {
            renameat2(
                parent.file.as_raw_fd(),
                source_name.as_ptr(),
                parent.file.as_raw_fd(),
                destination_name.as_ptr(),
                GOVERNANCE_RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        // SAFETY: same descriptor/name guarantees as the Linux path;
        // RENAME_EXCL gives renameatx_np no-replace publication.
        let result = unsafe {
            renameatx_np(
                parent.file.as_raw_fd(),
                source_name.as_ptr(),
                parent.file.as_raw_fd(),
                destination_name.as_ptr(),
                GOVERNANCE_RENAME_EXCL,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (parent, source_name, destination_name);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "directory-relative no-replace rename is unavailable on this platform",
        ))
    }
}

fn governance_entry_name(path: &std::path::Path) -> Result<&std::ffi::OsStr, std::io::Error> {
    path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "governance artifact `{}` has no valid file name",
                path.display()
            ),
        )
    })
}

fn next_governance_quarantine_name(
    parent: &GovernanceHeldParent,
    name: &std::ffi::OsStr,
) -> Result<(PathBuf, std::ffi::OsString), std::io::Error> {
    let base = governance_rollback_base_name(name)?;
    for slot in 0..8u8 {
        let candidate_name = std::ffi::OsString::from(format!(".{base}.rollback-{slot}"));
        let expected_copy_name = governance_quarantine_expected_copy_name(&candidate_name)?;
        if governance_artifact_record_at(parent, &candidate_name)?.is_none()
            && governance_artifact_record_at(parent, &expected_copy_name)?.is_none()
        {
            return Ok((parent.path.join(&candidate_name), candidate_name));
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "all fixed private governance rollback quarantines for `{}` are occupied",
            parent.path.join(name).display()
        ),
    ))
}

fn governance_rollback_base_name(name: &std::ffi::OsStr) -> Result<String, std::io::Error> {
    let name = name.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("governance artifact name `{name:?}` is not valid UTF-8"),
        )
    })?;
    let base = name
        .find(".rollback")
        .map_or(name, |index| &name[..index])
        .trim_start_matches('.')
        .to_string();
    if base.is_empty() || base.contains('/') || base.contains('\\') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("governance rollback base name `{name}` is invalid"),
        ));
    }
    Ok(base)
}

fn governance_quarantine_expected_copy_name(
    quarantine_name: &std::ffi::OsStr,
) -> Result<std::ffi::OsString, std::io::Error> {
    let base = governance_rollback_base_name(quarantine_name)?;
    let slot = quarantine_name
        .to_str()
        .and_then(|name| name.strip_prefix(&format!(".{base}.rollback-")))
        .and_then(|suffix| suffix.split('-').next())
        .filter(|slot| slot.chars().all(|byte| byte.is_ascii_digit()))
        .unwrap_or("x");
    Ok(std::ffi::OsString::from(format!(
        ".{base}.rollback-expected-{slot}"
    )))
}

/// Retain an authenticated entry in the governance-owned fixed cleanup pool.
/// The public guard authenticates the parent, binding, signer, source inode,
/// bytes, and pool slot, and performs the only source mutation.  No detector
/// fallback name is allocated when the guard is absent or retention fails.
fn retain_governance_entry_no_replace(
    parent: &GovernanceHeldParent,
    name: &std::ffi::OsStr,
    source_file: &std::fs::File,
    expected: &GovernanceArtifactRecord,
    action: &str,
    retention_guard: Option<&GovernanceCleanupPoolRetentionGuard>,
) -> Result<(), std::io::Error> {
    let source_identity = governance_artifact_identity_from_metadata(&source_file.metadata()?)
        .ok_or_else(|| governance_artifact_identity_error(&parent.path.join(name), action))?;
    if source_identity != expected.identity
        || governance_artifact_record_at(parent, name)?.as_ref() != Some(expected)
    {
        return Err(governance_artifact_identity_error(
            &parent.path.join(name),
            action,
        ));
    }
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    if governance_artifact_record_at(parent, name)?.as_ref() != Some(expected)
        || governance_artifact_identity_from_metadata(&source_file.metadata()?)
            != Some(source_identity.clone())
    {
        return Err(governance_artifact_identity_error(
            &parent.path.join(name),
            action,
        ));
    }
    #[cfg(test)]
    pause_before_governance_retained_move();
    let Some(retention_guard) = retention_guard else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "governance cleanup retention guard is required to {action} `{}`",
                parent.path.join(name).display()
            ),
        ));
    };
    let (device, inode) = {
        #[cfg(unix)]
        {
            (source_identity.device, source_identity.inode)
        }
        #[cfg(not(unix))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "governance cleanup retention requires Unix artifact identity",
            ));
        }
    };
    let expectation = GovernanceCleanupArtifactExpectation {
        device,
        inode,
        content_digest: sha256_hex(&expected.bytes),
        byte_len: expected.bytes.len() as u64,
    };
    let source_path = parent.path.join(name);
    let outcome = retention_guard
        .retain_cleanup_artifact(&source_path, expectation)
        .map_err(std::io::Error::other)?;
    match outcome {
        GovernanceCleanupPoolRetentionOutcome::Retained => {
            if governance_artifact_record_at(parent, name)?.is_some() {
                return Err(governance_artifact_identity_error(
                    &source_path,
                    "confirm fixed-pool governance retention",
                ));
            }
            Ok(())
        }
        GovernanceCleanupPoolRetentionOutcome::ForeignPreserved => Err(
            governance_artifact_identity_error(&source_path, "retain after a foreign replacement"),
        ),
        GovernanceCleanupPoolRetentionOutcome::PoolExhausted => Err(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            format!(
                "governance cleanup retention pool is exhausted while trying to {action} `{}`",
                source_path.display()
            ),
        )),
        GovernanceCleanupPoolRetentionOutcome::Uncertain => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "governance artifact `{}` entered an uncertain fixed-pool retention while trying to {action}",
                source_path.display()
            ),
        )),
    }
}

/// Retain a second exact inode for a journal entry before cleanup starts.  A
/// later cleanup failure must still be compensable even if an earlier
/// quarantine name has already been removed.  The destination is created by
/// hard-link/no-replace; a replacement source is therefore recorded as
/// uncertainty and never path-deleted.
fn backup_governance_rollback_entry(
    source: &std::path::Path,
    expected: &GovernanceArtifactRecord,
) -> Result<PathBuf, std::io::Error> {
    let parent = open_governance_quarantine_parent(source)?;
    let name = governance_entry_name(source)?;
    let source_entry = governance_parent_entry_path(&parent, name)?;
    let source_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&source_entry)?;
    let source_identity = governance_artifact_identity_from_metadata(&source_file.metadata()?)
        .ok_or_else(|| governance_artifact_identity_error(source, "backup a nonregular entry"))?;
    if source_identity != expected.identity
        || governance_artifact_record_at(&parent, name)?.as_ref() != Some(expected)
    {
        return Err(governance_artifact_identity_error(
            source,
            "backup a changed rollback entry",
        ));
    }
    let base = governance_rollback_base_name(name)?;
    let candidate_name = std::ffi::OsString::from(format!(".{base}.rollback-backup"));
    if governance_artifact_record_at(&parent, &candidate_name)?.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "fixed private governance rollback backup `{}` is already occupied",
                parent.path.join(&candidate_name).display()
            ),
        ));
    }
    verify_governance_quarantine_parent(&parent.path, &parent, parent.identity)?;
    if governance_artifact_identity_from_metadata(&source_file.metadata()?)
        != Some(source_identity.clone())
        || governance_artifact_record_at(&parent, name)?.as_ref() != Some(expected)
    {
        return Err(governance_artifact_identity_error(
            source,
            "backup a changed rollback entry",
        ));
    }
    let candidate = parent.path.join(&candidate_name);
    match governance_hard_link_at(&parent, name, &parent, &candidate_name) {
        Ok(()) => {
            if governance_artifact_record_at(&parent, &candidate_name)?.as_ref() == Some(expected)
                && governance_artifact_identity_from_metadata(&source_file.metadata()?)
                    == Some(source_identity.clone())
            {
                Ok(candidate)
            } else {
                Err(governance_artifact_identity_error(
                    &candidate,
                    "retain an identity-changed rollback backup",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

fn governance_artifact_identity_error(path: &std::path::Path, action: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "governance artifact `{}` changed identity or bytes before invocation rollback; refusing {action}",
            path.display()
        ),
    )
}

fn restore_governance_quarantine_no_replace(
    quarantine: &std::path::Path,
    original: &std::path::Path,
    expected: &GovernanceArtifactRecord,
) -> Result<(), std::io::Error> {
    let quarantine_parent = open_governance_quarantine_parent(quarantine)?;
    let original_parent = if quarantine.parent() == original.parent() {
        quarantine_parent.clone_handle()?
    } else {
        open_governance_quarantine_parent(original)?
    };
    let quarantine_name = governance_entry_name(quarantine)?;
    let original_name = governance_entry_name(original)?;
    let Some(source) = governance_artifact_record_at(&quarantine_parent, quarantine_name)? else {
        return Err(governance_artifact_identity_error(
            quarantine,
            "restore a missing quarantine",
        ));
    };
    if &source != expected {
        return Err(governance_artifact_identity_error(
            quarantine,
            "restore a changed quarantine",
        ));
    }
    verify_governance_quarantine_parent(
        &quarantine_parent.path,
        &quarantine_parent,
        quarantine_parent.identity,
    )?;
    verify_governance_quarantine_parent(
        &original_parent.path,
        &original_parent,
        original_parent.identity,
    )?;
    match governance_hard_link_at(
        &quarantine_parent,
        quarantine_name,
        &original_parent,
        original_name,
    ) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(governance_artifact_identity_error(
                original,
                "overwrite an existing foreign artifact",
            ));
        }
        Err(error) => return Err(error),
    }
    verify_governance_quarantine_parent(
        &quarantine_parent.path,
        &quarantine_parent,
        quarantine_parent.identity,
    )?;
    verify_governance_quarantine_parent(
        &original_parent.path,
        &original_parent,
        original_parent.identity,
    )?;
    match governance_artifact_record_at(&original_parent, original_name)? {
        Some(restored) if restored == *expected => Ok(()),
        Some(_) | None => Err(governance_artifact_identity_error(
            original,
            "restore a changed artifact",
        )),
    }
}

fn restore_governance_quarantine_entry_no_replace(
    quarantine: &std::path::Path,
    original: &std::path::Path,
    expected: Option<&GovernanceArtifactRecord>,
) -> Result<(), std::io::Error> {
    match governance_artifact_record(quarantine) {
        Ok(Some(record)) => {
            if let Some(expected) = expected
                && &record != expected
            {
                return Err(governance_artifact_identity_error(
                    quarantine,
                    "restore a changed quarantine",
                ));
            }
            restore_governance_quarantine_no_replace(quarantine, original, &record)
        }
        Ok(None) => Err(governance_artifact_identity_error(
            quarantine,
            "restore a missing quarantine",
        )),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
fn remove_private_governance_quarantine(
    quarantine: &std::path::Path,
    expected: &GovernanceArtifactRecord,
) -> Result<(), std::io::Error> {
    let parent = open_governance_quarantine_parent(quarantine)?;
    remove_private_governance_quarantine_with_parent_and_retention(
        quarantine, expected, &parent, None,
    )
}

fn remove_private_governance_quarantine_for_selection(
    selection: &GovernancePathSelection,
    quarantine: &std::path::Path,
    expected: &GovernanceArtifactRecord,
) -> Result<(), std::io::Error> {
    let parent = open_governance_quarantine_parent(quarantine)?;
    remove_private_governance_quarantine_with_parent_and_retention(
        quarantine,
        expected,
        &parent,
        selection.cleanup_pool_retention_guard(),
    )
}

fn remove_private_governance_quarantine_with_parent(
    quarantine: &std::path::Path,
    expected: &GovernanceArtifactRecord,
    parent: &GovernanceHeldParent,
) -> Result<(), std::io::Error> {
    remove_private_governance_quarantine_with_parent_and_retention(
        quarantine, expected, parent, None,
    )
}

fn remove_private_governance_quarantine_with_parent_and_retention(
    quarantine: &std::path::Path,
    expected: &GovernanceArtifactRecord,
    parent: &GovernanceHeldParent,
    retention_guard: Option<&GovernanceCleanupPoolRetentionGuard>,
) -> Result<(), std::io::Error> {
    let name = governance_entry_name(quarantine)?;
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    #[cfg(test)]
    if take_governance_rollback_cleanup_failure_on_call() {
        return Err(std::io::Error::other(format!(
            "injected governance rollback cleanup failure at `{}`",
            quarantine.display()
        )));
    }
    let held_quarantine = governance_parent_entry_path(parent, name)?;
    let mut file_options = std::fs::OpenOptions::new();
    file_options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        file_options.custom_flags(GOVERNANCE_O_NOFOLLOW | GOVERNANCE_O_CLOEXEC);
    }
    let file = file_options.open(&held_quarantine)?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            format!(
                "governance rollback quarantine `{}` is locked",
                quarantine.display()
            ),
        ),
        std::fs::TryLockError::Error(error) => error,
    })?;
    let held = governance_authority_sidecar_identity_from_metadata(&file.metadata()?).ok_or_else(
        || governance_artifact_identity_error(quarantine, "remove a nonregular quarantine"),
    )?;
    let Some(named) = governance_artifact_record_at(parent, name)? else {
        return Err(governance_artifact_identity_error(
            quarantine,
            "remove a missing quarantine",
        ));
    };
    if &named != expected {
        return Err(governance_artifact_identity_error(
            quarantine,
            "remove a changed quarantine",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if held.device != metadata.dev() || held.inode != metadata.ino() {
            return Err(governance_artifact_identity_error(
                quarantine,
                "remove an identity-changed quarantine",
            ));
        }
    }
    let Some(final_record) = governance_artifact_record_at(parent, name)? else {
        return Err(governance_artifact_identity_error(
            quarantine,
            "remove a disappeared quarantine",
        ));
    };
    if &final_record != expected {
        return Err(governance_artifact_identity_error(
            quarantine,
            "remove a replaced quarantine",
        ));
    }
    #[cfg(test)]
    pause_before_governance_artifact_mutation();
    let Some(after_barrier) = governance_artifact_record_at(parent, name)? else {
        return Err(governance_artifact_identity_error(
            quarantine,
            "remove a disappeared quarantine after final identity check",
        ));
    };
    if &after_barrier != expected {
        return Err(governance_artifact_identity_error(
            quarantine,
            "remove a replacement after final identity check",
        ));
    }
    let Some(after_final_barrier) = governance_artifact_record_at(parent, name)? else {
        return Err(governance_artifact_identity_error(
            quarantine,
            "remove a disappeared quarantine after final identity check",
        ));
    };
    if &after_final_barrier != expected {
        return Err(governance_artifact_identity_error(
            quarantine,
            "remove a replacement after final identity check",
        ));
    }
    // Production cleanup has an authenticated fixed-pool capability.  Let the
    // capability perform the only source mutation directly; creating a second
    // private hard-link name here would create an untracked compensation entry
    // if the anchor pair is temporarily mixed during rollback.
    if let Some(retention_guard) = retention_guard {
        retain_governance_entry_no_replace(
            parent,
            name,
            &file,
            expected,
            "retain a private governance quarantine",
            Some(retention_guard),
        )?;
        let expected_copy_name = governance_quarantine_expected_copy_name(name)?;
        if expected_copy_name != name
            && let Some(copy) = governance_artifact_record_at(parent, &expected_copy_name)?
        {
            if &copy != expected {
                return Err(governance_artifact_identity_error(
                    &parent.path.join(&expected_copy_name),
                    "retain a changed rollback expected copy",
                ));
            }
            let copy_entry = governance_parent_entry_path(parent, &expected_copy_name)?;
            let copy_file = file_options.open(&copy_entry)?;
            retain_governance_entry_no_replace(
                parent,
                &expected_copy_name,
                &copy_file,
                expected,
                "retain a private rollback expected copy",
                Some(retention_guard),
            )?;
        }
        return Ok(());
    }
    #[cfg(test)]
    pause_before_governance_private_quarantine_stage();
    // Publish a hard link into the same held, O_NOFOLLOW parent directory.
    // Unlike rename, hard_link is atomic no-replace publication: a writer
    // that wins the destination race is reported as uncertainty and its entry
    // is never overwritten or unlinked by this invocation.
    let (staged, staged_name) = next_governance_quarantine_name(parent, name)?;
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    if governance_artifact_record_at(parent, name)?.as_ref() != Some(expected)
        || governance_authority_sidecar_identity_from_metadata(&file.metadata()?) != Some(held)
    {
        return Err(governance_artifact_identity_error(
            quarantine,
            "stage a changed quarantine",
        ));
    }
    #[cfg(test)]
    pause_after_governance_rollback_quarantine_reservation(&staged);
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    if governance_artifact_record_at(parent, &staged_name)?.is_some() {
        return Err(governance_artifact_identity_error(
            &staged,
            "overwrite a foreign staged quarantine destination",
        ));
    }
    match governance_hard_link_at(parent, name, parent, &staged_name) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(governance_artifact_identity_error(
                &staged,
                "overwrite a foreign staged quarantine destination",
            ));
        }
        Err(error) => return Err(error),
    }
    let moved = governance_artifact_record_at(parent, &staged_name)?.ok_or_else(|| {
        governance_artifact_identity_error(&staged, "remove a disappeared staged quarantine")
    })?;
    if &moved != expected {
        return Err(governance_artifact_identity_error(
            &staged,
            "remove a foreign staged quarantine",
        ));
    }
    if governance_artifact_record_at(parent, name)?.as_ref() != Some(expected)
        || governance_authority_sidecar_identity_from_metadata(&file.metadata()?) != Some(held)
    {
        return Err(governance_artifact_identity_error(
            quarantine,
            "unlink a changed quarantine",
        ));
    }
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    if governance_artifact_record_at(parent, name)?.as_ref() != Some(expected)
        || governance_authority_sidecar_identity_from_metadata(&file.metadata()?) != Some(held)
    {
        return Err(governance_artifact_identity_error(
            quarantine,
            "unlink a replacement after final identity check",
        ));
    }
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    retain_governance_entry_no_replace(
        parent,
        name,
        &file,
        expected,
        "retain a private quarantine after a replacement at its final identity check",
        retention_guard,
    )?;
    if governance_artifact_record_at(parent, name)?.is_some() {
        return Err(governance_artifact_identity_error(
            quarantine,
            "confirm a privately retained quarantine move",
        ));
    }
    // Both the original and the hard-linked journal copy are now retained by
    // exact inode in private names.  They are never unlinked by pathname;
    // bounded lifecycle cleanup may process these names later.
    if governance_artifact_record_at(parent, &staged_name)?.as_ref() != Some(expected) {
        return Err(governance_artifact_identity_error(
            &staged,
            "retain a replaced staged quarantine",
        ));
    }
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    retain_governance_entry_no_replace(
        parent,
        &staged_name,
        &file,
        expected,
        "retain a staged private quarantine after its final identity check",
        retention_guard,
    )?;
    Ok(())
}

fn quarantine_governance_artifact(
    selection: Option<&GovernancePathSelection>,
    path: &std::path::Path,
    expected: &GovernanceArtifactRecord,
) -> Result<Option<PathBuf>, std::io::Error> {
    let parent = open_governance_quarantine_parent(path)?;
    quarantine_governance_artifact_with_parent(selection, path, expected, &parent)
}

fn quarantine_governance_artifact_with_parent(
    selection: Option<&GovernancePathSelection>,
    path: &std::path::Path,
    expected: &GovernanceArtifactRecord,
    parent: &GovernanceHeldParent,
) -> Result<Option<PathBuf>, std::io::Error> {
    if let Some(selection) = selection {
        return quarantine_governance_artifact_for_selection(selection, path, expected, parent);
    }
    let name = governance_entry_name(path)?;
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    let Some(actual) = governance_artifact_record_at(parent, name)? else {
        return Ok(None);
    };
    if &actual != expected {
        return Err(governance_artifact_identity_error(
            path,
            "remove or quarantine a foreign artifact",
        ));
    }
    if let Some(selection) = selection {
        selection.verify_rollback_guards()?;
    }
    #[cfg(test)]
    pause_before_governance_artifact_identity_recheck();
    if let Some(selection) = selection {
        selection.verify_rollback_guards()?;
    }
    let Some(rechecked) = governance_artifact_record_at(parent, name)? else {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a disappeared artifact",
        ));
    };
    if &rechecked != expected {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a changed artifact",
        ));
    }
    if let Some(selection) = selection {
        selection.verify_rollback_guards()?;
    }
    let Some(final_record) = governance_artifact_record_at(parent, name)? else {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a disappeared artifact",
        ));
    };
    if &final_record != expected {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a changed artifact",
        ));
    }
    if let Some(selection) = selection {
        selection.verify_rollback_guards()?;
    }
    let Some(final_record_after_barrier) = governance_artifact_record_at(parent, name)? else {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a disappeared artifact",
        ));
    };
    if &final_record_after_barrier != expected {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a replacement",
        ));
    }
    if let Some(selection) = selection {
        selection.verify_rollback_guards()?;
    }
    // This barrier is intentionally after the last identity read that
    // authenticates the source entry.  The resumed path performs one more
    // identity check; a replacement at the exact seam is therefore retained
    // rather than moved or removed by pathname.
    #[cfg(test)]
    pause_before_governance_artifact_mutation();
    let Some(after_final_barrier) = governance_artifact_record_at(parent, name)? else {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a disappeared artifact after final identity check",
        ));
    };
    if &after_final_barrier != expected {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a replacement after final identity check",
        ));
    }
    let mut source_options = std::fs::OpenOptions::new();
    source_options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        source_options.custom_flags(GOVERNANCE_O_NOFOLLOW | GOVERNANCE_O_CLOEXEC);
    }
    let source_entry = governance_parent_entry_path(parent, name)?;
    let source_file = source_options.open(&source_entry)?;
    let source_identity = governance_artifact_identity_from_metadata(&source_file.metadata()?)
        .ok_or_else(|| governance_artifact_identity_error(path, "open a nonregular artifact"))?;
    if source_identity != expected.identity {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine an identity-changed artifact",
        ));
    }
    let (quarantine, quarantine_name) = next_governance_quarantine_name(parent, name)?;
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    if let Some(selection) = selection {
        selection.verify_rollback_guards()?;
    }
    let Some(after_reservation) = governance_artifact_record_at(parent, name)? else {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a disappeared artifact",
        ));
    };
    if &after_reservation != expected {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a changed artifact",
        ));
    }
    if governance_artifact_record_at(parent, &quarantine_name)?.is_some() {
        return Err(governance_artifact_identity_error(
            &quarantine,
            "overwrite a foreign quarantine destination",
        ));
    }
    if let Some(selection) = selection {
        selection.verify_rollback_guards()?;
    }
    #[cfg(test)]
    pause_after_governance_rollback_quarantine_reservation(&quarantine);
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    if governance_artifact_record_at(parent, &quarantine_name)?.is_some() {
        return Err(governance_artifact_identity_error(
            &quarantine,
            "overwrite a foreign quarantine destination",
        ));
    }
    if governance_artifact_record_at(parent, name)?.as_ref() != Some(expected)
        || governance_artifact_identity_from_metadata(&source_file.metadata()?).as_ref()
            != Some(&source_identity)
    {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a changed source",
        ));
    }
    match governance_hard_link_at(parent, name, parent, &quarantine_name) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(governance_artifact_identity_error(
                &quarantine,
                "overwrite a foreign quarantine destination",
            ));
        }
        Err(error) => {
            return Err(error);
        }
    }
    let moved = governance_artifact_record_at(parent, &quarantine_name)?.ok_or_else(|| {
        governance_artifact_identity_error(&quarantine, "quarantine a disappeared artifact")
    })?;
    if moved != *expected
        || governance_artifact_record_at(parent, name)?.as_ref() != Some(expected)
        || governance_artifact_identity_from_metadata(&source_file.metadata()?).as_ref()
            != Some(&source_identity)
    {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a foreign replacement",
        ));
    }
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    if governance_artifact_record_at(parent, name)?.as_ref() != Some(expected)
        || governance_artifact_identity_from_metadata(&source_file.metadata()?).as_ref()
            != Some(&source_identity)
    {
        return Err(governance_artifact_identity_error(
            path,
            "unlink a replacement after final identity check",
        ));
    }
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    retain_governance_entry_no_replace(
        parent,
        name,
        &source_file,
        expected,
        "retain a quarantined source after a replacement at its final identity check",
        selection.and_then(GovernancePathSelection::cleanup_pool_retention_guard),
    )?;
    if governance_artifact_record_at(parent, name)?.is_some() {
        return Err(governance_artifact_identity_error(
            path,
            "confirm a quarantined source move",
        ));
    }
    Ok(Some(quarantine))
}

/// Quarantine one selected stream entry without asking the cleanup-pool guard
/// to mutate a single signed anchor.  Rollback first moves every active
/// anchor into private entries, then installs the prior complete stream, and
/// only then runs fixed-pool retention on those private entries.  The second
/// hard link preserves the expected inode if a foreign writer wins the exact
/// rename seam; it is a deterministic bounded name, never a PID/counter
/// fallback.
fn quarantine_governance_artifact_for_selection(
    selection: &GovernancePathSelection,
    path: &std::path::Path,
    expected: &GovernanceArtifactRecord,
    parent: &GovernanceHeldParent,
) -> Result<Option<PathBuf>, std::io::Error> {
    let name = governance_entry_name(path)?;
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    let Some(actual) = governance_artifact_record_at(parent, name)? else {
        return Ok(None);
    };
    if &actual != expected {
        return Err(governance_artifact_identity_error(
            path,
            "remove or quarantine a foreign artifact",
        ));
    }
    selection.verify_rollback_guards()?;
    let mut source_options = std::fs::OpenOptions::new();
    source_options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        source_options.custom_flags(GOVERNANCE_O_NOFOLLOW | GOVERNANCE_O_CLOEXEC);
    }
    let source_entry = governance_parent_entry_path(parent, name)?;
    let source_file = source_options.open(&source_entry)?;
    let source_identity = governance_artifact_identity_from_metadata(&source_file.metadata()?)
        .ok_or_else(|| governance_artifact_identity_error(path, "open a nonregular artifact"))?;
    if source_identity != expected.identity {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine an identity-changed artifact",
        ));
    }
    let (quarantine, quarantine_name) = next_governance_quarantine_name(parent, name)?;
    let expected_copy_name = governance_quarantine_expected_copy_name(&quarantine_name)?;
    let expected_copy = parent.path.join(&expected_copy_name);
    if governance_artifact_record_at(parent, &quarantine_name)?.is_some()
        || governance_artifact_record_at(parent, &expected_copy_name)?.is_some()
    {
        return Err(governance_artifact_identity_error(
            &quarantine,
            "reuse an occupied fixed rollback quarantine",
        ));
    }
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    if governance_artifact_record_at(parent, name)?.as_ref() != Some(expected)
        || governance_artifact_identity_from_metadata(&source_file.metadata()?).as_ref()
            != Some(&source_identity)
    {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a changed source",
        ));
    }
    match governance_hard_link_at(parent, name, parent, &expected_copy_name) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(governance_artifact_identity_error(
                &expected_copy,
                "overwrite a foreign rollback expected copy",
            ));
        }
        Err(error) => return Err(error),
    }
    let expected_copy_record = governance_artifact_record_at(parent, &expected_copy_name)?;
    if expected_copy_record.as_ref() != Some(expected) {
        return Err(governance_artifact_identity_error(
            &expected_copy,
            "retain a changed rollback expected copy",
        ));
    }
    selection.verify_rollback_guards()?;
    #[cfg(test)]
    pause_after_governance_rollback_quarantine_reservation(&quarantine);
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    if governance_artifact_record_at(parent, &quarantine_name)?.is_some()
        || governance_artifact_record_at(parent, name)?.as_ref() != Some(expected)
        || governance_artifact_identity_from_metadata(&source_file.metadata()?).as_ref()
            != Some(&source_identity)
    {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a changed source or destination",
        ));
    }
    match governance_rename_no_replace_at(parent, name, &quarantine_name) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(governance_artifact_identity_error(
                &quarantine,
                "overwrite a foreign quarantine destination",
            ));
        }
        Err(error) => return Err(error),
    }
    let moved = governance_artifact_record_at(parent, &quarantine_name)?.ok_or_else(|| {
        governance_artifact_identity_error(&quarantine, "quarantine a disappeared artifact")
    })?;
    if moved != *expected {
        // The no-replace move may have moved a foreign entry that won the
        // final-check seam. Restore it only when the canonical name is still
        // absent; never overwrite a competing entry.
        if governance_artifact_record_at(parent, name)?.is_none() {
            let _ = governance_rename_no_replace_at(parent, &quarantine_name, name);
        }
        return Err(governance_artifact_identity_error(
            path,
            "quarantine a foreign replacement",
        ));
    }
    if governance_artifact_record_at(parent, name)?.is_some()
        || governance_artifact_identity_from_metadata(&source_file.metadata()?).as_ref()
            != Some(&source_identity)
    {
        return Err(governance_artifact_identity_error(
            path,
            "quarantine an unexpected source after move",
        ));
    }
    verify_governance_quarantine_parent(&parent.path, parent, parent.identity)?;
    selection.verify_rollback_guards()?;
    Ok(Some(quarantine))
}

fn install_governance_artifact_no_replace(
    selection: &GovernancePathSelection,
    path: &std::path::Path,
    before: &GovernanceArtifactRecord,
) -> Result<(GovernanceArtifactRecord, PathBuf), std::io::Error> {
    use std::io::Write;

    let parent = open_governance_quarantine_parent(path)?;
    let target_name = governance_entry_name(path)?;
    let base = governance_rollback_base_name(target_name)?;
    let temporary_name = std::ffi::OsString::from(format!(".{base}.rollback-install"));
    let temporary = parent.path.join(&temporary_name);
    let temporary_entry = governance_parent_entry_path(&parent, &temporary_name)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary_entry)?;
    file.write_all(&before.bytes)?;
    file.sync_all()?;
    let temporary_record =
        governance_artifact_record_at(&parent, &temporary_name)?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("rollback temporary `{}` disappeared", temporary.display()),
            )
        })?;
    let result = (|| {
        verify_governance_quarantine_parent(&parent.path, &parent, parent.identity)?;
        selection.verify_rollback_guards()?;
        if governance_artifact_record_at(&parent, target_name)?.is_some() {
            return Err(governance_artifact_identity_error(
                path,
                "overwrite an existing artifact",
            ));
        }
        // The target absence check is the last identity read before the
        // atomic no-replace hard-link.  The adversarial test pauses here so
        // a competing creator can win the exact seam; `hard_link` must then
        // fail with AlreadyExists and leave that foreign target untouched.
        #[cfg(test)]
        pause_before_governance_artifact_install();
        match governance_hard_link_at(&parent, &temporary_name, &parent, target_name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(governance_artifact_identity_error(
                    path,
                    "overwrite a foreign artifact",
                ));
            }
            Err(error) => return Err(error),
        }
        verify_governance_quarantine_parent(&parent.path, &parent, parent.identity)?;
        selection.verify_rollback_guards()?;
        let installed = governance_artifact_record_at(&parent, target_name)?.ok_or_else(|| {
            governance_artifact_identity_error(path, "install a missing artifact")
        })?;
        if installed.identity != temporary_record.identity || installed.bytes != before.bytes {
            return Err(governance_artifact_identity_error(
                path,
                "install an identity-changed artifact",
            ));
        }
        parent.file.sync_all()?;
        Ok(installed)
    })();
    match result {
        Ok(installed) => Ok((installed, temporary)),
        Err(error) => {
            if let Ok(Some(temp)) = governance_artifact_record_at(&parent, &temporary_name) {
                let _ = remove_private_governance_quarantine_with_parent_and_retention(
                    &temporary,
                    &temp,
                    &parent,
                    selection.cleanup_pool_retention_guard(),
                );
            }
            Err(error)
        }
    }
}

/// Undo only the active artifacts created by a failed path selection operation.
/// Pre-existing complete streams are never touched. Recovery of a pre-existing
/// lock-only stream removes the newly created anchors but deliberately leaves
/// its permanent lock in place; recovery of a checkpoint-lagging stream restores
/// the original signed state and leaves its lock in place.
fn rollback_governance_artifacts_after_selection_conflict(
    selection: &GovernancePathSelection,
    before: &GovernanceArtifactSnapshot,
    ownership: GovernanceArtifactOwnership,
) -> Result<(), std::io::Error> {
    let constructor_before = ownership.constructor_before.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "governance rollback lacks an exact constructor preflight snapshot",
        )
    })?;
    if constructor_before != before {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "governance rollback constructor preflight no longer matches selected prestate at `{}`",
                selection.path().display()
            ),
        ));
    }
    let path = selection.path();
    let sequence_path = GovernancePolicy::persistence_sequence_path(path);
    let lock_path = GovernancePolicy::persistence_lock_path(path);
    let plans = [
        (
            path,
            ownership.state,
            before.state.as_ref(),
            ownership.expected_after.state.as_ref(),
        ),
        (
            sequence_path.as_path(),
            ownership.sequence,
            before.sequence.as_ref(),
            ownership.expected_after.sequence.as_ref(),
        ),
        (
            lock_path.as_path(),
            ownership.lock,
            before.lock.as_ref(),
            ownership.expected_after.lock.as_ref(),
        ),
    ];

    // Authenticate every artifact before mutating any one of them. This is
    // the transaction preflight: a foreign replacement in any peer aborts
    // the whole rollback with the original stream untouched.
    selection.verify_rollback_guards()?;
    if selection.cleanup_pool_retention_guard().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "governance rollback requires an authenticated cleanup-pool retention guard",
        ));
    }
    for (artifact_path, mutation, original, expected_after) in plans {
        preflight_governance_rollback_entry(
            selection,
            artifact_path,
            mutation,
            original,
            expected_after,
        )?;
    }
    selection.verify_rollback_guards()?;

    let mut journal = Vec::new();
    for (artifact_path, mutation, original, expected_after) in plans {
        match journalize_governance_rollback_entry(
            selection,
            artifact_path,
            mutation,
            original,
            expected_after,
        ) {
            Ok(Some(entry)) => {
                journal.push(entry);
                #[cfg(test)]
                if journal.len() == 1 {
                    pause_after_governance_rollback_journal_entry();
                }
            }
            Ok(None) => {}
            Err(error) => {
                let compensation = compensate_governance_rollback_journal(selection, &mut journal);
                return Err(match compensation {
                    Ok(()) => error,
                    Err(compensation_error) => std::io::Error::other(format!(
                        "{error}; transactional rollback compensation failed: {compensation_error}"
                    )),
                });
            }
        }
    }

    // The selected reinitialize prestate may legitimately be state+lock with
    // no checkpoint.  All active post-constructor anchors are now quarantined,
    // so the pool guard sees the safe both-absent anchor set.  Retain the
    // private sources before publishing any partial prestate; a later guard
    // call after installing state alone would (correctly) reject the mixed
    // stream.
    for entry in &journal {
        if let Some(expected) = governance_artifact_record(&entry.quarantine)? {
            let parent = open_governance_quarantine_parent(&entry.quarantine)?;
            retain_governance_entry_no_replace(
                &parent,
                governance_entry_name(&entry.quarantine)?,
                &std::fs::OpenOptions::new().read(true).write(true).open(
                    governance_parent_entry_path(
                        &parent,
                        governance_entry_name(&entry.quarantine)?,
                    )?,
                )?,
                &expected,
                "retain a rollback quarantine before publishing the prior stream",
                selection.cleanup_pool_retention_guard(),
            )?;
        }
    }

    if let Err(error) = install_governance_rollback_entries(&mut journal, selection) {
        let compensation = compensate_governance_rollback_journal(selection, &mut journal);
        return Err(match compensation {
            Ok(()) => error,
            Err(compensation_error) => std::io::Error::other(format!(
                "{error}; transactional rollback compensation failed: {compensation_error}"
            )),
        });
    }

    if let Err(error) = verify_governance_rollback_commit(&journal, selection)
        .and_then(|()| prepare_governance_rollback_cleanup(&mut journal, selection))
    {
        let compensation = compensate_governance_rollback_journal(selection, &mut journal);
        return Err(match compensation {
            Ok(()) => error,
            Err(compensation_error) => std::io::Error::other(format!(
                "{error}; transactional rollback compensation failed: {compensation_error}"
            )),
        });
    }
    // Every journal entry is now committed and has a retained backup.  Only
    // this final cleanup phase may remove private names; if a later cleanup
    // fails, compensation can restore entries whose primary quarantine was
    // already removed from the directory.
    for index in 0..journal.len() {
        if let Err(error) = finalize_governance_rollback_entry(&journal[index], selection) {
            let compensation = compensate_governance_rollback_journal(selection, &mut journal);
            return Err(match compensation {
                Ok(()) => error,
                Err(compensation_error) => std::io::Error::other(format!(
                    "{error}; transactional rollback compensation failed: {compensation_error}"
                )),
            });
        }
    }
    for entry in &journal {
        if let Err(error) = cleanup_governance_rollback_backups(selection, entry) {
            return Err(std::io::Error::other(format!(
                "governance rollback committed but private backup cleanup failed: {error}"
            )));
        }
    }
    if !journal.is_empty()
        && let Some(parent) = path.parent()
    {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[derive(Debug)]
struct GovernanceRollbackJournalEntry {
    path: PathBuf,
    mutation: GovernanceArtifactMutation,
    before: Option<GovernanceArtifactRecord>,
    after: GovernanceArtifactRecord,
    quarantine: PathBuf,
    installed: Option<(GovernanceArtifactRecord, PathBuf)>,
    /// Retained hard-link copies created before any cleanup unlink.  These
    /// make a later finalization failure compensable after an earlier private
    /// quarantine name has already been removed.
    cleanup_backups: Vec<(GovernanceArtifactRecord, PathBuf)>,
}

fn preflight_governance_rollback_entry(
    selection: &GovernancePathSelection,
    path: &std::path::Path,
    mutation: GovernanceArtifactMutation,
    before: Option<&GovernanceArtifactRecord>,
    expected_after: Option<&GovernanceArtifactRecord>,
) -> Result<bool, std::io::Error> {
    selection.verify_rollback_guards()?;
    if mutation == GovernanceArtifactMutation::Preserve {
        return Ok(false);
    }
    let expected_after = expected_after.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "missing invocation-owned governance artifact identity for `{}`",
                path.display()
            ),
        )
    })?;
    let actual = governance_artifact_record(path)?;
    match mutation {
        GovernanceArtifactMutation::Created => {
            if actual.as_ref() != Some(expected_after) {
                return Err(governance_artifact_identity_error(
                    path,
                    "remove an artifact changed before rollback",
                ));
            }
            Ok(true)
        }
        GovernanceArtifactMutation::Replaced => {
            let before = before.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("missing pre-reinitialize artifact for `{}`", path.display()),
                )
            })?;
            if actual.as_ref() == Some(before) {
                return Ok(false);
            }
            if actual.as_ref() != Some(expected_after) {
                return Err(governance_artifact_identity_error(
                    path,
                    "restore over a foreign artifact",
                ));
            }
            Ok(true)
        }
        GovernanceArtifactMutation::Preserve => Ok(false),
    }
}

fn journalize_governance_rollback_entry(
    selection: &GovernancePathSelection,
    path: &std::path::Path,
    mutation: GovernanceArtifactMutation,
    before: Option<&GovernanceArtifactRecord>,
    expected_after: Option<&GovernanceArtifactRecord>,
) -> Result<Option<GovernanceRollbackJournalEntry>, std::io::Error> {
    if !preflight_governance_rollback_entry(selection, path, mutation, before, expected_after)? {
        return Ok(None);
    }
    let expected_after = expected_after.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("missing post-constructor artifact for `{}`", path.display()),
        )
    })?;
    let quarantine = quarantine_governance_artifact(Some(selection), path, expected_after)?
        .ok_or_else(|| {
            governance_artifact_identity_error(path, "quarantine a disappeared artifact")
        })?;
    let mut cleanup_backups = Vec::new();
    let expected_copy_name =
        governance_quarantine_expected_copy_name(governance_entry_name(&quarantine)?)?;
    let expected_copy = quarantine
        .parent()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "rollback quarantine `{}` has no parent",
                    quarantine.display()
                ),
            )
        })?
        .join(&expected_copy_name);
    if let Some(copy) = governance_artifact_record(&expected_copy)? {
        if copy != *expected_after {
            return Err(governance_artifact_identity_error(
                &expected_copy,
                "retain a changed rollback expected copy",
            ));
        }
        cleanup_backups.push((copy, expected_copy));
    }
    Ok(Some(GovernanceRollbackJournalEntry {
        path: path.to_path_buf(),
        mutation,
        before: before.cloned(),
        after: expected_after.clone(),
        quarantine,
        installed: None,
        cleanup_backups,
    }))
}

fn install_governance_rollback_entries(
    journal: &mut [GovernanceRollbackJournalEntry],
    selection: &GovernancePathSelection,
) -> Result<(), std::io::Error> {
    for entry in journal.iter_mut() {
        if entry.mutation != GovernanceArtifactMutation::Replaced {
            continue;
        }
        let before = entry.before.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "missing pre-reinitialize artifact for `{}`",
                    entry.path.display()
                ),
            )
        })?;
        let installed = install_governance_artifact_no_replace(selection, &entry.path, before)?;
        entry.installed = Some(installed);
    }
    Ok(())
}

fn prepare_governance_rollback_cleanup(
    journal: &mut [GovernanceRollbackJournalEntry],
    selection: &GovernancePathSelection,
) -> Result<(), std::io::Error> {
    for entry in journal.iter_mut() {
        selection.verify_rollback_guards()?;
        if governance_artifact_record(&entry.quarantine)?.as_ref() == Some(&entry.after) {
            let quarantine_backup =
                backup_governance_rollback_entry(&entry.quarantine, &entry.after)?;
            entry
                .cleanup_backups
                .push((entry.after.clone(), quarantine_backup));
        }
        if let Some((installed, temporary)) = &entry.installed {
            let temporary_backup = backup_governance_rollback_entry(temporary, installed)?;
            entry
                .cleanup_backups
                .push((installed.clone(), temporary_backup));
        }
    }
    selection.verify_rollback_guards()
}

fn rollback_copy_for_entry(
    entry: &GovernanceRollbackJournalEntry,
    expected: &GovernanceArtifactRecord,
) -> Result<Option<PathBuf>, std::io::Error> {
    if governance_artifact_record(&entry.quarantine)?.as_ref() == Some(expected) {
        return Ok(Some(entry.quarantine.clone()));
    }
    for (record, path) in &entry.cleanup_backups {
        if record == expected && governance_artifact_record(path)?.as_ref() == Some(expected) {
            return Ok(Some(path.clone()));
        }
    }
    Ok(None)
}

fn cleanup_governance_rollback_backups(
    selection: &GovernancePathSelection,
    entry: &GovernanceRollbackJournalEntry,
) -> Result<(), std::io::Error> {
    let mut first_error = None;
    for (record, path) in &entry.cleanup_backups {
        match governance_artifact_record(path) {
            Ok(None) => continue,
            Err(error) => {
                first_error.get_or_insert(error);
                continue;
            }
            Ok(Some(_)) => {}
        }
        selection.verify_rollback_guards()?;
        if let Err(error) =
            remove_private_governance_quarantine_for_selection(selection, path, record)
        {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn verify_governance_rollback_commit(
    journal: &[GovernanceRollbackJournalEntry],
    selection: &GovernancePathSelection,
) -> Result<(), std::io::Error> {
    for entry in journal {
        selection.verify_rollback_guards()?;
        let actual = governance_artifact_record(&entry.path)?;
        match entry.mutation {
            GovernanceArtifactMutation::Created if actual.is_some() => {
                return Err(governance_artifact_identity_error(
                    &entry.path,
                    "commit a rollback while its created artifact is present",
                ));
            }
            GovernanceArtifactMutation::Replaced => {
                let expected_current = entry
                    .installed
                    .as_ref()
                    .map(|(installed, _)| installed)
                    .or(entry.before.as_ref());
                if actual.as_ref() != expected_current {
                    return Err(governance_artifact_identity_error(
                        &entry.path,
                        "commit a rollback after its restored artifact changed",
                    ));
                }
            }
            GovernanceArtifactMutation::Preserve | GovernanceArtifactMutation::Created => {}
        }
        let quarantine_retained = governance_artifact_record(&entry.quarantine)?.as_ref()
            == Some(&entry.after)
            || entry.cleanup_backups.iter().any(|(record, path)| {
                record == &entry.after
                    && governance_artifact_record(path).ok().flatten().as_ref()
                        == Some(&entry.after)
            });
        if !quarantine_retained {
            return Err(governance_artifact_identity_error(
                &entry.quarantine,
                "commit a rollback after its quarantine changed",
            ));
        }
        if let Some((installed, temporary)) = &entry.installed
            && governance_artifact_record(temporary)?.as_ref() != Some(installed)
        {
            return Err(governance_artifact_identity_error(
                temporary,
                "commit a rollback after its temporary changed",
            ));
        }
    }
    selection.verify_rollback_guards()
}

fn compensate_governance_rollback_journal(
    selection: &GovernancePathSelection,
    journal: &mut [GovernanceRollbackJournalEntry],
) -> Result<(), std::io::Error> {
    let mut first_error = None;
    for entry in journal.iter_mut().rev() {
        if let Err(error) = selection.verify_rollback_guards() {
            first_error.get_or_insert(error);
            continue;
        }
        let result = match entry.mutation {
            GovernanceArtifactMutation::Created => match governance_artifact_record(&entry.path)? {
                None => {
                    let source =
                        rollback_copy_for_entry(entry, &entry.after)?.ok_or_else(|| {
                            governance_artifact_identity_error(
                                &entry.path,
                                "restore a rollback artifact after finalization failure",
                            )
                        })?;
                    selection.verify_rollback_guards()?;
                    restore_governance_quarantine_no_replace(&source, &entry.path, &entry.after)?;
                    selection.verify_rollback_guards()?;
                    let result = remove_private_governance_quarantine_for_selection(
                        selection,
                        &source,
                        &entry.after,
                    );
                    let backup_cleanup = cleanup_governance_rollback_backups(selection, entry);
                    result.and(backup_cleanup)
                }
                Some(current) if current == entry.after => Err(governance_artifact_identity_error(
                    &entry.path,
                    "delete an uncertain rollback artifact",
                )),
                Some(_) => Err(governance_artifact_identity_error(
                    &entry.path,
                    "overwrite a foreign rollback artifact",
                )),
            },
            GovernanceArtifactMutation::Replaced => {
                let before = entry.before.as_ref().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("missing rollback prestate for `{}`", entry.path.display()),
                    )
                })?;
                let current = governance_artifact_record(&entry.path)?;
                if current.as_ref() == Some(before) {
                    let installed_quarantine =
                        quarantine_governance_artifact(Some(selection), &entry.path, before)?
                            .ok_or_else(|| {
                                governance_artifact_identity_error(
                                    &entry.path,
                                    "quarantine a restored rollback artifact",
                                )
                            })?;
                    let source =
                        rollback_copy_for_entry(entry, &entry.after)?.ok_or_else(|| {
                            governance_artifact_identity_error(
                                &entry.path,
                                "restore a rollback artifact after finalization failure",
                            )
                        })?;
                    selection.verify_rollback_guards()?;
                    restore_governance_quarantine_no_replace(&source, &entry.path, &entry.after)?;
                    let mut cleanup_error = None;
                    if let Err(error) = remove_private_governance_quarantine_for_selection(
                        selection,
                        &installed_quarantine,
                        before,
                    ) {
                        cleanup_error.get_or_insert(error);
                    }
                    if let Err(error) = remove_private_governance_quarantine_for_selection(
                        selection,
                        &source,
                        &entry.after,
                    ) {
                        cleanup_error.get_or_insert(error);
                    }
                    if let Err(error) = cleanup_governance_rollback_backups(selection, entry) {
                        cleanup_error.get_or_insert(error);
                    }
                    cleanup_error.map_or(Ok(()), Err)
                } else if let Some(current) = current {
                    let Some((installed, temporary)) = entry.installed.as_ref() else {
                        return Err(governance_artifact_identity_error(
                            &entry.path,
                            "restore an unjournaled rollback artifact",
                        ));
                    };
                    if &current != installed {
                        Err(governance_artifact_identity_error(
                            &entry.path,
                            "overwrite a foreign rollback artifact",
                        ))
                    } else {
                        let installed_quarantine = quarantine_governance_artifact(
                            Some(selection),
                            &entry.path,
                            installed,
                        )?
                        .ok_or_else(|| {
                            governance_artifact_identity_error(
                                &entry.path,
                                "quarantine a missing installed rollback artifact",
                            )
                        })?;
                        let source =
                            rollback_copy_for_entry(entry, &entry.after)?.ok_or_else(|| {
                                governance_artifact_identity_error(
                                    &entry.path,
                                    "restore a rollback artifact after finalization failure",
                                )
                            })?;
                        selection.verify_rollback_guards()?;
                        restore_governance_quarantine_no_replace(
                            &source,
                            &entry.path,
                            &entry.after,
                        )?;
                        let mut cleanup_error = None;
                        if let Err(error) = remove_private_governance_quarantine_for_selection(
                            selection,
                            &installed_quarantine,
                            installed,
                        ) {
                            cleanup_error.get_or_insert(error);
                        }
                        if let Err(error) = remove_private_governance_quarantine_for_selection(
                            selection, temporary, installed,
                        ) {
                            cleanup_error.get_or_insert(error);
                        }
                        if let Err(error) = remove_private_governance_quarantine_for_selection(
                            selection,
                            &source,
                            &entry.after,
                        ) {
                            cleanup_error.get_or_insert(error);
                        }
                        if let Err(error) = cleanup_governance_rollback_backups(selection, entry) {
                            cleanup_error.get_or_insert(error);
                        }
                        cleanup_error.map_or(Ok(()), Err)
                    }
                } else {
                    // Journalization moves the post-constructor entry into a
                    // private quarantine before any prestate is installed.
                    // If a later journal entry drifts, compensation therefore
                    // sees the canonical name absent and must republish the
                    // exact quarantined post-constructor inode.  Publication
                    // is atomic no-replace, so a competing creator at this
                    // seam remains untouched and turns compensation into an
                    // explicit error instead of an overwrite.
                    let source =
                        rollback_copy_for_entry(entry, &entry.after)?.ok_or_else(|| {
                            governance_artifact_identity_error(
                                &entry.path,
                                "restore a rollback artifact after journalization failure",
                            )
                        })?;
                    selection.verify_rollback_guards()?;
                    restore_governance_quarantine_no_replace(&source, &entry.path, &entry.after)?;
                    selection.verify_rollback_guards()?;
                    let result = remove_private_governance_quarantine_for_selection(
                        selection,
                        &source,
                        &entry.after,
                    );
                    let backup_cleanup = cleanup_governance_rollback_backups(selection, entry);
                    result.and(backup_cleanup)
                }
            }
            GovernanceArtifactMutation::Preserve => Ok(()),
        };
        if let Err(error) = result {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn finalize_governance_rollback_entry(
    entry: &GovernanceRollbackJournalEntry,
    selection: &GovernancePathSelection,
) -> Result<(), std::io::Error> {
    selection.verify_rollback_guards()?;
    if governance_artifact_record(&entry.quarantine)?.as_ref() == Some(&entry.after) {
        remove_private_governance_quarantine_for_selection(
            selection,
            &entry.quarantine,
            &entry.after,
        )?;
    }
    if let Some((installed, temporary)) = &entry.installed {
        selection.verify_rollback_guards()?;
        remove_private_governance_quarantine_for_selection(selection, temporary, installed)?;
    }
    Ok(())
}

fn governance_selection_conflict_with_rollback(
    selection: &GovernancePathSelection,
    conflict: std::io::Error,
    ownership: GovernanceArtifactOwnership,
) -> std::io::Error {
    let rollback = rollback_governance_artifacts_after_selection_conflict(
        selection,
        selection.initial_artifacts(),
        ownership,
    );
    match rollback {
        Ok(()) => conflict,
        Err(rollback_error) => std::io::Error::other(format!(
            "{conflict}; governance selection rollback failed: {rollback_error}"
        )),
    }
}

fn admit_runtime_identity(
    registry: &FileAgentIdentityRegistry,
    role: AgentRole,
    slot: &str,
    identity: &PersistedAgentIdentity,
    now_ms: i64,
) -> Result<bool, std::io::Error> {
    match registry.admit_persisted_identity(role, slot, identity, now_ms) {
        Ok(RegistryAdmission::Added | RegistryAdmission::Refreshed) => Ok(true),
        Err(swarm_runtime::agent_identity::AgentIdentityError::UnregisteredIdentity {
            agent_id,
            ..
        }) => {
            tracing::warn!(
                role = ?role,
                slot,
                agent_id,
                module = module_path!(),
                "persisted runtime identity is not admitted; skipping agent registration"
            );
            Ok(false)
        }
        Err(error) => Err(std::io::Error::other(error)),
    }
}

fn admit_required_tom_identity(
    registry: &FileAgentIdentityRegistry,
    identity: &PersistedAgentIdentity,
    now_ms: i64,
) -> Result<RegistryAdmission, std::io::Error> {
    registry
        .admit_persisted_identity(AgentRole::Tom, "primary", identity, now_ms)
        .map_err(|error| {
            std::io::Error::other(format!(
                "Tom/primary identity must be admitted before governance state can load: {error}"
            ))
        })
}

fn build_restartable_agent<F>(
    build: F,
) -> Result<(Box<dyn SwarmAgent>, AgentRestartFactory), String>
where
    F: Fn() -> Result<Box<dyn SwarmAgent>, String> + Send + Sync + 'static,
{
    let restart_factory: AgentRestartFactory = Arc::new(build);
    let agent = (restart_factory.as_ref())()?;
    Ok((agent, restart_factory))
}

fn register_persisted_runtime_agent<F>(
    dispatcher: &mut AgentDispatcher,
    identity_store: &FileAgentKeyStore,
    identity_registry: &FileAgentIdentityRegistry,
    role: AgentRole,
    slot: &str,
    now_ms: i64,
    build: F,
) -> Result<Option<AgentId>, std::io::Error>
where
    F: FnOnce(PersistedAgentIdentity) -> Result<(Box<dyn SwarmAgent>, AgentRestartFactory), String>,
{
    let identity = load_persisted_agent_identity(identity_store, role, slot)?;
    if !admit_runtime_identity(identity_registry, role, slot, &identity, now_ms)? {
        return Ok(None);
    }

    let expected_agent_id = identity.id.clone();
    let (agent, restart_factory) = build(identity).map_err(std::io::Error::other)?;
    if agent.id() != &expected_agent_id {
        return Err(std::io::Error::other(format!(
            "restartable agent builder for {role:?}/{slot} returned mismatched id `{}` (expected `{expected_agent_id}`)",
            agent.id()
        )));
    }

    dispatcher
        .register_restartable(agent, restart_factory)
        .map_err(std::io::Error::other)?;
    Ok(Some(expected_agent_id))
}

fn register_preloaded_runtime_agent<F>(
    dispatcher: &mut AgentDispatcher,
    identity: PersistedAgentIdentity,
    build: F,
) -> Result<AgentId, std::io::Error>
where
    F: FnOnce(PersistedAgentIdentity) -> Result<(Box<dyn SwarmAgent>, AgentRestartFactory), String>,
{
    let expected_agent_id = identity.id.clone();
    let (agent, restart_factory) = build(identity).map_err(std::io::Error::other)?;
    if agent.id() != &expected_agent_id {
        return Err(std::io::Error::other(format!(
            "restartable Tom/primary builder returned mismatched id `{}` (expected `{expected_agent_id}`)",
            agent.id()
        )));
    }
    dispatcher
        .register_restartable(agent, restart_factory)
        .map_err(std::io::Error::other)?;
    Ok(expected_agent_id)
}

fn governance_policy_for_bootstrap(
    config: GovernancePolicyConfig,
    path: &std::path::Path,
    identity: &PersistedAgentIdentity,
    key_status: AgentKeyLoadStatus,
) -> Result<GovernancePolicy, swarm_agents::tom_agent::GovernancePersistenceError> {
    match key_status {
        AgentKeyLoadStatus::Created => GovernancePolicy::initialize_persistence(
            config,
            path,
            identity.id.clone(),
            identity.signing_key.clone(),
        ),
        AgentKeyLoadStatus::Loaded => GovernancePolicy::with_persistence(
            config,
            path,
            identity.id.clone(),
            identity.signing_key.clone(),
        ),
    }
}

fn governance_policy_for_bootstrap_with_authority_pair_guard(
    config: GovernancePolicyConfig,
    path: &std::path::Path,
    identity: &PersistedAgentIdentity,
    key_status: AgentKeyLoadStatus,
    guard: GovernanceAuthorityPairGuard,
) -> Result<GovernancePolicy, swarm_agents::tom_agent::GovernancePersistenceError> {
    if key_status != AgentKeyLoadStatus::Created {
        return Err(swarm_agents::tom_agent::GovernancePersistenceError::Write {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a selector-held authority guard is only transferable to a new bootstrap stream",
            ),
        });
    }
    GovernancePolicy::initialize_persistence_with_authority_pair_guard(
        config,
        path,
        identity.id.clone(),
        identity.signing_key.clone(),
        guard,
    )
}

/// The shipped `swarm-detect` governance composition.
///
/// Every security-sensitive consumer receives a clone of one opaque authority
/// minted by the authenticated persisted governance policy.
#[derive(Clone)]
struct ShippedGovernanceWiring {
    authority: GovernanceAuthority,
}

impl ShippedGovernanceWiring {
    fn new(authority: GovernanceAuthority) -> Self {
        Self { authority }
    }

    fn configure_ingest(&self, state: IngestState) -> IngestState {
        state.with_governance_authority(self.authority.clone())
    }

    fn configure_dispatcher(&self, dispatcher: AgentDispatcher) -> AgentDispatcher {
        dispatcher.with_governance_authority(self.authority.clone())
    }

    fn configure_containment(
        &self,
        sweep: swarm_runtime::containment::ContainmentSweep,
    ) -> swarm_runtime::containment::ContainmentSweep {
        sweep.with_governance_authority(self.authority.clone())
    }
}

fn spawn_secret_reload_watcher(
    secret_dir: PathBuf,
    reload_tx: tokio::sync::mpsc::UnboundedSender<ReloadTrigger>,
    mut global_shutdown: tokio::sync::watch::Receiver<bool>,
) -> RetargetableWatcher {
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let watched_path = secret_dir.clone();
    let join_handle = tokio::spawn(async move {
        let callback_tx = reload_tx.clone();
        let mut watcher = match notify::recommended_watcher(
            move |result: Result<notify::Event, notify::Error>| match result {
                Ok(event)
                    if matches!(
                        event.kind,
                        EventKind::Create(_)
                            | EventKind::Modify(_)
                            | EventKind::Remove(_)
                            | EventKind::Any
                    ) =>
                {
                    let _ = callback_tx.send(ReloadTrigger::SecretChange);
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(
                        module = module_path!(),
                        reason = %error,
                        "secret watcher error"
                    );
                }
            },
        ) {
            Ok(watcher) => watcher,
            Err(error) => {
                tracing::error!(
                    module = module_path!(),
                    secret_dir = %watched_path.display(),
                    reason = %error,
                    "failed to create secret watcher"
                );
                return;
            }
        };

        if let Err(error) = watcher.watch(&watched_path, RecursiveMode::Recursive) {
            tracing::error!(
                module = module_path!(),
                secret_dir = %watched_path.display(),
                reason = %error,
                "failed to watch secret directory"
            );
            return;
        }

        loop {
            tokio::select! {
                changed = global_shutdown.changed() => {
                    if changed.is_err() || *global_shutdown.borrow() {
                        break;
                    }
                }
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() {
                        break;
                    }
                }
            }
        }
    });

    RetargetableWatcher {
        path: secret_dir,
        stop_tx,
        join_handle,
    }
}

fn spawn_reload_tasks(
    state: IngestState,
    shutdown: tokio::sync::watch::Sender<bool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let config_path = state.config_path().to_path_buf();
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::unbounded_channel::<ReloadTrigger>();
    let mut handles = Vec::new();

    let file_tx = reload_tx.clone();
    let watch_path = config_path.clone();
    let mut watcher_shutdown = shutdown.subscribe();
    handles.push(tokio::spawn(async move {
        let callback_tx = file_tx.clone();
        let mut watcher = match notify::recommended_watcher(
            move |result: Result<notify::Event, notify::Error>| match result {
                Ok(event)
                    if matches!(
                        event.kind,
                        EventKind::Create(_)
                            | EventKind::Modify(_)
                            | EventKind::Remove(_)
                            | EventKind::Any
                    ) =>
                {
                    let _ = callback_tx.send(ReloadTrigger::FileChange);
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(
                        module = module_path!(),
                        reason = %error,
                        "config watcher error"
                    );
                }
            },
        ) {
            Ok(watcher) => watcher,
            Err(error) => {
                tracing::error!(
                    module = module_path!(),
                    reason = %error,
                    "failed to create config watcher"
                );
                return;
            }
        };

        if let Err(error) = watcher.watch(&watch_path, RecursiveMode::NonRecursive) {
            tracing::error!(
                module = module_path!(),
                config_path = %watch_path.display(),
                reason = %error,
                "failed to watch config file"
            );
            return;
        }

        let _ = watcher_shutdown.changed().await;
    }));

    #[cfg(unix)]
    {
        let sighup_tx = reload_tx.clone();
        let mut sighup_shutdown = shutdown.subscribe();
        handles.push(tokio::spawn(async move {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                Ok(mut sighup) => loop {
                    tokio::select! {
                        _ = sighup_shutdown.changed() => break,
                        signal = sighup.recv() => {
                            if signal.is_none() {
                                break;
                            }
                            let _ = sighup_tx.send(ReloadTrigger::Signal("SIGHUP"));
                        }
                    }
                },
                Err(error) => {
                    tracing::error!(
                        module = module_path!(),
                        reason = %error,
                        "failed to register SIGHUP handler"
                    );
                }
            }
        }));
    }

    let mut reload_shutdown = shutdown.subscribe();
    handles.push(tokio::spawn(async move {
        let mut secret_watcher = state
            .secret_dir_path()
            .map(|secret_dir| {
                spawn_secret_reload_watcher(secret_dir, reload_tx.clone(), shutdown.subscribe())
            });

        loop {
            tokio::select! {
                _ = reload_shutdown.changed() => break,
                trigger = reload_rx.recv() => {
                    let Some(trigger) = trigger else {
                        break;
                    };

                    // SecretChange triggers only secret re-resolution (no
                    // YAML re-parse). FileChange and Signal do a full reload.
                    match trigger {
                        ReloadTrigger::SecretChange => {
                            let reason = "secret file change";
                            match state.reload_secrets_only() {
                                Ok(()) => {
                                    tracing::info!(
                                        module = module_path!(),
                                        trigger = %reason,
                                        "reloaded secrets without full config reload"
                                    );
                                }
                                Err(error) => {
                                    tracing::error!(
                                        module = module_path!(),
                                        trigger = %reason,
                                        reason = %error,
                                        "secret reload failed"
                                    );
                                }
                            }
                            continue;
                        }
                        ReloadTrigger::FileChange | ReloadTrigger::Signal(_) => {}
                    }

                    let reason = match trigger {
                        ReloadTrigger::FileChange => {
                            let mut seen_file_events = 1usize;
                            let debounce_deadline =
                                tokio::time::Instant::now() + Duration::from_millis(RELOAD_DEBOUNCE_MS);
                            let sleep = tokio::time::sleep_until(debounce_deadline);
                            tokio::pin!(sleep);
                            loop {
                                tokio::select! {
                                    _ = &mut sleep => break format!(
                                        "config file change (coalesced {seen_file_events} events)"
                                    ),
                                    _ = reload_shutdown.changed() => return,
                                    next = reload_rx.recv() => match next {
                                        Some(ReloadTrigger::FileChange) => {
                                            seen_file_events = seen_file_events.saturating_add(1);
                                        }
                                        Some(ReloadTrigger::SecretChange) => {
                                            // Secret changed during config debounce — do a
                                            // full reload which also re-resolves secrets.
                                            break "config + secret file change".to_string();
                                        }
                                        Some(ReloadTrigger::Signal(reason)) => break reason.to_string(),
                                        None => return,
                                    }
                                }
                            }
                        }
                        ReloadTrigger::Signal(reason) => reason.to_string(),
                        ReloadTrigger::SecretChange => unreachable!("handled above"),
                    };

                    match state.reload_from_disk() {
                        Ok(()) => {
                            let next_secret_dir = state.secret_dir_path();
                            let current_secret_dir =
                                secret_watcher.as_ref().map(|watcher| &watcher.path);
                            if watch_paths_differ(current_secret_dir, next_secret_dir.as_ref()) {
                                if let Some(watcher) = secret_watcher.take() {
                                    watcher.stop();
                                }
                                secret_watcher = next_secret_dir.map(|secret_dir| {
                                    spawn_secret_reload_watcher(
                                        secret_dir,
                                        reload_tx.clone(),
                                        shutdown.subscribe(),
                                    )
                                });
                            }
                            tracing::info!(
                                module = module_path!(),
                                trigger = %reason,
                                "reloaded runtime config"
                            );
                        }
                        Err(error) => {
                            tracing::error!(
                                module = module_path!(),
                                trigger = %reason,
                                reason = %error,
                                "config reload failed"
                            );
                        }
                    }
                }
            }
        }

        if let Some(watcher) = secret_watcher {
            watcher.stop();
        }
    }));

    handles
}

async fn wait_for_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(error) = result {
                            tracing::error!(
                                module = module_path!(),
                                reason = %error,
                                "ctrl-c handler failed"
                            );
                        }
                        "SIGINT"
                    }
                    _ = sigterm.recv() => {
                        "SIGTERM"
                    }
                }
            }
            Err(error) => {
                tracing::error!(
                    module = module_path!(),
                    reason = %error,
                    "failed to register SIGTERM handler"
                );
                if let Err(ctrl_c_error) = tokio::signal::ctrl_c().await {
                    tracing::error!(
                        module = module_path!(),
                        reason = %ctrl_c_error,
                        "ctrl-c handler failed"
                    );
                }
                "shutdown signal"
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(
                module = module_path!(),
                reason = %error,
                "ctrl-c handler failed"
            );
        }
        "shutdown signal"
    }
}

async fn wait_for_shutdown_request(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

async fn await_reload_tasks(handles: Vec<tokio::task::JoinHandle<()>>) {
    for handle in handles {
        let _ = handle.await;
    }
}

async fn await_background_task(name: &str, handle: tokio::task::JoinHandle<()>) {
    match tokio::time::timeout(Duration::from_secs(GRACEFUL_SHUTDOWN_TIMEOUT_SECS), handle).await {
        Ok(joined) => {
            let _ = joined;
        }
        Err(_) => {
            tracing::error!(
                module = module_path!(),
                task = name,
                timeout_secs = GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
                "background task shutdown timed out"
            );
        }
    }
}

async fn await_background_tasks(name: &str, handles: Vec<tokio::task::JoinHandle<()>>) {
    for (index, handle) in handles.into_iter().enumerate() {
        let task_name = format!("{name}[{index}]");
        await_background_task(task_name.as_str(), handle).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let _tracing = swarm_runtime_http::cli::tracing::init_tracing(
        "swarm_detect",
        cli.otlp_endpoint.as_deref(),
    )?;
    let config = load_config(&cli.config)?;
    let startup_attestation = StartupAttestationReport::verify(&cli.config);
    let anti_tamper_monitor = AntiTamperMonitor::new();
    let anti_tamper =
        anti_tamper_monitor.evaluate(&config.runtime.anti_tamper, config.runtime.mode);

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "config": cli.config,
                "mode": config.runtime.mode,
                "strategy": config.detection.strategy,
                "serve": cli.serve,
                "bind": cli.bind,
                "startup_attestation": startup_attestation.clone(),
                "anti_tamper": anti_tamper.clone(),
            }))?
        );
    } else if cli.serve {
        println!(
            "swarm-detect serving config={} mode={:?} strategy={} bind={}",
            cli.config.display(),
            config.runtime.mode,
            config.detection.strategy,
            cli.bind
        );
    } else if cli.reinitialize_governance_state {
        println!(
            "swarm-detect reinitializing governance state config={}",
            cli.config.display()
        );
    } else {
        let mut paths = if let Some(dir) = &cli.scenarios_dir {
            scenario_paths_in_dir(dir)?
        } else {
            Vec::new()
        };
        paths.extend(cli.scenario.iter().cloned());
        println!(
            "swarm-detect config={} mode={:?} strategy={} scenario_count={}",
            cli.config.display(),
            config.runtime.mode,
            config.detection.strategy,
            paths.len()
        );
    }

    if !startup_attestation.ready_for_mode(config.runtime.mode) {
        return Err(StartupAttestationFailure::new(&startup_attestation).into());
    }
    if !anti_tamper.effective_ready() {
        return Err(AntiTamperFailure::new(&anti_tamper).into());
    }

    if cli.reinitialize_governance_state {
        let identity_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&cli.config, &config.identity))
                .map_err(std::io::Error::other)?;
        let identity_registry = FileAgentIdentityRegistry::open(resolve_identity_registry_dir(
            &cli.config,
            &config.identity,
        ))
        .map_err(std::io::Error::other)?;
        let tom_identity = identity_store
            .load_existing(AgentRole::Tom, "primary")
            .map_err(std::io::Error::other)?;
        admit_required_tom_identity(
            &identity_registry,
            &tom_identity,
            swarm_runtime::runtime_events::now_ms(),
        )?;
        let mut governance_selection = resolve_partition_governance_state_path(
            &cli.config,
            &config.identity,
            GovernancePathResolutionMode::Reinitialize,
        )?;
        let cleanup_guard_available =
            governance_selection.acquire_cleanup_pool_retention_guard(&tom_identity)?;
        governance_selection.acquire_authority_pair_guard(&cli.config, &config.identity)?;
        let governance_path = governance_selection.path().to_path_buf();
        let initial_artifacts = governance_selection.initial_artifacts().clone();
        governance_selection.verify_initial_artifacts(&cli.config, &config.identity)?;
        let ownership = reinitialize_artifact_ownership(&initial_artifacts);
        let constructor_before = governance_selection.capture_constructor_preflight(
            &cli.config,
            &config.identity,
            GovernancePathResolutionMode::Reinitialize,
        )?;
        let ownership = ownership.with_constructor_before(constructor_before.clone());
        let authority_pair_identity_before = governance_selection.authority_pair_identity();
        if cleanup_guard_available {
            let cleanup_guard = governance_selection.take_cleanup_pool_retention_guard()?;
            drop(cleanup_guard);
        }
        let authority_pair_guard = governance_selection.take_authority_pair_guard()?;
        let reinitialized = Arc::new(
            GovernancePolicy::reinitialize_persistence_with_authority_pair_guard(
                GovernancePolicyConfig {
                    contingency_lease_ttl_ms: config.runtime.partition_contingency_lease_ttl_ms,
                    contingency_blast_radius_cap: config
                        .runtime
                        .partition_contingency_blast_radius_cap,
                },
                governance_selection.path(),
                tom_identity.id.clone(),
                tom_identity.signing_key.clone(),
                format!(
                    "discarded-{}-{}",
                    swarm_runtime::runtime_events::now_ms(),
                    std::process::id()
                ),
                authority_pair_guard,
            )?,
        );
        let expected_after = match governance_selection.capture_constructor_artifacts(
            &constructor_before,
            GovernancePathResolutionMode::Reinitialize,
        ) {
            Ok(expected_after) => expected_after,
            Err(conflict) => {
                drop(reinitialized);
                let _ = governance_selection.acquire_cleanup_pool_retention_guard(&tom_identity);
                let error = governance_selection_conflict_with_rollback(
                    &governance_selection,
                    conflict,
                    ownership,
                );
                drop(governance_selection);
                return Err(error.into());
            }
        };
        let ownership = ownership.with_expected_after(expected_after.clone());
        let validation = governance_selection
            .verify_artifacts_exact(
                &cli.config,
                &config.identity,
                GovernancePathResolutionMode::Reinitialize,
                &expected_after,
            )
            .and_then(|_| {
                if governance_selection.authority_pair_identity() != authority_pair_identity_before
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "governance authority pair identity changed during construction",
                    ));
                }
                reinitialized
                    .authority()
                    .map(|_| ())
                    .map_err(std::io::Error::other)
            })
            .and_then(|_| {
                governance_selection.verify_artifacts_exact(
                    &cli.config,
                    &config.identity,
                    GovernancePathResolutionMode::Reinitialize,
                    &expected_after,
                )
            });
        if let Err(conflict) = validation {
            drop(reinitialized);
            let _ = governance_selection.acquire_cleanup_pool_retention_guard(&tom_identity);
            let error = governance_selection_conflict_with_rollback(
                &governance_selection,
                conflict,
                ownership,
            );
            drop(governance_selection);
            return Err(error.into());
        }
        drop(reinitialized);
        drop(governance_selection);
        println!(
            "swarm-detect initialized empty signed governance state at {}",
            governance_path.display()
        );
        return Ok(());
    }

    if cli.serve {
        let approval_harness = build_approval_harness(&cli)?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (telemetry_tx, telemetry_rx) = tokio::sync::mpsc::channel(10_000);
        let (bridge_ingest_tx, mut bridge_ingest_rx) =
            tokio::sync::mpsc::channel::<swarm_core::telemetry::TelemetryEvent>(10_000);
        let telemetry_rx = WhiskerAgent::shared_receiver(telemetry_rx);
        let agent_health = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
        let mode_state = Arc::new(arc_swap::ArcSwap::from_pointee(SwarmModeState::new()));
        let bridge_registry = BridgeRuntimeRegistry::from_config(&config)?;
        let bridge_health = bridge_registry.shared_health();
        let threat_intel_registry = ThreatIntelFeedRuntimeRegistry::from_config(&config);
        let threat_intel_feed_health = threat_intel_registry.shared_health();
        let runtime_events = RuntimeEventBroadcaster::new(DEFAULT_RUNTIME_EVENT_CAPACITY);
        let agent_key_dir = resolve_agent_key_dir(&cli.config, &config.identity);
        let identity_store =
            FileAgentKeyStore::open(&agent_key_dir).map_err(std::io::Error::other)?;
        let identity_registry = FileAgentIdentityRegistry::open(resolve_identity_registry_dir(
            &cli.config,
            &config.identity,
        ))
        .map_err(std::io::Error::other)?;
        let now_ms = swarm_runtime::runtime_events::now_ms();
        let (tom_identity, tom_key_status) = identity_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .map_err(std::io::Error::other)?;
        admit_required_tom_identity(&identity_registry, &tom_identity, now_ms)?;
        let governance_config = GovernancePolicyConfig {
            contingency_lease_ttl_ms: config.runtime.partition_contingency_lease_ttl_ms,
            contingency_blast_radius_cap: config.runtime.partition_contingency_blast_radius_cap,
        };
        let (governance_policy, _governance_selection_guard) = {
            let mut governance_selection = resolve_partition_governance_state_path(
                &cli.config,
                &config.identity,
                GovernancePathResolutionMode::Bootstrap,
            )?;
            let cleanup_guard_available =
                governance_selection.acquire_cleanup_pool_retention_guard(&tom_identity)?;
            if tom_key_status == AgentKeyLoadStatus::Created {
                governance_selection.acquire_authority_pair_guard(&cli.config, &config.identity)?;
            }
            let initial_artifacts = governance_selection.initial_artifacts().clone();
            governance_selection.verify_initial_artifacts(&cli.config, &config.identity)?;
            let ownership = bootstrap_artifact_ownership(&initial_artifacts, tom_key_status);
            let constructor_before = governance_selection.capture_constructor_preflight(
                &cli.config,
                &config.identity,
                GovernancePathResolutionMode::Bootstrap,
            )?;
            let ownership = ownership.with_constructor_before(constructor_before.clone());
            let authority_pair_identity_before = governance_selection.authority_pair_identity();
            if cleanup_guard_available {
                let cleanup_guard = governance_selection.take_cleanup_pool_retention_guard()?;
                drop(cleanup_guard);
            }
            let policy = Arc::new(if tom_key_status == AgentKeyLoadStatus::Created {
                let authority_pair_guard = governance_selection.take_authority_pair_guard()?;
                governance_policy_for_bootstrap_with_authority_pair_guard(
                    governance_config,
                    governance_selection.path(),
                    &tom_identity,
                    tom_key_status,
                    authority_pair_guard,
                )?
            } else {
                governance_policy_for_bootstrap(
                    governance_config,
                    governance_selection.path(),
                    &tom_identity,
                    tom_key_status,
                )?
            });
            let expected_after = match governance_selection.capture_constructor_artifacts(
                &constructor_before,
                GovernancePathResolutionMode::Bootstrap,
            ) {
                Ok(expected_after) => expected_after,
                Err(conflict) => {
                    drop(policy);
                    let _ =
                        governance_selection.acquire_cleanup_pool_retention_guard(&tom_identity);
                    let error = governance_selection_conflict_with_rollback(
                        &governance_selection,
                        conflict,
                        ownership,
                    );
                    drop(governance_selection);
                    return Err(error.into());
                }
            };
            let ownership = ownership.with_expected_after(expected_after.clone());
            let validation = governance_selection
                .verify_artifacts_exact(
                    &cli.config,
                    &config.identity,
                    GovernancePathResolutionMode::Bootstrap,
                    &expected_after,
                )
                .and_then(|_| {
                    if governance_selection.authority_pair_identity()
                        != authority_pair_identity_before
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "governance authority pair identity changed during construction",
                        ));
                    }
                    policy
                        .authority()
                        .map(|_| ())
                        .map_err(std::io::Error::other)
                })
                .and_then(|_| {
                    governance_selection.verify_artifacts_exact(
                        &cli.config,
                        &config.identity,
                        GovernancePathResolutionMode::Bootstrap,
                        &expected_after,
                    )
                });
            if let Err(conflict) = validation {
                drop(policy);
                let _ = governance_selection.acquire_cleanup_pool_retention_guard(&tom_identity);
                let error = governance_selection_conflict_with_rollback(
                    &governance_selection,
                    conflict,
                    ownership,
                );
                drop(governance_selection);
                return Err(error.into());
            }
            (policy, Arc::new(governance_selection))
        };
        let governance = ShippedGovernanceWiring::new(
            governance_policy
                .authority()
                .map_err(std::io::Error::other)?,
        );
        let ingest_identity =
            load_persisted_agent_identity(&identity_store, AgentRole::Whisker, "primary")?;
        let state = IngestState::from_config_with_signing_key(
            cli.config.clone(),
            config.clone(),
            ingest_identity.signing_key.clone(),
        )?
        .with_startup_attestation(startup_attestation.clone())
        .with_anti_tamper_report(anti_tamper.clone());
        let state = governance.configure_ingest(
            state
                .with_telemetry_channel(telemetry_tx.clone())
                .with_agent_health(Arc::clone(&agent_health))
                .with_mode_state(Arc::clone(&mode_state))
                .with_bridge_health(bridge_health)
                .with_threat_intel_feed_health(threat_intel_feed_health)
                .with_shutdown_channel(shutdown_tx.clone())
                .with_runtime_events(runtime_events.clone())
                .with_approval_harness(approval_harness),
        );
        let dispatcher_shutdown = shutdown_rx.clone();
        let monitor_shutdown = shutdown_rx.clone();
        let mut dispatcher = governance.configure_dispatcher(
            AgentDispatcher::new(
                AgentDispatcherConfig::default(),
                dispatcher_shutdown,
                state.current_substrate(),
                Arc::clone(&agent_health),
            )
            .with_mode_state(Arc::clone(&mode_state))
            .with_request_response_router(state.current_request_response_router())
            .with_strategy_proposal_router(state.current_strategy_proposal_router())
            .with_runtime_events(runtime_events.clone()),
        );
        let mut admitted_identities = Vec::new();
        if let Some(metrics) = state.current_prometheus_metrics() {
            dispatcher = dispatcher.with_metrics(metrics);
        }
        if let Some(whisker_id) = register_persisted_runtime_agent(
            &mut dispatcher,
            &identity_store,
            &identity_registry,
            AgentRole::Whisker,
            "primary",
            now_ms,
            {
                let state = state.clone();
                let telemetry_rx = Arc::clone(&telemetry_rx);
                move |identity| {
                    build_restartable_agent(move || {
                        Ok(Box::new(
                            WhiskerAgent::new_with_shared_receiver_and_signing_key(
                                identity.id.clone(),
                                identity.signing_key.clone(),
                                Arc::clone(&telemetry_rx),
                                state.current_detector(),
                                state.current_substrate(),
                                state.current_pheromone_config(),
                            ),
                        ))
                    })
                }
            },
        )? {
            admitted_identities.push(whisker_id);
        }
        if let Some(calico_id) = register_optional_calico_agent(
            &mut dispatcher,
            &cli.config,
            &config,
            &state,
            &identity_store,
            &identity_registry,
            now_ms,
        )? {
            admitted_identities.push(calico_id);
        }
        let tom_id = register_preloaded_runtime_agent(&mut dispatcher, tom_identity, {
            let governance_policy = Arc::clone(&governance_policy);
            let degraded_tick_threshold = config.runtime.governance_degraded_tick_threshold;
            move |identity| {
                let governance_policy = Arc::clone(&governance_policy);
                build_restartable_agent(move || {
                    // Fallible since BFT-03: the governance policy holds at
                    // most ONE governor signing key, so a restart that tried
                    // to install a second, different key is a configuration
                    // error the supervisor must see, not something to swallow.
                    Ok(Box::new(
                        TomAgent::new_with_signing_key(
                            identity.id.clone(),
                            identity.signing_key.clone(),
                            degraded_tick_threshold,
                            Arc::clone(&governance_policy),
                        )
                        .map_err(|error| error.to_string())?,
                    ))
                })
            }
        })?;
        admitted_identities.push(tom_id);
        if let Some(pounce_id) = register_persisted_runtime_agent(
            &mut dispatcher,
            &identity_store,
            &identity_registry,
            AgentRole::Pouncer,
            "primary",
            now_ms,
            {
                let governance_policy = Arc::clone(&governance_policy);
                let state = state.clone();
                move |identity| {
                    let governance_policy = Arc::clone(&governance_policy);
                    let state = state.clone();
                    build_restartable_agent(move || {
                        Ok(Box::new(
                            PounceAgent::new_with_signing_key(
                                identity.id.clone(),
                                identity.signing_key.clone(),
                                state.current_pheromone_config().response_playbook.clone(),
                            )
                            .with_governance_policy(Arc::clone(&governance_policy)),
                        ))
                    })
                }
            },
        )? {
            admitted_identities.push(pounce_id);
        }
        if config.evolution.enabled
            && let Some(kitten_id) = register_persisted_runtime_agent(
                &mut dispatcher,
                &identity_store,
                &identity_registry,
                AgentRole::Kitten,
                "primary",
                now_ms,
                {
                    let config_path = cli.config.clone();
                    let config = config.clone();
                    let state = state.clone();
                    move |identity| {
                        build_restartable_agent(move || {
                            Ok(Box::new(KittenAgent::new_with_signing_key(
                                identity.id.clone(),
                                identity.signing_key.clone(),
                                config_path.clone(),
                                config.clone(),
                                state.current_substrate(),
                            )))
                        })
                    }
                },
            )?
        {
            admitted_identities.push(kitten_id);
        }
        if let Some(sphinx_id) = register_optional_sphinx_agent(
            &mut dispatcher,
            &cli.config,
            &config,
            &state,
            &identity_store,
            &identity_registry,
            now_ms,
        )? {
            admitted_identities.push(sphinx_id);
        }
        if config.investigation.enabled
            && let Some(stalker_id) = register_persisted_runtime_agent(
                &mut dispatcher,
                &identity_store,
                &identity_registry,
                AgentRole::Stalker,
                "primary",
                now_ms,
                {
                    let state = state.clone();
                    move |identity| {
                        build_restartable_agent(move || {
                            Ok(Box::new(StalkerAgent::new_with_signing_key(
                                identity.id.clone(),
                                identity.signing_key.clone(),
                                state.current_replay_store(),
                                state.current_investigation(),
                                state.current_substrate(),
                                state.current_pheromone_config(),
                            )))
                        })
                    }
                },
            )?
        {
            admitted_identities.push(stalker_id);
        }
        if config.correlation.enabled
            && let Some(weaver_id) = register_persisted_runtime_agent(
                &mut dispatcher,
                &identity_store,
                &identity_registry,
                AgentRole::Weaver,
                "primary",
                now_ms,
                {
                    let state = state.clone();
                    move |identity| {
                        build_restartable_agent(move || {
                            Ok(Box::new(WeaverAgent::new_with_signing_key(
                                identity.id.clone(),
                                identity.signing_key.clone(),
                                state.current_correlation_engine(),
                                state.current_investigation_store(),
                                state.current_incident_store(),
                            )))
                        })
                    }
                },
            )?
        {
            admitted_identities.push(weaver_id);
        }
        dispatcher.set_admitted_identities(admitted_identities);
        let mut dispatcher_handle = Some(tokio::spawn(async move {
            dispatcher.run().await;
        }));
        let bridge_processing_state = state.clone();
        let mut bridge_processing_shutdown = shutdown_rx.clone();
        let mut bridge_processor_handle = Some(tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = bridge_processing_shutdown.changed() => {
                        if changed.is_err() || *bridge_processing_shutdown.borrow() {
                            break;
                        }
                    }
                    maybe_event = bridge_ingest_rx.recv() => {
                        let Some(event) = maybe_event else {
                            break;
                        };
                        let event_id = event.event_id.clone();
                        let source = event.source.clone();
                        if let Err(error) = bridge_processing_state.process_bridge_event(event).await {
                            tracing::warn!(
                                event_id = %event_id,
                                source = %source,
                                reason = %error,
                                module = module_path!(),
                                "bridge event processing failed"
                            );
                        }
                    }
                }
            }
        }));
        let mut concentration_monitor = ConcentrationMonitor::new(
            state.current_pheromone_config(),
            Arc::new(state.current_substrate()),
        )
        .with_shared_mode_state(Arc::clone(&mode_state))
        .with_runtime_events(runtime_events);
        let mut monitor_handle = Some(tokio::spawn(async move {
            concentration_monitor
                .run_until_shutdown(CONCENTRATION_MONITOR_INTERVAL_MS, monitor_shutdown)
                .await;
        }));
        // The TTL sweep. Without it a containment lease is a record with no
        // consequence: it would expire and nothing would notice, which is the
        // state this lane exists to leave behind.
        //
        // The store comes from the RUNTIME, not from config: for an in-memory
        // store a second instance built here would be a different map, and the
        // sweep would find nothing while reporting clean passes.
        //
        // ONE SWEEP OBJECT, TWO TRIGGERS. The `Arc` built here is spawned as the
        // TTL task AND handed to the operator release route below, so an
        // operator's early release and the automatic expiry act on the same
        // store, the same executor, the same execution mode and the same
        // governance authority. Two `ContainmentSweep`s over a
        // `MemoryContainmentLeaseStore` would be two different maps and the
        // route would find no leases at all (QRT-04).
        let containment_sweep: Option<Arc<swarm_runtime::containment::ContainmentSweep>> =
            match state.current_containment_store() {
                Some(store) => {
                    match swarm_runtime::containment::rollback_executor_from_config(
                        &state.current_response_adapter_config(),
                    ) {
                        Ok(executor) => Some(Arc::new(governance.configure_containment(
                            swarm_runtime::containment::ContainmentSweep::new(
                                store,
                                executor,
                                state.current_execution_mode(),
                            ),
                        ))),
                        Err(error) => {
                            // Loud, not fatal: the runtime still refuses containments
                            // it cannot lease, so nothing new gets contained. What is
                            // lost is automatic release of anything already open.
                            tracing::error!(
                                module = module_path!(),
                                reason = %error,
                                "containment sweep NOT started; open containments will not expire"
                            );
                            None
                        }
                    }
                }
                None => {
                    tracing::warn!(
                        module = module_path!(),
                        "no containment lease store configured; containment sweep not started"
                    );
                    None
                }
            };
        let mut containment_sweep_handle = containment_sweep.as_ref().map(|sweep| {
            let settings = state.current_containment_settings();
            let sweep = Arc::clone(sweep);
            let sweep_shutdown = shutdown_rx.clone();
            let interval_ms = settings.sweep_interval_ms;
            tracing::info!(
                module = module_path!(),
                interval_ms,
                lease_ttl_ms = settings.lease_ttl_ms,
                "containment sweep started"
            );
            tokio::spawn(async move {
                sweep.run_until_shutdown(interval_ms, sweep_shutdown).await;
            })
        });
        let bridge_metrics = state.current_prometheus_metrics();
        // KNOWN LIMITATION: telemetry bridge workers are also spawned once from
        // the initial `runtime.telemetry_sources` config. `reload_from_disk()`
        // does not rebuild them, so adding/removing/rotating a bridge endpoint
        // only takes effect after a process restart. Same per-worker shutdown
        // refactor needed as for the threat-intel registry; tracked as follow-up.
        let mut bridge_handles =
            Some(bridge_registry.spawn(bridge_ingest_tx, shutdown_rx.clone(), bridge_metrics));
        // KNOWN LIMITATION: these worker handles are spawned once from the initial
        // config and bound to the process-wide `shutdown_rx`. `reload_from_disk()`
        // does not rebuild them, so changes to `runtime.threat_intel_feeds` (added,
        // removed, rotated endpoints, swapped pheromone substrate) only take effect
        // after a process restart. Restarting workers in-place needs a per-worker
        // shutdown signal in `ThreatIntelFeedRuntimeRegistry`; tracked as follow-up.
        let mut threat_intel_handles =
            Some(threat_intel_registry.spawn(state.current_substrate(), shutdown_rx.clone()));
        let mut reload_handles = Some(spawn_reload_tasks(state.clone(), shutdown_tx.clone()));
        let anti_tamper_state = state.clone();
        let anti_tamper_shutdown = shutdown_rx.clone();
        let mut anti_tamper_handle = Some(tokio::spawn(async move {
            anti_tamper_monitor
                .run_until_shutdown(anti_tamper_state, anti_tamper_shutdown)
                .await;
        }));
        let listener = tokio::net::TcpListener::bind(&cli.bind).await?;
        let serve_state = state.clone();
        // The operator containment routes ride on the daemon's own listener,
        // because this is the process that holds the lease store, runs the TTL
        // sweep, and owns the governance receipt chain. `swarmctl quarantine
        // release` is a client of these two routes; see
        // `swarm_runtime_http::http::containment` for why it is not a local
        // subcommand.
        //
        // A misconfigured operator surface must NOT silently ship a daemon with
        // no release route: `containment_operator_router` fails when a bearer
        // token env is missing, and that failure is reported here rather than
        // swallowed, so the absence of the route is always visible in the log.
        let mut router = detect_http_router(serve_state);
        match containment_sweep.as_ref() {
            Some(sweep) if config.operator.enabled => {
                match swarm_runtime_http::http::containment_operator_router(
                    &config,
                    Arc::clone(sweep),
                ) {
                    Ok(containment_router) => {
                        tracing::info!(
                            module = module_path!(),
                            "operator containment release routes mounted"
                        );
                        router = router.merge(containment_router);
                    }
                    Err(error) => tracing::error!(
                        module = module_path!(),
                        reason = %error,
                        "operator containment release routes NOT mounted; early release is \
                         unavailable and leases can only end at their TTL"
                    ),
                }
            }
            Some(_) => tracing::warn!(
                module = module_path!(),
                "operator surface disabled in config; containment release routes not mounted"
            ),
            None => tracing::warn!(
                module = module_path!(),
                "no containment sweep; containment release routes not mounted"
            ),
        }
        let server = serve_with_listener(
            listener,
            router,
            config.tls.clone(),
            wait_for_shutdown_request(shutdown_rx),
        );
        tokio::pin!(server);

        tokio::select! {
            result = &mut server => {
                let _ = shutdown_tx.send(true);
                if let Some(handle) = dispatcher_handle.take() {
                    await_background_task("dispatcher", handle).await;
                }
                if let Some(handle) = bridge_processor_handle.take() {
                    await_background_task("bridge_processor", handle).await;
                }
                if let Some(handle) = monitor_handle.take() {
                    await_background_task("concentration_monitor", handle).await;
                }
                if let Some(handle) = containment_sweep_handle.take() {
                    await_background_task("containment_sweep", handle).await;
                }
                if let Some(handles) = bridge_handles.take() {
                    await_background_tasks("bridge", handles).await;
                }
                if let Some(handles) = threat_intel_handles.take() {
                    await_background_tasks("threat_intel_feed", handles).await;
                }
                if let Some(handles) = reload_handles.take() {
                    await_reload_tasks(handles).await;
                }
                if let Some(handle) = anti_tamper_handle.take() {
                    await_background_task("anti_tamper_monitor", handle).await;
                }
                result?;
            }
            signal = wait_for_shutdown_signal() => {
                tracing::info!(
                    module = module_path!(),
                    signal,
                    "shutdown requested"
                );
                state.begin_drain();
                let drained = state.wait_for_drain().await;
                tracing::info!(
                    module = module_path!(),
                    signal,
                    drained,
                    active_requests = state.active_requests(),
                    drain_timeout_ms = state.drain_timeout().as_millis() as u64,
                    "serve-mode drain completed before shutdown"
                );
                let _ = shutdown_tx.send(true);
                match tokio::time::timeout(
                    Duration::from_secs(GRACEFUL_SHUTDOWN_TIMEOUT_SECS),
                    &mut server,
                )
                .await
                {
                    Ok(result) => result?,
                    Err(_) => {
                        tracing::error!(
                            module = module_path!(),
                            timeout_secs = GRACEFUL_SHUTDOWN_TIMEOUT_SECS,
                            "graceful shutdown timed out; forcing exit"
                        );
                    }
                }
                if let Some(handle) = dispatcher_handle.take() {
                    await_background_task("dispatcher", handle).await;
                }
                if let Some(handle) = bridge_processor_handle.take() {
                    await_background_task("bridge_processor", handle).await;
                }
                if let Some(handle) = monitor_handle.take() {
                    await_background_task("concentration_monitor", handle).await;
                }
                if let Some(handle) = containment_sweep_handle.take() {
                    await_background_task("containment_sweep", handle).await;
                }
                if let Some(handles) = bridge_handles.take() {
                    await_background_tasks("bridge", handles).await;
                }
                if let Some(handles) = threat_intel_handles.take() {
                    await_background_tasks("threat_intel_feed", handles).await;
                }
                if let Some(handles) = reload_handles.take() {
                    await_reload_tasks(handles).await;
                }
                if let Some(handle) = anti_tamper_handle.take() {
                    await_background_task("anti_tamper_monitor", handle).await;
                }
            }
        }
        tracing::info!(module = module_path!(), "shutdown complete");
        return Ok(());
    }

    let detector = build_composite_detector(&config.detection)?;
    let stack = ConfiguredRuntimeStack::from_config(config.clone(), SummaryInvestigator)?;
    let mut paths = if let Some(dir) = &cli.scenarios_dir {
        scenario_paths_in_dir(dir)?
    } else {
        Vec::new()
    };
    paths.extend(cli.scenario.iter().cloned());

    if paths.is_empty() {
        return Ok(());
    }

    let agent_id = AgentId("swarm-detect".to_string());
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let mut scenarios = 0usize;
    let mut events = 0usize;
    let mut findings = 0usize;
    let mut deposits = 0usize;

    for path in paths {
        let loaded = load_scenario_manifest(&path)?;
        let scenario_name = loaded.manifest.name.clone();
        let ReplayScenarioInput::Events {
            events: scenario_events,
        } = loaded.manifest.input.clone()
        else {
            return Err(format!(
                "scenario `{}` does not use event input",
                loaded.path.display()
            )
            .into());
        };
        let scenario_event_count = scenario_events.len();
        let mut scenario_findings = 0usize;
        let mut scenario_deposits = 0usize;
        for step in scenario_events {
            let approval = ApprovalContext {
                live_mode: matches!(
                    config.runtime.mode,
                    swarm_core::config::RuntimeMode::LiveResponse
                ),
                receipt_chain: Vec::new(),
                correlation_id: None,
                now_ms: step.event.timestamp,
            };
            let outcome = stack
                .process_event(
                    &detector,
                    &step.event,
                    EventExecutionContext {
                        agent_id: &agent_id,
                        approval: &approval,
                        signing_key: &signing_key,
                    },
                    |_| Some(step.action.clone()),
                )
                .await?;
            events += 1;
            match outcome {
                Some(bundle) => {
                    findings += bundle.replay.bundle.findings.len();
                    deposits += bundle.replay.bundle.deposits.len();
                    scenario_findings += bundle.replay.bundle.findings.len();
                    scenario_deposits += bundle.replay.bundle.deposits.len();
                    if cli.json {
                        println!(
                            "{}",
                            serde_json::to_string(&json!({
                                "scenario": scenario_name,
                                "event_id": bundle.replay.bundle.event.event_id,
                                "finding_count": bundle.replay.bundle.findings.len(),
                                "deposit_count": bundle.replay.bundle.deposits.len(),
                                "policy_verdict": bundle.replay.bundle.audit.policy.verdict,
                                "response_kind": response_kind(&bundle.replay.bundle.audit.response),
                            }))?
                        );
                    } else {
                        println!(
                            "{} {} findings={} deposits={} policy={:?} response={}",
                            scenario_name,
                            bundle.replay.bundle.event.event_id,
                            bundle.replay.bundle.findings.len(),
                            bundle.replay.bundle.deposits.len(),
                            bundle.replay.bundle.audit.policy.verdict,
                            response_kind(&bundle.replay.bundle.audit.response)
                        );
                    }
                }
                None if !cli.json => {
                    println!(
                        "{} {} findings=0 deposits=0",
                        scenario_name, step.event.event_id
                    )
                }
                None => println!(
                    "{}",
                    serde_json::to_string(
                        &json!({"scenario": scenario_name, "event_id": step.event.event_id, "finding_count": 0, "deposit_count": 0, "policy_verdict": null, "response_kind": null})
                    )?
                ),
            }
        }
        scenarios += 1;
        if cli.json {
            println!(
                "{}",
                serde_json::to_string(
                    &json!({"scenario": scenario_name, "total_events": scenario_event_count, "total_findings": scenario_findings, "total_deposits": scenario_deposits})
                )?
            );
        } else {
            println!(
                "scenario={} total_events={} total_findings={} total_deposits={}",
                scenario_name, scenario_event_count, scenario_findings, scenario_deposits
            );
        }
    }

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"scenarios_processed": scenarios, "total_events": events, "total_findings": findings, "total_deposits": deposits})
            )?
        );
    } else {
        println!(
            "summary scenarios_processed={} total_events={} total_findings={} total_deposits={}",
            scenarios, events, findings, deposits
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        Cli, GovernanceArtifactSet, GovernancePathResolutionMode, GovernancePathSelectionLock,
        ShippedGovernanceWiring, backup_governance_rollback_entry, bootstrap_artifact_ownership,
        build_approval_harness, default_partition_governance_state_path,
        ensure_governance_authority_lock_pair, governance_artifact_record,
        governance_artifact_record_at, governance_artifact_set, governance_artifact_snapshot,
        governance_policy_for_bootstrap, governance_quarantine_expected_copy_name,
        governance_selection_lock_path, inject_governance_rollback_cleanup_failure_on_call,
        install_governance_artifact_read_barrier, install_governance_authority_hard_link_barrier,
        install_governance_authority_sidecar_create_barrier,
        install_governance_authority_source_open_barrier,
        install_governance_authority_source_pin_barrier, install_governance_final_mutation_barrier,
        install_governance_parent_mutation_barrier,
        install_governance_private_quarantine_stage_barrier,
        install_governance_retained_move_barrier,
        install_governance_rollback_after_reservation_barrier, install_governance_rollback_barrier,
        install_governance_rollback_install_barrier, install_governance_rollback_journal_barrier,
        next_governance_quarantine_name, open_governance_quarantine_parent,
        quarantine_governance_artifact, register_optional_calico_agent,
        register_optional_sphinx_agent, reinitialize_artifact_ownership,
        remove_private_governance_quarantine, resolve_partition_governance_state_path,
        retain_governance_entry_no_replace, rollback_governance_artifacts_after_selection_conflict,
        watch_paths_differ,
    };
    use clap::Parser;
    use std::path::PathBuf;
    use std::sync::Arc;
    use swarm_core::agent::{AgentRole, SwarmModeState};
    use swarm_ingest_runtime::ingest::IngestState;
    use swarm_pheromone::ConfiguredPheromoneSubstrate;
    use swarm_runtime::agent_identity::{
        AgentKeyLoadStatus, FileAgentIdentityRegistry, FileAgentKeyStore, RegistryAdmission,
        resolve_agent_key_dir, resolve_identity_registry_dir,
    };
    use swarm_runtime::dispatcher::{AgentDispatcher, AgentDispatcherConfig};
    use swarm_runtime::runtime_events::RuntimeEventBroadcaster;

    fn governance_artifacts_snapshot(
        state_paths: &[&std::path::Path],
    ) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        state_paths
            .iter()
            .flat_map(|state_path| {
                [
                    (*state_path).to_path_buf(),
                    swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(
                        state_path,
                    ),
                    swarm_agents::tom_agent::GovernancePolicy::persistence_lock_path(state_path),
                    swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                        state_path,
                    ),
                    governance_selection_lock_path(state_path),
                ]
            })
            .map(|path| {
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) => Some(bytes),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => panic!("failed to snapshot `{}`: {error}", path.display()),
                };
                (path, bytes)
            })
            .collect()
    }

    fn directory_entry_names(
        parent: &super::GovernanceHeldParent,
    ) -> Result<Vec<std::ffi::OsString>, std::io::Error> {
        let mut names = std::fs::read_dir(&parent.path)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        Ok(names)
    }

    fn seed_cleanup_pool_for_fresh_stream(
        config_path: &std::path::Path,
        identity: &swarm_core::config::IdentityConfig,
        tom_identity: &swarm_runtime::agent_identity::PersistedAgentIdentity,
    ) {
        let mut selection = resolve_partition_governance_state_path(
            config_path,
            identity,
            GovernancePathResolutionMode::Bootstrap,
        )
        .expect("fresh stream selection should establish the sidecar pair");
        assert!(
            selection
                .acquire_cleanup_pool_retention_guard(tom_identity)
                .expect("fresh stream should establish its signed cleanup pool")
        );
        drop(selection.take_cleanup_pool_retention_guard().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn detector_cleanup_pool_exhaustion_preserves_the_unmoved_source() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-detector-pool-exhaustion-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        seed_cleanup_pool_for_fresh_stream(&config_path, &identity_config, &tom_identity);
        let policy = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        drop(policy);
        let mut selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .unwrap();
        selection
            .acquire_cleanup_pool_retention_guard(&tom_identity)
            .expect("the complete stream should authenticate its cleanup pool");
        let parent = open_governance_quarantine_parent(&current_path).unwrap();
        for slot in 0..64_u8 {
            let name = std::ffi::OsString::from(format!(".detector-pool-exhaustion-{slot}"));
            let path = parent.path.join(&name);
            std::fs::write(&path, format!("owned-{slot}")).unwrap();
            let expected = governance_artifact_record_at(&parent, &name)
                .unwrap()
                .expect("the pool source should be a regular artifact");
            let source = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            retain_governance_entry_no_replace(
                &parent,
                &name,
                &source,
                &expected,
                "fill the detector cleanup pool",
                selection.cleanup_pool_retention_guard(),
            )
            .expect("each fixed pool slot should retain exactly one source");
            assert!(
                governance_artifact_record_at(&parent, &name)
                    .unwrap()
                    .is_none()
            );
        }

        let overflow_name = std::ffi::OsString::from(".detector-pool-exhaustion-overflow");
        let overflow_path = parent.path.join(&overflow_name);
        std::fs::write(&overflow_path, b"must-remain-on-exhaustion").unwrap();
        let overflow_before = governance_artifact_record_at(&parent, &overflow_name)
            .unwrap()
            .expect("the overflow source should be a regular artifact");
        let namespace_before_retries = directory_entry_names(&parent).unwrap();
        let source = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&overflow_path)
            .unwrap();
        for retry in 0..8 {
            let error = retain_governance_entry_no_replace(
                &parent,
                &overflow_name,
                &source,
                &overflow_before,
                "retain after pool exhaustion",
                selection.cleanup_pool_retention_guard(),
            )
            .expect_err("pool exhaustion must fail closed before moving the source");
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::StorageFull,
                "retry {retry} must report fixed-pool exhaustion"
            );
            assert_eq!(
                governance_artifact_record_at(&parent, &overflow_name).unwrap(),
                Some(overflow_before.clone()),
                "retry {retry} must leave the exact source bytes and identity in place"
            );
            assert_eq!(
                directory_entry_names(&parent).unwrap(),
                namespace_before_retries,
                "retry {retry} must not allocate an unbounded fallback name"
            );
        }
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn detector_rollback_private_name_set_is_fixed_and_reusable() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-detector-fixed-rollback-names-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("artifact");
        std::fs::write(&source, b"source").unwrap();
        let parent = open_governance_quarantine_parent(&source).unwrap();
        for slot in 0..8_u8 {
            let quarantine = std::ffi::OsString::from(format!(".artifact.rollback-{slot}"));
            let expected = governance_quarantine_expected_copy_name(&quarantine).unwrap();
            std::fs::write(parent.path.join(&quarantine), b"quarantine").unwrap();
            std::fs::write(parent.path.join(expected), b"expected-copy").unwrap();
        }
        let before = directory_entry_names(&parent).unwrap();
        for _ in 0..32 {
            let error = next_governance_quarantine_name(&parent, std::ffi::OsStr::new("artifact"))
                .expect_err("the fixed rollback namespace must fail closed when full");
            assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
            assert_eq!(directory_entry_names(&parent).unwrap(), before);
        }
        std::fs::remove_file(parent.path.join(".artifact.rollback-0")).unwrap();
        std::fs::remove_file(parent.path.join(".artifact.rollback-expected-0")).unwrap();
        let (_, recovered_name) =
            next_governance_quarantine_name(&parent, std::ffi::OsStr::new("artifact"))
                .expect("a freed fixed slot should be reusable");
        assert_eq!(
            recovered_name,
            std::ffi::OsString::from(".artifact.rollback-0")
        );
        let after = directory_entry_names(&parent).unwrap();
        let mut expected_after = before;
        expected_after.retain(|name| {
            name != std::ffi::OsStr::new(".artifact.rollback-0")
                && name != std::ffi::OsStr::new(".artifact.rollback-expected-0")
        });
        assert_eq!(after, expected_after);

        let source_record = governance_artifact_record(&source)
            .unwrap()
            .expect("the rollback backup source should remain present");
        let backup = backup_governance_rollback_entry(&source, &source_record)
            .expect("the fixed rollback backup name should be publishable once");
        assert_eq!(
            backup.file_name().unwrap(),
            std::ffi::OsStr::new(".artifact.rollback-backup")
        );
        let after_backup = directory_entry_names(&parent).unwrap();
        let second_backup = backup_governance_rollback_entry(&source, &source_record)
            .expect_err("a repeated rollback backup must not allocate another name");
        assert_eq!(second_backup.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            directory_entry_names(&parent).unwrap(),
            after_backup,
            "repeated backup failure must leave the bounded name set unchanged"
        );
        std::fs::remove_file(backup).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn shipped_builder_shares_one_governance_policy_across_every_trust_consumer() {
        use swarm_response::ExecutionMode;
        use swarm_response::containment::MemoryContainmentLeaseStore;
        use swarm_response::rollback::SandboxRollbackExecutor;
        use swarm_runtime::containment::ContainmentSweep;

        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("rulesets/default.yaml");
        let mut config =
            swarm_runtime::config::load_config(&config_path).expect("default config should load");
        let voter = swarm_crypto::Ed25519Signer::from_secret_material(
            "shipped-governance-composition-approver",
        );
        config.operator.auth.principals = vec![swarm_core::config::OperatorPrincipalConfig {
            operator_id: format!("swarm:ed25519:{}", voter.public_key_hex()),
            token_env: "SWARM_SHIPPED_COMPOSITION_APPROVER_TOKEN".to_string(),
            token_expires_at_ms: None,
            scopes: vec![swarm_core::config::OperatorScope::Approve],
        }];
        let raw_state =
            IngestState::from_config(config_path, config).expect("ingest state should build");
        let substrate = raw_state.current_substrate();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let health_state = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
        let raw_dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate,
            health_state,
        );
        let raw_sweep = ContainmentSweep::new(
            Arc::new(MemoryContainmentLeaseStore::new()),
            Arc::new(SandboxRollbackExecutor),
            ExecutionMode::Enforced,
        );
        let root = std::env::temp_dir().join(format!(
            "swarm-detect-shared-governance-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ));
        let store = FileAgentKeyStore::open(root.join("keys"))
            .expect("temporary Tom identity store should open");
        let (identity, key_status) = store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .expect("temporary Tom identity should load");
        let policy = Arc::new(
            governance_policy_for_bootstrap(
                swarm_agents::tom_agent::GovernancePolicyConfig::default(),
                &root.join("governance.json"),
                &identity,
                key_status,
            )
            .expect("persisted governance policy should initialize"),
        );
        let authority = policy
            .authority()
            .expect("persisted governance policy should mint authority");
        let expected_identity = authority.identity();
        let wiring = ShippedGovernanceWiring::new(authority.clone());

        let state = wiring.configure_ingest(raw_state);
        let dispatcher = wiring.configure_dispatcher(raw_dispatcher);
        let sweep = wiring.configure_containment(raw_sweep);

        assert_eq!(
            state.governance_authority_identity(),
            Some(expected_identity)
        );
        assert_eq!(
            dispatcher.governance_authority_identity(),
            Some(expected_identity)
        );
        assert_eq!(
            sweep.governance_authority_identity(),
            Some(expected_identity)
        );
        assert_eq!(
            state.human_resume_governance_authority_identity(),
            Some(expected_identity)
        );
        drop(state);
        drop(dispatcher);
        drop(sweep);
        drop(wiring);
        drop(authority);
        drop(policy);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn watch_paths_differ_detects_secret_dir_retargets() {
        let left = Some(PathBuf::from("/tmp/a"));
        let right = Some(PathBuf::from("/tmp/b"));

        assert!(watch_paths_differ(left.as_ref(), right.as_ref()));
        assert!(watch_paths_differ(left.as_ref(), None));
        assert!(!watch_paths_differ(left.as_ref(), left.as_ref()));
        assert!(!watch_paths_differ(None, None));
    }

    #[test]
    fn governance_state_lives_beside_the_stable_agent_key_root() {
        let identity = swarm_core::config::IdentityConfig {
            agent_key_dir: "/var/lib/swarm/agent-keys".to_string(),
            registry_dir: "/var/lib/swarm/agent-identity".to_string(),
        };
        assert_eq!(
            default_partition_governance_state_path(
                std::path::Path::new("/etc/swarm/swarm.yaml"),
                &identity,
            ),
            PathBuf::from("/var/lib/swarm/governance-partition-state.json")
        );
    }

    #[test]
    fn failed_initialization_leaves_lock_only_state_for_explicit_reinitialize() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-lock-only-recovery-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let sequence_path =
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&current_path);
        let blocker = sequence_path.with_extension(format!(
            "{}.tmp-{}",
            sequence_path.extension().unwrap().to_str().unwrap(),
            std::process::id()
        ));
        std::fs::create_dir(&blocker).unwrap();

        let error = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .expect_err("a blocked first checkpoint must leave only its durable lock");
        assert!(error.to_string().contains("initialization"));
        assert!(!current_path.exists());
        assert!(!sequence_path.exists());
        let lock_path =
            swarm_agents::tom_agent::GovernancePolicy::persistence_lock_path(&current_path);
        let lock_before = std::fs::read(&lock_path).unwrap();
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::LockOnly
        );
        std::fs::remove_dir(&blocker).unwrap();

        let bootstrap_error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .expect_err("ordinary bootstrap must reject an interrupted lock-only stream");
        assert!(
            bootstrap_error
                .to_string()
                .contains("transition is incomplete")
        );

        let selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Reinitialize,
        )
        .expect("explicit reinitialize should select the sole lock-only stream");
        assert_eq!(selection.path(), current_path);
        let recovered = swarm_agents::tom_agent::GovernancePolicy::reinitialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            selection.path(),
            tom_identity.id,
            tom_identity.signing_key,
        )
        .expect("explicit reinitialize should reuse the permanent lock");
        selection
            .verify_artifacts(
                &config_path,
                &identity_config,
                GovernancePathResolutionMode::Reinitialize,
            )
            .unwrap();
        assert_eq!(std::fs::read(&lock_path).unwrap(), lock_before);
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Complete
        );
        drop(selection);
        assert_eq!(recovered.status_report().total_governors, 1);
        drop(recovered);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn complete_stream_reinitialize_refuses_before_sidecar_or_archive_mutation() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-complete-reinitialize-refusal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        let policy = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        drop(policy);
        std::fs::write(
            governance_selection_lock_path(&current_path),
            b"selection-lock",
        )
        .unwrap();
        let before = governance_artifacts_snapshot(&[&current_path, &legacy_path]);

        let error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Reinitialize,
        )
        .expect_err("complete streams must not be archived by detector reinitialize");
        assert!(error.to_string().contains("complete governance stream"));
        assert_eq!(
            before,
            governance_artifacts_snapshot(&[&current_path, &legacy_path]),
            "complete-stream refusal must not create sidecars, archives, or anchors"
        );
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Complete
        );
        assert_eq!(
            governance_artifact_set(&legacy_path).unwrap(),
            GovernanceArtifactSet::Absent
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn selection_rejects_a_foreign_complete_stream_created_after_bootstrap_snapshot() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-bootstrap-snapshot-drift-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, key_status) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        assert_eq!(key_status, AgentKeyLoadStatus::Created);
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        let selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .unwrap();
        assert_eq!(
            selection.initial_artifacts().artifact_set(),
            GovernanceArtifactSet::Absent
        );

        let foreign = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id,
            tom_identity.signing_key,
        )
        .unwrap();
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Complete
        );
        let before_revalidation = governance_artifacts_snapshot(&[&current_path, &legacy_path]);
        let error = selection
            .verify_initial_artifacts(&config_path, &identity_config)
            .expect_err("a complete stream created after selection must be rejected before open");
        assert!(
            error.to_string().contains("changed after selection"),
            "{error}"
        );
        assert_eq!(
            before_revalidation,
            governance_artifacts_snapshot(&[&current_path, &legacy_path]),
            "snapshot revalidation must not delete or rewrite the foreign stream"
        );
        drop(foreign);
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn constructor_gap_foreign_complete_stream_is_rejected_without_rollback() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-constructor-gap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, key_status) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        let selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .unwrap();
        selection
            .verify_initial_artifacts(&config_path, &identity_config)
            .unwrap();
        let foreign = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        let before_constructor = governance_artifacts_snapshot(&[&current_path, &legacy_path]);
        let detector_error = governance_policy_for_bootstrap(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            &tom_identity,
            key_status,
        )
        .expect_err("a foreign stream created in the constructor gap must block opening");
        assert!(
            detector_error
                .to_string()
                .contains("held by another process")
                || detector_error.to_string().contains("locked")
                || detector_error.to_string().contains("authority"),
            "unexpected constructor-gap error: {detector_error}"
        );
        assert_eq!(
            before_constructor,
            governance_artifacts_snapshot(&[&current_path, &legacy_path]),
            "constructor refusal must not roll back or rewrite the foreign stream"
        );
        drop(foreign);
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn bootstrap_guard_rejects_dropped_foreign_lock_only_initializer_after_preflight() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-guard-lock-only-gap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, key_status) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        assert_eq!(key_status, AgentKeyLoadStatus::Created);
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        let mut selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .unwrap();
        selection
            .acquire_authority_pair_guard(&config_path, &identity_config)
            .unwrap();
        selection
            .verify_initial_artifacts(&config_path, &identity_config)
            .unwrap();
        let constructor_before = selection
            .capture_constructor_preflight(
                &config_path,
                &identity_config,
                GovernancePathResolutionMode::Bootstrap,
            )
            .unwrap();
        assert_eq!(
            constructor_before.artifact_set(),
            GovernanceArtifactSet::Absent
        );
        let before_foreign = governance_artifacts_snapshot(&[&current_path, &legacy_path]);

        // The foreign writer starts only after the exact detector preflight.  Its
        // authority acquisition must be refused by the selector-held guard, so
        // it cannot leave a lock-only residue or race the transferred constructor.
        let foreign_path = current_path.clone();
        let foreign_id = tom_identity.id.clone();
        let foreign_key = tom_identity.signing_key.clone();
        let foreign = std::thread::spawn(move || {
            swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
                swarm_agents::tom_agent::GovernancePolicyConfig::default(),
                foreign_path,
                foreign_id,
                foreign_key,
            )
        })
        .join()
        .unwrap();
        assert!(
            foreign.is_err(),
            "a writer started after preflight must not acquire the selector-held authority"
        );
        assert_eq!(
            before_foreign,
            governance_artifacts_snapshot(&[&current_path, &legacy_path]),
            "the refused foreign lock-only writer must leave every artifact byte/existence unchanged"
        );

        let authority_pair_guard = selection.take_authority_pair_guard().unwrap();
        let policy = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence_with_authority_pair_guard(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id,
            tom_identity.signing_key,
            authority_pair_guard,
        )
        .expect("the selector-held guard must transfer to the sole bootstrap constructor");
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Complete
        );
        drop(policy);
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reinitialize_guard_rejects_dropped_foreign_completed_reinitializer_after_preflight() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-guard-reinitialize-gap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        let initial = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        drop(initial);
        std::fs::remove_file(
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&current_path),
        )
        .unwrap();

        let mut selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Reinitialize,
        )
        .unwrap();
        selection
            .acquire_authority_pair_guard(&config_path, &identity_config)
            .unwrap();
        let constructor_before = selection
            .capture_constructor_preflight(
                &config_path,
                &identity_config,
                GovernancePathResolutionMode::Reinitialize,
            )
            .unwrap();
        assert_eq!(
            constructor_before.artifact_set(),
            GovernanceArtifactSet::RecoverablePartial
        );
        let before_foreign = governance_artifacts_snapshot(&[&current_path, &legacy_path]);

        // A direct reinitializer that starts after preflight cannot archive the
        // selected partial stream while the selector-held authority is retained.
        let foreign_path = current_path.clone();
        let foreign_id = tom_identity.id.clone();
        let foreign_key = tom_identity.signing_key.clone();
        let foreign = std::thread::spawn(move || {
            swarm_agents::tom_agent::GovernancePolicy::reinitialize_persistence(
                swarm_agents::tom_agent::GovernancePolicyConfig::default(),
                foreign_path,
                foreign_id,
                foreign_key,
            )
        })
        .join()
        .unwrap();
        assert!(
            foreign.is_err(),
            "a dropped foreign reinitializer must not acquire the selected authority"
        );
        assert_eq!(
            before_foreign,
            governance_artifacts_snapshot(&[&current_path, &legacy_path]),
            "the refused foreign reinitializer must not archive or rewrite selected artifacts"
        );

        let authority_pair_guard = selection.take_authority_pair_guard().unwrap();
        let recovered =
            swarm_agents::tom_agent::GovernancePolicy::reinitialize_persistence_with_authority_pair_guard(
                swarm_agents::tom_agent::GovernancePolicyConfig::default(),
                &current_path,
                tom_identity.id,
                tom_identity.signing_key,
                "discarded-detector-guard-test",
                authority_pair_guard,
            )
            .expect("the selector-held guard must transfer to the sole reinitializer");
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Complete
        );
        drop(recovered);
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn selection_rejects_a_foreign_lock_only_stream_created_after_bootstrap_snapshot() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-bootstrap-lock-only-drift-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, key_status) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        assert_eq!(key_status, AgentKeyLoadStatus::Created);
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        let selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .unwrap();
        let sequence_path =
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&current_path);
        let blocker = sequence_path.with_extension(format!(
            "{}.tmp-{}",
            sequence_path.extension().unwrap().to_str().unwrap(),
            std::process::id()
        ));
        std::fs::create_dir(&blocker).unwrap();
        let foreign_error = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id,
            tom_identity.signing_key,
        )
        .expect_err("the foreign initializer should leave a lock-only stream");
        assert!(foreign_error.to_string().contains("initialization"));
        std::fs::remove_dir(&blocker).unwrap();
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::LockOnly
        );
        let before_revalidation = governance_artifacts_snapshot(&[&current_path, &legacy_path]);
        let error = selection
            .capture_constructor_preflight(
                &config_path,
                &identity_config,
                GovernancePathResolutionMode::Bootstrap,
            )
            .expect_err(
                "a lock-only stream created after selection must be rejected before construction",
            );
        assert!(
            error.to_string().contains("changed after selection"),
            "{error}"
        );
        assert_eq!(
            before_revalidation,
            governance_artifacts_snapshot(&[&current_path, &legacy_path]),
            "snapshot revalidation must preserve the foreign lock-only stream"
        );
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn selection_rejects_a_foreign_reinitialized_stream_before_recovery_mutation() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-reinitialize-snapshot-drift-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        let initial = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        drop(initial);
        std::fs::remove_file(
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&current_path),
        )
        .unwrap();
        let selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Reinitialize,
        )
        .unwrap();
        assert_eq!(
            selection.initial_artifacts().artifact_set(),
            GovernanceArtifactSet::RecoverablePartial
        );
        let foreign = swarm_agents::tom_agent::GovernancePolicy::reinitialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Complete
        );
        let before_revalidation = governance_artifacts_snapshot(&[&current_path, &legacy_path]);
        let error = selection
            .capture_constructor_preflight(
                &config_path,
                &identity_config,
                GovernancePathResolutionMode::Reinitialize,
            )
            .expect_err("a dropped foreign reinitializer must be rejected before construction");
        assert!(
            error.to_string().contains("changed after selection"),
            "{error}"
        );
        assert_eq!(
            before_revalidation,
            governance_artifacts_snapshot(&[&current_path, &legacy_path]),
            "reinitialize preflight must not restore stale prestate over a foreign stream"
        );
        drop(foreign);
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn upgrade_discovers_the_signed_governance_stream_at_the_legacy_config_path() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-legacy-upgrade-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, key_status) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        assert_eq!(key_status, AgentKeyLoadStatus::Created);

        let legacy_path = root.join("data/governance-partition-state.json");
        let policy = governance_policy_for_bootstrap(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &legacy_path,
            &tom_identity,
            key_status,
        )
        .unwrap();
        let legacy_report = policy.status_report();
        drop(policy);

        let discovered = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .expect("legacy signed stream should be discovered during upgrade");
        assert_eq!(discovered.path(), legacy_path);
        assert_ne!(
            discovered.path(),
            default_partition_governance_state_path(&config_path, &identity_config)
        );

        let reloaded = governance_policy_for_bootstrap(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            discovered.path(),
            &tom_identity,
            AgentKeyLoadStatus::Loaded,
        )
        .unwrap();
        assert_eq!(reloaded.status_report(), legacy_report);
        discovered
            .verify_artifacts(
                &config_path,
                &identity_config,
                GovernancePathResolutionMode::Bootstrap,
            )
            .unwrap();
        drop(reloaded);
        drop(discovered);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_reinitialize_recovers_a_legacy_state_with_a_missing_checkpoint_without_forking() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-legacy-reinitialize-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let legacy_path = root.join("data/governance-partition-state.json");
        let policy = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &legacy_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        drop(policy);
        let legacy_sequence_path =
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&legacy_path);
        std::fs::remove_file(&legacy_sequence_path).unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);

        let bootstrap_error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .expect_err("ordinary bootstrap must reject a missing checkpoint");
        assert!(
            bootstrap_error
                .to_string()
                .contains("legacy governance state path is incomplete")
        );

        let selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Reinitialize,
        )
        .expect("explicit reinitialize may select state-plus-lock legacy recovery");
        assert_eq!(selection.path(), legacy_path);
        let recovered = swarm_agents::tom_agent::GovernancePolicy::reinitialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            selection.path(),
            tom_identity.id,
            tom_identity.signing_key,
        )
        .expect("explicit reinitialize should repair the selected legacy stream");
        selection
            .verify_artifacts(
                &config_path,
                &identity_config,
                GovernancePathResolutionMode::Reinitialize,
            )
            .unwrap();
        drop(selection);
        assert_eq!(
            governance_artifact_set(&legacy_path).unwrap(),
            GovernanceArtifactSet::Complete
        );
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Absent
        );
        assert_eq!(recovered.status_report().total_governors, 1);
        drop(recovered);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn upgrade_refuses_competing_current_and_legacy_governance_streams() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-legacy-conflict-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let legacy_path = root.join("data/governance-partition-state.json");
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        for path in [&legacy_path, &current_path] {
            let policy = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
                swarm_agents::tom_agent::GovernancePolicyConfig::default(),
                path,
                tom_identity.id.clone(),
                tom_identity.signing_key.clone(),
            )
            .unwrap();
            drop(policy);
        }

        let current_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &current_path,
            );
        let legacy_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &legacy_path,
            );
        std::fs::remove_file(&legacy_sidecar).unwrap();
        std::fs::hard_link(&current_sidecar, &legacy_sidecar).unwrap();
        std::fs::write(
            governance_selection_lock_path(&current_path),
            b"selection-lock",
        )
        .unwrap();
        let before = governance_artifacts_snapshot(&[&current_path, &legacy_path]);

        let error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .expect_err("two complete streams must never be selected implicitly");
        assert_eq!(
            error.to_string(),
            format!(
                "governance authority exists at both `{}` and legacy path `{}`; refusing to choose a fork",
                current_path.display(),
                legacy_path.display()
            )
        );
        assert_eq!(
            before,
            governance_artifacts_snapshot(&[&current_path, &legacy_path]),
            "competing complete streams must not mutate any artifact"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn explicit_reinitialize_refuses_two_recoverable_partial_streams() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-reinitialize-ambiguous-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let legacy_path = root.join("data/governance-partition-state.json");
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        for path in [&legacy_path, &current_path] {
            let policy = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
                swarm_agents::tom_agent::GovernancePolicyConfig::default(),
                path,
                tom_identity.id.clone(),
                tom_identity.signing_key.clone(),
            )
            .unwrap();
            drop(policy);
            std::fs::remove_file(
                swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(path),
            )
            .unwrap();
        }

        let current_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &current_path,
            );
        let legacy_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &legacy_path,
            );
        std::fs::remove_file(&legacy_sidecar).unwrap();
        std::fs::hard_link(&current_sidecar, &legacy_sidecar).unwrap();
        std::fs::write(
            governance_selection_lock_path(&current_path),
            b"selection-lock",
        )
        .unwrap();
        let before = governance_artifacts_snapshot(&[&current_path, &legacy_path]);

        let error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Reinitialize,
        )
        .expect_err("two state-plus-lock partials are ambiguous and must refuse recovery");
        assert_eq!(
            error.to_string(),
            format!(
                "governance authority exists at both `{}` and legacy path `{}`; refusing to choose a fork",
                current_path.display(),
                legacy_path.display()
            )
        );
        assert_eq!(
            before,
            governance_artifacts_snapshot(&[&current_path, &legacy_path]),
            "ambiguous partial streams must not mutate any artifact"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn governance_path_selection_lock_refuses_concurrent_scan_and_competing_creation() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-selection-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let first = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .unwrap();
        let thread_config_path = config_path.clone();
        let thread_identity_config = identity_config.clone();
        let concurrent = std::thread::spawn(move || {
            resolve_partition_governance_state_path(
                &thread_config_path,
                &thread_identity_config,
                GovernancePathResolutionMode::Bootstrap,
            )
        })
        .join()
        .unwrap();
        let concurrent_error = match concurrent {
            Ok(_) => panic!("a second resolver must not scan while the first holds the lock"),
            Err(error) => error,
        };
        assert_eq!(concurrent_error.kind(), std::io::ErrorKind::WouldBlock);

        let current_path = first.path().to_path_buf();
        let current_policy = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        drop(first);
        drop(current_policy);

        let legacy_path = root.join("data/governance-partition-state.json");
        let legacy_policy = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &legacy_path,
            tom_identity.id,
            tom_identity.signing_key,
        )
        .unwrap();
        drop(legacy_policy);
        let before = governance_artifacts_snapshot(&[&current_path, &legacy_path]);
        let conflict = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .expect_err("competing streams created after the serialized scan must still refuse");
        assert_eq!(
            conflict.to_string(),
            format!(
                "governance authority exists at both `{}` and legacy path `{}`; refusing to choose a fork",
                current_path.display(),
                legacy_path.display()
            )
        );
        assert_eq!(
            before,
            governance_artifacts_snapshot(&[&current_path, &legacy_path]),
            "competing writers must leave both complete streams unchanged"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn serving_current_policy_retains_authority_guard_after_selection_release() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-authority-guard-current-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        let selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .unwrap();
        let serving = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        selection
            .verify_artifacts(
                &config_path,
                &identity_config,
                GovernancePathResolutionMode::Bootstrap,
            )
            .unwrap();
        drop(selection);

        let competing = std::thread::spawn({
            let legacy_path = legacy_path.clone();
            let id = tom_identity.id.clone();
            let key = tom_identity.signing_key.clone();
            move || {
                swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
                    swarm_agents::tom_agent::GovernancePolicyConfig::default(),
                    legacy_path,
                    id,
                    key,
                )
            }
        })
        .join()
        .unwrap()
        .expect_err("the alternate initializer must honor the retained authority guard");
        assert!(matches!(
            competing,
            swarm_agents::tom_agent::GovernancePersistenceError::AuthorityStateLocked { .. }
        ));
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Complete
        );
        assert_eq!(
            governance_artifact_set(&legacy_path).unwrap(),
            GovernanceArtifactSet::Absent
        );

        drop(serving);
        let reopened = swarm_agents::tom_agent::GovernancePolicy::with_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id,
            tom_identity.signing_key,
        )
        .expect("dropping the serving policy must release the shared authority guard");
        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn serving_legacy_policy_retains_authority_guard_after_selection_release() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-authority-guard-legacy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        let initial = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &legacy_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        drop(initial);
        let selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .unwrap();
        assert_eq!(selection.path(), legacy_path);
        let serving = swarm_agents::tom_agent::GovernancePolicy::with_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &legacy_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        drop(selection);

        let competing = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .expect_err("the alternate initializer must honor the retained legacy guard");
        assert!(matches!(
            competing,
            swarm_agents::tom_agent::GovernancePersistenceError::AuthorityStateLocked { .. }
        ));
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Absent
        );
        assert_eq!(
            governance_artifact_set(&legacy_path).unwrap(),
            GovernanceArtifactSet::Complete
        );

        drop(serving);
        let reopened = swarm_agents::tom_agent::GovernancePolicy::with_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &legacy_path,
            tom_identity.id,
            tom_identity.signing_key,
        )
        .expect("dropping the serving legacy policy must release its authority guard");
        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reinitialized_policy_retains_authority_guard_after_selection_release() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-authority-guard-reinitialize-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        let initial = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        drop(initial);
        std::fs::remove_file(
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&current_path),
        )
        .unwrap();
        let selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Reinitialize,
        )
        .unwrap();
        let serving = swarm_agents::tom_agent::GovernancePolicy::reinitialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            selection.path(),
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        selection
            .verify_artifacts(
                &config_path,
                &identity_config,
                GovernancePathResolutionMode::Reinitialize,
            )
            .unwrap();
        drop(selection);

        let competing = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &legacy_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .expect_err("the alternate initializer must honor the retained reinitialize guard");
        assert!(matches!(
            competing,
            swarm_agents::tom_agent::GovernancePersistenceError::AuthorityStateLocked { .. }
        ));
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Complete
        );
        assert_eq!(
            governance_artifact_set(&legacy_path).unwrap(),
            GovernanceArtifactSet::Absent
        );

        drop(serving);
        let reopened = swarm_agents::tom_agent::GovernancePolicy::with_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id,
            tom_identity.signing_key,
        )
        .expect("dropping the reinitialized policy must release its authority guard");
        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn rollback_refuses_same_bytes_replacement_before_unlink() {
        use std::os::unix::fs::MetadataExt;

        let root = std::env::temp_dir().join(format!(
            "swarm-governance-rollback-unlink-identity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        seed_cleanup_pool_for_fresh_stream(&config_path, &identity_config, &tom_identity);
        let mut selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .unwrap();
        let policy = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        let after = governance_artifact_snapshot(&current_path).unwrap();
        drop(policy);
        selection
            .acquire_cleanup_pool_retention_guard(&tom_identity)
            .expect("completed bootstrap stream should retain through its fixed pool");
        let expected_state = after.state.as_ref().unwrap().bytes.clone();
        let (reached, resumed, _destination) =
            install_governance_rollback_after_reservation_barrier();
        let foreign_path = current_path.clone();
        let foreign_temp = current_path.with_extension("foreign-state");
        let current_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &current_path,
            );
        let legacy_path = super::legacy_partition_governance_state_path(&config_path);
        let legacy_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &legacy_path,
            );
        let foreign_sidecar_source = root.join("foreign-authority");
        let current_sidecar_for_replacement = current_sidecar.clone();
        let legacy_sidecar_for_replacement = legacy_sidecar.clone();
        let foreign_sidecar_source_for_replacement = foreign_sidecar_source.clone();
        let replacement = std::thread::spawn(move || {
            reached.wait();
            std::fs::write(&foreign_temp, expected_state).unwrap();
            std::fs::rename(&foreign_temp, &foreign_path).unwrap();
            std::fs::write(
                &foreign_sidecar_source_for_replacement,
                b"foreign-authority",
            )
            .unwrap();
            std::fs::remove_file(&current_sidecar_for_replacement).unwrap();
            std::fs::remove_file(&legacy_sidecar_for_replacement).unwrap();
            std::fs::hard_link(
                &foreign_sidecar_source_for_replacement,
                &current_sidecar_for_replacement,
            )
            .unwrap();
            std::fs::hard_link(
                &foreign_sidecar_source_for_replacement,
                &legacy_sidecar_for_replacement,
            )
            .unwrap();
            resumed.wait();
        });

        let ownership = bootstrap_artifact_ownership(
            selection.initial_artifacts(),
            AgentKeyLoadStatus::Created,
        )
        .with_constructor_before(selection.initial_artifacts().clone())
        .with_expected_after(after.clone());
        let error = rollback_governance_artifacts_after_selection_conflict(
            &selection,
            selection.initial_artifacts(),
            ownership,
        )
        .expect_err("same-bytes replacement with a new inode must refuse deletion");
        replacement.join().unwrap();
        assert!(error.to_string().contains("changed"), "{error}");
        let foreign = governance_artifact_snapshot(&current_path).unwrap();
        assert_eq!(
            foreign.state.as_ref().unwrap().bytes,
            after.state.as_ref().unwrap().bytes,
            "the foreign replacement retains the same bytes"
        );
        assert_ne!(
            foreign.state.as_ref().unwrap().identity,
            after.state.as_ref().unwrap().identity,
            "the barrier replacement must have a new file identity"
        );
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Complete,
            "refusing rollback must not delete the foreign complete stream"
        );
        assert_eq!(
            std::fs::read(&current_sidecar).unwrap(),
            b"foreign-authority"
        );
        assert_eq!(
            std::fs::read(&legacy_sidecar).unwrap(),
            b"foreign-authority"
        );
        assert_eq!(
            std::fs::symlink_metadata(&current_sidecar).unwrap().ino(),
            std::fs::symlink_metadata(&legacy_sidecar).unwrap().ino(),
            "the competing authority pair remains one shared foreign inode"
        );
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_refuses_source_replacement_before_identity_recheck() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-quarantine-source-recheck-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("artifact");
        std::fs::write(&source, b"owned-artifact").unwrap();
        let expected = governance_artifact_record(&source)
            .unwrap()
            .expect("source should be regular");
        let (reached, resumed) = install_governance_rollback_barrier();
        let replacement = std::thread::spawn({
            let source = source.clone();
            move || {
                reached.wait();
                std::fs::remove_file(&source).unwrap();
                std::fs::write(&source, b"foreign-source").unwrap();
                resumed.wait();
            }
        });

        let error = quarantine_governance_artifact(None, &source, &expected)
            .expect_err("a source replacement before identity recheck must fail closed");
        replacement.join().unwrap();
        assert!(error.to_string().contains("changed"), "{error}");
        assert_eq!(std::fs::read(&source).unwrap(), b"foreign-source");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_refuses_reserved_destination_replacement() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-quarantine-destination-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .unwrap();
        let policy = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id,
            tom_identity.signing_key,
        )
        .unwrap();
        let after = governance_artifact_snapshot(&current_path).unwrap();
        let expected = after.state.as_ref().unwrap().clone();
        let (reached, resumed, destination) =
            install_governance_rollback_after_reservation_barrier();
        let parent = current_path.parent().unwrap().to_path_buf();
        let prefix = format!(
            ".{}.rollback-",
            current_path.file_name().unwrap().to_string_lossy()
        );
        let candidate_prefix = prefix.clone();
        let replacement = std::thread::spawn(move || {
            reached.wait();
            let candidate = destination
                .lock()
                .unwrap()
                .clone()
                .expect("quarantine destination must be published before the barrier");
            assert!(candidate.starts_with(&parent));
            assert!(
                candidate
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(&candidate_prefix))
            );
            std::fs::write(&candidate, b"foreign-quarantine-destination").unwrap();
            resumed.wait();
            candidate
        });
        let error = quarantine_governance_artifact(Some(&selection), &current_path, &expected)
            .expect_err("a replaced quarantine destination must fail before rename");
        let candidate = replacement.join().unwrap();
        assert!(error.to_string().contains("destination"), "{error}");
        assert_eq!(
            governance_artifact_record(&current_path).unwrap().as_ref(),
            Some(&expected),
            "the source artifact must remain when the private destination changes"
        );
        assert_eq!(
            std::fs::read(candidate).unwrap(),
            b"foreign-quarantine-destination"
        );
        drop(policy);
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn private_quarantine_refuses_replacement_before_final_mutation() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-private-final-mutation-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let private_path = root.join("private-quarantine");
        std::fs::write(&private_path, b"owned-private-quarantine").unwrap();
        let expected = governance_artifact_record(&private_path)
            .unwrap()
            .expect("private quarantine should be regular");
        let (reached, resumed) = install_governance_final_mutation_barrier();
        let replacement = std::thread::spawn({
            let private_path = private_path.clone();
            move || {
                reached.wait();
                std::fs::remove_file(&private_path).unwrap();
                std::fs::write(&private_path, b"foreign-private-final-mutation").unwrap();
                resumed.wait();
            }
        });

        let error = remove_private_governance_quarantine(&private_path, &expected)
            .expect_err("a private replacement before final mutation must fail closed");
        replacement.join().unwrap();
        assert!(
            error.to_string().contains("after final identity check"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(&private_path).unwrap(),
            b"foreign-private-final-mutation"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn private_quarantine_unlink_refuses_replacement_after_final_check() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-private-unlink-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let private_path = root.join("private-quarantine");
        std::fs::write(&private_path, b"owned-private-quarantine").unwrap();
        let expected = governance_artifact_record(&private_path)
            .unwrap()
            .expect("private quarantine should be regular");
        let (reached, resumed) = install_governance_private_quarantine_stage_barrier();
        let replacement = std::thread::spawn({
            let private_path = private_path.clone();
            move || {
                reached.wait();
                std::fs::remove_file(&private_path).unwrap();
                std::fs::write(&private_path, b"foreign-private-quarantine").unwrap();
                resumed.wait();
            }
        });
        let error = remove_private_governance_quarantine(&private_path, &expected)
            .expect_err("a private quarantine replacement after final verification must refuse");
        replacement.join().unwrap();
        assert!(error.to_string().contains("changed"), "{error}");
        assert_eq!(
            std::fs::read(&private_path).unwrap(),
            b"foreign-private-quarantine",
            "the foreign replacement must not be unlinked"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn private_quarantine_destination_replacement_is_retained() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-private-destination-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let private_path = root.join("private-quarantine");
        std::fs::write(&private_path, b"owned-private-quarantine").unwrap();
        let expected = governance_artifact_record(&private_path)
            .unwrap()
            .expect("private quarantine should be regular");
        let (reached, resumed, destination) =
            install_governance_rollback_after_reservation_barrier();
        let destination_for_replacement = destination.clone();
        let replacement = std::thread::spawn({
            let private_path = private_path.clone();
            move || {
                reached.wait();
                let candidate = destination_for_replacement
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("private destination must be published before the barrier");
                assert_eq!(candidate.parent(), private_path.parent());
                std::fs::write(&candidate, b"foreign-private-destination").unwrap();
                resumed.wait();
            }
        });
        let error = remove_private_governance_quarantine(&private_path, &expected)
            .expect_err("a private destination replacement must fail closed");
        replacement.join().unwrap();
        assert!(error.to_string().contains("destination"), "{error}");
        assert_eq!(
            std::fs::read(&private_path).unwrap(),
            b"owned-private-quarantine"
        );
        let candidate = destination
            .lock()
            .unwrap()
            .clone()
            .expect("destination path should remain observable");
        assert_eq!(
            std::fs::read(candidate).unwrap(),
            b"foreign-private-destination"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn private_quarantine_final_unlink_replacement_is_retained() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-private-unlink-final-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let private_path = root.join("private-quarantine");
        std::fs::write(&private_path, b"owned-private-quarantine").unwrap();
        let expected = governance_artifact_record(&private_path)
            .unwrap()
            .expect("private quarantine should be regular");
        let (reached, resumed) = install_governance_retained_move_barrier();
        let replacement = std::thread::spawn({
            let private_path = private_path.clone();
            move || {
                reached.wait();
                std::fs::remove_file(&private_path).unwrap();
                std::fs::write(&private_path, b"foreign-private-final").unwrap();
                resumed.wait();
            }
        });
        let error = remove_private_governance_quarantine(&private_path, &expected)
            .expect_err("a final private unlink replacement must fail closed");
        replacement.join().unwrap();
        assert!(error.to_string().contains("replacement"), "{error}");
        assert_eq!(
            std::fs::read(&private_path).unwrap(),
            b"foreign-private-final"
        );
        assert!(
            std::fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().contains("rollback-")),
            "the owned staged copy must be retained after final unlink uncertainty"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_source_final_unlink_replacement_is_retained() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-quarantine-source-final-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("artifact");
        std::fs::write(&source, b"owned-artifact").unwrap();
        let expected = governance_artifact_record(&source)
            .unwrap()
            .expect("source should be regular");
        let (reached, resumed) = install_governance_retained_move_barrier();
        let replacement = std::thread::spawn({
            let source = source.clone();
            move || {
                reached.wait();
                std::fs::remove_file(&source).unwrap();
                std::fs::write(&source, b"foreign-source-final").unwrap();
                resumed.wait();
            }
        });
        let error = quarantine_governance_artifact(None, &source, &expected)
            .expect_err("a source replacement after final verification must fail closed");
        replacement.join().unwrap();
        assert!(error.to_string().contains("replacement"), "{error}");
        assert_eq!(std::fs::read(&source).unwrap(), b"foreign-source-final");
        let quarantine = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".artifact.rollback-"))
            })
            .expect("published quarantine must be retained on unlink uncertainty");
        assert_eq!(std::fs::read(quarantine).unwrap(), b"owned-artifact");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_held_parent_retarget_mutates_only_original_directory() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-quarantine-parent-retarget-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let parent = root.join("state");
        let moved_parent = root.join("state-held");
        std::fs::create_dir_all(&parent).unwrap();
        let source = parent.join("artifact");
        std::fs::write(&source, b"owned-artifact").unwrap();
        let expected = governance_artifact_record(&source)
            .unwrap()
            .expect("source should be regular");
        let (reached, resumed) = install_governance_parent_mutation_barrier();
        let replacement = std::thread::spawn({
            let parent = parent.clone();
            let moved_parent = moved_parent.clone();
            move || {
                reached.wait();
                std::fs::rename(&parent, &moved_parent).unwrap();
                std::fs::create_dir(&parent).unwrap();
                std::fs::write(parent.join("artifact"), b"foreign-parent-artifact").unwrap();
                resumed.wait();
            }
        });
        let error = quarantine_governance_artifact(None, &source, &expected)
            .expect_err("a parent retarget at the held-dirfd mutation seam must fail closed");
        replacement.join().unwrap();
        assert!(error.to_string().contains("parent"), "{error}");
        assert_eq!(
            std::fs::read(parent.join("artifact")).unwrap(),
            b"foreign-parent-artifact",
            "the replacement parent must not be mutated through its pathname"
        );
        assert_eq!(
            std::fs::read(moved_parent.join("artifact")).unwrap(),
            b"owned-artifact",
            "the held original parent must retain the source artifact"
        );
        let retained = std::fs::read_dir(&moved_parent)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".artifact.rollback-"))
            })
            .expect("the held directory may retain its owned quarantine after uncertainty");
        assert_eq!(std::fs::read(retained).unwrap(), b"owned-artifact");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn private_quarantine_held_parent_retarget_mutates_only_original_directory() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-private-parent-retarget-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let parent = root.join("state");
        let moved_parent = root.join("state-held");
        std::fs::create_dir_all(&parent).unwrap();
        let private_path = parent.join("private-quarantine");
        std::fs::write(&private_path, b"owned-private-quarantine").unwrap();
        let expected = governance_artifact_record(&private_path)
            .unwrap()
            .expect("private quarantine should be regular");
        let (reached, resumed) = install_governance_parent_mutation_barrier();
        let replacement = std::thread::spawn({
            let parent = parent.clone();
            let moved_parent = moved_parent.clone();
            move || {
                reached.wait();
                std::fs::rename(&parent, &moved_parent).unwrap();
                std::fs::create_dir(&parent).unwrap();
                std::fs::write(
                    parent.join("private-quarantine"),
                    b"foreign-parent-private-quarantine",
                )
                .unwrap();
                resumed.wait();
            }
        });
        let error = remove_private_governance_quarantine(&private_path, &expected)
            .expect_err("a parent retarget at private staging must fail closed");
        replacement.join().unwrap();
        assert!(error.to_string().contains("parent"), "{error}");
        assert_eq!(
            std::fs::read(parent.join("private-quarantine")).unwrap(),
            b"foreign-parent-private-quarantine",
            "the replacement parent must not be mutated through its pathname"
        );
        assert_eq!(
            std::fs::read(moved_parent.join("private-quarantine")).unwrap(),
            b"owned-private-quarantine",
            "the held original parent must retain the source artifact"
        );
        let retained = std::fs::read_dir(&moved_parent)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .starts_with(".private-quarantine.rollback-")
                })
            })
            .expect("the held directory may retain its staged copy after uncertainty");
        assert_eq!(
            std::fs::read(retained).unwrap(),
            b"owned-private-quarantine"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn artifact_loader_binds_held_fd_through_symlink_and_inode_swap() {
        use std::os::unix::fs::{MetadataExt, symlink};

        let root = std::env::temp_dir().join(format!(
            "swarm-governance-artifact-loader-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();

        let artifact = root.join("artifact");
        let foreign_target = root.join("foreign-target");
        std::fs::write(&artifact, b"owned-artifact").unwrap();
        std::fs::write(&foreign_target, b"foreign-target").unwrap();
        let (reached, resumed) = install_governance_artifact_read_barrier();
        let replacement = std::thread::spawn({
            let artifact = artifact.clone();
            let foreign_target = foreign_target.clone();
            move || {
                reached.wait();
                std::fs::remove_file(&artifact).unwrap();
                symlink(&foreign_target, &artifact).unwrap();
                resumed.wait();
            }
        });
        let error = governance_artifact_record(&artifact)
            .expect_err("a symlink swap during a held-fd read must fail closed");
        replacement.join().unwrap();
        assert!(error.to_string().contains("changed identity"), "{error}");
        assert!(
            std::fs::symlink_metadata(&artifact)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_link(&artifact).unwrap(), foreign_target);
        assert_eq!(std::fs::read(&foreign_target).unwrap(), b"foreign-target");

        std::fs::remove_file(&artifact).unwrap();
        std::fs::write(&artifact, b"owned-artifact").unwrap();
        let original_identity = std::fs::symlink_metadata(&artifact).unwrap();
        let (reached, resumed) = install_governance_artifact_read_barrier();
        let replacement = std::thread::spawn({
            let artifact = artifact.clone();
            move || {
                reached.wait();
                let temporary = artifact.with_extension("foreign");
                std::fs::write(&temporary, b"foreign-inode").unwrap();
                std::fs::rename(&temporary, &artifact).unwrap();
                resumed.wait();
            }
        });
        let error = governance_artifact_record(&artifact)
            .expect_err("an inode swap during a held-fd read must fail closed");
        replacement.join().unwrap();
        assert!(error.to_string().contains("changed identity"), "{error}");
        let foreign_identity = std::fs::symlink_metadata(&artifact).unwrap();
        assert!(foreign_identity.file_type().is_file());
        assert_ne!(
            (original_identity.dev(), original_identity.ino()),
            (foreign_identity.dev(), foreign_identity.ino())
        );
        assert_eq!(std::fs::read(&artifact).unwrap(), b"foreign-inode");

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn rollback_refuses_same_bytes_replacement_before_restore_install() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-rollback-rename-identity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        seed_cleanup_pool_for_fresh_stream(&config_path, &identity_config, &tom_identity);
        let initial_policy = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        drop(initial_policy);
        std::fs::remove_file(
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&current_path),
        )
        .unwrap();
        let before = governance_artifact_snapshot(&current_path).unwrap();
        let mut selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Reinitialize,
        )
        .unwrap();
        let reinitialized = swarm_agents::tom_agent::GovernancePolicy::reinitialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            selection.path(),
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        let after = governance_artifact_snapshot(&current_path).unwrap();
        drop(reinitialized);
        selection
            .acquire_cleanup_pool_retention_guard(&tom_identity)
            .expect("completed reinitialize stream should retain through its fixed pool");
        let expected_state = after.state.as_ref().unwrap().bytes.clone();
        let (reached_final, resumed_final) = install_governance_rollback_install_barrier();
        let foreign_path = current_path.clone();
        let foreign_temp = current_path.with_extension("foreign-state");
        let replacement = std::thread::spawn(move || {
            reached_final.wait();
            std::fs::write(&foreign_temp, expected_state).unwrap();
            std::fs::rename(&foreign_temp, &foreign_path).unwrap();
            resumed_final.wait();
        });

        let ownership = reinitialize_artifact_ownership(&before)
            .with_constructor_before(before.clone())
            .with_expected_after(after.clone());
        let error =
            rollback_governance_artifacts_after_selection_conflict(&selection, &before, ownership)
                .expect_err("same-bytes replacement with a new inode must refuse overwrite");
        replacement.join().unwrap();
        assert!(error.to_string().contains("overwrite"), "{error}");
        let foreign = governance_artifact_snapshot(&current_path).unwrap();
        assert_eq!(
            foreign.state.as_ref().unwrap().bytes,
            after.state.as_ref().unwrap().bytes,
            "the foreign replacement retains the same bytes"
        );
        assert_ne!(
            foreign.state.as_ref().unwrap().identity,
            after.state.as_ref().unwrap().identity,
            "the barrier replacement must have a new file identity"
        );
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Complete,
            "refusing rollback must not overwrite the foreign complete stream"
        );
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn transactional_rollback_compensates_prior_state_mutation_on_later_peer_drift() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-rollback-journal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        seed_cleanup_pool_for_fresh_stream(&config_path, &identity_config, &tom_identity);
        let initial = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        drop(initial);
        let sequence_path =
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&current_path);
        std::fs::remove_file(&sequence_path).unwrap();
        let before = governance_artifact_snapshot(&current_path).unwrap();
        let mut selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Reinitialize,
        )
        .unwrap();
        let reinitialized = swarm_agents::tom_agent::GovernancePolicy::reinitialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            selection.path(),
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        let after = governance_artifact_snapshot(&current_path).unwrap();
        drop(reinitialized);
        selection
            .acquire_cleanup_pool_retention_guard(&tom_identity)
            .expect("completed reinitialize stream should retain through its fixed pool");
        let expected_state = after.state.as_ref().unwrap().clone();
        let (reached, resumed) = install_governance_rollback_journal_barrier();
        let foreign_sequence = sequence_path.clone();
        let replacement = std::thread::spawn(move || {
            reached.wait();
            let temporary = foreign_sequence.with_extension("foreign-sequence");
            std::fs::write(&temporary, b"foreign-sequence").unwrap();
            std::fs::rename(&temporary, &foreign_sequence).unwrap();
            resumed.wait();
        });
        let ownership = reinitialize_artifact_ownership(&before)
            .with_constructor_before(before.clone())
            .with_expected_after(after.clone());
        let error =
            rollback_governance_artifacts_after_selection_conflict(&selection, &before, ownership)
                .expect_err(
                    "a later peer identity drift must abort and compensate earlier rollback",
                );
        replacement.join().unwrap();
        assert!(error.to_string().contains("changed identity"));
        let final_snapshot = governance_artifact_snapshot(&current_path).unwrap();
        assert_eq!(
            final_snapshot.state.as_ref().unwrap(),
            &expected_state,
            "compensation must restore the exact post-constructor state"
        );
        assert_eq!(
            final_snapshot.sequence.as_ref().unwrap().bytes,
            b"foreign-sequence",
            "the foreign later peer must remain untouched"
        );
        assert_ne!(
            final_snapshot.sequence.as_ref().unwrap().identity,
            after.sequence.as_ref().unwrap().identity,
            "the foreign peer must retain its replacement identity"
        );
        assert_eq!(
            final_snapshot.state.as_ref().unwrap().identity.device,
            expected_state.identity.device
        );
        assert_eq!(
            final_snapshot.state.as_ref().unwrap().identity.inode,
            expected_state.identity.inode
        );
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Complete
        );
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn transactional_rollback_restores_all_entries_when_late_finalization_fails() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-rollback-finalization-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        seed_cleanup_pool_for_fresh_stream(&config_path, &identity_config, &tom_identity);
        let initial = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        drop(initial);
        let sequence_path =
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&current_path);
        std::fs::remove_file(&sequence_path).unwrap();
        let before = governance_artifact_snapshot(&current_path).unwrap();
        let mut selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Reinitialize,
        )
        .unwrap();
        let reinitialized = swarm_agents::tom_agent::GovernancePolicy::reinitialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            selection.path(),
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        let after = super::governance_artifact_snapshot(&current_path).unwrap();
        let expected_after = after.clone();
        inject_governance_rollback_cleanup_failure_on_call(2);
        drop(reinitialized);
        selection
            .acquire_cleanup_pool_retention_guard(&tom_identity)
            .expect("completed reinitialize stream should retain through its fixed pool");
        let ownership = reinitialize_artifact_ownership(&before)
            .with_constructor_before(before.clone())
            .with_expected_after(after);
        let error =
            rollback_governance_artifacts_after_selection_conflict(&selection, &before, ownership)
                .expect_err("a late finalization failure must trigger whole-journal compensation");
        assert!(
            error
                .to_string()
                .contains("injected governance rollback cleanup failure"),
            "{error}"
        );
        assert_eq!(
            super::governance_artifact_snapshot(&current_path).unwrap(),
            expected_after
        );
        assert!(
            std::fs::read_dir(current_path.parent().unwrap())
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    !name.contains(".rollback-") && !name.contains("rollback-backup")
                }),
            "finalization compensation must not strand detector rollback entries"
        );
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn rollback_no_replace_install_preserves_target_created_after_final_check() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-rollback-install-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let key_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &identity_config)).unwrap();
        let (tom_identity, _) = key_store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        seed_cleanup_pool_for_fresh_stream(&config_path, &identity_config, &tom_identity);
        let initial = swarm_agents::tom_agent::GovernancePolicy::initialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &current_path,
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        drop(initial);
        let sequence_path =
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&current_path);
        std::fs::remove_file(&sequence_path).unwrap();
        let before = governance_artifact_snapshot(&current_path).unwrap();
        let mut selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Reinitialize,
        )
        .unwrap();
        let reinitialized = swarm_agents::tom_agent::GovernancePolicy::reinitialize_persistence(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            selection.path(),
            tom_identity.id.clone(),
            tom_identity.signing_key.clone(),
        )
        .unwrap();
        let after = governance_artifact_snapshot(&current_path).unwrap();
        drop(reinitialized);
        selection
            .acquire_cleanup_pool_retention_guard(&tom_identity)
            .expect("completed reinitialize stream should retain through its fixed pool");
        let foreign_bytes = b"foreign-state-after-final-check".to_vec();
        let expected_foreign_bytes = foreign_bytes.clone();
        let (reached, resumed) = install_governance_rollback_install_barrier();
        let foreign_path = current_path.clone();
        let replacement = std::thread::spawn(move || {
            reached.wait();
            let temporary = foreign_path.with_extension("foreign-state");
            std::fs::write(&temporary, &foreign_bytes).unwrap();
            std::fs::rename(&temporary, &foreign_path).unwrap();
            resumed.wait();
        });
        let ownership = reinitialize_artifact_ownership(&before)
            .with_constructor_before(before.clone())
            .with_expected_after(after);
        let error =
            rollback_governance_artifacts_after_selection_conflict(&selection, &before, ownership)
                .expect_err(
                    "a target created after the final check must refuse no-replace install",
                );
        replacement.join().unwrap();
        assert!(error.to_string().contains("overwrite") || error.to_string().contains("changed"));
        assert_eq!(
            std::fs::read(&current_path).unwrap(),
            expected_foreign_bytes
        );
        assert_eq!(
            governance_artifact_set(&current_path).unwrap(),
            GovernanceArtifactSet::Complete,
            "refusing install must preserve the foreign target and its peers"
        );
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn governance_path_selection_lock_rejects_a_nonregular_file() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-selection-lock-directory-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        let selection_lock_path = governance_selection_lock_path(&current_path);
        std::fs::create_dir(&selection_lock_path).unwrap();

        let error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .expect_err("a directory at the selection-lock path must fail closed");
        assert!(error.to_string().contains("not a regular file"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn governance_path_selection_lock_rejects_a_symlink() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-selection-lock-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        let target = root.join("selection-lock-target");
        std::fs::write(&target, b"target").unwrap();
        let selection_lock_path = governance_selection_lock_path(&current_path);
        std::os::unix::fs::symlink(&target, &selection_lock_path).unwrap();

        let error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .expect_err("a symlink at the selection-lock path must fail closed");
        assert!(error.to_string().contains("not a regular file"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn upgrade_refuses_partial_current_governance_artifacts_without_mutation() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-partial-current-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        std::fs::write(&current_path, b"partial-current-state").unwrap();
        std::fs::write(
            governance_selection_lock_path(&current_path),
            b"selection-lock",
        )
        .unwrap();
        ensure_governance_authority_lock_pair(&current_path, &legacy_path).unwrap();
        let before = governance_artifacts_snapshot(&[&current_path, &legacy_path]);

        let error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .expect_err("a partial current stream must fail closed");
        assert!(error.to_string().contains("transition is incomplete"));
        let recovery_error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Reinitialize,
        )
        .expect_err("explicit recovery must still refuse a current stream without a lock");
        assert!(recovery_error.to_string().contains("missing its lock"));

        let after = governance_artifacts_snapshot(&[&current_path, &legacy_path]);
        assert_eq!(
            before, after,
            "partial current discovery must not create, delete, or rewrite any artifact"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn upgrade_refuses_partial_legacy_governance_artifacts_without_mutation() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-partial-legacy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        std::fs::write(
            governance_selection_lock_path(&current_path),
            b"selection-lock",
        )
        .unwrap();
        std::fs::write(&legacy_path, b"partial-legacy-state").unwrap();
        let legacy_sequence_path =
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&legacy_path);
        std::fs::write(&legacy_sequence_path, b"partial-legacy-sequence").unwrap();
        ensure_governance_authority_lock_pair(&current_path, &legacy_path).unwrap();
        let before = governance_artifacts_snapshot(&[&current_path, &legacy_path]);

        let error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .expect_err("a partial legacy stream must fail closed");
        assert!(
            error
                .to_string()
                .contains("legacy governance state path is incomplete")
        );
        let recovery_error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Reinitialize,
        )
        .expect_err("explicit recovery must still refuse a legacy stream without a lock");
        assert!(recovery_error.to_string().contains("missing its lock"));

        let after = governance_artifacts_snapshot(&[&current_path, &legacy_path]);
        assert_eq!(
            before, after,
            "partial legacy discovery must not create, delete, or rewrite any artifact"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn authority_sidecar_inode_mismatch_refuses_selection_without_mutation() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-authority-mismatch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        std::fs::write(&current_path, b"partial-current-state").unwrap();
        std::fs::write(
            governance_selection_lock_path(&current_path),
            b"selection-lock",
        )
        .unwrap();
        let current_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &current_path,
            );
        let legacy_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &legacy_path,
            );
        std::fs::write(&current_sidecar, b"current-authority").unwrap();
        std::fs::write(&legacy_sidecar, b"legacy-authority").unwrap();
        let before = governance_artifacts_snapshot(&[&current_path, &legacy_path]);

        let error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .expect_err("different authority inodes must never be selected");
        assert!(error.to_string().contains("authority"), "{error}");

        let after = governance_artifacts_snapshot(&[&current_path, &legacy_path]);
        assert_eq!(before, after);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn authority_sidecar_create_fd_replacement_preserves_foreign_entry() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-authority-create-fd-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = super::legacy_partition_governance_state_path(&config_path);
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        let current_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &current_path,
            );
        let legacy_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &legacy_path,
            );
        let (reached, resumed) = install_governance_authority_sidecar_create_barrier();
        let replacement = std::thread::spawn({
            let current_sidecar = current_sidecar.clone();
            move || {
                reached.wait();
                std::fs::remove_file(&current_sidecar).unwrap();
                std::fs::write(&current_sidecar, b"foreign-created-after-create_new").unwrap();
                resumed.wait();
            }
        });
        let error = ensure_governance_authority_lock_pair(&current_path, &legacy_path)
            .expect_err("a sidecar replacement after create_new must fail closed");
        replacement.join().unwrap();
        assert!(error.to_string().contains("changed"), "{error}");
        assert_eq!(
            std::fs::read(&current_sidecar).unwrap(),
            b"foreign-created-after-create_new"
        );
        assert!(
            !legacy_sidecar.exists(),
            "a foreign replacement must not be adopted as the source for a new sidecar"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn authority_hard_link_validation_failure_preserves_a_replacement_target() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "swarm-governance-authority-hard-link-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        let selection_path = governance_selection_lock_path(&current_path);
        std::fs::write(&selection_path, b"selection-lock").unwrap();
        let current_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &current_path,
            );
        let legacy_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &legacy_path,
            );
        std::fs::write(&current_sidecar, b"authority").unwrap();
        let foreign_target = root.join("foreign-authority");
        std::fs::write(&foreign_target, b"foreign-authority").unwrap();
        let (reached, resumed) = install_governance_authority_hard_link_barrier();
        let replacement = std::thread::spawn({
            let legacy_sidecar = legacy_sidecar.clone();
            let foreign_target = foreign_target.clone();
            move || {
                reached.wait();
                std::fs::remove_file(&legacy_sidecar).unwrap();
                symlink(&foreign_target, &legacy_sidecar).unwrap();
                resumed.wait();
            }
        });
        let selection = GovernancePathSelectionLock::acquire(selection_path).unwrap();
        let error = ensure_governance_authority_lock_pair(&current_path, &legacy_path)
            .expect_err("validation must fail after the hard-link target is replaced");
        replacement.join().unwrap();
        assert!(error.to_string().contains("changed identity"), "{error}");
        assert!(
            std::fs::symlink_metadata(&legacy_sidecar)
                .unwrap()
                .file_type()
                .is_symlink(),
            "cleanup must preserve the foreign replacement rather than unlink by path"
        );
        assert_eq!(std::fs::read(&current_sidecar).unwrap(), b"authority");
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn authority_hard_link_source_replacement_preserves_foreign_source_and_target() {
        use std::os::unix::fs::MetadataExt;

        let root = std::env::temp_dir().join(format!(
            "swarm-governance-authority-source-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        let selection_path = governance_selection_lock_path(&current_path);
        std::fs::write(&selection_path, b"selection-lock").unwrap();
        let current_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &current_path,
            );
        let legacy_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &legacy_path,
            );
        std::fs::write(&current_sidecar, b"original-authority").unwrap();
        let original_identity = std::fs::symlink_metadata(&current_sidecar).unwrap().ino();
        let (reached, resumed) = install_governance_authority_source_pin_barrier();
        let replacement = std::thread::spawn({
            let current_sidecar = current_sidecar.clone();
            move || {
                reached.wait();
                std::fs::remove_file(&current_sidecar).unwrap();
                std::fs::write(&current_sidecar, b"foreign-source").unwrap();
                resumed.wait();
            }
        });
        let selection = GovernancePathSelectionLock::acquire(selection_path).unwrap();
        let error = ensure_governance_authority_lock_pair(&current_path, &legacy_path)
            .expect_err("a source replacement after descriptor pinning must fail closed");
        replacement.join().unwrap();
        assert!(error.to_string().contains("source") || error.to_string().contains("identity"));
        assert_eq!(std::fs::read(&current_sidecar).unwrap(), b"foreign-source");
        assert_ne!(
            std::fs::symlink_metadata(&current_sidecar).unwrap().ino(),
            original_identity,
            "the foreign source replacement must remain a new inode"
        );
        assert_eq!(
            std::fs::read(&legacy_sidecar).unwrap(),
            b"foreign-source",
            "a target linked from a replaced source is foreign and must be retained"
        );
        assert_ne!(
            std::fs::symlink_metadata(&legacy_sidecar).unwrap().ino(),
            original_identity,
            "the retained target must have the foreign source identity"
        );
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn authority_hard_link_source_replacement_before_open_preserves_foreign_source() {
        use std::os::unix::fs::MetadataExt;

        let root = std::env::temp_dir().join(format!(
            "swarm-governance-authority-source-open-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        let selection_path = governance_selection_lock_path(&current_path);
        std::fs::write(&selection_path, b"selection-lock").unwrap();
        let current_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &current_path,
            );
        let legacy_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &legacy_path,
            );
        std::fs::write(&current_sidecar, b"original-authority").unwrap();
        let original_identity = std::fs::symlink_metadata(&current_sidecar).unwrap();
        let (reached, resumed) = install_governance_authority_source_open_barrier();
        let replacement = std::thread::spawn({
            let current_sidecar = current_sidecar.clone();
            move || {
                reached.wait();
                std::fs::remove_file(&current_sidecar).unwrap();
                std::fs::write(&current_sidecar, b"foreign-source-before-open").unwrap();
                resumed.wait();
            }
        });
        let selection = GovernancePathSelectionLock::acquire(selection_path).unwrap();
        let error = ensure_governance_authority_lock_pair(&current_path, &legacy_path)
            .expect_err("a source replacement before descriptor open must fail closed");
        replacement.join().unwrap();
        assert!(error.to_string().contains("source") || error.to_string().contains("identity"));
        assert_eq!(
            std::fs::read(&current_sidecar).unwrap(),
            b"foreign-source-before-open"
        );
        let foreign_identity = std::fs::symlink_metadata(&current_sidecar).unwrap();
        assert_ne!(
            (original_identity.dev(), original_identity.ino()),
            (foreign_identity.dev(), foreign_identity.ino()),
            "the foreign source replacement must remain a new inode"
        );
        assert!(
            !legacy_sidecar.exists(),
            "no hard-link target may be created from the replaced source"
        );
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn selected_authority_pair_replacement_is_observed_without_repairing_sidecars() {
        use std::os::unix::fs::MetadataExt;

        let root = std::env::temp_dir().join(format!(
            "swarm-governance-authority-pair-replacement-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        let selection = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .unwrap();
        let current_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &current_path,
            );
        let legacy_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &legacy_path,
            );
        let pinned = selection.authority_pair_identity();
        let replacement_source = root.join("replacement-authority");
        std::fs::write(&replacement_source, b"replacement-authority").unwrap();
        std::fs::remove_file(&current_sidecar).unwrap();
        std::fs::remove_file(&legacy_sidecar).unwrap();
        std::fs::hard_link(&replacement_source, &current_sidecar).unwrap();
        std::fs::hard_link(&replacement_source, &legacy_sidecar).unwrap();
        let before = governance_artifacts_snapshot(&[&current_path, &legacy_path]);
        let error = selection
            .verify_authority_pair_identity(&config_path, &identity_config)
            .expect_err("replacement of both sidecar names must fail the pinned selection");
        assert!(
            error.to_string().contains("changed after selection"),
            "{error}"
        );
        assert_ne!(
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_identity(
                &current_path,
            )
            .unwrap()
            .inode,
            pinned.inode
        );
        assert_eq!(
            before,
            governance_artifacts_snapshot(&[&current_path, &legacy_path]),
            "authority validation must not repair or remove replacement sidecars"
        );
        let current_metadata = std::fs::symlink_metadata(&current_sidecar).unwrap();
        let legacy_metadata = std::fs::symlink_metadata(&legacy_sidecar).unwrap();
        assert_eq!(current_metadata.dev(), legacy_metadata.dev());
        assert_eq!(current_metadata.ino(), legacy_metadata.ino());
        drop(selection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn authority_sidecar_symlink_refuses_selection_without_mutation() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "swarm-governance-authority-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        // Keep the stream complete so resolver preflight reaches the
        // malformed authority sidecar check rather than rejecting an
        // unrelated partial artifact set first.
        std::fs::write(&current_path, b"complete-current-state").unwrap();
        std::fs::write(
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&current_path),
            b"0",
        )
        .unwrap();
        std::fs::write(
            swarm_agents::tom_agent::GovernancePolicy::persistence_lock_path(&current_path),
            b"lock",
        )
        .unwrap();
        std::fs::write(
            governance_selection_lock_path(&current_path),
            b"selection-lock",
        )
        .unwrap();
        let target = root.join("authority-target");
        std::fs::write(&target, b"authority-target").unwrap();
        let current_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &current_path,
            );
        symlink(&target, &current_sidecar).unwrap();
        let before = governance_artifact_snapshot(&current_path).unwrap();
        let selection_before =
            std::fs::read(governance_selection_lock_path(&current_path)).unwrap();

        let error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .expect_err("a symlink authority sidecar must fail closed");
        assert!(error.to_string().contains("regular non-symlink"), "{error}");

        assert_eq!(governance_artifact_snapshot(&current_path).unwrap(), before);
        assert_eq!(
            std::fs::read(governance_selection_lock_path(&current_path)).unwrap(),
            selection_before
        );
        assert!(
            std::fs::symlink_metadata(&current_sidecar)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            !swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &legacy_path
            )
            .exists()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn authority_sidecar_nonregular_refuses_selection_without_mutation() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-authority-directory-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_path = root.join("rulesets/default.yaml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let identity_config = swarm_core::config::IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };
        let current_path = default_partition_governance_state_path(&config_path, &identity_config);
        let legacy_path = root.join("data/governance-partition-state.json");
        std::fs::create_dir_all(current_path.parent().unwrap()).unwrap();
        // Keep the stream complete so resolver preflight reaches the
        // malformed authority sidecar check rather than rejecting an
        // unrelated partial artifact set first.
        std::fs::write(&current_path, b"complete-current-state").unwrap();
        std::fs::write(
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&current_path),
            b"0",
        )
        .unwrap();
        std::fs::write(
            swarm_agents::tom_agent::GovernancePolicy::persistence_lock_path(&current_path),
            b"lock",
        )
        .unwrap();
        let selection_lock = governance_selection_lock_path(&current_path);
        std::fs::write(&selection_lock, b"selection-lock").unwrap();
        let current_sidecar =
            swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &current_path,
            );
        std::fs::create_dir(&current_sidecar).unwrap();
        let before = governance_artifact_snapshot(&current_path).unwrap();
        let selection_before = std::fs::read(&selection_lock).unwrap();

        let error = resolve_partition_governance_state_path(
            &config_path,
            &identity_config,
            GovernancePathResolutionMode::Bootstrap,
        )
        .expect_err("a directory authority sidecar must fail closed");
        assert!(error.to_string().contains("regular non-symlink"), "{error}");
        assert_eq!(governance_artifact_snapshot(&current_path).unwrap(), before);
        assert_eq!(std::fs::read(&selection_lock).unwrap(), selection_before);
        assert!(
            std::fs::symlink_metadata(&current_sidecar)
                .unwrap()
                .file_type()
                .is_dir()
        );
        assert!(
            !swarm_agents::tom_agent::GovernancePolicy::persistence_authority_lock_path(
                &legacy_path
            )
            .exists()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn deleted_registry_and_governance_files_do_not_reinitialize_an_existing_tom_key() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-bootstrap-deletion-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let key_root = root.join("keys");
        let registry_root = root.join("registry");
        let state_path = root.join("governance-partition-state.json");
        let store = FileAgentKeyStore::open(&key_root).unwrap();
        let (identity, status) = store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        assert_eq!(status, AgentKeyLoadStatus::Created);
        let registry = FileAgentIdentityRegistry::open(&registry_root).unwrap();
        assert_eq!(
            registry
                .admit_persisted_identity(AgentRole::Tom, "primary", &identity, 1)
                .unwrap(),
            RegistryAdmission::Added
        );
        let policy = governance_policy_for_bootstrap(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &state_path,
            &identity,
            status,
        )
        .unwrap();
        drop(policy);
        drop(registry);

        std::fs::remove_dir_all(&registry_root).unwrap();
        std::fs::remove_file(&state_path).unwrap();
        std::fs::remove_file(
            swarm_agents::tom_agent::GovernancePolicy::persistence_sequence_path(&state_path),
        )
        .unwrap();

        let (loaded_identity, loaded_status) = store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        assert_eq!(loaded_status, AgentKeyLoadStatus::Loaded);
        let recreated_registry = FileAgentIdentityRegistry::open(&registry_root).unwrap();
        assert_eq!(
            recreated_registry
                .admit_persisted_identity(AgentRole::Tom, "primary", &loaded_identity, 2)
                .unwrap(),
            RegistryAdmission::Added,
            "registry deletion alone makes admission look new, so it cannot authorize bootstrap"
        );
        assert!(matches!(
            governance_policy_for_bootstrap(
                swarm_agents::tom_agent::GovernancePolicyConfig::default(),
                &state_path,
                &loaded_identity,
                loaded_status,
            )
            .unwrap_err(),
            swarm_agents::tom_agent::GovernancePersistenceError::MissingState { .. }
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn bootstrap_refuses_a_second_daemon_for_the_live_governance_stream() {
        let root = std::env::temp_dir().join(format!(
            "swarm-governance-bootstrap-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state_path = root.join("governance-partition-state.json");
        let store = FileAgentKeyStore::open(root.join("keys")).unwrap();
        let (identity, status) = store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let first = governance_policy_for_bootstrap(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &state_path,
            &identity,
            status,
        )
        .unwrap();

        let error = governance_policy_for_bootstrap(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &state_path,
            &identity,
            AgentKeyLoadStatus::Loaded,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            swarm_agents::tom_agent::GovernancePersistenceError::StateLocked { .. }
        ));

        drop(first);
        let second = governance_policy_for_bootstrap(
            swarm_agents::tom_agent::GovernancePolicyConfig::default(),
            &state_path,
            &identity,
            AgentKeyLoadStatus::Loaded,
        )
        .unwrap();
        drop(second);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn serve_approval_harness_configures_all_four_durable_stores() {
        let root = std::env::temp_dir().join(format!(
            "swarm-detect-approval-stores-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ));
        let cli = Cli::parse_from([
            "swarm-detect",
            "--approval-set-results-dir",
            root.join("sets").to_str().unwrap(),
            "--approval-ledger-results-dir",
            root.join("ledgers").to_str().unwrap(),
            "--approval-verdict-results-dir",
            root.join("verdicts").to_str().unwrap(),
            "--approval-receipt-pack-results-dir",
            root.join("packs").to_str().unwrap(),
        ]);

        let harness = build_approval_harness(&cli).expect("all approval stores should open");
        assert!(harness.list_verdicts().unwrap().verdicts.is_empty());
        assert!(harness.list_receipt_packs().unwrap().packs.is_empty());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn serve_mode_registers_sphinx_when_memory_is_enabled() {
        let root = std::env::temp_dir().join(format!(
            "swarm-detect-sphinx-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("temporary root should be created");

        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("rulesets/default.yaml");
        let mut config =
            swarm_runtime::config::load_config(&config_path).expect("default config should load");
        config.memory.enabled = true;
        config.identity.agent_key_dir = root.join("agent-keys").display().to_string();
        config.identity.registry_dir = root.join("agent-identity").display().to_string();
        config.memory.knowledge_graph_results_dir =
            root.join("knowledge-graph").display().to_string();

        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let health_state = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
        let substrate = ConfiguredPheromoneSubstrate::from_config(&config.pheromone)
            .expect("substrate should build");
        let state = IngestState::from_config(config_path.clone(), config.clone())
            .expect("ingest state should build");
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate.clone(),
            Arc::clone(&health_state),
        )
        .with_mode_state(Arc::new(arc_swap::ArcSwap::from_pointee(
            SwarmModeState::new(),
        )))
        .with_runtime_events(RuntimeEventBroadcaster::new(16));

        let identity_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &config.identity))
                .expect("agent key store should open");
        let identity_registry = FileAgentIdentityRegistry::open(resolve_identity_registry_dir(
            &config_path,
            &config.identity,
        ))
        .expect("identity registry should open");
        let registered_id = register_optional_sphinx_agent(
            &mut dispatcher,
            &config_path,
            &config,
            &state,
            &identity_store,
            &identity_registry,
            swarm_runtime::runtime_events::now_ms(),
        )
        .expect("sphinx registration should succeed");
        let registered_id = registered_id.expect("sphinx should be registered");

        let summary = dispatcher.agent_health_summary();
        let first_id = summary
            .iter()
            .find(|entry| entry.role == AgentRole::Sphinx)
            .map(|entry| entry.id.clone())
            .expect("sphinx entry should exist");
        assert!(first_id.starts_with("swarm:ed25519:"));
        assert_eq!(first_id, registered_id.0);

        let reloaded_identity =
            super::load_persisted_agent_identity(&identity_store, AgentRole::Sphinx, "primary")
                .expect("persisted sphinx identity should reload");
        assert_eq!(first_id, reloaded_identity.id.0);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn serve_mode_registers_calico_when_deception_is_enabled() {
        let root = std::env::temp_dir().join(format!(
            "swarm-detect-calico-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("temporary root should be created");

        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("rulesets/default.yaml");
        let mut config =
            swarm_runtime::config::load_config(&config_path).expect("default config should load");
        config.deception.enabled = true;
        config.identity.agent_key_dir = root.join("agent-keys").display().to_string();
        config.identity.registry_dir = root.join("agent-identity").display().to_string();
        // Without this, `resolve_deception_root` joins the repo-relative default to
        // `config_path.parent()` and `FileCalicoLifecycleStore::open` create_dir_all's
        // `rulesets/data/deception-lifecycle` inside the checkout. The sibling helper at
        // `calico_agent.rs:991` already redirects it; this call site was missed.
        config.deception.lifecycle_results_dir =
            root.join("deception-lifecycle").display().to_string();

        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let health_state = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new()));
        let substrate = ConfiguredPheromoneSubstrate::from_config(&config.pheromone)
            .expect("substrate should build");
        let state = IngestState::from_config(config_path.clone(), config.clone())
            .expect("ingest state should build");
        let mut dispatcher = AgentDispatcher::new(
            AgentDispatcherConfig::default(),
            shutdown_rx,
            substrate.clone(),
            Arc::clone(&health_state),
        )
        .with_mode_state(Arc::new(arc_swap::ArcSwap::from_pointee(
            SwarmModeState::new(),
        )))
        .with_runtime_events(RuntimeEventBroadcaster::new(16));

        let identity_store =
            FileAgentKeyStore::open(resolve_agent_key_dir(&config_path, &config.identity))
                .expect("agent key store should open");
        let identity_registry = FileAgentIdentityRegistry::open(resolve_identity_registry_dir(
            &config_path,
            &config.identity,
        ))
        .expect("identity registry should open");
        let registered_id = register_optional_calico_agent(
            &mut dispatcher,
            &config_path,
            &config,
            &state,
            &identity_store,
            &identity_registry,
            swarm_runtime::runtime_events::now_ms(),
        )
        .expect("calico registration should succeed");
        let registered_id = registered_id.expect("calico should be registered");

        let summary = dispatcher.agent_health_summary();
        let first_id = summary
            .iter()
            .find(|entry| entry.role == AgentRole::Calico)
            .map(|entry| entry.id.clone())
            .expect("calico entry should exist");
        assert!(first_id.starts_with("swarm:ed25519:"));
        assert_eq!(first_id, registered_id.0);

        let _ = std::fs::remove_dir_all(root);
    }
}
