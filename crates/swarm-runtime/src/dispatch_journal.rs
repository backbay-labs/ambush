//! Durable consumption of a dispatch permission, before the external effect.
//!
//! A reservation permanently consumes the requester/action/hunt identity. An
//! absent completion means an unknown outcome, including after cancellation or
//! restart; it never permits retransmission. Completions are separate events.
//! This unsigned local authorization journal establishes one runtime dispatch;
//! adapters must separately prevent ambiguous retries of external requests.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use swarm_crypto::{canonical_json_bytes, sha256_hex};
use swarm_policy::{ActionRequest, CapabilityLease};
use swarm_response::{ResponseError, ResponseReceipt};

const VERSION: u32 = 1;
const MAX_CHECKPOINT_BYTES: u64 = 1024;
const MANIFEST_NAME: &str = "initialized";
const LOCK_NAME: &str = "writer.lock";
const JOURNAL_NAME: &str = "dispatch-journal.jsonl";
pub const MAX_DISPATCH_ENTRIES: usize = 100_000;
pub const MAX_DISPATCH_RECORD_BYTES: usize = 65_536;
pub const MAX_DISPATCH_JOURNAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 96;

#[derive(Debug, thiserror::Error)]
pub enum DispatchJournalError {
    #[error("dispatch journal I/O at `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("dispatch journal `{path}` already has a writer")]
    AlreadyOpen { path: PathBuf },
    #[error("corrupt dispatch journal: {0}")]
    Corrupt(String),
    #[error("dispatch `{dispatch_id}` was already reserved; retransmission is forbidden")]
    AlreadyReserved { dispatch_id: String },
    #[error("dispatch journal limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("dispatch journal is poisoned; reconcile its durable state")]
    Poisoned,
    #[error("dispatch `{0}` has no durable reservation")]
    UnknownDispatch(String),
    #[error("dispatch `{0}` already has a completion")]
    AlreadyCompleted(String),
    #[error("dispatch journal serialization failed: {0}")]
    Serialization(String),
}

impl DispatchJournalError {
    /// Whether existing dispatch permission is known to have been consumed.
    /// I/O errors and poison are uncertainty, not proof of a prior reservation.
    pub fn has_prior_reservation(&self) -> bool {
        matches!(
            self,
            Self::AlreadyReserved { .. } | Self::AlreadyCompleted(_)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchPhase {
    /// Permission was consumed; the external effect may or may not have occurred.
    OutcomeUnknown,
    /// An adapter result was returned and subsequently synced.
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchRecord {
    pub dispatch_id: String,
    pub request: ActionRequest,
    pub lease: CapabilityLease,
    pub reserved_at_ms: i64,
    pub completion: Option<Result<ResponseReceipt, ResponseError>>,
}

impl DispatchRecord {
    pub fn phase(&self) -> DispatchPhase {
        if self.completion.is_some() {
            DispatchPhase::Completed
        } else {
            DispatchPhase::OutcomeUnknown
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum JournalEvent {
    Header {
        version: u32,
    },
    Intent {
        dispatch_id: String,
        request: ActionRequest,
        lease: CapabilityLease,
        reserved_at_ms: i64,
    },
    Completion {
        dispatch_id: String,
        result: Result<ResponseReceipt, ResponseError>,
    },
}

#[derive(Debug)]
struct JournalState {
    file: File,
    records: BTreeMap<String, DispatchRecord>,
    bytes: u64,
    poisoned: bool,
    hasher: Sha256,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u32,
    bytes: u64,
    digest: String,
    writer_identity: String,
}

#[derive(Debug, Clone, Copy)]
struct JournalLimits {
    max_entries: usize,
    max_bytes: u64,
}

impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            max_entries: MAX_DISPATCH_ENTRIES,
            max_bytes: MAX_DISPATCH_JOURNAL_BYTES,
        }
    }
}

/// One writer holds an OS lock for this value's lifetime. Share it with `Arc`,
/// including across configuration reloads. No automatic eviction is safe.
/// Each append rehashes the bounded existing file in O(journal bytes) time to
/// reject live corruption, using an 8 KiB buffer rather than cloning the log.
#[derive(Debug)]
pub struct DispatchJournal {
    directory: PathBuf,
    journal_path: PathBuf,
    _writer_lock: File,
    state: Mutex<JournalState>,
    limits: JournalLimits,
}

impl DispatchJournal {
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, DispatchJournalError> {
        Self::open_with_directory_sync(directory, sync_directory)
    }

    fn open_with_directory_sync(
        directory: impl AsRef<Path>,
        mut sync: impl FnMut(&Path) -> Result<(), DispatchJournalError>,
    ) -> Result<Self, DispatchJournalError> {
        create_directory_durably(directory.as_ref())?;
        let directory =
            fs::canonicalize(directory.as_ref()).map_err(|e| io_error(directory.as_ref(), e))?;
        // Another opener may have created ANY component and paused before
        // syncing its parent. Existence cannot establish naming durability.
        // Every successful opener therefore syncs the canonical naming chain,
        // leaf through root, before it can publish dispatch permission.
        for ancestor in directory.ancestors() {
            sync(ancestor)?;
        }
        let lock_path = directory.join(LOCK_NAME);
        let (writer_lock, new_lock) = match new_private_file()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                require_regular_file(&lock_path)?;
                (
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&lock_path)
                        .map_err(|e| io_error(&lock_path, e))?,
                    false,
                )
            }
            Err(error) => return Err(io_error(&lock_path, error)),
        };
        match writer_lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(DispatchJournalError::AlreadyOpen { path: directory });
            }
            Err(TryLockError::Error(error)) => return Err(io_error(&lock_path, error)),
        }
        let journal_path = directory.join(JOURNAL_NAME);
        let manifest_path = directory.join(MANIFEST_NAME);
        if new_lock {
            if journal_path
                .try_exists()
                .map_err(|e| io_error(&journal_path, e))?
                || manifest_path
                    .try_exists()
                    .map_err(|e| io_error(&manifest_path, e))?
            {
                return Err(DispatchJournalError::Corrupt(
                    "writer lock missing from an existing journal".into(),
                ));
            }
            let header = serialize_event(&JournalEvent::Header { version: VERSION })?;
            let mut file = new_private_file()
                .write(true)
                .create_new(true)
                .open(&journal_path)
                .map_err(|e| io_error(&journal_path, e))?;
            file.write_all(&header)
                .map_err(|e| io_error(&journal_path, e))?;
            file.sync_all().map_err(|e| io_error(&journal_path, e))?;
            writer_lock
                .sync_all()
                .map_err(|e| io_error(&lock_path, e))?;
            sync_directory(&directory)?;
            let mut hasher = Sha256::new();
            hasher.update(&header);
            write_checkpoint(
                &directory,
                &Checkpoint {
                    version: VERSION,
                    bytes: header.len() as u64,
                    digest: hex::encode(hasher.finalize()),
                    writer_identity: file_identity(&writer_lock, &lock_path)?,
                },
            )?;
        }
        let checkpoint = read_checkpoint(&directory)?;
        validate_writer(&directory, &writer_lock, &checkpoint)?;
        require_regular_file(&journal_path)?;
        let (records, bytes, hasher) = read_records(&journal_path)?;
        validate_checkpoint(&checkpoint, bytes, &hasher)?;
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&journal_path)
            .map_err(|e| io_error(&journal_path, e))?;
        Ok(Self {
            directory,
            journal_path,
            _writer_lock: writer_lock,
            state: Mutex::new(JournalState {
                file,
                records,
                bytes,
                poisoned: false,
                hasher,
            }),
            limits: JournalLimits::default(),
        })
    }

    /// Sync the reservation before its permission can reach the executor.
    /// Existing reservations are refused regardless of their recorded outcome.
    pub(crate) fn reserve(
        &self,
        request: &ActionRequest,
        lease: &CapabilityLease,
        now_ms: i64,
    ) -> Result<String, DispatchJournalError> {
        validate_json_depth(&request.evidence)?;
        let dispatch_id = request_id(request)?;
        // Bound serialization before cloning potentially large evidence or leases.
        serialize_bounded(request)?;
        serialize_bounded(lease)?;
        let mut state = self.lock()?;
        // INVARIANT: RuntimeDispatchIdentityConsumedOnce
        if state.records.contains_key(&dispatch_id) {
            return Err(DispatchJournalError::AlreadyReserved { dispatch_id });
        }
        if state.records.len() >= self.limits.max_entries {
            return Err(DispatchJournalError::LimitExceeded("dispatch entry count"));
        }
        if lease.action != request.action.kind() || lease.expires_at_ms <= now_ms {
            return Err(DispatchJournalError::Corrupt(
                "reservation requires an active lease for this action".into(),
            ));
        }
        let event = JournalEvent::Intent {
            dispatch_id: dispatch_id.clone(),
            request: request.clone(),
            lease: lease.clone(),
            reserved_at_ms: now_ms,
        };
        self.append(&mut state, &event)?;
        state.records.insert(
            dispatch_id.clone(),
            DispatchRecord {
                dispatch_id: dispatch_id.clone(),
                request: request.clone(),
                lease: lease.clone(),
                reserved_at_ms: now_ms,
                completion: None,
            },
        );
        Ok(dispatch_id)
    }

    pub(crate) fn complete(
        &self,
        dispatch_id: &str,
        result: &Result<ResponseReceipt, ResponseError>,
    ) -> Result<(), DispatchJournalError> {
        let mut state = self.lock()?;
        let record = state
            .records
            .get(dispatch_id)
            .ok_or_else(|| DispatchJournalError::UnknownDispatch(dispatch_id.into()))?;
        if record.completion.is_some() {
            return Err(DispatchJournalError::AlreadyCompleted(dispatch_id.into()));
        }
        match result {
            Ok(receipt) => {
                validate_json_depth(&receipt.details)?;
                if let Some(value) = receipt
                    .audit
                    .governance
                    .as_ref()
                    .and_then(|governance| governance.receipt.as_ref())
                {
                    validate_json_depth(value)?;
                }
            }
            Err(error) => validate_json_depth(&error.failure.details)?,
        }
        serialize_bounded(result)?;
        let event = JournalEvent::Completion {
            dispatch_id: dispatch_id.into(),
            result: result.clone(),
        };
        self.append(&mut state, &event)?;
        if let Some(record) = state.records.get_mut(dispatch_id) {
            record.completion = Some(result.clone());
        }
        Ok(())
    }

    pub fn lookup(
        &self,
        dispatch_id: &str,
    ) -> Result<Option<DispatchRecord>, DispatchJournalError> {
        Ok(self.lock()?.records.get(dispatch_id).cloned())
    }

    /// Reparse disk independently of the in-memory cache, under the writer mutex.
    pub fn lookup_persisted(
        &self,
        dispatch_id: &str,
    ) -> Result<Option<DispatchRecord>, DispatchJournalError> {
        let mut state = self.lock()?;
        let result = self
            .validate_files(&state)
            .and_then(|()| read_records(&self.journal_path))
            .and_then(|(records, bytes, hasher)| {
                validate_checkpoint(&read_checkpoint(&self.directory)?, bytes, &hasher)?;
                Ok(records.get(dispatch_id).cloned())
            });
        if result.is_err() {
            state.poisoned = true;
        }
        result
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }
    pub fn request_id(request: &ActionRequest) -> Result<String, DispatchJournalError> {
        request_id(request)
    }

    fn lock(&self) -> Result<MutexGuard<'_, JournalState>, DispatchJournalError> {
        let state = self
            .state
            .lock()
            .map_err(|_| DispatchJournalError::Poisoned)?;
        if state.poisoned {
            return Err(DispatchJournalError::Poisoned);
        }
        Ok(state)
    }

    fn validate_files(&self, state: &JournalState) -> Result<(), DispatchJournalError> {
        let checkpoint = read_checkpoint(&self.directory)?;
        validate_writer(&self.directory, &self._writer_lock, &checkpoint)?;
        validate_checkpoint(&checkpoint, state.bytes, &state.hasher)?;
        require_regular_file(&self.journal_path)?;
        let disk = fs::metadata(&self.journal_path).map_err(|e| io_error(&self.journal_path, e))?;
        let open = state
            .file
            .metadata()
            .map_err(|e| io_error(&self.journal_path, e))?;
        if disk.len() != state.bytes || open.len() != state.bytes {
            return Err(DispatchJournalError::Corrupt(
                "journal changed outside its writer".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if disk.dev() != open.dev() || disk.ino() != open.ino() {
                return Err(DispatchJournalError::Corrupt(
                    "journal file was replaced".into(),
                ));
            }
        }
        // A length/inode check alone misses in-place corruption. Read in fixed
        // chunks so every returned permission still has a replay-valid prefix.
        let mut file =
            File::open(&self.journal_path).map_err(|e| io_error(&self.journal_path, e))?;
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|e| io_error(&self.journal_path, e))?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > state.bytes {
                return Err(DispatchJournalError::Corrupt(
                    "journal grew outside its writer".into(),
                ));
            }
            digest.update(&buffer[..count]);
        }
        validate_checkpoint(&checkpoint, total, &digest)
    }

    fn append(
        &self,
        state: &mut JournalState,
        event: &JournalEvent,
    ) -> Result<(), DispatchJournalError> {
        let bytes = serialize_event(event)?;
        if state.bytes.saturating_add(bytes.len() as u64) > self.limits.max_bytes {
            return Err(DispatchJournalError::LimitExceeded("journal byte count"));
        }
        // A returned write error cannot establish zero bytes reached disk. Even
        // a successful append followed by a sync failure must poison the writer.
        let mut next_hasher = state.hasher.clone();
        next_hasher.update(&bytes);
        let result = self.validate_files(state).and_then(|()| {
            state
                .file
                .write_all(&bytes)
                .map_err(|e| io_error(&self.journal_path, e))?;
            state
                .file
                .sync_all()
                .map_err(|e| io_error(&self.journal_path, e))?;
            write_checkpoint(
                &self.directory,
                &Checkpoint {
                    version: VERSION,
                    bytes: state.bytes + bytes.len() as u64,
                    digest: hex::encode(next_hasher.clone().finalize()),
                    writer_identity: file_identity(
                        &self._writer_lock,
                        &self.directory.join(LOCK_NAME),
                    )?,
                },
            )
        });
        if let Err(error) = result {
            state.poisoned = true;
            return Err(error);
        }
        state.bytes += bytes.len() as u64;
        state.hasher = next_hasher;
        Ok(())
    }
}

/// Once per complete action/requester/hunt: changes to evidence, severity,
/// lease, or time cannot manufacture a new identity for the same operation.
pub fn request_id(request: &ActionRequest) -> Result<String, DispatchJournalError> {
    #[derive(Serialize)]
    struct Identity<'a> {
        hunt_id: &'a swarm_core::types::HuntId,
        requested_by: &'a swarm_core::types::AgentId,
        action: &'a swarm_core::types::ResponseAction,
    }
    let identity = Identity {
        hunt_id: &request.hunt_id,
        requested_by: &request.requested_by,
        action: &request.action,
    };
    serialize_bounded(&identity)?;
    let body = canonical_json_bytes(&identity)
        .map_err(|e| DispatchJournalError::Serialization(e.to_string()))?;
    let mut preimage = b"ambush.dispatch-intent.v1\0".to_vec();
    preimage.extend_from_slice(&body);
    Ok(format!("dispatch:{}", sha256_hex(&preimage)))
}

fn serialize_event(event: &JournalEvent) -> Result<Vec<u8>, DispatchJournalError> {
    let mut bytes = serialize_bounded(event)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_DISPATCH_RECORD_BYTES {
        return Err(DispatchJournalError::LimitExceeded("record byte count"));
    }
    // serde_json can serialize deeper values than its default decoder accepts.
    // Validate the exact event envelope before consuming dispatch permission.
    let _: JournalEvent = serde_json::from_slice(&bytes).map_err(|e| {
        DispatchJournalError::Serialization(format!("event cannot be recovered: {e}"))
    })?;
    Ok(bytes)
}

type LoadedRecords = (BTreeMap<String, DispatchRecord>, u64, Sha256);

fn read_records(path: &Path) -> Result<LoadedRecords, DispatchJournalError> {
    let file = File::open(path).map_err(|e| io_error(path, e))?;
    let expected_bytes = file.metadata().map_err(|e| io_error(path, e))?.len();
    if expected_bytes > MAX_DISPATCH_JOURNAL_BYTES {
        return Err(DispatchJournalError::LimitExceeded("journal byte count"));
    }
    let mut reader = BufReader::new(file);
    let mut records = BTreeMap::<String, DispatchRecord>::new();
    let mut read_bytes = 0_u64;
    let mut hasher = Sha256::new();
    let mut line_number = 0_usize;
    loop {
        let mut line = Vec::new();
        let count = Read::by_ref(&mut reader)
            .take((MAX_DISPATCH_RECORD_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|e| io_error(path, e))?;
        if count == 0 {
            break;
        }
        line_number += 1;
        if count > MAX_DISPATCH_RECORD_BYTES {
            return Err(DispatchJournalError::LimitExceeded("record byte count"));
        }
        if line.last() != Some(&b'\n') {
            return Err(DispatchJournalError::Corrupt(format!(
                "truncated record at line {line_number}"
            )));
        }
        read_bytes += count as u64;
        if read_bytes > MAX_DISPATCH_JOURNAL_BYTES {
            return Err(DispatchJournalError::LimitExceeded("journal byte count"));
        }
        hasher.update(&line);
        let event: JournalEvent = serde_json::from_slice(&line)
            .map_err(|e| DispatchJournalError::Corrupt(format!("line {line_number}: {e}")))?;
        if line_number == 1 {
            if !matches!(event, JournalEvent::Header { version: VERSION }) {
                return Err(DispatchJournalError::Corrupt(
                    "missing or unsupported journal header".into(),
                ));
            }
            continue;
        }
        match event {
            JournalEvent::Header { .. } => {
                return Err(DispatchJournalError::Corrupt(
                    "duplicate journal header".into(),
                ));
            }
            JournalEvent::Intent {
                dispatch_id,
                request,
                lease,
                reserved_at_ms,
            } => {
                if request_id(&request)? != dispatch_id || records.contains_key(&dispatch_id) {
                    return Err(DispatchJournalError::Corrupt(
                        "mismatched or duplicate intent identity".into(),
                    ));
                }
                if lease.action != request.action.kind() || lease.expires_at_ms <= reserved_at_ms {
                    return Err(DispatchJournalError::Corrupt(
                        "intent has invalid action authorization".into(),
                    ));
                }
                if records.len() >= MAX_DISPATCH_ENTRIES {
                    return Err(DispatchJournalError::LimitExceeded("dispatch entry count"));
                }
                records.insert(
                    dispatch_id.clone(),
                    DispatchRecord {
                        dispatch_id,
                        request,
                        lease,
                        reserved_at_ms,
                        completion: None,
                    },
                );
            }
            JournalEvent::Completion {
                dispatch_id,
                result,
            } => {
                let record = records.get_mut(&dispatch_id).ok_or_else(|| {
                    DispatchJournalError::Corrupt("completion without intent".into())
                })?;
                if record.completion.replace(result).is_some() {
                    return Err(DispatchJournalError::Corrupt("duplicate completion".into()));
                }
            }
        }
    }
    if line_number == 0 || read_bytes != expected_bytes {
        return Err(DispatchJournalError::Corrupt(
            "empty or concurrently changed journal".into(),
        ));
    }
    Ok((records, read_bytes, hasher))
}

fn io_error(path: &Path, source: std::io::Error) -> DispatchJournalError {
    DispatchJournalError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn require_regular_file(path: &Path) -> Result<(), DispatchJournalError> {
    let metadata = fs::symlink_metadata(path).map_err(|e| io_error(path, e))?;
    if !metadata.file_type().is_file() {
        return Err(DispatchJournalError::Corrupt(format!(
            "`{}` is not a regular file",
            path.display()
        )));
    }
    Ok(())
}

fn read_checkpoint(directory: &Path) -> Result<Checkpoint, DispatchJournalError> {
    let path = directory.join(MANIFEST_NAME);
    if path
        .with_extension("tmp")
        .try_exists()
        .map_err(|e| io_error(&path, e))?
    {
        return Err(DispatchJournalError::Corrupt(
            "interrupted checkpoint update".into(),
        ));
    }
    require_regular_file(&path)?;
    let mut bytes = Vec::new();
    File::open(&path)
        .map_err(|e| io_error(&path, e))?
        .take(MAX_CHECKPOINT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error(&path, e))?;
    if bytes.len() as u64 > MAX_CHECKPOINT_BYTES {
        return Err(DispatchJournalError::Corrupt("oversized checkpoint".into()));
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| DispatchJournalError::Corrupt(format!("invalid checkpoint: {e}")))
}

fn write_checkpoint(directory: &Path, checkpoint: &Checkpoint) -> Result<(), DispatchJournalError> {
    let path = directory.join(MANIFEST_NAME);
    let temporary = path.with_extension("tmp");
    let bytes = serialize_bounded(checkpoint)?;
    let mut file = new_private_file()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|e| io_error(&temporary, e))?;
    file.write_all(&bytes)
        .map_err(|e| io_error(&temporary, e))?;
    file.sync_all().map_err(|e| io_error(&temporary, e))?;
    fs::rename(&temporary, &path).map_err(|e| io_error(&path, e))?;
    sync_directory(directory)
}

fn validate_checkpoint(
    checkpoint: &Checkpoint,
    bytes: u64,
    hasher: &Sha256,
) -> Result<(), DispatchJournalError> {
    if checkpoint.version != VERSION
        || checkpoint.bytes != bytes
        || checkpoint.digest != hex::encode(hasher.clone().finalize())
    {
        return Err(DispatchJournalError::Corrupt(
            "journal differs from durable checkpoint".into(),
        ));
    }
    Ok(())
}

fn validate_writer(
    directory: &Path,
    file: &File,
    checkpoint: &Checkpoint,
) -> Result<(), DispatchJournalError> {
    let path = directory.join(LOCK_NAME);
    require_regular_file(&path)?;
    let named = fs::metadata(&path).map_err(|e| io_error(&path, e))?;
    if checkpoint.writer_identity != file_identity(file, &path)?
        || checkpoint.writer_identity != metadata_identity(&named)?
    {
        return Err(DispatchJournalError::Corrupt(
            "writer lock was replaced".into(),
        ));
    }
    Ok(())
}

fn file_identity(file: &File, path: &Path) -> Result<String, DispatchJournalError> {
    metadata_identity(&file.metadata().map_err(|e| io_error(path, e))?)
}

fn metadata_identity(metadata: &fs::Metadata) -> Result<String, DispatchJournalError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(format!("{}:{}", metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(DispatchJournalError::Corrupt(
            "durable dispatch journal requires Unix file identity".into(),
        ))
    }
}

fn new_private_file() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn validate_json_depth(value: &serde_json::Value) -> Result<(), DispatchJournalError> {
    let mut pending = vec![(0_usize, value)];
    let mut visited = 0_usize;
    while let Some((depth, value)) = pending.pop() {
        if depth > MAX_JSON_DEPTH {
            return Err(DispatchJournalError::Serialization(
                "JSON nesting exceeds recoverable depth".into(),
            ));
        }
        visited += 1;
        let children = match value {
            serde_json::Value::Array(values) => values.len(),
            serde_json::Value::Object(values) => values.len(),
            _ => 0,
        };
        if visited
            .saturating_add(pending.len())
            .saturating_add(children)
            > MAX_DISPATCH_RECORD_BYTES
        {
            return Err(DispatchJournalError::LimitExceeded("JSON node count"));
        }
        match value {
            serde_json::Value::Array(values) => {
                pending.extend(values.iter().map(|value| (depth + 1, value)))
            }
            serde_json::Value::Object(values) => {
                pending.extend(values.values().map(|value| (depth + 1, value)))
            }
            _ => {}
        }
    }
    Ok(())
}

fn serialize_bounded(value: &impl Serialize) -> Result<Vec<u8>, DispatchJournalError> {
    struct BoundedWriter {
        bytes: Vec<u8>,
        exceeded: bool,
    }
    impl Write for BoundedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.bytes.len().saturating_add(bytes.len()) >= MAX_DISPATCH_RECORD_BYTES {
                self.exceeded = true;
                return Err(std::io::Error::other("record byte limit"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut writer, value);
    if writer.exceeded {
        return Err(DispatchJournalError::LimitExceeded("record byte count"));
    }
    result.map_err(|e| DispatchJournalError::Serialization(e.to_string()))?;
    Ok(writer.bytes)
}

fn sync_directory(path: &Path) -> Result<(), DispatchJournalError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| io_error(path, e))
}

fn create_directory_durably(path: &Path) -> Result<(), DispatchJournalError> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(DispatchJournalError::Corrupt(format!(
                "`{}` is not a directory",
                path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(path, error)),
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    create_directory_durably(parent)?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(path)
                .map_err(|e| io_error(path, e))?
                .is_dir()
            {
                return Err(DispatchJournalError::Corrupt(
                    "journal directory changed during creation".into(),
                ));
            }
        }
        Err(error) => return Err(io_error(path, error)),
    }
    sync_directory(parent)
}

#[cfg(test)]
#[path = "dispatch_journal_tests.rs"]
mod tests;
