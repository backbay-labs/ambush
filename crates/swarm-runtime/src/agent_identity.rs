use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use swarm_core::agent::AgentRole;
use swarm_core::config::IdentityConfig;
use swarm_core::types::AgentId;
use swarm_crypto::{canonical_json_bytes, sha256_hex};

#[derive(Debug, thiserror::Error)]
pub enum AgentIdentityError {
    #[error("failed to create agent key directory `{path}`: {source}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to durably sync agent key root parent `{path}`: {source}")]
    SyncKeyRootParent {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read agent key `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write agent key `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid agent key `{path}`: {reason}")]
    InvalidKey { path: PathBuf, reason: String },

    #[error("failed to read identity registry `{path}`: {source}")]
    ReadRegistry {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write identity registry `{path}`: {source}")]
    WriteRegistry {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse identity registry `{path}`: {source}")]
    ParseRegistry {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to encode continuity payload: {0}")]
    EncodeContinuity(#[from] swarm_crypto::CryptoError),

    #[error("identity mismatch for {role:?}/{slot}: expected `{expected}`, got `{actual}`")]
    IdentityMismatch {
        role: AgentRole,
        slot: String,
        expected: String,
        actual: String,
    },

    #[error(
        "identity mismatch for persisted key {role:?}/{slot}: derived `{derived}` but record uses `{recorded}`"
    )]
    DerivedIdentityMismatch {
        role: AgentRole,
        slot: String,
        derived: String,
        recorded: String,
    },

    #[error("unregistered identity `{agent_id}` for {role:?}/{slot}")]
    UnregisteredIdentity {
        role: AgentRole,
        slot: String,
        agent_id: String,
    },

    #[error("no active identity registered for {role:?}/{slot}")]
    MissingActiveIdentity { role: AgentRole, slot: String },

    #[error("invalid continuity proof `{proof_id}`: {reason}")]
    InvalidContinuityProof { proof_id: String, reason: String },
}

#[derive(Debug, Clone)]
pub struct PersistedAgentIdentity {
    pub id: AgentId,
    pub signing_key: SigningKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentKeyLoadStatus {
    Created,
    Loaded,
}

impl PersistedAgentIdentity {
    fn from_signing_key(signing_key: SigningKey) -> Self {
        let id = AgentId::from_verifying_key(&signing_key.verifying_key());
        Self { id, signing_key }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryAdmission {
    Added,
    Refreshed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveAgentIdentityRecord {
    pub role: AgentRole,
    pub slot: String,
    pub agent_id: AgentId,
    pub public_key_hex: String,
    pub admitted_at_ms: i64,
    pub last_seen_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredAgentIdentityRecord {
    pub role: AgentRole,
    pub slot: String,
    pub agent_id: AgentId,
    pub public_key_hex: String,
    pub retired_at_ms: i64,
    pub active_until_ms: i64,
    pub continuity_proof_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentityContinuityPayload {
    pub schema_version: u32,
    pub role: AgentRole,
    pub slot: String,
    pub previous_agent_id: AgentId,
    pub next_agent_id: AgentId,
    pub previous_public_key_hex: String,
    pub next_public_key_hex: String,
    pub signed_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentityContinuityProof {
    pub proof_id: String,
    pub payload: AgentIdentityContinuityPayload,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AgentIdentityRegistrySnapshot {
    #[serde(default)]
    pub active: Vec<ActiveAgentIdentityRecord>,
    #[serde(default)]
    pub retired: Vec<RetiredAgentIdentityRecord>,
    #[serde(default)]
    pub continuity_proofs: Vec<AgentIdentityContinuityProof>,
}

#[derive(Debug, Clone)]
pub struct IdentityRotationOutcome {
    pub previous_agent_id: AgentId,
    pub next_identity: PersistedAgentIdentity,
    pub proof: AgentIdentityContinuityProof,
}

pub struct FileAgentKeyStore {
    root: PathBuf,
}

impl FileAgentKeyStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, AgentIdentityError> {
        Self::open_with_parent_sync(root, |parent| {
            fs::File::open(parent).and_then(|directory| directory.sync_all())
        })
    }

    fn open_with_parent_sync<ParentSync>(
        root: impl AsRef<Path>,
        mut sync_parent: ParentSync,
    ) -> Result<Self, AgentIdentityError>
    where
        ParentSync: FnMut(&Path) -> std::io::Result<()>,
    {
        let root = root.as_ref().to_path_buf();
        let missing = missing_key_root_directories(&root)?;
        let mut created = Vec::with_capacity(missing.len());
        for directory in missing.iter().rev() {
            match fs::create_dir(directory) {
                Ok(()) => created.push(directory.clone()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let metadata = fs::symlink_metadata(directory).map_err(|source| {
                        AgentIdentityError::CreateDir {
                            path: directory.clone(),
                            source,
                        }
                    })?;
                    if !metadata.file_type().is_dir() {
                        best_effort_remove_empty_key_directories(&created);
                        return Err(AgentIdentityError::CreateDir {
                            path: directory.clone(),
                            source: std::io::Error::new(
                                std::io::ErrorKind::AlreadyExists,
                                "key-store path component is not a directory",
                            ),
                        });
                    }
                }
                Err(source) => {
                    best_effort_remove_empty_key_directories(&created);
                    return Err(AgentIdentityError::CreateDir {
                        path: directory.clone(),
                        source,
                    });
                }
            }
        }
        for directory in created.iter().rev() {
            let parent =
                normalized_parent(directory).ok_or_else(|| AgentIdentityError::CreateDir {
                    path: directory.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "new key-store directory has no existing parent anchor",
                    ),
                })?;
            if let Err(source) = sync_parent(&parent) {
                best_effort_remove_empty_key_directories(&created);
                return Err(AgentIdentityError::SyncKeyRootParent {
                    path: parent,
                    source,
                });
            }
        }
        Ok(Self { root })
    }

    pub fn load_or_create(
        &self,
        role: AgentRole,
        slot: &str,
    ) -> Result<PersistedAgentIdentity, AgentIdentityError> {
        self.load_or_create_with_status(role, slot)
            .map(|(identity, _status)| identity)
    }

    /// Load a stable role/slot key, reporting whether this call created it.
    ///
    /// Security-sensitive bootstrap code must not infer first initialization from
    /// a mutable identity-registry row. A key that already existed before this call
    /// is an existing installation even if its registry entry was deleted.
    pub fn load_or_create_with_status(
        &self,
        role: AgentRole,
        slot: &str,
    ) -> Result<(PersistedAgentIdentity, AgentKeyLoadStatus), AgentIdentityError> {
        let path = self.key_path(role, slot);
        match fs::read(&path) {
            Ok(bytes) => Self::decode_key(&path, &bytes)
                .map(|identity| (identity, AgentKeyLoadStatus::Loaded)),
            Err(source) if source.kind() == ErrorKind::NotFound => {
                let signing_key = SigningKey::generate(&mut OsRng);
                if self.write_new_key(&path, &signing_key)? {
                    Ok((
                        PersistedAgentIdentity::from_signing_key(signing_key),
                        AgentKeyLoadStatus::Created,
                    ))
                } else {
                    let bytes = fs::read(&path).map_err(|source| AgentIdentityError::Read {
                        path: path.clone(),
                        source,
                    })?;
                    Self::decode_key(&path, &bytes)
                        .map(|identity| (identity, AgentKeyLoadStatus::Loaded))
                }
            }
            Err(source) => Err(AgentIdentityError::Read { path, source }),
        }
    }

    pub fn replace(
        &self,
        role: AgentRole,
        slot: &str,
        signing_key: &SigningKey,
    ) -> Result<PersistedAgentIdentity, AgentIdentityError> {
        let path = self.key_path(role, slot);
        write_bytes_atomic(&path, &signing_key.to_bytes()).map_err(|source| {
            AgentIdentityError::Write {
                path: path.clone(),
                source,
            }
        })?;
        Ok(PersistedAgentIdentity::from_signing_key(
            signing_key.clone(),
        ))
    }

    fn key_path(&self, role: AgentRole, slot: &str) -> PathBuf {
        self.root.join(format!(
            "{}-{}.ed25519",
            role_slug(role),
            sanitize_slot(slot)
        ))
    }

    fn decode_key(path: &Path, bytes: &[u8]) -> Result<PersistedAgentIdentity, AgentIdentityError> {
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AgentIdentityError::InvalidKey {
                path: path.to_path_buf(),
                reason: format!("expected 32 raw seed bytes, got {}", bytes.len()),
            })?;
        Ok(PersistedAgentIdentity::from_signing_key(
            SigningKey::from_bytes(&seed),
        ))
    }

    fn write_new_key(
        &self,
        path: &Path,
        signing_key: &SigningKey,
    ) -> Result<bool, AgentIdentityError> {
        self.write_new_key_with_sync(path, signing_key, fs::File::sync_all, |parent| {
            fs::File::open(parent).and_then(|directory| directory.sync_all())
        })
    }

    fn write_new_key_with_sync<FileSync, ParentSync>(
        &self,
        path: &Path,
        signing_key: &SigningKey,
        sync_file: FileSync,
        sync_parent: ParentSync,
    ) -> Result<bool, AgentIdentityError>
    where
        FileSync: FnOnce(&fs::File) -> std::io::Result<()>,
        ParentSync: FnOnce(&Path) -> std::io::Result<()>,
    {
        use std::fs::OpenOptions;
        use std::io::Write;

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(source) if source.kind() == ErrorKind::AlreadyExists => return Ok(false),
            Err(source) => {
                return Err(AgentIdentityError::Write {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        file.write_all(&signing_key.to_bytes())
            .and_then(|()| sync_file(&file))
            .map_err(|source| AgentIdentityError::Write {
                path: path.to_path_buf(),
                source,
            })?;
        if let Some(parent) = path.parent() {
            sync_parent(parent).map_err(|source| AgentIdentityError::Write {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        Ok(true)
    }
}

fn missing_key_root_directories(root: &Path) -> Result<Vec<PathBuf>, AgentIdentityError> {
    let mut missing = Vec::new();
    let mut current = root.to_path_buf();
    loop {
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => return Ok(missing),
            Ok(_) => {
                return Err(AgentIdentityError::CreateDir {
                    path: current,
                    source: std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "key-store path component is not a directory",
                    ),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(current.clone());
                current =
                    normalized_parent(&current).ok_or_else(|| AgentIdentityError::CreateDir {
                        path: root.to_path_buf(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "key-store path has no existing directory anchor",
                        ),
                    })?;
            }
            Err(source) => {
                return Err(AgentIdentityError::CreateDir {
                    path: current,
                    source,
                });
            }
        }
    }
}

fn normalized_parent(path: &Path) -> Option<PathBuf> {
    path.parent().map(|parent| {
        if parent.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            parent.to_path_buf()
        }
    })
}

fn best_effort_remove_empty_key_directories(created_shallow_to_deep: &[PathBuf]) {
    for directory in created_shallow_to_deep.iter().rev() {
        let _ = fs::remove_dir(directory);
    }
}

pub struct FileAgentIdentityRegistry {
    registry_path: PathBuf,
}

impl FileAgentIdentityRegistry {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, AgentIdentityError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|source| AgentIdentityError::CreateDir {
            path: root.clone(),
            source,
        })?;
        let registry_path = root.join("registry.json");
        Ok(Self { registry_path })
    }

    pub fn snapshot(&self) -> Result<AgentIdentityRegistrySnapshot, AgentIdentityError> {
        self.load_snapshot()
    }

    pub fn admitted_agent_ids(&self) -> Result<Vec<AgentId>, AgentIdentityError> {
        Ok(self
            .load_snapshot()?
            .active
            .into_iter()
            .map(|entry| entry.agent_id)
            .collect())
    }

    pub fn admit_persisted_identity(
        &self,
        role: AgentRole,
        slot: &str,
        identity: &PersistedAgentIdentity,
        now_ms: i64,
    ) -> Result<RegistryAdmission, AgentIdentityError> {
        let slot = sanitize_slot(slot);
        let derived_identity =
            PersistedAgentIdentity::from_signing_key(identity.signing_key.clone());
        if derived_identity.id != identity.id {
            return Err(AgentIdentityError::DerivedIdentityMismatch {
                role,
                slot,
                derived: derived_identity.id.0,
                recorded: identity.id.0.clone(),
            });
        }

        let public_key_hex = hex::encode(identity.signing_key.verifying_key().to_bytes());
        let mut snapshot = self.load_snapshot()?;
        if let Some(existing) = snapshot
            .active
            .iter_mut()
            .find(|entry| entry.role == role && entry.slot == slot)
        {
            if existing.agent_id != identity.id {
                return Err(AgentIdentityError::UnregisteredIdentity {
                    role,
                    slot,
                    agent_id: identity.id.0.clone(),
                });
            }
            existing.last_seen_at_ms = now_ms;
            existing.public_key_hex = public_key_hex;
            self.persist_snapshot(&snapshot)?;
            return Ok(RegistryAdmission::Refreshed);
        }

        snapshot.active.push(ActiveAgentIdentityRecord {
            role,
            slot,
            agent_id: identity.id.clone(),
            public_key_hex,
            admitted_at_ms: now_ms,
            last_seen_at_ms: now_ms,
        });
        snapshot.active.sort_by(|left, right| {
            registry_key(left.role, &left.slot).cmp(&registry_key(right.role, &right.slot))
        });
        self.persist_snapshot(&snapshot)?;
        Ok(RegistryAdmission::Added)
    }

    pub fn is_admitted(&self, agent_id: &AgentId) -> Result<bool, AgentIdentityError> {
        Ok(self
            .load_snapshot()?
            .active
            .iter()
            .any(|entry| &entry.agent_id == agent_id))
    }

    pub fn rotate_identity(
        &self,
        key_store: &FileAgentKeyStore,
        role: AgentRole,
        slot: &str,
        active_until_ms: i64,
        now_ms: i64,
    ) -> Result<IdentityRotationOutcome, AgentIdentityError> {
        let slot = sanitize_slot(slot);
        let current_identity = key_store.load_or_create(role, &slot)?;
        let current_public_key_hex =
            hex::encode(current_identity.signing_key.verifying_key().to_bytes());
        let mut snapshot = self.load_snapshot()?;
        let Some(active_index) = snapshot
            .active
            .iter()
            .position(|entry| entry.role == role && entry.slot == slot)
        else {
            return Err(AgentIdentityError::MissingActiveIdentity { role, slot });
        };

        let active_record = snapshot.active[active_index].clone();
        if active_record.agent_id != current_identity.id {
            return Err(AgentIdentityError::UnregisteredIdentity {
                role,
                slot: active_record.slot,
                agent_id: current_identity.id.0,
            });
        }

        let next_signing_key = SigningKey::generate(&mut OsRng);
        let next_identity = PersistedAgentIdentity::from_signing_key(next_signing_key.clone());
        let next_public_key_hex = hex::encode(next_signing_key.verifying_key().to_bytes());
        let payload = AgentIdentityContinuityPayload {
            schema_version: 1,
            role,
            slot: active_record.slot.clone(),
            previous_agent_id: current_identity.id.clone(),
            next_agent_id: next_identity.id.clone(),
            previous_public_key_hex: current_public_key_hex.clone(),
            next_public_key_hex: next_public_key_hex.clone(),
            signed_at_ms: now_ms,
        };
        let payload_bytes = canonical_json_bytes(&payload)?;
        let signature = current_identity.signing_key.sign(&payload_bytes);
        let proof = AgentIdentityContinuityProof {
            proof_id: sha256_hex(&payload_bytes),
            payload,
            signature_hex: hex::encode(signature.to_bytes()),
        };
        verify_continuity_proof(&proof)?;

        let next_identity = key_store.replace(role, &active_record.slot, &next_signing_key)?;
        snapshot.active[active_index] = ActiveAgentIdentityRecord {
            role,
            slot: active_record.slot.clone(),
            agent_id: next_identity.id.clone(),
            public_key_hex: next_public_key_hex,
            admitted_at_ms: now_ms,
            last_seen_at_ms: now_ms,
        };
        snapshot.retired.push(RetiredAgentIdentityRecord {
            role,
            slot: active_record.slot.clone(),
            agent_id: active_record.agent_id.clone(),
            public_key_hex: active_record.public_key_hex.clone(),
            retired_at_ms: now_ms,
            active_until_ms,
            continuity_proof_id: proof.proof_id.clone(),
        });
        snapshot.continuity_proofs.push(proof.clone());
        snapshot.retired.sort_by_key(|entry| entry.retired_at_ms);
        snapshot
            .continuity_proofs
            .sort_by_key(|entry| entry.payload.signed_at_ms);
        self.persist_snapshot(&snapshot)?;

        Ok(IdentityRotationOutcome {
            previous_agent_id: active_record.agent_id,
            next_identity,
            proof,
        })
    }

    fn load_snapshot(&self) -> Result<AgentIdentityRegistrySnapshot, AgentIdentityError> {
        match fs::read(&self.registry_path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|source| AgentIdentityError::ParseRegistry {
                    path: self.registry_path.clone(),
                    source,
                })
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {
                Ok(AgentIdentityRegistrySnapshot::default())
            }
            Err(source) => Err(AgentIdentityError::ReadRegistry {
                path: self.registry_path.clone(),
                source,
            }),
        }
    }

    fn persist_snapshot(
        &self,
        snapshot: &AgentIdentityRegistrySnapshot,
    ) -> Result<(), AgentIdentityError> {
        let bytes = serde_json::to_vec_pretty(snapshot).map_err(|source| {
            AgentIdentityError::ParseRegistry {
                path: self.registry_path.clone(),
                source,
            }
        })?;
        write_bytes_atomic(&self.registry_path, &bytes).map_err(|source| {
            AgentIdentityError::WriteRegistry {
                path: self.registry_path.clone(),
                source,
            }
        })
    }
}

pub fn resolve_agent_key_dir(config_path: &Path, identity: &IdentityConfig) -> PathBuf {
    let raw = Path::new(identity.agent_key_dir.trim());
    if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(raw)
    }
}

pub fn resolve_identity_registry_dir(config_path: &Path, identity: &IdentityConfig) -> PathBuf {
    let raw = Path::new(identity.registry_dir.trim());
    if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(raw)
    }
}

pub fn verify_continuity_proof(
    proof: &AgentIdentityContinuityProof,
) -> Result<(), AgentIdentityError> {
    let payload_bytes = canonical_json_bytes(&proof.payload)?;
    if sha256_hex(&payload_bytes) != proof.proof_id {
        return Err(AgentIdentityError::InvalidContinuityProof {
            proof_id: proof.proof_id.clone(),
            reason: "proof_id does not match canonical payload hash".to_string(),
        });
    }
    let public_key_bytes =
        hex::decode(&proof.payload.previous_public_key_hex).map_err(|error| {
            AgentIdentityError::InvalidContinuityProof {
                proof_id: proof.proof_id.clone(),
                reason: format!("invalid previous public key hex: {error}"),
            }
        })?;
    let public_key: [u8; 32] = public_key_bytes.as_slice().try_into().map_err(|_| {
        AgentIdentityError::InvalidContinuityProof {
            proof_id: proof.proof_id.clone(),
            reason: format!(
                "expected 32-byte previous public key, got {}",
                public_key_bytes.len()
            ),
        }
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|error| {
        AgentIdentityError::InvalidContinuityProof {
            proof_id: proof.proof_id.clone(),
            reason: format!("invalid previous public key: {error}"),
        }
    })?;
    let signature_bytes = hex::decode(&proof.signature_hex).map_err(|error| {
        AgentIdentityError::InvalidContinuityProof {
            proof_id: proof.proof_id.clone(),
            reason: format!("invalid signature hex: {error}"),
        }
    })?;
    let signature: [u8; 64] = signature_bytes.as_slice().try_into().map_err(|_| {
        AgentIdentityError::InvalidContinuityProof {
            proof_id: proof.proof_id.clone(),
            reason: format!("expected 64-byte signature, got {}", signature_bytes.len()),
        }
    })?;
    verifying_key
        .verify(&payload_bytes, &DalekSignature::from_bytes(&signature))
        .map_err(|error| AgentIdentityError::InvalidContinuityProof {
            proof_id: proof.proof_id.clone(),
            reason: format!("signature verification failed: {error}"),
        })
}

fn role_slug(role: AgentRole) -> &'static str {
    match role {
        AgentRole::Whisker => "whisker",
        AgentRole::Stalker => "stalker",
        AgentRole::Weaver => "weaver",
        AgentRole::Pouncer => "pounce",
        AgentRole::Tom => "tom",
        AgentRole::Kitten => "kitten",
        AgentRole::Sphinx => "sphinx",
        AgentRole::Calico => "calico",
    }
}

fn sanitize_slot(slot: &str) -> String {
    let sanitized = slot
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "primary".to_string()
    } else {
        sanitized
    }
}

fn registry_key(role: AgentRole, slot: &str) -> String {
    format!("{}:{slot}", role_slug(role))
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let temp_path = path.with_extension(format!(
        "{}.tmp-{}",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("identity"),
        std::process::id()
    ));
    fs::write(&temp_path, bytes)?;
    fs::rename(temp_path, path)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        AgentKeyLoadStatus, FileAgentIdentityRegistry, FileAgentKeyStore, RegistryAdmission,
        resolve_agent_key_dir, resolve_identity_registry_dir, verify_continuity_proof,
    };
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use std::fs;
    use std::path::PathBuf;
    use swarm_core::agent::AgentRole;
    use swarm_core::config::IdentityConfig;

    fn temp_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "swarm-agent-identity-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn key_store_reuses_same_identity_on_reload() {
        let root = temp_root("reuse");
        let first = FileAgentKeyStore::open(&root)
            .unwrap()
            .load_or_create(AgentRole::Whisker, "primary")
            .unwrap();
        let second = FileAgentKeyStore::open(&root)
            .unwrap()
            .load_or_create(AgentRole::Whisker, "primary")
            .unwrap();

        assert_eq!(first.id, second.id);
        assert_eq!(first.signing_key.to_bytes(), second.signing_key.to_bytes());
    }

    #[test]
    fn key_store_open_retries_parent_sync_before_creating_one_key() {
        let parent = temp_root("open-parent-sync");
        let root = parent.join("keys");
        let Err(error) = FileAgentKeyStore::open_with_parent_sync(&root, |_| {
            Err(std::io::Error::other(
                "injected key-root parent sync failure",
            ))
        }) else {
            panic!("an unsynced key root must not be returned for identity creation");
        };
        assert!(matches!(
            error,
            super::AgentIdentityError::SyncKeyRootParent { .. }
        ));
        assert!(
            !root.exists(),
            "failed durability must remove only the newly created empty root"
        );

        let retry_attempt = std::cell::RefCell::new(Vec::new());
        let store = FileAgentKeyStore::open_with_parent_sync(&root, |synced| {
            retry_attempt.borrow_mut().push(synced.to_path_buf());
            Ok(())
        })
        .unwrap();
        assert_eq!(retry_attempt.into_inner(), vec![parent]);
        let (created, created_status) = store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let (loaded, loaded_status) = FileAgentKeyStore::open(&root)
            .unwrap()
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        assert_eq!(created_status, AgentKeyLoadStatus::Created);
        assert_eq!(loaded_status, AgentKeyLoadStatus::Loaded);
        assert_eq!(
            created.signing_key.to_bytes(),
            loaded.signing_key.to_bytes()
        );
    }

    #[test]
    fn key_store_open_syncs_only_the_new_ancestor_chain() {
        let anchor = temp_root("open-nested-parent-sync");
        let first = anchor.join("first");
        let second = first.join("second");
        let root = second.join("keys");
        let failed_attempt = std::cell::RefCell::new(Vec::new());

        let error = match FileAgentKeyStore::open_with_parent_sync(&root, |parent| {
            failed_attempt.borrow_mut().push(parent.to_path_buf());
            if parent == first {
                Err(std::io::Error::other(
                    "injected higher-ancestor sync failure",
                ))
            } else {
                Ok(())
            }
        }) {
            Ok(_) => panic!("a higher-ancestor sync failure must abort key-store open"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            super::AgentIdentityError::SyncKeyRootParent { ref path, .. } if path == &first
        ));
        assert_eq!(
            failed_attempt.into_inner(),
            vec![second.clone(), first.clone()]
        );
        assert!(anchor.is_dir());
        assert!(
            !first.exists(),
            "failed durability removes the newly created empty chain for retry"
        );

        let retry_attempt = std::cell::RefCell::new(Vec::new());
        let store = FileAgentKeyStore::open_with_parent_sync(&root, |parent| {
            retry_attempt.borrow_mut().push(parent.to_path_buf());
            Ok(())
        })
        .unwrap();
        let retry_attempt = retry_attempt.into_inner();
        assert_eq!(
            retry_attempt,
            vec![second, first, anchor],
            "only parents anchoring newly created directory entries are synced"
        );

        let (created, created_status) = store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let (loaded, loaded_status) = FileAgentKeyStore::open(&root)
            .unwrap()
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        assert_eq!(created_status, AgentKeyLoadStatus::Created);
        assert_eq!(loaded_status, AgentKeyLoadStatus::Loaded);
        assert_eq!(created.id, loaded.id);
    }

    #[test]
    fn key_store_open_syncs_no_ancestors_for_an_existing_root() {
        let root = temp_root("open-existing-root-no-sync");
        let sync_attempts = std::cell::RefCell::new(Vec::new());
        let store = FileAgentKeyStore::open_with_parent_sync(&root, |parent| {
            sync_attempts.borrow_mut().push(parent.to_path_buf());
            Ok(())
        })
        .unwrap();
        assert!(sync_attempts.into_inner().is_empty());

        let (_, status) = store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        assert_eq!(status, AgentKeyLoadStatus::Created);
    }

    #[test]
    fn key_store_reports_creation_separately_from_loading_an_existing_key() {
        let root = temp_root("load-status");
        let store = FileAgentKeyStore::open(&root).unwrap();
        let (created, created_status) = store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();
        let key_path = root.join("tom-primary.ed25519");
        assert_eq!(fs::read(&key_path).unwrap(), created.signing_key.to_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let (loaded, loaded_status) = store
            .load_or_create_with_status(AgentRole::Tom, "primary")
            .unwrap();

        assert_eq!(created_status, AgentKeyLoadStatus::Created);
        assert_eq!(loaded_status, AgentKeyLoadStatus::Loaded);
        assert_eq!(created.id, loaded.id);
        assert_eq!(
            created.signing_key.to_bytes(),
            loaded.signing_key.to_bytes()
        );
    }

    #[test]
    fn key_store_sync_failures_leave_an_existing_key_that_cannot_be_recreated() {
        for (slot, fail_file_sync) in [("file-sync-failure", true), ("dir-sync-failure", false)] {
            let root = temp_root(slot);
            let store = FileAgentKeyStore::open(&root).unwrap();
            let path = store.key_path(AgentRole::Tom, slot);
            let signing_key = SigningKey::generate(&mut OsRng);
            let result = store.write_new_key_with_sync(
                &path,
                &signing_key,
                |file| {
                    if fail_file_sync {
                        Err(std::io::Error::other("injected file sync failure"))
                    } else {
                        file.sync_all()
                    }
                },
                |_| Err(std::io::Error::other("injected parent sync failure")),
            );

            assert!(matches!(
                result,
                Err(super::AgentIdentityError::Write { .. })
            ));
            assert_eq!(fs::read(&path).unwrap(), signing_key.to_bytes());
            let (loaded, status) = store
                .load_or_create_with_status(AgentRole::Tom, slot)
                .unwrap();
            assert_eq!(status, AgentKeyLoadStatus::Loaded);
            assert_eq!(loaded.signing_key.to_bytes(), signing_key.to_bytes());
        }
    }

    #[test]
    fn key_store_create_new_race_never_replaces_an_existing_key() {
        let root = temp_root("create-new-race");
        let store = FileAgentKeyStore::open(&root).unwrap();
        let path = store.key_path(AgentRole::Tom, "primary");
        let winner = SigningKey::generate(&mut OsRng);
        let loser = SigningKey::generate(&mut OsRng);

        assert!(store.write_new_key(&path, &winner).unwrap());
        assert!(!store.write_new_key(&path, &loser).unwrap());
        assert_eq!(fs::read(&path).unwrap(), winner.to_bytes());
    }

    #[test]
    fn relative_agent_key_dir_resolves_from_config_parent() {
        let config_path = PathBuf::from("/tmp/swarm/rulesets/default.yaml");
        let identity = IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };

        assert_eq!(
            resolve_agent_key_dir(&config_path, &identity),
            PathBuf::from("/tmp/swarm/rulesets/data/agent-keys")
        );
    }

    #[test]
    fn relative_registry_dir_resolves_from_config_parent() {
        let config_path = PathBuf::from("/tmp/swarm/rulesets/default.yaml");
        let identity = IdentityConfig {
            agent_key_dir: "data/agent-keys".to_string(),
            registry_dir: "data/agent-identity".to_string(),
        };

        assert_eq!(
            resolve_identity_registry_dir(&config_path, &identity),
            PathBuf::from("/tmp/swarm/rulesets/data/agent-identity")
        );
    }

    #[test]
    fn registry_admits_first_seen_identity_and_refreshes_existing_identity() {
        let root = temp_root("registry-admit");
        let key_store = FileAgentKeyStore::open(root.join("keys")).unwrap();
        let registry = FileAgentIdentityRegistry::open(root.join("registry")).unwrap();
        let identity = key_store
            .load_or_create(AgentRole::Whisker, "primary")
            .unwrap();

        let first = registry
            .admit_persisted_identity(AgentRole::Whisker, "primary", &identity, 1_000)
            .unwrap();
        let second = registry
            .admit_persisted_identity(AgentRole::Whisker, "primary", &identity, 2_000)
            .unwrap();

        assert_eq!(first, RegistryAdmission::Added);
        assert_eq!(second, RegistryAdmission::Refreshed);
        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.active.len(), 1);
        assert_eq!(snapshot.active[0].agent_id, identity.id);
        assert_eq!(snapshot.active[0].last_seen_at_ms, 2_000);
        assert!(registry.is_admitted(&identity.id).unwrap());
    }

    #[test]
    fn registry_rejects_unregistered_identity_for_existing_role_slot() {
        let root = temp_root("registry-reject");
        let key_store = FileAgentKeyStore::open(root.join("keys")).unwrap();
        let registry = FileAgentIdentityRegistry::open(root.join("registry")).unwrap();
        let first = key_store.load_or_create(AgentRole::Tom, "primary").unwrap();
        registry
            .admit_persisted_identity(AgentRole::Tom, "primary", &first, 1_000)
            .unwrap();
        let rotated = key_store
            .replace(AgentRole::Tom, "primary", &SigningKey::generate(&mut OsRng))
            .unwrap();

        let error = registry
            .admit_persisted_identity(AgentRole::Tom, "primary", &rotated, 2_000)
            .unwrap_err();
        assert!(matches!(
            error,
            super::AgentIdentityError::UnregisteredIdentity { .. }
        ));
    }

    #[test]
    fn rotation_updates_registry_and_produces_verifiable_continuity_proof() {
        let root = temp_root("registry-rotate");
        let key_store = FileAgentKeyStore::open(root.join("keys")).unwrap();
        let registry = FileAgentIdentityRegistry::open(root.join("registry")).unwrap();
        let initial = key_store
            .load_or_create(AgentRole::Kitten, "primary")
            .unwrap();
        registry
            .admit_persisted_identity(AgentRole::Kitten, "primary", &initial, 1_000)
            .unwrap();

        let rotated = registry
            .rotate_identity(&key_store, AgentRole::Kitten, "primary", 5_000, 2_000)
            .unwrap();

        assert_ne!(rotated.previous_agent_id, rotated.next_identity.id);
        verify_continuity_proof(&rotated.proof).unwrap();

        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.active.len(), 1);
        assert_eq!(snapshot.active[0].agent_id, rotated.next_identity.id);
        assert_eq!(snapshot.retired.len(), 1);
        assert_eq!(snapshot.retired[0].agent_id, rotated.previous_agent_id);
        assert_eq!(snapshot.retired[0].active_until_ms, 5_000);
        assert_eq!(snapshot.continuity_proofs.len(), 1);
        assert_eq!(snapshot.continuity_proofs[0], rotated.proof);
        assert_eq!(
            key_store
                .load_or_create(AgentRole::Kitten, "primary")
                .unwrap()
                .id,
            rotated.next_identity.id
        );
    }
}
