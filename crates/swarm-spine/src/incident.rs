use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use swarm_core::config::BundleStoreConfig;

/// One candidate investigation evaluated during incident assembly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentMemberDecision {
    pub investigation_id: String,
    pub hunt_id: String,
    pub finding_id: String,
    pub reason: String,
    pub shared_keys: Vec<String>,
}

/// Durable incident artifact assembled from persisted investigation bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelatedIncident {
    pub incident_id: String,
    pub summary: String,
    pub created_at_ms: i64,
    pub window_start_ms: i64,
    pub window_end_ms: i64,
    pub correlation_keys: Vec<String>,
    pub related_receipt_ids: Vec<String>,
    pub included_members: Vec<IncidentMemberDecision>,
    pub rejected_members: Vec<IncidentMemberDecision>,
}

impl CorrelatedIncident {
    pub fn included_hunt_ids(&self) -> Vec<String> {
        dedupe_strings(
            self.included_members
                .iter()
                .map(|member| member.hunt_id.clone()),
        )
    }

    pub fn included_investigation_ids(&self) -> Vec<String> {
        dedupe_strings(
            self.included_members
                .iter()
                .map(|member| member.investigation_id.clone()),
        )
    }
}

/// Metadata surfaced for recent incidents and operator review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentRecord {
    pub incident_id: String,
    pub summary: String,
    pub created_at_ms: i64,
    pub included_hunt_ids: Vec<String>,
    pub included_investigation_ids: Vec<String>,
    pub related_receipt_ids: Vec<String>,
    pub correlation_keys: Vec<String>,
    pub bundle_path: String,
}

impl IncidentRecord {
    fn from_incident(incident: &CorrelatedIncident, bundle_path: String) -> Self {
        Self {
            incident_id: incident.incident_id.clone(),
            summary: incident.summary.clone(),
            created_at_ms: incident.created_at_ms,
            included_hunt_ids: incident.included_hunt_ids(),
            included_investigation_ids: incident.included_investigation_ids(),
            related_receipt_ids: incident.related_receipt_ids.clone(),
            correlation_keys: incident.correlation_keys.clone(),
            bundle_path,
        }
    }
}

/// Loaded incident artifact with its persisted metadata.
#[derive(Debug, Clone)]
pub struct IncidentLookup {
    pub record: IncidentRecord,
    pub incident: CorrelatedIncident,
}

/// Health summary for an incident store backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentStoreHealth {
    pub backend: String,
    pub durable: bool,
    pub ready: bool,
    pub stored_incidents: usize,
    pub details: String,
}

/// Incident store errors.
#[derive(Debug, thiserror::Error)]
pub enum IncidentStoreError {
    #[error("incident store lock poisoned")]
    PoisonedLock,

    #[error("failed to read incident store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write incident store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse incident store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Store contract for durable incident artifacts.
pub trait IncidentStore: Send + Sync {
    fn persist(&self, incident: &CorrelatedIncident) -> Result<IncidentRecord, IncidentStoreError>;
    fn load_by_incident_id(
        &self,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, IncidentStoreError>;
    fn load_by_hunt_id(&self, hunt_id: &str) -> Result<Option<IncidentLookup>, IncidentStoreError>;
    fn recent(&self, limit: usize) -> Result<Vec<IncidentRecord>, IncidentStoreError>;
    fn health(&self) -> Result<IncidentStoreHealth, IncidentStoreError>;
}

/// Configured incident store backend.
#[derive(Debug, Clone)]
pub enum ConfiguredIncidentStore {
    Memory(MemoryIncidentStore),
    LocalFiles(FileIncidentStore),
}

impl ConfiguredIncidentStore {
    pub fn from_config(config: &BundleStoreConfig) -> Result<Self, IncidentStoreError> {
        match config {
            BundleStoreConfig::Memory => Ok(Self::Memory(MemoryIncidentStore::default())),
            BundleStoreConfig::LocalFiles { directory } => {
                Ok(Self::LocalFiles(FileIncidentStore::open(directory)?))
            }
        }
    }
}

impl IncidentStore for ConfiguredIncidentStore {
    fn persist(&self, incident: &CorrelatedIncident) -> Result<IncidentRecord, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.persist(incident),
            Self::LocalFiles(store) => store.persist(incident),
        }
    }

    fn load_by_incident_id(
        &self,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.load_by_incident_id(incident_id),
            Self::LocalFiles(store) => store.load_by_incident_id(incident_id),
        }
    }

    fn load_by_hunt_id(&self, hunt_id: &str) -> Result<Option<IncidentLookup>, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.load_by_hunt_id(hunt_id),
            Self::LocalFiles(store) => store.load_by_hunt_id(hunt_id),
        }
    }

    fn recent(&self, limit: usize) -> Result<Vec<IncidentRecord>, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.recent(limit),
            Self::LocalFiles(store) => store.recent(limit),
        }
    }

    fn health(&self) -> Result<IncidentStoreHealth, IncidentStoreError> {
        match self {
            Self::Memory(store) => store.health(),
            Self::LocalFiles(store) => store.health(),
        }
    }
}

/// In-memory incident store for tests and operator snapshots.
#[derive(Debug, Clone, Default)]
pub struct MemoryIncidentStore {
    incidents: Arc<RwLock<Vec<CorrelatedIncident>>>,
}

impl IncidentStore for MemoryIncidentStore {
    fn persist(&self, incident: &CorrelatedIncident) -> Result<IncidentRecord, IncidentStoreError> {
        let mut guard = self
            .incidents
            .write()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        guard.retain(|existing| existing.incident_id != incident.incident_id);
        guard.push(incident.clone());
        Ok(IncidentRecord::from_incident(
            incident,
            "memory".to_string(),
        ))
    }

    fn load_by_incident_id(
        &self,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, IncidentStoreError> {
        let guard = self
            .incidents
            .read()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        Ok(guard
            .iter()
            .find(|incident| incident.incident_id == incident_id)
            .cloned()
            .map(|incident| IncidentLookup {
                record: IncidentRecord::from_incident(&incident, "memory".to_string()),
                incident,
            }))
    }

    fn load_by_hunt_id(&self, hunt_id: &str) -> Result<Option<IncidentLookup>, IncidentStoreError> {
        let guard = self
            .incidents
            .read()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        Ok(sorted_recent_incidents(&guard)
            .into_iter()
            .find(|incident| {
                incident
                    .included_hunt_ids()
                    .iter()
                    .any(|candidate| candidate == hunt_id)
            })
            .map(|incident| IncidentLookup {
                record: IncidentRecord::from_incident(&incident, "memory".to_string()),
                incident,
            }))
    }

    fn recent(&self, limit: usize) -> Result<Vec<IncidentRecord>, IncidentStoreError> {
        let guard = self
            .incidents
            .read()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        let mut entries = sorted_recent_incidents(&guard)
            .into_iter()
            .map(|incident| IncidentRecord::from_incident(&incident, "memory".to_string()))
            .collect::<Vec<_>>();
        entries.truncate(limit);
        Ok(entries)
    }

    fn health(&self) -> Result<IncidentStoreHealth, IncidentStoreError> {
        let guard = self
            .incidents
            .read()
            .map_err(|_| IncidentStoreError::PoisonedLock)?;
        Ok(IncidentStoreHealth {
            backend: "memory".to_string(),
            durable: false,
            ready: true,
            stored_incidents: guard.len(),
            details: "ephemeral in-process incident store".to_string(),
        })
    }
}

/// File-backed incident store for restart-safe review artifacts.
#[derive(Debug, Clone)]
pub struct FileIncidentStore {
    root: PathBuf,
}

impl FileIncidentStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, IncidentStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("incidents")).map_err(|source| IncidentStoreError::Write {
            path: root.clone(),
            source,
        })?;
        Ok(Self { root })
    }

    fn incidents_dir(&self) -> PathBuf {
        self.root.join("incidents")
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<IncidentIndex, IncidentStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(IncidentIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| IncidentStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw).map_err(|source| IncidentStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &IncidentIndex) -> Result<(), IncidentStoreError> {
        let path = self.index_path();
        let raw =
            serde_json::to_string_pretty(index).map_err(|source| IncidentStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| IncidentStoreError::Write { path, source })
    }

    fn incident_path(&self, incident_id: &str) -> PathBuf {
        self.incidents_dir()
            .join(format!("{}.json", sanitize_id(incident_id)))
    }

    fn write_incident(&self, incident: &CorrelatedIncident) -> Result<String, IncidentStoreError> {
        let path = self.incident_path(&incident.incident_id);
        let raw =
            serde_json::to_string_pretty(incident).map_err(|source| IncidentStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        fs::write(&path, raw).map_err(|source| IncidentStoreError::Write {
            path: path.clone(),
            source,
        })?;
        Ok(path
            .strip_prefix(&self.root)
            .unwrap_or(&path)
            .display()
            .to_string())
    }

    fn read_incident(&self, record: IncidentRecord) -> Result<IncidentLookup, IncidentStoreError> {
        let path = self.root.join(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| IncidentStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let incident = serde_json::from_str(&raw)
            .map_err(|source| IncidentStoreError::Parse { path, source })?;
        Ok(IncidentLookup { record, incident })
    }
}

impl IncidentStore for FileIncidentStore {
    fn persist(&self, incident: &CorrelatedIncident) -> Result<IncidentRecord, IncidentStoreError> {
        let bundle_path = self.write_incident(incident)?;
        let mut index = self.read_index()?;
        index
            .entries
            .retain(|entry| entry.incident_id != incident.incident_id);
        let record = IncidentRecord::from_incident(incident, bundle_path);
        index.entries.push(record.clone());
        self.write_index(&index)?;
        Ok(record)
    }

    fn load_by_incident_id(
        &self,
        incident_id: &str,
    ) -> Result<Option<IncidentLookup>, IncidentStoreError> {
        let index = self.read_index()?;
        if let Some(record) = index
            .entries
            .into_iter()
            .find(|entry| entry.incident_id == incident_id)
        {
            return self.read_incident(record).map(Some);
        }
        Ok(None)
    }

    fn load_by_hunt_id(&self, hunt_id: &str) -> Result<Option<IncidentLookup>, IncidentStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
        if let Some(record) = entries.into_iter().find(|entry| {
            entry
                .included_hunt_ids
                .iter()
                .any(|candidate| candidate == hunt_id)
        }) {
            return self.read_incident(record).map(Some);
        }
        Ok(None)
    }

    fn recent(&self, limit: usize) -> Result<Vec<IncidentRecord>, IncidentStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
        entries.truncate(limit);
        Ok(entries)
    }

    fn health(&self) -> Result<IncidentStoreHealth, IncidentStoreError> {
        fs::create_dir_all(self.incidents_dir()).map_err(|source| IncidentStoreError::Write {
            path: self.root.clone(),
            source,
        })?;
        let stored_incidents = self.read_index()?.entries.len();
        Ok(IncidentStoreHealth {
            backend: "local_files".to_string(),
            durable: true,
            ready: true,
            stored_incidents,
            details: format!("incident directory at {}", self.root.display()),
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct IncidentIndex {
    entries: Vec<IncidentRecord>,
}

fn sorted_recent_incidents(incidents: &[CorrelatedIncident]) -> Vec<CorrelatedIncident> {
    let mut ordered = incidents.to_vec();
    ordered.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
    ordered
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn dedupe_strings<I>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut output = Vec::new();
    for value in values {
        if !output.iter().any(|existing| existing == &value) {
            output.push(value);
        }
    }
    output
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        ConfiguredIncidentStore, CorrelatedIncident, FileIncidentStore, IncidentMemberDecision,
        IncidentStore, IncidentStoreHealth,
    };
    use swarm_core::config::BundleStoreConfig;

    fn sample_incident() -> CorrelatedIncident {
        CorrelatedIncident {
            incident_id: "incident:hunt-1:1".to_string(),
            summary: "Two related investigations share host and user".to_string(),
            created_at_ms: 1_700_000_000_500,
            window_start_ms: 1_700_000_000_100,
            window_end_ms: 1_700_000_000_450,
            correlation_keys: vec!["host:host-1".to_string(), "user:alice".to_string()],
            related_receipt_ids: vec![
                "receipt-upstream-1".to_string(),
                "receipt-response-1".to_string(),
            ],
            included_members: vec![
                IncidentMemberDecision {
                    investigation_id: "investigation:hunt-1:1".to_string(),
                    hunt_id: "hunt-1".to_string(),
                    finding_id: "finding-1".to_string(),
                    reason: "seed investigation".to_string(),
                    shared_keys: vec!["host:host-1".to_string(), "user:alice".to_string()],
                },
                IncidentMemberDecision {
                    investigation_id: "investigation:hunt-2:1".to_string(),
                    hunt_id: "hunt-2".to_string(),
                    finding_id: "finding-2".to_string(),
                    reason: "shared host and user within correlation window".to_string(),
                    shared_keys: vec!["host:host-1".to_string(), "user:alice".to_string()],
                },
            ],
            rejected_members: vec![IncidentMemberDecision {
                investigation_id: "investigation:hunt-3:1".to_string(),
                hunt_id: "hunt-3".to_string(),
                finding_id: "finding-3".to_string(),
                reason: "outside correlation time window".to_string(),
                shared_keys: vec!["host:host-1".to_string()],
            }],
        }
    }

    #[test]
    fn file_store_persists_and_loads_by_hunt_id() {
        let root = std::env::temp_dir().join("swarm-spine-incidents");
        let _ = std::fs::remove_dir_all(&root);
        let store = FileIncidentStore::open(&root).unwrap();
        let incident = sample_incident();
        let record = store.persist(&incident).unwrap();

        assert_eq!(record.included_hunt_ids.len(), 2);
        let loaded = store.load_by_hunt_id("hunt-2").unwrap().unwrap();
        assert_eq!(loaded.incident.incident_id, incident.incident_id);

        let health = store.health().unwrap();
        assert_eq!(
            health,
            IncidentStoreHealth {
                backend: "local_files".to_string(),
                durable: true,
                ready: true,
                stored_incidents: 1,
                details: format!("incident directory at {}", root.display()),
            }
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn configured_store_selects_memory_and_local_backends() {
        let memory = ConfiguredIncidentStore::from_config(&BundleStoreConfig::Memory).unwrap();
        assert_eq!(memory.health().unwrap().backend, "memory");

        let root = std::env::temp_dir().join("swarm-spine-configured-incidents");
        let _ = std::fs::remove_dir_all(&root);
        let local = ConfiguredIncidentStore::from_config(&BundleStoreConfig::LocalFiles {
            directory: root.display().to_string(),
        })
        .unwrap();
        assert_eq!(local.health().unwrap().backend, "local_files");
        let _ = std::fs::remove_dir_all(root);
    }
}
