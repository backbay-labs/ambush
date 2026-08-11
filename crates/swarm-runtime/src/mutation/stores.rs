use super::*;
use ed25519_dalek::SigningKey;
use swarm_core::signed_state::{SignedStateEnvelope, SignedStateExpectation};
use swarm_core::types::AgentId;

const EVOLUTION_POPULATION_STATE_KIND: &str = "evolution_population_state";
const EVOLUTION_POPULATION_STREAM_ID: &str = "population";
const EVOLUTION_EPISODE_STATE_KIND: &str = "evolution_episode_report";

/// Errors raised by the persisted mutation-spec store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionMutationStoreError {
    #[error("failed to read evolution mutation store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution mutation store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution mutation store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted materialization-batch store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionMutationMaterializationBatchStoreError {
    #[error(
        "failed to read evolution mutation materialization batch store file `{path}`: {source}"
    )]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "failed to write evolution mutation materialization batch store file `{path}`: {source}"
    )]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(
        "failed to parse evolution mutation materialization batch store file `{path}`: {source}"
    )]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted validation-batch store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionMutationValidationBatchStoreError {
    #[error("failed to read evolution mutation validation batch store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution mutation validation batch store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution mutation validation batch store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted ranking store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionMutationRankingStoreError {
    #[error("failed to read evolution mutation ranking store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution mutation ranking store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution mutation ranking store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the durable population store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionPopulationStoreError {
    #[error("failed to read evolution population store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution population store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution population store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("missing signing context for evolution population store `{path}`")]
    MissingSignerContext { path: PathBuf },

    #[error("evolution population store signature verification failed for `{path}`: {source}")]
    InvalidSignature {
        path: PathBuf,
        #[source]
        source: swarm_core::SignedStateError,
    },
}

/// Errors raised by the durable evolution-episode store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionEpisodeStoreError {
    #[error("failed to read evolution episode store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution episode store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution episode store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("missing signing context for evolution episode store `{path}`")]
    MissingSignerContext { path: PathBuf },

    #[error("evolution episode store signature verification failed for `{path}`: {source}")]
    InvalidSignature {
        path: PathBuf,
        #[source]
        source: swarm_core::SignedStateError,
    },
}

/// Errors raised by the durable evolution benchmark store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionBenchmarkStoreError {
    #[error("failed to read evolution benchmark store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution benchmark store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution benchmark store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed store for durable mutation specs.
#[derive(Debug, Clone)]
pub struct FileEvolutionMutationStore {
    root: PathBuf,
}

impl FileEvolutionMutationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionMutationStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionMutationStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, mutation_spec_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(mutation_spec_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    pub(crate) fn read_index(&self) -> Result<EvolutionMutationIndex, EvolutionMutationStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionMutationIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionMutationStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionMutationStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionMutationIndex,
    ) -> Result<(), EvolutionMutationStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionMutationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionMutationStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionMutationSpecReport,
    ) -> Result<EvolutionMutationSpecRecord, EvolutionMutationStoreError> {
        let path = self.report_path(&report.mutation_spec_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionMutationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionMutationStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionMutationSpecRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.mutation_spec_id != record.mutation_spec_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        mutation_spec_id: &str,
    ) -> Result<Option<EvolutionMutationSpecLookup>, EvolutionMutationStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.mutation_spec_id == mutation_spec_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionMutationStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionMutationStoreError::Parse { path, source })?;
        Ok(Some(EvolutionMutationSpecLookup { record, report }))
    }
}

/// File-backed store for durable materialization batches.
#[derive(Debug, Clone)]
pub struct FileEvolutionMutationMaterializationBatchStore {
    root: PathBuf,
}

impl FileEvolutionMutationMaterializationBatchStore {
    pub fn open(
        path: impl AsRef<Path>,
    ) -> Result<Self, EvolutionMutationMaterializationBatchStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, batch_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(batch_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    pub(crate) fn read_index(
        &self,
    ) -> Result<
        EvolutionMutationMaterializationBatchIndex,
        EvolutionMutationMaterializationBatchStoreError,
    > {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionMutationMaterializationBatchIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Parse { path, source }
        })
    }

    fn write_index(
        &self,
        index: &EvolutionMutationMaterializationBatchIndex,
    ) -> Result<(), EvolutionMutationMaterializationBatchStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Write { path, source }
        })
    }

    pub fn persist(
        &self,
        report: &EvolutionMutationMaterializationBatchReport,
    ) -> Result<
        EvolutionMutationMaterializationBatchRecord,
        EvolutionMutationMaterializationBatchStoreError,
    > {
        let path = self.report_path(&report.batch_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Write {
                path: path.clone(),
                source,
            }
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionMutationMaterializationBatchRecord::from_report(
            report,
            path.display().to_string(),
        );
        index
            .entries
            .retain(|entry| entry.batch_id != record.batch_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        batch_id: &str,
    ) -> Result<
        Option<EvolutionMutationMaterializationBatchLookup>,
        EvolutionMutationMaterializationBatchStoreError,
    > {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.batch_id == batch_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw).map_err(|source| {
            EvolutionMutationMaterializationBatchStoreError::Parse { path, source }
        })?;
        Ok(Some(EvolutionMutationMaterializationBatchLookup {
            record,
            report,
        }))
    }
}

/// File-backed store for durable validation batches.
#[derive(Debug, Clone)]
pub struct FileEvolutionMutationValidationBatchStore {
    root: PathBuf,
}

impl FileEvolutionMutationValidationBatchStore {
    pub fn open(
        path: impl AsRef<Path>,
    ) -> Result<Self, EvolutionMutationValidationBatchStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionMutationValidationBatchStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, validation_batch_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(validation_batch_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    pub(crate) fn read_index(
        &self,
    ) -> Result<EvolutionMutationValidationBatchIndex, EvolutionMutationValidationBatchStoreError>
    {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionMutationValidationBatchIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMutationValidationBatchStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionMutationValidationBatchStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionMutationValidationBatchIndex,
    ) -> Result<(), EvolutionMutationValidationBatchStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionMutationValidationBatchStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionMutationValidationBatchStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionMutationValidationBatchReport,
    ) -> Result<EvolutionMutationValidationBatchRecord, EvolutionMutationValidationBatchStoreError>
    {
        let path = self.report_path(&report.validation_batch_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionMutationValidationBatchStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| {
            EvolutionMutationValidationBatchStoreError::Write {
                path: path.clone(),
                source,
            }
        })?;

        let mut index = self.read_index()?;
        let record =
            EvolutionMutationValidationBatchRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.validation_batch_id != record.validation_batch_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        validation_batch_id: &str,
    ) -> Result<
        Option<EvolutionMutationValidationBatchLookup>,
        EvolutionMutationValidationBatchStoreError,
    > {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.validation_batch_id == validation_batch_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMutationValidationBatchStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionMutationValidationBatchStoreError::Parse { path, source })?;
        Ok(Some(EvolutionMutationValidationBatchLookup {
            record,
            report,
        }))
    }
}

/// File-backed store for durable candidate rankings.
#[derive(Debug, Clone)]
pub struct FileEvolutionMutationRankingStore {
    root: PathBuf,
}

impl FileEvolutionMutationRankingStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionMutationRankingStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionMutationRankingStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, ranking_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(ranking_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    pub(crate) fn read_index(
        &self,
    ) -> Result<EvolutionMutationRankingIndex, EvolutionMutationRankingStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionMutationRankingIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMutationRankingStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionMutationRankingStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionMutationRankingIndex,
    ) -> Result<(), EvolutionMutationRankingStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionMutationRankingStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionMutationRankingStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionMutationRankingReport,
    ) -> Result<EvolutionMutationRankingRecord, EvolutionMutationRankingStoreError> {
        let path = self.report_path(&report.ranking_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionMutationRankingStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionMutationRankingStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record =
            EvolutionMutationRankingRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.ranking_id != record.ranking_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        ranking_id: &str,
    ) -> Result<Option<EvolutionMutationRankingLookup>, EvolutionMutationRankingStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.ranking_id == ranking_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| {
            EvolutionMutationRankingStoreError::Read {
                path: path.clone(),
                source,
            }
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionMutationRankingStoreError::Parse { path, source })?;
        Ok(Some(EvolutionMutationRankingLookup { record, report }))
    }
}

/// File-backed store for the durable mutation population state.
#[derive(Debug, Clone)]
pub struct FileEvolutionPopulationStore {
    root: PathBuf,
    signer_agent_id: Option<AgentId>,
    signing_key: Option<SigningKey>,
}

impl FileEvolutionPopulationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionPopulationStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|source| EvolutionPopulationStoreError::Write {
            path: root.clone(),
            source,
        })?;
        Ok(Self {
            root,
            signer_agent_id: None,
            signing_key: None,
        })
    }

    pub fn open_signed(
        path: impl AsRef<Path>,
        signer_agent_id: AgentId,
        signing_key: SigningKey,
    ) -> Result<Self, EvolutionPopulationStoreError> {
        let mut store = Self::open(path)?;
        store.signer_agent_id = Some(signer_agent_id);
        store.signing_key = Some(signing_key);
        Ok(store)
    }

    fn state_path(&self) -> PathBuf {
        self.root.join("state.json")
    }

    fn state_sequence_path(&self) -> PathBuf {
        self.root.join("state.sequence.json")
    }

    pub fn load(&self) -> Result<Option<EvolutionPopulationState>, EvolutionPopulationStoreError> {
        self.load_internal(None)
    }

    pub fn load_trusted(
        &self,
        expected_signer_agent_id: &AgentId,
    ) -> Result<Option<EvolutionPopulationState>, EvolutionPopulationStoreError> {
        self.load_internal(Some(expected_signer_agent_id))
    }

    fn load_internal(
        &self,
        expected_signer_agent_id: Option<&AgentId>,
    ) -> Result<Option<EvolutionPopulationState>, EvolutionPopulationStoreError> {
        let path = self.state_path();
        if !path.exists() {
            return Ok(None);
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionPopulationStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let envelope: SignedStateEnvelope<EvolutionPopulationState> = serde_json::from_str(&raw)
            .map_err(|source| EvolutionPopulationStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        let accepted_sequence = self.read_state_sequence()?;
        let verified = envelope
            .verify(SignedStateExpectation {
                state_kind: EVOLUTION_POPULATION_STATE_KIND,
                stream_id: EVOLUTION_POPULATION_STREAM_ID,
                expected_signer_agent_id,
                accepted_sequence,
            })
            .map_err(|source| EvolutionPopulationStoreError::InvalidSignature {
                path: path.clone(),
                source,
            })?;
        if accepted_sequence.is_none_or(|sequence| sequence < verified.sequence) {
            self.write_state_sequence(verified.sequence)?;
        }
        Ok(Some(verified.payload))
    }

    pub fn persist(
        &self,
        state: &EvolutionPopulationState,
    ) -> Result<(), EvolutionPopulationStoreError> {
        let path = self.state_path();
        let signer_agent_id = self.signer_agent_id.as_ref().ok_or_else(|| {
            EvolutionPopulationStoreError::MissingSignerContext { path: path.clone() }
        })?;
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            EvolutionPopulationStoreError::MissingSignerContext { path: path.clone() }
        })?;
        let sequence = self.read_state_sequence()?.unwrap_or(0).saturating_add(1);
        let envelope = SignedStateEnvelope::sign(
            EVOLUTION_POPULATION_STATE_KIND,
            EVOLUTION_POPULATION_STREAM_ID,
            signer_agent_id.clone(),
            sequence,
            state.clone(),
            signing_key,
        )
        .map_err(|source| EvolutionPopulationStoreError::InvalidSignature {
            path: path.clone(),
            source,
        })?;
        let raw = serde_json::to_string_pretty(&envelope).map_err(|source| {
            EvolutionPopulationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionPopulationStoreError::Write {
            path: path.clone(),
            source,
        })?;
        self.write_state_sequence(sequence)
    }

    fn read_state_sequence(&self) -> Result<Option<u64>, EvolutionPopulationStoreError> {
        let path = self.state_sequence_path();
        if !path.exists() {
            return Ok(None);
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionPopulationStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map(Some)
            .map_err(|source| EvolutionPopulationStoreError::Parse { path, source })
    }

    fn write_state_sequence(&self, sequence: u64) -> Result<(), EvolutionPopulationStoreError> {
        let path = self.state_sequence_path();
        let raw = serde_json::to_string_pretty(&sequence).map_err(|source| {
            EvolutionPopulationStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionPopulationStoreError::Write { path, source })
    }
}

/// File-backed store for durable red-blue evolution episodes.
#[derive(Debug, Clone)]
pub struct FileEvolutionEpisodeStore {
    root: PathBuf,
    signer_agent_id: Option<AgentId>,
    signing_key: Option<SigningKey>,
}

impl FileEvolutionEpisodeStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionEpisodeStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionEpisodeStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self {
            root,
            signer_agent_id: None,
            signing_key: None,
        })
    }

    pub fn open_signed(
        path: impl AsRef<Path>,
        signer_agent_id: AgentId,
        signing_key: SigningKey,
    ) -> Result<Self, EvolutionEpisodeStoreError> {
        let mut store = Self::open(path)?;
        store.signer_agent_id = Some(signer_agent_id);
        store.signing_key = Some(signing_key);
        Ok(store)
    }

    fn report_path(&self, episode_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(episode_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn sequence_path(&self, episode_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.sequence.json", sanitize_id(episode_id)))
    }

    pub(crate) fn read_index(&self) -> Result<EvolutionEpisodeIndex, EvolutionEpisodeStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionEpisodeIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| EvolutionEpisodeStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionEpisodeStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &EvolutionEpisodeIndex) -> Result<(), EvolutionEpisodeStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionEpisodeStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionEpisodeStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionEpisodeReport,
    ) -> Result<EvolutionEpisodeRecord, EvolutionEpisodeStoreError> {
        let path = self.report_path(&report.episode_id);
        let signer_agent_id = self.signer_agent_id.as_ref().ok_or_else(|| {
            EvolutionEpisodeStoreError::MissingSignerContext { path: path.clone() }
        })?;
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            EvolutionEpisodeStoreError::MissingSignerContext { path: path.clone() }
        })?;
        let sequence = self
            .read_sequence(&report.episode_id)?
            .unwrap_or(0)
            .saturating_add(1);
        let envelope = SignedStateEnvelope::sign(
            EVOLUTION_EPISODE_STATE_KIND,
            report.episode_id.clone(),
            signer_agent_id.clone(),
            sequence,
            report.clone(),
            signing_key,
        )
        .map_err(|source| EvolutionEpisodeStoreError::InvalidSignature {
            path: path.clone(),
            source,
        })?;
        let raw = serde_json::to_string_pretty(&envelope).map_err(|source| {
            EvolutionEpisodeStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionEpisodeStoreError::Write {
            path: path.clone(),
            source,
        })?;
        self.write_sequence(&report.episode_id, sequence)?;

        let mut index = self.read_index()?;
        let record = EvolutionEpisodeRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.episode_id != record.episode_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        episode_id: &str,
    ) -> Result<Option<EvolutionEpisodeLookup>, EvolutionEpisodeStoreError> {
        self.load_internal(episode_id, None)
    }

    pub fn load_trusted(
        &self,
        episode_id: &str,
        expected_signer_agent_id: &AgentId,
    ) -> Result<Option<EvolutionEpisodeLookup>, EvolutionEpisodeStoreError> {
        self.load_internal(episode_id, Some(expected_signer_agent_id))
    }

    fn load_internal(
        &self,
        episode_id: &str,
        expected_signer_agent_id: Option<&AgentId>,
    ) -> Result<Option<EvolutionEpisodeLookup>, EvolutionEpisodeStoreError> {
        let path = self.report_path(episode_id);
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path).map_err(|source| EvolutionEpisodeStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let envelope: SignedStateEnvelope<EvolutionEpisodeReport> = serde_json::from_str(&raw)
            .map_err(|source| EvolutionEpisodeStoreError::Parse {
                path: path.clone(),
                source,
            })?;
        let accepted_sequence = self.read_sequence(episode_id)?;
        let verified = envelope
            .verify(SignedStateExpectation {
                state_kind: EVOLUTION_EPISODE_STATE_KIND,
                stream_id: episode_id,
                expected_signer_agent_id,
                accepted_sequence,
            })
            .map_err(|source| EvolutionEpisodeStoreError::InvalidSignature {
                path: path.clone(),
                source,
            })?;
        if accepted_sequence.is_none_or(|sequence| sequence < verified.sequence) {
            self.write_sequence(episode_id, verified.sequence)?;
        }
        let report = verified.payload;
        let record = EvolutionEpisodeRecord::from_report(&report, path.display().to_string());
        Ok(Some(EvolutionEpisodeLookup { record, report }))
    }

    pub fn latest(
        &self,
        limit: usize,
    ) -> Result<Vec<EvolutionEpisodeRecord>, EvolutionEpisodeStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.truncate(limit);
        Ok(entries)
    }

    fn read_sequence(&self, episode_id: &str) -> Result<Option<u64>, EvolutionEpisodeStoreError> {
        let path = self.sequence_path(episode_id);
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path).map_err(|source| EvolutionEpisodeStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw)
            .map(Some)
            .map_err(|source| EvolutionEpisodeStoreError::Parse { path, source })
    }

    fn write_sequence(
        &self,
        episode_id: &str,
        sequence: u64,
    ) -> Result<(), EvolutionEpisodeStoreError> {
        let path = self.sequence_path(episode_id);
        let raw = serde_json::to_string_pretty(&sequence).map_err(|source| {
            EvolutionEpisodeStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionEpisodeStoreError::Write { path, source })
    }
}

/// File-backed store for durable bounded evolution benchmark runs.
#[derive(Debug, Clone)]
pub struct FileEvolutionBenchmarkStore {
    root: PathBuf,
}

impl FileEvolutionBenchmarkStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionBenchmarkStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionBenchmarkStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, benchmark_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(benchmark_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    pub(crate) fn read_index(
        &self,
    ) -> Result<EvolutionBenchmarkIndex, EvolutionBenchmarkStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionBenchmarkIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionBenchmarkStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionBenchmarkStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionBenchmarkIndex,
    ) -> Result<(), EvolutionBenchmarkStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionBenchmarkStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionBenchmarkStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionBenchmarkRunReport,
    ) -> Result<EvolutionBenchmarkRunRecord, EvolutionBenchmarkStoreError> {
        let path = self.report_path(&report.benchmark_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionBenchmarkStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionBenchmarkStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionBenchmarkRunRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.benchmark_id != record.benchmark_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.updated_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        benchmark_id: &str,
    ) -> Result<Option<EvolutionBenchmarkRunLookup>, EvolutionBenchmarkStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.benchmark_id == benchmark_id)
            .cloned()
        else {
            return Ok(None);
        };
        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionBenchmarkStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionBenchmarkStoreError::Parse { path, source })?;
        Ok(Some(EvolutionBenchmarkRunLookup { record, report }))
    }

    pub fn latest(
        &self,
        limit: usize,
    ) -> Result<Vec<EvolutionBenchmarkRunRecord>, EvolutionBenchmarkStoreError> {
        let mut entries = self.read_index()?.entries;
        entries.truncate(limit);
        Ok(entries)
    }
}
