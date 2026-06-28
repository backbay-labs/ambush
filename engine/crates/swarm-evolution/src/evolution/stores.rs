use super::types::{EvolutionAssuranceCaseRecord, EvolutionAssuranceCaseReport};
use super::*;

/// File-backed store for proof-backed queue admission artifacts.
#[derive(Debug, Clone)]
pub struct FileEvolutionProofStore {
    root: PathBuf,
}

impl FileEvolutionProofStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionProofStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionProofStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, proof_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(proof_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvolutionProofIndex, EvolutionProofStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionProofIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| EvolutionProofStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionProofStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &EvolutionProofIndex) -> Result<(), EvolutionProofStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionProofStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionProofStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionProofReport,
    ) -> Result<EvolutionProofRecord, EvolutionProofStoreError> {
        let path = self.report_path(&report.proof_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionProofStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionProofStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionProofRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.proof_id != record.proof_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn records(&self) -> Result<Vec<EvolutionProofRecord>, EvolutionProofStoreError> {
        Ok(self.read_index()?.entries)
    }

    pub fn load(
        &self,
        proof_id: &str,
    ) -> Result<Option<EvolutionProofLookup>, EvolutionProofStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.proof_id == proof_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| EvolutionProofStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionProofStoreError::Parse { path, source })?;
        Ok(Some(EvolutionProofLookup { record, report }))
    }

    pub fn latest(&self) -> Result<Option<EvolutionProofLookup>, EvolutionProofStoreError> {
        let Some(record) = self.read_index()?.entries.into_iter().next() else {
            return Ok(None);
        };
        self.load(&record.proof_id)
    }
}

/// Errors raised by the persisted evolution queue store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionProposalStoreError {
    #[error("failed to read evolution proposal store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution proposal store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution proposal store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Errors raised by the persisted assurance-case store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionAssuranceCaseStoreError {
    #[error("failed to read evolution assurance-case store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution assurance-case store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution assurance-case store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to encode evolution assurance-case scenario `{path}`: {source}")]
    ScenarioEncode {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
}

/// Errors raised by the persisted queue-to-canary handoff store.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionHandoffStoreError {
    #[error("failed to read evolution handoff store file `{path}`: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write evolution handoff store file `{path}`: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse evolution handoff store file `{path}`: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// File-backed store for durable evolution proposals.
#[derive(Debug, Clone)]
pub struct FileEvolutionProposalStore {
    root: PathBuf,
}

impl FileEvolutionProposalStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionProposalStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionProposalStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, proposal_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(proposal_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvolutionProposalIndex, EvolutionProposalStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionProposalIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionProposalStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionProposalStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionProposalIndex,
    ) -> Result<(), EvolutionProposalStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionProposalStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionProposalStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionProposalReport,
    ) -> Result<EvolutionProposalRecord, EvolutionProposalStoreError> {
        let path = self.report_path(&report.proposal_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionProposalStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionProposalStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionProposalRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.proposal_id != record.proposal_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        proposal_id: &str,
    ) -> Result<Option<EvolutionProposalLookup>, EvolutionProposalStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.proposal_id == proposal_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionProposalStoreError::Read {
                path: path.clone(),
                source,
            })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionProposalStoreError::Parse { path, source })?;
        Ok(Some(EvolutionProposalLookup { record, report }))
    }

    pub fn list(
        &self,
        strategy_id: Option<&str>,
        review_state: Option<EvolutionProposalReviewState>,
    ) -> Result<EvolutionProposalList, EvolutionProposalStoreError> {
        let index = self.read_index()?;
        let proposals = index
            .entries
            .into_iter()
            .filter(|entry| {
                strategy_id
                    .map(|expected| entry.strategy_id == expected)
                    .unwrap_or(true)
            })
            .filter(|entry| {
                review_state
                    .map(|expected| entry.review_state == expected)
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        Ok(EvolutionProposalList {
            total_count: proposals.len(),
            strategy_id: strategy_id.map(ToOwned::to_owned),
            review_state,
            proposals,
        })
    }
}

/// File-backed store for durable replay-ready assurance cases.
#[derive(Debug, Clone)]
pub(crate) struct FileEvolutionAssuranceCaseStore {
    root: PathBuf,
}

impl FileEvolutionAssuranceCaseStore {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionAssuranceCaseStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionAssuranceCaseStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        fs::create_dir_all(root.join("scenarios")).map_err(|source| {
            EvolutionAssuranceCaseStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, case_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(case_id)))
    }

    fn scenario_path(&self, case_id: &str) -> PathBuf {
        self.root
            .join("scenarios")
            .join(format!("{}.yaml", sanitize_id(case_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvolutionAssuranceCaseIndex, EvolutionAssuranceCaseStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionAssuranceCaseIndex::default());
        }
        let raw =
            fs::read_to_string(&path).map_err(|source| EvolutionAssuranceCaseStoreError::Read {
                path: path.clone(),
                source,
            })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionAssuranceCaseStoreError::Parse { path, source })
    }

    fn write_index(
        &self,
        index: &EvolutionAssuranceCaseIndex,
    ) -> Result<(), EvolutionAssuranceCaseStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionAssuranceCaseStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw)
            .map_err(|source| EvolutionAssuranceCaseStoreError::Write { path, source })
    }

    pub(crate) fn persist(
        &self,
        report: &EvolutionAssuranceCaseReport,
        scenario: &ReplayScenarioManifest,
    ) -> Result<EvolutionAssuranceCaseRecord, EvolutionAssuranceCaseStoreError> {
        let scenario_path = self.scenario_path(&report.case_id);
        let mut report = report.clone();
        report.scenario_path = scenario_path.display().to_string();

        let scenario_raw = serde_yaml::to_string(scenario).map_err(|source| {
            EvolutionAssuranceCaseStoreError::ScenarioEncode {
                path: scenario_path.clone(),
                source,
            }
        })?;
        fs::write(&scenario_path, scenario_raw).map_err(|source| {
            EvolutionAssuranceCaseStoreError::Write {
                path: scenario_path.clone(),
                source,
            }
        })?;

        let report_path = self.report_path(&report.case_id);
        let report_raw = serde_json::to_string_pretty(&report).map_err(|source| {
            EvolutionAssuranceCaseStoreError::Parse {
                path: report_path.clone(),
                source,
            }
        })?;
        fs::write(&report_path, report_raw).map_err(|source| {
            EvolutionAssuranceCaseStoreError::Write {
                path: report_path.clone(),
                source,
            }
        })?;

        let mut index = self.read_index()?;
        let record =
            EvolutionAssuranceCaseRecord::from_report(&report, report_path.display().to_string());
        index
            .entries
            .retain(|entry| entry.case_id != record.case_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }
}

/// File-backed store for durable queue-to-canary handoff packets.
#[derive(Debug, Clone)]
pub struct FileEvolutionHandoffStore {
    root: PathBuf,
}

impl FileEvolutionHandoffStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, EvolutionHandoffStoreError> {
        let root = path.as_ref().to_path_buf();
        fs::create_dir_all(root.join("reports")).map_err(|source| {
            EvolutionHandoffStoreError::Write {
                path: root.clone(),
                source,
            }
        })?;
        Ok(Self { root })
    }

    fn report_path(&self, handoff_id: &str) -> PathBuf {
        self.root
            .join("reports")
            .join(format!("{}.json", sanitize_id(handoff_id)))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn read_index(&self) -> Result<EvolutionHandoffIndex, EvolutionHandoffStoreError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(EvolutionHandoffIndex::default());
        }
        let raw = fs::read_to_string(&path).map_err(|source| EvolutionHandoffStoreError::Read {
            path: path.clone(),
            source,
        })?;
        serde_json::from_str(&raw)
            .map_err(|source| EvolutionHandoffStoreError::Parse { path, source })
    }

    fn write_index(&self, index: &EvolutionHandoffIndex) -> Result<(), EvolutionHandoffStoreError> {
        let path = self.index_path();
        let raw = serde_json::to_string_pretty(index).map_err(|source| {
            EvolutionHandoffStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionHandoffStoreError::Write { path, source })
    }

    pub fn persist(
        &self,
        report: &EvolutionHandoffReport,
    ) -> Result<EvolutionHandoffRecord, EvolutionHandoffStoreError> {
        let path = self.report_path(&report.handoff_id);
        let raw = serde_json::to_string_pretty(report).map_err(|source| {
            EvolutionHandoffStoreError::Parse {
                path: path.clone(),
                source,
            }
        })?;
        fs::write(&path, raw).map_err(|source| EvolutionHandoffStoreError::Write {
            path: path.clone(),
            source,
        })?;

        let mut index = self.read_index()?;
        let record = EvolutionHandoffRecord::from_report(report, path.display().to_string());
        index
            .entries
            .retain(|entry| entry.handoff_id != record.handoff_id);
        index.entries.push(record.clone());
        index
            .entries
            .sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        self.write_index(&index)?;
        Ok(record)
    }

    pub fn load(
        &self,
        handoff_id: &str,
    ) -> Result<Option<EvolutionHandoffLookup>, EvolutionHandoffStoreError> {
        let index = self.read_index()?;
        let Some(record) = index
            .entries
            .iter()
            .find(|entry| entry.handoff_id == handoff_id)
            .cloned()
        else {
            return Ok(None);
        };

        let path = PathBuf::from(&record.bundle_path);
        let raw = fs::read_to_string(&path).map_err(|source| EvolutionHandoffStoreError::Read {
            path: path.clone(),
            source,
        })?;
        let report = serde_json::from_str(&raw)
            .map_err(|source| EvolutionHandoffStoreError::Parse { path, source })?;
        Ok(Some(EvolutionHandoffLookup { record, report }))
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EvolutionProofIndex {
    entries: Vec<EvolutionProofRecord>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EvolutionProposalIndex {
    entries: Vec<EvolutionProposalRecord>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EvolutionAssuranceCaseIndex {
    entries: Vec<EvolutionAssuranceCaseRecord>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EvolutionHandoffIndex {
    entries: Vec<EvolutionHandoffRecord>,
}
