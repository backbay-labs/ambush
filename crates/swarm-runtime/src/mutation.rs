use crate::drafting::{
    DefaultEvolutionDraftingHarness, EvolutionDraftMaterializationRequest,
    EvolutionDraftPromotionStoreError, EvolutionDraftingError, EvolutionMaterializationLookup,
    EvolutionPressureReport, EvolutionPressureSourceKind,
};
use crate::replay::{ExperimentLineage, ReplayHarnessError, load_detector_experiment_manifest};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors surfaced by the guided mutation workflow.
#[derive(Debug, thiserror::Error)]
pub enum EvolutionMutationError {
    #[error(transparent)]
    Drafting(#[from] EvolutionDraftingError),

    #[error(transparent)]
    Replay(#[from] ReplayHarnessError),

    #[error(transparent)]
    PromotionStore(#[from] EvolutionDraftPromotionStoreError),

    #[error(transparent)]
    MutationStore(#[from] EvolutionMutationStoreError),

    #[error(transparent)]
    Serialization(#[from] serde_json::Error),

    #[error("invalid mutation spec request: {reason}")]
    InvalidMutationSpecRequest { reason: String },

    #[error("mutation spec `{mutation_spec_id}` was not found")]
    MutationSpecNotFound { mutation_spec_id: String },

    #[error("mutation spec `{mutation_spec_id}` already defines variant `{variant_id}`")]
    DuplicateVariantId {
        mutation_spec_id: String,
        variant_id: String,
    },

    #[error("mutation spec `{mutation_spec_id}` already defines strategy `{strategy_id}`")]
    DuplicateStrategyId {
        mutation_spec_id: String,
        strategy_id: String,
    },

    #[error("failed to read experiment search path `{path}`: {source}")]
    ManifestReadDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Stable source kind for one mutation spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionMutationSourceKind {
    Draft,
    Materialization,
}

/// Structured profile overrides applied to one variant candidate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationProfileOverrides {
    pub add_suspicious_parents: Vec<String>,
    pub remove_suspicious_parents: Vec<String>,
    pub add_suspicious_children: Vec<String>,
    pub remove_suspicious_children: Vec<String>,
    pub high_confidence_threshold: Option<String>,
    pub medium_confidence_threshold: Option<String>,
}

impl EvolutionMutationProfileOverrides {
    fn to_materialization_request(
        &self,
        draft_id: String,
        base_experiment_path: PathBuf,
    ) -> Result<EvolutionDraftMaterializationRequest, EvolutionMutationError> {
        let high_confidence_threshold = parse_optional_threshold(
            self.high_confidence_threshold.as_deref(),
            "high_confidence_threshold",
        )?;
        let medium_confidence_threshold = parse_optional_threshold(
            self.medium_confidence_threshold.as_deref(),
            "medium_confidence_threshold",
        )?;
        if let (Some(high), Some(medium)) = (high_confidence_threshold, medium_confidence_threshold)
            && medium > high
        {
            return Err(EvolutionMutationError::InvalidMutationSpecRequest {
                reason: format!(
                    "medium_confidence_threshold {medium:.3} cannot exceed high_confidence_threshold {high:.3}"
                ),
            });
        }

        Ok(EvolutionDraftMaterializationRequest {
            draft_id,
            base_experiment_path: Some(base_experiment_path),
            add_suspicious_parents: normalize_entries(&self.add_suspicious_parents),
            remove_suspicious_parents: normalize_entries(&self.remove_suspicious_parents),
            add_suspicious_children: normalize_entries(&self.add_suspicious_children),
            remove_suspicious_children: normalize_entries(&self.remove_suspicious_children),
            high_confidence_threshold,
            medium_confidence_threshold,
        })
    }

    fn dimensions(&self) -> Vec<String> {
        let mut dimensions = Vec::new();
        if !self.add_suspicious_parents.is_empty() {
            dimensions.push("add_suspicious_parent".to_string());
        }
        if !self.remove_suspicious_parents.is_empty() {
            dimensions.push("remove_suspicious_parent".to_string());
        }
        if !self.add_suspicious_children.is_empty() {
            dimensions.push("add_suspicious_child".to_string());
        }
        if !self.remove_suspicious_children.is_empty() {
            dimensions.push("remove_suspicious_child".to_string());
        }
        if self.high_confidence_threshold.is_some() {
            dimensions.push("high_confidence_threshold".to_string());
        }
        if self.medium_confidence_threshold.is_some() {
            dimensions.push("medium_confidence_threshold".to_string());
        }
        if dimensions.is_empty() {
            dimensions.push("profile_copy".to_string());
        }
        dimensions
    }
}

/// Request used to create one durable mutation spec from a draft or materialization.
#[derive(Debug, Clone)]
pub struct EvolutionMutationSpecCreateRequest {
    pub draft_id: Option<String>,
    pub materialization_id: Option<String>,
    pub base_experiment_path: Option<PathBuf>,
    pub rationale: String,
}

/// One operator-authored variant attached to a mutation spec.
#[derive(Debug, Clone)]
pub struct EvolutionMutationVariantCreateRequest {
    pub variant_id: Option<String>,
    pub strategy_id: String,
    pub strategy_description: String,
    pub mutation: String,
    pub rationale: String,
    pub overrides: EvolutionMutationProfileOverrides,
}

/// Durable mutation variant preserved on a mutation spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationVariantSpec {
    pub variant_id: String,
    pub strategy_id: String,
    pub strategy_description: String,
    pub mutation: String,
    pub rationale: String,
    pub mutation_dimensions: Vec<String>,
    pub overrides: EvolutionMutationProfileOverrides,
}

/// Durable operator-authored mutation spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionMutationSpecReport {
    pub mutation_spec_id: String,
    pub created_at_ms: i64,
    pub source_kind: EvolutionMutationSourceKind,
    pub draft_id: String,
    pub materialization_id: Option<String>,
    pub pressure_id: String,
    pub promotion_id: Option<String>,
    pub queue_proposal_id: Option<String>,
    pub source_strategy_id: String,
    pub source_strategy_description: String,
    pub source_lineage: ExperimentLineage,
    pub source_pressure_kind: EvolutionPressureSourceKind,
    pub source_experiment_id: String,
    pub source_experiment_name: String,
    pub base_experiment_path: String,
    pub operator_rationale: String,
    pub variants: Vec<EvolutionMutationVariantSpec>,
}

/// Metadata surfaced for one persisted mutation spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionMutationSpecRecord {
    pub mutation_spec_id: String,
    pub source_kind: EvolutionMutationSourceKind,
    pub source_strategy_id: String,
    pub variant_count: usize,
    pub created_at_ms: i64,
    pub bundle_path: String,
}

impl EvolutionMutationSpecRecord {
    fn from_report(report: &EvolutionMutationSpecReport, bundle_path: String) -> Self {
        Self {
            mutation_spec_id: report.mutation_spec_id.clone(),
            source_kind: report.source_kind,
            source_strategy_id: report.source_strategy_id.clone(),
            variant_count: report.variants.len(),
            created_at_ms: report.created_at_ms,
            bundle_path,
        }
    }
}

/// Persisted mutation spec loaded with metadata.
#[derive(Debug, Clone)]
pub struct EvolutionMutationSpecLookup {
    pub record: EvolutionMutationSpecRecord,
    pub report: EvolutionMutationSpecReport,
}

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

    fn read_index(&self) -> Result<EvolutionMutationIndex, EvolutionMutationStoreError> {
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

/// Harness for operator-authored mutation specs.
pub struct DefaultEvolutionMutationHarness {
    pub mutation_store: FileEvolutionMutationStore,
}

impl DefaultEvolutionMutationHarness {
    pub fn from_path(results_dir: impl AsRef<Path>) -> Result<Self, EvolutionMutationError> {
        Ok(Self {
            mutation_store: FileEvolutionMutationStore::open(results_dir)?,
        })
    }

    pub fn create_mutation_spec(
        &self,
        drafting: &DefaultEvolutionDraftingHarness,
        request: EvolutionMutationSpecCreateRequest,
    ) -> Result<EvolutionMutationSpecLookup, EvolutionMutationError> {
        validate_create_request(&request)?;
        let created_at_ms = now_ms();

        let report = if let Some(draft_id) = request.draft_id {
            let draft = drafting.load_draft(&draft_id)?.ok_or_else(|| {
                EvolutionDraftingError::DraftNotFound {
                    draft_id: draft_id.clone(),
                }
            })?;
            let pressure = drafting
                .load_pressure(&draft.report.pressure_id)?
                .ok_or_else(|| EvolutionDraftingError::PressureNotFound {
                    pressure_id: draft.report.pressure_id.clone(),
                })?;
            let base_experiment_path = match request.base_experiment_path {
                Some(path) => path,
                None => infer_base_experiment_path(
                    &drafting.config_path,
                    &draft.report.draft_id,
                    &pressure.report,
                )?,
            };
            let base_manifest = load_detector_experiment_manifest(&base_experiment_path)?;
            let promotion = drafting
                .promotion_store
                .load_for_draft(&draft.report.draft_id)?;

            EvolutionMutationSpecReport {
                mutation_spec_id: mutation_spec_id(
                    EvolutionMutationSourceKind::Draft,
                    &draft.report.strategy_id,
                    created_at_ms,
                ),
                created_at_ms,
                source_kind: EvolutionMutationSourceKind::Draft,
                draft_id: draft.report.draft_id.clone(),
                materialization_id: None,
                pressure_id: draft.report.pressure_id.clone(),
                promotion_id: promotion
                    .as_ref()
                    .map(|lookup| lookup.report.promotion_id.clone()),
                queue_proposal_id: promotion
                    .as_ref()
                    .map(|lookup| lookup.report.queue_proposal_id.clone()),
                source_strategy_id: draft.report.strategy_id.clone(),
                source_strategy_description: draft.report.strategy_description.clone(),
                source_lineage: ExperimentLineage {
                    parent_strategy_id: draft.report.parent_strategy_id.clone(),
                    mutation: draft.report.lineage_mutation.clone(),
                    rationale: draft.report.lineage_rationale.clone(),
                },
                source_pressure_kind: pressure.report.source_kind,
                source_experiment_id: pressure
                    .report
                    .experiment_id
                    .clone()
                    .unwrap_or_else(|| format!("experiment:{}", base_manifest.name)),
                source_experiment_name: pressure
                    .report
                    .experiment_name
                    .clone()
                    .unwrap_or_else(|| base_manifest.name.clone()),
                base_experiment_path: base_experiment_path.display().to_string(),
                operator_rationale: request.rationale,
                variants: Vec::new(),
            }
        } else {
            let materialization_id = request.materialization_id.expect("validated source");
            let materialization = drafting
                .load_materialization(&materialization_id)?
                .ok_or_else(|| EvolutionDraftingError::MaterializationNotFound {
                    materialization_id: materialization_id.clone(),
                })?;
            let promotion = drafting
                .promotion_store
                .load_for_draft(&materialization.report.draft_id)?;

            EvolutionMutationSpecReport {
                mutation_spec_id: mutation_spec_id(
                    EvolutionMutationSourceKind::Materialization,
                    &materialization.report.strategy_id,
                    created_at_ms,
                ),
                created_at_ms,
                source_kind: EvolutionMutationSourceKind::Materialization,
                draft_id: materialization.report.draft_id.clone(),
                materialization_id: Some(materialization.report.materialization_id.clone()),
                pressure_id: materialization.report.pressure_id.clone(),
                promotion_id: promotion
                    .as_ref()
                    .map(|lookup| lookup.report.promotion_id.clone()),
                queue_proposal_id: promotion
                    .as_ref()
                    .map(|lookup| lookup.report.queue_proposal_id.clone()),
                source_strategy_id: materialization.report.strategy_id.clone(),
                source_strategy_description: materialization.report.strategy_description.clone(),
                source_lineage: materialization.report.lineage.clone(),
                source_pressure_kind: resolve_materialization_pressure_kind(
                    drafting,
                    &materialization,
                )?,
                source_experiment_id: materialization.report.experiment_id.clone(),
                source_experiment_name: materialization.report.experiment_name.clone(),
                base_experiment_path: request
                    .base_experiment_path
                    .unwrap_or_else(|| PathBuf::from(&materialization.report.experiment_path))
                    .display()
                    .to_string(),
                operator_rationale: request.rationale,
                variants: Vec::new(),
            }
        };

        let record = self.mutation_store.persist(&report)?;
        Ok(EvolutionMutationSpecLookup { record, report })
    }

    pub fn append_variant(
        &self,
        mutation_spec_id: &str,
        request: EvolutionMutationVariantCreateRequest,
    ) -> Result<EvolutionMutationSpecLookup, EvolutionMutationError> {
        let mut lookup = self.mutation_store.load(mutation_spec_id)?.ok_or_else(|| {
            EvolutionMutationError::MutationSpecNotFound {
                mutation_spec_id: mutation_spec_id.to_string(),
            }
        })?;

        let variant_id = request
            .variant_id
            .unwrap_or_else(|| sanitize_id(&request.strategy_id));
        if lookup
            .report
            .variants
            .iter()
            .any(|variant| variant.variant_id == variant_id)
        {
            return Err(EvolutionMutationError::DuplicateVariantId {
                mutation_spec_id: mutation_spec_id.to_string(),
                variant_id,
            });
        }
        if lookup
            .report
            .variants
            .iter()
            .any(|variant| variant.strategy_id == request.strategy_id)
        {
            return Err(EvolutionMutationError::DuplicateStrategyId {
                mutation_spec_id: mutation_spec_id.to_string(),
                strategy_id: request.strategy_id,
            });
        }

        let _validation_request = request.overrides.to_materialization_request(
            lookup.report.draft_id.clone(),
            PathBuf::from(&lookup.report.base_experiment_path),
        )?;

        let variant = EvolutionMutationVariantSpec {
            variant_id,
            strategy_id: request.strategy_id,
            strategy_description: request.strategy_description,
            mutation: request.mutation,
            rationale: request.rationale,
            mutation_dimensions: request.overrides.dimensions(),
            overrides: request.overrides,
        };

        lookup.report.variants.push(variant);
        let record = self.mutation_store.persist(&lookup.report)?;
        Ok(EvolutionMutationSpecLookup {
            record,
            report: lookup.report,
        })
    }

    pub fn load_mutation_spec(
        &self,
        mutation_spec_id: &str,
    ) -> Result<Option<EvolutionMutationSpecLookup>, EvolutionMutationError> {
        Ok(self.mutation_store.load(mutation_spec_id)?)
    }
}

/// Render one durable mutation spec.
pub fn render_evolution_mutation_spec(report: &EvolutionMutationSpecReport) -> String {
    let mut lines = vec![
        "Evolution Mutation Spec".to_string(),
        format!("Mutation spec ID: {}", report.mutation_spec_id),
        format!("Source kind: {}", mutation_source_label(report.source_kind)),
        format!("Draft ID: {}", report.draft_id),
        format!(
            "Source strategy: {} | {}",
            report.source_strategy_id, report.source_strategy_description
        ),
        format!(
            "Source experiment: {} ({})",
            report.source_experiment_name, report.source_experiment_id
        ),
        format!("Base experiment path: {}", report.base_experiment_path),
        format!("Operator rationale: {}", report.operator_rationale),
    ];

    if let Some(materialization_id) = &report.materialization_id {
        lines.push(format!("Source materialization: {}", materialization_id));
    }
    if let Some(queue_proposal_id) = &report.queue_proposal_id {
        lines.push(format!("Reviewed queue proposal: {}", queue_proposal_id));
    }

    if report.variants.is_empty() {
        lines.push("Variants: none".to_string());
    } else {
        lines.push("Variants:".to_string());
        for variant in &report.variants {
            lines.push(format!(
                "- {} | strategy={} | mutation={} | dims={}",
                variant.variant_id,
                variant.strategy_id,
                variant.mutation,
                variant.mutation_dimensions.join(",")
            ));
        }
    }

    lines.join("\n")
}

fn mutation_source_label(kind: EvolutionMutationSourceKind) -> &'static str {
    match kind {
        EvolutionMutationSourceKind::Draft => "draft",
        EvolutionMutationSourceKind::Materialization => "materialization",
    }
}

fn validate_create_request(
    request: &EvolutionMutationSpecCreateRequest,
) -> Result<(), EvolutionMutationError> {
    match (&request.draft_id, &request.materialization_id) {
        (Some(_), None) | (None, Some(_)) => {}
        _ => {
            return Err(EvolutionMutationError::InvalidMutationSpecRequest {
                reason: "exactly one of draft_id or materialization_id must be set".to_string(),
            });
        }
    }
    if request.rationale.trim().is_empty() {
        return Err(EvolutionMutationError::InvalidMutationSpecRequest {
            reason: "rationale cannot be empty".to_string(),
        });
    }
    Ok(())
}

fn resolve_materialization_pressure_kind(
    drafting: &DefaultEvolutionDraftingHarness,
    materialization: &EvolutionMaterializationLookup,
) -> Result<EvolutionPressureSourceKind, EvolutionMutationError> {
    let pressure = drafting
        .load_pressure(&materialization.report.pressure_id)?
        .ok_or_else(|| EvolutionDraftingError::PressureNotFound {
            pressure_id: materialization.report.pressure_id.clone(),
        })?;
    Ok(pressure.report.source_kind)
}

fn infer_base_experiment_path(
    config_path: &Path,
    draft_id: &str,
    pressure: &EvolutionPressureReport,
) -> Result<PathBuf, EvolutionMutationError> {
    let experiment_name = pressure.experiment_name.as_deref().ok_or_else(|| {
        EvolutionMutationError::InvalidMutationSpecRequest {
            reason: format!("no source experiment name found for draft `{draft_id}`"),
        }
    })?;
    let experiments_dir = repo_root_from_config_path(config_path).join("experiments");
    find_experiment_manifest_path(&experiments_dir, experiment_name)?.ok_or_else(|| {
        EvolutionMutationError::InvalidMutationSpecRequest {
            reason: format!("could not resolve a base experiment manifest for draft `{draft_id}`"),
        }
    })
}

fn find_experiment_manifest_path(
    root: &Path,
    experiment_name: &str,
) -> Result<Option<PathBuf>, EvolutionMutationError> {
    if !root.exists() {
        return Ok(None);
    }

    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries =
            fs::read_dir(&dir).map_err(|source| EvolutionMutationError::ManifestReadDir {
                path: dir.clone(),
                source,
            })?;
        for entry in entries {
            let entry = entry.map_err(|source| EvolutionMutationError::ManifestReadDir {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            let file_type =
                entry
                    .file_type()
                    .map_err(|source| EvolutionMutationError::ManifestReadDir {
                        path: path.clone(),
                        source,
                    })?;
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
                continue;
            };
            if !matches!(extension, "yaml" | "yml") {
                continue;
            }
            let manifest = load_detector_experiment_manifest(&path)?;
            if manifest.name == experiment_name {
                return Ok(Some(path));
            }
        }
    }

    Ok(None)
}

fn repo_root_from_config_path(config_path: &Path) -> PathBuf {
    if let Some(parent) = config_path.parent() {
        if parent.file_name().is_some_and(|name| name == "rulesets") {
            return parent.parent().unwrap_or(parent).to_path_buf();
        }
        return parent.to_path_buf();
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn parse_optional_threshold(
    raw: Option<&str>,
    field: &str,
) -> Result<Option<f64>, EvolutionMutationError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let value =
        raw.parse::<f64>()
            .map_err(|_| EvolutionMutationError::InvalidMutationSpecRequest {
                reason: format!("{field} must be a valid floating-point number, got `{raw}`"),
            })?;
    if !(0.0..=1.0).contains(&value) {
        return Err(EvolutionMutationError::InvalidMutationSpecRequest {
            reason: format!("{field} must be between 0.0 and 1.0, got {value}"),
        });
    }
    Ok(Some(value))
}

fn normalize_entries(values: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for value in values {
        let lowered = value.to_ascii_lowercase();
        if !normalized
            .iter()
            .any(|entry: &String| entry.eq_ignore_ascii_case(&lowered))
        {
            normalized.push(lowered);
        }
    }
    normalized
}

fn mutation_spec_id(
    source_kind: EvolutionMutationSourceKind,
    strategy_id: &str,
    created_at_ms: i64,
) -> String {
    format!(
        "evolution_mutation_spec:{}:{}:{}",
        mutation_source_label(source_kind),
        strategy_id,
        created_at_ms
    )
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
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
        .expect("system time after unix epoch")
        .as_millis() as i64
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct EvolutionMutationIndex {
    entries: Vec<EvolutionMutationSpecRecord>,
}

#[cfg(test)]
mod tests {
    use super::{
        DefaultEvolutionMutationHarness, EvolutionDraftMaterializationRequest,
        EvolutionMutationProfileOverrides, EvolutionMutationSourceKind,
        EvolutionMutationSpecCreateRequest, EvolutionMutationVariantCreateRequest,
        render_evolution_mutation_spec,
    };
    use crate::drafting::{DefaultEvolutionDraftingHarness, EvolutionDraftCreateRequest};
    use crate::replay::DefaultReplayHarness;
    use crate::strategy::DefaultStrategyScorecardHarness;
    use std::fs;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .unwrap()
            .to_path_buf()
    }

    fn ruleset_path() -> PathBuf {
        repo_root().join("rulesets/default.yaml")
    }

    fn office_control_experiment() -> PathBuf {
        repo_root().join("experiments/office-baseline-control.yaml")
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "swarm-team-six-{}-{}",
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn copy_experiment_fixture(root: &PathBuf, name: &str) -> PathBuf {
        let path = root.join(format!("{name}.yaml"));
        fs::copy(office_control_experiment(), &path).unwrap();
        path
    }

    #[tokio::test]
    async fn mutation_spec_from_reviewed_draft_persists() {
        let root = unique_temp_dir("mutation-spec-draft");
        let replay_dir = root.join("replay");
        let experiment_dir = root.join("experiments");
        let verification_dir = root.join("verifications");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let pressure_dir = root.join("pressures");
        let draft_dir = root.join("drafts");
        let promotion_dir = root.join("promotions");
        let materialization_dir = root.join("materializations");
        let validation_dir = root.join("validation");
        let reconciliation_dir = root.join("reconciliations");
        let queue_dir = root.join("queue");
        let mutation_dir = root.join("mutations");
        let base_experiment = copy_experiment_fixture(&root, "office-control-copy");

        let replay = DefaultReplayHarness::from_path(ruleset_path(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let scorecards =
            DefaultStrategyScorecardHarness::from_path(ruleset_path(), &memory_dir, &scorecard_dir)
                .unwrap();
        let scorecard = scorecards
            .create_scorecard(
                &replay,
                office_control_experiment(),
                &experiment_dir,
                &verification_dir,
                &verification.report.verification_id,
            )
            .await
            .unwrap();
        let drafting = DefaultEvolutionDraftingHarness::from_path(
            ruleset_path(),
            &pressure_dir,
            &draft_dir,
            &promotion_dir,
            &materialization_dir,
            &validation_dir,
            &reconciliation_dir,
        )
        .unwrap();
        let pressure = drafting
            .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
            .unwrap();
        let draft = drafting
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: "office_mutation_parent_v1".to_string(),
                strategy_description: "mutation parent draft for office control".to_string(),
                mutation: "guided_mutation_seed".to_string(),
                rationale: "operator wants to compare several explicit variants".to_string(),
            })
            .unwrap();
        let promotion = drafting
            .promote_draft(
                &queue_dir,
                &draft.report.draft_id,
                "review this parent draft first",
            )
            .unwrap();

        let mutation = DefaultEvolutionMutationHarness::from_path(&mutation_dir).unwrap();
        let spec = mutation
            .create_mutation_spec(
                &drafting,
                EvolutionMutationSpecCreateRequest {
                    draft_id: Some(draft.report.draft_id.clone()),
                    materialization_id: None,
                    base_experiment_path: Some(base_experiment),
                    rationale: "package explicit parent and threshold mutations under one spec"
                        .to_string(),
                },
            )
            .unwrap();
        let spec = mutation
            .append_variant(
                &spec.report.mutation_spec_id,
                EvolutionMutationVariantCreateRequest {
                    variant_id: Some("tighter-thresholds".to_string()),
                    strategy_id: "office_mutation_threshold_v1".to_string(),
                    strategy_description: "raise confidence thresholds without changing parents"
                        .to_string(),
                    mutation: "raise_thresholds".to_string(),
                    rationale: "test whether stricter gating reduces replay regressions"
                        .to_string(),
                    overrides: EvolutionMutationProfileOverrides {
                        high_confidence_threshold: Some("0.98".to_string()),
                        medium_confidence_threshold: Some("0.92".to_string()),
                        ..EvolutionMutationProfileOverrides::default()
                    },
                },
            )
            .unwrap();

        assert_eq!(spec.report.source_kind, EvolutionMutationSourceKind::Draft);
        assert_eq!(
            spec.report.queue_proposal_id.as_deref(),
            Some(promotion.report.queue_proposal_id.as_str())
        );
        assert_eq!(spec.report.variants.len(), 1);
        assert_eq!(
            spec.report.variants[0].mutation_dimensions,
            vec![
                "high_confidence_threshold".to_string(),
                "medium_confidence_threshold".to_string()
            ]
        );
        assert!(render_evolution_mutation_spec(&spec.report).contains("Evolution Mutation Spec"));

        let loaded = mutation
            .load_mutation_spec(&spec.report.mutation_spec_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.report.variants.len(), 1);
    }

    #[tokio::test]
    async fn mutation_spec_from_materialized_candidate_persists() {
        let root = unique_temp_dir("mutation-spec-materialization");
        let replay_dir = root.join("replay");
        let verification_dir = root.join("verifications");
        let memory_dir = root.join("memory");
        let scorecard_dir = root.join("scorecards");
        let pressure_dir = root.join("pressures");
        let draft_dir = root.join("drafts");
        let promotion_dir = root.join("promotions");
        let materialization_dir = root.join("materializations");
        let validation_dir = root.join("validation");
        let reconciliation_dir = root.join("reconciliations");
        let mutation_dir = root.join("mutations");
        let queue_dir = root.join("queue");
        let base_experiment = copy_experiment_fixture(&root, "office-control-seed");

        let replay = DefaultReplayHarness::from_path(ruleset_path(), &replay_dir).unwrap();
        let verification = replay
            .evaluate_verification_path(office_control_experiment(), &verification_dir)
            .await
            .unwrap();
        let scorecards =
            DefaultStrategyScorecardHarness::from_path(ruleset_path(), &memory_dir, &scorecard_dir)
                .unwrap();
        let scorecard = scorecards
            .create_scorecard(
                &replay,
                office_control_experiment(),
                &root.join("experiments"),
                &verification_dir,
                &verification.report.verification_id,
            )
            .await
            .unwrap();
        let drafting = DefaultEvolutionDraftingHarness::from_path(
            ruleset_path(),
            &pressure_dir,
            &draft_dir,
            &promotion_dir,
            &materialization_dir,
            &validation_dir,
            &reconciliation_dir,
        )
        .unwrap();
        let pressure = drafting
            .create_pressure_from_scorecard(&scorecards, &scorecard.report.scorecard_id)
            .unwrap();
        let draft = drafting
            .create_draft(EvolutionDraftCreateRequest {
                pressure_id: pressure.report.pressure_id.clone(),
                strategy_id: "office_materialized_parent_v1".to_string(),
                strategy_description: "materialized parent draft".to_string(),
                mutation: "materialize_parent_for_guided_mutation".to_string(),
                rationale: "seed a later mutation bench from a concrete candidate".to_string(),
            })
            .unwrap();
        drafting
            .promote_draft(
                &queue_dir,
                &draft.report.draft_id,
                "review the parent draft before mutation",
            )
            .unwrap();
        let materialization = drafting
            .materialize_draft(EvolutionDraftMaterializationRequest {
                draft_id: draft.report.draft_id.clone(),
                base_experiment_path: Some(base_experiment),
                ..EvolutionDraftMaterializationRequest::default()
            })
            .unwrap();

        let mutation = DefaultEvolutionMutationHarness::from_path(&mutation_dir).unwrap();
        let spec = mutation
            .create_mutation_spec(
                &drafting,
                EvolutionMutationSpecCreateRequest {
                    draft_id: None,
                    materialization_id: Some(materialization.report.materialization_id.clone()),
                    base_experiment_path: None,
                    rationale:
                        "branch explicit parent and child mutations from the materialized candidate"
                            .to_string(),
                },
            )
            .unwrap();
        let spec = mutation
            .append_variant(
                &spec.report.mutation_spec_id,
                EvolutionMutationVariantCreateRequest {
                    variant_id: Some("python-parent".to_string()),
                    strategy_id: "office_python_parent_v2".to_string(),
                    strategy_description: "broaden parent matching to python".to_string(),
                    mutation: "broaden_parent_set".to_string(),
                    rationale: "explicitly measure the broader parent signal".to_string(),
                    overrides: EvolutionMutationProfileOverrides {
                        add_suspicious_parents: vec!["python".to_string()],
                        ..EvolutionMutationProfileOverrides::default()
                    },
                },
            )
            .unwrap();

        assert_eq!(
            spec.report.source_kind,
            EvolutionMutationSourceKind::Materialization
        );
        assert_eq!(
            spec.report.materialization_id.as_deref(),
            Some(materialization.report.materialization_id.as_str())
        );
        assert_eq!(
            spec.report.base_experiment_path,
            materialization.report.experiment_path
        );
        assert_eq!(spec.report.variants.len(), 1);
    }
}
