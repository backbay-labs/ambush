use super::*;

pub(crate) fn mutation_source_label(kind: EvolutionMutationSourceKind) -> &'static str {
    match kind {
        EvolutionMutationSourceKind::Draft => "draft",
        EvolutionMutationSourceKind::Materialization => "materialization",
        EvolutionMutationSourceKind::Autonomous => "autonomous",
    }
}

pub(crate) fn autonomous_recipe_label(kind: EvolutionAutonomousVariantRecipeKind) -> &'static str {
    match kind {
        EvolutionAutonomousVariantRecipeKind::SeedControl => "seed_control",
        EvolutionAutonomousVariantRecipeKind::BoundedPerturbation => "bounded_perturbation",
        EvolutionAutonomousVariantRecipeKind::GapExpansion => "gap_expansion",
        EvolutionAutonomousVariantRecipeKind::BoundedCrossover => "bounded_crossover",
    }
}

pub(crate) fn review_state_label(value: EvolutionProposalReviewState) -> &'static str {
    match value {
        EvolutionProposalReviewState::PendingReview => "pending_review",
        EvolutionProposalReviewState::AcceptedForCanary => "accepted_for_canary",
        EvolutionProposalReviewState::Deferred => "deferred",
        EvolutionProposalReviewState::Rejected => "rejected",
        EvolutionProposalReviewState::Blocked => "blocked",
    }
}

pub(crate) fn advisory_recommendation_label(
    value: Option<StrategyAdvisoryRecommendation>,
) -> &'static str {
    match value {
        Some(StrategyAdvisoryRecommendation::RetainBaseline) => "retain_baseline",
        Some(StrategyAdvisoryRecommendation::CandidatePreferred) => "candidate_preferred",
        Some(StrategyAdvisoryRecommendation::CandidateAlreadyStableInProduction) => {
            "candidate_already_stable_in_production"
        }
        None => "none",
    }
}

pub(crate) fn validate_create_request(
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

pub(crate) fn validate_autonomous_create_request(
    request: &EvolutionAutonomousMutationSpecCreateRequest,
) -> Result<(), EvolutionMutationError> {
    if request.draft_id.trim().is_empty() {
        return Err(EvolutionMutationError::InvalidMutationSpecRequest {
            reason: "draft_id cannot be empty for autonomous mutation generation".to_string(),
        });
    }
    if request.strategy_root.trim().is_empty() {
        return Err(EvolutionMutationError::InvalidMutationSpecRequest {
            reason: "strategy_root cannot be empty for autonomous mutation generation".to_string(),
        });
    }
    if request.rationale.trim().is_empty() {
        return Err(EvolutionMutationError::InvalidMutationSpecRequest {
            reason: "rationale cannot be empty".to_string(),
        });
    }
    if request.max_variants == 0 {
        return Err(EvolutionMutationError::InvalidMutationSpecRequest {
            reason: "max_variants must be greater than zero".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn apply_profile_overrides(
    profile: &mut SuspiciousProcessTreeProfile,
    request: &EvolutionDraftMaterializationRequest,
) -> Result<Vec<String>, EvolutionMutationError> {
    let mut changes = Vec::new();

    for parent in &request.add_suspicious_parents {
        let parent = parent.to_ascii_lowercase();
        if !profile
            .suspicious_parents
            .iter()
            .any(|entry: &String| entry.eq_ignore_ascii_case(&parent))
        {
            profile.suspicious_parents.push(parent.clone());
            changes.push(format!("add suspicious parent `{parent}`"));
        }
    }
    for parent in &request.remove_suspicious_parents {
        let parent = parent.to_ascii_lowercase();
        let before = profile.suspicious_parents.len();
        profile
            .suspicious_parents
            .retain(|entry: &String| !entry.eq_ignore_ascii_case(&parent));
        if before != profile.suspicious_parents.len() {
            changes.push(format!("remove suspicious parent `{parent}`"));
        }
    }
    for child in &request.add_suspicious_children {
        let child = child.to_ascii_lowercase();
        if !profile
            .suspicious_children
            .iter()
            .any(|entry: &String| entry.eq_ignore_ascii_case(&child))
        {
            profile.suspicious_children.push(child.clone());
            changes.push(format!("add suspicious child `{child}`"));
        }
    }
    for child in &request.remove_suspicious_children {
        let child = child.to_ascii_lowercase();
        let before = profile.suspicious_children.len();
        profile
            .suspicious_children
            .retain(|entry: &String| !entry.eq_ignore_ascii_case(&child));
        if before != profile.suspicious_children.len() {
            changes.push(format!("remove suspicious child `{child}`"));
        }
    }

    if let Some(value) = request.high_confidence_threshold {
        if profile.high_confidence_threshold != value {
            changes.push(format!("set high confidence threshold to {:.3}", value));
        }
        profile.high_confidence_threshold = value;
    }
    if let Some(value) = request.medium_confidence_threshold {
        if profile.medium_confidence_threshold != value {
            changes.push(format!("set medium confidence threshold to {:.3}", value));
        }
        profile.medium_confidence_threshold = value;
    }
    if profile.medium_confidence_threshold > profile.high_confidence_threshold {
        return Err(EvolutionMutationError::InvalidMutationSpecRequest {
            reason: format!(
                "medium confidence threshold {:.3} cannot exceed high confidence threshold {:.3}",
                profile.medium_confidence_threshold, profile.high_confidence_threshold
            ),
        });
    }

    normalize_profile_entries(&mut profile.suspicious_parents);
    normalize_profile_entries(&mut profile.suspicious_children);

    if changes.is_empty() {
        changes.push("profile copied from base experiment without profile overrides".to_string());
    }

    Ok(changes)
}

pub(crate) fn resolve_materialization_pressure_kind(
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

pub(crate) fn infer_base_experiment_path(
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

pub(crate) fn find_experiment_manifest_path(
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

pub(crate) fn repo_root_from_config_path(config_path: &Path) -> PathBuf {
    if let Some(parent) = config_path.parent() {
        if parent.file_name().is_some_and(|name| name == "rulesets") {
            return parent.parent().unwrap_or(parent).to_path_buf();
        }
        return parent.to_path_buf();
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub(crate) fn parse_optional_threshold(
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

pub(crate) fn normalize_entries(values: &[String]) -> Vec<String> {
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

pub(crate) fn normalize_profile_entries(values: &mut Vec<String>) {
    let mut normalized = Vec::new();
    for value in values.drain(..) {
        let lowered = value.to_ascii_lowercase();
        if !normalized
            .iter()
            .any(|entry: &String| entry.eq_ignore_ascii_case(&lowered))
        {
            normalized.push(lowered);
        }
    }
    *values = normalized;
}

pub(crate) fn mutation_spec_id(
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

pub(crate) fn mutation_materialization_batch_id(
    mutation_spec_id: &str,
    created_at_ms: i64,
) -> String {
    format!(
        "evolution_mutation_materialization_batch:{}:{}",
        sanitize_id(mutation_spec_id),
        created_at_ms
    )
}

pub(crate) fn mutation_validation_batch_id(mutation_spec_id: &str, created_at_ms: i64) -> String {
    format!(
        "evolution_mutation_validation_batch:{}:{}",
        sanitize_id(mutation_spec_id),
        created_at_ms
    )
}

pub(crate) fn mutation_ranking_id(
    mutation_spec_id: &str,
    validation_batch_id: &str,
    created_at_ms: i64,
) -> String {
    format!(
        "evolution_mutation_ranking:{}:{}:{}",
        short_digest(mutation_spec_id),
        short_digest(validation_batch_id),
        created_at_ms
    )
}

pub(crate) fn review_packet_id(validation_batch_id: &str, rank: usize, variant_id: &str) -> String {
    format!(
        "evolution_review_packet:{}:{}:{}",
        sanitize_id(validation_batch_id),
        rank,
        sanitize_id(variant_id)
    )
}

pub(crate) fn mutation_materialization_id(
    mutation_spec_id: &str,
    variant_id: &str,
    created_at_ms: i64,
) -> String {
    format!(
        "evolution_mutation_materialization:{}:{}:{}",
        sanitize_id(mutation_spec_id),
        sanitize_id(variant_id),
        created_at_ms
    )
}

pub(crate) fn materialized_experiment_name(strategy_id: &str, created_at_ms: i64) -> String {
    format!(
        "mutation_materialized_{}_{}",
        sanitize_id(strategy_id),
        created_at_ms
    )
}

pub(crate) fn materialized_experiment_path(
    base_experiment_path: &Path,
    strategy_id: &str,
    created_at_ms: i64,
) -> PathBuf {
    let parent = base_experiment_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    parent.join(format!(
        "mutation-{}-{}.yaml",
        sanitize_id(strategy_id),
        created_at_ms
    ))
}

pub(crate) fn experiment_id_for_manifest(manifest: &DetectorExperimentManifest) -> String {
    format!(
        "experiment:{}:{}",
        manifest.name,
        manifest.candidate.strategy_id()
    )
}

pub(crate) fn validation_bundle_status_label(
    value: EvolutionValidationBundleStatus,
) -> &'static str {
    match value {
        EvolutionValidationBundleStatus::ReadyForQueue => "ready_for_queue",
        EvolutionValidationBundleStatus::Blocked => "blocked",
    }
}

pub(crate) fn proof_status_label(value: EvolutionProposalProofStatus) -> &'static str {
    match value {
        EvolutionProposalProofStatus::Proved => "proved",
        EvolutionProposalProofStatus::Missing => "missing",
        EvolutionProposalProofStatus::Inconsistent => "inconsistent",
    }
}

pub(crate) fn sha256_hex<T: Serialize>(value: &T) -> Result<String, EvolutionMutationError> {
    let bytes = serde_json::to_vec(value)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
}

pub(crate) fn short_digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    digest[..12].to_string()
}

pub(crate) fn sanitize_id(value: &str) -> String {
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

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct EvolutionMutationIndex {
    pub(crate) entries: Vec<EvolutionMutationSpecRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct EvolutionMutationMaterializationBatchIndex {
    pub(crate) entries: Vec<EvolutionMutationMaterializationBatchRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct EvolutionMutationValidationBatchIndex {
    pub(crate) entries: Vec<EvolutionMutationValidationBatchRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct EvolutionMutationRankingIndex {
    pub(crate) entries: Vec<EvolutionMutationRankingRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct EvolutionEpisodeIndex {
    pub(crate) entries: Vec<EvolutionEpisodeRecord>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct EvolutionBenchmarkIndex {
    pub(crate) entries: Vec<EvolutionBenchmarkRunRecord>,
}

pub(crate) fn generation_for_ranking(
    index: &EvolutionMutationRankingIndex,
    ranking_id: &str,
) -> usize {
    let mut entries = index.entries.clone();
    entries.sort_by_key(|entry| entry.created_at_ms);
    entries
        .iter()
        .position(|entry| entry.ranking_id == ranking_id)
        .map(|position| position + 1)
        .unwrap_or_else(|| entries.len().max(1))
}
