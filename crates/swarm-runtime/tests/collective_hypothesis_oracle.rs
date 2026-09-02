//! Independent truth contract for the collective-hypothesis benchmark.
//!
//! Production graph code does not define or repair this oracle. Later plans
//! consume these strict fixtures and must fail if their bytes or semantics move.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use serde::Deserialize;
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST_REL: &str = "scenarios/collective-hypothesis-graph/manifest.yaml";
const BASELINE_REL: &str = "docs/benchmarks/collective-hypothesis-graph-baseline.json";
const EXPECTED_FAMILIES: [SourceFamily; 6] = [
    SourceFamily::Process,
    SourceFamily::Identity,
    SourceFamily::Kubernetes,
    SourceFamily::Cloudtrail,
    SourceFamily::Network,
    SourceFamily::ThreatIntelligence,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceFamily {
    Process,
    Identity,
    Kubernetes,
    Cloudtrail,
    Network,
    ThreatIntelligence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScenarioClass {
    TrainingAttack,
    WithheldAttack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StageStatus {
    Observed,
    MissingEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogicalClock {
    origin_ms: i64,
    tick_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceContract {
    family: SourceFamily,
    corroborating_evidence_id: String,
    conflicting_evidence_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct TruthContract {
    hypothesis_ids: Vec<String>,
    selected_hypothesis_id: String,
    node_ids: Vec<String>,
    causal_edge_ids: Vec<String>,
    kill_chain_stage_ids: Vec<String>,
    required_evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaneContract {
    lane_id: String,
    max_investigators: u16,
    adaptive_task_allocation: bool,
    corpus_digest_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaneControls {
    single_agent: LaneContract,
    collective: LaneContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusLimits {
    max_nodes: usize,
    max_edges: usize,
    max_evidence_bytes: usize,
    max_tasks: usize,
    max_virtual_ms: u64,
    max_work_units: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricDenominators {
    adjudicated_cases: u64,
    attack_chain_stages: u64,
    causal_edges: u64,
    logical_tasks: u64,
    evidence_claims: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricThresholds {
    min_hypothesis_time_reduction_bps: u16,
    min_attack_chain_recall_gain_bps: u16,
    max_false_causal_edge_rate_bps: u16,
    max_duplicate_work_rate_bps: u16,
    min_evidence_coverage_bps: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricContract {
    denominators: MetricDenominators,
    thresholds: MetricThresholds,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkManifest {
    schema_version: u32,
    corpus_id: String,
    corpus_version: u32,
    seed: u64,
    logical_clock: LogicalClock,
    training_fixture: String,
    withheld_fixture: String,
    source_contracts: Vec<SourceContract>,
    truth: TruthContract,
    controls: LaneControls,
    limits: CorpusLimits,
    metrics: MetricContract,
    task_identities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureEvent {
    event_id: String,
    evidence_id: String,
    source_family: SourceFamily,
    logical_time_ms: i64,
    signal_kind: String,
    supports: Vec<String>,
    refutes: Vec<String>,
    entity_ids: Vec<String>,
    relation_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureStage {
    stage_id: String,
    status: StageStatus,
    evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioFixture {
    schema_version: u32,
    scenario_id: String,
    class: ScenarioClass,
    seed_time_ms: i64,
    hypothesis_ids: Vec<String>,
    events: Vec<FixtureEvent>,
    expected_kill_chain: Vec<FixtureStage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OracleDigests {
    manifest_sha256: String,
    ambiguous_fixture_sha256: String,
    withheld_fixture_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct SingleAgentBaseline {
    median_hypothesis_time_ms: u64,
    attack_chain_recall_bps: u16,
    false_causal_edge_rate_bps: u16,
    duplicate_work_rate_bps: u16,
    evidence_coverage_bps: u16,
    logical_work_units: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkBaseline {
    schema_version: u32,
    corpus_id: String,
    corpus_version: u32,
    oracle_digests: OracleDigests,
    denominators: MetricDenominators,
    thresholds: MetricThresholds,
    single_agent_baseline: SingleAgentBaseline,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("swarm-runtime has a crates parent")
        .parent()
        .expect("crates has a repository parent")
        .to_path_buf()
}

fn parse_yaml<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    serde_yaml::from_str(&fs::read_to_string(path).expect("fixture must be readable"))
        .expect("fixture must match the strict schema")
}

fn parse_json<T: for<'de> Deserialize<'de>>(path: &Path) -> T {
    serde_json::from_str(&fs::read_to_string(path).expect("baseline must be readable"))
        .expect("baseline must match the strict schema")
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn all_unique(values: impl IntoIterator<Item = String>) -> bool {
    let values = values.into_iter().collect::<Vec<_>>();
    values.iter().cloned().collect::<BTreeSet<_>>().len() == values.len()
}

fn nonempty_unique(values: &[String], label: &str) -> Result<(), String> {
    if values.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if !all_unique(values.to_vec()) {
        return Err(format!("{label} contains a duplicate"));
    }
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(format!("{label} contains an empty identifier"));
    }
    Ok(())
}

fn validate_fixture(
    fixture: &ScenarioFixture,
    expected_class: ScenarioClass,
    manifest: &BenchmarkManifest,
) -> Result<(), String> {
    if fixture.schema_version != 1 || fixture.class != expected_class {
        return Err("fixture schema or class mismatch".to_string());
    }
    nonempty_unique(&fixture.hypothesis_ids, "fixture hypothesis IDs")?;
    if fixture.hypothesis_ids != manifest.truth.hypothesis_ids {
        return Err("fixture hypothesis set drifted from truth".to_string());
    }
    nonempty_unique(
        &fixture
            .events
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>(),
        "event IDs",
    )?;
    nonempty_unique(
        &fixture
            .events
            .iter()
            .map(|event| event.evidence_id.clone())
            .collect::<Vec<_>>(),
        "evidence IDs",
    )?;
    if fixture.events.is_empty() || fixture.expected_kill_chain.is_empty() {
        return Err("fixture must contain events and kill-chain stages".to_string());
    }
    let max_time = fixture
        .seed_time_ms
        .checked_add(manifest.limits.max_virtual_ms as i64)
        .ok_or_else(|| "virtual clock overflows".to_string())?;
    let mut prior_time = fixture.seed_time_ms;
    for event in &fixture.events {
        if event.signal_kind.trim().is_empty()
            || event.supports.is_empty()
            || event.refutes.is_empty()
            || event.entity_ids.is_empty()
        {
            return Err(format!("event {} is vacuous", event.event_id));
        }
        if event.logical_time_ms <= prior_time || event.logical_time_ms > max_time {
            return Err(format!("event {} has invalid logical time", event.event_id));
        }
        prior_time = event.logical_time_ms;
        if event
            .supports
            .iter()
            .chain(event.refutes.iter())
            .any(|id| !fixture.hypothesis_ids.contains(id))
        {
            return Err(format!(
                "event {} names an unknown hypothesis",
                event.event_id
            ));
        }
        if event.supports.iter().any(|id| event.refutes.contains(id)) {
            return Err(format!(
                "event {} both supports and refutes a hypothesis",
                event.event_id
            ));
        }
    }
    let expected_stages = manifest
        .truth
        .kill_chain_stage_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let actual_stages = fixture
        .expected_kill_chain
        .iter()
        .map(|stage| stage.stage_id.clone())
        .collect::<BTreeSet<_>>();
    if expected_stages != actual_stages || actual_stages.len() != fixture.expected_kill_chain.len()
    {
        return Err("kill-chain stages are incomplete or duplicated".to_string());
    }
    let evidence = fixture
        .events
        .iter()
        .map(|event| event.evidence_id.as_str())
        .collect::<BTreeSet<_>>();
    for stage in &fixture.expected_kill_chain {
        match stage.status {
            StageStatus::Observed if stage.evidence_ids.is_empty() => {
                return Err(format!("observed stage {} has no evidence", stage.stage_id));
            }
            StageStatus::MissingEvidence if !stage.evidence_ids.is_empty() => {
                return Err(format!("missing stage {} claims evidence", stage.stage_id));
            }
            _ => {}
        }
        if stage
            .evidence_ids
            .iter()
            .any(|id| !evidence.contains(id.as_str()))
        {
            return Err(format!("stage {} names absent evidence", stage.stage_id));
        }
    }
    Ok(())
}

fn validate_manifest_and_corpus(
    manifest: &BenchmarkManifest,
    training: &ScenarioFixture,
    withheld: &ScenarioFixture,
) -> Result<(), String> {
    if manifest.schema_version != 1
        || manifest.corpus_id != "collective-hypothesis-graph-v1"
        || manifest.corpus_version != 1
        || manifest.seed == 0
        || manifest.logical_clock.origin_ms <= 0
        || manifest.logical_clock.tick_ms == 0
    {
        return Err("manifest identity or logical clock is invalid".to_string());
    }
    if Path::new(&manifest.training_fixture).is_absolute()
        || Path::new(&manifest.withheld_fixture).is_absolute()
        || manifest.training_fixture.contains("..")
        || manifest.withheld_fixture.contains("..")
    {
        return Err("fixture paths must remain repository-relative".to_string());
    }
    let families = manifest
        .source_contracts
        .iter()
        .map(|contract| contract.family)
        .collect::<Vec<_>>();
    if families.iter().copied().collect::<BTreeSet<_>>()
        != EXPECTED_FAMILIES.into_iter().collect::<BTreeSet<_>>()
        || families.len() != EXPECTED_FAMILIES.len()
    {
        return Err("source families are missing or duplicated".to_string());
    }
    nonempty_unique(&manifest.truth.hypothesis_ids, "truth hypothesis IDs")?;
    nonempty_unique(&manifest.truth.node_ids, "truth node IDs")?;
    nonempty_unique(&manifest.truth.causal_edge_ids, "truth edge IDs")?;
    nonempty_unique(
        &manifest.truth.kill_chain_stage_ids,
        "truth kill-chain stage IDs",
    )?;
    nonempty_unique(&manifest.truth.required_evidence_ids, "truth evidence IDs")?;
    if manifest.truth.hypothesis_ids.len() < 2
        || !manifest
            .truth
            .hypothesis_ids
            .contains(&manifest.truth.selected_hypothesis_id)
    {
        return Err("truth must retain competing hypotheses and a valid selection".to_string());
    }
    if manifest.task_identities.len() != 100
        || !all_unique(manifest.task_identities.clone())
        || manifest
            .task_identities
            .iter()
            .enumerate()
            .any(|(index, id)| id != &format!("task:edge:{index:03}"))
    {
        return Err("the corpus must contain exactly 100 stable task identities".to_string());
    }
    let limits = &manifest.limits;
    if limits.max_nodes == 0
        || limits.max_nodes > 4096
        || limits.max_edges == 0
        || limits.max_edges > 8192
        || limits.max_evidence_bytes == 0
        || limits.max_evidence_bytes > 16 * 1024 * 1024
        || limits.max_tasks < manifest.task_identities.len()
        || limits.max_tasks > 4096
        || limits.max_virtual_ms == 0
        || limits.max_virtual_ms > 3_600_000
        || limits.max_work_units == 0
        || limits.max_work_units > 1_000_000
    {
        return Err("resource limits are zero, inconsistent, or unbounded".to_string());
    }
    let denominators = &manifest.metrics.denominators;
    if denominators.adjudicated_cases == 0
        || denominators.attack_chain_stages != manifest.truth.kill_chain_stage_ids.len() as u64
        || denominators.causal_edges != manifest.truth.causal_edge_ids.len() as u64
        || denominators.logical_tasks != manifest.task_identities.len() as u64
        || denominators.evidence_claims == 0
    {
        return Err("metric denominators are missing or inconsistent".to_string());
    }
    let thresholds = &manifest.metrics.thresholds;
    if thresholds.min_hypothesis_time_reduction_bps != 2_000
        || thresholds.min_attack_chain_recall_gain_bps != 1_000
        || thresholds.max_false_causal_edge_rate_bps != 1_000
        || thresholds.max_duplicate_work_rate_bps != 500
        || thresholds.min_evidence_coverage_bps != 9_000
    {
        return Err("acceptance thresholds drifted".to_string());
    }
    if manifest.controls.single_agent.max_investigators != 1
        || manifest.controls.single_agent.adaptive_task_allocation
        || manifest.controls.collective.max_investigators < 2
        || !manifest.controls.collective.adaptive_task_allocation
        || manifest.controls.single_agent.corpus_digest_ref != manifest.corpus_id
        || manifest.controls.collective.corpus_digest_ref != manifest.corpus_id
        || manifest.controls.single_agent.lane_id == manifest.controls.collective.lane_id
    {
        return Err("paired control lanes are not comparable".to_string());
    }
    validate_fixture(training, ScenarioClass::TrainingAttack, manifest)?;
    validate_fixture(withheld, ScenarioClass::WithheldAttack, manifest)?;
    if training.scenario_id == withheld.scenario_id {
        return Err("training and withheld scenario IDs overlap".to_string());
    }
    let training_evidence = training
        .events
        .iter()
        .map(|event| event.evidence_id.clone())
        .collect::<BTreeSet<_>>();
    let withheld_evidence = withheld
        .events
        .iter()
        .map(|event| event.evidence_id.clone())
        .collect::<BTreeSet<_>>();
    if !training_evidence.is_disjoint(&withheld_evidence) {
        return Err("training and withheld evidence overlap".to_string());
    }
    let training_by_evidence = training
        .events
        .iter()
        .map(|event| (event.evidence_id.as_str(), event))
        .collect::<BTreeMap<_, _>>();
    for contract in &manifest.source_contracts {
        let support = training_by_evidence
            .get(contract.corroborating_evidence_id.as_str())
            .ok_or_else(|| format!("{:?} lacks corroborating evidence", contract.family))?;
        let conflict = training_by_evidence
            .get(contract.conflicting_evidence_id.as_str())
            .ok_or_else(|| format!("{:?} lacks conflicting evidence", contract.family))?;
        if support.source_family != contract.family
            || conflict.source_family != contract.family
            || !support
                .supports
                .contains(&manifest.truth.selected_hypothesis_id)
            || !conflict
                .refutes
                .contains(&manifest.truth.selected_hypothesis_id)
        {
            return Err(format!(
                "{:?} support/conflict semantics drifted",
                contract.family
            ));
        }
    }
    let all_evidence = training_evidence
        .union(&withheld_evidence)
        .cloned()
        .collect::<BTreeSet<_>>();
    if denominators.evidence_claims != all_evidence.len() as u64
        || manifest
            .truth
            .required_evidence_ids
            .iter()
            .any(|id| !all_evidence.contains(id))
    {
        return Err("truth evidence or its denominator is incomplete".to_string());
    }
    if withheld
        .expected_kill_chain
        .iter()
        .filter(|stage| stage.status == StageStatus::MissingEvidence)
        .count()
        != 1
    {
        return Err("withheld fixture must contain one explicit evidence gap".to_string());
    }
    Ok(())
}

fn validate_baseline(
    root: &Path,
    manifest: &BenchmarkManifest,
    baseline: &BenchmarkBaseline,
) -> Result<(), String> {
    if baseline.schema_version != 1
        || baseline.corpus_id != manifest.corpus_id
        || baseline.corpus_version != manifest.corpus_version
        || baseline.denominators != manifest.metrics.denominators
        || baseline.thresholds != manifest.metrics.thresholds
    {
        return Err("baseline contract drifted from the manifest".to_string());
    }
    let digest_pairs = [
        (
            MANIFEST_REL,
            baseline.oracle_digests.manifest_sha256.as_str(),
        ),
        (
            manifest.training_fixture.as_str(),
            baseline.oracle_digests.ambiguous_fixture_sha256.as_str(),
        ),
        (
            manifest.withheld_fixture.as_str(),
            baseline.oracle_digests.withheld_fixture_sha256.as_str(),
        ),
    ];
    for (relative, expected) in digest_pairs {
        let actual = sha256(&fs::read(root.join(relative)).map_err(|error| error.to_string())?);
        if actual != expected || expected.len() != 64 {
            return Err(format!("oracle digest mismatch for {relative}"));
        }
    }
    let control = &baseline.single_agent_baseline;
    if control.median_hypothesis_time_ms == 0
        || control.logical_work_units == 0
        || [
            control.attack_chain_recall_bps,
            control.false_causal_edge_rate_bps,
            control.duplicate_work_rate_bps,
            control.evidence_coverage_bps,
        ]
        .into_iter()
        .any(|value| value > 10_000)
    {
        return Err("single-agent baseline is incomplete or out of range".to_string());
    }
    Ok(())
}

fn remove_nested(mapping: &mut Mapping, path: &[&str]) {
    let key = Value::String(path[0].to_string());
    if path.len() == 1 {
        mapping.remove(&key);
        return;
    }
    let child = mapping
        .get_mut(&key)
        .and_then(Value::as_mapping_mut)
        .expect("mutation path must exist");
    remove_nested(child, &path[1..]);
}

#[test]
fn benchmark_manifest_is_strict() {
    let root = repo_root();
    let manifest_path = root.join(MANIFEST_REL);
    let manifest_text = fs::read_to_string(&manifest_path).expect("manifest must exist");
    let manifest: BenchmarkManifest =
        serde_yaml::from_str(&manifest_text).expect("manifest must match strict schema");
    let training: ScenarioFixture = parse_yaml(&root.join(&manifest.training_fixture));
    let withheld: ScenarioFixture = parse_yaml(&root.join(&manifest.withheld_fixture));
    let baseline: BenchmarkBaseline = parse_json(&root.join(BASELINE_REL));

    validate_manifest_and_corpus(&manifest, &training, &withheld)
        .expect("checked-in semantic oracle must be complete");
    validate_baseline(&root, &manifest, &baseline)
        .expect("checked-in baseline must bind exact oracle bytes");

    let mut missing_family = manifest.clone();
    missing_family.source_contracts.pop();
    assert!(validate_manifest_and_corpus(&missing_family, &training, &withheld).is_err());

    let mut duplicate_family = manifest.clone();
    duplicate_family
        .source_contracts
        .push(duplicate_family.source_contracts[0].clone());
    assert!(validate_manifest_and_corpus(&duplicate_family, &training, &withheld).is_err());

    let mut duplicate_id = manifest.clone();
    duplicate_id.task_identities[99] = duplicate_id.task_identities[0].clone();
    assert!(validate_manifest_and_corpus(&duplicate_id, &training, &withheld).is_err());

    let mut absent_truth = manifest.clone();
    absent_truth.truth.causal_edge_ids.clear();
    assert!(validate_manifest_and_corpus(&absent_truth, &training, &withheld).is_err());

    let mut overlapping_withheld = withheld.clone();
    overlapping_withheld.events[0].evidence_id = training.events[0].evidence_id.clone();
    assert!(validate_manifest_and_corpus(&manifest, &training, &overlapping_withheld).is_err());

    let mut unbounded = manifest.clone();
    unbounded.limits.max_work_units = usize::MAX;
    assert!(validate_manifest_and_corpus(&unbounded, &training, &withheld).is_err());

    let mut missing_denominator: Value = serde_yaml::from_str(&manifest_text).unwrap();
    remove_nested(
        missing_denominator.as_mapping_mut().unwrap(),
        &["metrics", "denominators", "causal_edges"],
    );
    assert!(
        serde_yaml::from_value::<BenchmarkManifest>(missing_denominator).is_err(),
        "a missing metric denominator must fail deserialization"
    );

    let mut missing_threshold: Value = serde_yaml::from_str(&manifest_text).unwrap();
    remove_nested(
        missing_threshold.as_mapping_mut().unwrap(),
        &["metrics", "thresholds", "min_hypothesis_time_reduction_bps"],
    );
    assert!(
        serde_yaml::from_value::<BenchmarkManifest>(missing_threshold).is_err(),
        "a missing acceptance threshold must fail deserialization"
    );

    let mut unknown_field: Value = serde_yaml::from_str(&manifest_text).unwrap();
    unknown_field.as_mapping_mut().unwrap().insert(
        Value::String("implementation_override".to_string()),
        Value::Bool(true),
    );
    assert!(
        serde_yaml::from_value::<BenchmarkManifest>(unknown_field).is_err(),
        "unknown oracle fields must fail closed"
    );

    let baseline_text = fs::read_to_string(root.join(BASELINE_REL)).unwrap();
    let mut baseline_value: serde_json::Value = serde_json::from_str(&baseline_text).unwrap();
    baseline_value.as_object_mut().unwrap().insert(
        "implementation_override".to_string(),
        serde_json::json!(true),
    );
    assert!(serde_json::from_value::<BenchmarkBaseline>(baseline_value).is_err());

    let mut tampered_baseline = baseline.clone();
    tampered_baseline.oracle_digests.ambiguous_fixture_sha256 = sha256(b"tampered");
    assert!(validate_baseline(&root, &manifest, &tampered_baseline).is_err());
}
