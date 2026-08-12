use super::stores::{
    ExperimentStoreError, PromotionReviewStoreError, ReplayRunStoreError, ShadowStoreError,
    VerificationStoreError,
};
use crate::config::{DetectorProfileError, RuntimeConfigError};
use crate::correlation::CorrelationError;
use crate::service::{RuntimeMetricsSnapshot, ServiceError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::ResponseAction;
use swarm_policy::PolicyVerdict;
use swarm_spine::{CorrelatedIncident, InvestigationBundle, InvestigationStoreError, ReplayBundle};
use swarm_whisker::{
    BehavioralAnomalyProfile, CredentialAccessProfile, DnsExfiltrationProfile,
    FilelessExecutionProfile, LateralMovementProfile, NetworkConnectProfile, PersistenceProfile,
    SupplyChainProfile, SuspiciousProcessTreeProfile, SuspiciousScriptingProfile, TelemetryEvent,
};

/// Errors surfaced by offline replay and evaluation flows.
#[derive(Debug, thiserror::Error)]
pub enum ReplayHarnessError {
    #[error(transparent)]
    Config(#[from] RuntimeConfigError),

    #[error(transparent)]
    Service(#[from] ServiceError),

    #[error(transparent)]
    Correlation(#[from] CorrelationError),

    #[error(transparent)]
    DetectorProfile(#[from] DetectorProfileError),

    #[error(transparent)]
    ProfileValidation(#[from] swarm_whisker::ProfileValidationError),

    #[error(transparent)]
    InvestigationStore(#[from] InvestigationStoreError),

    #[error(transparent)]
    Store(#[from] ReplayRunStoreError),

    #[error(transparent)]
    ExperimentStore(#[from] ExperimentStoreError),

    #[error(transparent)]
    VerificationStore(#[from] VerificationStoreError),

    #[error(transparent)]
    ShadowStore(#[from] ShadowStoreError),

    #[error(transparent)]
    PromotionReviewStore(#[from] PromotionReviewStoreError),

    #[error("failed to read replay scenario `{path}`: {source}")]
    ScenarioRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse replay scenario `{path}`: {source}")]
    ScenarioParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("invalid replay scenario `{path}`: {reason}")]
    ScenarioValidation { path: PathBuf, reason: String },

    #[error("failed to read replay suite `{path}`: {source}")]
    SuiteRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse replay suite `{path}`: {source}")]
    SuiteParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("invalid replay suite `{path}`: {reason}")]
    SuiteValidation { path: PathBuf, reason: String },

    #[error("failed to read detector experiment `{path}`: {source}")]
    ExperimentRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse detector experiment `{path}`: {source}")]
    ExperimentParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("invalid detector experiment `{path}`: {reason}")]
    ExperimentValidation { path: PathBuf, reason: String },

    #[error("failed to read verification corpus `{path}`: {source}")]
    VerificationRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse verification corpus `{path}`: {source}")]
    VerificationParse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("invalid verification corpus `{path}`: {reason}")]
    VerificationValidation { path: PathBuf, reason: String },

    #[error("required {kind} artifact `{id}` was not found")]
    ArtifactMissing { kind: &'static str, id: String },

    #[error("invalid promotion review request: {reason}")]
    ReviewValidation { reason: String },

    #[error("failed to read replay bundle fixture `{path}`: {source}")]
    BundleRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse replay bundle fixture `{path}`: {source}")]
    BundleParse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("unsupported detector strategy `{strategy}`")]
    UnsupportedDetector { strategy: String },
}

/// Whether one replay scenario represents adversarial coverage or benign control traffic.
///
/// Deliberately NOT `Default`, and `class` below is deliberately not
/// `#[serde(default)]`. Every safety invariant in `replay::verification` keys
/// off this value: `known_bad_coverage` demands a detection from `Adversarial`
/// scenarios and `false_positive_bound` draws counterexamples from `Benign`
/// ones. `Mixed` satisfies neither predicate, so a scenario carrying it is
/// exempt from both invariants at once and contributes to neither -- it passes
/// without either check ever looking at it, in the lane that signs evidence
/// bundles.
///
/// A default is what made that reachable silently: an omitted `class:` key, a
/// struct literal, or `..Default::default()` all produced `Mixed` with nothing
/// said. There is no safe class to assume for an unclassified scenario, so
/// there is no default. Absence is a deserialization error, and an explicit
/// `Mixed` is refused by `validation::validate_manifest`, so no LOADED manifest
/// can carry it -- which is what the eight other sites that branch on this
/// value (`metrics`, `evasion_coverage`, `red_swarm`, `mutation::fitness`,
/// `evolution::assurance`) rely on, none of them having a check of their own.
///
/// The variant itself is kept because this enum is serialised into persisted
/// evidence artifacts, and removing a variant would make historical bundles
/// that recorded it unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayScenarioClass {
    Benign,
    Adversarial,
    Mixed,
}

/// Repo-owned metadata attached to one tracked replay scenario.
///
/// Not `Default` either, for the same reason: a defaulted metadata block would
/// reintroduce the defaulted class one level up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayScenarioMetadata {
    pub class: ReplayScenarioClass,
    #[serde(default)]
    pub threat_class: Option<ThreatClass>,
    #[serde(default)]
    pub campaign: Option<String>,
    #[serde(default)]
    pub techniques: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Repo-owned metadata attached to a named replay suite.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySuiteMetadata {
    #[serde(default)]
    pub campaign: Option<String>,
    #[serde(default)]
    pub techniques: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Repo-owned replay scenario manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayScenarioManifest {
    pub name: String,
    pub description: String,
    pub seed_time_ms: i64,
    pub requested_by: String,
    #[serde(default)]
    pub receipt_chain: Vec<String>,
    /// Required. A scenario with no metadata block has no class, and a
    /// classless scenario is exempt from every safety invariant -- see
    /// `ReplayScenarioClass`.
    pub metadata: ReplayScenarioMetadata,
    pub input: ReplayScenarioInput,
    #[serde(default)]
    pub expectations: ReplayExpectations,
}

/// Repo-owned manifest describing a named replay suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySuiteManifest {
    pub name: String,
    pub description: String,
    pub corpus_version: String,
    #[serde(default)]
    pub metadata: ReplaySuiteMetadata,
    pub scenarios: Vec<String>,
}

/// Repo-owned verification corpus target referenced by one candidate experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentVerificationTarget {
    pub corpus: String,
}

/// Known-bad coverage source for one verification corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationKnownBadCorpus {
    pub suite: String,
}

/// Benign-control source for one verification corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationBenignControlCorpus {
    pub scenarios: Vec<String>,
}

/// Canonical threat-class template used to prevent detector self-suppression.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationThreatClassTemplate {
    pub name: String,
    pub threat_class: ThreatClass,
    pub event: TelemetryEvent,
}

/// Repo-owned resource budgets for candidate detectors.
///
/// `max_false_positive_rate` and `max_total_detections` are ENFORCED: both are
/// counts and rates over fixture content, so they compute the same value on any
/// machine. `max_detect_latency_us` is ADVISORY -- see its field docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationResourceBudgets {
    pub max_false_positive_rate: f64,
    /// ADVISORY ONLY. Recorded as the reference point for the non-gating
    /// `detect_latency_budget` observation; nothing fails a verification for
    /// exceeding it. The value it is compared against is a wall-clock `Instant`
    /// delta, which measures the machine and the build profile rather than the
    /// candidate. Kept in the schema, and kept at its original value, because
    /// the observation is meaningless without a reference point and because a
    /// trend tool wants the historical series to stay comparable.
    pub max_detect_latency_us: u64,
    pub max_total_detections: usize,
}

/// Repo-owned verification corpus and invariant inputs for candidate detectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationCorpusManifest {
    pub name: String,
    pub description: String,
    pub known_bad: VerificationKnownBadCorpus,
    pub benign_controls: VerificationBenignControlCorpus,
    pub canonical_templates: Vec<VerificationThreatClassTemplate>,
    pub resource_budgets: VerificationResourceBudgets,
}

/// Replay input source for one scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReplayScenarioInput {
    Events { events: Vec<ReplayScenarioStep> },
    ReplayBundles { paths: Vec<String> },
}

impl ReplayScenarioInput {
    pub(super) fn kind(&self) -> ReplayInputKind {
        match self {
            Self::Events { .. } => ReplayInputKind::Events,
            Self::ReplayBundles { .. } => ReplayInputKind::ReplayBundles,
        }
    }
}

/// One replay step driven by a normalized telemetry event and requested response action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayScenarioStep {
    pub action: ResponseAction,
    pub event: TelemetryEvent,
}

/// Expected outcomes for a replay scenario.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayExpectations {
    #[serde(default)]
    pub replay_bundle_count: Option<usize>,
    #[serde(default)]
    pub investigation_count: Option<usize>,
    #[serde(default)]
    pub incident_count: Option<usize>,
    #[serde(default)]
    pub hunts: Vec<ExpectedHuntOutcome>,
    #[serde(default)]
    pub incident_hunt_groups: Vec<Vec<String>>,
    /// ADVISORY ONLY. Recorded as the reference point for the non-gating
    /// `max_detect_latency_us` observation on the evaluation report; no
    /// scenario, suite, or `swarmctl replay-evaluate` exit code fails for
    /// exceeding it.
    ///
    /// The value it is compared against is a wall-clock `Instant` delta
    /// captured in `service::runtime_service`, so it measures the machine, the
    /// build profile, and whatever else the scheduler was running -- not the
    /// fixture. Eight consecutive idle-machine runs of `replay-evaluate` over
    /// the shipped corpus spread 658-888us, a 35% swing, and a single stall
    /// flipped `scenarios/office-dropper-correlation.yaml` from pass to fail on
    /// unchanged code. Contributors are told to run this gate by
    /// `CONTRIBUTING.md` and `README.md`, so the failure landed on people whose
    /// only mistake was owning a slow laptop.
    ///
    /// The Rust field is named for what it does; the manifest key is
    /// deliberately unchanged so that every tracked scenario still loads, keeps
    /// its value, and keeps reporting against it. `deny_unknown_fields` is on
    /// this struct, so dropping the key from the Rust type would have made all
    /// fourteen shipped manifests fail to load outright.
    #[serde(rename = "max_detect_latency_us", default)]
    pub advisory_max_detect_latency_us: Option<u64>,
    /// ADVISORY ONLY -- see [`ReplayExpectations::advisory_max_detect_latency_us`].
    #[serde(rename = "max_policy_latency_us", default)]
    pub advisory_max_policy_latency_us: Option<u64>,
    /// ADVISORY ONLY -- see [`ReplayExpectations::advisory_max_detect_latency_us`].
    #[serde(rename = "max_response_latency_us", default)]
    pub advisory_max_response_latency_us: Option<u64>,
}

/// Expected outcome for one replay hunt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedHuntOutcome {
    pub hunt_id: String,
    pub action_kind: String,
    pub policy_verdict: PolicyVerdict,
    pub response_kind: String,
}

/// Replay input type recorded in the durable result bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayInputKind {
    Events,
    ReplayBundles,
}

/// Stable actual hunt outcome captured from one replay run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActualHuntOutcome {
    pub hunt_id: String,
    pub action_kind: String,
    pub policy_verdict: PolicyVerdict,
    pub response_kind: String,
}

/// Deterministic replay summary used for repeatability checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayDeterministicSummary {
    pub replay_bundle_count: usize,
    pub investigation_count: usize,
    pub incident_count: usize,
    pub hunts: Vec<ActualHuntOutcome>,
    pub incident_hunt_groups: Vec<Vec<String>>,
}

impl ReplayDeterministicSummary {
    pub(super) fn from_outputs(
        replay_bundles: &[ReplayBundle],
        investigations: &[InvestigationBundle],
        incidents: &[CorrelatedIncident],
    ) -> Self {
        let mut hunts = replay_bundles
            .iter()
            .map(|bundle| ActualHuntOutcome {
                hunt_id: bundle.audit.hunt_id.clone(),
                action_kind: bundle.action_kind().to_string(),
                policy_verdict: bundle.audit.policy.verdict,
                response_kind: bundle.audit.response_kind().to_string(),
            })
            .collect::<Vec<_>>();
        hunts.sort_by(|left, right| left.hunt_id.cmp(&right.hunt_id));

        let mut incident_hunt_groups = incidents
            .iter()
            .map(|incident| {
                let mut hunt_ids = incident.included_hunt_ids();
                hunt_ids.sort();
                hunt_ids.dedup();
                hunt_ids
            })
            .collect::<Vec<_>>();
        incident_hunt_groups.sort();

        Self {
            replay_bundle_count: replay_bundles.len(),
            investigation_count: investigations.len(),
            incident_count: incidents.len(),
            hunts,
            incident_hunt_groups,
        }
    }
}

/// Durable replay result bundle written by the offline harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRunBundle {
    pub run_id: String,
    pub scenario_name: String,
    pub scenario_path: String,
    pub description: String,
    pub metadata: ReplayScenarioMetadata,
    pub input_kind: ReplayInputKind,
    pub seed_time_ms: i64,
    pub created_at_ms: i64,
    pub requested_by: String,
    pub expectations: ReplayExpectations,
    pub replay_bundles: Vec<ReplayBundle>,
    pub investigations: Vec<InvestigationBundle>,
    pub incidents: Vec<CorrelatedIncident>,
    pub deterministic_summary: ReplayDeterministicSummary,
    pub performance: RuntimeMetricsSnapshot,
}

/// Metadata surfaced for one persisted replay run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRunRecord {
    pub run_id: String,
    pub scenario_name: String,
    pub input_kind: ReplayInputKind,
    pub created_at_ms: i64,
    pub replay_bundle_count: usize,
    pub investigation_count: usize,
    pub incident_count: usize,
    pub bundle_path: String,
}

impl ReplayRunRecord {
    pub(super) fn from_bundle(bundle: &ReplayRunBundle, bundle_path: String) -> Self {
        Self {
            run_id: bundle.run_id.clone(),
            scenario_name: bundle.scenario_name.clone(),
            input_kind: bundle.input_kind,
            created_at_ms: bundle.created_at_ms,
            replay_bundle_count: bundle.deterministic_summary.replay_bundle_count,
            investigation_count: bundle.deterministic_summary.investigation_count,
            incident_count: bundle.deterministic_summary.incident_count,
            bundle_path,
        }
    }
}

/// Persisted replay run loaded with metadata.
#[derive(Debug, Clone)]
pub struct ReplayRunLookup {
    pub record: ReplayRunRecord,
    pub bundle: ReplayRunBundle,
}

/// Health summary for the replay run store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRunStoreHealth {
    pub backend: String,
    pub durable: bool,
    pub ready: bool,
    pub stored_runs: usize,
    pub details: String,
}

/// One replay evaluation check.
///
/// Everything in this list is GATING: `ReplayEvaluationReport::passed` reduces
/// over it, `ReplaySuiteReport::passed` reduces over that, and
/// `swarmctl replay-evaluate` turns a false into `std::process::exit(1)`. Only
/// checks that are a deterministic function of fixture content belong here --
/// every one of them is an equality against the manifest's expected replay
/// output. A measurement of the machine the replay happened to run on does not
/// -- see [`ReplayEvaluationObservation`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayEvaluationCheck {
    pub name: String,
    pub passed: bool,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub details: String,
}

/// One recorded, NON-GATING measurement taken during a replay evaluation.
///
/// Observations exist so a signal can be kept without letting it decide a
/// verdict. Nothing in the runtime reduces over this collection:
/// `ReplayEvaluationReport::passed` reduces over `checks` only, and
/// `ReplaySuiteReport::passed` counts scenarios whose `passed` is false.
///
/// The distinction is a separate collection rather than a `gating: bool` flag
/// on [`ReplayEvaluationCheck`] for the same reason option F split the
/// verification collections: a flag leaves the measurement sitting inside a
/// list whose name promises verdict inputs, and every present and future
/// consumer has to remember to filter on it. Forgetting fails CLOSED and
/// silently -- here that means `swarmctl replay-evaluate` exiting nonzero on a
/// contributor's machine for code that is fine. Splitting the collection makes
/// the reduce correct by construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayEvaluationObservation {
    pub name: String,
    /// The scenario-manifest budget this measurement is compared against.
    /// ADVISORY ONLY: recorded so a human or a trend tool has a reference
    /// point, never enforced. See
    /// `ReplayExpectations::advisory_max_detect_latency_us`.
    pub advisory_budget: serde_json::Value,
    /// The measurement itself.
    pub observed: serde_json::Value,
    /// Recorded fact, not a verdict: nothing gates on this. It is here so a
    /// trend tool can chart budget breaches without re-deriving the comparison.
    pub within_advisory_budget: bool,
    pub details: String,
}

/// Full evaluation report for one replay run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayEvaluationReport {
    pub run_id: String,
    pub scenario_name: String,
    pub scenario_path: String,
    pub metadata: ReplayScenarioMetadata,
    /// GATING. `passed` is exactly `checks.iter().all(|check| check.passed)`.
    pub passed: bool,
    pub checks: Vec<ReplayEvaluationCheck>,
    /// NON-GATING measurements. `#[serde(default)]` so evaluation reports
    /// persisted before observations existed still load.
    #[serde(default)]
    pub observations: Vec<ReplayEvaluationObservation>,
    pub deterministic_summary: ReplayDeterministicSummary,
    pub performance: RuntimeMetricsSnapshot,
}

/// How a replay suite was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplaySuiteSourceKind {
    ScenariosDir,
    SuiteManifest,
    ScenarioList,
}

/// Per-technique status for one evaluated replay suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayTechniqueGroupReport {
    pub technique: String,
    pub total_scenarios: usize,
    pub failing_scenarios: Vec<String>,
}

/// Per-scenario result within one evaluated replay suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySuiteScenarioReport {
    pub scenario_name: String,
    pub scenario_path: String,
    pub metadata: ReplayScenarioMetadata,
    pub evaluation: ReplayEvaluationReport,
}

/// Suite-level replay evaluation report across a tracked scenario directory or named manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySuiteReport {
    pub source: String,
    pub source_kind: ReplaySuiteSourceKind,
    pub suite_name: Option<String>,
    pub suite_description: Option<String>,
    pub corpus_version: Option<String>,
    pub total_scenarios: usize,
    pub passed_scenarios: usize,
    pub failed_scenarios: usize,
    pub passed: bool,
    pub scenario_reports: Vec<ReplaySuiteScenarioReport>,
    pub technique_groups: Vec<ReplayTechniqueGroupReport>,
}

/// Repo-owned target corpus for one detector experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentCorpusTarget {
    pub suite: String,
}

/// Repo-owned lineage metadata for one detector experiment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentLineage {
    pub parent_strategy_id: String,
    pub mutation: String,
    pub rationale: String,
}

/// Offline safety thresholds for one detector experiment.
///
/// `require_known_bad_coverage` and `max_false_positive_delta` are ENFORCED:
/// both are counts over fixture content, so they compute the same value on any
/// machine. The detect-latency delta is ADVISORY -- see its field docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentGateConfig {
    #[serde(default = "default_require_known_bad_coverage")]
    pub require_known_bad_coverage: bool,
    #[serde(default)]
    pub max_false_positive_delta: i64,
    /// ADVISORY ONLY. Recorded as the reference point for the non-gating
    /// `max_detect_latency_delta_us` observation; no experiment, shadow,
    /// promotion review, or canary admission fails for exceeding it.
    ///
    /// The value it is compared against is a DIFFERENCE OF TWO MAXIMA over
    /// wall-clock `Instant` deltas -- the candidate suite's worst detect
    /// latency minus the baseline suite's. A uniform slowdown cancels out,
    /// which is why this looked safe, but the two suites run one after the
    /// other, so anything that slows down only the second one moves the
    /// difference. On an idle arm64 machine with nothing injected the nominal
    /// spread was already 1327us against the 2000us budget
    /// `experiments/office-python-parent-broadening.yaml` sets.
    ///
    /// The Rust field is named for what it does; the manifest key is
    /// deliberately unchanged so that every existing `gates:` block still
    /// loads, keeps its value, and keeps reporting against it.
    #[serde(
        rename = "max_detect_latency_delta_us",
        default = "default_max_detect_latency_delta_us"
    )]
    pub advisory_max_detect_latency_delta_us: u64,
}

impl Default for ExperimentGateConfig {
    fn default() -> Self {
        Self {
            require_known_bad_coverage: default_require_known_bad_coverage(),
            max_false_positive_delta: 0,
            advisory_max_detect_latency_delta_us: default_max_detect_latency_delta_us(),
        }
    }
}

/// Candidate detector description loaded from a repo-owned manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case")]
pub enum DetectorCandidateManifest {
    SuspiciousProcessTree {
        strategy_id: String,
        description: String,
        profile: SuspiciousProcessTreeProfile,
    },
    FilelessExecution {
        strategy_id: String,
        description: String,
        profile: FilelessExecutionProfile,
    },
    BehavioralAnomaly {
        strategy_id: String,
        description: String,
        profile: BehavioralAnomalyProfile,
    },
    DnsExfiltration {
        strategy_id: String,
        description: String,
        profile: DnsExfiltrationProfile,
    },
    LateralMovement {
        strategy_id: String,
        description: String,
        profile: LateralMovementProfile,
    },
    CredentialAccess {
        strategy_id: String,
        description: String,
        profile: CredentialAccessProfile,
    },
    SuspiciousScripting {
        strategy_id: String,
        description: String,
        profile: SuspiciousScriptingProfile,
    },
    Persistence {
        strategy_id: String,
        description: String,
        profile: PersistenceProfile,
    },
    SupplyChain {
        strategy_id: String,
        description: String,
        profile: SupplyChainProfile,
    },
    NetworkConnect {
        strategy_id: String,
        description: String,
        profile: NetworkConnectProfile,
    },
}

impl DetectorCandidateManifest {
    pub fn strategy_id(&self) -> &str {
        match self {
            Self::SuspiciousProcessTree { strategy_id, .. } => strategy_id.as_str(),
            Self::FilelessExecution { strategy_id, .. } => strategy_id.as_str(),
            Self::BehavioralAnomaly { strategy_id, .. } => strategy_id.as_str(),
            Self::DnsExfiltration { strategy_id, .. } => strategy_id.as_str(),
            Self::LateralMovement { strategy_id, .. } => strategy_id.as_str(),
            Self::CredentialAccess { strategy_id, .. } => strategy_id.as_str(),
            Self::SuspiciousScripting { strategy_id, .. } => strategy_id.as_str(),
            Self::Persistence { strategy_id, .. } => strategy_id.as_str(),
            Self::SupplyChain { strategy_id, .. } => strategy_id.as_str(),
            Self::NetworkConnect { strategy_id, .. } => strategy_id.as_str(),
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Self::SuspiciousProcessTree { description, .. } => description.as_str(),
            Self::FilelessExecution { description, .. } => description.as_str(),
            Self::BehavioralAnomaly { description, .. } => description.as_str(),
            Self::DnsExfiltration { description, .. } => description.as_str(),
            Self::LateralMovement { description, .. } => description.as_str(),
            Self::CredentialAccess { description, .. } => description.as_str(),
            Self::SuspiciousScripting { description, .. } => description.as_str(),
            Self::Persistence { description, .. } => description.as_str(),
            Self::SupplyChain { description, .. } => description.as_str(),
            Self::NetworkConnect { description, .. } => description.as_str(),
        }
    }
}

/// Repo-owned experiment manifest that compares production and candidate detectors offline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorExperimentManifest {
    pub name: String,
    pub description: String,
    pub corpus: ExperimentCorpusTarget,
    pub verification: ExperimentVerificationTarget,
    pub candidate: DetectorCandidateManifest,
    pub lineage: ExperimentLineage,
    #[serde(default)]
    pub gates: ExperimentGateConfig,
}

/// Scenario-level regression surfaced by a detector comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyScenarioRegression {
    pub scenario_name: String,
    pub scenario_path: String,
    pub class: ReplayScenarioClass,
    pub techniques: Vec<String>,
    pub reason: String,
}

/// Technique-level regression summary surfaced by a detector comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyTechniqueRegression {
    pub technique: String,
    pub scenarios: Vec<String>,
}

/// Aggregate detector metrics over one replay suite.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategyExperimentMetrics {
    pub total_scenarios: usize,
    pub adversarial_scenarios: usize,
    pub benign_scenarios: usize,
    pub true_positive_scenarios: usize,
    pub false_negative_scenarios: usize,
    pub true_negative_scenarios: usize,
    pub false_positive_scenarios: usize,
    pub detection_rate: f64,
    pub false_positive_rate: f64,
    pub max_detect_latency_us: u64,
}

/// Delta between baseline and candidate detector metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StrategyExperimentMetricDelta {
    pub detection_rate_delta: f64,
    pub false_positive_rate_delta: f64,
    pub max_detect_latency_delta_us: i64,
    pub false_positive_scenario_delta: i64,
}

/// Comparison summary across baseline and candidate replay suites.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyExperimentComparison {
    pub baseline: StrategyExperimentMetrics,
    pub candidate: StrategyExperimentMetrics,
    pub delta: StrategyExperimentMetricDelta,
    pub scenario_regressions: Vec<StrategyScenarioRegression>,
    pub technique_regressions: Vec<StrategyTechniqueRegression>,
}

/// One offline safety gate verdict for a detector experiment.
///
/// Everything in this list is GATING: `StrategyExperimentReport::passed` and
/// `StrategyShadowReport::passed` reduce over it, `collect_review_blocking_reasons`
/// turns every failure here into a promotion blocker, `canary.rs` refuses
/// admission on a failed shadow, and `pressure_from_experiment` turns every
/// failure into evolution selection pressure. Only gates that are a
/// deterministic function of fixture content belong here. A measurement of the
/// machine the experiment happened to run on does not -- see
/// [`ExperimentObservation`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentGateResult {
    pub name: String,
    pub passed: bool,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub details: String,
}

/// One recorded, NON-GATING measurement taken during a detector experiment.
///
/// Observations exist so a signal can be kept without letting it decide a
/// verdict. Nothing in the runtime reduces over this collection:
/// `StrategyExperimentReport::passed` and `StrategyShadowReport::passed` reduce
/// over `gates` only, `collect_review_blocking_reasons` iterates `gates` only,
/// and `pressure_from_experiment` iterates `gates` only.
///
/// The distinction is a separate collection rather than a `gating: bool` flag
/// on [`ExperimentGateResult`] for the same reason option F split the
/// verification collections: a flag leaves the measurement sitting inside a
/// list whose name promises verdict inputs, and every present and future
/// consumer has to remember to filter on it. Forgetting fails CLOSED and
/// silently -- the candidate is refused canary admission for something that was
/// never its fault. Splitting the collection makes the reduce correct by
/// construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentObservation {
    pub name: String,
    /// The manifest budget this measurement is compared against. ADVISORY
    /// ONLY: recorded so a human or a trend tool has a reference point, never
    /// enforced. See `ExperimentGateConfig::advisory_max_detect_latency_delta_us`.
    pub advisory_budget: serde_json::Value,
    /// The measurement itself.
    pub observed: serde_json::Value,
    /// Recorded fact, not a verdict: nothing gates on this. It is here so a
    /// trend tool can chart budget breaches without re-deriving the comparison.
    pub within_advisory_budget: bool,
    pub details: String,
}

/// Persisted detector experiment report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyExperimentReport {
    pub experiment_id: String,
    pub experiment_name: String,
    pub description: String,
    pub created_at_ms: i64,
    pub suite_name: String,
    pub suite_path: String,
    pub corpus_version: String,
    pub lineage: ExperimentLineage,
    pub baseline_strategy_id: String,
    pub candidate_strategy_id: String,
    pub candidate_description: String,
    pub baseline_report: ReplaySuiteReport,
    pub candidate_report: ReplaySuiteReport,
    pub comparison: StrategyExperimentComparison,
    /// GATING. `passed` is exactly `gates.iter().all(|gate| gate.passed)`.
    pub gates: Vec<ExperimentGateResult>,
    /// NON-GATING measurements. `#[serde(default)]` so experiment reports
    /// persisted before observations existed still load.
    #[serde(default)]
    pub observations: Vec<ExperimentObservation>,
    pub passed: bool,
}

/// Metadata surfaced for one persisted detector experiment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyExperimentRecord {
    pub experiment_id: String,
    pub experiment_name: String,
    pub suite_name: String,
    pub corpus_version: String,
    pub created_at_ms: i64,
    pub passed: bool,
    pub bundle_path: String,
}

impl StrategyExperimentRecord {
    pub(super) fn from_report(report: &StrategyExperimentReport, bundle_path: String) -> Self {
        Self {
            experiment_id: report.experiment_id.clone(),
            experiment_name: report.experiment_name.clone(),
            suite_name: report.suite_name.clone(),
            corpus_version: report.corpus_version.clone(),
            created_at_ms: report.created_at_ms,
            passed: report.passed,
            bundle_path,
        }
    }
}

/// Persisted detector experiment loaded with metadata.
#[derive(Debug, Clone)]
pub struct StrategyExperimentLookup {
    pub record: StrategyExperimentRecord,
    pub report: StrategyExperimentReport,
}

/// One failing reference or counterexample for a verification invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCounterexample {
    pub subject: String,
    pub reference: String,
    pub details: String,
}

/// One verification invariant verdict for a candidate detector.
///
/// Everything in this list is GATING: `DetectorVerificationReport::passed`
/// reduces over it, and `collect_review_blocking_reasons` turns every failure
/// here into a promotion blocker. Only invariants that are a deterministic
/// function of fixture content belong here. A measurement of the machine the
/// verification happened to run on does not -- see [`VerificationObservation`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationInvariantResult {
    pub name: String,
    pub passed: bool,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub details: String,
    pub counterexamples: Vec<VerificationCounterexample>,
}

/// Where a recorded observation's reported value came from, e.g. the single
/// slowest scenario behind a worst-case latency number.
///
/// Deliberately NOT a [`VerificationCounterexample`]: a counterexample is
/// evidence for a failed verdict, and an observation reaches no verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationObservationSource {
    pub subject: String,
    pub reference: String,
    pub details: String,
}

/// One recorded, NON-GATING measurement taken during verification.
///
/// Observations exist so a signal can be kept without letting it decide a
/// verdict. Nothing in the runtime reduces over this collection:
/// `DetectorVerificationReport::passed` reduces over `invariants` only, and
/// `collect_review_blocking_reasons` iterates `invariants` only.
///
/// The distinction is a separate collection rather than a `gating: bool` flag
/// on `VerificationInvariantResult` on purpose. A flag leaves the measurement
/// sitting inside a list whose name promises verdict inputs, and every present
/// and future consumer -- the `passed` reduce, promotion blockers, the formal
/// safety gate, swarmctl, the assurance-case reports -- has to remember to
/// filter on it. Forgetting fails CLOSED and silently: the candidate is
/// rejected for something that was never its fault. Splitting the collection
/// makes the reduce correct by construction, and a consumer that has not heard
/// of observations simply does not see latency instead of wrongly gating on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationObservation {
    pub name: String,
    /// The corpus budget this measurement is compared against. ADVISORY ONLY:
    /// recorded so a human or a trend tool has a reference point, never
    /// enforced. See `verifications/office-detector-safety-v1.yaml`.
    pub advisory_budget: serde_json::Value,
    /// The measurement itself.
    pub observed: serde_json::Value,
    /// Recorded fact, not a verdict: nothing gates on this. It is here so a
    /// trend tool can chart budget breaches without re-deriving the comparison.
    pub within_advisory_budget: bool,
    pub details: String,
    pub sources: Vec<VerificationObservationSource>,
}

/// Persisted candidate-verification report derived from one experiment plus a verification corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorVerificationReport {
    pub verification_id: String,
    pub experiment_id: String,
    pub experiment_name: String,
    pub corpus_name: String,
    pub corpus_path: String,
    pub created_at_ms: i64,
    pub lineage: ExperimentLineage,
    pub candidate_strategy_id: String,
    pub candidate_description: String,
    /// GATING. `passed` is exactly `invariants.iter().all(|i| i.passed)`.
    pub invariants: Vec<VerificationInvariantResult>,
    /// NON-GATING measurements. `#[serde(default)]` so verification reports
    /// persisted before observations existed still load.
    #[serde(default)]
    pub observations: Vec<VerificationObservation>,
    pub passed: bool,
}

/// Metadata surfaced for one persisted verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorVerificationRecord {
    pub verification_id: String,
    pub experiment_id: String,
    pub candidate_strategy_id: String,
    pub corpus_name: String,
    pub created_at_ms: i64,
    pub passed: bool,
    pub bundle_path: String,
}

impl DetectorVerificationRecord {
    pub(super) fn from_report(report: &DetectorVerificationReport, bundle_path: String) -> Self {
        Self {
            verification_id: report.verification_id.clone(),
            experiment_id: report.experiment_id.clone(),
            candidate_strategy_id: report.candidate_strategy_id.clone(),
            corpus_name: report.corpus_name.clone(),
            created_at_ms: report.created_at_ms,
            passed: report.passed,
            bundle_path,
        }
    }
}

/// Persisted verification report loaded with metadata.
#[derive(Debug, Clone)]
pub struct DetectorVerificationLookup {
    pub record: DetectorVerificationRecord,
    pub report: DetectorVerificationReport,
}

/// Persisted shadow-comparison report derived from one offline experiment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyShadowReport {
    pub shadow_id: String,
    pub experiment_id: String,
    pub experiment_name: String,
    pub created_at_ms: i64,
    pub source_artifacts: Vec<String>,
    pub suite_name: String,
    pub suite_path: String,
    pub corpus_version: String,
    pub lineage: ExperimentLineage,
    pub baseline_strategy_id: String,
    pub candidate_strategy_id: String,
    pub candidate_description: String,
    pub comparison: StrategyExperimentComparison,
    /// GATING. Copied from the experiment report; `passed` reduces over it.
    pub gates: Vec<ExperimentGateResult>,
    /// NON-GATING measurements copied from the experiment report.
    /// `#[serde(default)]` so shadow reports persisted before observations
    /// existed still load.
    #[serde(default)]
    pub observations: Vec<ExperimentObservation>,
    pub passed: bool,
}

/// Metadata surfaced for one persisted shadow report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyShadowRecord {
    pub shadow_id: String,
    pub experiment_id: String,
    pub candidate_strategy_id: String,
    pub suite_name: String,
    pub corpus_version: String,
    pub created_at_ms: i64,
    pub passed: bool,
    pub bundle_path: String,
}

impl StrategyShadowRecord {
    pub(super) fn from_report(report: &StrategyShadowReport, bundle_path: String) -> Self {
        Self {
            shadow_id: report.shadow_id.clone(),
            experiment_id: report.experiment_id.clone(),
            candidate_strategy_id: report.candidate_strategy_id.clone(),
            suite_name: report.suite_name.clone(),
            corpus_version: report.corpus_version.clone(),
            created_at_ms: report.created_at_ms,
            passed: report.passed,
            bundle_path,
        }
    }
}

/// Persisted shadow report loaded with metadata.
#[derive(Debug, Clone)]
pub struct StrategyShadowLookup {
    pub record: StrategyShadowRecord,
    pub report: StrategyShadowReport,
}

/// Final operator recommendation for one promotion review packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionReviewRecommendation {
    ReadyForManualReview,
    Blocked,
}

/// One blocking reason preserved in a promotion review packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionReviewBlockingReason {
    pub source: String,
    pub name: String,
    pub details: String,
    pub references: Vec<String>,
}

/// Durable operator-facing packet tying verification and shadow evidence together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionReviewPacket {
    pub review_id: String,
    pub experiment_id: String,
    pub experiment_name: String,
    pub created_at_ms: i64,
    pub suite_name: String,
    pub corpus_version: String,
    pub lineage: ExperimentLineage,
    pub candidate_strategy_id: String,
    pub candidate_description: String,
    pub verification_id: String,
    pub verification_passed: bool,
    pub shadow_id: String,
    pub shadow_passed: bool,
    pub detection_rate_delta: f64,
    pub false_positive_rate_delta: f64,
    pub max_detect_latency_delta_us: i64,
    pub recommendation: PromotionReviewRecommendation,
    pub blocking_reasons: Vec<PromotionReviewBlockingReason>,
}

/// Metadata surfaced for one persisted promotion review packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionReviewRecord {
    pub review_id: String,
    pub experiment_id: String,
    pub candidate_strategy_id: String,
    pub corpus_version: String,
    pub created_at_ms: i64,
    pub ready_for_review: bool,
    pub bundle_path: String,
}

impl PromotionReviewRecord {
    pub(super) fn from_packet(packet: &PromotionReviewPacket, bundle_path: String) -> Self {
        Self {
            review_id: packet.review_id.clone(),
            experiment_id: packet.experiment_id.clone(),
            candidate_strategy_id: packet.candidate_strategy_id.clone(),
            corpus_version: packet.corpus_version.clone(),
            created_at_ms: packet.created_at_ms,
            ready_for_review: packet.recommendation
                == PromotionReviewRecommendation::ReadyForManualReview,
            bundle_path,
        }
    }
}

/// Persisted promotion review packet loaded with metadata.
#[derive(Debug, Clone)]
pub struct PromotionReviewLookup {
    pub record: PromotionReviewRecord,
    pub packet: PromotionReviewPacket,
}

#[derive(Debug, Clone)]
pub struct LoadedReplayScenario {
    pub path: PathBuf,
    pub manifest: ReplayScenarioManifest,
}

#[derive(Debug, Clone)]
pub(super) struct LoadedReplaySuite {
    pub(super) path: PathBuf,
    pub(super) manifest: ReplaySuiteManifest,
}

#[derive(Debug, Clone)]
pub(super) struct LoadedDetectorExperiment {
    pub(super) path: PathBuf,
    pub(super) manifest: DetectorExperimentManifest,
}

fn default_require_known_bad_coverage() -> bool {
    true
}

fn default_max_detect_latency_delta_us() -> u64 {
    2_000
}
