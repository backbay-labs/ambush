use crate::detector_factory::{DetectorFactoryError, build_detector_from_candidate};
use crate::drafting::{
    DefaultEvolutionDraftingHarness, EvolutionDraftMaterializationRequest,
    EvolutionDraftPromotionStoreError, EvolutionDraftingError, EvolutionMaterializationLookup,
    EvolutionMaterializationReport, EvolutionMaterializationStoreError, EvolutionPressureReport,
    EvolutionPressureSourceKind, EvolutionValidationBundleStatus,
};
use crate::evolution::{EvolutionProposalAdvisorySummary, EvolutionProposalProofStatus};
use crate::evolution::{
    EvolutionProposalReviewState, EvolutionProposalStoreError, FileEvolutionProposalStore,
};
use crate::replay::{
    DefaultReplayHarness, DetectorCandidateManifest, DetectorExperimentManifest,
    DetectorVerificationReport, ExperimentLineage, ExperimentStoreError, FileExperimentStore,
    FileVerificationStore, ReplayHarnessError, ReplayScenarioClass, ReplayScenarioInput,
    StrategyExperimentReport, VerificationStoreError, load_detector_experiment_manifest,
    load_replay_suite_manifest, load_scenario_manifest, load_verification_manifest,
    resolve_manifest_relative_path,
};
use crate::strategy::{
    DefaultStrategyScorecardHarness, StrategyAdvisorError, StrategyAdvisoryRecommendation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::EvolutionFitnessWeightsConfig;
use swarm_core::pheromone::ThreatClass;
use swarm_whisker::{
    DetectionStrategy, SuspiciousProcessTreeProfile, TelemetryEvent, TelemetryPayload,
};

const ADVERSARIAL_PRESSURE_BLEND_WEIGHT: f64 = 0.20;
const EVASION_PRESSURE_BLEND_WEIGHT: f64 = 0.20;

#[path = "mutation/autonomous.rs"]
mod autonomous;
#[path = "mutation/fitness.rs"]
mod fitness;
#[path = "mutation/harness.rs"]
mod harness;
#[path = "mutation/helpers.rs"]
mod helpers;
#[path = "mutation/render.rs"]
mod render;
#[path = "mutation/stores.rs"]
mod stores;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "mutation/test_support.rs"]
mod test_support;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "mutation/tests_autonomous.rs"]
mod tests_autonomous;
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "mutation/tests_core.rs"]
mod tests_core;
#[path = "mutation/types.rs"]
mod types;

pub use fitness::summarize_evolution_benchmark_baseline;
pub use harness::DefaultEvolutionMutationHarness;
pub use render::*;
pub use stores::*;
pub use types::*;

pub(crate) use autonomous::*;
pub(crate) use fitness::*;
pub(crate) use helpers::*;
