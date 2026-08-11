use crate::canary::{CanaryError, DefaultCanaryHarness};
use crate::config::{RuntimeConfigError, load_config};
use crate::evasion_coverage::{
    actionable_gaps_for_detector, evaluate_repo_evasion_coverage, resolve_repo_root,
};
use crate::replay::{
    DefaultReplayHarness, DetectorCandidateManifest, DetectorExperimentManifest,
    DetectorVerificationLookup, DetectorVerificationReport, ExperimentLineage, FileShadowStore,
    FileVerificationStore, ReplayExpectations, ReplayHarnessError, ReplayScenarioClass,
    ReplayScenarioInput, ReplayScenarioManifest, ReplayScenarioMetadata, ReplaySuiteManifest,
    ShadowStoreError, StrategyShadowLookup, StrategyShadowReport, VerificationCounterexample,
    VerificationStoreError, load_detector_experiment_manifest, load_replay_suite_manifest,
    load_scenario_manifest, load_verification_manifest, resolve_manifest_relative_path,
};
use crate::strategy::{
    DefaultStrategyScorecardHarness, StrategyAdvisorError, StrategyAdvisoryRecommendation,
    StrategyRolloutStateSummary, StrategyScorecard,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::{EvolutionAssuranceSolverStatusConfig, SwarmConfig};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::AgentId;
use swarm_crypto::{
    DetachedSignature, Ed25519Signer, canonical_json_bytes, verify_detached_signature,
};
#[cfg(feature = "z3")]
use z3::{Config as Z3Config, Params as Z3Params, SatResult, Solver as Z3Solver, with_z3_config};

const DEFAULT_Z3_TIMEOUT_MS: u64 = 30_000;

#[path = "evolution/assurance.rs"]
mod assurance;
#[path = "evolution/formal_safety.rs"]
mod formal_safety;
#[path = "evolution/harnesses.rs"]
mod harnesses;
#[path = "evolution/helpers.rs"]
mod helpers;
#[path = "evolution/render.rs"]
mod render;
#[path = "evolution/stores.rs"]
mod stores;
#[cfg(test)]
#[path = "evolution/tests.rs"]
mod tests;
#[path = "evolution/types.rs"]
mod types;

pub use formal_safety::{DefaultEvolutionProofHarness, DefaultFormalSafetyGate};
pub use harnesses::{DefaultEvolutionHandoffHarness, DefaultEvolutionQueueHarness};
pub use render::{
    render_evolution_handoff, render_evolution_proof, render_evolution_proposal,
    render_evolution_proposal_list,
};
pub use stores::{
    EvolutionAssuranceCaseStoreError, EvolutionHandoffStoreError, EvolutionProposalStoreError,
    FileEvolutionHandoffStore, FileEvolutionProofStore, FileEvolutionProposalStore,
};
pub use types::*;

pub(crate) use assurance::*;
pub(crate) use helpers::*;
pub(crate) use stores::FileEvolutionAssuranceCaseStore;
