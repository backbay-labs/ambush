use crate::alert_tuning::{AlertTuningReport, build_alert_tuning_report};
use crate::bridge_runtime::BridgeStatusReport;
use crate::config::{DetectorProfileError, RuntimeConfig, kill_chain_sequence_profile};
use crate::correlation::{CorrelationEngine, CorrelationError, CorrelationOutcome};
use crate::detection::metrics::CriticalPathMetrics;
use crate::detection::pipeline::{
    DetectionPipelineOutcome, PipelineError, detect_and_deposit, infer_agent_role,
    persist_findings_as_deposits,
};
use crate::evolution_status::EvolutionStatusReport;
use crate::investigation::{
    InvestigationCoordinator, InvestigationError, InvestigationQueueSnapshot, InvestigationStrategy,
};
use crate::providence::{PROVIDENCE_CHANNEL, ProvidenceHealthStatus};
use crate::runtime_events::{AsyncLaneStatusLevel, AsyncLaneStatusSnapshot, now_ms};
use crate::sequence_detector::{
    KILL_CHAIN_SEQUENCE_STRATEGY_ID, KillChainSequenceDetector, KillChainSequenceDetectorError,
};
use crate::{RuntimeError, RuntimeMode, SwarmRuntime};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::any::type_name;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use swarm_core::agent::SwarmMode;
use swarm_core::config::{ResponsePlaybookRuleResolution, RuntimeDegradationLevel, SwarmConfig};
use swarm_core::observability::with_trace_id;
use swarm_core::pheromone::ThreatClass;
use swarm_core::telemetry::TelemetryPayload;
use swarm_core::types::{
    AgentId, ResponseAction, ResponseBlastRadiusImpact, ResponseBlastRadiusPreview,
    ResponseRehearsalPreview, ResponseRehearsalScopeKind, ResponseRollbackPreview,
    ResponseRollbackStep, ResponseRollbackStepKind, Severity,
};
use swarm_pheromone::{
    ConfiguredPheromoneSubstrate, PheromoneSubstrate, SubstrateError, SubstrateHealth,
};
use swarm_policy::ApprovalGate;
use swarm_policy::configurable_gate::ConfigurableApprovalGate;
use swarm_policy::static_gate::scope_for_response_action;
use swarm_policy::{ActionRequest, ApprovalContext, ApprovalError, PolicyVerdict};
use swarm_response::{
    DispatchingExecutor, NotificationRouter, ResponseExecutor, SiemFindingForwarder,
};
use swarm_spine::{
    AuditResponseRecord, ConfiguredIncidentStore, ConfiguredInvestigationBundleStore,
    ConfiguredReplayBundleStore, FalsePositiveMeasurementReport, IncidentLookup, IncidentRecord,
    IncidentStore, IncidentStoreHealth, InvestigationBundleLookup, InvestigationBundleRecord,
    InvestigationBundleStore, InvestigationStoreHealth, ReplayBundle, ReplayBundleLookup,
    ReplayBundleRecord, ReplayBundleStore, ReplayPreview, ReplayStoreError, ReplayStoreHealth,
    summarize_false_positive_measurements,
};
use swarm_whisker::{DetectionFinding, DetectionStrategy, TelemetryEvent};
use tracing::Instrument as _;

mod preview;
mod runtime_service;
mod stack;
mod status;
mod types;

pub use self::runtime_service::RuntimeService;
pub use self::types::*;

use self::preview::*;
use self::status::*;
use self::types::{RuntimeMetrics, RuntimeStage};

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    include!("tests_support.rs");

    mod runtime {
        use super::*;

        include!("tests_runtime.rs");
    }

    mod preview {
        use super::*;

        include!("tests_preview.rs");
    }

    mod operator {
        use super::*;

        include!("tests_operator.rs");
    }
}
