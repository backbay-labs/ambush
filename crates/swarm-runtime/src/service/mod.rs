//! In-process runtime service layer: the API that `replay`, `control`, `evidence`
//! and the operator HTTP surface all call into.
//!
//! # Placement (SPLIT-01, phase 282)
//!
//! This module STAYS in `swarm-runtime` when the operator HTTP surface is extracted
//! into its own crate. It is not part of the transport crate, and moving it there is
//! a build failure waiting to happen.
//!
//! WHY: `replay` reaches into `service` from NON-TEST code, in two places --
//! `replay/harness.rs` imports `crate::service::{EventExecutionContext, RuntimeService}`
//! and `replay/types.rs` imports `crate::service::{RuntimeMetricsSnapshot, ServiceError}`.
//! If `service/` moved into the HTTP crate, the extracted replay crate would have to
//! depend on the HTTP crate, and running a replay would pull in `axum`, `hyper`,
//! `hyper-util`, `tokio-rustls`, `rustls-pemfile` and `x509-parser`. Replay is an
//! offline evidence lane; it has no business carrying a TLS stack.
//!
//! WHAT MAKES THAT SAFE: nothing in this module's non-test code names a transport
//! type. Measured on this tree, `mod.rs`, `preview.rs`, `runtime_service.rs`,
//! `stack.rs`, `status.rs` and `types.rs` (3,249 of the module's 5,629 lines) contain
//! zero references to axum, hyper, rustls, tower, reqwest, `tokio::net`, `TcpListener`,
//! `SocketAddr`, `StatusCode`, `IntoResponse`, `Router` or `HeaderMap`. So `service`
//! keeps the remainder crate free of the transport closure while still being reachable
//! from replay: the dependency runs remainder -> replay, never replay -> transport.
//!
//! ONE EXCEPTION, AND IT IS TEST-ONLY: `tests_support.rs` stands up a local `axum`
//! server on an ephemeral `tokio::net::TcpListener` as a fake SIEM sink (11 transport
//! references). It is included only under the `#[cfg(test)] mod tests` block below, so
//! it makes `axum` and `tokio`'s net feature DEV-dependencies of the remainder crate,
//! not runtime ones. A dev-dependency edge does not appear in a downstream consumer's
//! dependency graph and cannot form a cycle with the HTTP crate.
//!
//! IF THIS CHANGES: a transport type appearing in non-test code here invalidates the
//! placement above, and the HTTP extraction has to be re-planned before it is cut --
//! either by moving the offending code out of `service` or by moving `service` and
//! accepting that replay inherits transport.

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
