//! `GET /v1/operator/policy` — the rules in file order, and the daemon's own
//! evaluation of one triple. Read-only: the profile is sha256-pinned inside a
//! signed attestation, so the console shows the policy and never edits it.

use axum::Json;
use axum::extract::{Extension, Query, State};
use serde::{Deserialize, Serialize};
use swarm_core::config::{OperatorScope, PolicyRuleConfig, PolicyTimeWindowConfig};
use swarm_core::pheromone::ThreatClass;
use swarm_core::types::Severity;
use swarm_ingest_runtime::control::CURRENT_OPERATOR_API_SCHEMA_VERSION;
use swarm_ingest_runtime::ingest::perch_ops::policy::{
    PolicyEvaluation, PolicyTriple, evaluate_triple,
};

use super::PerchHttpState;
use crate::http::auth::{AuthenticatedOperatorPrincipal, require_operator_api_scope};
use crate::http::error::OperatorApiError;

/// The optional triple. All three or none: a partial triple is a `400`,
/// because an evaluation against a guessed field is worse than no evaluation.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyQuery {
    pub threat_class: Option<ThreatClass>,
    pub severity: Option<Severity>,
    pub action: Option<String>,
}

/// Where the policy came from, and why the surface is read-only.
#[derive(Debug, Clone, Serialize)]
pub struct PolicySource {
    /// The profile path the runtime started on.
    pub path: String,
    /// Whether a `.sig.json` sibling exists beside it — the reason an edit
    /// here would produce a config the runtime refuses to start on.
    pub attested: bool,
}

/// One rule as the console renders it: file order, selectors, and limits.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyRuleView {
    pub index: usize,
    pub name: String,
    pub decision: String,
    pub threat_class: ThreatClass,
    /// `ResponseAction::kind()` slugs; empty means every action.
    pub actions: Vec<String>,
    pub min_severity: Severity,
    pub max_severity: Severity,
    pub time_window_utc: Option<PolicyTimeWindowConfig>,
    pub max_actions_per_agent_per_minute: Option<usize>,
}

/// The whole read.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyResponse {
    pub schema_version: u32,
    pub human_gate_severity: Severity,
    pub lease_ttl_ms: i64,
    pub max_actions_per_scope_per_minute: usize,
    pub source: PolicySource,
    pub rules: Vec<PolicyRuleView>,
    /// Present only when a triple was asked about.
    pub evaluation: Option<PolicyEvaluation>,
}

fn rule_view(index: usize, rule: &PolicyRuleConfig) -> PolicyRuleView {
    PolicyRuleView {
        index,
        name: rule.name.clone(),
        decision: serde_json::to_value(rule.decision)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default(),
        threat_class: rule.threat_class.clone(),
        actions: rule
            .actions
            .iter()
            .filter_map(|selector| {
                serde_json::to_value(selector)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
            })
            .collect(),
        min_severity: rule.min_severity,
        max_severity: rule.max_severity,
        time_window_utc: rule.time_window_utc,
        max_actions_per_agent_per_minute: rule.max_actions_per_agent_per_minute,
    }
}

pub(super) async fn policy_handler(
    Extension(principal): Extension<AuthenticatedOperatorPrincipal>,
    State(state): State<PerchHttpState>,
    Query(query): Query<PolicyQuery>,
) -> Result<Json<PolicyResponse>, OperatorApiError> {
    require_operator_api_scope(&principal, OperatorScope::Read, "read")?;
    let triple = match (query.threat_class, query.severity, query.action) {
        (None, None, None) => None,
        (Some(threat_class), Some(severity), Some(action)) => Some(PolicyTriple {
            threat_class,
            severity,
            action,
        }),
        _ => {
            return Err(OperatorApiError::bad_request(
                "threat_class, severity and action are evaluated together; give all three or none",
            ));
        }
    };
    let policy = state.ingest.current_policy_config();
    let path = state.ingest.config_path().to_path_buf();
    let attested = path
        .file_name()
        .map(|name| {
            let mut sig = name.to_os_string();
            sig.push(".sig.json");
            path.with_file_name(sig).is_file()
        })
        .unwrap_or(false);
    let evaluation = triple
        .as_ref()
        .map(|triple| evaluate_triple(&policy, triple));
    Ok(Json(PolicyResponse {
        schema_version: CURRENT_OPERATOR_API_SCHEMA_VERSION,
        human_gate_severity: policy.human_gate_severity,
        lease_ttl_ms: policy.lease_ttl_ms,
        max_actions_per_scope_per_minute: policy.max_actions_per_scope_per_minute,
        source: PolicySource {
            path: path.display().to_string(),
            attested,
        },
        rules: policy
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| rule_view(index, rule))
            .collect(),
        evaluation,
    }))
}
