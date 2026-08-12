use crate::alert_tuning::{AlertTuningReport, build_alert_tuning_report};
use crate::anti_tamper::AntiTamperReport;
use crate::bridge_runtime::bridge_health_report;
use crate::control::{
    CURRENT_OPERATOR_API_SCHEMA_VERSION, OPERATOR_API_SCHEMA_VERSION_HEADER,
    resolve_operator_api_schema_version,
};
use crate::escalation::standard_threat_classes;
use crate::evasion_coverage::EvasionCoverageSnapshot;
use crate::http::rate_limit::HttpRateLimitRejection;
use crate::http::tls_identity::TlsClientIdentity;
use crate::providence::verify_providence_context_token;
use crate::runtime_events::{AsyncLaneStatusSnapshot, RuntimeEvent, now_ms};
use crate::service::{HttpRateLimitStatus, OperatorBearerTokenStatus, RuntimeDegradationStatus};
use axum::Router;
use axum::extract::{Extension, Json, Path as AxumPath, Query, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Json as ResponseJson;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use swarm_core::ThreatClass;
use swarm_core::agent::{AgentHealthEntry, SwarmMode, SwarmModeState};
use swarm_core::config::{
    OperatorScope, OperatorSurfaceConfig, PlatformApiConfig, PlatformApiScope,
};
use swarm_core::pheromone::PheromoneDeposit;
use swarm_core::types::{ProvidenceIncidentReconciliation, ResponseRehearsalPreview, Severity};
use swarm_pheromone::{DepositQuery, PheromoneSubstrate};
use swarm_response::SwarmFindingEnvelope;
use swarm_spine::{
    FalsePositiveMeasurementReport, IncidentStore, InvestigationBundleStore, InvestigationStatus,
    ReplayBundleLookup, ReplayBundleStore, summarize_false_positive_measurements,
};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use zeroize::Zeroizing;

use super::IngestState;

pub(super) const DEFAULT_PLATFORM_API_PAGE_SIZE: usize = 50;
pub(super) const MAX_PLATFORM_API_PAGE_SIZE: usize = 200;
pub(super) const PLATFORM_POSTURE_RECENT_FINDINGS_LIMIT: usize = 10;

#[derive(Debug, Clone)]
pub(super) struct PlatformApiKeyRecord {
    pub(super) name: String,
    pub(super) key_hash: String,
    pub(super) scopes: Vec<PlatformApiScope>,
}

#[derive(Debug, Clone)]
pub(super) struct PlatformApiAuthState {
    pub(super) keys: Arc<Vec<PlatformApiKeyRecord>>,
    pub(super) bearer_principals: Arc<Vec<ConfiguredPlatformApiBearerPrincipal>>,
    pub(super) context_token_env: Arc<str>,
}

#[derive(Debug, Clone)]
pub(super) enum PlatformApiBearerAuthFailure {
    Invalid,
    Expired {
        operator_id: Arc<str>,
        expires_at_ms: i64,
    },
}

fn read_platform_api_token_from_env(env_name: &str) -> Option<Zeroizing<String>> {
    let mut token = std::env::var(env_name).ok().map(Zeroizing::new)?;
    while matches!(token.as_bytes().last(), Some(b'\n' | b'\r')) {
        token.pop();
    }
    (!token.is_empty()).then_some(token)
}

impl PlatformApiAuthState {
    pub(super) fn from_config(
        config: &PlatformApiConfig,
        operator: &OperatorSurfaceConfig,
    ) -> Self {
        let keys = config
            .keys
            .iter()
            .map(|key| PlatformApiKeyRecord {
                name: key.name.clone(),
                key_hash: key.key_hash.to_ascii_lowercase(),
                scopes: key.scopes.clone(),
            })
            .collect();
        let bearer_principals: Vec<ConfiguredPlatformApiBearerPrincipal> = operator
            .auth
            .effective_principals()
            .into_iter()
            .filter_map(|principal| {
                if read_platform_api_token_from_env(&principal.token_env).is_none() {
                    tracing::warn!(
                        operator_id = %principal.operator_id,
                        token_env = %principal.token_env,
                        "platform API operator bearer token env is missing or empty"
                    );
                    return None;
                }
                Some(ConfiguredPlatformApiBearerPrincipal {
                    principal: PlatformApiBearerPrincipal {
                        operator_id: Arc::from(principal.operator_id),
                        scopes: principal.scopes,
                    },
                    token_env: Arc::from(principal.token_env),
                    token_expires_at_ms: principal.token_expires_at_ms,
                })
            })
            .collect();
        let context_token_env = Arc::from(operator.auth.context_token_env().to_string());
        if config.keys.is_empty() {
            tracing::debug!("platform API auth disabled because no API keys are configured");
        } else if bearer_principals.is_empty() {
            tracing::warn!(
                "platform API operator bearer auth is unavailable because no readable bearer principals were resolved"
            );
        }
        if read_platform_api_token_from_env(&context_token_env).is_none() {
            tracing::warn!(
                token_env = %context_token_env,
                "platform API Providence context token env is missing or empty"
            );
        }
        Self {
            keys: Arc::new(keys),
            bearer_principals: Arc::new(bearer_principals),
            context_token_env,
        }
    }

    pub(super) fn authenticate(&self, key: &str) -> Option<PlatformApiPrincipal> {
        let key_hash = platform_api_key_hash_hex(key);
        self.keys.iter().find_map(|candidate| {
            (candidate.key_hash == key_hash).then(|| PlatformApiPrincipal {
                name: candidate.name.clone(),
                scopes: candidate.scopes.clone(),
            })
        })
    }

    pub(super) fn context_token_secret(&self) -> Option<Zeroizing<String>> {
        read_platform_api_token_from_env(&self.context_token_env)
    }

    pub(super) fn authenticate_bearer(
        &self,
        token: &str,
        now_ms: i64,
    ) -> Result<PlatformApiBearerPrincipal, PlatformApiBearerAuthFailure> {
        let mut expired = None;
        for principal in self.bearer_principals.iter() {
            let Some(expected_token) =
                read_platform_api_token_from_env(principal.token_env.as_ref())
            else {
                continue;
            };
            if expected_token.as_str() != token {
                continue;
            }
            if let Some(expires_at_ms) = principal.token_expires_at_ms
                && now_ms > expires_at_ms
            {
                expired = Some(PlatformApiBearerAuthFailure::Expired {
                    operator_id: principal.principal.operator_id.clone(),
                    expires_at_ms,
                });
                continue;
            }
            return Ok(principal.principal.clone());
        }
        Err(expired.unwrap_or(PlatformApiBearerAuthFailure::Invalid))
    }
}

#[derive(Debug, Clone)]
pub(super) struct PlatformApiBearerPrincipal {
    pub(super) operator_id: Arc<str>,
    pub(super) scopes: Vec<OperatorScope>,
}

impl PlatformApiBearerPrincipal {
    pub(super) fn has_scope(&self, scope: OperatorScope) -> bool {
        self.scopes.contains(&scope)
    }
}

#[derive(Debug, Clone)]
pub(super) struct PlatformApiContextTokenPrincipal;

#[derive(Debug, Clone)]
pub(super) struct ConfiguredPlatformApiBearerPrincipal {
    pub(super) principal: PlatformApiBearerPrincipal,
    pub(super) token_env: Arc<str>,
    pub(super) token_expires_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
pub(super) struct PlatformApiPrincipal {
    pub(super) name: String,
    pub(super) scopes: Vec<PlatformApiScope>,
}

impl PlatformApiPrincipal {
    pub(super) fn has_scope(&self, scope: PlatformApiScope) -> bool {
        self.scopes.contains(&scope)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PlatformApiEnvelope<T> {
    pub(super) schema_version: u32,
    pub(super) data: Vec<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) cursor: Option<String>,
}

impl<T> PlatformApiEnvelope<T> {
    fn new(data: Vec<T>, cursor: Option<String>) -> Self {
        Self {
            schema_version: CURRENT_OPERATOR_API_SCHEMA_VERSION,
            data,
            cursor,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PlatformFindingSummary {
    pub(super) bundle_id: String,
    pub(super) hunt_id: String,
    pub(super) trail_id: String,
    pub(super) created_at_ms: i64,
    pub(super) host_id: Option<String>,
    pub(super) response_kind: String,
    pub(super) response_receipt_id: Option<String>,
    pub(super) related_receipt_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) latest_rehearsal_bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) latest_rehearsal: Option<ResponseRehearsalPreview>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) related_incident_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) related_incident_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) related_incident_providence_reconciliation: Option<ProvidenceIncidentReconciliation>,
    pub(super) finding: SwarmFindingEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PlatformIncidentSummary {
    pub(super) incident_id: String,
    pub(super) summary: String,
    pub(super) created_at_ms: i64,
    pub(super) included_hunt_ids: Vec<String>,
    pub(super) included_investigation_ids: Vec<String>,
    pub(super) related_receipt_ids: Vec<String>,
    pub(super) correlation_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) providence_reconciliation: Option<ProvidenceIncidentReconciliation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) latest_rehearsal_hunt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) latest_rehearsal_bundle_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) latest_rehearsal: Option<ResponseRehearsalPreview>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PlatformDetectorStatus {
    pub(super) ready: bool,
    pub(super) strategy: String,
    pub(super) details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PlatformLifecycleStatus {
    pub(super) draining: bool,
    pub(super) active_requests: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PlatformRuntimeStatus {
    pub(super) captured_at_ms: i64,
    pub(super) mode_state: SwarmModeState,
    pub(super) degradation: RuntimeDegradationStatus,
    pub(super) agent_health: Vec<AgentHealthEntry>,
    pub(super) detector: PlatformDetectorStatus,
    pub(super) lifecycle: PlatformLifecycleStatus,
    pub(super) anti_tamper: AntiTamperReport,
    pub(super) async_lane: AsyncLaneStatusSnapshot,
    pub(super) false_positive_tracking: FalsePositiveMeasurementReport,
    pub(super) alert_tuning: AlertTuningReport,
    pub(super) bearer_tokens: Vec<OperatorBearerTokenStatus>,
    pub(super) rate_limit: HttpRateLimitStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) bridge_health: Option<crate::bridge_runtime::BridgeStatusReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PlatformThreatConcentrationSummary {
    pub(super) threat_class: ThreatClass,
    pub(super) total_strength: f64,
    pub(super) distinct_sources: usize,
    pub(super) peak_confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PlatformInvestigationSummary {
    pub(super) investigation_id: String,
    pub(super) hunt_id: String,
    pub(super) finding_id: String,
    pub(super) status: InvestigationStatus,
    pub(super) queued_at_ms: i64,
    pub(super) last_updated_ms: i64,
    pub(super) response_kind: String,
    pub(super) correlation_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) summary_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PlatformAssetPosture {
    pub(super) host_id: String,
    pub(super) captured_at_ms: i64,
    pub(super) escalation_level: SwarmMode,
    pub(super) threat_concentrations: Vec<PlatformThreatConcentrationSummary>,
    pub(super) active_investigations: Vec<PlatformInvestigationSummary>,
    pub(super) recent_findings: Vec<PlatformFindingSummary>,
}

#[derive(Debug, Deserialize)]
pub(super) struct PlatformFindingsQuery {
    pub(super) cursor: Option<String>,
    pub(super) page_size: Option<usize>,
    pub(super) hunt_id: Option<String>,
    pub(super) finding_id: Option<String>,
    pub(super) strategy_id: Option<String>,
    pub(super) threat_class: Option<ThreatClass>,
    pub(super) severity: Option<Severity>,
    pub(super) host_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PlatformIncidentsQuery {
    cursor: Option<String>,
    page_size: Option<usize>,
    incident_id: Option<String>,
    hunt_id: Option<String>,
    receipt_id: Option<String>,
    correlation_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct EvasionCoverageQuery {
    detector: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub(super) struct PlatformFindingsStreamQuery {
    pub(super) host_id: Option<String>,
    pub(super) strategy_id: Option<String>,
    pub(super) threat_class: Option<ThreatClass>,
    pub(super) severity: Option<Severity>,
}

#[derive(Debug, Clone)]
pub(super) struct PlatformCursorKey {
    pub(super) created_at_ms: i64,
    pub(super) stable_id: String,
}

impl PlatformCursorKey {
    pub(super) fn encode(&self) -> String {
        format!("{}:{}", self.created_at_ms, self.stable_id)
    }

    pub(super) fn parse(raw: &str) -> Result<Self, PlatformApiError> {
        let (created_at_ms, stable_id) = raw
            .split_once(':')
            .ok_or_else(|| PlatformApiError::bad_request("invalid cursor"))?;
        let created_at_ms = created_at_ms
            .parse::<i64>()
            .map_err(|_| PlatformApiError::bad_request("invalid cursor"))?;
        if stable_id.trim().is_empty() {
            return Err(PlatformApiError::bad_request("invalid cursor"));
        }
        Ok(Self {
            created_at_ms,
            stable_id: stable_id.to_string(),
        })
    }
}

#[derive(Debug)]
pub(super) struct PlatformApiError {
    pub(super) status: StatusCode,
    pub(super) error: String,
    pub(super) retry_after_seconds: Option<u64>,
}

impl PlatformApiError {
    pub(super) fn bad_request(error: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: error.into(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn unauthorized(error: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: error.into(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn forbidden(error: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error: error.into(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn internal(error: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: error.into(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn service_unavailable(error: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            error: error.into(),
            retry_after_seconds: None,
        }
    }

    pub(super) fn too_many_requests(error: impl Into<String>, retry_after_seconds: u64) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            error: error.into(),
            retry_after_seconds: Some(retry_after_seconds),
        }
    }
}

impl IntoResponse for PlatformApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            ResponseJson(json!({
                "error": self.error,
            })),
        )
            .into_response();
        if let Some(retry_after_seconds) = self.retry_after_seconds
            && let Ok(value) = retry_after_seconds.to_string().parse()
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

pub(super) fn platform_api_key_hash_hex(raw: &str) -> String {
    format!("{:x}", Sha256::digest(raw.trim().as_bytes()))
}

pub(super) fn platform_api_page_size(requested: Option<usize>) -> Result<usize, PlatformApiError> {
    match requested {
        Some(0) => Err(PlatformApiError::bad_request(
            "page_size must be greater than zero",
        )),
        Some(value) => Ok(value.min(MAX_PLATFORM_API_PAGE_SIZE)),
        None => Ok(DEFAULT_PLATFORM_API_PAGE_SIZE),
    }
}

fn parse_requested_schema_version_header(
    headers: &axum::http::HeaderMap,
) -> Result<Option<u32>, PlatformApiError> {
    headers
        .get(OPERATOR_API_SCHEMA_VERSION_HEADER)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| {
                    PlatformApiError::bad_request(format!(
                        "{OPERATOR_API_SCHEMA_VERSION_HEADER} header must be valid UTF-8"
                    ))
                })?
                .trim()
                .parse::<u32>()
                .map_err(|_| {
                    PlatformApiError::bad_request(format!(
                        "{OPERATOR_API_SCHEMA_VERSION_HEADER} header must be an unsigned integer"
                    ))
                })
        })
        .transpose()
}

pub(super) fn request_query_param(request: &axum::extract::Request, key: &str) -> Option<String> {
    // Standard HTTP clients (the generated Python client, the demo widget,
    // axum's own Query extractor) percent-encode `:` in finding/incident IDs
    // as `%3A`. Decoding here ensures scoped values match the unencoded token
    // scope; without it, valid context-token requests are rejected with 403.
    request.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let candidate = parts.next()?;
            if candidate == key {
                Some(percent_decode_query_value(parts.next().unwrap_or_default()))
            } else {
                None
            }
        })
    })
}

fn percent_decode_query_value(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi * 16 + lo) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(super) fn context_token_matches_platform_request(
    request: &axum::extract::Request,
    scope: &crate::providence::ProvidenceContextScope,
) -> bool {
    // Context tokens are scoped to the finding/incident the operator was
    // shown — they MUST NOT grant access to runtime health, bridge state, or
    // configured bearer-token metadata exposed by /runtime/status. That route
    // requires the bearer token + x-api-key path.
    match request.uri().path() {
        "/v2/api/findings" | "/findings" => {
            !scope.finding_id.as_deref().is_some_and(|value| {
                request_query_param(request, "finding_id").as_deref() != Some(value)
            }) && !scope.hunt_id.as_deref().is_some_and(|value| {
                request_query_param(request, "hunt_id").as_deref() != Some(value)
            }) && !scope.strategy_id.as_deref().is_some_and(|value| {
                request_query_param(request, "strategy_id").as_deref() != Some(value)
            }) && !scope.threat_class.as_ref().is_some_and(|value| {
                let expected = super::threat_class_slug(value);
                request_query_param(request, "threat_class").as_deref() != Some(expected.as_str())
            })
        }
        "/v2/api/incidents" | "/incidents" => {
            !scope.incident_id.as_deref().is_some_and(|value| {
                request_query_param(request, "incident_id").as_deref() != Some(value)
            }) && !scope.hunt_id.as_deref().is_some_and(|value| {
                request_query_param(request, "hunt_id").as_deref() != Some(value)
            })
        }
        _ => false,
    }
}

pub(super) fn is_after_platform_cursor(
    item: &PlatformCursorKey,
    cursor: &PlatformCursorKey,
) -> bool {
    item.created_at_ms < cursor.created_at_ms
        || (item.created_at_ms == cursor.created_at_ms && item.stable_id < cursor.stable_id)
}

pub(super) fn finalize_platform_page<T>(
    mut items: Vec<T>,
    page_size: usize,
    key_for: impl Fn(&T) -> PlatformCursorKey,
) -> PlatformApiEnvelope<T> {
    let cursor = if items.len() > page_size {
        items
            .get(page_size)
            .map(|_| key_for(&items[page_size - 1]).encode())
    } else {
        None
    };
    items.truncate(page_size);
    PlatformApiEnvelope::new(items, cursor)
}

fn latest_rehearsal_for_hunt(
    state: &IngestState,
    hunt_id: &str,
) -> Result<(Option<String>, Option<ResponseRehearsalPreview>), PlatformApiError> {
    let lookup = state
        .current_replay_store()
        .load_by_hunt_id(hunt_id)
        .map_err(|error| PlatformApiError::internal(error.to_string()))?;
    Ok(
        match lookup.and_then(|lookup| {
            lookup
                .bundle
                .rehearsal
                .as_ref()
                .cloned()
                .map(|preview| (lookup.bundle.bundle_id, preview))
        }) {
            Some((bundle_id, preview)) => (Some(bundle_id), Some(preview)),
            None => (None, None),
        },
    )
}

pub(super) fn platform_finding_summary_from_lookup(
    state: &IngestState,
    lookup: &ReplayBundleLookup,
) -> Result<PlatformFindingSummary, PlatformApiError> {
    let finding = &lookup.bundle.audit.detection;
    let hunt_id = lookup.bundle.audit.hunt_id.clone();
    let (latest_rehearsal_bundle_id, latest_rehearsal) =
        latest_rehearsal_for_hunt(state, &hunt_id)?;
    let related_incident = state
        .current_incident_store()
        .load_by_hunt_id(&hunt_id)
        .map_err(|error| PlatformApiError::internal(error.to_string()))?;
    Ok(PlatformFindingSummary {
        bundle_id: lookup.bundle.bundle_id.clone(),
        hunt_id,
        trail_id: lookup.bundle.audit.trail_id.clone(),
        created_at_ms: lookup.bundle.audit.created_at_ms,
        host_id: lookup.bundle.event.host_id.clone(),
        response_kind: lookup.bundle.audit.response_kind().to_string(),
        response_receipt_id: lookup
            .bundle
            .audit
            .response_receipt_id()
            .map(ToString::to_string),
        related_receipt_ids: lookup.bundle.audit.all_receipt_ids(),
        latest_rehearsal_bundle_id,
        latest_rehearsal,
        related_incident_id: related_incident
            .as_ref()
            .map(|lookup| lookup.record.incident_id.clone()),
        related_incident_summary: related_incident
            .as_ref()
            .map(|lookup| lookup.record.summary.clone()),
        related_incident_providence_reconciliation: related_incident
            .and_then(|lookup| lookup.record.providence_reconciliation),
        finding: SwarmFindingEnvelope::from(finding),
    })
}

pub(super) fn platform_finding_matches_query(
    lookup: &ReplayBundleLookup,
    query: &PlatformFindingsQuery,
) -> bool {
    let finding = &lookup.bundle.audit.detection;
    query
        .hunt_id
        .as_deref()
        .is_none_or(|hunt_id| lookup.bundle.audit.hunt_id == hunt_id)
        && query
            .finding_id
            .as_deref()
            .is_none_or(|finding_id| finding.finding_id == finding_id)
        && query
            .strategy_id
            .as_deref()
            .is_none_or(|strategy_id| finding.strategy_id == strategy_id)
        && query
            .threat_class
            .as_ref()
            .is_none_or(|threat_class| finding.threat_class == *threat_class)
        && query
            .severity
            .is_none_or(|severity| finding.severity == severity)
        && query
            .host_id
            .as_deref()
            .is_none_or(|host_id| lookup.bundle.event.host_id.as_deref() == Some(host_id))
}

pub(super) fn load_platform_findings(
    state: &IngestState,
    query: &PlatformFindingsQuery,
) -> Result<Vec<PlatformFindingSummary>, PlatformApiError> {
    let store = state.current_replay_store();
    let records = store
        .recent(usize::MAX)
        .map_err(|error| PlatformApiError::internal(error.to_string()))?;

    let mut findings = Vec::new();
    for record in records {
        let Some(lookup) = store
            .load_by_bundle_id(&record.bundle_id)
            .map_err(|error| PlatformApiError::internal(error.to_string()))?
        else {
            continue;
        };
        if !platform_finding_matches_query(&lookup, query) {
            continue;
        }
        findings.push(platform_finding_summary_from_lookup(state, &lookup)?);
    }

    findings.sort_by(|left, right| {
        right
            .created_at_ms
            .cmp(&left.created_at_ms)
            .then_with(|| right.bundle_id.cmp(&left.bundle_id))
    });
    Ok(findings)
}

pub(super) fn host_concentration_from_deposits(
    deposits: &[PheromoneDeposit],
    threat_class: &ThreatClass,
    now: i64,
    evaporation_threshold: f64,
) -> PlatformThreatConcentrationSummary {
    let mut sources = HashSet::new();
    let mut total_strength = 0.0;
    let mut peak_confidence: f64 = 0.0;

    for deposit in deposits
        .iter()
        .filter(|deposit| &deposit.threat_class == threat_class)
    {
        if deposit.is_evaporated(now, evaporation_threshold) {
            continue;
        }
        total_strength += deposit.strength_at(now);
        peak_confidence = peak_confidence.max(deposit.confidence);
        sources.insert(deposit.agent_id.0.clone());
    }

    PlatformThreatConcentrationSummary {
        threat_class: threat_class.clone(),
        total_strength,
        distinct_sources: sources.len(),
        peak_confidence,
    }
}

pub(super) fn finding_stream_matches_query(
    host_id: Option<&str>,
    finding: &SwarmFindingEnvelope,
    query: &PlatformFindingsStreamQuery,
) -> bool {
    query
        .host_id
        .as_deref()
        .is_none_or(|value| host_id == Some(value))
        && query
            .strategy_id
            .as_deref()
            .is_none_or(|value| finding.strategy_id == value)
        && query
            .threat_class
            .as_ref()
            .is_none_or(|value| finding.threat_class == *value)
        && query.severity.is_none_or(|value| finding.severity == value)
}

pub(super) fn is_active_investigation_status(status: InvestigationStatus) -> bool {
    matches!(
        status,
        InvestigationStatus::Queued | InvestigationStatus::Running
    )
}

// --- Router builders ---

pub(super) fn platform_api_router(state: &IngestState) -> Router<IngestState> {
    Router::new()
        .route("/findings", get(platform_findings_handler))
        .route("/incidents", get(platform_incidents_handler))
        .route("/evasion/coverage", get(platform_evasion_coverage_handler))
        .route(
            "/assets/{host_id}/posture",
            get(platform_asset_posture_handler),
        )
        .route("/stream/findings", get(platform_findings_stream_handler))
        .route("/runtime/status", get(platform_runtime_status_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_platform_api_key_auth_resolved,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_platform_api_bearer_auth_resolved,
        ))
        .layer(middleware::from_fn(
            require_supported_platform_api_schema_version,
        ))
}

pub(super) fn legacy_evasion_api_router(state: &IngestState) -> Router<IngestState> {
    Router::new()
        .route("/evasion/coverage", get(platform_evasion_coverage_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_platform_api_key_auth_resolved,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_platform_api_bearer_auth_resolved,
        ))
        .layer(middleware::from_fn(
            require_supported_platform_api_schema_version,
        ))
}

// --- Auth middleware ---

async fn require_supported_platform_api_schema_version(
    headers: axum::http::HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, PlatformApiError> {
    let requested = parse_requested_schema_version_header(&headers)?;
    resolve_operator_api_schema_version(requested).map_err(PlatformApiError::bad_request)?;
    Ok(next.run(request).await)
}

async fn require_platform_api_key_auth_resolved(
    State(state): State<IngestState>,
    headers: axum::http::HeaderMap,
    mut request: axum::extract::Request,
    next: Next,
) -> Result<Response, PlatformApiError> {
    let auth = state.platform_api_auth();
    if request
        .extensions()
        .get::<PlatformApiContextTokenPrincipal>()
        .is_some()
    {
        request.extensions_mut().insert(PlatformApiPrincipal {
            name: "providence-context-token".to_string(),
            scopes: vec![PlatformApiScope::Read],
        });
        return Ok(next.run(request).await);
    }
    let bearer_principal = request
        .extensions()
        .get::<PlatformApiBearerPrincipal>()
        .cloned();
    let key = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| PlatformApiError::unauthorized("missing x-api-key header"))?;
    let principal = auth
        .authenticate(key)
        .ok_or_else(|| PlatformApiError::unauthorized("invalid platform API key"))?;
    if !principal.has_scope(PlatformApiScope::Read) {
        return Err(PlatformApiError::forbidden(
            "platform API key does not grant read scope",
        ));
    }
    tracing::debug!(
        platform_api_operator_id = bearer_principal
            .as_ref()
            .map(|principal| principal.operator_id.as_ref())
            .unwrap_or("unknown"),
        platform_api_principal = %principal.name,
        tls_client_identity = request
            .extensions()
            .get::<TlsClientIdentity>()
            .map(TlsClientIdentity::as_str)
            .unwrap_or("none"),
        scopes = ?principal.scopes,
        "authenticated platform API request"
    );
    request.extensions_mut().insert(principal);
    Ok(next.run(request).await)
}

async fn require_platform_api_bearer_auth_resolved(
    State(state): State<IngestState>,
    headers: axum::http::HeaderMap,
    mut request: axum::extract::Request,
    next: Next,
) -> Result<Response, PlatformApiError> {
    let auth = state.platform_api_auth();
    let peer_addr = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    state
        .platform_api_rate_limiter()
        .check_request(&headers, peer_addr, request.uri().path(), now_ms())
        .map_err(map_platform_rate_limit_rejection)?;
    if request.method() == axum::http::Method::GET
        && let Some(raw_token) = request_query_param(&request, "context_token")
    {
        let secret_material = auth.context_token_secret().ok_or_else(|| {
            PlatformApiError::service_unavailable(format!(
                "platform API Providence context token env `{}` is missing or empty",
                auth.context_token_env
            ))
        })?;
        let claims =
            verify_providence_context_token(secret_material.as_str(), &raw_token, now_ms())
                .map_err(PlatformApiError::unauthorized)?;
        if !context_token_matches_platform_request(&request, &claims.scope) {
            return Err(PlatformApiError::forbidden(
                "context token scope does not match requested platform API resource",
            ));
        }
        request
            .extensions_mut()
            .insert(PlatformApiContextTokenPrincipal);
        return Ok(next.run(request).await);
    }
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or_else(|| PlatformApiError::unauthorized("missing Authorization header"))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| PlatformApiError::unauthorized("expected Authorization: Bearer <token>"))?;
    let principal = auth
        .authenticate_bearer(token, now_ms())
        .map_err(|error| match error {
            PlatformApiBearerAuthFailure::Invalid => {
                PlatformApiError::unauthorized("invalid bearer token")
            }
            PlatformApiBearerAuthFailure::Expired {
                operator_id,
                expires_at_ms,
            } => PlatformApiError::unauthorized(format!(
                "bearer token for operator `{operator_id}` expired at {expires_at_ms}"
            )),
        })?;
    if !principal.has_scope(OperatorScope::Read) {
        return Err(PlatformApiError::forbidden(
            "operator bearer token does not grant read scope",
        ));
    }

    request.extensions_mut().insert(principal);
    Ok(next.run(request).await)
}

fn map_platform_rate_limit_rejection(rejection: HttpRateLimitRejection) -> PlatformApiError {
    PlatformApiError::too_many_requests(
        format!(
            "{} rate limit exceeded for source `{}` on `{}`; retry after {}ms",
            rate_limit_threshold_label(rejection.threshold),
            rejection.source,
            rejection.path,
            rejection.retry_after_ms
        ),
        retry_after_seconds(rejection.retry_after_ms),
    )
}

fn rate_limit_threshold_label(threshold: crate::service::HttpRateLimitThreshold) -> &'static str {
    match threshold {
        crate::service::HttpRateLimitThreshold::Burst => "burst",
        crate::service::HttpRateLimitThreshold::Sustained => "sustained",
    }
}

fn retry_after_seconds(retry_after_ms: u64) -> u64 {
    retry_after_ms.max(1).div_ceil(1_000)
}

// --- Handlers ---

async fn platform_findings_handler(
    Extension(principal): Extension<PlatformApiPrincipal>,
    State(state): State<IngestState>,
    Query(query): Query<PlatformFindingsQuery>,
) -> Result<Json<PlatformApiEnvelope<PlatformFindingSummary>>, PlatformApiError> {
    let page_size = platform_api_page_size(query.page_size)?;
    let cursor = query
        .cursor
        .as_deref()
        .map(PlatformCursorKey::parse)
        .transpose()?;
    let mut findings = load_platform_findings(&state, &query)?;
    if let Some(cursor) = cursor.as_ref() {
        findings.retain(|item| {
            is_after_platform_cursor(
                &PlatformCursorKey {
                    created_at_ms: item.created_at_ms,
                    stable_id: item.bundle_id.clone(),
                },
                cursor,
            )
        });
    }

    tracing::debug!(
        platform_api_principal = %principal.name,
        endpoint = "/v2/api/findings",
        returned = findings.len(),
        "served platform findings"
    );
    Ok(Json(finalize_platform_page(findings, page_size, |item| {
        PlatformCursorKey {
            created_at_ms: item.created_at_ms,
            stable_id: item.bundle_id.clone(),
        }
    })))
}

async fn platform_asset_posture_handler(
    Extension(principal): Extension<PlatformApiPrincipal>,
    State(state): State<IngestState>,
    AxumPath(host_id): AxumPath<String>,
) -> Result<Json<PlatformApiEnvelope<PlatformAssetPosture>>, PlatformApiError> {
    let substrate = state.current_substrate();
    let now = super::unix_timestamp_secs();
    let pheromone_config = state.stack.load_full().service.config.pheromone.clone();
    let deposits = substrate
        .query_deposits(DepositQuery {
            threat_class: None,
            since_timestamp: None,
            host_id: Some(host_id.clone()),
            limit: 0,
        })
        .await
        .map_err(|error| PlatformApiError::internal(error.to_string()))?;

    let mut escalation_level = SwarmMode::Normal;
    let mut threat_concentrations = Vec::with_capacity(standard_threat_classes().len());
    for threat_class in standard_threat_classes() {
        let threat_class_config = substrate
            .query_threat_class_config(&threat_class)
            .await
            .map_err(|error| PlatformApiError::internal(error.to_string()))?;
        let policy = pheromone_config.resolve_threat_class_policy(threat_class_config.as_ref());
        let concentration = host_concentration_from_deposits(
            &deposits,
            &threat_class,
            now,
            policy.evaporation_threshold,
        );
        if concentration.total_strength >= policy.incident_threshold
            && concentration.distinct_sources >= policy.min_sources_for_escalation
        {
            escalation_level = SwarmMode::Incident;
        } else if escalation_level == SwarmMode::Normal
            && concentration.total_strength >= policy.alert_threshold
            && concentration.distinct_sources >= policy.min_sources_for_escalation
        {
            escalation_level = SwarmMode::Alert;
        }
        threat_concentrations.push(concentration);
    }

    let mut active_investigations = state
        .current_investigation_store()
        .recent(usize::MAX)
        .map_err(|error| PlatformApiError::internal(error.to_string()))?
        .into_iter()
        .filter(|record| {
            record.host_id.as_deref() == Some(host_id.as_str())
                && is_active_investigation_status(record.status)
        })
        .map(|record| PlatformInvestigationSummary {
            investigation_id: record.investigation_id,
            hunt_id: record.hunt_id,
            finding_id: record.finding_id,
            status: record.status,
            queued_at_ms: record.queued_at_ms,
            last_updated_ms: record.last_updated_ms,
            response_kind: record.response_kind,
            correlation_keys: record.correlation_keys,
            summary_preview: record.summary_preview,
        })
        .collect::<Vec<_>>();
    active_investigations.sort_by(|left, right| {
        right
            .last_updated_ms
            .cmp(&left.last_updated_ms)
            .then_with(|| right.investigation_id.cmp(&left.investigation_id))
    });

    let mut recent_findings = load_platform_findings(
        &state,
        &PlatformFindingsQuery {
            cursor: None,
            page_size: None,
            hunt_id: None,
            finding_id: None,
            strategy_id: None,
            threat_class: None,
            severity: None,
            host_id: Some(host_id.clone()),
        },
    )?;
    recent_findings.truncate(PLATFORM_POSTURE_RECENT_FINDINGS_LIMIT);

    tracing::debug!(
        platform_api_principal = %principal.name,
        endpoint = "/v2/api/assets/{host_id}/posture",
        host_id = %host_id,
        "served platform asset posture"
    );
    Ok(Json(PlatformApiEnvelope::new(
        vec![PlatformAssetPosture {
            host_id,
            captured_at_ms: now_ms(),
            escalation_level,
            threat_concentrations,
            active_investigations,
            recent_findings,
        }],
        None,
    )))
}

async fn platform_incidents_handler(
    Extension(principal): Extension<PlatformApiPrincipal>,
    State(state): State<IngestState>,
    Query(query): Query<PlatformIncidentsQuery>,
) -> Result<Json<PlatformApiEnvelope<PlatformIncidentSummary>>, PlatformApiError> {
    let page_size = platform_api_page_size(query.page_size)?;
    let cursor = query
        .cursor
        .as_deref()
        .map(PlatformCursorKey::parse)
        .transpose()?;
    let mut incidents = state
        .current_incident_store()
        .recent(usize::MAX)
        .map_err(|error| PlatformApiError::internal(error.to_string()))?
        .into_iter()
        .filter(|record| {
            query
                .incident_id
                .as_deref()
                .is_none_or(|incident_id| record.incident_id == incident_id)
                && !query.hunt_id.as_deref().is_some_and(|hunt_id| {
                    !record
                        .included_hunt_ids
                        .iter()
                        .any(|value| value == hunt_id)
                })
                && !query.receipt_id.as_deref().is_some_and(|receipt_id| {
                    !record
                        .related_receipt_ids
                        .iter()
                        .any(|value| value == receipt_id)
                })
                && !query
                    .correlation_key
                    .as_deref()
                    .is_some_and(|correlation_key| {
                        !record
                            .correlation_keys
                            .iter()
                            .any(|value| value == correlation_key)
                    })
        })
        .map(|record| {
            let rehearsal_hunt_id = query
                .hunt_id
                .as_deref()
                .filter(|hunt_id| {
                    record
                        .included_hunt_ids
                        .iter()
                        .any(|value| value == *hunt_id)
                })
                .map(ToString::to_string)
                .or_else(|| record.included_hunt_ids.first().cloned());
            let (latest_rehearsal_bundle_id, latest_rehearsal) = rehearsal_hunt_id
                .as_deref()
                .map(|hunt_id| latest_rehearsal_for_hunt(&state, hunt_id))
                .transpose()?
                .unwrap_or((None, None));
            Ok(PlatformIncidentSummary {
                incident_id: record.incident_id,
                summary: record.summary,
                created_at_ms: record.created_at_ms,
                included_hunt_ids: record.included_hunt_ids,
                included_investigation_ids: record.included_investigation_ids,
                related_receipt_ids: record.related_receipt_ids,
                correlation_keys: record.correlation_keys,
                providence_reconciliation: record.providence_reconciliation,
                latest_rehearsal_hunt_id: rehearsal_hunt_id,
                latest_rehearsal_bundle_id,
                latest_rehearsal,
            })
        })
        .collect::<Result<Vec<_>, PlatformApiError>>()?;

    incidents.sort_by(|left, right| {
        right
            .created_at_ms
            .cmp(&left.created_at_ms)
            .then_with(|| right.incident_id.cmp(&left.incident_id))
    });
    if let Some(cursor) = cursor.as_ref() {
        incidents.retain(|item| {
            is_after_platform_cursor(
                &PlatformCursorKey {
                    created_at_ms: item.created_at_ms,
                    stable_id: item.incident_id.clone(),
                },
                cursor,
            )
        });
    }

    tracing::debug!(
        platform_api_principal = %principal.name,
        endpoint = "/v2/api/incidents",
        returned = incidents.len(),
        "served platform incidents"
    );
    Ok(Json(finalize_platform_page(incidents, page_size, |item| {
        PlatformCursorKey {
            created_at_ms: item.created_at_ms,
            stable_id: item.incident_id.clone(),
        }
    })))
}

async fn platform_runtime_status_handler(
    Extension(principal): Extension<PlatformApiPrincipal>,
    State(state): State<IngestState>,
) -> Result<Json<PlatformApiEnvelope<PlatformRuntimeStatus>>, PlatformApiError> {
    let detector = state.detector_status();
    let bridge_health = state.bridge_health.as_ref().map(bridge_health_report);
    let incident_summary_limit = state
        .stack
        .load_full()
        .service
        .config
        .audit
        .recent_decisions_limit;
    let incidents = state
        .current_incident_store()
        .recent(incident_summary_limit)
        .map_err(|error| PlatformApiError::internal(error.to_string()))?;
    let async_lane = state
        .current_async_lane_status()
        .await
        .map_err(|error| PlatformApiError::internal(error.to_string()))?;
    let degradation = state.current_runtime_degradation().await;
    let captured_at_ms = now_ms();
    let rate_limit = state.platform_api_rate_limiter.status();
    let bearer_tokens = state
        .stack
        .load_full()
        .service
        .config
        .operator
        .auth
        .effective_principals()
        .into_iter()
        .map(|principal| {
            let expired = principal.token_is_expired(captured_at_ms);
            OperatorBearerTokenStatus {
                operator_id: principal.operator_id,
                token_env: principal.token_env,
                expires_at_ms: principal.token_expires_at_ms,
                expired,
            }
        })
        .collect();
    let status = PlatformRuntimeStatus {
        captured_at_ms,
        mode_state: state.current_mode_state(),
        degradation,
        agent_health: state.current_agent_health(),
        detector: PlatformDetectorStatus {
            ready: detector.ready,
            strategy: detector.strategy,
            details: detector.details,
        },
        lifecycle: PlatformLifecycleStatus {
            draining: state.is_draining(),
            active_requests: state.active_requests(),
        },
        anti_tamper: state.current_anti_tamper_report(),
        async_lane,
        false_positive_tracking: summarize_false_positive_measurements(&incidents),
        alert_tuning: build_alert_tuning_report(&incidents),
        bearer_tokens,
        rate_limit,
        bridge_health,
    };

    tracing::debug!(
        platform_api_principal = %principal.name,
        endpoint = "/v2/api/runtime/status",
        "served platform runtime status"
    );
    Ok(Json(PlatformApiEnvelope::new(vec![status], None)))
}

pub(crate) async fn platform_evasion_coverage_handler(
    Extension(principal): Extension<PlatformApiPrincipal>,
    State(state): State<IngestState>,
    Query(query): Query<EvasionCoverageQuery>,
) -> Result<ResponseJson<EvasionCoverageSnapshot>, PlatformApiError> {
    let mut snapshot = state
        .current_evasion_coverage()
        .map_err(|error| PlatformApiError::internal(error.to_string()))?;
    if let Some(detector) = query.detector.as_deref() {
        snapshot
            .detectors
            .retain(|entry| entry.detector == detector);
        if snapshot.detectors.is_empty() {
            return Err(PlatformApiError::bad_request(format!(
                "unknown evasion detector `{detector}`"
            )));
        }
    }

    tracing::debug!(
        platform_api_principal = %principal.name,
        endpoint = "/evasion/coverage",
        detector = ?query.detector,
        returned = snapshot.detectors.len(),
        "served evasion coverage"
    );
    Ok(ResponseJson(snapshot))
}

pub(crate) async fn platform_findings_stream_handler(
    Extension(principal): Extension<PlatformApiPrincipal>,
    State(state): State<IngestState>,
    Query(query): Query<PlatformFindingsStreamQuery>,
) -> Result<Response, PlatformApiError> {
    let Some(receiver) = state.subscribe_runtime_events() else {
        return Err(PlatformApiError::service_unavailable(
            "runtime event stream is not configured",
        ));
    };

    tracing::debug!(
        platform_api_principal = %principal.name,
        endpoint = "/v2/api/stream/findings",
        host_id = ?query.host_id,
        strategy_id = ?query.strategy_id,
        threat_class = ?query.threat_class,
        severity = ?query.severity,
        "serving platform findings stream"
    );

    let stream = BroadcastStream::new(receiver).filter_map(move |result| {
        let Ok(event) = result else {
            return None;
        };
        let RuntimeEvent::Finding {
            emitted_at_ms,
            host_id,
            finding,
        } = event
        else {
            return None;
        };
        if !finding_stream_matches_query(host_id.as_deref(), &finding, &query) {
            return None;
        }

        Some(Ok::<SseEvent, Infallible>(
            SseEvent::default()
                .event("finding")
                .id(emitted_at_ms.to_string())
                .data(serde_json::to_string(&finding).unwrap_or_else(|error| {
                    json!({
                        "schema": "serialization_error",
                        "reason": error.to_string(),
                    })
                    .to_string()
                })),
        ))
    });

    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::default().interval(Duration::from_secs(15)))
        .into_response())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod query_decoding_tests {
    use super::percent_decode_query_value;

    #[test]
    fn decodes_percent_encoded_colons() {
        // Finding/incident IDs commonly contain `:` which clients encode as
        // `%3A`. Without decoding, scope comparison rejects valid requests.
        assert_eq!(
            percent_decode_query_value("finding%3Aevt-1%3Ahost-a"),
            "finding:evt-1:host-a"
        );
    }

    #[test]
    fn decodes_plus_as_space() {
        assert_eq!(percent_decode_query_value("a+b"), "a b");
    }

    #[test]
    fn passes_through_unencoded_text() {
        assert_eq!(percent_decode_query_value("plain-id-123"), "plain-id-123");
    }

    #[test]
    fn leaves_malformed_percent_sequences_intact() {
        // Trailing `%` with no hex digits or non-hex follow-up: don't panic;
        // emit the byte as-is.
        assert_eq!(percent_decode_query_value("a%"), "a%");
        assert_eq!(percent_decode_query_value("a%ZZ"), "a%ZZ");
    }
}
