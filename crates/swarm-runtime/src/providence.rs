use crate::bridge_runtime::BridgeStatusReport;
use crate::runtime_events::now_ms;
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use swarm_core::agent::{AgentHealth, AgentHealthEntry, SwarmMode, SwarmModeState};
use swarm_core::config::{NotificationChannelConfig, OperatorSurfaceConfig};
use swarm_core::types::{
    ProvidenceCallbackAuditEntry, ProvidenceCreateIncidentBody, ProvidenceIncidentReconciliation,
    ProvidenceIncidentStatus, ProvidenceReconciliationOutcome, SWARM_PROVIDENCE_WEBHOOK_SCHEMA,
    SWARM_PROVIDENCE_WEBHOOK_SCHEMA_VERSION, Severity, SwarmProvidenceAggregateContext,
    SwarmProvidenceCallbackRequest, SwarmProvidenceFindingContext, SwarmProvidenceLinks,
    SwarmProvidenceRuntimeBridgeHealth, SwarmProvidenceRuntimeContext,
    SwarmProvidenceWebhookContract,
};
use swarm_crypto::{
    DetachedSignature, Ed25519Signer, canonical_json_bytes, hmac_sha256_hex,
    verify_detached_signature,
};
use swarm_response::{DeadLetterEntry, DeadLetterJournal, ExecutionMode};
use swarm_spine::{
    ConfiguredIncidentStore, CorrelatedIncident, ExternalReference, IncidentLookup,
    IncidentMemberDecision, IncidentRecord, IncidentStore,
};
use uuid::Uuid;

pub const PROVIDENCE_CHANNEL: &str = "providence_webhook";
pub const PROVIDENCE_EXTERNAL_SYSTEM: &str = "providence";
pub const SWARM_PROVIDENCE_CONTEXT_TOKEN_SCHEMA: &str = "swarm_providence_context_token";
const PROVIDENCE_RETRY_DELAYS_MS: [u64; 3] = [50, 100, 200];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvidenceContextScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hunt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_class: Option<swarm_core::ThreatClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvidenceContextTokenClaims {
    pub schema: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub nonce: String,
    pub scope: ProvidenceContextScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvidenceContextTokenEnvelope {
    pub claims: ProvidenceContextTokenClaims,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvidenceHealthStatus {
    pub configured: bool,
    pub reachable: bool,
    pub authenticated: bool,
    pub accepting_writes: bool,
    pub status: String,
    pub details: String,
}

impl ProvidenceHealthStatus {
    pub fn ready(&self) -> bool {
        self.configured && self.reachable && self.authenticated && self.accepting_writes
    }
}

#[derive(Debug, Clone)]
pub struct ProvidenceRuntimeContext {
    pub operator: OperatorSurfaceConfig,
    pub mode_state: SwarmModeState,
    pub agent_health: Vec<AgentHealthEntry>,
    pub bridge_health: BridgeStatusReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvidenceFeedbackTarget {
    pub incident_id: String,
    pub finding_id: String,
    pub hunt_id: String,
    pub event_id: String,
    pub host_id: Option<String>,
    pub strategy_id: Option<String>,
    pub threat_class: swarm_core::ThreatClass,
    pub severity: Severity,
}

impl ProvidenceContextScope {
    pub fn is_empty(&self) -> bool {
        self.incident_id.is_none()
            && self.hunt_id.is_none()
            && self.finding_id.is_none()
            && self.strategy_id.is_none()
            && self.threat_class.is_none()
    }
}

pub fn mint_providence_context_token(
    operator: &OperatorSurfaceConfig,
    scope: ProvidenceContextScope,
    issued_at_ms: i64,
) -> Result<String, String> {
    if scope.is_empty() {
        return Err("Providence context token scope must not be empty".to_string());
    }
    let secret_material = std::env::var(operator.auth.context_token_env())
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!(
                "operator surface context token env `{}` is missing or empty",
                operator.auth.context_token_env()
            )
        })?;
    let signer = Ed25519Signer::from_secret_material(&secret_material);
    let claims = ProvidenceContextTokenClaims {
        schema: SWARM_PROVIDENCE_CONTEXT_TOKEN_SCHEMA.to_string(),
        issued_at_ms,
        expires_at_ms: issued_at_ms + (operator.widget_token_ttl_secs as i64 * 1_000),
        nonce: Uuid::new_v4().to_string(),
        scope,
    };
    let payload = canonical_json_bytes(&claims).map_err(|error| error.to_string())?;
    let envelope = ProvidenceContextTokenEnvelope {
        claims,
        signature: signer.sign(&payload),
    };
    Ok(hex::encode(
        serde_json::to_vec(&envelope).map_err(|error| error.to_string())?,
    ))
}

pub fn verify_providence_context_token(
    secret_material: &str,
    raw: &str,
    now_ms: i64,
) -> Result<ProvidenceContextTokenClaims, String> {
    let bytes = hex::decode(raw.trim()).map_err(|error| error.to_string())?;
    let envelope = serde_json::from_slice::<ProvidenceContextTokenEnvelope>(&bytes)
        .map_err(|error| error.to_string())?;
    if envelope.claims.schema != SWARM_PROVIDENCE_CONTEXT_TOKEN_SCHEMA {
        return Err(format!(
            "unexpected Providence context token schema `{}`",
            envelope.claims.schema
        ));
    }
    if envelope.claims.scope.is_empty() {
        return Err("Providence context token scope must not be empty".to_string());
    }
    if now_ms > envelope.claims.expires_at_ms {
        return Err("Providence context token has expired".to_string());
    }
    let payload = canonical_json_bytes(&envelope.claims).map_err(|error| error.to_string())?;
    verify_detached_signature(&payload, &envelope.signature).map_err(|error| error.to_string())?;
    let signer = Ed25519Signer::from_secret_material(secret_material);
    if envelope.signature.key_id != signer.key_id()
        || envelope.signature.public_key_hex != signer.public_key_hex()
    {
        return Err("Providence context token was not signed by the operator key".to_string());
    }
    Ok(envelope.claims)
}

fn append_query_params(url: String, params: &[(&str, Option<String>)]) -> String {
    let pairs = params
        .iter()
        .filter_map(|(key, value)| value.as_ref().map(|value| format!("{key}={value}")))
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        return url;
    }
    if url.contains('?') {
        format!("{url}&{}", pairs.join("&"))
    } else {
        format!("{url}?{}", pairs.join("&"))
    }
}

pub fn build_scoped_providence_links(
    operator: &OperatorSurfaceConfig,
    scope: ProvidenceContextScope,
) -> SwarmProvidenceLinks {
    let token = mint_providence_context_token(operator, scope.clone(), now_ms()).ok();
    let threat_class = scope.threat_class.as_ref().map(threat_class_slug);
    let dashboard = append_query_params(
        join_base_url(&operator.runtime_base_url, "/v1/demo/widget"),
        &[
            ("context_token", token.clone()),
            ("incident_id", scope.incident_id.clone()),
            ("hunt_id", scope.hunt_id.clone()),
            ("finding_id", scope.finding_id.clone()),
            ("strategy_id", scope.strategy_id.clone()),
            ("threat_class", threat_class.clone()),
        ],
    );
    let event_stream = append_query_params(
        join_base_url(&operator.runtime_base_url, "/v1/events/stream"),
        &[
            (
                "types",
                Some(
                    "agent_action,response_execution,concentration_snapshot,escalation,mode_transition,finding"
                        .to_string(),
                ),
            ),
            ("context_token", token.clone()),
            ("hunt_id", scope.hunt_id.clone()),
            ("finding_id", scope.finding_id.clone()),
            ("strategy_id", scope.strategy_id.clone()),
            ("threat_class", threat_class.clone()),
        ],
    );
    let finding_drilldown = append_query_params(
        join_base_url(&operator.runtime_base_url, "/v2/api/findings"),
        &[
            ("context_token", token.clone()),
            ("finding_id", scope.finding_id.clone()),
            ("hunt_id", scope.hunt_id.clone()),
            ("strategy_id", scope.strategy_id.clone()),
            ("threat_class", threat_class.clone()),
        ],
    );
    let incident = append_query_params(
        join_base_url(&operator.runtime_base_url, "/v2/api/incidents"),
        &[
            ("context_token", token),
            ("incident_id", scope.incident_id.clone()),
            ("hunt_id", scope.hunt_id.clone()),
        ],
    );
    SwarmProvidenceLinks {
        dashboard,
        event_stream,
        finding_drilldown,
        replay_bundle: append_query_params(
            join_base_url(&operator.public_base_url, "/v1/operator/replay"),
            &[("hunt_id", scope.hunt_id.clone())],
        ),
        audit_trail: append_query_params(
            join_base_url(&operator.public_base_url, "/v1/operator/review"),
            &[
                ("hunt_id", scope.hunt_id.clone()),
                ("incident_id", scope.incident_id.clone()),
            ],
        ),
        incident,
        review_home: append_query_params(
            join_base_url(&operator.public_base_url, "/v1/operator/review"),
            &[
                ("hunt_id", scope.hunt_id.clone()),
                ("incident_id", scope.incident_id.clone()),
            ],
        ),
    }
}

#[derive(Debug, Clone)]
struct ProvidenceRemoteIncident {
    remote_id: String,
    remote_url: Option<String>,
    severity: Severity,
    status: ProvidenceIncidentStatus,
}

#[derive(Debug, Clone, Default)]
struct ProvidenceAdapterState {
    open_incidents: BTreeMap<String, ProvidenceRemoteIncident>,
}

#[derive(Clone)]
pub struct ProvidenceIncidentAdapter {
    client: reqwest::Client,
    config: NotificationChannelConfig,
    journal: Arc<DeadLetterJournal>,
    state: Arc<Mutex<ProvidenceAdapterState>>,
}

impl ProvidenceIncidentAdapter {
    pub fn new(
        config: NotificationChannelConfig,
        max_dead_letter_bytes: Option<u64>,
    ) -> std::io::Result<Self> {
        let journal = Arc::new(DeadLetterJournal::new(
            PathBuf::from(&config.dead_letter_path),
            max_dead_letter_bytes,
        )?);
        Ok(Self {
            client: reqwest::Client::new(),
            config,
            journal,
            state: Arc::new(Mutex::new(ProvidenceAdapterState::default())),
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.config.target_url.trim().is_empty()
    }

    pub fn journal_path(&self) -> &PathBuf {
        self.journal.path()
    }

    pub async fn probe_health(&self) -> ProvidenceHealthStatus {
        let request = self
            .apply_auth(
                self.client
                    .get(self.config.target_url.clone())
                    .timeout(Duration::from_millis(self.config.timeout_ms)),
            )
            .send()
            .await;

        match request {
            Ok(response) => {
                let status = response.status();
                let (authenticated, accepting_writes, label, details) = match status {
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => (
                        false,
                        false,
                        "auth_failed",
                        format!("Providence rejected credentials with HTTP {status}"),
                    ),
                    StatusCode::METHOD_NOT_ALLOWED => (
                        true,
                        true,
                        "ok",
                        "Providence incidents endpoint is reachable".to_string(),
                    ),
                    _ if status.is_success() => (
                        true,
                        true,
                        "ok",
                        "Providence incidents endpoint is reachable".to_string(),
                    ),
                    _ if status.is_server_error() => (
                        true,
                        false,
                        "degraded",
                        format!("Providence returned HTTP {status}"),
                    ),
                    _ => (
                        true,
                        false,
                        "degraded",
                        format!("Providence returned HTTP {status}"),
                    ),
                };
                ProvidenceHealthStatus {
                    configured: true,
                    reachable: true,
                    authenticated,
                    accepting_writes,
                    status: label.to_string(),
                    details,
                }
            }
            Err(error) => ProvidenceHealthStatus {
                configured: true,
                reachable: false,
                authenticated: false,
                accepting_writes: false,
                status: "unreachable".to_string(),
                details: error.to_string(),
            },
        }
    }

    pub async fn sync_incidents(
        &self,
        incident_store: &ConfiguredIncidentStore,
        runtime: &ProvidenceRuntimeContext,
        limit: usize,
    ) -> Result<(), String> {
        let mut recent = incident_store
            .recent(limit)
            .map_err(|error| format!("failed to list recent incidents: {error}"))?;
        recent.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));

        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            for record in &recent {
                let Some(reference) = record
                    .external_references
                    .iter()
                    .find(|reference| reference.system == PROVIDENCE_EXTERNAL_SYSTEM)
                else {
                    continue;
                };
                let Some(incident_key) = providence_incident_key(record) else {
                    continue;
                };
                state.open_incidents.entry(incident_key).or_insert_with(|| {
                    let reconciliation = record.providence_reconciliation.as_ref();
                    ProvidenceRemoteIncident {
                        remote_id: reference.id.clone(),
                        remote_url: reconciliation
                            .and_then(|entry| entry.remote_incident_url.clone())
                            .or_else(|| reference.url.clone()),
                        severity: reconciliation
                            .map(|entry| entry.remote_severity)
                            .unwrap_or_else(|| record.severity.unwrap_or(Severity::Medium)),
                        status: reconciliation
                            .map(|entry| entry.remote_status)
                            .unwrap_or(ProvidenceIncidentStatus::Open),
                    }
                });
            }
        }

        if runtime.mode_state.current == SwarmMode::Normal {
            let keys = {
                let state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                state.open_incidents.keys().cloned().collect::<Vec<_>>()
            };
            for incident_key in keys {
                let Some(record) = recent.iter().find(|record| {
                    providence_incident_key(record).as_deref() == Some(&incident_key)
                }) else {
                    continue;
                };
                self.resolve_incident(record, runtime).await?;
            }
            return Ok(());
        }

        for record in recent {
            let Some(incident_key) = providence_incident_key(&record) else {
                continue;
            };
            if record
                .providence_reconciliation
                .as_ref()
                .is_some_and(|entry| entry.needs_review)
            {
                tracing::warn!(
                    incident_id = %record.incident_id,
                    outcome = ?record
                        .providence_reconciliation
                        .as_ref()
                        .map(|entry| entry.outcome),
                    "Providence reconciliation requires review; skipping automatic sync"
                );
                continue;
            }
            let target_severity = mode_adjusted_severity(
                record.severity.unwrap_or(Severity::Medium),
                runtime.mode_state.current,
            );
            let target_status = mode_adjusted_status(runtime.mode_state.current);
            let maybe_reference = record
                .external_references
                .iter()
                .find(|reference| reference.system == PROVIDENCE_EXTERNAL_SYSTEM)
                .cloned();
            if let Some(reference) = maybe_reference {
                {
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner());
                    state
                        .open_incidents
                        .entry(incident_key.clone())
                        .or_insert_with(|| ProvidenceRemoteIncident {
                            remote_id: reference.id,
                            remote_url: reference.url,
                            severity: target_severity,
                            status: target_status,
                        });
                }
                self.update_incident(&record, runtime, target_severity, target_status)
                    .await?;
            } else {
                self.create_incident(incident_store, &record, runtime, incident_key)
                    .await?;
            }
        }

        Ok(())
    }

    async fn create_incident(
        &self,
        incident_store: &ConfiguredIncidentStore,
        record: &IncidentRecord,
        runtime: &ProvidenceRuntimeContext,
        incident_key: String,
    ) -> Result<(), String> {
        let contract = build_providence_contract(record, runtime, incident_key.clone());
        let response = self
            .send_with_retries(
                "create_incident",
                Method::POST,
                self.config.target_url.clone(),
                &incident_key,
                &contract,
            )
            .await?;
        let remote_id = extract_remote_id(&response).unwrap_or_else(|| incident_key.clone());
        let remote_url = extract_remote_url(&response)
            .or_else(|| join_target_url(&self.config.target_url, &remote_id).ok());
        let _ = incident_store
            .upsert_external_reference(
                &record.incident_id,
                ExternalReference {
                    system: PROVIDENCE_EXTERNAL_SYSTEM.to_string(),
                    id: remote_id.clone(),
                    url: remote_url.clone(),
                },
            )
            .map_err(|error| format!("failed to persist Providence external reference: {error}"))?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.open_incidents.insert(
            incident_key,
            ProvidenceRemoteIncident {
                remote_id,
                remote_url,
                severity: contract.create_incident.severity,
                status: contract.create_incident.status,
            },
        );
        Ok(())
    }

    async fn update_incident(
        &self,
        record: &IncidentRecord,
        runtime: &ProvidenceRuntimeContext,
        target_severity: Severity,
        target_status: ProvidenceIncidentStatus,
    ) -> Result<(), String> {
        let Some(incident_key) = providence_incident_key(record) else {
            return Ok(());
        };
        let handle = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            state.open_incidents.get(&incident_key).cloned()
        };
        let Some(handle) = handle else {
            return Ok(());
        };
        if handle.severity == target_severity && handle.status == target_status {
            return Ok(());
        }
        let contract = build_providence_contract(record, runtime, incident_key.clone())
            .with_status(target_status)
            .with_severity(target_severity);
        let update_url = handle
            .remote_url
            .clone()
            .or_else(|| join_target_url(&self.config.target_url, &handle.remote_id).ok())
            .ok_or_else(|| "failed to derive Providence incident update URL".to_string())?;
        self.send_with_retries(
            "update_incident",
            Method::PUT,
            update_url,
            &incident_key,
            &contract,
        )
        .await?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(existing) = state.open_incidents.get_mut(&incident_key) {
            existing.severity = target_severity;
            existing.status = target_status;
        }
        Ok(())
    }

    async fn resolve_incident(
        &self,
        record: &IncidentRecord,
        runtime: &ProvidenceRuntimeContext,
    ) -> Result<(), String> {
        let Some(incident_key) = providence_incident_key(record) else {
            return Ok(());
        };
        let handle = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            state.open_incidents.get(&incident_key).cloned()
        };
        let Some(handle) = handle else {
            return Ok(());
        };
        if handle.status == ProvidenceIncidentStatus::Resolved {
            return Ok(());
        }
        let contract = build_providence_contract(record, runtime, incident_key.clone())
            .with_status(ProvidenceIncidentStatus::Resolved)
            .with_severity(handle.severity);
        let update_url = handle
            .remote_url
            .clone()
            .or_else(|| join_target_url(&self.config.target_url, &handle.remote_id).ok())
            .ok_or_else(|| "failed to derive Providence incident resolve URL".to_string())?;
        self.send_with_retries(
            "resolve_incident",
            Method::PUT,
            update_url,
            &incident_key,
            &contract,
        )
        .await?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(existing) = state.open_incidents.get_mut(&incident_key) {
            existing.status = ProvidenceIncidentStatus::Resolved;
        }
        Ok(())
    }

    async fn send_with_retries<T>(
        &self,
        action: &str,
        method: Method,
        url: String,
        incident_key: &str,
        payload: &T,
    ) -> Result<Value, String>
    where
        T: Serialize,
    {
        let value = serde_json::to_value(payload)
            .map_err(|error| format!("failed to serialize payload: {error}"))?;
        let body_bytes = canonical_json_bytes(&value)
            .map_err(|error| format!("failed to encode Providence payload: {error}"))?;
        let mut last_error = String::new();
        for (attempt_index, delay_ms) in PROVIDENCE_RETRY_DELAYS_MS.iter().enumerate() {
            match self
                .send_request(
                    method.clone(),
                    &url,
                    incident_key,
                    body_bytes.clone(),
                    action,
                )
                .await
            {
                Ok(response) => return Ok(response),
                Err(error) => {
                    last_error = error;
                    if attempt_index + 1 < PROVIDENCE_RETRY_DELAYS_MS.len() {
                        tokio::time::sleep(Duration::from_millis(*delay_ms)).await;
                    }
                }
            }
        }
        self.write_dead_letter(
            action,
            PROVIDENCE_RETRY_DELAYS_MS.len() as u32,
            last_error.clone(),
            json!({
                "incident_key": incident_key,
                "request_url": url,
                "notification_payload": value,
            }),
        );
        Err(last_error)
    }

    async fn send_request(
        &self,
        method: Method,
        url: &str,
        incident_key: &str,
        body_bytes: Vec<u8>,
        action: &str,
    ) -> Result<Value, String> {
        let mut request = self
            .apply_auth(
                self.client
                    .request(method, url)
                    .timeout(Duration::from_millis(self.config.timeout_ms)),
            )
            .header("content-type", "application/json")
            .header("idempotency-key", incident_key)
            .body(body_bytes.clone());
        if let Some(signature) = &self.config.request_signature {
            request = request.header(
                signature.header.as_str(),
                format!(
                    "sha256={}",
                    hmac_sha256_hex(signature.secret.as_bytes(), &body_bytes)
                ),
            );
        }
        let response = request
            .send()
            .await
            .map_err(|error| format!("Providence {action} request failed: {error}"))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| format!("Providence {action} response read failed: {error}"))?;
        let parsed = if body.is_empty() {
            json!({})
        } else {
            serde_json::from_slice::<Value>(&body).unwrap_or_else(|_| {
                json!({
                    "raw_body": String::from_utf8_lossy(&body),
                })
            })
        };
        if status.is_success() {
            Ok(parsed)
        } else {
            Err(format!(
                "Providence {action} returned HTTP {status}: {parsed}"
            ))
        }
    }

    fn apply_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(auth_token) = &self.config.auth_token {
            request.bearer_auth(auth_token)
        } else {
            request
        }
    }

    fn write_dead_letter(&self, action: &str, attempts: u32, last_error: String, details: Value) {
        let entry = DeadLetterEntry {
            timestamp_ms: now_ms(),
            receipt_id: format!("providence:{action}:{}", now_ms()),
            action: action.to_string(),
            mode: ExecutionMode::Enforced,
            adapter: PROVIDENCE_EXTERNAL_SYSTEM.to_string(),
            attempts,
            last_error,
            details,
        };
        if let Err(error) = self.journal.write(&entry) {
            tracing::error!(reason = %error, "failed to write Providence dead-letter entry");
        }
    }
}

trait ProvidenceContractExt {
    fn with_status(self, status: ProvidenceIncidentStatus) -> Self;
    fn with_severity(self, severity: Severity) -> Self;
}

impl ProvidenceContractExt for SwarmProvidenceWebhookContract {
    fn with_status(mut self, status: ProvidenceIncidentStatus) -> Self {
        self.create_incident.status = status;
        self
    }

    fn with_severity(mut self, severity: Severity) -> Self {
        self.create_incident.severity = severity;
        self.finding.severity = severity;
        self
    }
}

pub fn providence_incident_key(record: &IncidentRecord) -> Option<String> {
    Some(format!(
        "{}:{}:{}",
        record.trigger_strategy_id.as_ref()?,
        threat_class_slug(record.threat_class.as_ref()?),
        record.trigger_finding_id.as_ref()?,
    ))
}

pub fn resolve_feedback_target(
    lookup: &IncidentLookup,
    finding_id: Option<&str>,
) -> Result<ProvidenceFeedbackTarget, String> {
    let member =
        select_feedback_member(&lookup.incident.included_members, finding_id).ok_or_else(|| {
            match finding_id {
                Some(finding_id) => format!(
                    "incident `{}` does not contain finding `{finding_id}`",
                    lookup.record.incident_id
                ),
                None => format!(
                    "incident `{}` does not expose any included finding",
                    lookup.record.incident_id
                ),
            }
        })?;
    let event_id = lookup
        .record
        .trigger_event_id
        .clone()
        .unwrap_or_else(|| member.hunt_id.clone());
    Ok(ProvidenceFeedbackTarget {
        incident_id: lookup.record.incident_id.clone(),
        finding_id: member.finding_id.clone(),
        hunt_id: member.hunt_id.clone(),
        event_id,
        host_id: extract_host_id_from_keys(&member.shared_keys)
            .or_else(|| extract_host_id_from_keys(&lookup.record.correlation_keys)),
        strategy_id: lookup.record.trigger_strategy_id.clone(),
        threat_class: lookup
            .record
            .threat_class
            .clone()
            .unwrap_or_else(|| swarm_core::ThreatClass::Custom("unknown".to_string())),
        severity: lookup.record.severity.unwrap_or(Severity::Medium),
    })
}

fn extract_host_id_from_keys(keys: &[String]) -> Option<String> {
    keys.iter()
        .find_map(|key| key.strip_prefix("host:").map(ToString::to_string))
}

pub fn resolve_callback_incident(
    incident_store: &ConfiguredIncidentStore,
    request: &SwarmProvidenceCallbackRequest,
) -> Result<IncidentLookup, String> {
    if let Some(incident_id) = request.incident_id.as_deref()
        && let Some(lookup) = incident_store
            .load_by_incident_id(incident_id)
            .map_err(|error| error.to_string())?
    {
        return Ok(lookup);
    }

    let recent = incident_store
        .recent(usize::MAX)
        .map_err(|error| error.to_string())?;

    if let Some(record) = recent.iter().find(|record| {
        record.external_references.iter().any(|reference| {
            reference.system == PROVIDENCE_EXTERNAL_SYSTEM
                && reference.id == request.remote_incident_id
        })
    }) {
        return incident_store
            .load_by_incident_id(&record.incident_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| {
                format!(
                    "incident `{}` disappeared during Providence callback reconciliation",
                    record.incident_id
                )
            });
    }

    if let Some(record) = recent
        .iter()
        .find(|record| providence_incident_key(record).as_deref() == Some(&request.incident_key))
    {
        return incident_store
            .load_by_incident_id(&record.incident_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| {
                format!(
                    "incident `{}` disappeared during Providence callback reconciliation",
                    record.incident_id
                )
            });
    }

    Err(format!(
        "no incident matched Providence callback remote_id=`{}` incident_key=`{}`",
        request.remote_incident_id, request.incident_key
    ))
}

pub fn build_providence_reconciliation(
    record: &IncidentRecord,
    mode_state: &SwarmModeState,
    request: &SwarmProvidenceCallbackRequest,
    reconciled_at_ms: i64,
) -> ProvidenceIncidentReconciliation {
    let swarm_status = mode_adjusted_status(mode_state.current);
    let swarm_severity = mode_adjusted_severity(
        record.severity.unwrap_or(Severity::Medium),
        mode_state.current,
    );
    let expected_key = providence_incident_key(record);
    let key_mismatch = expected_key
        .as_deref()
        .is_some_and(|expected| expected != request.incident_key);
    let remote_rank = providence_status_rank(request.status);
    let swarm_rank = providence_status_rank(swarm_status);
    let (outcome, needs_review, summary) = if key_mismatch {
        let expected = expected_key.unwrap_or_else(|| "unavailable".to_string());
        (
            ProvidenceReconciliationOutcome::Mismatch,
            true,
            format!(
                "Providence callback incident_key `{}` did not match the Swarm incident key `{expected}`.",
                request.incident_key
            ),
        )
    } else if request.status == swarm_status && request.severity == swarm_severity {
        (
            ProvidenceReconciliationOutcome::InSync,
            false,
            format!(
                "Providence and Swarm agree on status `{}` and severity `{}`.",
                providence_status_label(request.status),
                severity_label(request.severity)
            ),
        )
    } else if remote_rank > swarm_rank {
        (
            ProvidenceReconciliationOutcome::ProvidenceAhead,
            true,
            format!(
                "Providence is ahead: remote status `{}` exceeds Swarm status `{}`.",
                providence_status_label(request.status),
                providence_status_label(swarm_status)
            ),
        )
    } else if remote_rank < swarm_rank {
        (
            ProvidenceReconciliationOutcome::SwarmAhead,
            true,
            format!(
                "Swarm is ahead: local status `{}` exceeds Providence status `{}`.",
                providence_status_label(swarm_status),
                providence_status_label(request.status)
            ),
        )
    } else {
        (
            ProvidenceReconciliationOutcome::Mismatch,
            true,
            format!(
                "Providence and Swarm disagree on severity: remote `{}` vs local `{}`.",
                severity_label(request.severity),
                severity_label(swarm_severity)
            ),
        )
    };

    ProvidenceIncidentReconciliation {
        incident_key: request.incident_key.clone(),
        remote_incident_id: request.remote_incident_id.clone(),
        remote_incident_url: request.remote_incident_url.clone(),
        remote_status: request.status,
        remote_severity: request.severity,
        swarm_status,
        swarm_severity,
        remote_updated_at_ms: request.updated_at_ms,
        reconciled_at_ms,
        outcome,
        needs_review,
        summary,
    }
}

pub fn apply_providence_callback_reconciliation(
    incident: &mut CorrelatedIncident,
    request: &SwarmProvidenceCallbackRequest,
    request_signature: String,
    payload: Value,
    reconciliation: ProvidenceIncidentReconciliation,
    received_at_ms: i64,
) {
    upsert_external_reference(
        &mut incident.external_references,
        ExternalReference {
            system: PROVIDENCE_EXTERNAL_SYSTEM.to_string(),
            id: request.remote_incident_id.clone(),
            url: request.remote_incident_url.clone(),
        },
    );
    incident.providence_reconciliation = Some(reconciliation.clone());
    incident
        .providence_callback_audit_entries
        .push(ProvidenceCallbackAuditEntry {
            callback_id: format!(
                "providence-callback:{}:{received_at_ms}",
                sanitize_callback_id(&incident.incident_id)
            ),
            received_at_ms,
            event: request.event,
            incident_key: request.incident_key.clone(),
            remote_incident_id: request.remote_incident_id.clone(),
            request_signature,
            payload,
            reconciliation,
        });
}

fn select_feedback_member<'a>(
    members: &'a [IncidentMemberDecision],
    finding_id: Option<&str>,
) -> Option<&'a IncidentMemberDecision> {
    finding_id
        .and_then(|finding_id| {
            members
                .iter()
                .find(|member| member.finding_id == finding_id)
        })
        .or_else(|| members.first())
}

fn providence_status_rank(status: ProvidenceIncidentStatus) -> u8 {
    match status {
        ProvidenceIncidentStatus::Open => 0,
        ProvidenceIncidentStatus::Investigating => 1,
        ProvidenceIncidentStatus::Resolved => 2,
    }
}

fn providence_status_label(status: ProvidenceIncidentStatus) -> &'static str {
    match status {
        ProvidenceIncidentStatus::Open => "open",
        ProvidenceIncidentStatus::Investigating => "investigating",
        ProvidenceIncidentStatus::Resolved => "resolved",
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn upsert_external_reference(
    references: &mut Vec<ExternalReference>,
    external_reference: ExternalReference,
) {
    if let Some(existing) = references
        .iter_mut()
        .find(|existing| existing.system == external_reference.system)
    {
        *existing = external_reference;
    } else {
        references.push(external_reference);
    }
}

fn sanitize_callback_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}

fn build_providence_contract(
    record: &IncidentRecord,
    runtime: &ProvidenceRuntimeContext,
    incident_key: String,
) -> SwarmProvidenceWebhookContract {
    let (active_agent_count, degraded_agent_count, failed_agent_count) =
        active_agent_counts(&runtime.agent_health);
    let trigger_event_id = record.trigger_event_id.clone().unwrap_or_else(|| {
        record
            .included_hunt_ids
            .first()
            .cloned()
            .unwrap_or_default()
    });
    let trigger_finding_id = record.trigger_finding_id.clone().unwrap_or_default();
    let trigger_strategy_id = record.trigger_strategy_id.clone().unwrap_or_default();
    let threat_class = record
        .threat_class
        .clone()
        .unwrap_or_else(|| swarm_core::ThreatClass::Custom("unknown".to_string()));
    let severity = mode_adjusted_severity(
        record.severity.unwrap_or(Severity::Medium),
        runtime.mode_state.current,
    );
    let links = build_scoped_providence_links(
        &runtime.operator,
        ProvidenceContextScope {
            incident_id: Some(record.incident_id.clone()),
            hunt_id: Some(trigger_event_id.clone()),
            finding_id: Some(trigger_finding_id.clone()),
            strategy_id: Some(trigger_strategy_id.clone()),
            threat_class: Some(threat_class.clone()),
        },
    );
    SwarmProvidenceWebhookContract {
        schema: SWARM_PROVIDENCE_WEBHOOK_SCHEMA.to_string(),
        schema_version: SWARM_PROVIDENCE_WEBHOOK_SCHEMA_VERSION,
        channel: PROVIDENCE_CHANNEL.to_string(),
        incident_key,
        create_incident: ProvidenceCreateIncidentBody {
            title: format!(
                "{} incident correlated by {}",
                threat_class_slug(&threat_class),
                trigger_strategy_id
            ),
            severity,
            status: mode_adjusted_status(runtime.mode_state.current),
            source: "swarm-team-six".to_string(),
            description: build_providence_incident_description(
                record,
                runtime.mode_state.current,
                &links,
                runtime.agent_health.len(),
                active_agent_count,
                degraded_agent_count,
                failed_agent_count,
                runtime.bridge_health.status(),
            ),
        },
        finding: SwarmProvidenceFindingContext {
            schema: "swarm_correlated_incident".to_string(),
            finding_id: trigger_finding_id.clone(),
            event_id: trigger_event_id.clone(),
            strategy_id: trigger_strategy_id,
            threat_class: threat_class.clone(),
            severity,
            confidence: 1.0,
            evidence: json!({
                "incident_id": record.incident_id,
                "included_hunt_ids": record.included_hunt_ids,
                "correlation_keys": record.correlation_keys,
            }),
        },
        aggregate: SwarmProvidenceAggregateContext {
            first_seen_ms: record.created_at_ms,
            last_seen_ms: record.created_at_ms,
            count: record.included_hunt_ids.len(),
        },
        runtime: SwarmProvidenceRuntimeContext {
            mode: runtime.mode_state.current,
            registered_agent_count: runtime.agent_health.len(),
            active_agent_count,
            degraded_agent_count,
            failed_agent_count,
            bridge_health: SwarmProvidenceRuntimeBridgeHealth {
                status: runtime.bridge_health.status().to_string(),
                configured: runtime.bridge_health.configured,
                ok: runtime.bridge_health.ok,
                degraded: runtime.bridge_health.degraded,
                idle: runtime.bridge_health.idle,
                entries: runtime
                    .bridge_health
                    .entries
                    .iter()
                    .map(|entry| {
                        json!({
                            "name": entry.name,
                            "source_id": entry.source_id,
                            "status": entry.status(),
                            "ready": entry.ready,
                            "events_processed": entry.events_processed,
                            "error_count": entry.error_count,
                            "lag_seconds": entry.lag_seconds,
                            "last_error": entry.last_error,
                        })
                    })
                    .collect(),
            },
        },
        links,
    }
}

fn mode_adjusted_status(mode: SwarmMode) -> ProvidenceIncidentStatus {
    match mode {
        SwarmMode::Normal => ProvidenceIncidentStatus::Resolved,
        SwarmMode::Alert | SwarmMode::Incident => ProvidenceIncidentStatus::Open,
    }
}

fn mode_adjusted_severity(severity: Severity, mode: SwarmMode) -> Severity {
    match mode {
        SwarmMode::Incident => severity.max(Severity::Critical),
        SwarmMode::Alert => severity.max(Severity::High),
        SwarmMode::Normal => severity,
    }
}

fn extract_remote_id(value: &Value) -> Option<String> {
    value
        .get("id")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            value
                .get("incident_id")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .or_else(|| {
            value
                .get("data")
                .and_then(|data| data.get("id"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
}

fn extract_remote_url(value: &Value) -> Option<String> {
    value
        .get("url")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            value
                .get("links")
                .and_then(|links| links.get("self"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
}

fn join_target_url(target_url: &str, remote_id: &str) -> Result<String, String> {
    let mut url = Url::parse(target_url)
        .map_err(|error| format!("invalid Providence target URL: {error}"))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| "Providence target URL cannot be a base".to_string())?;
        segments.pop_if_empty();
        segments.push(remote_id);
    }
    Ok(url.to_string())
}

fn join_base_url(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

fn threat_class_slug(threat_class: &swarm_core::ThreatClass) -> String {
    serde_json::to_value(threat_class)
        .ok()
        .and_then(|value| value.as_str().map(ToString::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn active_agent_counts(entries: &[AgentHealthEntry]) -> (usize, usize, usize) {
    let degraded = entries
        .iter()
        .filter(|entry| entry.health == AgentHealth::Degraded)
        .count();
    let failed = entries
        .iter()
        .filter(|entry| entry.health == AgentHealth::Failed)
        .count();
    let active = entries
        .iter()
        .filter(|entry| entry.health != AgentHealth::Failed)
        .count();
    (active, degraded, failed)
}

#[allow(clippy::too_many_arguments)]
fn build_providence_incident_description(
    record: &IncidentRecord,
    mode: SwarmMode,
    links: &SwarmProvidenceLinks,
    registered_agent_count: usize,
    active_agent_count: usize,
    degraded_agent_count: usize,
    failed_agent_count: usize,
    bridge_status: &str,
) -> String {
    format!(
        "Swarm incident {incident_id} is in {mode:?} mode.\n\
Trigger finding: {finding_id}\n\
Included hunts: {included_hunts}\n\
Correlation keys: {correlation_keys}\n\
Registered agents: {registered_agent_count} (active={active_agent_count}, degraded={degraded_agent_count}, failed={failed_agent_count})\n\
Bridge health: {bridge_status}\n\
Incident review: {incident_link}\n\
Replay bundle: {replay_link}\n\
Review home: {review_link}",
        incident_id = record.incident_id,
        finding_id = record.trigger_finding_id.as_deref().unwrap_or("unknown"),
        included_hunts = record.included_hunt_ids.join(", "),
        correlation_keys = record.correlation_keys.join(", "),
        incident_link = links.incident,
        replay_link = links.replay_bundle,
        review_link = links.review_home,
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
pub mod tests {
    use super::{
        PROVIDENCE_EXTERNAL_SYSTEM, ProvidenceIncidentAdapter, ProvidenceRuntimeContext,
        providence_incident_key,
    };
    use crate::bridge_runtime::BridgeStatusReport;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::routing::{get, put};
    use axum::{Json, Router};
    use serde_json::Value;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use swarm_core::agent::SwarmModeState;
    use swarm_core::config::{
        BundleStoreConfig, NotificationChannelConfig, NotificationRateLimitConfig,
        OperatorSurfaceConfig,
    };
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::{
        ProvidenceIncidentReconciliation, ProvidenceReconciliationOutcome, Severity,
    };
    use swarm_spine::{
        ConfiguredIncidentStore, CorrelatedIncident, ExternalReference, IncidentMemberDecision,
        IncidentStore,
    };
    use tokio::sync::{Mutex, oneshot};

    #[derive(Clone, Default)]
    struct TestProvidenceState {
        requests: Arc<Mutex<Vec<(String, Value)>>>,
        create_failures_remaining: Arc<Mutex<usize>>,
    }

    async fn health_handler() -> StatusCode {
        StatusCode::METHOD_NOT_ALLOWED
    }

    async fn create_handler(
        State(state): State<TestProvidenceState>,
        Json(payload): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        let mut failures = state.create_failures_remaining.lock().await;
        if *failures > 0 {
            *failures -= 1;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "temporary"})),
            );
        }
        state
            .requests
            .lock()
            .await
            .push(("POST".to_string(), payload.clone()));
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": "prov-incident-1"
            })),
        )
    }

    async fn update_handler(
        State(state): State<TestProvidenceState>,
        Path(id): Path<String>,
        Json(payload): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        let mut payload = payload;
        payload["remote_id"] = Value::String(id);
        state
            .requests
            .lock()
            .await
            .push(("PUT".to_string(), payload.clone()));
        (
            StatusCode::OK,
            Json(serde_json::json!({"id": "prov-incident-1"})),
        )
    }

    async fn spawn_providence_server(
        create_failures_remaining: usize,
    ) -> (
        String,
        TestProvidenceState,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = TestProvidenceState {
            requests: Arc::new(Mutex::new(Vec::new())),
            create_failures_remaining: Arc::new(Mutex::new(create_failures_remaining)),
        };
        let app = Router::new()
            .route("/incidents", get(health_handler).post(create_handler))
            .route("/incidents/{id}", put(update_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        (
            format!("http://{addr}/incidents"),
            state,
            shutdown_tx,
            handle,
        )
    }

    fn temp_path(label: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("swarm-runtime-providence-{label}-{nanos}.jsonl"))
            .display()
            .to_string()
    }

    fn incident_store() -> ConfiguredIncidentStore {
        ConfiguredIncidentStore::from_config(&BundleStoreConfig::Memory).unwrap()
    }

    fn sample_incident() -> CorrelatedIncident {
        CorrelatedIncident {
            incident_id: "incident:evt-1:1".to_string(),
            summary: "incident".to_string(),
            created_at_ms: 1_700_000_000_000,
            window_start_ms: 1_700_000_000_000,
            window_end_ms: 1_700_000_000_100,
            correlation_keys: vec!["host:host-1".to_string()],
            related_receipt_ids: vec!["receipt-1".to_string()],
            included_members: vec![IncidentMemberDecision {
                investigation_id: "investigation:evt-1".to_string(),
                hunt_id: "evt-1".to_string(),
                finding_id: "finding-1".to_string(),
                reason: "seed".to_string(),
                shared_keys: vec!["host:host-1".to_string()],
                evidence_links: Vec::new(),
                confidence_score: 1.0,
            }],
            rejected_members: Vec::new(),
            graph_dimensions: Vec::new(),
            confidence_score: 1.0,
            trigger_event_id: Some("evt-1".to_string()),
            trigger_finding_id: Some("finding-1".to_string()),
            trigger_strategy_id: Some("suspicious_process_tree".to_string()),
            threat_class: Some(ThreatClass::Execution),
            severity: Some(Severity::High),
            external_references: Vec::new(),
            providence_reconciliation: None,
            providence_callback_audit_entries: Vec::new(),
            feedback_audit_entries: Vec::new(),
            false_positive_measurements: Vec::new(),
        }
    }

    fn runtime_context(mode: swarm_core::agent::SwarmMode) -> ProvidenceRuntimeContext {
        let mut mode_state = SwarmModeState::new();
        if mode != swarm_core::agent::SwarmMode::Normal {
            mode_state.current = mode;
            mode_state.last_transition_at = Some(1_700_000_000_000);
            mode_state.triggering_threat_class = Some(ThreatClass::Execution);
        }
        ProvidenceRuntimeContext {
            operator: OperatorSurfaceConfig {
                enabled: true,
                bind_addr: "127.0.0.1:0".to_string(),
                auth: Default::default(),
                public_base_url: "https://swarm.example".to_string(),
                runtime_base_url: "https://runtime.example".to_string(),
                allowed_embed_origins: Vec::new(),
                max_list_results: 20,
                widget_token_ttl_secs: 900,
            },
            mode_state,
            agent_health: Vec::new(),
            bridge_health: BridgeStatusReport::default(),
        }
    }

    #[tokio::test]
    async fn sync_creates_updates_and_resolves_incidents() {
        let (target_url, state, shutdown_tx, handle) = spawn_providence_server(0).await;
        let store = incident_store();
        let record = store.persist(&sample_incident()).unwrap();
        assert_eq!(
            providence_incident_key(&record).as_deref(),
            Some("suspicious_process_tree:execution:finding-1")
        );
        let adapter = ProvidenceIncidentAdapter::new(
            NotificationChannelConfig {
                target_url,
                auth_token: Some("bearer".to_string()),
                request_signature: None,
                timeout_ms: 500,
                rate_limit: NotificationRateLimitConfig::default(),
                quiet_hours: None,
                dead_letter_path: temp_path("success"),
            },
            None,
        )
        .unwrap();

        adapter
            .sync_incidents(
                &store,
                &runtime_context(swarm_core::agent::SwarmMode::Alert),
                10,
            )
            .await
            .unwrap();
        adapter
            .sync_incidents(
                &store,
                &runtime_context(swarm_core::agent::SwarmMode::Incident),
                10,
            )
            .await
            .unwrap();
        adapter
            .sync_incidents(
                &store,
                &runtime_context(swarm_core::agent::SwarmMode::Normal),
                10,
            )
            .await
            .unwrap();

        let requests = state.requests.lock().await.clone();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].0, "POST");
        assert_eq!(requests[1].0, "PUT");
        assert_eq!(requests[2].0, "PUT");
        assert_eq!(
            requests[0].1["incident_key"],
            "suspicious_process_tree:execution:finding-1"
        );
        assert_eq!(requests[1].1["create_incident"]["severity"], "CRITICAL");
        assert_eq!(requests[2].1["create_incident"]["status"], "resolved");

        let persisted = store
            .load_by_incident_id("incident:evt-1:1")
            .unwrap()
            .unwrap();
        assert_eq!(persisted.record.external_references.len(), 1);
        assert_eq!(
            persisted.record.external_references[0].system,
            PROVIDENCE_EXTERNAL_SYSTEM
        );

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn sync_skips_incidents_with_review_required_reconciliation() {
        let (target_url, state, shutdown_tx, handle) = spawn_providence_server(0).await;
        let store = incident_store();
        let mut incident = sample_incident();
        incident.external_references.push(ExternalReference {
            system: PROVIDENCE_EXTERNAL_SYSTEM.to_string(),
            id: "prov-incident-review".to_string(),
            url: Some("http://127.0.0.1/incidents/prov-incident-review".to_string()),
        });
        incident.providence_reconciliation = Some(ProvidenceIncidentReconciliation {
            incident_key: "suspicious_process_tree:execution:finding-1".to_string(),
            remote_incident_id: "prov-incident-review".to_string(),
            remote_incident_url: Some(
                "http://127.0.0.1/incidents/prov-incident-review".to_string(),
            ),
            remote_status: super::ProvidenceIncidentStatus::Resolved,
            remote_severity: Severity::High,
            swarm_status: super::ProvidenceIncidentStatus::Open,
            swarm_severity: Severity::High,
            remote_updated_at_ms: 1_700_000_000_500,
            reconciled_at_ms: 1_700_000_000_600,
            outcome: ProvidenceReconciliationOutcome::ProvidenceAhead,
            needs_review: true,
            summary: "Providence resolved the incident before Swarm did.".to_string(),
        });
        store.persist(&incident).unwrap();

        let adapter = ProvidenceIncidentAdapter::new(
            NotificationChannelConfig {
                target_url,
                auth_token: Some("bearer".to_string()),
                request_signature: None,
                timeout_ms: 500,
                rate_limit: NotificationRateLimitConfig::default(),
                quiet_hours: None,
                dead_letter_path: temp_path("review-blocked"),
            },
            None,
        )
        .unwrap();

        adapter
            .sync_incidents(
                &store,
                &runtime_context(swarm_core::agent::SwarmMode::Alert),
                10,
            )
            .await
            .unwrap();

        let requests = state.requests.lock().await.clone();
        assert!(requests.is_empty());

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn adapter_retries_and_dead_letters_failures() {
        let (target_url, _state, shutdown_tx, handle) = spawn_providence_server(3).await;
        let store = incident_store();
        store.persist(&sample_incident()).unwrap();
        let adapter = ProvidenceIncidentAdapter::new(
            NotificationChannelConfig {
                target_url,
                auth_token: Some("bearer".to_string()),
                request_signature: None,
                timeout_ms: 500,
                rate_limit: NotificationRateLimitConfig::default(),
                quiet_hours: None,
                dead_letter_path: temp_path("failure"),
            },
            None,
        )
        .unwrap();

        let error = adapter
            .sync_incidents(
                &store,
                &runtime_context(swarm_core::agent::SwarmMode::Alert),
                10,
            )
            .await
            .unwrap_err();
        assert!(error.contains("HTTP 503"));

        let raw = std::fs::read_to_string(adapter.journal_path()).unwrap();
        assert_eq!(raw.lines().count(), 1);
        let entry: swarm_response::DeadLetterEntry =
            serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(entry.action, "create_incident");
        assert_eq!(entry.attempts, 3);
        assert_eq!(
            entry.details["incident_key"],
            "suspicious_process_tree:execution:finding-1"
        );

        let _ = shutdown_tx.send(());
        handle.await.unwrap();
    }
}
