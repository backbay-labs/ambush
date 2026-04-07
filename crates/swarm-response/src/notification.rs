use crate::ExecutionMode;
use crate::config::{
    NotificationChannelConfig, NotificationRoutingConfig, QuietHoursConfig, RoutingRule,
};
use crate::dead_letter::{DeadLetterEntry, DeadLetterJournal};
use crate::siem::SwarmFindingEnvelope;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use swarm_core::pheromone::ThreatClass;
use swarm_whisker::DetectionFinding;
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    #[error("unknown notification channel `{channel}`")]
    UnknownChannel { channel: String },

    #[error("failed to read notification dead-letter journal for `{channel}`: {source}")]
    ReadDeadLetter {
        channel: String,
        #[source]
        source: std::io::Error,
    },

    #[error("notification replay entry `{receipt_id}` is missing a stored payload")]
    MissingPayload { receipt_id: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationReplayResult {
    pub channel: String,
    pub receipt_id: String,
    pub status: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AggregatedNotification {
    pub schema: String,
    pub channel: String,
    pub strategy_id: String,
    pub threat_class: ThreatClass,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub highest_severity: swarm_core::types::Severity,
    pub count: usize,
    pub sample_finding: SwarmFindingEnvelope,
}

#[derive(Clone)]
pub struct NotificationRouter {
    inner: Arc<NotificationRouterInner>,
}

struct NotificationRouterInner {
    routing: NotificationRoutingConfig,
    channels: BTreeMap<String, NotificationChannelState>,
    aggregates: Mutex<HashMap<NotificationAggregateKey, NotificationAggregateState>>,
    rate_limits: Mutex<HashMap<String, VecDeque<i64>>>,
}

#[derive(Clone)]
struct NotificationChannelState {
    config: NotificationChannelConfig,
    client: reqwest::Client,
    journal: Arc<DeadLetterJournal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NotificationAggregateKey {
    channel: String,
    strategy_id: String,
    threat_class: ThreatClass,
}

#[derive(Debug, Clone)]
struct NotificationAggregateState {
    key: NotificationAggregateKey,
    first_seen_ms: i64,
    last_seen_ms: i64,
    highest_severity: swarm_core::types::Severity,
    count: usize,
    sample_finding: SwarmFindingEnvelope,
}

impl NotificationRouter {
    pub fn new(
        channels: BTreeMap<String, NotificationChannelConfig>,
        routing: NotificationRoutingConfig,
    ) -> Self {
        let channels = channels
            .into_iter()
            .map(|(name, config)| {
                // TODO: thread max_dead_letter_bytes from RuntimeSettings
                let journal = Arc::new(DeadLetterJournal::from_path(
                    config.dead_letter_path.clone(),
                    None,
                ));
                (
                    name,
                    NotificationChannelState {
                        config,
                        client: reqwest::Client::new(),
                        journal,
                    },
                )
            })
            .collect();
        Self {
            inner: Arc::new(NotificationRouterInner {
                routing,
                channels,
                aggregates: Mutex::new(HashMap::new()),
                rate_limits: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.inner.channels.is_empty() && !self.inner.routing.rules.is_empty()
    }

    pub async fn route_finding(&self, finding: &DetectionFinding) {
        if !self.is_enabled() {
            return;
        }
        let now_ms = current_time_ms();
        let sample = SwarmFindingEnvelope::from(finding);
        let matched_channels = self.matching_channels(finding, now_ms);
        for channel in matched_channels {
            let key = NotificationAggregateKey {
                channel: channel.clone(),
                strategy_id: finding.strategy_id.clone(),
                threat_class: finding.threat_class.clone(),
            };
            let should_schedule = {
                let mut aggregates = self.inner.aggregates.lock().await;
                if let Some(existing) = aggregates.get_mut(&key) {
                    existing.last_seen_ms = now_ms;
                    existing.count = existing.count.saturating_add(1);
                    if finding.severity > existing.highest_severity {
                        existing.highest_severity = finding.severity;
                    }
                    existing.sample_finding = sample.clone();
                    false
                } else {
                    aggregates.insert(
                        key.clone(),
                        NotificationAggregateState {
                            key: key.clone(),
                            first_seen_ms: now_ms,
                            last_seen_ms: now_ms,
                            highest_severity: finding.severity,
                            count: 1,
                            sample_finding: sample.clone(),
                        },
                    );
                    true
                }
            };
            if should_schedule {
                let router = self.clone();
                let delay_ms = self.inner.routing.dedup_window_ms;
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    if let Err(error) = router.flush_key(key).await {
                        tracing::error!(reason = %error, "failed to flush notification aggregate");
                    }
                });
            }
        }
    }

    pub async fn list_dead_letters(
        &self,
        channel: &str,
        limit: Option<usize>,
    ) -> Result<Vec<DeadLetterEntry>, NotificationError> {
        let state =
            self.inner
                .channels
                .get(channel)
                .ok_or_else(|| NotificationError::UnknownChannel {
                    channel: channel.to_string(),
                })?;
        state
            .journal
            .read_entries(limit)
            .map_err(|source| NotificationError::ReadDeadLetter {
                channel: channel.to_string(),
                source,
            })
    }

    pub async fn replay_dead_letters(
        &self,
        channel: &str,
        receipt_ids: Option<Vec<String>>,
    ) -> Result<Vec<NotificationReplayResult>, NotificationError> {
        let entries = self.list_dead_letters(channel, None).await?;
        let selected = match receipt_ids {
            Some(receipt_ids) => entries
                .into_iter()
                .filter(|entry| receipt_ids.contains(&entry.receipt_id))
                .collect::<Vec<_>>(),
            None => entries,
        };
        let mut results = Vec::new();
        for entry in selected {
            let payload = entry
                .details
                .get("notification_payload")
                .cloned()
                .ok_or_else(|| NotificationError::MissingPayload {
                    receipt_id: entry.receipt_id.clone(),
                })?;
            match self.send_payload(channel, payload, true).await {
                Ok(()) => results.push(NotificationReplayResult {
                    channel: channel.to_string(),
                    receipt_id: entry.receipt_id,
                    status: "replayed".to_string(),
                    summary: "notification replayed".to_string(),
                }),
                Err(summary) => results.push(NotificationReplayResult {
                    channel: channel.to_string(),
                    receipt_id: entry.receipt_id,
                    status: "failed".to_string(),
                    summary,
                }),
            }
        }
        Ok(results)
    }

    fn matching_channels(&self, finding: &DetectionFinding, now_ms: i64) -> Vec<String> {
        let mut matched = Vec::new();
        for rule in &self.inner.routing.rules {
            if rule_matches(rule, finding, now_ms) {
                matched.extend(rule.channels.iter().cloned());
            }
        }
        matched.sort();
        matched.dedup();
        matched
    }

    async fn flush_key(&self, key: NotificationAggregateKey) -> Result<(), NotificationError> {
        let Some(aggregate) = ({
            let mut aggregates = self.inner.aggregates.lock().await;
            aggregates.remove(&key)
        }) else {
            return Ok(());
        };

        let payload = AggregatedNotification {
            schema: "swarm_notification".to_string(),
            channel: aggregate.key.channel.clone(),
            strategy_id: aggregate.key.strategy_id.clone(),
            threat_class: aggregate.key.threat_class.clone(),
            first_seen_ms: aggregate.first_seen_ms,
            last_seen_ms: aggregate.last_seen_ms,
            highest_severity: aggregate.highest_severity,
            count: aggregate.count,
            sample_finding: aggregate.sample_finding.clone(),
        };

        if self.channel_in_quiet_hours(&aggregate.key.channel, aggregate.last_seen_ms)? {
            self.write_dead_letter(
                &aggregate.key.channel,
                aggregate.last_seen_ms,
                "quiet hours active".to_string(),
                json!(payload),
            );
            return Ok(());
        }

        if !self
            .rate_limit_allows(&aggregate.key.channel, aggregate.last_seen_ms)
            .await?
        {
            self.write_dead_letter(
                &aggregate.key.channel,
                aggregate.last_seen_ms,
                "notification rate limit exceeded".to_string(),
                json!(payload),
            );
            return Ok(());
        }

        if let Err(summary) = self
            .send_payload(&aggregate.key.channel, json!(payload), false)
            .await
        {
            self.write_dead_letter(
                &aggregate.key.channel,
                aggregate.last_seen_ms,
                summary,
                json!(payload),
            );
        }

        Ok(())
    }

    async fn rate_limit_allows(
        &self,
        channel: &str,
        now_ms: i64,
    ) -> Result<bool, NotificationError> {
        let state =
            self.inner
                .channels
                .get(channel)
                .ok_or_else(|| NotificationError::UnknownChannel {
                    channel: channel.to_string(),
                })?;
        let mut guard = self.inner.rate_limits.lock().await;
        let queue = guard.entry(channel.to_string()).or_default();
        let window_ms = state.config.rate_limit.window_ms as i64;
        while let Some(oldest) = queue.front().copied() {
            if now_ms - oldest >= window_ms {
                queue.pop_front();
            } else {
                break;
            }
        }
        if queue.len() >= state.config.rate_limit.max_notifications {
            return Ok(false);
        }
        queue.push_back(now_ms);
        Ok(true)
    }

    fn channel_in_quiet_hours(
        &self,
        channel: &str,
        now_ms: i64,
    ) -> Result<bool, NotificationError> {
        let state =
            self.inner
                .channels
                .get(channel)
                .ok_or_else(|| NotificationError::UnknownChannel {
                    channel: channel.to_string(),
                })?;
        Ok(state
            .config
            .quiet_hours
            .as_ref()
            .is_some_and(|quiet_hours| quiet_hours_match(quiet_hours, now_ms)))
    }

    async fn send_payload(
        &self,
        channel: &str,
        payload: Value,
        bypass_limits: bool,
    ) -> Result<(), String> {
        let state = self
            .inner
            .channels
            .get(channel)
            .ok_or_else(|| format!("unknown notification channel `{channel}`"))?;
        let mut request = state
            .client
            .post(&state.config.target_url)
            .timeout(Duration::from_millis(state.config.timeout_ms))
            .json(&payload);
        if let Some(auth_token) = &state.config.auth_token {
            request = request.bearer_auth(auth_token);
        }
        if bypass_limits {
            request = request.header("x-swarm-replay", "true");
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => Ok(()),
            Ok(response) => Err(format!(
                "notification delivery failed with status {}",
                response.status().as_u16()
            )),
            Err(error) => Err(format!("notification delivery failed: {error}")),
        }
    }

    fn write_dead_letter(
        &self,
        channel: &str,
        timestamp_ms: i64,
        last_error: String,
        payload: Value,
    ) {
        if let Some(state) = self.inner.channels.get(channel) {
            let entry = DeadLetterEntry {
                timestamp_ms,
                receipt_id: format!("notification:{channel}:{timestamp_ms}"),
                action: "notify".to_string(),
                mode: ExecutionMode::Enforced,
                adapter: format!("notification:{channel}"),
                attempts: 1,
                last_error,
                details: json!({
                    "channel": channel,
                    "notification_payload": payload,
                }),
            };
            if let Err(error) = state.journal.write(&entry) {
                tracing::error!(
                    channel = channel,
                    path = %state.journal.path().display(),
                    reason = %error,
                    "failed to write notification dead-letter entry"
                );
            }
        }
    }
}

fn rule_matches(rule: &RoutingRule, finding: &DetectionFinding, now_ms: i64) -> bool {
    if let Some(min_severity) = rule.min_severity
        && finding.severity < min_severity
    {
        return false;
    }
    if let Some(threat_class) = &rule.threat_class
        && &finding.threat_class != threat_class
    {
        return false;
    }
    match (rule.utc_start_hour, rule.utc_end_hour) {
        (Some(start), Some(end)) => hour_in_window(hour_utc(now_ms), start, end),
        _ => true,
    }
}

fn quiet_hours_match(quiet_hours: &QuietHoursConfig, now_ms: i64) -> bool {
    hour_in_window(
        hour_utc(now_ms),
        quiet_hours.start_hour_utc,
        quiet_hours.end_hour_utc,
    )
}

fn hour_in_window(current_hour: u8, start_hour: u8, end_hour: u8) -> bool {
    if start_hour < end_hour {
        current_hour >= start_hour && current_hour < end_hour
    } else {
        current_hour >= start_hour || current_hour < end_hour
    }
}

fn hour_utc(timestamp_ms: i64) -> u8 {
    let seconds = timestamp_ms.div_euclid(1_000);
    let seconds_of_day = seconds.rem_euclid(86_400);
    (seconds_of_day / 3_600) as u8
}

fn current_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{NotificationRouter, current_time_ms};
    use crate::config::{
        NotificationChannelConfig, NotificationRateLimitConfig, NotificationRoutingConfig,
        RoutingRule,
    };
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;
    use swarm_whisker::DetectionFinding;
    use tokio::sync::{Mutex, oneshot};

    #[derive(Clone, Default)]
    struct CaptureState {
        payloads: Arc<Mutex<Vec<Value>>>,
        auth: Arc<Mutex<Option<String>>>,
    }

    async fn handler(
        State(state): State<CaptureState>,
        headers: HeaderMap,
        Json(payload): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        {
            let mut payloads = state.payloads.lock().await;
            payloads.push(payload);
        }
        {
            let mut auth = state.auth.lock().await;
            *auth = headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string);
        }
        (StatusCode::OK, Json(json!({"ok": true})))
    }

    async fn spawn_server() -> (
        String,
        CaptureState,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let state = CaptureState::default();
        let app = Router::new()
            .route("/", post(handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            });
            let _ = server.await;
        });
        (format!("http://{address}/"), state, shutdown_tx, handle)
    }

    fn finding(event_id: &str, strategy_id: &str) -> DetectionFinding {
        DetectionFinding {
            finding_id: format!("finding-{event_id}"),
            event_id: event_id.to_string(),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence: 0.9,
            evidence: json!({"event_id": event_id}),
            strategy_id: strategy_id.to_string(),
        }
    }

    #[tokio::test]
    async fn router_dedups_matching_findings_into_one_notification() {
        let (target_url, state, shutdown_tx, handle) = spawn_server().await;
        let mut channels = BTreeMap::new();
        channels.insert(
            "soc".to_string(),
            NotificationChannelConfig {
                target_url,
                auth_token: Some("notify-secret".to_string()),
                timeout_ms: 500,
                rate_limit: NotificationRateLimitConfig {
                    max_notifications: 10,
                    window_ms: 1_000,
                },
                quiet_hours: None,
                dead_letter_path: std::env::temp_dir()
                    .join(format!("notify-dedup-{}.jsonl", std::process::id()))
                    .display()
                    .to_string(),
            },
        );
        let router = NotificationRouter::new(
            channels,
            NotificationRoutingConfig {
                dedup_window_ms: 20,
                rules: vec![RoutingRule {
                    min_severity: Some(Severity::Medium),
                    threat_class: Some(ThreatClass::Execution),
                    utc_start_hour: None,
                    utc_end_hour: None,
                    channels: vec!["soc".to_string()],
                }],
            },
        );

        router
            .route_finding(&finding("event-1", "suspicious_process_tree"))
            .await;
        router
            .route_finding(&finding("event-2", "suspicious_process_tree"))
            .await;
        tokio::time::sleep(Duration::from_millis(80)).await;

        let payloads = state.payloads.lock().await.clone();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["count"], 2);
        assert_eq!(
            state.auth.lock().await.clone(),
            Some("Bearer notify-secret".to_string())
        );

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn router_writes_and_replays_rate_limited_notifications() {
        let (target_url, state, shutdown_tx, handle) = spawn_server().await;
        let dead_letter_path = std::env::temp_dir()
            .join(format!("notify-rate-limit-{}.jsonl", current_time_ms()))
            .display()
            .to_string();
        let mut channels = BTreeMap::new();
        channels.insert(
            "soc".to_string(),
            NotificationChannelConfig {
                target_url,
                auth_token: None,
                timeout_ms: 500,
                rate_limit: NotificationRateLimitConfig {
                    max_notifications: 1,
                    window_ms: 10_000,
                },
                quiet_hours: None,
                dead_letter_path: dead_letter_path.clone(),
            },
        );
        let router = NotificationRouter::new(
            channels,
            NotificationRoutingConfig {
                dedup_window_ms: 10,
                rules: vec![RoutingRule {
                    min_severity: Some(Severity::Low),
                    threat_class: Some(ThreatClass::Execution),
                    utc_start_hour: None,
                    utc_end_hour: None,
                    channels: vec!["soc".to_string()],
                }],
            },
        );

        router
            .route_finding(&finding("event-1", "strategy-a"))
            .await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        router
            .route_finding(&finding("event-2", "strategy-b"))
            .await;
        tokio::time::sleep(Duration::from_millis(40)).await;

        let entries = router.list_dead_letters("soc", None).await.unwrap();
        assert_eq!(entries.len(), 1);

        let results = router.replay_dead_letters("soc", None).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, "replayed");

        let payloads = state.payloads.lock().await.clone();
        assert_eq!(payloads.len(), 2);

        let _ = std::fs::remove_file(dead_letter_path);
        let _ = shutdown_tx.send(());
        handle.abort();
    }
}
