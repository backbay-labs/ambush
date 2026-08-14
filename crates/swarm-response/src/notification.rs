use crate::ExecutionMode;
use crate::config::{
    NotificationChannelConfig, NotificationRoutingConfig, QuietHoursConfig, RoutingRule,
};
use crate::dead_letter::{DeadLetterEntry, DeadLetterJournal};
use crate::siem::SwarmFindingEnvelope;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use swarm_core::pheromone::ThreatClass;
use swarm_crypto::{canonical_json_bytes, hmac_sha256_hex};
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

type ChannelPayloadBuilder =
    dyn Fn(&str, &AggregatedNotification) -> Option<Value> + Send + Sync + 'static;

struct NotificationRouterInner {
    routing: NotificationRoutingConfig,
    channels: BTreeMap<String, NotificationChannelState>,
    aggregates: Mutex<HashMap<NotificationAggregateKey, NotificationAggregateState>>,
    rate_limits: Mutex<HashMap<String, VecDeque<i64>>>,
    payload_builder: RwLock<Option<Arc<ChannelPayloadBuilder>>>,
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
    /// The clock reading at or after which this aggregate may be flushed:
    /// `first_seen_ms + dedup_window_ms`. Held on the aggregate rather than
    /// implied by a sleeping task so that "the window has elapsed" is a
    /// comparison against a caller-supplied `now_ms`, not a wall-clock wait.
    flush_due_ms: i64,
    highest_severity: swarm_core::types::Severity,
    count: usize,
    sample_finding: SwarmFindingEnvelope,
}

impl NotificationRouter {
    pub fn new(
        channels: BTreeMap<String, NotificationChannelConfig>,
        routing: NotificationRoutingConfig,
        max_dead_letter_bytes: Option<u64>,
    ) -> Self {
        let channels = channels
            .into_iter()
            .map(|(name, config)| {
                let journal = Arc::new(DeadLetterJournal::from_path(
                    config.dead_letter_path.clone(),
                    max_dead_letter_bytes,
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
                payload_builder: RwLock::new(None),
            }),
        }
    }

    pub fn set_payload_builder<F>(&self, builder: F)
    where
        F: Fn(&str, &AggregatedNotification) -> Option<Value> + Send + Sync + 'static,
    {
        let mut guard = self
            .inner
            .payload_builder
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        *guard = Some(Arc::new(builder));
    }

    pub fn is_enabled(&self) -> bool {
        !self.inner.channels.is_empty() && !self.inner.routing.rules.is_empty()
    }

    /// Aggregate `finding` and schedule the dedup-window flush against the wall
    /// clock.
    ///
    /// This is the wall-clock wrapper. The decision it delegates -- *has the
    /// dedup window elapsed?* -- lives in [`Self::flush_due`], which takes the
    /// clock reading as a parameter, so callers that must be deterministic
    /// (tests, replay) can drive the same code path without sleeping.
    pub async fn route_finding(&self, finding: &DetectionFinding) {
        let opened = self.route_finding_at(finding, current_time_ms()).await;
        if opened {
            let router = self.clone();
            let delay_ms = self.inner.routing.dedup_window_ms;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                // `sleep` never returns early, so by construction the wall clock
                // has passed every deadline opened at or before the schedule
                // point. `flush_due` still re-checks each one, and leaves any
                // aggregate opened later in this same window alone.
                if let Err(error) = router.flush_due(current_time_ms()).await {
                    tracing::error!(reason = %error, "failed to flush notification aggregate");
                }
            });
        }
    }

    /// Aggregate `finding` using an explicit clock reading, without scheduling
    /// anything.
    ///
    /// Returns whether at least one new aggregate was opened -- i.e. whether a
    /// flush now needs to be driven for a deadline that did not exist before.
    /// Findings folded into an already-open aggregate return `false`: their
    /// deadline was set by the finding that opened it.
    async fn route_finding_at(&self, finding: &DetectionFinding, now_ms: i64) -> bool {
        if !self.is_enabled() {
            return false;
        }
        let sample = SwarmFindingEnvelope::from(finding);
        let matched_channels = self.matching_channels(finding, now_ms);
        let flush_due_ms = now_ms.saturating_add_unsigned(self.inner.routing.dedup_window_ms);
        let mut opened = false;
        for channel in matched_channels {
            let key = NotificationAggregateKey {
                channel: channel.clone(),
                strategy_id: finding.strategy_id.clone(),
                threat_class: finding.threat_class.clone(),
            };
            let mut aggregates = self.inner.aggregates.lock().await;
            if let Some(existing) = aggregates.get_mut(&key) {
                existing.last_seen_ms = now_ms;
                existing.count = existing.count.saturating_add(1);
                if finding.severity > existing.highest_severity {
                    existing.highest_severity = finding.severity;
                }
                existing.sample_finding = sample.clone();
            } else {
                aggregates.insert(
                    key.clone(),
                    NotificationAggregateState {
                        key: key.clone(),
                        first_seen_ms: now_ms,
                        last_seen_ms: now_ms,
                        flush_due_ms,
                        highest_severity: finding.severity,
                        count: 1,
                        sample_finding: sample.clone(),
                    },
                );
                opened = true;
            }
        }
        opened
    }

    /// Flush every aggregate whose dedup window closed at or before `now_ms`,
    /// and report how many were delivered, dead-lettered, or otherwise
    /// consumed.
    ///
    /// Aggregates still inside their window are left untouched, so this is safe
    /// to call at any cadence.
    async fn flush_due(&self, now_ms: i64) -> Result<usize, NotificationError> {
        let mut due = {
            let aggregates = self.inner.aggregates.lock().await;
            aggregates
                .values()
                .filter(|state| state.flush_due_ms <= now_ms)
                .map(|state| (state.flush_due_ms, state.key.clone()))
                .collect::<Vec<_>>()
        };
        // `aggregates` is a HashMap, so iteration order is not stable. Flush in
        // deadline order (channel and strategy breaking ties) or a rate limit
        // would dead-letter an arbitrary member of a due batch.
        due.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.channel.cmp(&right.1.channel))
                .then_with(|| left.1.strategy_id.cmp(&right.1.strategy_id))
        });
        let mut flushed = 0usize;
        for (_, key) in due {
            if self.flush_key(key).await? {
                flushed += 1;
            }
        }
        Ok(flushed)
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

    /// Drain one aggregate and deliver it. Returns whether an aggregate was
    /// still present -- a concurrent flush may have taken it first.
    async fn flush_key(&self, key: NotificationAggregateKey) -> Result<bool, NotificationError> {
        let Some(aggregate) = ({
            let mut aggregates = self.inner.aggregates.lock().await;
            aggregates.remove(&key)
        }) else {
            return Ok(false);
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

        let payload = self
            .channel_payload(&aggregate.key.channel, &payload)
            .unwrap_or_else(|| json!(payload));

        if self.channel_in_quiet_hours(&aggregate.key.channel, aggregate.last_seen_ms)? {
            self.write_dead_letter(
                &aggregate.key.channel,
                aggregate.last_seen_ms,
                "quiet hours active".to_string(),
                payload,
            );
            return Ok(true);
        }

        if !self
            .rate_limit_allows(&aggregate.key.channel, aggregate.last_seen_ms)
            .await?
        {
            self.write_dead_letter(
                &aggregate.key.channel,
                aggregate.last_seen_ms,
                "notification rate limit exceeded".to_string(),
                payload,
            );
            return Ok(true);
        }

        if let Err(summary) = self
            .send_payload(&aggregate.key.channel, payload.clone(), false)
            .await
        {
            self.write_dead_letter(
                &aggregate.key.channel,
                aggregate.last_seen_ms,
                summary,
                payload,
            );
        }

        Ok(true)
    }

    fn channel_payload(&self, channel: &str, aggregate: &AggregatedNotification) -> Option<Value> {
        let guard = self
            .inner
            .payload_builder
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        guard
            .as_ref()
            .and_then(|builder| builder(channel, aggregate))
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
        let payload_bytes = canonical_json_bytes(&payload)
            .map_err(|error| format!("failed to encode notification payload: {error}"))?;
        let mut request = state
            .client
            .post(&state.config.target_url)
            .timeout(Duration::from_millis(state.config.timeout_ms))
            .header("content-type", "application/json")
            .body(payload_bytes.clone());
        if let Some(auth_token) = &state.config.auth_token {
            request = request.bearer_auth(auth_token.expose_secret());
        }
        if let Some(signature) = &state.config.request_signature {
            request = request.header(
                signature.header.as_str(),
                format!(
                    "sha256={}",
                    hmac_sha256_hex(signature.secret.expose_secret().as_bytes(), &payload_bytes)
                ),
            );
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
    use super::NotificationRouter;
    use crate::config::{
        NotificationChannelConfig, NotificationRateLimitConfig, NotificationRoutingConfig,
        RoutingRule,
    };
    use crate::test_paths::temp_jsonl_path_string;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use swarm_core::pheromone::ThreatClass;
    use swarm_core::types::Severity;
    use swarm_whisker::DetectionFinding;
    use tokio::sync::{Mutex, oneshot};

    /// A fixed clock reading every test routes against. Nothing here reads the
    /// wall clock, so every deadline in these tests is arithmetic on this value.
    const BASE_MS: i64 = 1_700_000_000_000;

    #[derive(Clone, Default)]
    struct CaptureState {
        payloads: Arc<Mutex<Vec<Value>>>,
        auth: Arc<Mutex<Option<String>>>,
        signature: Arc<Mutex<Option<String>>>,
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
        {
            let mut signature = state.signature.lock().await;
            *signature = headers
                .get("x-swarm-signature")
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
                auth_token: Some("notify-secret".to_string().into()),
                request_signature: None,
                timeout_ms: 500,
                rate_limit: NotificationRateLimitConfig {
                    max_notifications: 10,
                    window_ms: 1_000,
                },
                quiet_hours: None,
                dead_letter_path: temp_jsonl_path_string("notify-dedup"),
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
            None,
        );

        // Both findings land inside the 20ms dedup window opened by the first.
        assert!(
            router
                .route_finding_at(&finding("event-1", "suspicious_process_tree"), BASE_MS)
                .await,
            "the first finding must open a new aggregate"
        );
        assert!(
            !router
                .route_finding_at(&finding("event-2", "suspicious_process_tree"), BASE_MS + 5)
                .await,
            "the second finding must fold into the open aggregate, not open a second one"
        );

        // One millisecond before the window closes there is nothing to send.
        // This is the boundary the old 40ms sleep could only hope for.
        assert_eq!(router.flush_due(BASE_MS + 19).await.unwrap(), 0);
        assert!(state.payloads.lock().await.is_empty());

        assert_eq!(router.flush_due(BASE_MS + 20).await.unwrap(), 1);

        let payloads = state.payloads.lock().await.clone();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["count"], 2);
        assert_eq!(payloads[0]["first_seen_ms"], BASE_MS);
        assert_eq!(payloads[0]["last_seen_ms"], BASE_MS + 5);
        assert_eq!(
            state.auth.lock().await.clone(),
            Some("Bearer notify-secret".to_string())
        );

        // The aggregate was drained, so a second flush at the same reading is a
        // no-op rather than a duplicate delivery.
        assert_eq!(router.flush_due(BASE_MS + 20).await.unwrap(), 0);
        assert_eq!(state.payloads.lock().await.len(), 1);

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn router_writes_and_replays_rate_limited_notifications() {
        let (target_url, state, shutdown_tx, handle) = spawn_server().await;
        let dead_letter_path = temp_jsonl_path_string("notify-rate-limit");
        let mut channels = BTreeMap::new();
        channels.insert(
            "soc".to_string(),
            NotificationChannelConfig {
                target_url,
                auth_token: None,
                request_signature: None,
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
            None,
        );

        // First aggregate: inside the rate limit, so it is delivered.
        router
            .route_finding_at(&finding("event-1", "strategy-a"), BASE_MS)
            .await;
        assert_eq!(router.flush_due(BASE_MS + 10).await.unwrap(), 1);
        assert_eq!(state.payloads.lock().await.len(), 1);

        // Second aggregate, 20ms later and so still inside the 10s rate-limit
        // window: refused, and dead-lettered rather than dropped.
        router
            .route_finding_at(&finding("event-2", "strategy-b"), BASE_MS + 20)
            .await;
        assert_eq!(router.flush_due(BASE_MS + 30).await.unwrap(), 1);
        assert_eq!(
            state.payloads.lock().await.len(),
            1,
            "the rate-limited aggregate must not reach the channel"
        );

        let entries = router.list_dead_letters("soc", None).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].last_error, "notification rate limit exceeded");
        assert_eq!(entries[0].timestamp_ms, BASE_MS + 20);

        let results = router.replay_dead_letters("soc", None).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, "replayed");

        let payloads = state.payloads.lock().await.clone();
        assert_eq!(payloads.len(), 2);

        let _ = std::fs::remove_file(dead_letter_path);
        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn router_uses_channel_specific_payload_builder_when_present() {
        let (target_url, state, shutdown_tx, handle) = spawn_server().await;
        let mut channels = BTreeMap::new();
        channels.insert(
            "providence_webhook".to_string(),
            NotificationChannelConfig {
                target_url,
                auth_token: None,
                request_signature: None,
                timeout_ms: 500,
                rate_limit: NotificationRateLimitConfig {
                    max_notifications: 10,
                    window_ms: 1_000,
                },
                quiet_hours: None,
                dead_letter_path: temp_jsonl_path_string("notify-providence"),
            },
        );
        let router = NotificationRouter::new(
            channels,
            NotificationRoutingConfig {
                dedup_window_ms: 10,
                rules: vec![RoutingRule {
                    min_severity: Some(Severity::Medium),
                    threat_class: Some(ThreatClass::Execution),
                    utc_start_hour: None,
                    utc_end_hour: None,
                    channels: vec!["providence_webhook".to_string()],
                }],
            },
            None,
        );
        router.set_payload_builder(|channel, aggregate| {
            (channel == "providence_webhook").then(|| {
                json!({
                    "schema": "swarm_providence_webhook",
                    "finding_id": &aggregate.sample_finding.finding_id,
                    "count": aggregate.count,
                })
            })
        });

        router
            .route_finding_at(&finding("event-1", "suspicious_process_tree"), BASE_MS)
            .await;
        assert_eq!(router.flush_due(BASE_MS + 10).await.unwrap(), 1);

        let payloads = state.payloads.lock().await.clone();
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["schema"], "swarm_providence_webhook");
        assert_eq!(payloads[0]["finding_id"], "finding-event-1");
        assert_eq!(payloads[0]["count"], 1);

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn router_signs_notifications_with_hmac_header() {
        let (target_url, state, shutdown_tx, handle) = spawn_server().await;
        let mut channels = BTreeMap::new();
        channels.insert(
            "providence_webhook".to_string(),
            NotificationChannelConfig {
                target_url,
                auth_token: Some("providence-bearer".to_string().into()),
                request_signature: Some(swarm_core::config::RequestSignatureConfig {
                    header: "X-Swarm-Signature".to_string(),
                    secret: "shared-providence-secret".to_string().into(),
                }),
                timeout_ms: 500,
                rate_limit: NotificationRateLimitConfig {
                    max_notifications: 10,
                    window_ms: 1_000,
                },
                quiet_hours: None,
                dead_letter_path: temp_jsonl_path_string("notify-providence-signed"),
            },
        );
        let router = NotificationRouter::new(
            channels,
            NotificationRoutingConfig {
                dedup_window_ms: 10,
                rules: vec![RoutingRule {
                    min_severity: Some(Severity::Medium),
                    threat_class: Some(ThreatClass::Execution),
                    utc_start_hour: None,
                    utc_end_hour: None,
                    channels: vec!["providence_webhook".to_string()],
                }],
            },
            None,
        );
        router.set_payload_builder(|channel, aggregate| {
            (channel == "providence_webhook").then(|| {
                json!({
                    "schema": "swarm_providence_webhook",
                    "schema_version": 1,
                    "finding_id": &aggregate.sample_finding.finding_id,
                    "count": aggregate.count,
                })
            })
        });

        router
            .route_finding_at(&finding("event-9", "suspicious_process_tree"), BASE_MS)
            .await;
        assert_eq!(router.flush_due(BASE_MS + 10).await.unwrap(), 1);

        let payloads = state.payloads.lock().await.clone();
        assert_eq!(payloads.len(), 1);
        assert_eq!(
            state.auth.lock().await.clone(),
            Some("Bearer providence-bearer".to_string())
        );
        let signature = state.signature.lock().await.clone();
        let expected = format!(
            "sha256={}",
            swarm_crypto::hmac_sha256_hex(
                b"shared-providence-secret",
                &swarm_crypto::canonical_json_bytes(&payloads[0]).unwrap()
            )
        );
        assert_eq!(signature, Some(expected));

        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn quiet_hours_dead_letter_the_aggregate_instead_of_sending_it() {
        // The quiet-hours branch of `flush_key` decides on `last_seen_ms`, so it
        // is only testable at all once the routing clock is a parameter: with
        // the wall clock, this test would pass or fail depending on the hour the
        // suite ran.
        let (target_url, state, shutdown_tx, handle) = spawn_server().await;
        let dead_letter_path = temp_jsonl_path_string("notify-quiet-hours");
        let mut channels = BTreeMap::new();
        channels.insert(
            "soc".to_string(),
            NotificationChannelConfig {
                target_url,
                auth_token: None,
                request_signature: None,
                timeout_ms: 500,
                rate_limit: NotificationRateLimitConfig {
                    max_notifications: 10,
                    window_ms: 1_000,
                },
                quiet_hours: Some(crate::config::QuietHoursConfig {
                    start_hour_utc: 22,
                    end_hour_utc: 6,
                }),
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
            None,
        );

        // 1970-01-02T23:00:00Z: inside the 22:00-06:00 quiet window.
        let quiet_ms = 86_400_000 + 23 * 3_600_000;
        router
            .route_finding_at(&finding("event-quiet", "strategy-a"), quiet_ms)
            .await;
        assert_eq!(router.flush_due(quiet_ms + 10).await.unwrap(), 1);
        assert!(
            state.payloads.lock().await.is_empty(),
            "a quiet-hours aggregate must not reach the channel"
        );
        let entries = router.list_dead_letters("soc", None).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].last_error, "quiet hours active");

        // 1970-01-02T12:00:00Z: outside it, so the same aggregate is delivered.
        let loud_ms = 86_400_000 + 12 * 3_600_000;
        router
            .route_finding_at(&finding("event-loud", "strategy-a"), loud_ms)
            .await;
        assert_eq!(router.flush_due(loud_ms + 10).await.unwrap(), 1);
        assert_eq!(state.payloads.lock().await.len(), 1);
        assert_eq!(
            router.list_dead_letters("soc", None).await.unwrap().len(),
            1,
            "the delivered aggregate must not have been dead-lettered"
        );

        let _ = std::fs::remove_file(dead_letter_path);
        let _ = shutdown_tx.send(());
        handle.abort();
    }

    #[tokio::test]
    async fn scheduled_flush_delivers_without_an_explicit_drain() {
        // Everything above drives `flush_due` directly, which would leave the
        // wall-clock scheduler inside `route_finding` -- the path production
        // actually uses -- untested. This test covers it, and is the only one
        // here that touches real time. It uses time as a FAILURE BOUND: the
        // verdict is "the payload arrived", and the deadline only decides how
        // long to keep asking. A loaded machine makes it slower, never wrong.
        let (target_url, state, shutdown_tx, handle) = spawn_server().await;
        let mut channels = BTreeMap::new();
        channels.insert(
            "soc".to_string(),
            NotificationChannelConfig {
                target_url,
                auth_token: None,
                request_signature: None,
                timeout_ms: 5_000,
                rate_limit: NotificationRateLimitConfig {
                    max_notifications: 10,
                    window_ms: 1_000,
                },
                quiet_hours: None,
                dead_letter_path: temp_jsonl_path_string("notify-scheduled"),
            },
        );
        let router = NotificationRouter::new(
            channels,
            NotificationRoutingConfig {
                dedup_window_ms: 10,
                rules: vec![RoutingRule {
                    min_severity: Some(Severity::Medium),
                    threat_class: Some(ThreatClass::Execution),
                    utc_start_hour: None,
                    utc_end_hour: None,
                    channels: vec!["soc".to_string()],
                }],
            },
            None,
        );

        router
            .route_finding(&finding("event-1", "suspicious_process_tree"))
            .await;

        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if state.payloads.lock().await.len() == 1 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "route_finding scheduled no flush: nothing delivered within 30s"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let payloads = state.payloads.lock().await.clone();
        assert_eq!(payloads[0]["count"], 1);
        assert_eq!(payloads[0]["schema"], "swarm_notification");

        let _ = shutdown_tx.send(());
        handle.abort();
    }
}
