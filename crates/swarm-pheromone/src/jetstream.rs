use crate::substrate::{
    AdmissionControl, BEHAVIORAL_BASELINE_STATE_KIND, DepositQuery, FeedbackSuppressionKey,
    MAX_ACTIVE_DEPOSIT_BYTES, MAX_ACTIVE_DEPOSITS, PheromoneSubstrate, SubstrateError,
    SubstrateHealth, VerifiedDeposit, concentration_for, decode_deposit_payload,
    deposit_suppression_key, feedback_suppression_marker, filter_deposits, filter_escalations,
    is_retention_expired, normalize_threat_intel_value, retention_initial_strength,
    trusted_system_unix_seconds, validate_deposit_policy, validate_deposit_retention,
};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
#[cfg(feature = "nats")]
use sha2::{Digest, Sha256};
#[cfg(feature = "nats")]
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(feature = "nats")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "nats")]
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
use swarm_core::pheromone::{
    BehavioralBaselineSnapshot, EscalationRecord, PheromoneConcentration, PheromoneDeposit,
    ThreatClass, ThreatClassConfig, ThreatClassPolicy, ThreatIntelEntry, ThreatIntelIndicatorType,
};
use swarm_core::signed_state::{SignedStateEnvelope, SignedStateExpectation};
use swarm_core::types::AgentId;
#[cfg(feature = "nats")]
use tokio::sync::{Mutex as AsyncMutex, OnceCell};
#[cfg(feature = "nats")]
use tokio::time::timeout;
#[cfg(feature = "nats")]
use tokio_stream::StreamExt;

const DEFAULT_BUCKET_NAME: &str = "swarm-pheromone-deposits";
#[cfg(feature = "nats")]
const DEFAULT_NATS_CONNECT_TIMEOUT_MS: u64 = 5_000;
#[cfg(feature = "nats")]
const DEFAULT_JETSTREAM_GC_PAGE_SIZE: usize = 512;
#[cfg(feature = "nats")]
const GC_KEY_PREFIX: &str = "exp";
#[cfg(feature = "nats")]
const ESCALATION_KEY_PREFIX: &str = "esc";
#[cfg(feature = "nats")]
const THREAT_CLASS_CONFIG_KEY_PREFIX: &str = "cfg";
#[cfg(feature = "nats")]
const THREAT_INTEL_KEY_PREFIX: &str = "intel";
#[cfg(feature = "nats")]
const BEHAVIORAL_BASELINE_KEY_PREFIX: &str = "baseline";
#[cfg(feature = "nats")]
const GC_PAGE_SPAN_SECS: i64 = 300;
#[cfg(feature = "nats")]
const MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES: usize = MAX_ACTIVE_DEPOSITS * 2;
#[cfg(feature = "nats")]
const MAX_DEPOSIT_KEY_INDEX_PARTITIONS: usize = 128;

#[cfg(feature = "nats")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DepositKeyKind {
    Evidence,
    Control,
}

#[cfg(feature = "nats")]
#[derive(Debug, Clone)]
struct CachedVerifiedDeposit {
    revision: u64,
    deposit: VerifiedDeposit,
}

/// Bounded, revision-aware cache for deposits that have already crossed the
/// full signature and structural admission boundary. JetStream revisions are
/// immutable, so an exact `(key, revision)` hit can safely avoid repeating
/// Ed25519 verification on every concentration scan. A revision change always
/// misses and therefore re-runs admission before the cache is updated.
#[cfg(feature = "nats")]
#[derive(Debug, Default)]
struct VerifiedDepositCache {
    entries: BTreeMap<String, CachedVerifiedDeposit>,
    encoded_bytes: usize,
}

#[cfg(feature = "nats")]
impl VerifiedDepositCache {
    fn get(&self, key: &str, revision: u64) -> Option<VerifiedDeposit> {
        self.entries
            .get(key)
            .filter(|entry| entry.revision == revision)
            .map(|entry| entry.deposit.clone())
    }

    fn insert(&mut self, key: String, revision: u64, deposit: VerifiedDeposit) {
        if let Some(previous) = self.entries.remove(&key) {
            self.encoded_bytes = self
                .encoded_bytes
                .saturating_sub(previous.deposit.encoded_len());
        }
        let encoded_len = deposit.encoded_len();
        while !self.entries.is_empty()
            && (self.entries.len() >= MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES
                || self.encoded_bytes.saturating_add(encoded_len) > MAX_ACTIVE_DEPOSIT_BYTES)
        {
            let Some(evicted) = self.entries.keys().next().cloned() else {
                break;
            };
            if let Some(evicted) = self.entries.remove(&evicted) {
                self.encoded_bytes = self
                    .encoded_bytes
                    .saturating_sub(evicted.deposit.encoded_len());
            }
        }
        self.encoded_bytes = self.encoded_bytes.saturating_add(encoded_len);
        self.entries
            .insert(key, CachedVerifiedDeposit { revision, deposit });
    }

    fn remove(&mut self, key: &str) {
        if let Some(removed) = self.entries.remove(key) {
            self.encoded_bytes = self
                .encoded_bytes
                .saturating_sub(removed.deposit.encoded_len());
        }
    }
}

#[cfg(feature = "nats")]
#[derive(Debug, Clone)]
struct IndexedDepositKey {
    timestamp: i64,
    key: String,
    encoded_len: usize,
    suppression_key: Option<FeedbackSuppressionKey>,
    feedback_marker_key: Option<FeedbackSuppressionKey>,
}

#[cfg(feature = "nats")]
impl PartialEq for IndexedDepositKey {
    fn eq(&self, other: &Self) -> bool {
        self.timestamp == other.timestamp && self.key == other.key
    }
}

#[cfg(feature = "nats")]
impl Eq for IndexedDepositKey {}

#[cfg(feature = "nats")]
impl PartialOrd for IndexedDepositKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(feature = "nats")]
impl Ord for IndexedDepositKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.key.cmp(&other.key))
    }
}

#[cfg(feature = "nats")]
fn retain_newest_deposit_key(window: &mut BTreeSet<(i64, String)>, key: String, limit: usize) {
    let _ = insert_newest_deposit_key(window, key, limit);
}

#[cfg(feature = "nats")]
fn insert_newest_deposit_key(
    window: &mut BTreeSet<(i64, String)>,
    key: String,
    limit: usize,
) -> Option<String> {
    window.insert((deposit_key_timestamp(&key).unwrap_or(i64::MIN), key));
    if window.len() > limit
        && let Some(oldest) = window.first().cloned()
    {
        window.remove(&oldest);
        return Some(oldest.1);
    }
    None
}

#[cfg(feature = "nats")]
fn retain_newest_partitioned_deposit_key_as(
    evidence_window: &mut BTreeSet<(i64, String)>,
    control_window: &mut BTreeSet<(i64, String)>,
    key: String,
    kind: DepositKeyKind,
    limit: usize,
) {
    let window = match kind {
        DepositKeyKind::Control => control_window,
        DepositKeyKind::Evidence => evidence_window,
    };
    retain_newest_deposit_key(window, key, limit);
}

#[cfg(feature = "nats")]
#[derive(Debug, Default)]
struct DepositKeyScanCursor {
    initialized: bool,
    last_sequence: u64,
}

#[cfg(feature = "nats")]
#[derive(Debug, Clone, Copy)]
enum DepositKeyLayout {
    Current,
    Legacy,
}

#[cfg(feature = "nats")]
#[derive(Debug, Clone, Copy)]
struct DepositKeyRefreshBounds {
    high_water: u64,
    retention_now: Option<i64>,
    retention_half_life_secs: Option<f64>,
    retention_evaporation_threshold: Option<f64>,
    partition_limit: usize,
}

#[cfg(feature = "nats")]
#[derive(Debug, Default)]
struct DepositKeyPartitionIndex {
    evidence: BTreeSet<IndexedDepositKey>,
    controls: BTreeSet<IndexedDepositKey>,
    evidence_bytes: usize,
    control_bytes: usize,
    current_layout: DepositKeyScanCursor,
    legacy_layout: DepositKeyScanCursor,
}

#[cfg(feature = "nats")]
impl DepositKeyPartitionIndex {
    fn remove_key(&mut self, key: &str) -> Option<IndexedDepositKey> {
        let evidence = self
            .evidence
            .iter()
            .find(|candidate| candidate.key == key)
            .cloned();
        if let Some(evidence) = evidence {
            self.evidence.remove(&evidence);
            self.evidence_bytes = self.evidence_bytes.saturating_sub(evidence.encoded_len);
            return Some(evidence);
        }
        let control = self
            .controls
            .iter()
            .find(|candidate| candidate.key == key)
            .cloned();
        if let Some(control) = control {
            self.controls.remove(&control);
            self.control_bytes = self.control_bytes.saturating_sub(control.encoded_len);
            return Some(control);
        }
        None
    }

    fn remove_oldest(&mut self, kind: DepositKeyKind) -> Option<IndexedDepositKey> {
        let oldest = match kind {
            DepositKeyKind::Evidence => self.evidence.first().cloned(),
            DepositKeyKind::Control => self.controls.first().cloned(),
        }?;
        self.remove_key(&oldest.key)
    }

    fn insert_bounded(
        &mut self,
        indexed: IndexedDepositKey,
        kind: DepositKeyKind,
        count_limit: usize,
    ) -> Vec<IndexedDepositKey> {
        let mut removed = Vec::new();
        match kind {
            DepositKeyKind::Evidence => {
                self.evidence_bytes = self.evidence_bytes.saturating_add(indexed.encoded_len);
                self.evidence.insert(indexed);
            }
            DepositKeyKind::Control => {
                self.control_bytes = self.control_bytes.saturating_add(indexed.encoded_len);
                self.controls.insert(indexed);
            }
        }

        while self.evidence.len() > count_limit {
            if let Some(evicted) = self.remove_oldest(DepositKeyKind::Evidence) {
                removed.push(evicted);
            }
        }
        while self.controls.len() > count_limit {
            if let Some(evicted) = self.remove_oldest(DepositKeyKind::Control) {
                removed.push(evicted);
            }
        }
        while self.evidence_bytes.saturating_add(self.control_bytes) > MAX_ACTIVE_DEPOSIT_BYTES {
            let kind = if self.evidence_bytes >= self.control_bytes {
                DepositKeyKind::Evidence
            } else {
                DepositKeyKind::Control
            };
            let Some(evicted) = self.remove_oldest(kind).or_else(|| {
                self.remove_oldest(match kind {
                    DepositKeyKind::Evidence => DepositKeyKind::Control,
                    DepositKeyKind::Control => DepositKeyKind::Evidence,
                })
            }) else {
                break;
            };
            removed.push(evicted);
        }
        removed
    }

    fn remove_evidence_orphaned_by_feedback(
        &mut self,
        removed: &IndexedDepositKey,
    ) -> Vec<IndexedDepositKey> {
        let Some(feedback_key) = removed.feedback_marker_key.as_ref() else {
            return Vec::new();
        };
        if self
            .controls
            .iter()
            .any(|entry| entry.feedback_marker_key.as_ref() == Some(feedback_key))
        {
            return Vec::new();
        }
        let related = self
            .evidence
            .iter()
            .filter(|entry| entry.suppression_key.as_ref() == Some(feedback_key))
            .cloned()
            .collect::<Vec<_>>();
        for entry in &related {
            let _ = self.remove_key(&entry.key);
        }
        related
    }

    fn total_bytes(&self) -> usize {
        self.evidence_bytes.saturating_add(self.control_bytes)
    }
}

#[cfg(feature = "nats")]
#[derive(Debug, Default)]
struct DepositKeyIndexes {
    partitions: BTreeMap<String, DepositKeyPartitionIndex>,
}

#[cfg(feature = "nats")]
impl DepositKeyIndexes {
    fn make_room_for(&mut self, segment: &str) {
        if self.partitions.contains_key(segment) {
            return;
        }
        while self.partitions.len() >= MAX_DEPOSIT_KEY_INDEX_PARTITIONS {
            let Some(evicted) = self.partitions.keys().next().cloned() else {
                break;
            };
            self.partitions.remove(&evicted);
        }
    }

    fn enforce_global_byte_bound(&mut self, current_segment: &str) {
        while self
            .partitions
            .values()
            .map(DepositKeyPartitionIndex::total_bytes)
            .sum::<usize>()
            > MAX_ACTIVE_DEPOSIT_BYTES
        {
            let evicted = self
                .partitions
                .keys()
                .find(|segment| segment.as_str() != current_segment)
                .cloned();
            let Some(evicted) = evicted else {
                break;
            };
            self.partitions.remove(&evicted);
        }
    }
}

/// JetStream-backed durable pheromone substrate.
#[derive(Clone)]
pub struct JetStreamPheromoneSubstrate {
    config: PheromoneConfig,
    admission_control: AdmissionControl,
    url: String,
    bucket: String,
    #[cfg(feature = "nats")]
    connect_timeout_ms: u64,
    #[cfg(feature = "nats")]
    gc_page_size: usize,
    #[cfg(feature = "nats")]
    connection: Arc<OnceCell<JetStreamConnection>>,
    #[cfg(feature = "nats")]
    gc_page_cursor: Arc<Mutex<Option<i64>>>,
    #[cfg(feature = "nats")]
    legacy_gc_complete: Arc<Mutex<bool>>,
    #[cfg(feature = "nats")]
    verified_deposit_cache: Arc<Mutex<VerifiedDepositCache>>,
    #[cfg(feature = "nats")]
    deposit_key_indexes: Arc<AsyncMutex<DepositKeyIndexes>>,
}

#[cfg(feature = "nats")]
struct JetStreamConnection {
    client: async_nats::Client,
    store: async_nats::jetstream::kv::Store,
}

#[cfg(feature = "nats")]
enum NatsAuthentication {
    None,
    Token(String),
    UserPassword { username: String, password: String },
}

#[cfg(feature = "nats")]
struct NatsEndpoint {
    server_url: String,
    display_url: String,
    authentication: NatsAuthentication,
}

#[cfg(feature = "nats")]
fn decode_nats_credential(component: &str, label: &'static str) -> Result<String, SubstrateError> {
    percent_encoding::percent_decode_str(component)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .map_err(|_| SubstrateError::Nats {
            operation: "parse endpoint",
            reason: format!("NATS {label} is not valid UTF-8"),
        })
}

#[cfg(feature = "nats")]
fn parse_nats_endpoint(raw_url: &str) -> Result<NatsEndpoint, SubstrateError> {
    let mut parsed = url::Url::parse(raw_url).map_err(|error| SubstrateError::Nats {
        operation: "parse endpoint",
        reason: format!("invalid NATS endpoint: {error}"),
    })?;
    if !matches!(parsed.scheme(), "nats" | "tls" | "ws" | "wss") {
        return Err(SubstrateError::Nats {
            operation: "parse endpoint",
            reason: format!("unsupported NATS endpoint scheme `{}`", parsed.scheme()),
        });
    }

    let username = decode_nats_credential(parsed.username(), "username")?;
    let password = parsed
        .password()
        .map(|value| decode_nats_credential(value, "password"))
        .transpose()?;
    let authentication = match (username.is_empty(), password) {
        (true, None) => NatsAuthentication::None,
        (false, None) => NatsAuthentication::Token(username),
        (false, Some(password)) => NatsAuthentication::UserPassword { username, password },
        (true, Some(_)) => {
            return Err(SubstrateError::Nats {
                operation: "parse endpoint",
                reason: "NATS endpoint password requires a username".to_string(),
            });
        }
    };
    parsed.set_username("").map_err(|()| SubstrateError::Nats {
        operation: "parse endpoint",
        reason: "NATS endpoint does not support an authority username".to_string(),
    })?;
    parsed
        .set_password(None)
        .map_err(|()| SubstrateError::Nats {
            operation: "parse endpoint",
            reason: "NATS endpoint does not support an authority password".to_string(),
        })?;
    let server_url = parsed.to_string();
    Ok(NatsEndpoint {
        display_url: server_url.clone(),
        server_url,
        authentication,
    })
}

#[cfg(feature = "nats")]
async fn connect_nats_endpoint(
    endpoint: NatsEndpoint,
) -> Result<async_nats::Client, SubstrateError> {
    let options = match endpoint.authentication {
        NatsAuthentication::None => async_nats::ConnectOptions::new(),
        NatsAuthentication::Token(token) => async_nats::ConnectOptions::with_token(token),
        NatsAuthentication::UserPassword { username, password } => {
            async_nats::ConnectOptions::with_user_and_password(username, password)
        }
    };
    options
        .connect(endpoint.server_url)
        .await
        .map_err(|error| nats_error("connect", error))
}

impl fmt::Debug for JetStreamPheromoneSubstrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "nats")]
        let endpoint = parse_nats_endpoint(&self.url)
            .map(|parsed| parsed.display_url)
            .unwrap_or_else(|_| "<invalid NATS endpoint>".to_string());
        #[cfg(not(feature = "nats"))]
        let endpoint = "<NATS support disabled>";
        f.debug_struct("JetStreamPheromoneSubstrate")
            .field("url", &endpoint)
            .field("bucket", &self.bucket)
            .finish()
    }
}

impl JetStreamPheromoneSubstrate {
    pub fn new(config: PheromoneConfig, url: impl Into<String>) -> Self {
        Self::with_bucket(config, url, DEFAULT_BUCKET_NAME)
    }

    pub fn with_bucket(
        config: PheromoneConfig,
        url: impl Into<String>,
        bucket: impl Into<String>,
    ) -> Self {
        #[cfg(feature = "nats")]
        let (connect_timeout_ms, gc_page_size) = match &config.backend {
            PheromoneBackendConfig::JetStream {
                connect_timeout_ms,
                gc_page_size,
                ..
            } => (*connect_timeout_ms, *gc_page_size),
            _ => (
                DEFAULT_NATS_CONNECT_TIMEOUT_MS,
                DEFAULT_JETSTREAM_GC_PAGE_SIZE,
            ),
        };

        Self {
            config,
            admission_control: AdmissionControl::default(),
            url: url.into(),
            bucket: bucket.into(),
            #[cfg(feature = "nats")]
            connect_timeout_ms,
            #[cfg(feature = "nats")]
            gc_page_size,
            #[cfg(feature = "nats")]
            connection: Arc::new(OnceCell::new()),
            #[cfg(feature = "nats")]
            gc_page_cursor: Arc::new(Mutex::new(None)),
            #[cfg(feature = "nats")]
            legacy_gc_complete: Arc::new(Mutex::new(false)),
            #[cfg(feature = "nats")]
            verified_deposit_cache: Arc::new(Mutex::new(VerifiedDepositCache::default())),
            #[cfg(feature = "nats")]
            deposit_key_indexes: Arc::new(AsyncMutex::new(DepositKeyIndexes::default())),
        }
    }

    pub async fn connect(
        config: PheromoneConfig,
        url: impl Into<String>,
    ) -> Result<Self, SubstrateError> {
        let substrate = Self::new(config, url);
        substrate.ensure_connected().await?;
        Ok(substrate)
    }

    pub async fn connect_with_bucket(
        config: PheromoneConfig,
        url: impl Into<String>,
        bucket: impl Into<String>,
    ) -> Result<Self, SubstrateError> {
        let substrate = Self::with_bucket(config, url, bucket);
        substrate.ensure_connected().await?;
        Ok(substrate)
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn set_admitted_identities(
        &self,
        identities: impl IntoIterator<Item = AgentId>,
    ) -> Result<(), SubstrateError> {
        self.admission_control.set_admitted_identities(identities)
    }

    #[cfg(feature = "nats")]
    async fn ensure_connected(&self) -> Result<&JetStreamConnection, SubstrateError> {
        let endpoint = parse_nats_endpoint(&self.url)?;
        let display_url = endpoint.display_url.clone();
        let bucket = self.bucket.clone();
        let connect_timeout_ms = self.connect_timeout_ms;

        self.connection
            .get_or_try_init(|| async move {
                let client = timeout(
                    std::time::Duration::from_millis(connect_timeout_ms),
                    connect_nats_endpoint(endpoint),
                )
                .await
                .map_err(|_| SubstrateError::Nats {
                    operation: "connect",
                    reason: format!(
                        "timed out after {connect_timeout_ms}ms while connecting to {display_url}"
                    ),
                })??;
                let jetstream = async_nats::jetstream::new(client.clone());
                let store = ensure_kv_bucket(&jetstream, &bucket).await?;
                Ok(JetStreamConnection { client, store })
            })
            .await
    }

    #[cfg(feature = "nats")]
    async fn purge_deposit_key(
        &self,
        connection: &JetStreamConnection,
        key: &str,
    ) -> Result<(), SubstrateError> {
        let subject = format!("{}{}", connection.store.prefix, key);
        let response = connection
            .store
            .stream
            .purge()
            .filter(subject)
            .await
            .map_err(|error| nats_error("purge bounded deposit key", error))?;
        if !response.success {
            return Err(SubstrateError::Nats {
                operation: "purge bounded deposit key",
                reason: format!("JetStream did not confirm purge for key `{key}`"),
            });
        }
        self.verified_deposit_cache
            .lock()
            .map_err(|_| SubstrateError::PoisonedLock)?
            .remove(key);
        Ok(())
    }

    #[cfg(feature = "nats")]
    async fn refresh_deposit_key_filter(
        &self,
        connection: &JetStreamConnection,
        key_filter: &str,
        threat_class: &ThreatClass,
        partition: &mut DepositKeyPartitionIndex,
        layout: DepositKeyLayout,
        bounds: DepositKeyRefreshBounds,
    ) -> Result<(), SubstrateError> {
        let (cursor_initialized, cursor_last_sequence) = match layout {
            DepositKeyLayout::Current => (
                partition.current_layout.initialized,
                partition.current_layout.last_sequence,
            ),
            DepositKeyLayout::Legacy => (
                partition.legacy_layout.initialized,
                partition.legacy_layout.last_sequence,
            ),
        };
        if cursor_initialized && bounds.high_water <= cursor_last_sequence {
            return Ok(());
        }
        let deliver_policy = if cursor_initialized {
            async_nats::jetstream::consumer::DeliverPolicy::ByStartSequence {
                start_sequence: cursor_last_sequence.saturating_add(1),
            }
        } else {
            async_nats::jetstream::consumer::DeliverPolicy::LastPerSubject
        };
        let consumer = connection
            .store
            .stream
            .create_consumer(async_nats::jetstream::consumer::push::OrderedConfig {
                deliver_subject: connection.client.new_inbox(),
                description: Some("bounded pheromone deposit index".to_string()),
                filter_subject: format!("{}{}", connection.store.prefix, key_filter),
                replay_policy: async_nats::jetstream::consumer::ReplayPolicy::Instant,
                deliver_policy,
                ..Default::default()
            })
            .await
            .map_err(|error| nats_error("create bounded deposit consumer", error))?;

        if consumer.cached_info().num_pending == 0 {
            let cursor = match layout {
                DepositKeyLayout::Current => &mut partition.current_layout,
                DepositKeyLayout::Legacy => &mut partition.legacy_layout,
            };
            cursor.initialized = true;
            cursor.last_sequence = cursor.last_sequence.max(bounds.high_water);
            return Ok(());
        }

        let mut observed_sequence = cursor_last_sequence;
        let mut messages = consumer
            .messages()
            .await
            .map_err(|error| nats_error("subscribe bounded deposit consumer", error))?;
        while let Some(message) = messages.next().await {
            let message =
                message.map_err(|error| nats_error("stream bounded deposit keys", error))?;
            let info = message
                .info()
                .map_err(|error| nats_error("parse bounded deposit metadata", error))?;
            observed_sequence = observed_sequence.max(info.stream_sequence);
            let key = message
                .subject
                .strip_prefix(&connection.store.prefix)
                .map(ToString::to_string)
                .unwrap_or_else(|| message.subject.to_string());
            let removed = message
                .message
                .headers
                .as_ref()
                .and_then(|headers| headers.get("KV-Operation"))
                .is_some_and(|operation| matches!(operation.as_str(), "DEL" | "PURGE"));

            if removed {
                let orphaned = partition
                    .remove_key(&key)
                    .map(|entry| partition.remove_evidence_orphaned_by_feedback(&entry))
                    .unwrap_or_default();
                // Delete markers on unique deposit subjects would otherwise
                // remain visible to every future LastPerSubject bootstrap.
                self.purge_deposit_key(connection, &key).await?;
                for entry in orphaned {
                    self.purge_deposit_key(connection, &entry.key).await?;
                }
            } else {
                let location = format!("jetstream://{}/{}", self.bucket, key);
                let deposit = decode_deposit_payload(&message.message.payload, location)?;
                self.admission_control
                    .validate_deposit_admission(&deposit)?;
                if &deposit.threat_class != threat_class {
                    return Err(SubstrateError::InvalidDeposit {
                        reason: format!(
                            "JetStream deposit key `{key}` threat class does not match its signed payload"
                        ),
                    });
                }
                let kind = deposit_kind(&deposit);
                if let Some(key_kind) = deposit_key_kind(&key)
                    && key_kind != kind
                {
                    return Err(SubstrateError::InvalidDeposit {
                        reason: format!(
                            "JetStream deposit key `{key}` class does not match its signed payload"
                        ),
                    });
                }
                let expired = match (
                    bounds.retention_now,
                    bounds.retention_half_life_secs,
                    bounds.retention_evaporation_threshold,
                ) {
                    (Some(now), Some(half_life_secs), Some(evaporation_threshold)) => {
                        is_retention_expired(&deposit, now, half_life_secs, evaporation_threshold)
                    }
                    _ => false,
                };
                if expired {
                    let orphaned = partition
                        .remove_key(&key)
                        .map(|entry| partition.remove_evidence_orphaned_by_feedback(&entry))
                        .unwrap_or_default();
                    self.purge_deposit_key(connection, &key).await?;
                    for entry in orphaned {
                        self.purge_deposit_key(connection, &entry.key).await?;
                    }
                } else {
                    self.verified_deposit_cache
                        .lock()
                        .map_err(|_| SubstrateError::PoisonedLock)?
                        .insert(key.clone(), info.stream_sequence, deposit.clone());
                    let indexed = IndexedDepositKey {
                        timestamp: deposit.timestamp,
                        key,
                        encoded_len: deposit.encoded_len(),
                        suppression_key: deposit_suppression_key(&deposit),
                        feedback_marker_key: feedback_suppression_marker(&deposit)
                            .map(|(key, _)| key),
                    };
                    let replacement_orphans = partition
                        .remove_key(&indexed.key)
                        .map(|entry| partition.remove_evidence_orphaned_by_feedback(&entry))
                        .unwrap_or_default();
                    let evicted = partition.insert_bounded(indexed, kind, bounds.partition_limit);
                    for related in replacement_orphans {
                        self.purge_deposit_key(connection, &related.key).await?;
                    }
                    for entry in evicted {
                        let orphaned = partition.remove_evidence_orphaned_by_feedback(&entry);
                        self.purge_deposit_key(connection, &entry.key).await?;
                        for related in orphaned {
                            self.purge_deposit_key(connection, &related.key).await?;
                        }
                    }
                }
            }

            if info.pending == 0 {
                break;
            }
        }
        let cursor = match layout {
            DepositKeyLayout::Current => &mut partition.current_layout,
            DepositKeyLayout::Legacy => &mut partition.legacy_layout,
        };
        cursor.initialized = true;
        cursor.last_sequence = cursor
            .last_sequence
            .max(bounds.high_water)
            .max(observed_sequence);
        Ok(())
    }

    #[cfg(feature = "nats")]
    async fn indexed_deposit_keys(
        &self,
        connection: &JetStreamConnection,
        threat_class: &ThreatClass,
        retention_now: Option<i64>,
        retention_policy: Option<&ThreatClassPolicy>,
        partition_limit: usize,
    ) -> Result<Vec<String>, SubstrateError> {
        let segment = threat_class_segment(threat_class);
        // One high-water read covers both the current and migration layouts.
        // Advancing an empty filter only to this pre-consumer boundary is
        // race-safe: a matching write after the snapshot is necessarily read
        // from high_water + 1 on this or the next refresh.
        let bounds = DepositKeyRefreshBounds {
            high_water: connection
                .store
                .stream
                .get_info()
                .await
                .map_err(|error| nats_error("read deposit stream high-water", error))?
                .state
                .last_sequence,
            retention_now,
            retention_half_life_secs: retention_policy.map(|policy| policy.half_life_secs),
            retention_evaporation_threshold: retention_policy
                .map(|policy| policy.evaporation_threshold),
            partition_limit,
        };
        let mut indexes = self.deposit_key_indexes.lock().await;
        indexes.make_room_for(&segment);
        {
            let partition = indexes.partitions.entry(segment.clone()).or_default();
            self.refresh_deposit_key_filter(
                connection,
                &format!("{GC_KEY_PREFIX}.*.{segment}.>"),
                threat_class,
                partition,
                DepositKeyLayout::Current,
                bounds,
            )
            .await?;
            self.refresh_deposit_key_filter(
                connection,
                &format!("{segment}.>"),
                threat_class,
                partition,
                DepositKeyLayout::Legacy,
                bounds,
            )
            .await?;
        }
        indexes.enforce_global_byte_bound(&segment);
        let Some(partition) = indexes.partitions.get(&segment) else {
            return Err(SubstrateError::Nats {
                operation: "maintain bounded deposit index",
                reason: format!("active threat-class partition `{segment}` was not retained"),
            });
        };

        debug_assert!(partition.total_bytes() <= MAX_ACTIVE_DEPOSIT_BYTES);
        Ok(partition
            .controls
            .iter()
            .chain(&partition.evidence)
            .map(|entry| entry.key.clone())
            .collect())
    }

    #[cfg(not(feature = "nats"))]
    async fn ensure_connected(&self) -> Result<(), SubstrateError> {
        Err(unsupported_backend())
    }

    #[cfg(feature = "nats")]
    async fn load_deposits(
        &self,
        threat_class: Option<&ThreatClass>,
        since_timestamp: Option<i64>,
        retention_now: Option<i64>,
    ) -> Result<Vec<VerifiedDeposit>, SubstrateError> {
        self.load_deposits_bounded(
            threat_class,
            since_timestamp,
            retention_now,
            MAX_ACTIVE_DEPOSITS,
        )
        .await
    }

    #[cfg(feature = "nats")]
    async fn load_deposits_bounded(
        &self,
        threat_class: Option<&ThreatClass>,
        since_timestamp: Option<i64>,
        retention_now: Option<i64>,
        partition_limit: usize,
    ) -> Result<Vec<VerifiedDeposit>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let retention_policy = if let (Some(threat_class), Some(_)) = (threat_class, retention_now)
        {
            let threat_class_config = self.load_threat_class_config(threat_class).await?;
            Some(
                self.config
                    .resolve_threat_class_policy(threat_class_config.as_ref()),
            )
        } else {
            None
        };
        let selected_keys = if let Some(threat_class) = threat_class {
            self.indexed_deposit_keys(
                connection,
                threat_class,
                retention_now,
                retention_policy.as_ref(),
                partition_limit,
            )
            .await?
        } else {
            // Unscoped operator queries are not on the 100 ms concentration
            // monitor path. They retain the compatibility scan so pre-GC-page
            // custom-class keys remain discoverable, while every scoped live
            // lookup uses the server-filtered incremental index above.
            let mut keys = connection
                .store
                .keys()
                .await
                .map_err(|error| nats_error("list unscoped deposit keys", error))?;
            let mut evidence_key_window = BTreeSet::new();
            let mut control_key_window = BTreeSet::new();
            while let Some(entry) = keys.next().await {
                let key =
                    entry.map_err(|error| nats_error("stream unscoped deposit keys", error))?;
                if is_escalation_key(&key)
                    || is_policy_key(&key)
                    || is_threat_intel_key(&key)
                    || is_behavioral_baseline_key(&key)
                {
                    continue;
                }
                if retention_now.is_some_and(|now| {
                    key_gc_page(&key).is_some_and(|page| page <= gc_sweep_page(now))
                }) {
                    continue;
                }
                let Some(kind) = self.classify_deposit_key(connection, &key).await? else {
                    continue;
                };
                retain_newest_partitioned_deposit_key_as(
                    &mut evidence_key_window,
                    &mut control_key_window,
                    key,
                    kind,
                    partition_limit,
                );
            }
            evidence_key_window
                .into_iter()
                .chain(control_key_window)
                .map(|(_, key)| key)
                .collect()
        };

        let mut deposits = Vec::with_capacity(selected_keys.len());
        let mut deposit_bytes = 0usize;
        for key in selected_keys {
            let Some(entry) = connection
                .store
                .entry(&key)
                .await
                .map_err(|error| nats_error("get entry", error))?
            else {
                continue;
            };
            if matches!(
                entry.operation,
                async_nats::jetstream::kv::Operation::Delete
                    | async_nats::jetstream::kv::Operation::Purge
            ) {
                self.verified_deposit_cache
                    .lock()
                    .map_err(|_| SubstrateError::PoisonedLock)?
                    .remove(&key);
                continue;
            }

            let cached = self
                .verified_deposit_cache
                .lock()
                .map_err(|_| SubstrateError::PoisonedLock)?
                .get(&key, entry.revision);
            let deposit = if let Some(deposit) = cached {
                deposit
            } else {
                let location = format!("jetstream://{}/{}", self.bucket, key);
                let deposit = decode_deposit_payload(&entry.value, location)?;
                self.verified_deposit_cache
                    .lock()
                    .map_err(|_| SubstrateError::PoisonedLock)?
                    .insert(key.clone(), entry.revision, deposit.clone());
                deposit
            };
            self.admission_control
                .validate_deposit_admission(&deposit)?;

            if let Some(key_kind) = deposit_key_kind(&key)
                && key_kind != deposit_kind(&deposit)
            {
                return Err(SubstrateError::InvalidDeposit {
                    reason: format!(
                        "JetStream deposit key `{key}` class does not match its signed payload"
                    ),
                });
            }

            if let Some(threat_class) = threat_class
                && &deposit.threat_class != threat_class
            {
                continue;
            }
            if let Some(since_timestamp) = since_timestamp
                && deposit.timestamp < since_timestamp
            {
                continue;
            }
            if let (Some(now), Some(policy)) = (retention_now, retention_policy.as_ref())
                && is_retention_expired(
                    &deposit,
                    now,
                    policy.half_life_secs,
                    policy.evaporation_threshold,
                )
            {
                continue;
            }
            let next_bytes = deposit_bytes.saturating_add(deposit.encoded_len());
            if next_bytes > MAX_ACTIVE_DEPOSIT_BYTES {
                return Err(SubstrateError::InvalidDeposit {
                    reason: format!(
                        "bounded JetStream deposit scan exceeds the {MAX_ACTIVE_DEPOSIT_BYTES}-byte aggregate limit"
                    ),
                });
            }

            deposit_bytes = next_bytes;
            deposits.push(deposit);
        }

        Ok(deposits)
    }

    #[cfg(feature = "nats")]
    fn classify_legacy_deposit_payload(
        &self,
        key: &str,
        payload: &[u8],
    ) -> Result<DepositKeyKind, SubstrateError> {
        let location = format!("jetstream://{}/{}", self.bucket, key);
        let raw = serde_json::from_slice::<serde_json::Value>(payload)
            .map_err(|source| SubstrateError::Decode { location, source })?;
        let confidence = raw
            .get("confidence")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| SubstrateError::InvalidDeposit {
                reason: format!(
                    "legacy JetStream deposit key `{key}` has no numeric confidence field"
                ),
            })?;
        Ok(if confidence == 0.0 {
            DepositKeyKind::Control
        } else {
            DepositKeyKind::Evidence
        })
    }

    #[cfg(feature = "nats")]
    async fn classify_deposit_key(
        &self,
        connection: &JetStreamConnection,
        key: &str,
    ) -> Result<Option<DepositKeyKind>, SubstrateError> {
        if let Some(kind) = deposit_key_kind(key) {
            return Ok(Some(kind));
        }

        // Keys written before the partitioned layout do not encode whether a
        // record is positive evidence or a zero-strength control. Read only
        // the numeric classification field while selecting the bounded
        // migration window; full structural and Ed25519 verification still
        // occurs below for every selected payload.
        let Some(entry) = connection
            .store
            .entry(key)
            .await
            .map_err(|error| nats_error("classify legacy entry", error))?
        else {
            return Ok(None);
        };
        if matches!(
            entry.operation,
            async_nats::jetstream::kv::Operation::Delete
                | async_nats::jetstream::kv::Operation::Purge
        ) {
            return Ok(None);
        }
        self.classify_legacy_deposit_payload(key, &entry.value)
            .map(Some)
    }

    #[cfg(feature = "nats")]
    async fn deposit_count(&self) -> Result<usize, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut count = 0usize;
        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            if is_escalation_key(&key)
                || is_policy_key(&key)
                || is_threat_intel_key(&key)
                || is_behavioral_baseline_key(&key)
            {
                continue;
            }
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    #[cfg(feature = "nats")]
    async fn load_threat_class_config(
        &self,
        threat_class: &ThreatClass,
    ) -> Result<Option<ThreatClassConfig>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let key = threat_class_config_key(threat_class);
        let Some(payload) = connection
            .store
            .get(&key)
            .await
            .map_err(|error| nats_error("get value", error))?
        else {
            return Ok(None);
        };

        let location = format!("jetstream://{}/{}", self.bucket, key);
        let record = serde_json::from_slice::<ThreatClassConfig>(&payload)
            .map_err(|source| SubstrateError::Decode { location, source })?;
        Ok(Some(record))
    }

    #[cfg(feature = "nats")]
    async fn load_threat_class_configs(&self) -> Result<Vec<ThreatClassConfig>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut configs = Vec::new();

        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            if !is_policy_key(&key) {
                continue;
            }

            let Some(payload) = connection
                .store
                .get(&key)
                .await
                .map_err(|error| nats_error("get value", error))?
            else {
                continue;
            };

            let location = format!("jetstream://{}/{}", self.bucket, key);
            let record = serde_json::from_slice::<ThreatClassConfig>(&payload)
                .map_err(|source| SubstrateError::Decode { location, source })?;
            configs.push(record);
        }

        configs.sort_by(|left, right| left.threat_class.cmp(&right.threat_class));
        Ok(configs)
    }

    #[cfg(feature = "nats")]
    async fn load_threat_intel_entry(
        &self,
        indicator_type: &ThreatIntelIndicatorType,
        value: &str,
        now: i64,
    ) -> Result<Option<ThreatIntelEntry>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let key = threat_intel_key(indicator_type, value);
        let Some(payload) = connection
            .store
            .get(&key)
            .await
            .map_err(|error| nats_error("get value", error))?
        else {
            return Ok(None);
        };

        let location = format!("jetstream://{}/{}", self.bucket, key);
        let entry = serde_json::from_slice::<ThreatIntelEntry>(&payload)
            .map_err(|source| SubstrateError::Decode { location, source })?;
        if entry.expires_at <= now {
            return Ok(None);
        }
        Ok(Some(entry))
    }

    #[cfg(feature = "nats")]
    async fn load_behavioral_baseline_snapshot(
        &self,
        strategy_id: &str,
    ) -> Result<Option<SignedStateEnvelope<BehavioralBaselineSnapshot>>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let key = behavioral_baseline_key(strategy_id);
        let Some(payload) = connection
            .store
            .get(&key)
            .await
            .map_err(|error| nats_error("get value", error))?
        else {
            return Ok(None);
        };

        let location = format!("jetstream://{}/{}", self.bucket, key);
        let snapshot =
            serde_json::from_slice::<SignedStateEnvelope<BehavioralBaselineSnapshot>>(&payload)
                .map_err(|source| SubstrateError::Decode { location, source })?;
        Ok(Some(snapshot))
    }

    #[cfg(feature = "nats")]
    async fn load_behavioral_baseline_sequence(
        &self,
        strategy_id: &str,
    ) -> Result<Option<u64>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let key = behavioral_baseline_sequence_key(strategy_id);
        let Some(payload) = connection
            .store
            .get(&key)
            .await
            .map_err(|error| nats_error("get value", error))?
        else {
            return Ok(None);
        };

        let location = format!("jetstream://{}/{}", self.bucket, key);
        serde_json::from_slice::<u64>(&payload)
            .map(Some)
            .map_err(|source| SubstrateError::Decode { location, source })
    }

    #[cfg(feature = "nats")]
    async fn load_escalations(
        &self,
        since_timestamp: i64,
    ) -> Result<Vec<EscalationRecord>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut escalations = Vec::new();

        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            if !is_escalation_key(&key) {
                continue;
            }

            let Some(payload) = connection
                .store
                .get(&key)
                .await
                .map_err(|error| nats_error("get value", error))?
            else {
                continue;
            };

            let location = format!("jetstream://{}/{}", self.bucket, key);
            let record = serde_json::from_slice::<EscalationRecord>(&payload)
                .map_err(|source| SubstrateError::Decode { location, source })?;
            if record.timestamp >= since_timestamp {
                escalations.push(record);
            }
        }

        Ok(filter_escalations(&escalations, since_timestamp))
    }

    #[cfg(feature = "nats")]
    fn note_gc_page(&self, page: i64) {
        let mut guard = self
            .gc_page_cursor
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *guard = Some(match *guard {
            Some(current) => current.min(page),
            None => page,
        });
    }

    #[cfg(feature = "nats")]
    async fn gc_evaporated_legacy(&self, now: i64) -> Result<usize, SubstrateError> {
        if *self
            .legacy_gc_complete
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
        {
            return Ok(0);
        }

        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut removed = 0usize;
        let mut saw_legacy_key = false;

        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            if is_escalation_key(&key)
                || is_policy_key(&key)
                || is_threat_intel_key(&key)
                || is_behavioral_baseline_key(&key)
            {
                continue;
            }
            if key_gc_page(&key).is_some() {
                continue;
            }
            saw_legacy_key = true;

            let Some(payload) = connection
                .store
                .get(&key)
                .await
                .map_err(|error| nats_error("get value", error))?
            else {
                continue;
            };

            let location = format!("jetstream://{}/{}", self.bucket, key);
            let deposit = decode_deposit_payload(&payload, location)?;
            if is_retention_expired(
                &deposit,
                now,
                self.config.default_half_life_secs,
                self.config.evaporation_threshold,
            ) {
                connection
                    .store
                    .delete(&key)
                    .await
                    .map_err(|error| nats_error("delete value", error))?;
                self.verified_deposit_cache
                    .lock()
                    .map_err(|_| SubstrateError::PoisonedLock)?
                    .remove(&key);
                removed = removed.saturating_add(1);
            }
        }

        if !saw_legacy_key {
            let mut guard = self
                .legacy_gc_complete
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            *guard = true;
        }

        Ok(removed)
    }

    #[cfg(feature = "nats")]
    async fn oldest_gc_page(&self) -> Result<Option<i64>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut oldest: Option<i64> = None;

        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            let Some(page) = key_gc_page(&key) else {
                continue;
            };
            oldest = Some(match oldest {
                Some(current) => current.min(page),
                None => page,
            });
        }

        Ok(oldest)
    }

    #[cfg(feature = "nats")]
    async fn gc_page_keys(
        &self,
        connection: &JetStreamConnection,
        page: i64,
    ) -> Result<Vec<String>, SubstrateError> {
        let consumer = connection
            .store
            .stream
            .create_consumer(async_nats::jetstream::consumer::push::OrderedConfig {
                deliver_subject: connection.client.new_inbox(),
                description: Some("kv gc page consumer".to_string()),
                filter_subject: format!("{}{}", connection.store.prefix, gc_page_subject(page)),
                headers_only: true,
                replay_policy: async_nats::jetstream::consumer::ReplayPolicy::Instant,
                deliver_policy: async_nats::jetstream::consumer::DeliverPolicy::LastPerSubject,
                ..Default::default()
            })
            .await
            .map_err(|error| nats_error("create gc page consumer", error))?;

        if consumer.cached_info().num_pending == 0 {
            return Ok(Vec::new());
        }

        let mut messages = consumer
            .messages()
            .await
            .map_err(|error| nats_error("subscribe gc page consumer", error))?;
        let mut keys = Vec::new();

        while let Some(message) = messages.next().await {
            let message = message.map_err(|error| nats_error("stream gc page consumer", error))?;
            let key = message
                .subject
                .strip_prefix(&connection.store.prefix)
                .map(ToString::to_string)
                .unwrap_or_else(|| message.subject.to_string());

            if connection
                .store
                .get(&key)
                .await
                .map_err(|error| nats_error("get value", error))?
                .is_some()
            {
                keys.push(key);
            }

            let info = message
                .info()
                .map_err(|error| nats_error("parse gc page metadata", error))?;
            if info.pending == 0 {
                break;
            }
        }

        Ok(keys)
    }

    #[cfg(feature = "nats")]
    async fn gc_evaporated_by_page(&self, now: i64) -> Result<usize, SubstrateError> {
        let current_page = gc_sweep_page(now);
        let cached_cursor = *self
            .gc_page_cursor
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let start_page = match cached_cursor {
            Some(page) => page,
            None => match self.oldest_gc_page().await? {
                Some(page) => page,
                None => return Ok(0),
            },
        };

        if start_page > current_page {
            return Ok(0);
        }

        let end_page = start_page
            .saturating_add(self.gc_page_size.saturating_sub(1) as i64)
            .min(current_page);
        let connection = self.ensure_connected().await?;
        let mut removed = 0usize;

        for page in start_page..=end_page {
            for key in self.gc_page_keys(connection, page).await? {
                connection
                    .store
                    .delete(&key)
                    .await
                    .map_err(|error| nats_error("delete value", error))?;
                self.verified_deposit_cache
                    .lock()
                    .map_err(|_| SubstrateError::PoisonedLock)?
                    .remove(&key);
                removed = removed.saturating_add(1);
            }
        }

        let mut guard = self
            .gc_page_cursor
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *guard = if end_page == current_page {
            None
        } else {
            Some(end_page.saturating_add(1))
        };

        Ok(removed)
    }

    #[cfg(feature = "nats")]
    async fn gc_evaporated_with_policy_scan(&self, now: i64) -> Result<usize, SubstrateError> {
        let threat_class_configs = self
            .load_threat_class_configs()
            .await?
            .into_iter()
            .map(|config| (config.threat_class.clone(), config))
            .collect::<BTreeMap<_, _>>();
        if threat_class_configs.is_empty() {
            return Ok(0);
        }

        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut removed = 0usize;

        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            if is_escalation_key(&key)
                || is_policy_key(&key)
                || is_threat_intel_key(&key)
                || is_behavioral_baseline_key(&key)
            {
                continue;
            }

            let Some(payload) = connection
                .store
                .get(&key)
                .await
                .map_err(|error| nats_error("get value", error))?
            else {
                continue;
            };

            let location = format!("jetstream://{}/{}", self.bucket, key);
            let deposit = decode_deposit_payload(&payload, location)?;
            let policy = self
                .config
                .resolve_threat_class_policy(threat_class_configs.get(&deposit.threat_class));
            if !is_retention_expired(
                &deposit,
                now,
                policy.half_life_secs,
                policy.evaporation_threshold,
            ) {
                continue;
            }

            connection
                .store
                .delete(&key)
                .await
                .map_err(|error| nats_error("delete value", error))?;
            self.verified_deposit_cache
                .lock()
                .map_err(|_| SubstrateError::PoisonedLock)?
                .remove(&key);
            removed = removed.saturating_add(1);
        }

        Ok(removed)
    }
}

#[cfg(feature = "nats")]
#[async_trait]
impl PheromoneSubstrate for JetStreamPheromoneSubstrate {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
        // Apply the same signature and hard encoded-size admission used by
        // every read path before a value can become durable. Otherwise an
        // oversized but validly signed value poisons all later scans.
        let deposit = VerifiedDeposit::admit(deposit)?;
        self.admission_control
            .validate_deposit_admission(&deposit)?;
        let threat_class_config = self.load_threat_class_config(&deposit.threat_class).await?;
        let policy = self
            .config
            .resolve_threat_class_policy(threat_class_config.as_ref());
        validate_deposit_policy(&deposit, policy.half_life_secs)?;
        let trusted_now = trusted_system_unix_seconds()?;
        validate_deposit_retention(
            &deposit,
            trusted_now,
            policy.half_life_secs,
            policy.evaporation_threshold,
            Some(trusted_now),
        )?;
        let connection = self.ensure_connected().await?;
        let payload = serde_json::to_vec(&*deposit).map_err(|source| SubstrateError::Encode {
            context: "jetstream pheromone deposit".to_string(),
            source,
        })?;
        let gc_page = expiration_gc_page(
            &deposit,
            policy.half_life_secs,
            policy.evaporation_threshold,
        );
        let key = deposit_key(
            &deposit,
            &payload,
            policy.half_life_secs,
            policy.evaporation_threshold,
        );

        let revision = connection
            .store
            .put(key.clone(), payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
        self.verified_deposit_cache
            .lock()
            .map_err(|_| SubstrateError::PoisonedLock)?
            .insert(key, revision, deposit);
        self.note_gc_page(gc_page);
        Ok(())
    }

    async fn record_escalation(&self, record: EscalationRecord) -> Result<(), SubstrateError> {
        let connection = self.ensure_connected().await?;
        let payload = serde_json::to_vec(&record).map_err(|source| SubstrateError::Encode {
            context: "jetstream escalation record".to_string(),
            source,
        })?;
        let key = escalation_key(&record, &payload);
        connection
            .store
            .put(key, payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
        Ok(())
    }

    async fn store_threat_class_config(
        &self,
        config: ThreatClassConfig,
    ) -> Result<(), SubstrateError> {
        let connection = self.ensure_connected().await?;
        let threat_class_segment = threat_class_segment(&config.threat_class);
        let payload = serde_json::to_vec(&config).map_err(|source| SubstrateError::Encode {
            context: "jetstream threat class config".to_string(),
            source,
        })?;
        let key = threat_class_config_key(&config.threat_class);
        connection
            .store
            .put(key, payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
        // GC pages are admission-time hints, not durable expiry authority.
        // A policy update must force a policy-aware replay so deposits that
        // remain live under a lower threshold cannot be discarded by an old
        // encoded page.
        self.deposit_key_indexes
            .lock()
            .await
            .partitions
            .remove(&threat_class_segment);
        Ok(())
    }

    async fn store_threat_intel_entry(
        &self,
        entry: ThreatIntelEntry,
    ) -> Result<(), SubstrateError> {
        let connection = self.ensure_connected().await?;
        let entry = ThreatIntelEntry {
            value: normalize_threat_intel_value(&entry.indicator_type, &entry.value),
            ..entry
        };
        let payload = serde_json::to_vec(&entry).map_err(|source| SubstrateError::Encode {
            context: "jetstream threat intel entry".to_string(),
            source,
        })?;
        let key = threat_intel_key(&entry.indicator_type, &entry.value);
        connection
            .store
            .put(key, payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
        Ok(())
    }

    async fn store_behavioral_baseline_snapshot(
        &self,
        snapshot: BehavioralBaselineSnapshot,
        signer_agent_id: &AgentId,
        signing_key: &SigningKey,
    ) -> Result<(), SubstrateError> {
        let connection = self.ensure_connected().await?;
        let key = behavioral_baseline_key(&snapshot.strategy_id);
        let sequence_key = behavioral_baseline_sequence_key(&snapshot.strategy_id);
        let current_sequence = self
            .load_behavioral_baseline_sequence(&snapshot.strategy_id)
            .await?
            .unwrap_or(0);
        let envelope = SignedStateEnvelope::sign(
            BEHAVIORAL_BASELINE_STATE_KIND,
            snapshot.strategy_id.clone(),
            signer_agent_id.clone(),
            current_sequence.saturating_add(1),
            snapshot,
            signing_key,
        )
        .map_err(|source| SubstrateError::InvalidBehavioralBaseline {
            strategy_id: key.clone(),
            source,
        })?;
        let payload = serde_json::to_vec(&envelope).map_err(|source| SubstrateError::Encode {
            context: "jetstream behavioral baseline snapshot".to_string(),
            source,
        })?;
        connection
            .store
            .put(key, payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
        let sequence_payload =
            serde_json::to_vec(&envelope.sequence()).map_err(|source| SubstrateError::Encode {
                context: "jetstream behavioral baseline sequence".to_string(),
                source,
            })?;
        connection
            .store
            .put(sequence_key, sequence_payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
        Ok(())
    }

    async fn query_concentration(
        &self,
        threat_class: &ThreatClass,
        now: i64,
    ) -> Result<PheromoneConcentration, SubstrateError> {
        let threat_class_config = self.load_threat_class_config(threat_class).await?;
        let policy = self
            .config
            .resolve_threat_class_policy(threat_class_config.as_ref());
        let deposits = self
            .load_deposits(Some(threat_class), None, Some(now))
            .await?;
        Ok(concentration_for(&deposits, threat_class, now, &policy))
    }

    async fn query_deposits(
        &self,
        query: DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        let deposits = self
            .load_deposits(query.threat_class.as_ref(), query.since_timestamp, None)
            .await?;
        Ok(filter_deposits(&deposits, query))
    }

    async fn query_escalations(
        &self,
        since_timestamp: i64,
    ) -> Result<Vec<EscalationRecord>, SubstrateError> {
        self.load_escalations(since_timestamp).await
    }

    async fn query_threat_class_config(
        &self,
        threat_class: &ThreatClass,
    ) -> Result<Option<ThreatClassConfig>, SubstrateError> {
        self.load_threat_class_config(threat_class).await
    }

    async fn query_threat_class_configs(&self) -> Result<Vec<ThreatClassConfig>, SubstrateError> {
        self.load_threat_class_configs().await
    }

    async fn query_threat_intel_entry(
        &self,
        indicator_type: &ThreatIntelIndicatorType,
        value: &str,
        now: i64,
    ) -> Result<Option<ThreatIntelEntry>, SubstrateError> {
        self.load_threat_intel_entry(indicator_type, value, now)
            .await
    }

    async fn query_behavioral_baseline_snapshot(
        &self,
        strategy_id: &str,
        expected_signer_agent_id: &AgentId,
    ) -> Result<Option<BehavioralBaselineSnapshot>, SubstrateError> {
        let Some(envelope) = self.load_behavioral_baseline_snapshot(strategy_id).await? else {
            return Ok(None);
        };
        let accepted_sequence = self.load_behavioral_baseline_sequence(strategy_id).await?;
        let statement = envelope
            .verify(SignedStateExpectation {
                state_kind: BEHAVIORAL_BASELINE_STATE_KIND,
                stream_id: strategy_id,
                expected_signer_agent_id: Some(expected_signer_agent_id),
                accepted_sequence,
            })
            .map_err(|source| SubstrateError::InvalidBehavioralBaseline {
                strategy_id: strategy_id.to_string(),
                source,
            })?;
        if accepted_sequence.is_none_or(|sequence| sequence < statement.sequence) {
            let connection = self.ensure_connected().await?;
            let payload = serde_json::to_vec(&statement.sequence).map_err(|source| {
                SubstrateError::Encode {
                    context: "jetstream behavioral baseline sequence".to_string(),
                    source,
                }
            })?;
            connection
                .store
                .put(
                    behavioral_baseline_sequence_key(strategy_id),
                    payload.into(),
                )
                .await
                .map_err(|error| nats_error("put value", error))?;
        }
        Ok(Some(statement.payload))
    }

    async fn gc_evaporated(&self, now: i64) -> Result<usize, SubstrateError> {
        if self.load_threat_class_configs().await?.is_empty() {
            let mut removed = 0usize;
            removed = removed.saturating_add(self.gc_evaporated_legacy(now).await?);
            removed = removed.saturating_add(self.gc_evaporated_by_page(now).await?);
            return Ok(removed);
        }

        let mut removed = 0usize;
        removed = removed.saturating_add(self.gc_evaporated_with_policy_scan(now).await?);
        Ok(removed)
    }

    async fn gc_expired_threat_intel(&self, now: i64) -> Result<usize, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut purged = 0usize;

        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            if !is_threat_intel_key(&key) {
                continue;
            }

            let Some(payload) = connection
                .store
                .get(&key)
                .await
                .map_err(|error| nats_error("get value", error))?
            else {
                continue;
            };

            let location = format!("jetstream://{}/{}", self.bucket, key);
            let intel_entry = serde_json::from_slice::<ThreatIntelEntry>(&payload)
                .map_err(|source| SubstrateError::Decode { location, source })?;

            if intel_entry.expires_at <= now {
                connection
                    .store
                    .delete(&key)
                    .await
                    .map_err(|error| nats_error("delete value", error))?;
                purged = purged.saturating_add(1);
            }
        }

        if purged > 0 {
            tracing::info!(purged, "gc_expired_threat_intel complete");
        } else {
            tracing::debug!(purged, "gc_expired_threat_intel complete");
        }
        Ok(purged)
    }

    async fn health(&self) -> Result<SubstrateHealth, SubstrateError> {
        match self.ensure_connected().await {
            Ok(connection) => {
                let ready = connection.client.connection_state()
                    == async_nats::connection::State::Connected;
                let deposit_count = match self.deposit_count().await {
                    Ok(count) => count,
                    Err(error) => {
                        return Ok(SubstrateHealth {
                            backend: "jetstream".to_string(),
                            durable: true,
                            ready: false,
                            details: format!(
                                "JetStream bucket `{}` at {} is reachable, but key listing failed: {error}",
                                self.bucket, self.url
                            ),
                            deposit_count: 0,
                        });
                    }
                };

                Ok(SubstrateHealth {
                    backend: "jetstream".to_string(),
                    durable: true,
                    ready,
                    details: format!("JetStream KV bucket `{}` at {}", self.bucket, self.url),
                    deposit_count,
                })
            }
            Err(error) => Ok(SubstrateHealth {
                backend: "jetstream".to_string(),
                durable: true,
                ready: false,
                details: format!("JetStream unavailable: {error}"),
                deposit_count: 0,
            }),
        }
    }
}

#[cfg(not(feature = "nats"))]
#[async_trait]
impl PheromoneSubstrate for JetStreamPheromoneSubstrate {
    async fn deposit(&self, _deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
        Err(unsupported_backend())
    }

    async fn record_escalation(&self, _record: EscalationRecord) -> Result<(), SubstrateError> {
        Err(unsupported_backend())
    }

    async fn store_threat_class_config(
        &self,
        _config: ThreatClassConfig,
    ) -> Result<(), SubstrateError> {
        Err(unsupported_backend())
    }

    async fn store_threat_intel_entry(
        &self,
        _entry: ThreatIntelEntry,
    ) -> Result<(), SubstrateError> {
        Err(unsupported_backend())
    }

    async fn store_behavioral_baseline_snapshot(
        &self,
        _snapshot: BehavioralBaselineSnapshot,
        _signer_agent_id: &AgentId,
        _signing_key: &SigningKey,
    ) -> Result<(), SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_concentration(
        &self,
        _threat_class: &ThreatClass,
        _now: i64,
    ) -> Result<PheromoneConcentration, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_deposits(
        &self,
        _query: DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_escalations(
        &self,
        _since_timestamp: i64,
    ) -> Result<Vec<EscalationRecord>, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_threat_class_config(
        &self,
        _threat_class: &ThreatClass,
    ) -> Result<Option<ThreatClassConfig>, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_threat_class_configs(&self) -> Result<Vec<ThreatClassConfig>, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_threat_intel_entry(
        &self,
        _indicator_type: &ThreatIntelIndicatorType,
        _value: &str,
        _now: i64,
    ) -> Result<Option<ThreatIntelEntry>, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn query_behavioral_baseline_snapshot(
        &self,
        _strategy_id: &str,
        _expected_signer_agent_id: &AgentId,
    ) -> Result<Option<BehavioralBaselineSnapshot>, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn gc_evaporated(&self, _now: i64) -> Result<usize, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn gc_expired_threat_intel(&self, _now: i64) -> Result<usize, SubstrateError> {
        Err(unsupported_backend())
    }

    async fn health(&self) -> Result<SubstrateHealth, SubstrateError> {
        Ok(SubstrateHealth {
            backend: "jetstream".to_string(),
            durable: true,
            ready: false,
            details: "backend compiled without `nats` feature".to_string(),
            deposit_count: 0,
        })
    }
}

#[cfg(feature = "nats")]
async fn ensure_kv_bucket(
    jetstream: &async_nats::jetstream::Context,
    bucket: &str,
) -> Result<async_nats::jetstream::kv::Store, SubstrateError> {
    match jetstream.get_key_value(bucket).await {
        Ok(store) => Ok(store),
        Err(_) => jetstream
            .create_key_value(async_nats::jetstream::kv::Config {
                bucket: bucket.to_string(),
                history: 1,
                ..Default::default()
            })
            .await
            .map_err(|error| nats_error("create kv bucket", error)),
    }
}

#[cfg(feature = "nats")]
fn deposit_key(
    deposit: &PheromoneDeposit,
    payload: &[u8],
    policy_half_life_secs: f64,
    evaporation_threshold: f64,
) -> String {
    let gc_page = expiration_gc_page(deposit, policy_half_life_secs, evaporation_threshold);
    let threat_class = threat_class_segment(&deposit.threat_class);
    let kind = match deposit_kind(deposit) {
        DepositKeyKind::Evidence => "evidence",
        DepositKeyKind::Control => "control",
    };
    let agent_hash = hash_prefix(deposit.agent_id.0.as_bytes(), 12);
    let deposit_hash = hash_prefix(payload, 12);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{GC_KEY_PREFIX}.{gc_page:020}.{threat_class}.{kind}.{:020}.{}-{deposit_hash}-{nonce}",
        deposit.timestamp.max(0),
        agent_hash
    )
}

#[cfg(feature = "nats")]
fn deposit_kind(deposit: &PheromoneDeposit) -> DepositKeyKind {
    if deposit.confidence == 0.0 {
        DepositKeyKind::Control
    } else {
        DepositKeyKind::Evidence
    }
}

#[cfg(feature = "nats")]
fn escalation_key(record: &EscalationRecord, payload: &[u8]) -> String {
    let threat_class = threat_class_segment(&record.threat_class);
    let record_hash = hash_prefix(payload, 12);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{ESCALATION_KEY_PREFIX}.{:020}.{}.{}-{record_hash}-{nonce}",
        record.timestamp.max(0),
        mode_segment(record.mode),
        threat_class
    )
}

#[cfg(feature = "nats")]
fn threat_class_segment(threat_class: &ThreatClass) -> String {
    match threat_class {
        ThreatClass::LateralMovement => "lateral_movement".to_string(),
        ThreatClass::DataExfiltration => "data_exfiltration".to_string(),
        ThreatClass::PrivilegeEscalation => "privilege_escalation".to_string(),
        ThreatClass::CommandAndControl => "command_and_control".to_string(),
        ThreatClass::InitialAccess => "initial_access".to_string(),
        ThreatClass::Persistence => "persistence".to_string(),
        ThreatClass::SupplyChain => "supply_chain".to_string(),
        ThreatClass::DefenseEvasion => "defense_evasion".to_string(),
        ThreatClass::CredentialAccess => "credential_access".to_string(),
        ThreatClass::Discovery => "discovery".to_string(),
        ThreatClass::Execution => "execution".to_string(),
        ThreatClass::Impact => "impact".to_string(),
        ThreatClass::Custom(name) => format!("custom_{}", sanitize_segment(name)),
    }
}

#[cfg(feature = "nats")]
fn mode_segment(mode: swarm_core::agent::SwarmMode) -> &'static str {
    match mode {
        swarm_core::agent::SwarmMode::Normal => "normal",
        swarm_core::agent::SwarmMode::Alert => "alert",
        swarm_core::agent::SwarmMode::Incident => "incident",
    }
}

#[cfg(feature = "nats")]
fn sanitize_segment(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();

    if sanitized.trim_matches('_').is_empty() {
        "custom".to_string()
    } else {
        sanitized
    }
}

#[cfg(feature = "nats")]
fn hash_prefix(bytes: &[u8], prefix_len: usize) -> String {
    let digest = Sha256::digest(bytes);
    let encoded = hex::encode(digest);
    let prefix_len = prefix_len.min(encoded.len());
    encoded[..prefix_len].to_string()
}

#[cfg(feature = "nats")]
fn deposit_key_timestamp(key: &str) -> Option<i64> {
    if let Some(stripped) = key.strip_prefix(&format!("{GC_KEY_PREFIX}.")) {
        let mut parts = stripped.split('.');
        let _page = parts.next()?;
        let _threat_class = parts.next()?;
        let kind_or_timestamp = parts.next()?;
        return if matches!(kind_or_timestamp, "evidence" | "control") {
            parts.next()?.parse().ok()
        } else {
            kind_or_timestamp.parse().ok()
        };
    }

    key.split('.').nth(1)?.parse().ok()
}

#[cfg(feature = "nats")]
fn deposit_key_kind(key: &str) -> Option<DepositKeyKind> {
    let stripped = key.strip_prefix(&format!("{GC_KEY_PREFIX}."))?;
    match stripped.split('.').nth(2)? {
        "evidence" => Some(DepositKeyKind::Evidence),
        "control" => Some(DepositKeyKind::Control),
        _ => None,
    }
}

#[cfg(feature = "nats")]
fn is_escalation_key(key: &str) -> bool {
    key.starts_with(&format!("{ESCALATION_KEY_PREFIX}."))
}

#[cfg(feature = "nats")]
fn is_policy_key(key: &str) -> bool {
    key.starts_with(&format!("{THREAT_CLASS_CONFIG_KEY_PREFIX}."))
}

#[cfg(feature = "nats")]
fn is_threat_intel_key(key: &str) -> bool {
    key.starts_with(&format!("{THREAT_INTEL_KEY_PREFIX}."))
}

#[cfg(feature = "nats")]
fn is_behavioral_baseline_key(key: &str) -> bool {
    key.starts_with(&format!("{BEHAVIORAL_BASELINE_KEY_PREFIX}."))
}

#[cfg(feature = "nats")]
fn threat_class_config_key(threat_class: &ThreatClass) -> String {
    format!(
        "{THREAT_CLASS_CONFIG_KEY_PREFIX}.{}",
        threat_class_segment(threat_class)
    )
}

#[cfg(feature = "nats")]
fn threat_intel_key(indicator_type: &ThreatIntelIndicatorType, value: &str) -> String {
    let normalized = normalize_threat_intel_value(indicator_type, value);
    format!(
        "{THREAT_INTEL_KEY_PREFIX}.{}.{}",
        threat_intel_indicator_segment(indicator_type),
        hash_prefix(normalized.as_bytes(), 64)
    )
}

#[cfg(feature = "nats")]
fn behavioral_baseline_key(strategy_id: &str) -> String {
    format!(
        "{BEHAVIORAL_BASELINE_KEY_PREFIX}.{}",
        sanitize_segment(strategy_id)
    )
}

#[cfg(feature = "nats")]
fn behavioral_baseline_sequence_key(strategy_id: &str) -> String {
    format!(
        "{BEHAVIORAL_BASELINE_KEY_PREFIX}.sequence.{}",
        sanitize_segment(strategy_id)
    )
}

#[cfg(feature = "nats")]
fn threat_intel_indicator_segment(indicator_type: &ThreatIntelIndicatorType) -> &'static str {
    match indicator_type {
        ThreatIntelIndicatorType::IpAddress => "ip_address",
        ThreatIntelIndicatorType::Domain => "domain",
        ThreatIntelIndicatorType::FileHash => "file_hash",
        ThreatIntelIndicatorType::Url => "url",
    }
}

#[cfg(feature = "nats")]
fn expiration_gc_page(
    deposit: &PheromoneDeposit,
    policy_half_life_secs: f64,
    evaporation_threshold: f64,
) -> i64 {
    let deadline = evaporation_deadline(deposit, policy_half_life_secs, evaporation_threshold);
    div_ceil_i64(deadline.max(0), GC_PAGE_SPAN_SECS)
}

#[cfg(feature = "nats")]
fn evaporation_deadline(
    deposit: &PheromoneDeposit,
    policy_half_life_secs: f64,
    evaporation_threshold: f64,
) -> i64 {
    let initial_strength = retention_initial_strength(deposit);
    if initial_strength <= evaporation_threshold || deposit.decay_half_life <= 0.0 {
        return deposit.timestamp;
    }

    let elapsed_until_evaporation = deposit.decay_half_life.min(policy_half_life_secs)
        * (initial_strength / evaporation_threshold).log2();
    deposit
        .timestamp
        .saturating_add(elapsed_until_evaporation.ceil() as i64)
}

#[cfg(feature = "nats")]
fn gc_sweep_page(now: i64) -> i64 {
    now.max(0).div_euclid(GC_PAGE_SPAN_SECS)
}

#[cfg(feature = "nats")]
fn div_ceil_i64(value: i64, divisor: i64) -> i64 {
    let quotient = value.div_euclid(divisor);
    let remainder = value.rem_euclid(divisor);
    if remainder == 0 {
        quotient
    } else {
        quotient.saturating_add(1)
    }
}

#[cfg(feature = "nats")]
fn key_gc_page(key: &str) -> Option<i64> {
    let stripped = key.strip_prefix(&format!("{GC_KEY_PREFIX}."))?;
    stripped.split('.').next()?.parse().ok()
}

#[cfg(feature = "nats")]
fn gc_page_subject(page: i64) -> String {
    format!("{GC_KEY_PREFIX}.{page:020}.>")
}

#[cfg(not(feature = "nats"))]
fn unsupported_backend() -> SubstrateError {
    SubstrateError::UnsupportedBackend {
        backend: "jetstream",
        reason: "swarm-pheromone was compiled without `nats` support".to_string(),
    }
}

#[cfg(feature = "nats")]
fn nats_error(operation: &'static str, error: impl fmt::Display) -> SubstrateError {
    SubstrateError::Nats {
        operation,
        reason: error.to_string(),
    }
}

#[cfg(all(test, feature = "nats"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        DEFAULT_JETSTREAM_GC_PAGE_SIZE, DEFAULT_NATS_CONNECT_TIMEOUT_MS, DepositKeyIndexes,
        DepositKeyKind, DepositKeyPartitionIndex, IndexedDepositKey, JetStreamPheromoneSubstrate,
        MAX_DEPOSIT_KEY_INDEX_PARTITIONS, MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES, NatsAuthentication,
        VerifiedDepositCache, deposit_key_kind, deposit_key_timestamp, evaporation_deadline,
        expiration_gc_page, gc_sweep_page, parse_nats_endpoint, retain_newest_deposit_key,
        retain_newest_partitioned_deposit_key_as,
    };
    use crate::{
        PheromoneSubstrate,
        substrate::{
            MAX_ACTIVE_DEPOSIT_BYTES, VerifiedDeposit, deposit_suppression_key,
            feedback_suppression_marker,
        },
    };
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use swarm_core::agent::SwarmMode;
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig, ResponsePlaybookConfig};
    use swarm_core::pheromone::{
        EscalationRecord, PheromoneDeposit, ThreatClass, ThreatClassConfig, ThreatIntelEntry,
        ThreatIntelIndicatorType,
    };
    use swarm_core::types::{AgentId, SWARM_PROVIDENCE_FEEDBACK_SCHEMA, Severity};

    fn substrate_config() -> PheromoneConfig {
        PheromoneConfig {
            default_half_life_secs: 3600.0,
            evaporation_threshold: 0.01,
            min_sources_for_escalation: 2,
            alert_threshold: 2.0,
            incident_threshold: 5.0,
            deescalation_cooldown_secs: 300,
            response_playbook: ResponsePlaybookConfig::default(),
            backend: PheromoneBackendConfig::JetStream {
                url: nats_url(),
                connect_timeout_ms: DEFAULT_NATS_CONNECT_TIMEOUT_MS,
                gc_page_size: DEFAULT_JETSTREAM_GC_PAGE_SIZE,
            },
        }
    }

    fn now_timestamp() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before unix epoch")
                .as_secs(),
        )
        .expect("unix timestamp exceeds i64")
    }

    fn signing_key_for_label(label: &str) -> SigningKey {
        let digest = Sha256::digest(label.as_bytes());
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&digest);
        SigningKey::from_bytes(&seed)
    }

    fn sample_deposit(agent_id: &str, timestamp: i64, confidence: f64) -> PheromoneDeposit {
        let key = signing_key_for_label(agent_id);
        let derived_agent_id = AgentId::from_verifying_key(&key.verifying_key());
        let mut deposit = PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({"signal": "jetstream-test"}),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence,
            timestamp,
            decay_half_life: 3600.0,
            agent_id: derived_agent_id.clone(),
            agent_identity: derived_agent_id.0,
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        };
        let signing_bytes = crate::substrate::signing_payload_bytes_for_deposit(&deposit).unwrap();
        deposit.signature = key.sign(&signing_bytes).to_bytes().to_vec();
        deposit.agent_key = key.verifying_key().to_bytes().to_vec();
        deposit
    }

    fn verified_sample_deposit() -> VerifiedDeposit {
        let key = SigningKey::from_bytes(&[92_u8; 32]);
        let mut deposit = sample_deposit("placeholder", 100, 0.9);
        deposit.agent_id = AgentId::from_verifying_key(&key.verifying_key());
        deposit.agent_identity = deposit.agent_id.0.clone();
        let signing_bytes = crate::substrate::signing_payload_bytes_for_deposit(&deposit).unwrap();
        deposit.signature = key.sign(&signing_bytes).to_bytes().to_vec();
        deposit.agent_key = key.verifying_key().to_bytes().to_vec();
        VerifiedDeposit::admit(deposit).unwrap()
    }

    fn resign_sample_deposit(
        label: &str,
        mut deposit: PheromoneDeposit,
        indicator: serde_json::Value,
    ) -> PheromoneDeposit {
        let key = signing_key_for_label(label);
        let derived_agent_id = AgentId::from_verifying_key(&key.verifying_key());
        deposit.indicator = indicator;
        deposit.agent_id = derived_agent_id.clone();
        deposit.agent_identity = derived_agent_id.0;
        deposit.signature.clear();
        deposit.agent_key.clear();
        let signing_bytes = crate::substrate::signing_payload_bytes_for_deposit(&deposit).unwrap();
        deposit.signature = key.sign(&signing_bytes).to_bytes().to_vec();
        deposit.agent_key = key.verifying_key().to_bytes().to_vec();
        deposit
    }

    fn indexed_deposit(key: &str, deposit: PheromoneDeposit) -> IndexedDepositKey {
        let deposit = VerifiedDeposit::admit(deposit).unwrap();
        IndexedDepositKey {
            timestamp: deposit.timestamp,
            key: key.to_string(),
            encoded_len: deposit.encoded_len(),
            suppression_key: deposit_suppression_key(&deposit),
            feedback_marker_key: feedback_suppression_marker(&deposit).map(|(key, _)| key),
        }
    }

    #[test]
    fn verified_deposit_cache_requires_an_exact_revision_and_stays_bounded() {
        let deposit = verified_sample_deposit();
        let mut cache = VerifiedDepositCache::default();

        assert!(cache.get("deposit-a", 41).is_none());
        cache.insert("deposit-a".to_string(), 41, deposit.clone());
        assert!(cache.get("deposit-a", 41).is_some());
        assert!(cache.get("deposit-a", 42).is_none());

        cache.insert("deposit-a".to_string(), 42, deposit.clone());
        assert!(cache.get("deposit-a", 41).is_none());
        assert!(cache.get("deposit-a", 42).is_some());

        for index in 0..=MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES {
            cache.insert(format!("deposit-{index:05}"), index as u64, deposit.clone());
        }
        assert_eq!(cache.entries.len(), MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES);
        assert!(cache.encoded_bytes <= MAX_ACTIVE_DEPOSIT_BYTES);

        let large = resign_sample_deposit(
            "large-cache-entry",
            sample_deposit("large-cache-entry", 101, 0.9),
            serde_json::json!({"padding": "x".repeat(200 * 1024)}),
        );
        let large = VerifiedDeposit::admit(large).unwrap();
        for index in 0..200 {
            cache.insert(format!("large-{index:05}"), index, large.clone());
        }
        assert!(cache.entries.len() < 200);
        assert!(cache.encoded_bytes <= MAX_ACTIVE_DEPOSIT_BYTES);
        assert_eq!(
            cache.encoded_bytes,
            cache
                .entries
                .values()
                .map(|entry| entry.deposit.encoded_len())
                .sum::<usize>()
        );
    }

    #[test]
    fn bounded_control_eviction_drops_related_evidence_when_final_feedback_is_lost() {
        let evidence = resign_sample_deposit(
            "evidence",
            sample_deposit("evidence", 100, 0.9),
            serde_json::json!({"event_id": "event-dismissed"}),
        );
        let dismissal = resign_sample_deposit(
            "reviewer",
            sample_deposit("reviewer", 200, 0.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "event_id": "event-dismissed",
                "action": "dismiss"
            }),
        );
        let unrelated_control = resign_sample_deposit(
            "control",
            sample_deposit("control", 300, 0.0),
            serde_json::json!({"event_id": "unrelated-control"}),
        );
        let mut index = DepositKeyPartitionIndex::default();
        assert!(
            index
                .insert_bounded(
                    indexed_deposit("evidence", evidence),
                    DepositKeyKind::Evidence,
                    1,
                )
                .is_empty()
        );
        assert!(
            index
                .insert_bounded(
                    indexed_deposit("dismissal", dismissal),
                    DepositKeyKind::Control,
                    1,
                )
                .is_empty()
        );
        let evicted = index.insert_bounded(
            indexed_deposit("unrelated-control", unrelated_control),
            DepositKeyKind::Control,
            1,
        );
        assert_eq!(evicted.len(), 1);
        let orphaned = index.remove_evidence_orphaned_by_feedback(&evicted[0]);
        assert_eq!(orphaned.len(), 1);
        assert_eq!(orphaned[0].key, "evidence");
        assert!(index.evidence.is_empty());
        assert_eq!(index.controls.len(), 1);
    }

    #[test]
    fn bounded_index_enforces_the_aggregate_encoded_byte_limit() {
        let large = resign_sample_deposit(
            "large-index-entry",
            sample_deposit("large-index-entry", 100, 0.9),
            serde_json::json!({"padding": "x".repeat(200 * 1024)}),
        );
        let mut index = DepositKeyPartitionIndex::default();
        let mut evicted = 0usize;
        for sequence in 0..200 {
            let mut deposit = large.clone();
            deposit.timestamp = 100 + sequence;
            deposit = resign_sample_deposit("large-index-entry", deposit, large.indicator.clone());
            evicted = evicted.saturating_add(
                index
                    .insert_bounded(
                        indexed_deposit(&format!("large-index-{sequence:05}"), deposit),
                        DepositKeyKind::Evidence,
                        MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES,
                    )
                    .len(),
            );
        }
        assert!(evicted > 0);
        assert!(index.evidence.len() < 200);
        assert!(index.total_bytes() <= MAX_ACTIVE_DEPOSIT_BYTES);
        assert_eq!(
            index.total_bytes(),
            index
                .evidence
                .iter()
                .chain(&index.controls)
                .map(|entry| entry.encoded_len)
                .sum::<usize>()
        );
    }

    #[test]
    fn deposit_indexes_bound_partitions_and_aggregate_bytes_globally() {
        let mut indexes = DepositKeyIndexes::default();
        for index in 0..MAX_DEPOSIT_KEY_INDEX_PARTITIONS {
            indexes.partitions.insert(
                format!("partition-{index:03}"),
                DepositKeyPartitionIndex::default(),
            );
        }
        indexes.make_room_for("current");
        indexes
            .partitions
            .insert("current".to_string(), DepositKeyPartitionIndex::default());
        assert_eq!(indexes.partitions.len(), MAX_DEPOSIT_KEY_INDEX_PARTITIONS);
        assert!(indexes.partitions.contains_key("current"));

        indexes
            .partitions
            .get_mut("current")
            .unwrap()
            .evidence_bytes = 20 * 1024 * 1024;
        indexes
            .partitions
            .insert("other".to_string(), DepositKeyPartitionIndex::default());
        indexes.partitions.get_mut("other").unwrap().control_bytes = 20 * 1024 * 1024;
        indexes.enforce_global_byte_bound("current");
        assert!(indexes.partitions.contains_key("current"));
        assert!(!indexes.partitions.contains_key("other"));
        assert!(
            indexes
                .partitions
                .values()
                .map(DepositKeyPartitionIndex::total_bytes)
                .sum::<usize>()
                <= MAX_ACTIVE_DEPOSIT_BYTES
        );
    }

    #[test]
    fn nats_endpoint_credentials_are_decoded_for_authentication_and_redacted_from_debug() {
        let endpoint = parse_nats_endpoint("nats://runtime:p%40ss@127.0.0.1:4222").unwrap();
        assert_eq!(endpoint.server_url, "nats://127.0.0.1:4222");
        match endpoint.authentication {
            NatsAuthentication::UserPassword { username, password } => {
                assert_eq!(username, "runtime");
                assert_eq!(password, "p@ss");
            }
            _ => panic!("expected user/password authentication"),
        }

        let substrate = JetStreamPheromoneSubstrate::with_bucket(
            substrate_config(),
            "nats://runtime:p%40ss@127.0.0.1:4222",
            "debug-redaction",
        );
        let debug = format!("{substrate:?}");
        assert!(debug.contains("nats://127.0.0.1:4222"));
        assert!(!debug.contains("runtime"));
        assert!(!debug.contains("p%40ss"));
        assert!(!debug.contains("p@ss"));
    }

    #[test]
    fn nats_endpoint_supports_token_authentication_and_rejects_non_nats_schemes() {
        let endpoint = parse_nats_endpoint("nats://opaque-token@127.0.0.1:4222").unwrap();
        assert!(matches!(
            endpoint.authentication,
            NatsAuthentication::Token(token) if token == "opaque-token"
        ));
        assert!(parse_nats_endpoint("https://127.0.0.1:4222").is_err());
    }

    #[test]
    fn deposit_key_timestamp_supports_current_and_legacy_layouts() {
        assert_eq!(
            deposit_key_timestamp(
                "exp.00000000000000000042.execution.evidence.00000000000000000123.agent"
            ),
            Some(123)
        );
        assert_eq!(
            deposit_key_timestamp("exp.00000000000000000042.execution.00000000000000000123.agent"),
            Some(123)
        );
        assert_eq!(
            deposit_key_timestamp("execution.00000000000000000456.agent"),
            Some(456)
        );
        assert_eq!(deposit_key_timestamp("exp.invalid.execution.agent"), None);
        assert_eq!(deposit_key_timestamp("execution.invalid.agent"), None);
    }

    #[test]
    fn deposit_key_kind_is_explicit_for_new_keys_and_absent_for_legacy_keys() {
        assert_eq!(
            deposit_key_kind(
                "exp.00000000000000000042.execution.evidence.00000000000000000123.agent"
            ),
            Some(DepositKeyKind::Evidence)
        );
        assert_eq!(
            deposit_key_kind(
                "exp.00000000000000000042.execution.control.00000000000000000124.agent"
            ),
            Some(DepositKeyKind::Control)
        );
        assert_eq!(
            deposit_key_kind("exp.00000000000000000042.execution.00000000000000000123.agent"),
            None
        );
    }

    #[test]
    fn jetstream_deposit_scan_retains_a_deterministic_newest_window() {
        let mut window = BTreeSet::new();
        let oldest = "exp.00000000000000000001.execution.00000000000000000100.oldest";
        let newest = "exp.00000000000000000003.execution.00000000000000000300.newest";
        let middle = "exp.00000000000000000002.execution.00000000000000000200.middle";

        retain_newest_deposit_key(&mut window, newest.to_string(), 2);
        retain_newest_deposit_key(&mut window, oldest.to_string(), 2);
        retain_newest_deposit_key(&mut window, middle.to_string(), 2);

        assert_eq!(
            window.into_iter().collect::<Vec<_>>(),
            vec![(200, middle.to_string()), (300, newest.to_string())]
        );

        let mut malformed_window = BTreeSet::new();
        retain_newest_deposit_key(&mut malformed_window, "malformed".to_string(), 1);
        retain_newest_deposit_key(&mut malformed_window, newest.to_string(), 1);
        assert_eq!(
            malformed_window.into_iter().collect::<Vec<_>>(),
            vec![(300, newest.to_string())]
        );

        let mut full_window = BTreeSet::new();
        for timestamp in 0..=MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES {
            retain_newest_deposit_key(
                &mut full_window,
                format!("execution.{timestamp:020}.agent"),
                MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES,
            );
        }
        assert_eq!(full_window.len(), MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES);
        assert_eq!(
            full_window.first().map(|(timestamp, _)| *timestamp),
            Some(1)
        );
        assert_eq!(
            full_window.last().map(|(timestamp, _)| *timestamp),
            Some(i64::try_from(MAX_VERIFIED_DEPOSIT_CACHE_ENTRIES).unwrap())
        );
    }

    #[test]
    fn jetstream_deposit_scan_partitions_control_records_before_bounding() {
        let mut evidence_window = BTreeSet::new();
        let mut control_window = BTreeSet::new();
        let evidence = "exp.00000000000000000042.execution.evidence.00000000000000000100.live";

        retain_newest_partitioned_deposit_key_as(
            &mut evidence_window,
            &mut control_window,
            evidence.to_string(),
            deposit_key_kind(evidence).unwrap(),
            2,
        );
        for timestamp in 200..203 {
            let key =
                format!("exp.00000000000000000042.execution.control.{timestamp:020}.inactive");
            let kind = deposit_key_kind(&key).unwrap();
            retain_newest_partitioned_deposit_key_as(
                &mut evidence_window,
                &mut control_window,
                key,
                kind,
                2,
            );
        }

        assert_eq!(
            evidence_window.into_iter().collect::<Vec<_>>(),
            vec![(100, evidence.to_string())]
        );
        assert_eq!(control_window.len(), 2);
        assert_eq!(
            control_window.first().map(|(timestamp, _)| *timestamp),
            Some(201)
        );
    }

    #[test]
    fn zero_strength_control_records_are_not_assigned_to_an_immediate_gc_page() {
        let deposit = sample_deposit("control", 100, 0.0);
        let deadline = evaporation_deadline(&deposit, 3_600.0, 0.01);

        assert!(deadline > deposit.timestamp);
        assert!(expiration_gc_page(&deposit, 3_600.0, 0.01) > gc_sweep_page(deposit.timestamp));
    }

    fn sample_escalation(mode: SwarmMode, timestamp: i64) -> EscalationRecord {
        EscalationRecord {
            mode,
            threat_class: ThreatClass::Execution,
            total_strength: 2.8,
            distinct_sources: 2,
            peak_confidence: 0.95,
            timestamp,
        }
    }

    fn sample_threat_class_config() -> ThreatClassConfig {
        ThreatClassConfig {
            threat_class: ThreatClass::Execution,
            half_life_secs: 180.0,
            evaporation_threshold: 0.05,
            alert_threshold: 1.2,
            incident_threshold: 3.4,
        }
    }

    fn sample_threat_intel_entry() -> ThreatIntelEntry {
        ThreatIntelEntry {
            indicator_type: ThreatIntelIndicatorType::Domain,
            value: "Example.COM.".to_string(),
            source: "operator".to_string(),
            indicator_id: None,
            confidence: 0.91,
            expires_at: 1_700_000_000_100,
        }
    }

    fn nats_url() -> String {
        std::env::var("SWARM_NATS_RUNTIME_URL")
            .or_else(|_| std::env::var("NATS_URL"))
            .unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string())
    }

    fn unique_bucket(label: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        format!("swarm-pheromone-{label}-{}-{nanos}", std::process::id())
    }

    async fn connect_for_test(label: &str) -> Option<(String, JetStreamPheromoneSubstrate)> {
        let bucket = unique_bucket(label);
        let url = nats_url();
        match JetStreamPheromoneSubstrate::connect_with_bucket(
            substrate_config(),
            url.clone(),
            bucket.clone(),
        )
        .await
        {
            Ok(substrate) => Some((bucket, substrate)),
            Err(error) => {
                assert!(
                    std::env::var_os("SWARM_NATS_HARNESS_SCRATCH").is_none(),
                    "repository-owned NATS harness failed to materialize JetStream test: {error}"
                );
                eprintln!("NATS server not available at {url}, skipping JetStream test: {error}");
                None
            }
        }
    }

    async fn wait_until<F, Fut>(mut condition: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if condition().await {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "condition was not satisfied before timeout"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    #[tokio::test]
    async fn jetstream_rejects_valid_oversized_deposit_before_connecting() {
        let substrate = JetStreamPheromoneSubstrate::with_bucket(
            substrate_config(),
            "nats://127.0.0.1:1",
            unique_bucket("oversized-prewrite"),
        );
        let key = SigningKey::from_bytes(&[91_u8; 32]);
        let mut deposit = sample_deposit("placeholder", 100, 0.9);
        deposit.agent_id = AgentId::from_verifying_key(&key.verifying_key());
        deposit.agent_identity = deposit.agent_id.0.clone();
        deposit.indicator["oversized"] =
            serde_json::Value::String("x".repeat(crate::substrate::MAX_SINGLE_DEPOSIT_BYTES));
        let signing_bytes = crate::substrate::signing_payload_bytes_for_deposit(&deposit).unwrap();
        deposit.signature = key.sign(&signing_bytes).to_bytes().to_vec();
        deposit.agent_key = key.verifying_key().to_bytes().to_vec();
        crate::substrate::validate_deposit_signature(&deposit).unwrap();

        assert!(matches!(
            substrate.deposit(deposit).await,
            Err(crate::SubstrateError::InvalidDeposit { reason })
                if reason.contains("hard limit")
        ));
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_recovers_deposits_after_reconnect() {
        let Some((bucket, substrate)) = connect_for_test("restart").await else {
            return;
        };
        let base = now_timestamp() - 2;
        substrate
            .deposit(sample_deposit("whisker-a", base, 0.9))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-b", base + 1, 0.8))
            .await
            .unwrap();
        wait_until(|| async { substrate.recent_deposits(10).await.unwrap().len() == 2 }).await;
        drop(substrate);

        let reopened = JetStreamPheromoneSubstrate::connect_with_bucket(
            substrate_config(),
            nats_url(),
            bucket,
        )
        .await
        .unwrap();
        let deposits = reopened.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 2);
        assert_eq!(deposits[0].timestamp, base + 1);
        assert_eq!(deposits[1].timestamp, base);

        let health = reopened.health().await.unwrap();
        assert!(health.ready);
        assert!(health.durable);
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_bounded_scan_filters_expired_keys_and_partitions_control_records() {
        let Some((_bucket, substrate)) = connect_for_test("partitioned-scan").await else {
            return;
        };
        let now = now_timestamp();
        substrate
            .deposit(sample_deposit("live-evidence", now, 0.9))
            .await
            .unwrap();
        let connection = substrate.ensure_connected().await.unwrap();
        let legacy_evidence = sample_deposit("legacy-live-evidence", now - 1, 0.8);
        let mut legacy_records = vec![legacy_evidence];
        legacy_records.extend((1..=4).map(|offset| {
            sample_deposit(
                &format!("legacy-inactive-control-{offset}"),
                now + offset,
                0.0,
            )
        }));
        let mut legacy_control_keys = Vec::new();
        for (index, deposit) in legacy_records.into_iter().enumerate() {
            let payload = serde_json::to_vec(&deposit).unwrap();
            let key = format!(
                "exp.{:020}.execution.{:020}.legacy-{index}",
                expiration_gc_page(&deposit, 3_600.0, 0.01),
                deposit.timestamp
            );
            if deposit.confidence == 0.0 {
                legacy_control_keys.push(key.clone());
            }
            connection.store.put(key, payload.into()).await.unwrap();
        }

        // The live concentration index uses server-side threat-class filters;
        // malformed values outside that filter are neither enumerated nor
        // decoded on the hot path.
        connection
            .store
            .put("unrelated.noise", b"not-json".as_slice().into())
            .await
            .unwrap();

        // The admission-time page says this record expired under threshold
        // 0.5, but the active operator override lowers the threshold to 0.001.
        // The page is only a candidate: signed payload plus current policy are
        // authoritative, so the record remains queryable and is not purged.
        let policy_sensitive = sample_deposit("policy-sensitive", now - 5_000, 0.9);
        let policy_sensitive_payload = serde_json::to_vec(&policy_sensitive).unwrap();
        let policy_sensitive_key = format!(
            "exp.{:020}.execution.evidence.{:020}.policy-sensitive",
            expiration_gc_page(&policy_sensitive, 3_600.0, 0.5),
            policy_sensitive.timestamp
        );
        connection
            .store
            .put(
                policy_sensitive_key.clone(),
                policy_sensitive_payload.into(),
            )
            .await
            .unwrap();
        substrate
            .store_threat_class_config(ThreatClassConfig {
                threat_class: ThreatClass::Execution,
                half_life_secs: 3_600.0,
                evaporation_threshold: 0.001,
                alert_threshold: 1.2,
                incident_threshold: 3.4,
            })
            .await
            .unwrap();

        let deposits = substrate
            .load_deposits_bounded(Some(&ThreatClass::Execution), None, Some(now + 4), 3)
            .await
            .unwrap();
        assert_eq!(deposits.len(), 6);
        assert_eq!(
            deposits
                .iter()
                .filter(|deposit| deposit.confidence > 0.0)
                .count(),
            3
        );
        assert!(deposits.iter().any(|deposit| deposit.agent_id
            == AgentId::from_verifying_key(
                &signing_key_for_label("live-evidence").verifying_key()
            )));
        assert!(deposits.iter().any(|deposit| deposit.agent_id
            == AgentId::from_verifying_key(
                &signing_key_for_label("legacy-live-evidence").verifying_key()
            )));
        assert!(deposits.iter().any(|deposit| deposit.agent_id
            == AgentId::from_verifying_key(
                &signing_key_for_label("policy-sensitive").verifying_key()
            )));
        assert!(
            connection
                .store
                .entry(&policy_sensitive_key)
                .await
                .unwrap()
                .is_some(),
            "an old GC page must not override the current retention policy"
        );
        assert!(
            connection
                .store
                .entry(&legacy_control_keys[0])
                .await
                .unwrap()
                .is_none(),
            "the oldest over-limit control subject must be destructively purged"
        );
        assert!(
            connection
                .store
                .entry("unrelated.noise")
                .await
                .unwrap()
                .is_some(),
            "filtered compaction must not purge an unrelated KV subject"
        );
        {
            let indexes = substrate.deposit_key_indexes.lock().await;
            let execution = indexes.partitions.get("execution").unwrap();
            assert!(execution.current_layout.initialized);
            assert!(execution.legacy_layout.initialized);
            assert_eq!(execution.evidence.len(), 3);
            assert_eq!(execution.controls.len(), 3);
            assert!(execution.total_bytes() <= MAX_ACTIVE_DEPOSIT_BYTES);
        }

        // With no intervening stream revision, the next monitor read is served
        // from the bounded local index and exact KV gets; no history consumer
        // is recreated and no whole-bucket enumeration occurs.
        assert_eq!(
            substrate
                .load_deposits_bounded(Some(&ThreatClass::Execution), None, Some(now + 4), 3,)
                .await
                .unwrap()
                .len(),
            6
        );

        let mismatched = sample_deposit("mismatched-control", now + 4, 0.0);
        let mismatched_payload = serde_json::to_vec(&mismatched).unwrap();
        let mismatched_key = format!(
            "exp.{:020}.execution.evidence.{:020}.mismatched",
            expiration_gc_page(&mismatched, 3_600.0, 0.01),
            mismatched.timestamp
        );
        connection
            .store
            .put(mismatched_key, mismatched_payload.into())
            .await
            .unwrap();
        assert!(matches!(
            substrate
                .load_deposits_bounded(
                    Some(&ThreatClass::Execution),
                    None,
                    Some(now + 4),
                    10,
                )
                .await,
            Err(crate::SubstrateError::InvalidDeposit { reason })
                if reason.contains("class does not match its signed payload")
        ));
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_control_eviction_cannot_resurrect_dismissed_evidence() {
        let Some((_bucket, substrate)) = connect_for_test("feedback-window").await else {
            return;
        };
        let now = now_timestamp();
        let evidence = resign_sample_deposit(
            "feedback-evidence",
            sample_deposit("feedback-evidence", now - 10, 0.9),
            serde_json::json!({"event_id": "event-dismissed"}),
        );
        let dismissal = resign_sample_deposit(
            "feedback-reviewer",
            sample_deposit("feedback-reviewer", now - 5, 0.0),
            serde_json::json!({
                "schema": SWARM_PROVIDENCE_FEEDBACK_SCHEMA,
                "event_id": "event-dismissed",
                "action": "dismiss"
            }),
        );
        let unrelated_control = resign_sample_deposit(
            "feedback-control",
            sample_deposit("feedback-control", now, 0.0),
            serde_json::json!({"event_id": "unrelated-control"}),
        );
        substrate.deposit(evidence).await.unwrap();
        substrate.deposit(dismissal).await.unwrap();
        substrate.deposit(unrelated_control).await.unwrap();

        let retained = substrate
            .load_deposits_bounded(Some(&ThreatClass::Execution), None, Some(now), 1)
            .await
            .unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].confidence, 0.0);
        assert_eq!(substrate.deposit_count().await.unwrap(), 1);
        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, now)
            .await
            .unwrap();
        assert_eq!(concentration.total_strength, 0.0);
        assert_eq!(concentration.distinct_sources, 0);
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_gc_removes_evaporated_deposits() {
        let Some((_bucket, substrate)) = connect_for_test("gc").await else {
            return;
        };
        let now = now_timestamp();
        substrate
            .deposit(sample_deposit("whisker-a", now - 1, 0.1))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-b", now, 0.9))
            .await
            .unwrap();
        wait_until(|| async { substrate.recent_deposits(10).await.unwrap().len() == 2 }).await;

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 2);

        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, now + 14_000)
            .await
            .unwrap();
        assert_eq!(concentration.distinct_sources, 1);
        assert!(concentration.total_strength > substrate_config().evaporation_threshold);

        let removed = substrate.gc_evaporated(now + 14_000).await.unwrap();
        assert_eq!(
            removed, 0,
            "the scoped concentration index eagerly purges certainly expired GC pages"
        );

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(
            deposits[0].agent_id,
            AgentId::from_verifying_key(&signing_key_for_label("whisker-b").verifying_key())
        );
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_gc_pages_expired_entries_for_large_buckets() {
        let mut config = substrate_config();
        config.backend = PheromoneBackendConfig::JetStream {
            url: nats_url(),
            connect_timeout_ms: DEFAULT_NATS_CONNECT_TIMEOUT_MS,
            gc_page_size: 1,
        };
        let bucket = unique_bucket("gc-pages");
        let substrate =
            JetStreamPheromoneSubstrate::connect_with_bucket(config, nats_url(), bucket)
                .await
                .unwrap();

        let now = now_timestamp();
        substrate
            .deposit(sample_deposit("whisker-a", now - 2, 0.1))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-b", now - 1, 0.2))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-c", now, 0.9))
            .await
            .unwrap();

        let mut removed = 0;
        for _ in 0..64 {
            let batch = substrate.gc_evaporated(now + 18_000).await.unwrap();
            assert!(batch <= 1, "one-page GC exceeded its configured page bound");
            removed += batch;
            if removed == 2 {
                break;
            }
        }
        assert_eq!(removed, 2);

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(
            deposits[0].agent_id,
            AgentId::from_verifying_key(&signing_key_for_label("whisker-c").verifying_key())
        );
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_recovers_escalations_after_reconnect() {
        let Some((bucket, substrate)) = connect_for_test("escalations").await else {
            return;
        };
        substrate
            .record_escalation(sample_escalation(SwarmMode::Alert, 100))
            .await
            .unwrap();
        substrate
            .record_escalation(sample_escalation(SwarmMode::Incident, 200))
            .await
            .unwrap();
        wait_until(|| async { substrate.query_escalations(0).await.unwrap().len() == 2 }).await;
        drop(substrate);

        let reopened = JetStreamPheromoneSubstrate::connect_with_bucket(
            substrate_config(),
            nats_url(),
            bucket,
        )
        .await
        .unwrap();
        let escalations = reopened.query_escalations(0).await.unwrap();
        assert_eq!(escalations.len(), 2);
        assert_eq!(escalations[0].mode, SwarmMode::Alert);
        assert_eq!(escalations[1].mode, SwarmMode::Incident);
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_recovers_threat_class_configs_after_reconnect() {
        let Some((bucket, substrate)) = connect_for_test("threat-class-configs").await else {
            return;
        };
        substrate
            .store_threat_class_config(sample_threat_class_config())
            .await
            .unwrap();
        wait_until(|| async { substrate.query_threat_class_configs().await.unwrap().len() == 1 })
            .await;
        drop(substrate);

        let reopened = JetStreamPheromoneSubstrate::connect_with_bucket(
            substrate_config(),
            nats_url(),
            bucket,
        )
        .await
        .unwrap();
        let configs = reopened.query_threat_class_configs().await.unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].threat_class, ThreatClass::Execution);
        assert_eq!(configs[0].half_life_secs, 180.0);
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_recovers_threat_intel_entries_after_reconnect() {
        let Some((bucket, substrate)) = connect_for_test("threat-intel").await else {
            return;
        };
        substrate
            .store_threat_intel_entry(sample_threat_intel_entry())
            .await
            .unwrap();
        wait_until(|| async {
            substrate
                .query_threat_intel_entry(
                    &ThreatIntelIndicatorType::Domain,
                    "example.com",
                    1_700_000_000_000,
                )
                .await
                .unwrap()
                .is_some()
        })
        .await;
        drop(substrate);

        let reopened = JetStreamPheromoneSubstrate::connect_with_bucket(
            substrate_config(),
            nats_url(),
            bucket,
        )
        .await
        .unwrap();
        let stored = reopened
            .query_threat_intel_entry(
                &ThreatIntelIndicatorType::Domain,
                "example.com",
                1_700_000_000_000,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.value, "example.com");
        assert_eq!(stored.confidence, 0.91);

        let expired = reopened
            .query_threat_intel_entry(
                &ThreatIntelIndicatorType::Domain,
                "example.com",
                1_700_000_000_100,
            )
            .await
            .unwrap();
        assert!(expired.is_none());
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_gc_expired_threat_intel_removes_expired_entries() {
        let Some((_bucket, substrate)) = connect_for_test("gc-threat-intel").await else {
            return;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs() as i64;

        // Store one expired and one active threat-intel entry
        substrate
            .store_threat_intel_entry(ThreatIntelEntry {
                indicator_type: ThreatIntelIndicatorType::Domain,
                value: "expired.example.com".to_string(),
                source: "operator".to_string(),
                indicator_id: None,
                confidence: 0.9,
                expires_at: now - 100,
            })
            .await
            .unwrap();
        substrate
            .store_threat_intel_entry(ThreatIntelEntry {
                indicator_type: ThreatIntelIndicatorType::IpAddress,
                value: "10.0.0.1".to_string(),
                source: "operator".to_string(),
                indicator_id: None,
                confidence: 0.8,
                expires_at: now + 100_000,
            })
            .await
            .unwrap();

        wait_until(|| {
            let sub = substrate.clone();
            async move {
                sub.query_threat_intel_entry(&ThreatIntelIndicatorType::IpAddress, "10.0.0.1", now)
                    .await
                    .unwrap()
                    .is_some()
            }
        })
        .await;

        let purged = substrate.gc_expired_threat_intel(now).await.unwrap();
        assert_eq!(purged, 1);

        // Expired entry should be gone
        let expired = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::Domain, "expired.example.com", 0)
            .await
            .unwrap();
        assert!(expired.is_none());

        // Active entry should remain
        let active = substrate
            .query_threat_intel_entry(&ThreatIntelIndicatorType::IpAddress, "10.0.0.1", now)
            .await
            .unwrap();
        assert!(active.is_some());
    }
}
