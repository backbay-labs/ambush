use crate::substrate::{
    AdmissionControl, DepositQuery, PheromoneSubstrate, SubstrateError, SubstrateHealth,
    concentration_for, decode_deposit_payload, filter_deposits, filter_escalations,
    normalize_threat_intel_value, validate_deposit_signature,
};
use async_trait::async_trait;
#[cfg(feature = "nats")]
use sha2::{Digest, Sha256};
#[cfg(feature = "nats")]
use std::collections::BTreeMap;
use std::fmt;
#[cfg(feature = "nats")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "nats")]
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig};
use swarm_core::pheromone::{
    BehavioralBaselineSnapshot, EscalationRecord, PheromoneConcentration, PheromoneDeposit,
    ThreatClass, ThreatClassConfig, ThreatIntelEntry, ThreatIntelIndicatorType,
};
use swarm_core::types::AgentId;
#[cfg(feature = "nats")]
use tokio::sync::OnceCell;
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
}

#[cfg(feature = "nats")]
struct JetStreamConnection {
    client: async_nats::Client,
    store: async_nats::jetstream::kv::Store,
}

impl fmt::Debug for JetStreamPheromoneSubstrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JetStreamPheromoneSubstrate")
            .field("url", &self.url)
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
        let url = self.url.clone();
        let bucket = self.bucket.clone();
        let connect_timeout_ms = self.connect_timeout_ms;

        self.connection
            .get_or_try_init(|| async move {
                let client = timeout(
                    std::time::Duration::from_millis(connect_timeout_ms),
                    async_nats::connect(url.as_str()),
                )
                .await
                .map_err(|_| SubstrateError::Nats {
                    operation: "connect",
                    reason: format!(
                        "timed out after {connect_timeout_ms}ms while connecting to {url}"
                    ),
                })?
                .map_err(|error| nats_error("connect", error))?;
                let jetstream = async_nats::jetstream::new(client.clone());
                let store = ensure_kv_bucket(&jetstream, &bucket).await?;
                Ok(JetStreamConnection { client, store })
            })
            .await
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
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        let connection = self.ensure_connected().await?;
        let mut keys = connection
            .store
            .keys()
            .await
            .map_err(|error| nats_error("list keys", error))?;
        let mut deposits = Vec::new();

        while let Some(entry) = keys.next().await {
            let key = entry.map_err(|error| nats_error("stream keys", error))?;
            if is_escalation_key(&key)
                || is_policy_key(&key)
                || is_threat_intel_key(&key)
                || is_behavioral_baseline_key(&key)
            {
                continue;
            }
            if let Some(threat_class) = threat_class
                && !key_matches_threat_class(&key, threat_class)
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

            deposits.push(deposit);
        }

        Ok(deposits)
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
    ) -> Result<Option<BehavioralBaselineSnapshot>, SubstrateError> {
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
        let snapshot = serde_json::from_slice::<BehavioralBaselineSnapshot>(&payload)
            .map_err(|source| SubstrateError::Decode { location, source })?;
        Ok(Some(snapshot))
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
            if deposit.is_evaporated(now, self.config.evaporation_threshold) {
                connection
                    .store
                    .delete(&key)
                    .await
                    .map_err(|error| nats_error("delete value", error))?;
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
            if !deposit.is_evaporated(now, policy.evaporation_threshold) {
                continue;
            }

            connection
                .store
                .delete(&key)
                .await
                .map_err(|error| nats_error("delete value", error))?;
            removed = removed.saturating_add(1);
        }

        Ok(removed)
    }
}

#[cfg(feature = "nats")]
#[async_trait]
impl PheromoneSubstrate for JetStreamPheromoneSubstrate {
    async fn deposit(&self, deposit: PheromoneDeposit) -> Result<(), SubstrateError> {
        validate_deposit_signature(&deposit)?;
        self.admission_control
            .validate_deposit_admission(&deposit)?;
        let connection = self.ensure_connected().await?;
        let payload = serde_json::to_vec(&deposit).map_err(|source| SubstrateError::Encode {
            context: "jetstream pheromone deposit".to_string(),
            source,
        })?;
        let gc_page = expiration_gc_page(&deposit, self.config.evaporation_threshold);
        let key = deposit_key(&deposit, &payload, self.config.evaporation_threshold);

        connection
            .store
            .put(key, payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
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
    ) -> Result<(), SubstrateError> {
        let connection = self.ensure_connected().await?;
        let payload = serde_json::to_vec(&snapshot).map_err(|source| SubstrateError::Encode {
            context: "jetstream behavioral baseline snapshot".to_string(),
            source,
        })?;
        let key = behavioral_baseline_key(&snapshot.strategy_id);
        connection
            .store
            .put(key, payload.into())
            .await
            .map_err(|error| nats_error("put value", error))?;
        Ok(())
    }

    async fn query_concentration(
        &self,
        threat_class: &ThreatClass,
        now: i64,
    ) -> Result<PheromoneConcentration, SubstrateError> {
        let deposits = self.load_deposits(Some(threat_class), None).await?;
        let threat_class_config = self.load_threat_class_config(threat_class).await?;
        let policy = self
            .config
            .resolve_threat_class_policy(threat_class_config.as_ref());
        Ok(concentration_for(&deposits, threat_class, now, &policy))
    }

    async fn query_deposits(
        &self,
        query: DepositQuery,
    ) -> Result<Vec<PheromoneDeposit>, SubstrateError> {
        let deposits = self
            .load_deposits(query.threat_class.as_ref(), query.since_timestamp)
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
    ) -> Result<Option<BehavioralBaselineSnapshot>, SubstrateError> {
        self.load_behavioral_baseline_snapshot(strategy_id).await
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
fn deposit_key(deposit: &PheromoneDeposit, payload: &[u8], evaporation_threshold: f64) -> String {
    let gc_page = expiration_gc_page(deposit, evaporation_threshold);
    let threat_class = threat_class_segment(&deposit.threat_class);
    let agent_hash = hash_prefix(deposit.agent_id.0.as_bytes(), 12);
    let deposit_hash = hash_prefix(payload, 12);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{GC_KEY_PREFIX}.{gc_page:020}.{threat_class}.{:020}.{}-{deposit_hash}-{nonce}",
        deposit.timestamp.max(0),
        agent_hash
    )
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
fn key_matches_threat_class(key: &str, threat_class: &ThreatClass) -> bool {
    let expected = threat_class_segment(threat_class);
    if let Some(stripped) = key.strip_prefix(&format!("{GC_KEY_PREFIX}.")) {
        let mut parts = stripped.split('.');
        let _page = parts.next();
        return parts.next().is_some_and(|segment| segment == expected);
    }

    key.starts_with(expected.as_str())
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
fn threat_intel_indicator_segment(indicator_type: &ThreatIntelIndicatorType) -> &'static str {
    match indicator_type {
        ThreatIntelIndicatorType::IpAddress => "ip_address",
        ThreatIntelIndicatorType::Domain => "domain",
        ThreatIntelIndicatorType::FileHash => "file_hash",
    }
}

#[cfg(feature = "nats")]
fn expiration_gc_page(deposit: &PheromoneDeposit, evaporation_threshold: f64) -> i64 {
    let deadline = evaporation_deadline(deposit, evaporation_threshold);
    div_ceil_i64(deadline.max(0), GC_PAGE_SPAN_SECS)
}

#[cfg(feature = "nats")]
fn evaporation_deadline(deposit: &PheromoneDeposit, evaporation_threshold: f64) -> i64 {
    if deposit.confidence <= evaporation_threshold || deposit.decay_half_life <= 0.0 {
        return deposit.timestamp;
    }

    let elapsed_until_evaporation =
        deposit.decay_half_life * (deposit.confidence / evaporation_threshold).log2();
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
        DEFAULT_JETSTREAM_GC_PAGE_SIZE, DEFAULT_NATS_CONNECT_TIMEOUT_MS,
        JetStreamPheromoneSubstrate,
    };
    use crate::PheromoneSubstrate;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use swarm_core::agent::SwarmMode;
    use swarm_core::config::{PheromoneBackendConfig, PheromoneConfig, ResponsePlaybookConfig};
    use swarm_core::pheromone::{
        EscalationRecord, PheromoneDeposit, ThreatClass, ThreatClassConfig, ThreatIntelEntry,
        ThreatIntelIndicatorType,
    };
    use swarm_core::types::{AgentId, Severity};

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

    fn sample_deposit(agent_id: &str, timestamp: i64, confidence: f64) -> PheromoneDeposit {
        PheromoneDeposit {
            schema_version: PheromoneDeposit::current_schema_version(),
            indicator: serde_json::json!({"signal": "jetstream-test"}),
            threat_class: ThreatClass::Execution,
            severity: Severity::High,
            confidence,
            timestamp,
            decay_half_life: 3600.0,
            agent_id: AgentId(agent_id.to_string()),
            agent_identity: String::new(),
            agent_role: None,
            signature: Vec::new(),
            agent_key: Vec::new(),
        }
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
            confidence: 0.91,
            expires_at: 1_700_000_000_100,
        }
    }

    fn nats_url() -> String {
        std::env::var("NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".to_string())
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
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_recovers_deposits_after_reconnect() {
        let Some((bucket, substrate)) = connect_for_test("restart").await else {
            return;
        };
        substrate
            .deposit(sample_deposit("whisker-a", 100, 0.9))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-b", 200, 0.8))
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
        assert_eq!(deposits[0].timestamp, 200);
        assert_eq!(deposits[1].timestamp, 100);

        let health = reopened.health().await.unwrap();
        assert!(health.ready);
        assert!(health.durable);
    }

    #[tokio::test]
    #[ignore = "requires a JetStream-enabled NATS server at NATS_URL or nats://127.0.0.1:4222"]
    async fn jetstream_gc_removes_evaporated_deposits() {
        let Some((_bucket, substrate)) = connect_for_test("gc").await else {
            return;
        };
        substrate
            .deposit(sample_deposit("whisker-a", 0, 0.1))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-b", 100_000, 0.9))
            .await
            .unwrap();
        wait_until(|| async { substrate.recent_deposits(10).await.unwrap().len() == 2 }).await;

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 2);

        let concentration = substrate
            .query_concentration(&ThreatClass::Execution, 100_000)
            .await
            .unwrap();
        assert_eq!(concentration.distinct_sources, 1);
        assert!(concentration.total_strength >= 0.9);

        let removed = substrate.gc_evaporated(100_000).await.unwrap();
        assert_eq!(removed, 1);

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].agent_id.0, "whisker-b");
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

        substrate
            .deposit(sample_deposit("whisker-a", 0, 0.1))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-b", 20_000, 0.2))
            .await
            .unwrap();
        substrate
            .deposit(sample_deposit("whisker-c", 100_000, 0.9))
            .await
            .unwrap();

        assert_eq!(substrate.gc_evaporated(100_000).await.unwrap(), 1);
        assert_eq!(substrate.gc_evaporated(100_000).await.unwrap(), 1);
        assert_eq!(substrate.gc_evaporated(100_000).await.unwrap(), 0);

        let deposits = substrate.recent_deposits(10).await.unwrap();
        assert_eq!(deposits.len(), 1);
        assert_eq!(deposits[0].agent_id.0, "whisker-c");
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
                confidence: 0.9,
                expires_at: now - 100,
            })
            .await
            .unwrap();
        substrate
            .store_threat_intel_entry(ThreatIntelEntry {
                indicator_type: ThreatIntelIndicatorType::IpAddress,
                value: "10.0.0.1".to_string(),
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
