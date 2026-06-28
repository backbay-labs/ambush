#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use async_trait::async_trait;
use reqwest::Client;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use swarm_core::config::SentinelBridgeConfig;
use swarm_core::{
    BridgeHealth, ExhaustedResource, InfrastructureHealthEvent, ResourceExhaustionEvent,
    TelemetryBridge, TelemetryBridgeError, TelemetryBridgeResult, TelemetryEvent, TelemetryPayload,
    ThermalAnomalyEvent, ThermalSeverity,
};
use tokio::time::Instant;

const SOURCE_ID: &str = "sentinel";

#[derive(Debug, Clone, Default)]
struct MetricSample {
    name: String,
    labels: BTreeMap<String, String>,
    value: f64,
}

#[derive(Debug, Clone, Default)]
struct ScrapedMetrics {
    samples: Vec<MetricSample>,
    node_name: Option<String>,
    scrape_timestamp: i64,
}

impl ScrapedMetrics {
    fn get(&self, name: &str) -> f64 {
        self.samples
            .iter()
            .find(|sample| sample.name == name)
            .map(|sample| sample.value)
            .unwrap_or_default()
    }

    fn get_labeled(&self, name: &str, labels: &[(&str, &str)]) -> f64 {
        self.samples
            .iter()
            .find(|sample| {
                sample.name == name
                    && labels.iter().all(|(key, value)| {
                        sample.labels.get(*key).map(String::as_str) == Some(*value)
                    })
            })
            .map(|sample| sample.value)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default)]
struct SentinelSnapshot {
    network_rx_bytes_total: f64,
    network_tx_bytes_total: f64,
    network_rx_errors_total: f64,
    network_tx_errors_total: f64,
    memory_oom_kill_total: f64,
    cpu_temperature_celsius: f64,
    memory_usage_percent: f64,
    disk_usage_percent: f64,
}

pub struct SentinelBridge {
    config: SentinelBridgeConfig,
    client: Client,
    health: BridgeHealth,
    consecutive_failures: u32,
    previous: Option<SentinelSnapshot>,
    last_scrape_at: Option<Instant>,
}

impl SentinelBridge {
    pub fn new(config: SentinelBridgeConfig) -> Self {
        Self {
            config,
            client: Client::new(),
            health: BridgeHealth::new(SOURCE_ID),
            consecutive_failures: 0,
            previous: None,
            last_scrape_at: None,
        }
    }

    async fn wait_for_interval(&mut self) {
        let interval = Duration::from_millis(self.config.scrape_interval_ms);
        if let Some(last_scrape_at) = self.last_scrape_at {
            let elapsed = last_scrape_at.elapsed();
            if elapsed < interval {
                tokio::time::sleep(interval - elapsed).await;
            }
        }
        self.last_scrape_at = Some(Instant::now());
    }
}

#[async_trait]
impl TelemetryBridge for SentinelBridge {
    fn source_id(&self) -> &str {
        SOURCE_ID
    }

    async fn poll(&mut self) -> TelemetryBridgeResult<Vec<TelemetryEvent>> {
        self.wait_for_interval().await;

        let scraped = match scrape_metrics(&self.client, &self.config).await {
            Ok(scraped) => {
                self.consecutive_failures = 0;
                scraped
            }
            Err(error) => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                self.health.record_error(error.clone());
                return Err(
                    if self.consecutive_failures >= self.config.max_consecutive_failures {
                        TelemetryBridgeError::Unavailable(error)
                    } else {
                        TelemetryBridgeError::Connection(error)
                    },
                );
            }
        };

        let events = map_scraped_metrics(&scraped, self.previous.as_ref(), &self.config);
        self.previous = Some(snapshot_from_scraped(&scraped));

        for event in &events {
            if !self.validate_schema(event) {
                let message = format!(
                    "bridge `{SOURCE_ID}` produced invalid event `{}`",
                    event.event_id
                );
                self.health.record_error(message.clone());
                return Err(TelemetryBridgeError::Schema(message));
            }
            self.health.record_event(event.timestamp);
        }

        Ok(events)
    }

    fn validate_schema(&self, event: &TelemetryEvent) -> bool {
        if event.source != SOURCE_ID || event.event_id.trim().is_empty() || event.timestamp <= 0 {
            return false;
        }

        match &event.payload {
            TelemetryPayload::InfrastructureHealth(health) => {
                !health.node_name.trim().is_empty()
                    && valid_percent(health.cpu_usage_percent)
                    && valid_percent(health.memory_usage_percent)
                    && valid_percent(health.disk_usage_percent)
                    && valid_probability(health.failure_probability)
                    && valid_probability(health.prediction_confidence)
                    && health.cpu_frequency_mhz >= 0.0
                    && health.disk_io_latency_ms >= 0.0
                    && health.time_to_failure_secs >= -1.0
                    && health.collection_duration_ms >= 0.0
            }
            TelemetryPayload::ThermalAnomaly(thermal) => {
                !thermal.node_name.trim().is_empty()
                    && thermal.temperature_celsius > 0.0
                    && thermal.estimated_time_to_critical_secs >= -1.0
            }
            TelemetryPayload::ResourceExhaustion(exhaustion) => {
                !exhaustion.node_name.trim().is_empty()
                    && valid_percent(exhaustion.utilization_percent)
                    && exhaustion.capacity_value > 0
            }
            TelemetryPayload::ProcessStart(_)
            | TelemetryPayload::ProcessMemoryAccess(_)
            | TelemetryPayload::NetworkConnect(_)
            | TelemetryPayload::DnsQuery(_)
            | TelemetryPayload::RegistryAccess(_)
            | TelemetryPayload::RegistryPersistence(_)
            | TelemetryPayload::FilePersistence(_)
            | TelemetryPayload::AuthenticationEvent(_) => false,
        }
    }

    fn health(&self) -> BridgeHealth {
        self.health.clone()
    }
}

fn valid_percent(value: f64) -> bool {
    (0.0..=100.0).contains(&value)
}

fn valid_probability(value: f64) -> bool {
    (0.0..=1.0).contains(&value)
}

fn snapshot_from_scraped(scraped: &ScrapedMetrics) -> SentinelSnapshot {
    SentinelSnapshot {
        network_rx_bytes_total: scraped.get("sentinel_network_rx_bytes_total"),
        network_tx_bytes_total: scraped.get("sentinel_network_tx_bytes_total"),
        network_rx_errors_total: scraped.get("sentinel_network_rx_errors_total"),
        network_tx_errors_total: scraped.get("sentinel_network_tx_errors_total"),
        memory_oom_kill_total: scraped.get("sentinel_memory_oom_kill_total"),
        cpu_temperature_celsius: scraped.get("sentinel_cpu_temperature_celsius"),
        memory_usage_percent: scraped.get("sentinel_memory_usage_percent"),
        disk_usage_percent: scraped.get("sentinel_disk_usage_percent"),
    }
}

async fn scrape_metrics(
    client: &Client,
    config: &SentinelBridgeConfig,
) -> Result<ScrapedMetrics, String> {
    let response = client
        .get(&config.endpoint)
        .timeout(Duration::from_millis(config.scrape_timeout_ms))
        .send()
        .await
        .map_err(|error| format!("HTTP scrape failed: {error}"))?;
    let body = response
        .text()
        .await
        .map_err(|error| format!("failed to read scrape body: {error}"))?;
    parse_prometheus_text(&body)
}

fn parse_prometheus_text(body: &str) -> Result<ScrapedMetrics, String> {
    let mut samples = Vec::new();
    let mut node_name = None;

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let metric = parts
            .next()
            .ok_or_else(|| format!("invalid Prometheus sample `{trimmed}`"))?;
        let value = parts
            .next()
            .ok_or_else(|| format!("missing sample value in `{trimmed}`"))?
            .parse::<f64>()
            .map_err(|error| format!("invalid sample value in `{trimmed}`: {error}"))?;
        let (name, labels) = parse_metric_token(metric)?;
        if node_name.is_none() {
            node_name = labels
                .get("node")
                .cloned()
                .or_else(|| labels.get("instance").cloned());
        }
        samples.push(MetricSample {
            name,
            labels,
            value,
        });
    }

    if samples.is_empty() {
        return Err("failed to parse Prometheus metrics: no samples found".to_string());
    }

    Ok(ScrapedMetrics {
        samples,
        node_name,
        scrape_timestamp: current_unix_seconds(),
    })
}

fn parse_metric_token(token: &str) -> Result<(String, BTreeMap<String, String>), String> {
    let Some(brace_index) = token.find('{') else {
        return Ok((token.to_string(), BTreeMap::new()));
    };
    let Some(raw_labels) = token
        .strip_suffix('}')
        .and_then(|value| value.get(brace_index + 1..))
    else {
        return Err(format!("invalid label set `{token}`"));
    };
    let name = token[..brace_index].to_string();
    let mut labels = BTreeMap::new();
    if raw_labels.trim().is_empty() {
        return Ok((name, labels));
    }

    for entry in raw_labels.split(',') {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| format!("invalid label `{entry}` in `{token}`"))?;
        let value = value.trim();
        if !value.starts_with('"') || !value.ends_with('"') {
            return Err(format!("invalid quoted label value `{entry}` in `{token}`"));
        }
        labels.insert(key.trim().to_string(), value.trim_matches('"').to_string());
    }
    Ok((name, labels))
}

fn map_scraped_metrics(
    scraped: &ScrapedMetrics,
    previous: Option<&SentinelSnapshot>,
    config: &SentinelBridgeConfig,
) -> Vec<TelemetryEvent> {
    let node_name = scraped
        .node_name
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    let timestamp = scraped.scrape_timestamp;
    let mut events = vec![build_infrastructure_health(
        scraped, &node_name, timestamp, previous,
    )];

    let temperature = scraped.get("sentinel_cpu_temperature_celsius");
    let throttled = scraped.get("sentinel_cpu_throttled") > 0.5;
    if temperature >= config.thermal_anomaly_threshold_celsius || throttled {
        events.push(build_thermal_anomaly(
            scraped,
            &node_name,
            timestamp,
            temperature,
            throttled,
            previous,
        ));
    }

    let memory_usage = scraped.get("sentinel_memory_usage_percent");
    if memory_usage >= config.memory_exhaustion_threshold_percent {
        events.push(build_resource_exhaustion_memory(
            scraped,
            &node_name,
            timestamp,
            memory_usage,
            previous,
            config,
        ));
    }

    let disk_usage = scraped.get("sentinel_disk_usage_percent");
    if disk_usage >= config.disk_exhaustion_threshold_percent {
        events.push(build_resource_exhaustion_disk(
            scraped, &node_name, timestamp, disk_usage, previous, config,
        ));
    }

    events
}

fn build_infrastructure_health(
    scraped: &ScrapedMetrics,
    node_name: &str,
    timestamp: i64,
    previous: Option<&SentinelSnapshot>,
) -> TelemetryEvent {
    TelemetryEvent {
        source: SOURCE_ID.to_string(),
        event_id: format!("sentinel:{node_name}:health:{timestamp}"),
        timestamp,
        host_id: Some(node_name.to_string()),
        payload: TelemetryPayload::InfrastructureHealth(InfrastructureHealthEvent {
            node_name: node_name.to_string(),
            cpu_usage_percent: scraped.get("sentinel_cpu_usage_percent").clamp(0.0, 100.0),
            cpu_frequency_mhz: scraped.get("sentinel_cpu_frequency_mhz").max(0.0),
            load_average_1m: scraped
                .get_labeled("sentinel_cpu_load_average", &[("period", "1m")])
                .max(0.0),
            load_average_5m: scraped
                .get_labeled("sentinel_cpu_load_average", &[("period", "5m")])
                .max(0.0),
            load_average_15m: scraped
                .get_labeled("sentinel_cpu_load_average", &[("period", "15m")])
                .max(0.0),
            memory_usage_percent: scraped
                .get("sentinel_memory_usage_percent")
                .clamp(0.0, 100.0),
            memory_available_bytes: as_u64(scraped.get("sentinel_memory_available_bytes")),
            disk_usage_percent: scraped.get("sentinel_disk_usage_percent").clamp(0.0, 100.0),
            disk_io_latency_ms: scraped.get("sentinel_disk_io_latency_ms").max(0.0),
            network_rx_bytes: delta_u64(
                scraped.get("sentinel_network_rx_bytes_total"),
                previous.map(|snapshot| snapshot.network_rx_bytes_total),
            ),
            network_tx_bytes: delta_u64(
                scraped.get("sentinel_network_tx_bytes_total"),
                previous.map(|snapshot| snapshot.network_tx_bytes_total),
            ),
            network_rx_errors: delta_u64(
                scraped.get("sentinel_network_rx_errors_total"),
                previous.map(|snapshot| snapshot.network_rx_errors_total),
            ),
            network_tx_errors: delta_u64(
                scraped.get("sentinel_network_tx_errors_total"),
                previous.map(|snapshot| snapshot.network_tx_errors_total),
            ),
            failure_probability: scraped
                .get("sentinel_prediction_failure_probability")
                .clamp(0.0, 1.0),
            prediction_confidence: scraped
                .get("sentinel_prediction_confidence")
                .clamp(0.0, 1.0),
            time_to_failure_secs: scraped
                .get("sentinel_prediction_time_to_failure_seconds")
                .max(-1.0),
            collection_duration_ms: scraped.get("sentinel_collection_duration_ms").max(0.0),
        }),
    }
}

fn build_thermal_anomaly(
    scraped: &ScrapedMetrics,
    node_name: &str,
    timestamp: i64,
    temperature_celsius: f64,
    cpu_throttled: bool,
    previous: Option<&SentinelSnapshot>,
) -> TelemetryEvent {
    let trend_slope = previous
        .map(|snapshot| temperature_celsius - snapshot.cpu_temperature_celsius)
        .unwrap_or_default();
    let severity = if temperature_celsius >= 85.0 || cpu_throttled {
        ThermalSeverity::Critical
    } else if temperature_celsius >= 75.0 {
        ThermalSeverity::High
    } else if temperature_celsius >= 60.0 {
        ThermalSeverity::Elevated
    } else {
        ThermalSeverity::Normal
    };

    TelemetryEvent {
        source: SOURCE_ID.to_string(),
        event_id: format!("sentinel:{node_name}:thermal:{timestamp}"),
        timestamp,
        host_id: Some(node_name.to_string()),
        payload: TelemetryPayload::ThermalAnomaly(ThermalAnomalyEvent {
            node_name: node_name.to_string(),
            temperature_celsius,
            cpu_throttled,
            trend_slope,
            severity,
            estimated_time_to_critical_secs: scraped
                .get("sentinel_prediction_time_to_failure_seconds")
                .max(-1.0),
        }),
    }
}

fn build_resource_exhaustion_memory(
    scraped: &ScrapedMetrics,
    node_name: &str,
    timestamp: i64,
    utilization_percent: f64,
    previous: Option<&SentinelSnapshot>,
    config: &SentinelBridgeConfig,
) -> TelemetryEvent {
    let capacity_value = as_u64(scraped.get("sentinel_memory_total_bytes")).max(1);
    let available = as_u64(scraped.get("sentinel_memory_available_bytes"));
    let mut current_value = capacity_value.saturating_sub(available);
    if current_value == 0 {
        current_value = percent_of_capacity(capacity_value, utilization_percent);
    }

    TelemetryEvent {
        source: SOURCE_ID.to_string(),
        event_id: format!("sentinel:{node_name}:exhaustion:memory:{timestamp}"),
        timestamp,
        host_id: Some(node_name.to_string()),
        payload: TelemetryPayload::ResourceExhaustion(ResourceExhaustionEvent {
            node_name: node_name.to_string(),
            resource_kind: ExhaustedResource::Memory,
            utilization_percent: utilization_percent.clamp(0.0, 100.0),
            current_value,
            capacity_value,
            oom_kill_count: Some(delta_u64(
                scraped.get("sentinel_memory_oom_kill_total"),
                previous.map(|snapshot| snapshot.memory_oom_kill_total),
            )),
            swap_used_bytes: Some(as_u64(scraped.get("sentinel_memory_swap_used_bytes"))),
            is_new: previous
                .map(|snapshot| {
                    snapshot.memory_usage_percent < config.memory_exhaustion_threshold_percent
                })
                .unwrap_or(true),
        }),
    }
}

fn build_resource_exhaustion_disk(
    scraped: &ScrapedMetrics,
    node_name: &str,
    timestamp: i64,
    utilization_percent: f64,
    previous: Option<&SentinelSnapshot>,
    config: &SentinelBridgeConfig,
) -> TelemetryEvent {
    let capacity_value = as_u64(scraped.get("sentinel_disk_total_bytes")).max(1);
    let mut current_value = as_u64(scraped.get("sentinel_disk_used_bytes"));
    if current_value == 0 {
        current_value = percent_of_capacity(capacity_value, utilization_percent);
    }

    TelemetryEvent {
        source: SOURCE_ID.to_string(),
        event_id: format!("sentinel:{node_name}:exhaustion:disk:{timestamp}"),
        timestamp,
        host_id: Some(node_name.to_string()),
        payload: TelemetryPayload::ResourceExhaustion(ResourceExhaustionEvent {
            node_name: node_name.to_string(),
            resource_kind: ExhaustedResource::Disk,
            utilization_percent: utilization_percent.clamp(0.0, 100.0),
            current_value,
            capacity_value,
            oom_kill_count: None,
            swap_used_bytes: None,
            is_new: previous
                .map(|snapshot| {
                    snapshot.disk_usage_percent < config.disk_exhaustion_threshold_percent
                })
                .unwrap_or(true),
        }),
    }
}

fn as_u64(value: f64) -> u64 {
    value.max(0.0).round() as u64
}

fn percent_of_capacity(capacity: u64, percent: f64) -> u64 {
    ((capacity as f64) * percent.clamp(0.0, 100.0) / 100.0).round() as u64
}

fn delta_u64(current: f64, previous: Option<f64>) -> u64 {
    previous
        .map(|previous| current - previous)
        .unwrap_or_default()
        .max(0.0)
        .round() as u64
}

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::{
        SOURCE_ID, SentinelBridge, SentinelBridgeConfig, SentinelSnapshot, TelemetryBridge,
        TelemetryPayload, map_scraped_metrics, parse_prometheus_text,
    };
    use axum::{Router, routing::get};
    use tokio::net::TcpListener;

    fn sentinel_metrics_body(
        temperature_celsius: f64,
        memory_usage_percent: f64,
        disk_usage_percent: f64,
        network_rx_bytes_total: u64,
    ) -> String {
        format!(
            r#"
sentinel_cpu_usage_percent{{node="node-a"}} 96
sentinel_cpu_temperature_celsius{{node="node-a"}} {temperature_celsius}
sentinel_cpu_throttled{{node="node-a"}} 1
sentinel_cpu_frequency_mhz{{node="node-a"}} 3200
sentinel_cpu_load_average{{node="node-a",period="1m"}} 12
sentinel_cpu_load_average{{node="node-a",period="5m"}} 8
sentinel_cpu_load_average{{node="node-a",period="15m"}} 4
sentinel_memory_total_bytes{{node="node-a"}} 1000
sentinel_memory_available_bytes{{node="node-a"}} 100
sentinel_memory_usage_percent{{node="node-a"}} {memory_usage_percent}
sentinel_memory_oom_kill_total{{node="node-a"}} 3
sentinel_memory_swap_used_bytes{{node="node-a"}} 128
sentinel_disk_total_bytes{{node="node-a"}} 2000
sentinel_disk_used_bytes{{node="node-a"}} 1900
sentinel_disk_usage_percent{{node="node-a"}} {disk_usage_percent}
sentinel_disk_io_latency_ms{{node="node-a"}} 7
sentinel_network_rx_bytes_total{{node="node-a"}} {network_rx_bytes_total}
sentinel_network_tx_bytes_total{{node="node-a"}} 2000
sentinel_network_rx_errors_total{{node="node-a"}} 2
sentinel_network_tx_errors_total{{node="node-a"}} 1
sentinel_prediction_failure_probability{{node="node-a"}} 0.8
sentinel_prediction_confidence{{node="node-a"}} 0.9
sentinel_prediction_time_to_failure_seconds{{node="node-a"}} 45
sentinel_collection_duration_ms{{node="node-a"}} 11
"#
        )
    }

    async fn spawn_metrics_server(body: String) -> String {
        let app = Router::new().route(
            "/metrics",
            get({
                let body = body.clone();
                move || {
                    let body = body.clone();
                    async move { body }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/metrics")
    }

    #[tokio::test]
    async fn bridge_polls_metrics_and_emits_infrastructure_events() {
        let endpoint = spawn_metrics_server(sentinel_metrics_body(82.0, 91.0, 95.0, 1000)).await;
        let mut bridge = SentinelBridge::new(SentinelBridgeConfig {
            endpoint,
            scrape_interval_ms: 1,
            scrape_timeout_ms: 1_000,
            thermal_anomaly_threshold_celsius: 60.0,
            memory_exhaustion_threshold_percent: 85.0,
            disk_exhaustion_threshold_percent: 90.0,
            max_consecutive_failures: 3,
        });

        let events = bridge.poll().await.unwrap();
        assert_eq!(events.len(), 4);
        assert!(events.iter().all(|event| event.source == SOURCE_ID));
        assert!(
            events
                .iter()
                .any(|event| matches!(event.payload, TelemetryPayload::InfrastructureHealth(_)))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.payload, TelemetryPayload::ThermalAnomaly(_)))
        );
        assert_eq!(bridge.health().events_processed, 4);
    }

    #[test]
    fn mapper_computes_counter_deltas_and_resource_newness() {
        let scraped =
            parse_prometheus_text(&sentinel_metrics_body(78.0, 91.0, 95.0, 1500)).unwrap();
        let previous = SentinelSnapshot {
            network_rx_bytes_total: 1000.0,
            network_tx_bytes_total: 1500.0,
            network_rx_errors_total: 1.0,
            network_tx_errors_total: 1.0,
            memory_oom_kill_total: 2.0,
            cpu_temperature_celsius: 70.0,
            memory_usage_percent: 90.0,
            disk_usage_percent: 92.0,
        };
        let config = SentinelBridgeConfig {
            endpoint: "http://127.0.0.1:9100/metrics".to_string(),
            scrape_interval_ms: 5_000,
            scrape_timeout_ms: 3_000,
            thermal_anomaly_threshold_celsius: 60.0,
            memory_exhaustion_threshold_percent: 85.0,
            disk_exhaustion_threshold_percent: 90.0,
            max_consecutive_failures: 5,
        };

        let events = map_scraped_metrics(&scraped, Some(&previous), &config);
        let health = events
            .iter()
            .find_map(|event| match &event.payload {
                TelemetryPayload::InfrastructureHealth(health) => Some(health),
                _ => None,
            })
            .unwrap();
        assert_eq!(health.network_rx_bytes, 500);

        let memory = events
            .iter()
            .find_map(|event| match &event.payload {
                TelemetryPayload::ResourceExhaustion(exhaustion)
                    if matches!(
                        exhaustion.resource_kind,
                        swarm_core::ExhaustedResource::Memory
                    ) =>
                {
                    Some(exhaustion)
                }
                _ => None,
            })
            .unwrap();
        assert!(!memory.is_new);
        assert_eq!(memory.oom_kill_count, Some(1));
    }

    #[test]
    fn validation_rejects_non_sentinel_payload_kinds() {
        let bridge = SentinelBridge::new(SentinelBridgeConfig {
            endpoint: "http://127.0.0.1:9100/metrics".to_string(),
            scrape_interval_ms: 5_000,
            scrape_timeout_ms: 3_000,
            thermal_anomaly_threshold_celsius: 60.0,
            memory_exhaustion_threshold_percent: 85.0,
            disk_exhaustion_threshold_percent: 90.0,
            max_consecutive_failures: 5,
        });
        let event = swarm_core::TelemetryEvent {
            source: SOURCE_ID.to_string(),
            event_id: "evt-1".to_string(),
            timestamp: 1,
            host_id: Some("node-a".to_string()),
            payload: swarm_core::TelemetryPayload::ProcessStart(swarm_core::ProcessStartEvent {
                parent_process: "init".to_string(),
                process_name: "miner".to_string(),
                command_line: "miner".to_string(),
                user: None,
                executable_path: None,
                signer: None,
                signature_valid: None,
            }),
        };

        assert!(!bridge.validate_schema(&event));
    }
}
