use prometheus_client::encoding::{EncodeLabelSet, text::encode};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

const LATENCY_BUCKETS_US: [f64; 6] = [100.0, 500.0, 1_000.0, 5_000.0, 10_000.0, 50_000.0];
const INGEST_REQUEST_BUCKETS_US: [f64; 8] = [
    1_000.0, 5_000.0, 10_000.0, 25_000.0, 50_000.0, 100_000.0, 250_000.0, 500_000.0,
];

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct VerdictLabels {
    verdict: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct IngestOutcomeLabels {
    status: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct GuardRejectionLabels {
    guard_name: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct AdapterOutcomeLabels {
    outcome: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct FindingLabels {
    threat_class: String,
    detector: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct AgentRoleLabels {
    role: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BridgeLabels {
    bridge: String,
    source_id: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct EvasionCoverageLabels {
    detector: String,
    threat_class: String,
    suite: String,
}

#[derive(Clone)]
pub struct CriticalPathMetrics {
    registry: Arc<Mutex<Registry>>,
    ingest_request_latency_us: Histogram,
    ingest_events_total: Family<IngestOutcomeLabels, Counter>,
    detect_latency_us: Histogram,
    policy_latency_us: Histogram,
    response_latency_us: Histogram,
    heap_bytes: Gauge<u64, AtomicU64>,
    heap_pressure_ratio: Gauge<f64, AtomicU64>,
    verdict_total: Family<VerdictLabels, Counter>,
    guard_rejections_total: Family<GuardRejectionLabels, Counter>,
    adapter_outcomes_total: Family<AdapterOutcomeLabels, Counter>,
    findings_total: Family<FindingLabels, Counter>,
    agent_ticks_total: Family<AgentRoleLabels, Counter>,
    agent_role_shifts_total: Family<AgentRoleLabels, Counter>,
    agent_health_transitions_total: Family<AgentRoleLabels, Counter>,
    bridge_events_processed: Family<BridgeLabels, Gauge<u64, AtomicU64>>,
    bridge_error_count: Family<BridgeLabels, Gauge<u64, AtomicU64>>,
    bridge_lag_seconds: Family<BridgeLabels, Gauge<f64, AtomicU64>>,
    bridge_ready: Family<BridgeLabels, Gauge>,
    evasion_catch_rate: Family<EvasionCoverageLabels, Gauge<f64, AtomicU64>>,
    evasion_total_payloads: Family<EvasionCoverageLabels, Gauge<u64, AtomicU64>>,
    evasion_detected_payloads: Family<EvasionCoverageLabels, Gauge<u64, AtomicU64>>,
}

impl CriticalPathMetrics {
    pub fn new() -> Self {
        let ingest_request_latency_us = Histogram::new(INGEST_REQUEST_BUCKETS_US);
        let ingest_events_total = Family::<IngestOutcomeLabels, Counter>::default();
        let detect_latency_us = Histogram::new(LATENCY_BUCKETS_US);
        let policy_latency_us = Histogram::new(LATENCY_BUCKETS_US);
        let response_latency_us = Histogram::new(LATENCY_BUCKETS_US);
        let heap_bytes = Gauge::<u64, AtomicU64>::default();
        let heap_pressure_ratio = Gauge::<f64, AtomicU64>::default();
        let verdict_total = Family::<VerdictLabels, Counter>::default();
        let guard_rejections_total = Family::<GuardRejectionLabels, Counter>::default();
        let adapter_outcomes_total = Family::<AdapterOutcomeLabels, Counter>::default();
        let findings_total = Family::<FindingLabels, Counter>::default();
        let agent_ticks_total = Family::<AgentRoleLabels, Counter>::default();
        let agent_role_shifts_total = Family::<AgentRoleLabels, Counter>::default();
        let agent_health_transitions_total = Family::<AgentRoleLabels, Counter>::default();
        let bridge_events_processed = Family::<BridgeLabels, Gauge<u64, AtomicU64>>::default();
        let bridge_error_count = Family::<BridgeLabels, Gauge<u64, AtomicU64>>::default();
        let bridge_lag_seconds = Family::<BridgeLabels, Gauge<f64, AtomicU64>>::default();
        let bridge_ready = Family::<BridgeLabels, Gauge>::default();
        let evasion_catch_rate = Family::<EvasionCoverageLabels, Gauge<f64, AtomicU64>>::default();
        let evasion_total_payloads =
            Family::<EvasionCoverageLabels, Gauge<u64, AtomicU64>>::default();
        let evasion_detected_payloads =
            Family::<EvasionCoverageLabels, Gauge<u64, AtomicU64>>::default();
        let mut registry = Registry::with_prefix("swarm");
        registry.register(
            "ingest_request_latency_microseconds",
            "End-to-end HTTP ingest request latency in microseconds",
            ingest_request_latency_us.clone(),
        );
        registry.register(
            "ingest_events",
            "Count of ingest events partitioned by request outcome",
            ingest_events_total.clone(),
        );
        registry.register(
            "detect_latency_microseconds",
            "Detection latency for the critical path in microseconds",
            detect_latency_us.clone(),
        );
        registry.register(
            "policy_latency_microseconds",
            "Policy evaluation latency for the critical path in microseconds",
            policy_latency_us.clone(),
        );
        registry.register(
            "response_latency_microseconds",
            "Response execution latency for the critical path in microseconds",
            response_latency_us.clone(),
        );
        registry.register(
            "heap_bytes",
            "Current process heap usage in bytes",
            heap_bytes.clone(),
        );
        registry.register(
            "heap_pressure_ratio",
            "Current process heap pressure as usage divided by the best available memory limit",
            heap_pressure_ratio.clone(),
        );
        registry.register(
            "verdict",
            "Policy verdict outcome counter",
            verdict_total.clone(),
        );
        registry.register(
            "guard_rejections",
            "Guard rejection counter by guard name",
            guard_rejections_total.clone(),
        );
        registry.register(
            "adapter_outcomes",
            "Response adapter outcome counter",
            adapter_outcomes_total.clone(),
        );
        registry.register(
            "findings",
            "Detection finding counter by threat class and detector",
            findings_total.clone(),
        );
        registry.register(
            "agent_ticks",
            "Agent tick completion counter partitioned by role",
            agent_ticks_total.clone(),
        );
        registry.register(
            "agent_role_shifts",
            "Agent role shift counter partitioned by role",
            agent_role_shifts_total.clone(),
        );
        registry.register(
            "agent_health_transitions",
            "Agent health transition counter partitioned by role",
            agent_health_transitions_total.clone(),
        );
        registry.register(
            "bridge_events_processed",
            "Latest processed event count for each configured telemetry bridge",
            bridge_events_processed.clone(),
        );
        registry.register(
            "bridge_error_count",
            "Latest error count for each configured telemetry bridge",
            bridge_error_count.clone(),
        );
        registry.register(
            "bridge_lag_seconds",
            "Latest observed lag in seconds for each configured telemetry bridge",
            bridge_lag_seconds.clone(),
        );
        registry.register(
            "bridge_ready",
            "Whether each configured telemetry bridge is currently healthy",
            bridge_ready.clone(),
        );
        registry.register(
            "evasion_catch_rate",
            "Measured detector catch rate over the repo-owned evasion corpus",
            evasion_catch_rate.clone(),
        );
        registry.register(
            "evasion_total_payloads",
            "Total adversarial payloads measured for one detector and threat class in the evasion corpus",
            evasion_total_payloads.clone(),
        );
        registry.register(
            "evasion_detected_payloads",
            "Detected adversarial payloads for one detector and threat class in the evasion corpus",
            evasion_detected_payloads.clone(),
        );
        Self {
            registry: Arc::new(Mutex::new(registry)),
            ingest_request_latency_us,
            ingest_events_total,
            detect_latency_us,
            policy_latency_us,
            response_latency_us,
            heap_bytes,
            heap_pressure_ratio,
            verdict_total,
            guard_rejections_total,
            adapter_outcomes_total,
            findings_total,
            agent_ticks_total,
            agent_role_shifts_total,
            agent_health_transitions_total,
            bridge_events_processed,
            bridge_error_count,
            bridge_lag_seconds,
            bridge_ready,
            evasion_catch_rate,
            evasion_total_payloads,
            evasion_detected_payloads,
        }
    }

    pub fn observe_detect(&self, latency_us: f64) {
        self.detect_latency_us.observe(latency_us);
    }

    pub fn observe_ingest_request(&self, latency_us: f64) {
        self.ingest_request_latency_us.observe(latency_us);
    }

    pub fn observe_ingest_events(&self, status: &str, count: u64) {
        self.ingest_events_total
            .get_or_create(&IngestOutcomeLabels {
                status: status.to_string(),
            })
            .inc_by(count);
    }

    pub fn observe_policy(&self, latency_us: f64) {
        self.policy_latency_us.observe(latency_us);
    }

    pub fn observe_response(&self, latency_us: f64) {
        self.response_latency_us.observe(latency_us);
    }

    pub fn observe_heap(&self, bytes: u64, pressure_ratio: f64) {
        self.heap_bytes.set(bytes);
        self.heap_pressure_ratio.set(pressure_ratio);
    }

    pub fn observe_verdict(&self, verdict: &str) {
        self.verdict_total
            .get_or_create(&VerdictLabels {
                verdict: verdict.to_string(),
            })
            .inc();
    }

    pub fn observe_guard_rejection(&self, guard_name: &str) {
        self.guard_rejections_total
            .get_or_create(&GuardRejectionLabels {
                guard_name: guard_name.to_string(),
            })
            .inc();
    }

    pub fn observe_adapter_outcome(&self, outcome: &str) {
        self.adapter_outcomes_total
            .get_or_create(&AdapterOutcomeLabels {
                outcome: outcome.to_string(),
            })
            .inc();
    }

    pub fn observe_finding(&self, threat_class: &str, detector: &str) {
        self.findings_total
            .get_or_create(&FindingLabels {
                threat_class: threat_class.to_string(),
                detector: detector.to_string(),
            })
            .inc();
    }

    pub fn observe_agent_tick(&self, role: &str) {
        self.agent_ticks_total
            .get_or_create(&AgentRoleLabels {
                role: role.to_string(),
            })
            .inc();
    }

    pub fn observe_agent_role_shift(&self, role: &str) {
        self.agent_role_shifts_total
            .get_or_create(&AgentRoleLabels {
                role: role.to_string(),
            })
            .inc();
    }

    pub fn observe_agent_health_transition(&self, role: &str) {
        self.agent_health_transitions_total
            .get_or_create(&AgentRoleLabels {
                role: role.to_string(),
            })
            .inc();
    }

    pub fn observe_bridge_health(
        &self,
        bridge: &str,
        source_id: &str,
        ready: bool,
        events_processed: u64,
        error_count: u64,
        lag_seconds: Option<f64>,
    ) {
        let labels = BridgeLabels {
            bridge: bridge.to_string(),
            source_id: source_id.to_string(),
        };
        self.bridge_events_processed
            .get_or_create(&labels)
            .set(events_processed);
        self.bridge_error_count
            .get_or_create(&labels)
            .set(error_count);
        self.bridge_lag_seconds
            .get_or_create(&labels)
            .set(lag_seconds.unwrap_or_default());
        self.bridge_ready
            .get_or_create(&labels)
            .set(if ready { 1 } else { 0 });
    }

    pub fn observe_evasion_coverage(
        &self,
        detector: &str,
        threat_class: &str,
        suite: &str,
        total_payloads: u64,
        detected_payloads: u64,
        catch_rate: f64,
    ) {
        let labels = EvasionCoverageLabels {
            detector: detector.to_string(),
            threat_class: threat_class.to_string(),
            suite: suite.to_string(),
        };
        self.evasion_catch_rate
            .get_or_create(&labels)
            .set(catch_rate.clamp(0.0, 1.0));
        self.evasion_total_payloads
            .get_or_create(&labels)
            .set(total_payloads);
        self.evasion_detected_payloads
            .get_or_create(&labels)
            .set(detected_payloads);
    }
}

impl Default for CriticalPathMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub fn encode_metrics(metrics: &CriticalPathMetrics) -> String {
    let registry = metrics
        .registry
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let mut output = String::new();
    let _ = encode(&mut output, &registry);
    output
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{CriticalPathMetrics, encode_metrics};

    #[test]
    fn encode_metrics_renders_all_histograms() {
        let metrics = CriticalPathMetrics::new();
        metrics.observe_ingest_request(7_500.0);
        metrics.observe_ingest_events("accepted", 25);
        metrics.observe_detect(125.0);
        metrics.observe_policy(240.0);
        metrics.observe_response(800.0);
        metrics.observe_heap(4_096, 0.25);

        let encoded = encode_metrics(&metrics);
        assert!(encoded.contains("# HELP swarm_ingest_request_latency_microseconds"));
        assert!(encoded.contains("# TYPE swarm_ingest_request_latency_microseconds histogram"));
        assert!(encoded.contains("swarm_ingest_request_latency_microseconds_bucket"));
        assert!(encoded.contains("swarm_ingest_events_total{status=\"accepted\"} 25"));
        assert!(encoded.contains("# HELP swarm_detect_latency_microseconds"));
        assert!(encoded.contains("# TYPE swarm_detect_latency_microseconds histogram"));
        assert!(encoded.contains("swarm_detect_latency_microseconds_bucket"));
        assert!(encoded.contains("swarm_policy_latency_microseconds"));
        assert!(encoded.contains("swarm_response_latency_microseconds"));
        assert!(encoded.contains("swarm_heap_bytes 4096"));
        assert!(encoded.contains("swarm_heap_pressure_ratio 0.25"));
    }

    #[test]
    fn encode_metrics_renders_verdict_counters() {
        let metrics = CriticalPathMetrics::new();
        metrics.observe_verdict("allow");
        metrics.observe_verdict("deny");
        metrics.observe_verdict("require_human");

        let encoded = encode_metrics(&metrics);
        assert!(encoded.contains("swarm_verdict_total{verdict=\"allow\"} 1"));
        assert!(encoded.contains("swarm_verdict_total{verdict=\"deny\"} 1"));
        assert!(encoded.contains("swarm_verdict_total{verdict=\"require_human\"} 1"));
    }

    #[test]
    fn encode_metrics_renders_guard_rejections() {
        let metrics = CriticalPathMetrics::new();
        metrics.observe_guard_rejection("rate_limiter");

        let encoded = encode_metrics(&metrics);
        assert!(encoded.contains("swarm_guard_rejections_total{guard_name=\"rate_limiter\"} 1"));
    }

    #[test]
    fn encode_metrics_renders_adapter_outcomes() {
        let metrics = CriticalPathMetrics::new();
        metrics.observe_adapter_outcome("success");
        metrics.observe_adapter_outcome("timeout");
        metrics.observe_adapter_outcome("failure");

        let encoded = encode_metrics(&metrics);
        assert!(encoded.contains("swarm_adapter_outcomes_total{outcome=\"success\"} 1"));
        assert!(encoded.contains("swarm_adapter_outcomes_total{outcome=\"timeout\"} 1"));
        assert!(encoded.contains("swarm_adapter_outcomes_total{outcome=\"failure\"} 1"));
    }

    #[test]
    fn encode_metrics_renders_findings() {
        let metrics = CriticalPathMetrics::new();
        metrics.observe_finding("execution", "suspicious_process_tree");

        let encoded = encode_metrics(&metrics);
        assert!(
            encoded.contains(
                "swarm_findings_total{detector=\"suspicious_process_tree\",threat_class=\"execution\"} 1"
            ) || encoded.contains(
                "swarm_findings_total{threat_class=\"execution\",detector=\"suspicious_process_tree\"} 1"
            )
        );
    }

    #[test]
    fn encode_metrics_renders_agent_counters() {
        let metrics = CriticalPathMetrics::new();
        metrics.observe_agent_tick("whisker");
        metrics.observe_agent_role_shift("stalker");
        metrics.observe_agent_health_transition("weaver");

        let encoded = encode_metrics(&metrics);
        assert!(encoded.contains("swarm_agent_ticks_total{role=\"whisker\"} 1"));
        assert!(encoded.contains("swarm_agent_role_shifts_total{role=\"stalker\"} 1"));
        assert!(encoded.contains("swarm_agent_health_transitions_total{role=\"weaver\"} 1"));
    }

    #[test]
    fn encode_metrics_renders_bridge_health_gauges() {
        let metrics = CriticalPathMetrics::new();
        metrics.observe_bridge_health("cloudtrail-primary", "cloudtrail", true, 4, 1, Some(12.5));

        let encoded = encode_metrics(&metrics);
        assert!(
            encoded.contains("swarm_bridge_events_processed{bridge=\"cloudtrail-primary\",source_id=\"cloudtrail\"} 4")
                || encoded.contains("swarm_bridge_events_processed{source_id=\"cloudtrail\",bridge=\"cloudtrail-primary\"} 4")
        );
        assert!(
            encoded.contains(
                "swarm_bridge_error_count{bridge=\"cloudtrail-primary\",source_id=\"cloudtrail\"} 1"
            ) || encoded.contains(
                "swarm_bridge_error_count{source_id=\"cloudtrail\",bridge=\"cloudtrail-primary\"} 1"
            )
        );
        assert!(
            encoded.contains(
                "swarm_bridge_ready{bridge=\"cloudtrail-primary\",source_id=\"cloudtrail\"} 1"
            ) || encoded.contains(
                "swarm_bridge_ready{source_id=\"cloudtrail\",bridge=\"cloudtrail-primary\"} 1"
            )
        );
        assert!(
            encoded.contains("swarm_bridge_lag_seconds{bridge=\"cloudtrail-primary\",source_id=\"cloudtrail\"} 12.5")
                || encoded.contains("swarm_bridge_lag_seconds{source_id=\"cloudtrail\",bridge=\"cloudtrail-primary\"} 12.5")
        );
    }

    #[test]
    fn encode_metrics_renders_evasion_coverage_gauges() {
        let metrics = CriticalPathMetrics::new();
        metrics.observe_evasion_coverage(
            "suspicious_process_tree",
            "execution",
            "evasion_breadth_v1",
            10,
            8,
            0.8,
        );

        let encoded = encode_metrics(&metrics);
        assert!(
            encoded.contains(
                "swarm_evasion_catch_rate{detector=\"suspicious_process_tree\",threat_class=\"execution\",suite=\"evasion_breadth_v1\"} 0.8"
            ) || encoded.contains(
                "swarm_evasion_catch_rate{detector=\"suspicious_process_tree\",suite=\"evasion_breadth_v1\",threat_class=\"execution\"} 0.8"
            ) || encoded.contains(
                "swarm_evasion_catch_rate{suite=\"evasion_breadth_v1\",detector=\"suspicious_process_tree\",threat_class=\"execution\"} 0.8"
            )
        );
        assert!(
            encoded.contains(
                "swarm_evasion_total_payloads{detector=\"suspicious_process_tree\",threat_class=\"execution\",suite=\"evasion_breadth_v1\"} 10"
            ) || encoded.contains(
                "swarm_evasion_total_payloads{detector=\"suspicious_process_tree\",suite=\"evasion_breadth_v1\",threat_class=\"execution\"} 10"
            ) || encoded.contains(
                "swarm_evasion_total_payloads{suite=\"evasion_breadth_v1\",detector=\"suspicious_process_tree\",threat_class=\"execution\"} 10"
            )
        );
        assert!(
            encoded.contains(
                "swarm_evasion_detected_payloads{detector=\"suspicious_process_tree\",threat_class=\"execution\",suite=\"evasion_breadth_v1\"} 8"
            ) || encoded.contains(
                "swarm_evasion_detected_payloads{detector=\"suspicious_process_tree\",suite=\"evasion_breadth_v1\",threat_class=\"execution\"} 8"
            ) || encoded.contains(
                "swarm_evasion_detected_payloads{suite=\"evasion_breadth_v1\",detector=\"suspicious_process_tree\",threat_class=\"execution\"} 8"
            )
        );
    }
}
