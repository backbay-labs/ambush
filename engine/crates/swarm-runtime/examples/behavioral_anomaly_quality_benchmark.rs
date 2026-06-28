#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;
use std::path::PathBuf;

use serde_json::{Value, json};
use swarm_core::config::SwarmConfig;
use swarm_runtime::config::load_config;
use swarm_whisker::{
    AuthenticationEventData, BehavioralAnomalyDetector, BehavioralAnomalyProfile, DetectionFinding,
    DetectionStrategy, DnsQueryEvent, FilePersistenceEvent, NetworkConnectEvent,
    ProcessMemoryAccessEvent, ProcessStartEvent, RegistryAccessEvent, RegistryPersistenceEvent,
    TelemetryEvent, TelemetryPayload,
};

type BenchError = Box<dyn Error + Send + Sync>;

const ACTIONABLE_THRESHOLD_DEFAULT: f64 = 0.85;
const STALE_GAP_SECS: i64 = 16_200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedLabel {
    Benign,
    Anomalous,
}

#[derive(Clone, Debug)]
struct BenchmarkCase {
    id: &'static str,
    family: &'static str,
    description: &'static str,
    expected: ExpectedLabel,
    warmup: Vec<TelemetryEvent>,
    evaluation: TelemetryEvent,
}

#[derive(Clone, Debug)]
struct CaseOutcome {
    case: BenchmarkCase,
    current_confidence: f64,
    current_positive: bool,
    legacy_confidence: f64,
    legacy_positive: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct Metrics {
    true_positive: usize,
    false_positive: usize,
    true_negative: usize,
    false_negative: usize,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn default_config_path() -> PathBuf {
    repo_root().join("rulesets/default.yaml")
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(default)
}

fn merge_json_value(target: &mut Value, overlay: Value) {
    match (target, overlay) {
        (Value::Object(target), Value::Object(overlay)) => {
            for (key, value) in overlay {
                match target.get_mut(&key) {
                    Some(existing) => merge_json_value(existing, value),
                    None => {
                        target.insert(key, value);
                    }
                }
            }
        }
        (target, overlay) => *target = overlay,
    }
}

fn behavioral_profile(config: &SwarmConfig) -> Result<BehavioralAnomalyProfile, BenchError> {
    let mut merged = serde_json::to_value(BehavioralAnomalyProfile {
        high_confidence_threshold: config.detection.high_confidence_threshold,
        medium_confidence_threshold: config.detection.medium_confidence_threshold,
        ..BehavioralAnomalyProfile::default()
    })?;
    if let Some(overrides) = config.detection.profiles.behavioral_anomaly.as_ref() {
        merge_json_value(&mut merged, overrides.clone());
    }
    Ok(serde_json::from_value(merged)?)
}

fn telemetry_event(event_id: &str, timestamp: i64, payload: TelemetryPayload) -> TelemetryEvent {
    TelemetryEvent {
        source: "behavioral-benchmark".to_string(),
        event_id: event_id.to_string(),
        timestamp,
        host_id: Some("bench-host".to_string()),
        payload,
    }
}

fn process_start(
    event_id: &str,
    timestamp: i64,
    parent_process: &str,
    process_name: &str,
    executable_path: &str,
    user: &str,
) -> TelemetryEvent {
    telemetry_event(
        event_id,
        timestamp,
        TelemetryPayload::ProcessStart(ProcessStartEvent {
            parent_process: parent_process.to_string(),
            process_name: process_name.to_string(),
            command_line: process_name.to_string(),
            user: Some(user.to_string()),
            executable_path: Some(executable_path.to_string()),
            signer: None,
            signature_valid: None,
        }),
    )
}

fn network_connect(
    event_id: &str,
    timestamp: i64,
    process_name: &str,
    destination_ip: &str,
    destination_port: u16,
    protocol: &str,
) -> TelemetryEvent {
    telemetry_event(
        event_id,
        timestamp,
        TelemetryPayload::NetworkConnect(NetworkConnectEvent {
            process_name: process_name.to_string(),
            destination_ip: destination_ip.to_string(),
            destination_port,
            protocol: protocol.to_string(),
        }),
    )
}

fn dns_query(
    event_id: &str,
    timestamp: i64,
    process_name: &str,
    query_name: &str,
    query_type: &str,
) -> TelemetryEvent {
    telemetry_event(
        event_id,
        timestamp,
        TelemetryPayload::DnsQuery(DnsQueryEvent {
            query_name: query_name.to_string(),
            query_type: query_type.to_string(),
            source_ip: Some("10.0.0.10".to_string()),
            process_name: Some(process_name.to_string()),
            response_code: Some("NOERROR".to_string()),
        }),
    )
}

fn authentication(
    event_id: &str,
    timestamp: i64,
    user: &str,
    source_host: &str,
    target_host: &str,
    target_service: &str,
    success: bool,
) -> TelemetryEvent {
    telemetry_event(
        event_id,
        timestamp,
        TelemetryPayload::AuthenticationEvent(AuthenticationEventData {
            auth_type: "kerberos".to_string(),
            source_host: Some(source_host.to_string()),
            target_host: Some(target_host.to_string()),
            target_service: Some(target_service.to_string()),
            process_name: Some("lsass.exe".to_string()),
            success,
            user: Some(user.to_string()),
        }),
    )
}

fn registry_access(
    event_id: &str,
    timestamp: i64,
    process_name: &str,
    registry_path: &str,
    target_process: &str,
) -> TelemetryEvent {
    telemetry_event(
        event_id,
        timestamp,
        TelemetryPayload::RegistryAccess(RegistryAccessEvent {
            process_name: process_name.to_string(),
            registry_path: registry_path.to_string(),
            access_type: "query".to_string(),
            target_process: Some(target_process.to_string()),
        }),
    )
}

fn registry_persistence(
    event_id: &str,
    timestamp: i64,
    process_name: &str,
    registry_path: &str,
    value_name: &str,
) -> TelemetryEvent {
    telemetry_event(
        event_id,
        timestamp,
        TelemetryPayload::RegistryPersistence(RegistryPersistenceEvent {
            process_name: process_name.to_string(),
            registry_path: registry_path.to_string(),
            value_name: Some(value_name.to_string()),
            value_data: None,
            access_type: "set_value".to_string(),
        }),
    )
}

fn file_persistence(
    event_id: &str,
    timestamp: i64,
    process_name: &str,
    file_path: &str,
) -> TelemetryEvent {
    telemetry_event(
        event_id,
        timestamp,
        TelemetryPayload::FilePersistence(FilePersistenceEvent {
            file_path: file_path.to_string(),
            operation: "create".to_string(),
            process_name: process_name.to_string(),
            content_preview: None,
        }),
    )
}

fn process_memory_access(
    event_id: &str,
    timestamp: i64,
    source_process: &str,
    target_process: &str,
    protection_flags: &[&str],
) -> TelemetryEvent {
    telemetry_event(
        event_id,
        timestamp,
        TelemetryPayload::ProcessMemoryAccess(ProcessMemoryAccessEvent {
            source_process: source_process.to_string(),
            target_process: target_process.to_string(),
            allocation_type: "virtual_alloc_ex".to_string(),
            protection_flags: protection_flags
                .iter()
                .map(|flag| flag.to_string())
                .collect(),
            region_size: 4096,
            call_stack_hint: None,
        }),
    )
}

fn repeated(event: TelemetryEvent, count: usize) -> Vec<TelemetryEvent> {
    (0..count)
        .map(|index| {
            let mut next = event.clone();
            next.event_id = format!("{}-warm-{index}", event.event_id);
            next.timestamp += index as i64;
            next
        })
        .collect()
}

fn stale_event(mut event: TelemetryEvent) -> TelemetryEvent {
    event.timestamp += STALE_GAP_SECS;
    event
}

fn benchmark_cases() -> Vec<BenchmarkCase> {
    vec![
        BenchmarkCase {
            id: "process_stale_normal",
            family: "process_start",
            description: "stale but previously normal Office -> PowerShell launch",
            expected: ExpectedLabel::Benign,
            warmup: repeated(
                process_start(
                    "process-stale",
                    1_900_000_000,
                    "winword",
                    "powershell",
                    "C:\\Users\\alice\\AppData\\Local\\Temp\\powershell.exe",
                    "alice",
                ),
                4,
            ),
            evaluation: stale_event(process_start(
                "process-stale-eval",
                1_900_000_000,
                "winword",
                "powershell",
                "C:\\Users\\alice\\AppData\\Local\\Temp\\powershell.exe",
                "alice",
            )),
        },
        BenchmarkCase {
            id: "process_true_anomaly",
            family: "process_start",
            description: "new Office -> rundll32 execution with untrusted path",
            expected: ExpectedLabel::Anomalous,
            warmup: repeated(
                process_start(
                    "process-anom",
                    1_900_000_100,
                    "winword",
                    "powershell",
                    "C:\\Users\\alice\\AppData\\Local\\Temp\\powershell.exe",
                    "alice",
                ),
                4,
            ),
            evaluation: process_start(
                "process-anom-eval",
                1_900_000_220,
                "winword",
                "rundll32",
                "C:\\Users\\alice\\AppData\\Local\\Temp\\rundll32.exe",
                "alice",
            ),
        },
        BenchmarkCase {
            id: "network_stale_normal",
            family: "network_connect",
            description: "stale but previously normal svchost outbound flow",
            expected: ExpectedLabel::Benign,
            warmup: repeated(
                network_connect(
                    "network-stale",
                    1_900_000_300,
                    "svchost.exe",
                    "10.0.0.5",
                    443,
                    "tcp",
                ),
                4,
            ),
            evaluation: stale_event(network_connect(
                "network-stale-eval",
                1_900_000_300,
                "svchost.exe",
                "10.0.0.5",
                443,
                "tcp",
            )),
        },
        BenchmarkCase {
            id: "network_true_anomaly",
            family: "network_connect",
            description: "new svchost outbound flow to rare high port",
            expected: ExpectedLabel::Anomalous,
            warmup: repeated(
                network_connect(
                    "network-anom",
                    1_900_000_400,
                    "svchost.exe",
                    "10.0.0.5",
                    443,
                    "tcp",
                ),
                4,
            ),
            evaluation: network_connect(
                "network-anom-eval",
                1_900_000_520,
                "svchost.exe",
                "198.51.100.25",
                8443,
                "tcp",
            ),
        },
        BenchmarkCase {
            id: "dns_stale_normal",
            family: "dns_query",
            description: "stale but previously normal updater DNS request",
            expected: ExpectedLabel::Benign,
            warmup: repeated(
                dns_query(
                    "dns-stale",
                    1_900_000_600,
                    "chrome.exe",
                    "updates.example.com",
                    "A",
                ),
                4,
            ),
            evaluation: stale_event(dns_query(
                "dns-stale-eval",
                1_900_000_600,
                "chrome.exe",
                "updates.example.com",
                "A",
            )),
        },
        BenchmarkCase {
            id: "dns_true_anomaly",
            family: "dns_query",
            description: "new TXT-style DNS pattern on same process",
            expected: ExpectedLabel::Anomalous,
            warmup: repeated(
                dns_query(
                    "dns-anom",
                    1_900_000_700,
                    "chrome.exe",
                    "updates.example.com",
                    "A",
                ),
                4,
            ),
            evaluation: dns_query(
                "dns-anom-eval",
                1_900_000_820,
                "chrome.exe",
                "exfiltration.bad.example",
                "TXT",
            ),
        },
        BenchmarkCase {
            id: "auth_stale_normal",
            family: "authentication_event",
            description: "stale but previously normal Kerberos service auth",
            expected: ExpectedLabel::Benign,
            warmup: repeated(
                authentication(
                    "auth-stale",
                    1_900_000_900,
                    "alice",
                    "host-a",
                    "dc-1",
                    "cifs",
                    true,
                ),
                4,
            ),
            evaluation: stale_event(authentication(
                "auth-stale-eval",
                1_900_000_900,
                "alice",
                "host-a",
                "dc-1",
                "cifs",
                true,
            )),
        },
        BenchmarkCase {
            id: "auth_true_anomaly",
            family: "authentication_event",
            description: "new successful auth path to a different host",
            expected: ExpectedLabel::Anomalous,
            warmup: repeated(
                authentication(
                    "auth-anom",
                    1_900_001_000,
                    "alice",
                    "host-a",
                    "dc-1",
                    "cifs",
                    true,
                ),
                4,
            ),
            evaluation: authentication(
                "auth-anom-eval",
                1_900_001_120,
                "alice",
                "host-b",
                "dc-2",
                "cifs",
                true,
            ),
        },
        BenchmarkCase {
            id: "registry_access_stale_normal",
            family: "registry_access",
            description: "stale but previously normal registry query pattern",
            expected: ExpectedLabel::Benign,
            warmup: repeated(
                registry_access(
                    "reg-access-stale",
                    1_900_001_200,
                    "reg.exe",
                    "HKLM\\SAM\\Domains\\Account",
                    "lsass.exe",
                ),
                4,
            ),
            evaluation: stale_event(registry_access(
                "reg-access-stale-eval",
                1_900_001_200,
                "reg.exe",
                "HKLM\\SAM\\Domains\\Account",
                "lsass.exe",
            )),
        },
        BenchmarkCase {
            id: "registry_access_true_anomaly",
            family: "registry_access",
            description: "new registry credential material query",
            expected: ExpectedLabel::Anomalous,
            warmup: repeated(
                registry_access(
                    "reg-access-anom",
                    1_900_001_300,
                    "reg.exe",
                    "HKLM\\SAM\\Domains\\Account",
                    "lsass.exe",
                ),
                4,
            ),
            evaluation: registry_access(
                "reg-access-anom-eval",
                1_900_001_420,
                "reg.exe",
                "HKLM\\SECURITY\\Policy\\Secrets",
                "winlogon.exe",
            ),
        },
        BenchmarkCase {
            id: "registry_persistence_stale_normal",
            family: "registry_persistence",
            description: "stale but previously normal Run key value write",
            expected: ExpectedLabel::Benign,
            warmup: repeated(
                registry_persistence(
                    "reg-persist-stale",
                    1_900_001_500,
                    "reg.exe",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "OneDrive",
                ),
                4,
            ),
            evaluation: stale_event(registry_persistence(
                "reg-persist-stale-eval",
                1_900_001_500,
                "reg.exe",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "OneDrive",
            )),
        },
        BenchmarkCase {
            id: "registry_persistence_true_anomaly",
            family: "registry_persistence",
            description: "new persistence Run key write under different hive",
            expected: ExpectedLabel::Anomalous,
            warmup: repeated(
                registry_persistence(
                    "reg-persist-anom",
                    1_900_001_600,
                    "reg.exe",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "OneDrive",
                ),
                4,
            ),
            evaluation: registry_persistence(
                "reg-persist-anom-eval",
                1_900_001_720,
                "reg.exe",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Updater",
            ),
        },
        BenchmarkCase {
            id: "file_stale_normal",
            family: "file_persistence",
            description: "stale but previously normal startup shortcut creation",
            expected: ExpectedLabel::Benign,
            warmup: repeated(
                file_persistence(
                    "file-stale",
                    1_900_001_800,
                    "explorer.exe",
                    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\onedrive.lnk",
                ),
                4,
            ),
            evaluation: stale_event(file_persistence(
                "file-stale-eval",
                1_900_001_800,
                "explorer.exe",
                "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\onedrive.lnk",
            )),
        },
        BenchmarkCase {
            id: "file_true_anomaly",
            family: "file_persistence",
            description: "new startup shortcut path for updater",
            expected: ExpectedLabel::Anomalous,
            warmup: repeated(
                file_persistence(
                    "file-anom",
                    1_900_001_900,
                    "explorer.exe",
                    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\onedrive.lnk",
                ),
                4,
            ),
            evaluation: file_persistence(
                "file-anom-eval",
                1_900_002_020,
                "explorer.exe",
                "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.lnk",
            ),
        },
        BenchmarkCase {
            id: "memory_stale_normal",
            family: "process_memory_access",
            description: "stale but previously normal memory allocation pattern",
            expected: ExpectedLabel::Benign,
            warmup: repeated(
                process_memory_access(
                    "memory-stale",
                    1_900_002_100,
                    "winword.exe",
                    "teams.exe",
                    &["readwrite"],
                ),
                4,
            ),
            evaluation: stale_event(process_memory_access(
                "memory-stale-eval",
                1_900_002_100,
                "winword.exe",
                "teams.exe",
                &["readwrite"],
            )),
        },
        BenchmarkCase {
            id: "memory_true_anomaly",
            family: "process_memory_access",
            description: "new RWX memory pattern into lsass",
            expected: ExpectedLabel::Anomalous,
            warmup: repeated(
                process_memory_access(
                    "memory-anom",
                    1_900_002_200,
                    "winword.exe",
                    "teams.exe",
                    &["readwrite"],
                ),
                4,
            ),
            evaluation: process_memory_access(
                "memory-anom-eval",
                1_900_002_320,
                "winword.exe",
                "lsass.exe",
                &["execute_readwrite"],
            ),
        },
    ]
}

fn legacy_control_confidence(
    finding: Option<&DetectionFinding>,
    medium_confidence_threshold: f64,
    high_confidence_threshold: f64,
) -> f64 {
    let Some(finding) = finding else {
        return 0.0;
    };
    let signal_count = finding
        .evidence
        .get("anomaly_modes")
        .and_then(|value| value.as_array())
        .map(|entries| entries.len())
        .unwrap_or(0);
    let scope_hits = finding
        .evidence
        .get("baseline_scope_hits")
        .and_then(|value| value.as_array())
        .map(|entries| entries.len())
        .unwrap_or(0);
    if signal_count == 0 || scope_hits == 0 {
        return 0.0;
    }
    (medium_confidence_threshold
        + 0.05 * signal_count.saturating_sub(1) as f64
        + 0.03 * scope_hits.saturating_sub(1) as f64)
        .clamp(medium_confidence_threshold, high_confidence_threshold)
}

fn evaluate_case(
    profile: &BehavioralAnomalyProfile,
    case: &BenchmarkCase,
    actionable_threshold: f64,
) -> Result<CaseOutcome, BenchError> {
    let detector = BehavioralAnomalyDetector::from_profile(profile.clone())?;
    for event in &case.warmup {
        detector.evaluate(event);
    }
    let findings = detector.evaluate(&case.evaluation);
    let current_confidence = findings
        .first()
        .map(|finding| finding.confidence)
        .unwrap_or(0.0);
    let legacy_confidence = legacy_control_confidence(
        findings.first(),
        profile.medium_confidence_threshold,
        profile.high_confidence_threshold,
    );
    Ok(CaseOutcome {
        case: case.clone(),
        current_confidence,
        current_positive: current_confidence >= actionable_threshold,
        legacy_confidence,
        legacy_positive: legacy_confidence >= actionable_threshold,
    })
}

fn compute_metrics(outcomes: &[CaseOutcome], use_current: bool) -> Metrics {
    let mut metrics = Metrics::default();
    for outcome in outcomes {
        let predicted_positive = if use_current {
            outcome.current_positive
        } else {
            outcome.legacy_positive
        };
        match (outcome.case.expected, predicted_positive) {
            (ExpectedLabel::Anomalous, true) => metrics.true_positive += 1,
            (ExpectedLabel::Anomalous, false) => metrics.false_negative += 1,
            (ExpectedLabel::Benign, true) => metrics.false_positive += 1,
            (ExpectedLabel::Benign, false) => metrics.true_negative += 1,
        }
    }
    metrics
}

fn catch_rate(metrics: Metrics) -> f64 {
    let total = metrics.true_positive + metrics.false_negative;
    if total == 0 {
        0.0
    } else {
        metrics.true_positive as f64 / total as f64
    }
}

fn false_positive_rate(metrics: Metrics) -> f64 {
    let total = metrics.false_positive + metrics.true_negative;
    if total == 0 {
        0.0
    } else {
        metrics.false_positive as f64 / total as f64
    }
}

fn format_bool(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn main() -> Result<(), BenchError> {
    let config_path = default_config_path();
    let config = load_config(&config_path)?;
    let profile = behavioral_profile(&config)?;
    let actionable_threshold = env_f64(
        "STS_BEHAVIORAL_ACTIONABLE_THRESHOLD",
        ACTIONABLE_THRESHOLD_DEFAULT,
    );
    let cases = benchmark_cases();
    let outcomes = cases
        .iter()
        .map(|case| evaluate_case(&profile, case, actionable_threshold))
        .collect::<Result<Vec<_>, _>>()?;

    let current_metrics = compute_metrics(&outcomes, true);
    let legacy_metrics = compute_metrics(&outcomes, false);
    let current_catch_rate = catch_rate(current_metrics);
    let current_false_positive_rate = false_positive_rate(current_metrics);
    let legacy_catch_rate = catch_rate(legacy_metrics);
    let legacy_false_positive_rate = false_positive_rate(legacy_metrics);
    let false_positive_improvement = if legacy_false_positive_rate > 0.0 {
        (legacy_false_positive_rate - current_false_positive_rate) / legacy_false_positive_rate
    } else {
        0.0
    };

    println!("# Behavioral Anomaly Quality Benchmark");
    println!();
    println!(
        "**Config:** `{}`",
        config_path
            .strip_prefix(repo_root())
            .unwrap_or(&config_path)
            .display()
    );
    println!(
        "**Profile:** medium `{:.2}`, high `{:.2}`, high-confidence z-score `{:.2}`, half-life `{:.0}`s",
        profile.medium_confidence_threshold,
        profile.high_confidence_threshold,
        profile.high_confidence_z_score,
        profile.baseline_half_life_secs
    );
    println!(
        "**Actionable confidence threshold:** `{:.2}`",
        actionable_threshold
    );
    println!(
        "**Corpus:** {} labeled cases ({} benign stale-normal, {} anomalous novel-behavior)",
        outcomes.len(),
        outcomes
            .iter()
            .filter(|outcome| outcome.case.expected == ExpectedLabel::Benign)
            .count(),
        outcomes
            .iter()
            .filter(|outcome| outcome.case.expected == ExpectedLabel::Anomalous)
            .count()
    );
    println!();
    println!(
        "| Case | Family | Label | Description | Current confidence | Current actionable | Legacy confidence | Legacy actionable |"
    );
    println!("| --- | --- | --- | --- | ---: | :---: | ---: | :---: |");
    for outcome in &outcomes {
        println!(
            "| `{}` | `{}` | `{}` | {} | {:.3} | {} | {:.3} | {} |",
            outcome.case.id,
            outcome.case.family,
            match outcome.case.expected {
                ExpectedLabel::Benign => "benign",
                ExpectedLabel::Anomalous => "anomalous",
            },
            outcome.case.description,
            outcome.current_confidence,
            format_bool(outcome.current_positive),
            outcome.legacy_confidence,
            format_bool(outcome.legacy_positive),
        );
    }
    println!();
    println!("| Model | TP | FP | TN | FN | Catch rate | False-positive rate |");
    println!("| --- | ---: | ---: | ---: | ---: | ---: | ---: |");
    println!(
        "| `current_deviation_scoring` | {} | {} | {} | {} | {:.3} | {:.3} |",
        current_metrics.true_positive,
        current_metrics.false_positive,
        current_metrics.true_negative,
        current_metrics.false_negative,
        current_catch_rate,
        current_false_positive_rate,
    );
    println!(
        "| `legacy_fixed_arithmetic_control` | {} | {} | {} | {} | {:.3} | {:.3} |",
        legacy_metrics.true_positive,
        legacy_metrics.false_positive,
        legacy_metrics.true_negative,
        legacy_metrics.false_negative,
        legacy_catch_rate,
        legacy_false_positive_rate,
    );
    println!();
    println!(
        "**False-positive reduction vs legacy fixed arithmetic:** `{:.1}%`",
        false_positive_improvement * 100.0
    );
    println!(
        "**Catch-rate delta vs legacy fixed arithmetic:** `{:.3}`",
        current_catch_rate - legacy_catch_rate
    );
    println!();
    println!(
        "```json\n{}\n```",
        serde_json::to_string_pretty(&json!({
            "actionable_threshold": actionable_threshold,
            "current": {
                "true_positive": current_metrics.true_positive,
                "false_positive": current_metrics.false_positive,
                "true_negative": current_metrics.true_negative,
                "false_negative": current_metrics.false_negative,
                "catch_rate": current_catch_rate,
                "false_positive_rate": current_false_positive_rate,
            },
            "legacy_control": {
                "true_positive": legacy_metrics.true_positive,
                "false_positive": legacy_metrics.false_positive,
                "true_negative": legacy_metrics.true_negative,
                "false_negative": legacy_metrics.false_negative,
                "catch_rate": legacy_catch_rate,
                "false_positive_rate": legacy_false_positive_rate,
            },
            "false_positive_reduction_fraction": false_positive_improvement,
            "catch_rate_delta": current_catch_rate - legacy_catch_rate,
        }))?
    );

    Ok(())
}
