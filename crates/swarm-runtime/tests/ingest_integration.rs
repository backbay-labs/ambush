use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use swarm_core::config::SwarmConfig;
use swarm_core::config::{PheromoneBackendConfig, RuntimeMode};
use swarm_runtime::bridge_runtime::BridgeStatusSnapshot;
use swarm_runtime::config::{load_config, write_debug_test_config_signature};
use swarm_runtime::ingest::IngestState;
use swarm_runtime::ingest::detect_http_router;
use tower::ServiceExt;

fn default_config_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rulesets/default.yaml")
}

fn config_with_strategy(strategy: &str) -> Result<SwarmConfig, Box<dyn std::error::Error>> {
    let mut cfg = load_config(default_config_path())?;
    cfg.detection.strategy = strategy.to_string();
    Ok(cfg)
}

fn unique_temp_config_path(label: &str) -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "swarm-runtime-ingest-{label}-{}-{millis}.yaml",
        std::process::id()
    ))
}

fn write_signed_config(
    path: &PathBuf,
    config: &SwarmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, serde_yaml::to_string(config)?)?;
    write_debug_test_config_signature(path)?;
    Ok(())
}

fn valid_process_event(event_id: &str) -> Value {
    json!({
        "source": "integration",
        "event_id": event_id,
        "timestamp": 1_700_000_000_000_i64,
        "host_id": "host-1",
        "payload": {
            "kind": "process_start",
            "parent_process": "winword",
            "process_name": "powershell",
            "command_line": "powershell.exe -enc AAA=",
            "user": "alice"
        }
    })
}

fn valid_dns_event(event_id: &str, query_name: &str) -> Value {
    json!({
        "source": "integration",
        "event_id": event_id,
        "timestamp": 1_700_000_000_100_i64,
        "host_id": "host-dns",
        "payload": {
            "kind": "dns_query",
            "query_name": query_name,
            "query_type": "A",
            "source_ip": "10.0.0.2",
            "process_name": "chrome.exe",
            "response_code": "NOERROR"
        }
    })
}

fn bridge_health(entries: Vec<BridgeStatusSnapshot>) -> Arc<Mutex<Vec<BridgeStatusSnapshot>>> {
    Arc::new(Mutex::new(entries))
}

async fn ingest(
    strategy: &str,
    body: Value,
) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
    let state = IngestState::from_config(default_config_path(), config_with_strategy(strategy)?)?;
    let app = detect_http_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?;
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    Ok((status, serde_json::from_slice(&body)?))
}

#[tokio::test]
async fn valid_json_array_returns_accepted_status() -> Result<(), Box<dyn std::error::Error>> {
    let (status, body) = ingest(
        "suspicious_process_tree",
        json!([valid_process_event("evt-1")]),
    )
    .await?;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"].as_array().map(Vec::len), Some(1));
    assert_eq!(body["rejected"].as_array().map(Vec::len), Some(0));
    assert_eq!(body["accepted"][0]["event_id"], "evt-1");
    assert_eq!(body["accepted"][0]["status"], "accepted");
    Ok(())
}

#[tokio::test]
async fn empty_array_returns_empty_accept_and_reject_lists()
-> Result<(), Box<dyn std::error::Error>> {
    let (status, body) = ingest("suspicious_process_tree", json!([])).await?;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], json!([]));
    assert_eq!(body["rejected"], json!([]));
    Ok(())
}

#[tokio::test]
async fn malformed_json_returns_structured_bad_request() -> Result<(), Box<dyn std::error::Error>> {
    let state = IngestState::from_config(
        default_config_path(),
        config_with_strategy("suspicious_process_tree")?,
    )?;
    let app = detect_http_router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(br#"{"not":"an array""#.to_vec()))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let json: Value = serde_json::from_slice(&body)?;
    assert!(
        json["error"]
            .as_str()
            .is_some_and(|message| !message.is_empty())
    );
    Ok(())
}

#[tokio::test]
async fn non_array_json_returns_structured_bad_request() -> Result<(), Box<dyn std::error::Error>> {
    let (status, body) = ingest(
        "suspicious_process_tree",
        json!({
            "source": "integration",
            "event_id": "evt-not-array"
        }),
    )
    .await?;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|message| !message.is_empty())
    );
    Ok(())
}

#[tokio::test]
async fn unknown_payload_kind_returns_per_event_rejection() -> Result<(), Box<dyn std::error::Error>>
{
    let invalid = json!([{
        "source": "integration",
        "event_id": "evt-unknown",
        "timestamp": 1_700_000_000_000_i64,
        "host_id": "host-unknown",
        "payload": {
            "kind": "unsupported_kind"
        }
    }]);
    let (status, body) = ingest("suspicious_process_tree", invalid).await?;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], json!([]));
    assert_eq!(body["rejected"][0]["event_id"], "evt-unknown");
    assert_eq!(body["rejected"][0]["status"], "rejected");
    Ok(())
}

#[tokio::test]
async fn missing_required_field_returns_per_event_rejection()
-> Result<(), Box<dyn std::error::Error>> {
    let invalid = json!([{
        "event_id": "evt-missing-source",
        "timestamp": 1_700_000_000_000_i64,
        "host_id": "host-missing",
        "payload": {
            "kind": "process_start",
            "parent_process": "winword",
            "process_name": "powershell",
            "command_line": "powershell.exe -enc AAA=",
            "user": "alice"
        }
    }]);
    let (status, body) = ingest("suspicious_process_tree", invalid).await?;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], json!([]));
    assert_eq!(body["rejected"][0]["event_id"], "evt-missing-source");
    assert_eq!(body["rejected"][0]["status"], "rejected");
    Ok(())
}

#[tokio::test]
async fn mixed_valid_and_invalid_events_split_between_lists()
-> Result<(), Box<dyn std::error::Error>> {
    let payload = json!([
        valid_process_event("evt-valid"),
        {
            "event_id": "evt-invalid",
            "timestamp": 1_700_000_000_000_i64,
            "payload": {
                "kind": "dns_query",
                "query_name": "www.google.com",
                "query_type": "A",
                "source_ip": "10.0.0.3",
                "process_name": "chrome.exe",
                "response_code": "NOERROR"
            }
        }
    ]);
    let (status, body) = ingest("suspicious_process_tree", payload).await?;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"][0]["event_id"], "evt-valid");
    assert_eq!(body["rejected"][0]["event_id"], "evt-invalid");
    Ok(())
}

#[tokio::test]
async fn ingest_router_coexists_with_metrics_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let state = IngestState::from_config(
        default_config_path(),
        config_with_strategy("dns_exfiltration")?,
    )?;
    let app = detect_http_router(state);

    let ingest_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/ingest/events")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&json!([valid_dns_event(
                    "evt-dns",
                    "www.google.com"
                )]))?))?,
        )
        .await?;
    assert_eq!(ingest_response.status(), StatusCode::OK);

    let metrics_response = app
        .oneshot(Request::builder().uri("/metrics").body(Body::empty())?)
        .await?;
    assert_eq!(metrics_response.status(), StatusCode::OK);
    let body = to_bytes(metrics_response.into_body(), usize::MAX).await?;
    let body = String::from_utf8(body.to_vec())?;
    assert!(body.contains("swarm_ingest_events_total"));
    assert!(body.contains("swarm_ingest_request_latency_microseconds"));
    assert!(body.contains("swarm_detect_latency_microseconds"));
    Ok(())
}

#[tokio::test]
async fn healthz_reports_ready_when_detect_stack_is_healthy()
-> Result<(), Box<dyn std::error::Error>> {
    let state = IngestState::from_config(
        default_config_path(),
        config_with_strategy("suspicious_process_tree")?,
    )?;
    let app = detect_http_router(state);

    let response = app
        .oneshot(Request::builder().uri("/healthz").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let json: Value = serde_json::from_slice(&body)?;
    assert_eq!(json["status"], "ok");
    assert_eq!(
        json["components"]["detector"]["strategy"],
        "suspicious_process_tree"
    );
    Ok(())
}

#[tokio::test]
async fn healthz_returns_service_unavailable_when_live_response_requires_durable_substrate()
-> Result<(), Box<dyn std::error::Error>> {
    let mut config = config_with_strategy("suspicious_process_tree")?;
    config.runtime.mode = RuntimeMode::LiveResponse;
    config.runtime.require_durable_live_response = true;
    config.pheromone.backend = PheromoneBackendConfig::InMemory;
    let state = IngestState::from_config(default_config_path(), config)?;
    let app = detect_http_router(state);

    let response = app
        .oneshot(Request::builder().uri("/healthz").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let json: Value = serde_json::from_slice(&body)?;
    assert_eq!(json["status"], "degraded");
    assert_eq!(json["components"]["substrate"]["effective_ready"], false);
    Ok(())
}

#[tokio::test]
async fn reload_from_disk_swaps_detector_strategy() -> Result<(), Box<dyn std::error::Error>> {
    let initial = config_with_strategy("suspicious_process_tree")?;
    let path = unique_temp_config_path("reload");
    write_signed_config(&path, &initial)?;

    let state = IngestState::from_config(path.clone(), initial)?;
    assert_eq!(state.detector_strategy_name(), "suspicious_process_tree");

    let updated = config_with_strategy("dns_exfiltration")?;
    write_signed_config(&path, &updated)?;
    state.reload_from_disk()?;

    assert_eq!(state.detector_strategy_name(), "dns_exfiltration");
    let _ = fs::remove_file(path);
    Ok(())
}

#[tokio::test]
async fn healthz_reports_detector_reload_failure() -> Result<(), Box<dyn std::error::Error>> {
    let initial = config_with_strategy("suspicious_process_tree")?;
    let path = unique_temp_config_path("reload-failure");
    write_signed_config(&path, &initial)?;

    let state = IngestState::from_config(path.clone(), initial)?;
    let mut invalid = config_with_strategy("suspicious_process_tree")?;
    invalid.detection.strategy = "not_a_real_detector".to_string();
    write_signed_config(&path, &invalid)?;
    assert!(state.reload_from_disk().is_err());

    let app = detect_http_router(state);
    let response = app
        .oneshot(Request::builder().uri("/healthz").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let json: Value = serde_json::from_slice(&body)?;
    assert_eq!(json["status"], "degraded");
    assert_eq!(json["components"]["detector"]["ready"], false);
    assert!(
        json["components"]["detector"]["details"]
            .as_str()
            .is_some_and(|details| details.contains("last reload failed"))
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[tokio::test]
async fn healthz_exposes_bridge_component_without_failing_ready_status()
-> Result<(), Box<dyn std::error::Error>> {
    let state = IngestState::from_config(
        default_config_path(),
        config_with_strategy("suspicious_process_tree")?,
    )?
    .with_bridge_health(bridge_health(vec![BridgeStatusSnapshot {
        name: "cloudtrail-primary".to_string(),
        source_id: "cloudtrail".to_string(),
        ready: false,
        events_processed: 4,
        error_count: 1,
        lag_seconds: Some(9.0),
        last_error: Some("fixture mapping failed".to_string()),
    }]));
    let app = detect_http_router(state);

    let response = app
        .oneshot(Request::builder().uri("/healthz").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let json: Value = serde_json::from_slice(&body)?;
    assert_eq!(json["status"], "ok");
    assert_eq!(json["components"]["bridges"]["status"], "degraded");
    assert_eq!(json["components"]["bridges"]["degraded"], 1);
    Ok(())
}

#[tokio::test]
async fn metrics_endpoint_renders_bridge_gauges() -> Result<(), Box<dyn std::error::Error>> {
    let state = IngestState::from_config(
        default_config_path(),
        config_with_strategy("dns_exfiltration")?,
    )?;
    let metrics = state
        .current_prometheus_metrics()
        .ok_or("prometheus metrics should be enabled")?;
    metrics.observe_bridge_health(
        "generic-json-primary",
        "generic_json",
        true,
        7,
        2,
        Some(3.5),
    );
    let app = detect_http_router(state);

    let response = app
        .oneshot(Request::builder().uri("/metrics").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    let metrics_body = String::from_utf8(body.to_vec())?;
    assert!(
        metrics_body.contains(
            "swarm_bridge_events_processed{bridge=\"generic-json-primary\",source_id=\"generic_json\"} 7"
        ) || metrics_body.contains(
            "swarm_bridge_events_processed{source_id=\"generic_json\",bridge=\"generic-json-primary\"} 7"
        )
    );
    assert!(
        metrics_body.contains(
            "swarm_bridge_lag_seconds{bridge=\"generic-json-primary\",source_id=\"generic_json\"} 3.5"
        ) || metrics_body.contains(
            "swarm_bridge_lag_seconds{source_id=\"generic_json\",bridge=\"generic-json-primary\"} 3.5"
        )
    );
    Ok(())
}
