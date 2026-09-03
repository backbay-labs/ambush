#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Route tests for the perch operator router. The bearer is in-memory
//! (`OperatorAuthState::for_test`), so nothing here touches process env.

use super::super::auth::OperatorAuthState;
use super::{PERCH_ROUTER_PATHS, perch_operator_router_for_test};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header::AUTHORIZATION, header::CONTENT_TYPE};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use swarm_core::config::{OperatorScope, SwarmConfig};
use swarm_ingest_runtime::ingest::IngestState;
use swarm_ingest_runtime::perch_ops::mint::{IncidentMintRequest, mint_incident};
use swarm_spine::IncidentStore;
use tower::ServiceExt;

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A per-test temp root so every repo-relative store a handler opens lands
/// under the OS temp dir rather than the checked-out crate root.
fn temp_root() -> PathBuf {
    let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "swarm-perch-http-{}-{}-{counter}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn perch_config() -> (SwarmConfig, PathBuf) {
    let root = temp_root();
    let mut config = super::super::tests::operator_config();
    config.evolution.paths.evolution_population_results_dir =
        root.join("evolution-population").display().to_string();
    (config, root)
}

fn app_with_scopes(scopes: Vec<OperatorScope>, token: &str) -> (Router, IngestState) {
    let (config, root) = perch_config();
    let state = IngestState::from_config(root.join("inline"), config.clone()).unwrap();
    let auth = OperatorAuthState::for_test("local-operator", scopes, token);
    (
        perch_operator_router_for_test(&config, state.clone(), auth),
        state,
    )
}

fn app() -> (Router, IngestState) {
    app_with_scopes(
        vec![OperatorScope::Read, OperatorScope::Approve],
        "secret-token",
    )
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

fn mint_body(finding_id: &str) -> serde_json::Value {
    serde_json::json!({
        "finding_id": finding_id,
        "hunt_id": "hunt-evt-1",
        "event_id": "hunt-evt-1",
        "strategy_id": "suspicious_process_tree",
        "threat_class": "execution",
        "severity": "HIGH",
        "created_at_ms": 1_700_000_000_000_i64,
        "summary": "Office-spawned encoded PowerShell",
        "host_id": "host-ops-1",
        "correlation_keys": []
    })
}

fn post_json(uri: &str, token: &str, body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header("x-swarm-schema-version", "1")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

/// RFC 4122 text form: 36 chars, dashes at 8/13/18/23, lowercase hex elsewhere.
fn looks_like_uuid(value: &str) -> bool {
    value.len() == 36
        && value.char_indices().all(|(index, ch)| match index {
            8 | 13 | 18 | 23 => ch == '-',
            _ => ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
        })
}

#[tokio::test]
async fn incidents_mints_a_case_id_and_replays_on_the_same_finding() {
    let (app, state) = app();
    let minted = app
        .clone()
        .oneshot(post_json(
            "/v1/operator/incidents",
            "secret-token",
            &mint_body("f-1"),
        ))
        .await
        .unwrap();
    assert_eq!(minted.status(), StatusCode::OK);
    let body = json_body(minted).await;
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["created"], true);
    let case_id = body["case_id"].as_str().unwrap().to_string();
    assert!(looks_like_uuid(&case_id), "{case_id}");
    assert_eq!(
        body["incident_id"],
        format!("incident:perch-case:{case_id}")
    );
    assert_eq!(body["degraded"], serde_json::json!([]));
    assert_eq!(
        body["record"]["trigger_strategy_id"],
        "suspicious_process_tree"
    );
    assert!(
        state
            .current_incident_store()
            .load_by_incident_id(body["incident_id"].as_str().unwrap())
            .unwrap()
            .is_some(),
        "the route wrote the daemon's live incident store"
    );

    let replayed = app
        .oneshot(post_json(
            "/v1/operator/incidents",
            "secret-token",
            &mint_body("f-1"),
        ))
        .await
        .unwrap();
    assert_eq!(replayed.status(), StatusCode::OK);
    let body = json_body(replayed).await;
    assert_eq!(body["created"], false);
    assert_eq!(body["case_id"], case_id);
}

#[tokio::test]
async fn incidents_refuses_a_client_supplied_case_id() {
    let (app, _state) = app();
    let mut body = mint_body("f-1");
    body["case_id"] = serde_json::json!("9499a6e2-8872-453b-80d9-dafc6fc7fc69");
    let refused = app
        .oneshot(post_json("/v1/operator/incidents", "secret-token", &body))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let body = json_body(refused).await;
    assert_eq!(body["error"], "bad_request");
    assert!(
        body["message"].as_str().unwrap().contains("case_id"),
        "{body}"
    );
}

#[tokio::test]
async fn incidents_names_a_missing_host_as_degraded() {
    let (app, _state) = app();
    let mut body = mint_body("f-1");
    body.as_object_mut().unwrap().remove("host_id");
    let minted = app
        .oneshot(post_json("/v1/operator/incidents", "secret-token", &body))
        .await
        .unwrap();
    assert_eq!(minted.status(), StatusCode::OK);
    let body = json_body(minted).await;
    assert_eq!(body["created"], true);
    assert_eq!(
        body["degraded"],
        serde_json::json!(["host_exclusion_unreachable"])
    );
}

#[tokio::test]
async fn incidents_requires_the_approve_scope() {
    let (app, _state) = app_with_scopes(vec![OperatorScope::Read], "read-only");
    let forbidden = app
        .clone()
        .oneshot(post_json(
            "/v1/operator/incidents",
            "read-only",
            &mint_body("f-1"),
        ))
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    let body = json_body(forbidden).await;
    assert_eq!(body["error"], "forbidden");

    let unauthorized = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/operator/incidents")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&mint_body("f-1")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn reviewed_requires_a_bearer_and_answers_the_window() {
    let (app, _state) = app();
    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/findings/reviewed")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let wrong_token = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/operator/findings/reviewed")
                .header(AUTHORIZATION, "Bearer not-the-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_token.status(), StatusCode::UNAUTHORIZED);

    let ok = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/findings/reviewed?limit=10")
                .header(AUTHORIZATION, "Bearer secret-token")
                .header("x-swarm-schema-version", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let body = json_body(ok).await;
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["window_incident_count"], 0);
    assert_eq!(body["window_is_truncated"], false);
    assert!(body["window_oldest_incident_at_ms"].is_null());
    assert_eq!(body["store_durable"], false);
    assert!(body["reviewed"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn reviewed_refuses_a_principal_without_the_read_scope() {
    let (app, _state) = app_with_scopes(vec![OperatorScope::Approve], "approve-only");
    let forbidden = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/findings/reviewed")
                .header(AUTHORIZATION, "Bearer approve-only")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    let body = json_body(forbidden).await;
    assert_eq!(body["error"], "forbidden");
}

#[tokio::test]
async fn reviewed_rejects_a_malformed_query() {
    let (app, _state) = app();
    let bad = app
        .oneshot(
            Request::builder()
                .uri("/v1/operator/findings/reviewed?limit=lots")
                .header(AUTHORIZATION, "Bearer secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
}

fn feedback_body(incident_id: &str, verdict: &str) -> serde_json::Value {
    serde_json::json!({
        "action": "dismiss",
        "incident_id": incident_id,
        "verdict_event_id": verdict.repeat(32),
        "reason": "looked like the backup job"
    })
}

fn mint_request(finding_id: &str) -> IncidentMintRequest {
    serde_json::from_value(mint_body(finding_id)).unwrap()
}

#[tokio::test]
async fn feedback_records_the_principal_as_the_analyst_and_replays_on_the_verdict() {
    let (app, state) = app();
    let minted = mint_incident(&state, mint_request("f-1"), 1).unwrap();
    let recorded = app
        .clone()
        .oneshot(post_json(
            "/v1/operator/findings/f-1/feedback",
            "secret-token",
            &feedback_body(&minted.incident_id, "ab"),
        ))
        .await
        .unwrap();
    assert_eq!(recorded.status(), StatusCode::OK);
    let body = json_body(recorded).await;
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["analyst_id"], "local-operator");
    assert_eq!(body["finding_id"], "f-1");
    assert_eq!(body["incident_id"], minted.incident_id);
    assert_eq!(body["false_positive"], true);
    assert_eq!(body["replayed"], false);
    assert_eq!(
        body["feedback_id"],
        format!("perch-feedback:f-1:{}", "ab".repeat(32))
    );
    assert_eq!(body["outcome"]["substrate"]["status"], "suppressed");

    let record = state
        .current_incident_store()
        .load_by_incident_id(&minted.incident_id)
        .unwrap()
        .unwrap()
        .record;
    assert_eq!(record.feedback_audit_entries.len(), 1);
    assert_eq!(
        record.feedback_audit_entries[0].analyst_id,
        "local-operator"
    );
    assert_eq!(
        record.feedback_audit_entries[0].request_signature,
        "operator-bearer:local-operator"
    );
    assert_eq!(record.false_positive_measurements.len(), 1);
    assert_eq!(
        record.false_positive_measurements[0].analyst_id,
        "local-operator"
    );
    assert_eq!(
        record.false_positive_measurements[0].strategy_id,
        "suspicious_process_tree"
    );
    assert_eq!(
        record.false_positive_measurements[0].host_id.as_deref(),
        Some("host-ops-1")
    );

    let replayed = app
        .oneshot(post_json(
            "/v1/operator/findings/f-1/feedback",
            "secret-token",
            &feedback_body(&minted.incident_id, "ab"),
        ))
        .await
        .unwrap();
    assert_eq!(replayed.status(), StatusCode::OK);
    let body = json_body(replayed).await;
    assert_eq!(body["replayed"], true);
    assert_eq!(body["analyst_id"], "local-operator");
}

#[tokio::test]
async fn feedback_refuses_a_body_analyst_id() {
    let (app, state) = app();
    let minted = mint_incident(&state, mint_request("f-1"), 1).unwrap();
    let mut body = feedback_body(&minted.incident_id, "ab");
    body["analyst_id"] = serde_json::json!("mallory");
    let refused = app
        .oneshot(post_json(
            "/v1/operator/findings/f-1/feedback",
            "secret-token",
            &body,
        ))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let body = json_body(refused).await;
    assert_eq!(body["error"], "bad_request");
    assert!(
        body["message"].as_str().unwrap().contains("analyst_id"),
        "{body}"
    );
    let record = state
        .current_incident_store()
        .load_by_incident_id(&minted.incident_id)
        .unwrap()
        .unwrap()
        .record;
    assert!(
        record.feedback_audit_entries.is_empty(),
        "nothing was recorded"
    );
}

#[tokio::test]
async fn feedback_on_an_unknown_incident_or_finding_is_not_found() {
    let (app, state) = app();
    let missing = app
        .clone()
        .oneshot(post_json(
            "/v1/operator/findings/f-9/feedback",
            "secret-token",
            &feedback_body("incident:perch-case:nope", "ee"),
        ))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let body = json_body(missing).await;
    assert_eq!(body["error"], "not_found");
    assert_eq!(
        body["message"],
        "incident `incident:perch-case:nope` was not found"
    );

    let minted = mint_incident(&state, mint_request("f-3"), 1).unwrap();
    let wrong_member = app
        .oneshot(post_json(
            "/v1/operator/findings/f-not-a-member/feedback",
            "secret-token",
            &feedback_body(&minted.incident_id, "ff"),
        ))
        .await
        .unwrap();
    assert_eq!(wrong_member.status(), StatusCode::NOT_FOUND);
    let body = json_body(wrong_member).await;
    assert_eq!(body["error"], "not_found");
    assert!(
        body["message"].as_str().unwrap().contains("f-not-a-member"),
        "{body}"
    );
}

#[tokio::test]
async fn feedback_requires_the_approve_scope() {
    let (app, state) = app_with_scopes(vec![OperatorScope::Read], "read-only");
    let minted = mint_incident(&state, mint_request("f-1"), 1).unwrap();
    let forbidden = app
        .oneshot(post_json(
            "/v1/operator/findings/f-1/feedback",
            "read-only",
            &feedback_body(&minted.incident_id, "ab"),
        ))
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    let body = json_body(forbidden).await;
    assert_eq!(body["error"], "forbidden");
}

#[test]
fn perch_paths_are_disjoint_from_the_containment_router() {
    assert_eq!(PERCH_ROUTER_PATHS.len(), 3);
    for path in PERCH_ROUTER_PATHS {
        assert!(path.starts_with("/v1/operator/"), "{path}");
        assert!(!path.starts_with("/v1/operator/containment"), "{path}");
    }
}

#[test]
fn the_path_inventory_matches_the_mounted_routes() {
    // W3-28: the inventory describes mounted handlers, never the future. Every
    // `.route(PERCH_ROUTER_PATHS[i], …)` in the router source must be indexed,
    // and every index must be mounted exactly once.
    let source = include_str!("mod.rs");
    let mounted: Vec<usize> = source
        .match_indices(".route(")
        .map(|(offset, _)| {
            let rest = &source[offset..];
            let start = rest
                .find("PERCH_ROUTER_PATHS[")
                .expect("route uses the inventory")
                + 19;
            let end = start + rest[start..].find(']').unwrap();
            rest[start..end].parse().unwrap()
        })
        .collect();
    let mut sorted = mounted.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(mounted.len(), PERCH_ROUTER_PATHS.len());
    assert_eq!(sorted, (0..PERCH_ROUTER_PATHS.len()).collect::<Vec<_>>());
}
