//! The console's two daemon reads. Both are GETs and neither appears on
//! `PERCH_DAEMON_WRITES` in `crate::perch::daemon_client`, which is the whole
//! non-GET surface (INV-01). Neither takes a path from the renderer: the route
//! is a `&'static str` constant in this file.

use serde::Deserialize;
use tauri::State;

use crate::app_state::AppState;
use crate::perch::daemon_client::{
    daemon_response_error, daemon_url, fetch_admitted_issuers, hold_list_query, perch_daemon_get,
    route, DaemonRoute, PerchAdmittedIssuers,
};

const ROUTE_REVIEWED: &str = "/v1/operator/findings/reviewed";
const ROUTE_POLICY: &str = "/v1/operator/policy";
const ROUTE_LIST_HOLDS: &str = "/v1/response/holds";
const ROUTE_GET_HOLD: &str = "/v1/response/holds/{hold_id}";

/// The default page the console asks for. Below the daemon's own 1000 ceiling
/// on purpose: a queue that needs a second page is a queue whose depth alarm
/// has long since fired, and `truncated` in the answer says so honestly.
const HOLD_PAGE: usize = 200;
const ROUTE_LIST_CONTAINMENTS: &str = "/v1/operator/containment/leases";
const ROUTE_EVASION_COVERAGE: &str = "/v2/api/evasion/coverage";
/// The tuning report an operator can read lives on the daemon's `/v2/api`,
/// not on `swarmctl serve`'s `/v1/operator/status`.
const ROUTE_OPERATOR_STATUS: &str = "/v2/api/runtime/status";

/// The daemon's honest review window: findings it has already ruled on, so the
/// console can show what its own verdicts did.
///
/// `since_ms` and `limit` are the only two knobs; both are numbers, so the
/// query string this builds carries nothing the renderer could shape into a
/// path.
#[tauri::command]
pub async fn perch_reviewed_findings(
    since_ms: Option<i64>,
    limit: Option<usize>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut path = ROUTE_REVIEWED.to_string();
    let query: Vec<String> = [
        since_ms.map(|s| format!("since_ms={s}")),
        limit.map(|l| format!("limit={l}")),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !query.is_empty() {
        path.push('?');
        path.push_str(&query.join("&"));
    }
    let r = perch_daemon_get(
        &state,
        &DaemonRoute {
            template: ROUTE_REVIEWED,
            path,
        },
    )
    .await?;
    if r.status != 200 {
        return Err(format!(
            "daemon answered {}: {}",
            r.status,
            r.body["message"].as_str().unwrap_or("")
        ));
    }
    Ok(r.body)
}

/// The admitted bridge identities and the lane channel ids (D-FC-2).
///
/// Unauthenticated on the daemon side — public keys and lane ids only — so it
/// is sent without a bearer. Nothing from the keyring crosses IPC in the
/// answer; `daemon_url` is read here only to prove the console is configured
/// before the fetch reports a confusing transport error.
#[tauri::command]
pub async fn perch_admitted_issuers(
    state: State<'_, AppState>,
) -> Result<PerchAdmittedIssuers, String> {
    daemon_url(&state)?;
    fetch_admitted_issuers(&state).await
}

// ===========================================================================
// B2r — THE TWO HOLD READS. The reconciliation authority.
//
// The relay's `46010` notices and `26006` alarms are a hint that something
// changed; these two answers are what a hold IS. Where they disagree the
// console renders the daemon's answer and says so, which is why neither of
// these commands swallows a status: a daemon that cannot answer must produce a
// refusal the queue can render, never an empty list. An empty list is a claim
// about the world.
// ===========================================================================

/// `GET /v1/response/holds` — every hold this daemon is holding, plus the two
/// facts the queue cannot render honestly without: `store_durable` and
/// `open_count`.
///
/// `include_terminal` is true: an expired or decided hold stays in the queue as
/// its own row, because a hold that vanished and a hold that expired look the
/// same to an operator who was not watching.
#[tauri::command]
pub async fn perch_list_holds(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let mut path = ROUTE_LIST_HOLDS.to_string();
    path.push_str(&hold_list_query(true, Some(HOLD_PAGE), None));
    let r = perch_daemon_get(
        &state,
        &DaemonRoute {
            template: ROUTE_LIST_HOLDS,
            path,
        },
    )
    .await?;
    if r.status != 200 {
        return Err(daemon_response_error(&r));
    }
    Ok(r.body)
}

/// `GET /v1/response/holds/{hold_id}` — one hold.
///
/// Also the W3-17 path out of a `409`: the console learns which decision won by
/// RE-READING this route, never from the conflict's error body.
///
/// The id is checked against the one implementation of the `hold_id` pattern
/// (`swarm_perch_wire::tags::is_opaque_hold_id`, R-3/W3-15) before a socket
/// opens, so a malformed id is a console-side refusal rather than a daemon 400
/// the operator has to interpret.
#[tauri::command]
pub async fn perch_get_hold(
    hold_id: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    if !swarm_perch_wire::tags::is_opaque_hold_id(&hold_id) {
        return Err("hold_id must match ^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$".to_string());
    }
    let r = perch_daemon_get(&state, &route(ROUTE_GET_HOLD, &[("hold_id", &hold_id)])?).await?;
    if r.status != 200 {
        return Err(daemon_response_error(&r));
    }
    Ok(r.body)
}

/// Store the daemon base URL and this operator's credential in the OS keyring.
///
/// The direction matters: values travel INTO the process here and never back
/// out. There is no command that reads either of them, which is what makes
/// INV-22 checkable rather than merely intended. Debug builds seed the same
/// keys from the environment at startup (D-FC-4); this is the path a Settings
/// surface will use.
#[tauri::command]
pub async fn perch_configure_daemon(
    base_url: String,
    credential: String,
    _state: State<'_, AppState>,
) -> Result<(), String> {
    let base_url = base_url.trim();
    let credential = credential.trim();
    if base_url.is_empty() || credential.is_empty() {
        return Err(
            "the daemon base URL and the operator credential are both required".to_string(),
        );
    }
    if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
        return Err("the daemon base URL must be an http:// or https:// origin".to_string());
    }
    let store = crate::secret_store::SecretStore::shared(crate::app_state::keyring_service());
    store.store(crate::perch::daemon_client::PERCH_DAEMON_URL_KEY, base_url)?;
    store.store(
        crate::perch::daemon_client::PERCH_DAEMON_BEARER_KEY,
        credential,
    )
}

/// `GET /v1/operator/containment/leases` — every containment lease the daemon
/// still lists as open.
///
/// A 503 is returned to the caller as a typed error rather than an empty list:
/// "no containment lease store is configured" and "nothing is contained" are
/// different facts, and a board that rendered them the same would tell an
/// operator the world is clear when nothing is watching it.
///
/// # Errors
///
/// The daemon's own message when it answers anything but 200, and the
/// transport error when it cannot be reached — both already redacted.
#[tauri::command]
pub async fn perch_list_containments(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let r = perch_daemon_get(
        &state,
        &DaemonRoute {
            template: ROUTE_LIST_CONTAINMENTS,
            path: ROUTE_LIST_CONTAINMENTS.to_string(),
        },
    )
    .await?;
    if r.status != 200 {
        return Err(daemon_response_error(&r));
    }
    Ok(r.body)
}

/// `GET /v2/api/evasion/coverage` — what the detectors deliberately do NOT see.
///
/// Served whole and unsummarized. Each gap carries the rationale its author
/// wrote, and the console renders that prose rather than a paraphrase: a
/// summary would be the console asserting a limit it did not measure.
///
/// # Errors
///
/// The daemon's own message on any non-200, and the transport error when it
/// cannot be reached.
#[tauri::command]
pub async fn perch_evasion_coverage(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let r = perch_daemon_get(
        &state,
        &DaemonRoute {
            template: ROUTE_EVASION_COVERAGE,
            path: ROUTE_EVASION_COVERAGE.to_string(),
        },
    )
    .await?;
    if r.status != 200 {
        return Err(daemon_response_error(&r));
    }
    Ok(r.body)
}

/// The triple `/policy` evaluates. All three or none; the daemon refuses a
/// partial one with a 400 and this command forwards that word.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyTripleInput {
    pub threat_class: String,
    pub severity: String,
    pub action: String,
}

/// `GET /v1/operator/policy[?threat_class=&severity=&action=]` — the rules in
/// file order, and the daemon's own evaluation of the triple when one is given.
#[tauri::command]
pub async fn perch_policy(
    triple: Option<PolicyTripleInput>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let mut path = ROUTE_POLICY.to_string();
    if let Some(triple) = triple {
        for (name, value) in [
            ("threat_class", &triple.threat_class),
            ("severity", &triple.severity),
            ("action", &triple.action),
        ] {
            if value.is_empty()
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(format!(
                    "policy triple field `{name}` must be a slug, got {value:?}"
                ));
            }
        }
        path.push_str(&format!(
            "?threat_class={}&severity={}&action={}",
            triple.threat_class, triple.severity, triple.action
        ));
    }
    let r = perch_daemon_get(
        &state,
        &DaemonRoute {
            template: ROUTE_POLICY,
            path,
        },
    )
    .await?;
    if r.status != 200 {
        return Err(format!(
            "daemon answered {}: {}",
            r.status,
            r.body["message"].as_str().unwrap_or("")
        ));
    }
    Ok(r.body)
}

/// `GET /v2/api/runtime/status` — the daemon's own status page, of which the
/// tuning bench reads `alert_tuning` and `false_positive_tracking`. The route
/// answers a page; this returns its first item, which is the runtime.
#[tauri::command]
pub async fn perch_operator_status(
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let r = perch_daemon_get(
        &state,
        &DaemonRoute {
            template: ROUTE_OPERATOR_STATUS,
            path: ROUTE_OPERATOR_STATUS.to_string(),
        },
    )
    .await?;
    if r.status != 200 {
        return Err(daemon_response_error(&r));
    }
    Ok(match r.body.get("data").and_then(|d| d.as_array()) {
        Some(items) if !items.is_empty() => items[0].clone(),
        _ => r.body,
    })
}
