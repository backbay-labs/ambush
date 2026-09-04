//! The console's two daemon reads. Both are GETs and neither appears on
//! `PERCH_DAEMON_WRITES` in `crate::perch::daemon_client`, which is the whole
//! non-GET surface (INV-01). Neither takes a path from the renderer: the route
//! is a `&'static str` constant in this file.

use tauri::State;

use crate::app_state::AppState;
use crate::perch::daemon_client::{
    daemon_response_error, daemon_url, fetch_admitted_issuers, hold_list_query, perch_daemon_get,
    route, DaemonRoute, PerchAdmittedIssuers,
};

const ROUTE_REVIEWED: &str = "/v1/operator/findings/reviewed";
const ROUTE_LIST_HOLDS: &str = "/v1/response/holds";
const ROUTE_GET_HOLD: &str = "/v1/response/holds/{hold_id}";

/// The default page the console asks for. Below the daemon's own 1000 ceiling
/// on purpose: a queue that needs a second page is a queue whose depth alarm
/// has long since fired, and `truncated` in the answer says so honestly.
const HOLD_PAGE: usize = 200;

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
