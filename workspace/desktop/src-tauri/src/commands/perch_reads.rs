//! The console's two daemon reads. Both are GETs and neither appears on
//! `PERCH_DAEMON_WRITES` in `crate::perch::daemon_client`, which is the whole
//! non-GET surface (INV-01). Neither takes a path from the renderer: the route
//! is a `&'static str` constant in this file.

use tauri::State;

use crate::app_state::AppState;
use crate::perch::daemon_client::{
    daemon_url, fetch_admitted_issuers, perch_daemon_get, DaemonRoute, PerchAdmittedIssuers,
};

const ROUTE_REVIEWED: &str = "/v1/operator/findings/reviewed";

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
