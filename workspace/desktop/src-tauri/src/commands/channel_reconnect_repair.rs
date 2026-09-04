use tauri::State;

use crate::{app_state::AppState, relay::query_relay};

const MAX_REPAIR_PAGE_LIMIT: u32 = 500;
// Kind 39005 is deliberately absent: `ambush_core::kind::is_relay_only_kind(39005)` is
// true, the relay synthesizes thread summaries at query time and never stores them, and
// this filter sets neither `top_level` nor `include_summaries`, so a repair query could
// never return one. Summaries are recovered by re-issuing the window request, not here.
const CHANNEL_REPAIR_KINDS: [u32; 17] = [
    5, 7, 9, 9005, 40001, 40002, 40003, 40008, 40099, 40100, 45001, 45003, 46010, 48100, 48101,
    48102, 48103,
];

fn build_channel_reconnect_repair_filter(
    channel_id: &str,
    since: u64,
    limit: u32,
    until: Option<u64>,
    before_id: Option<&str>,
) -> Result<serde_json::Value, String> {
    uuid::Uuid::parse_str(channel_id).map_err(|_| "invalid channel id".to_string())?;
    if limit == 0 || limit > MAX_REPAIR_PAGE_LIMIT {
        return Err(format!(
            "limit must be between 1 and {MAX_REPAIR_PAGE_LIMIT}"
        ));
    }
    if before_id.is_some() && until.is_none() {
        return Err("before_id requires until".to_string());
    }
    if let Some(event_id) = before_id {
        if event_id.len() != 64 || !event_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("before_id must be a 64-character hex event id".to_string());
        }
    }

    let mut filter = serde_json::Map::new();
    filter.insert("#h".to_string(), serde_json::json!([channel_id]));
    filter.insert("kinds".to_string(), serde_json::json!(CHANNEL_REPAIR_KINDS));
    filter.insert("since".to_string(), serde_json::json!(since));
    filter.insert("limit".to_string(), serde_json::json!(limit));
    if let Some(value) = until {
        filter.insert("until".to_string(), serde_json::json!(value));
    }
    if let Some(value) = before_id {
        filter.insert("before_id".to_string(), serde_json::json!(value));
    }
    Ok(serde_json::Value::Object(filter))
}

/// Fetch one lossless keyset page for reconnect repair using a fixed channel-event filter.
#[tauri::command]
pub async fn get_channel_reconnect_repair(
    channel_id: String,
    since: u64,
    limit: u32,
    until: Option<u64>,
    before_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<serde_json::Value>, String> {
    let filter = build_channel_reconnect_repair_filter(
        &channel_id,
        since,
        limit,
        until,
        before_id.as_deref(),
    )?;
    Ok(query_relay(&state, &[filter])
        .await?
        .iter()
        .filter_map(|event| serde_json::to_value(event).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_filter_is_fixed_and_keyset_scoped() {
        let id = "ab".repeat(32);
        let filter = build_channel_reconnect_repair_filter(
            "270f6caf-0feb-4055-93f3-cdbeb567ff28",
            100,
            500,
            Some(200),
            Some(&id),
        )
        .expect("valid filter");
        assert_eq!(
            filter["#h"],
            serde_json::json!(["270f6caf-0feb-4055-93f3-cdbeb567ff28"])
        );
        assert_eq!(filter["kinds"], serde_json::json!(CHANNEL_REPAIR_KINDS));
        assert_eq!(filter["since"], 100);
        assert_eq!(filter["limit"], 500);
        assert_eq!(filter["until"], 200);
        assert_eq!(filter["before_id"], id);
        assert!(filter.get("top_level").is_none());
        assert!(filter.get("include_summaries").is_none());
        assert!(filter.get("include_aux").is_none());
    }

    /// 01-DESIGN §8 / 11-PLAN-GROUND Task 3: a reconnect must repair the
    /// perch case-channel kinds a relay actually stores — held actions
    /// (46010) and the case canvas (40100) — or a console that dropped its
    /// socket during a hold would render a stale case. Thread summaries
    /// (39005) are excluded: the relay synthesizes them at query time and
    /// never stores them, so repairing them here is a guaranteed no-op (see
    /// the constant's comment).
    #[test]
    fn repair_kinds_cover_perch_case_channel_kinds() {
        for kind in [46010u32, 40100] {
            assert!(
                CHANNEL_REPAIR_KINDS.contains(&kind),
                "kind {kind} must be repaired on reconnect"
            );
        }
        assert!(
            !CHANNEL_REPAIR_KINDS.contains(&39005),
            "kind 39005 is relay-synthesized and never stored; repairing it cannot return a row"
        );
    }

    #[test]
    fn repair_filter_rejects_renderer_escape_hatches() {
        assert!(build_channel_reconnect_repair_filter("not-a-channel", 0, 1, None, None).is_err());
        assert!(build_channel_reconnect_repair_filter(
            "270f6caf-0feb-4055-93f3-cdbeb567ff28",
            0,
            0,
            None,
            None
        )
        .is_err());
        assert!(build_channel_reconnect_repair_filter(
            "270f6caf-0feb-4055-93f3-cdbeb567ff28",
            0,
            1,
            None,
            Some("bad")
        )
        .is_err());
    }
}
