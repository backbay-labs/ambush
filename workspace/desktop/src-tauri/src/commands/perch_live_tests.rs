//! The console half of the live walking skeleton, driven headless.
//!
//! The desktop's hold surface goes through Tauri commands holding the daemon
//! bearer and the operator's signing key, so a browser cannot drive it. This
//! test drives the SAME commands through Tauri's own IPC layer — argument
//! deserialization, the command bodies, leg-1 signing and relay publish, the
//! leg-2 POST, outcome mapping and the re-read — against a running relay and
//! daemon. The React tree above these commands runs against the mock bridge,
//! which now refuses any shape these commands would refuse.
//!
//! Ignored by default and skipped without `PERCH_LIVE_DAEMON_URL`; run with
//!
//! ```text
//! AMBUSH_DEV_KEYRING_SERVICE=ambush-desktop-dev.perch-live-driver \
//! AMBUSH_PRIVATE_KEY=<operator nsec> PERCH_LIVE_DAEMON_URL=http://127.0.0.1:9090 \
//! PERCH_LIVE_DAEMON_BEARER=<token> PERCH_LIVE_VERDICT_PUBKEY=<hex> \
//! cargo test --lib live_tests -- --ignored --nocapture --test-threads=1
//! ```
//!
//! The keyring service MUST be set in the shell, not here: it is read once
//! per process, and the driver must own a keychain blob of its own rather
//! than the app's. The value takes the worktree form the app accepts —
//! `ambush-desktop-dev.<scope>` — and the driver refuses any other.

use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, MockRuntime, INVOKE_KEY};
use tauri::webview::InvokeRequest;

/// sha256 of the well-known dev operator material; the daemon's hold-dev
/// profile pins the Ed25519 public half as `verdict_public_key_hex`.
const DEV_OPERATOR_MATERIAL: &str = "ambush-perch-dev-operator-v1";

struct Live {
    daemon_url: String,
    bearer: String,
    relay_url: String,
    verdict_public_key_hex: String,
    operator_id: String,
}

fn live() -> Option<Live> {
    let daemon_url = std::env::var("PERCH_LIVE_DAEMON_URL").ok()?;
    Some(Live {
        daemon_url,
        bearer: std::env::var("PERCH_LIVE_DAEMON_BEARER").unwrap_or_default(),
        relay_url: std::env::var("PERCH_LIVE_RELAY_URL")
            .unwrap_or_else(|_| "ws://localhost:3000".to_string()),
        verdict_public_key_hex: std::env::var("PERCH_LIVE_VERDICT_PUBKEY").unwrap_or_default(),
        operator_id: std::env::var("PERCH_LIVE_OPERATOR_ID")
            .unwrap_or_else(|_| "console".to_string()),
    })
}

/// The driver's own keychain blob: daemon settings plus the dev operator's
/// Ed25519 seed, exactly the entries the app mints or seeds for itself.
fn seed_keyring(live: &Live) {
    use crate::perch::daemon_client::{
        PERCH_DAEMON_BEARER_KEY, PERCH_DAEMON_URL_KEY, PERCH_OPERATOR_ID_KEY,
    };
    let service = crate::app_state::keyring_service();
    assert!(
        service.contains("live-driver"),
        "AMBUSH_DEV_KEYRING_SERVICE must name the driver's own blob, got {service}"
    );
    let store = crate::secret_store::SecretStore::shared(service);
    let seed = crate::commands::perch_verdict::sha256_hex(DEV_OPERATOR_MATERIAL.as_bytes());
    for (key, value) in [
        (PERCH_DAEMON_URL_KEY, live.daemon_url.as_str()),
        (PERCH_DAEMON_BEARER_KEY, live.bearer.as_str()),
        (PERCH_OPERATOR_ID_KEY, live.operator_id.as_str()),
        (
            crate::commands::perch_verdict::OPERATOR_ED25519_SECRET_KEY,
            seed.as_str(),
        ),
    ] {
        store
            .store(key, value)
            .expect("the driver's keyring accepts a write");
    }
}

fn webview(live: &Live) -> tauri::WebviewWindow<MockRuntime> {
    let state = crate::app_state::build_app_state();
    *state.relay_url_override.lock().expect("override lock") = Some(live.relay_url.clone());
    let app = mock_builder()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            crate::commands::perch_verdict_hold::perch_operator_identity,
            crate::commands::perch_reads::perch_list_holds,
            crate::commands::perch_reads::perch_get_hold,
            crate::commands::perch_verdict_hold::perch_record_hold_verdict,
            super::perch_decide_hold,
            crate::commands::perch_verdict_hold::perch_publish_verdict_update,
            crate::commands::perch_reads::perch_admitted_issuers,
            crate::commands::perch_reads::perch_reviewed_findings,
            super::perch_mint_incident,
            crate::commands::perch_verdict::perch_record_verdict,
            super::perch_finding_feedback
        ])
        .build(crate::app_context())
        .expect("app builds headless on the mock runtime");
    tauri::WebviewWindowBuilder::new(&app, "main", tauri::WebviewUrl::default())
        .build()
        .expect("mock webview builds")
}

/// One IPC round trip, shaped exactly as the renderer's `invokeTauri` sends it.
/// The webview's LOCAL origin, which is what every capability's context
/// names: `tauri://localhost` except on Windows and Android. A request from
/// any other origin is remote to the ACL and is refused before the command.
fn local_origin() -> tauri::Url {
    if cfg!(any(windows, target_os = "android")) {
        "http://tauri.localhost"
    } else {
        "tauri://localhost"
    }
    .parse()
    .expect("the local webview origin parses")
}

fn call(
    webview: &tauri::WebviewWindow<MockRuntime>,
    cmd: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value, String> {
    get_ipc_response(
        webview,
        InvokeRequest {
            cmd: cmd.to_string(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: local_origin(),
            body: InvokeBody::Json(body),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_string(),
        },
    )
    .map(|b| {
        b.deserialize::<serde_json::Value>()
            .expect("a JSON response")
    })
    .map_err(|e| {
        e.as_str()
            .map(str::to_string)
            .unwrap_or_else(|| e.to_string())
    })
}

/// The telemetry fixtures to ingest when the daemon holds fewer than two
/// notified holds: `PERCH_LIVE_INGEST_EVENTS`, comma-separated paths.
fn ingest_files() -> Vec<String> {
    std::env::var("PERCH_LIVE_INGEST_EVENTS")
        .unwrap_or_default()
        .split(',')
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.trim().to_string())
        .collect()
}

/// `POST /v1/ingest/events` for each fixture — the same documented route the
/// recipe's step 13 uses; ingest is unauthenticated on the dev profile.
///
/// Every `event_id` and `host_id` is suffixed per run and the timestamps are
/// now: telemetry the daemon has already escalated on cannot cross its
/// threshold again, so an unchanged fixture produces no new hold.
fn ingest_telemetry(live: &Live) {
    let run = format!(
        "r{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() % 100_000)
            .unwrap_or(0)
    );
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    for path in ingest_files() {
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let mut events: serde_json::Value = serde_json::from_str(&text).expect("fixture JSON");
        for (i, event) in events
            .as_array_mut()
            .expect("an array of events")
            .iter_mut()
            .enumerate()
        {
            for key in ["event_id", "host_id"] {
                if let Some(v) = event[key].as_str().map(|v| format!("{v}-{run}")) {
                    event[key] = serde_json::Value::String(v);
                }
            }
            event["timestamp"] = serde_json::json!(now_ms + i as i64);
        }
        let body = events.to_string();
        let status = tauri::async_runtime::block_on(async {
            reqwest::Client::new()
                .post(format!("{}/v1/ingest/events", live.daemon_url))
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .expect("ingest request")
                .status()
        });
        assert!(status.is_success(), "ingest of {path} answered {status}");
    }
}

fn notified_holds(webview: &tauri::WebviewWindow<MockRuntime>) -> Vec<serde_json::Value> {
    let holds = call(webview, "perch_list_holds", serde_json::json!({})).expect("holds list");
    let mut notified: Vec<serde_json::Value> = holds["holds"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|h| h["state"] == "notified")
        .collect();
    // Newest first: a hold on a scope this stack has already acted on can
    // draw the daemon's per-scope rate limit, which is a legitimate
    // `refused_late` but not the path this driver is here to walk.
    notified.sort_by_key(|h| std::cmp::Reverse(h["held_at_ms"].as_i64().unwrap_or(0)));
    notified
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The newest notified hold not yet decided by this run, producing one from
/// the telemetry fixtures when none is open. Each ingest is unique per call,
/// so a decision never waits on a hold the previous decision consumed.
fn next_notified_hold(
    webview: &tauri::WebviewWindow<MockRuntime>,
    live: &Live,
    decided: &[String],
) -> serde_json::Value {
    let pick = |holds: Vec<serde_json::Value>| {
        holds.into_iter().find(|h| {
            !decided
                .iter()
                .any(|d| d == h["hold_id"].as_str().unwrap_or_default())
        })
    };
    if let Some(hold) = pick(notified_holds(webview)) {
        return hold;
    }
    // Escalation is edge-triggered on the pheromone concentration, so telemetry
    // ingested while the last crossing is still decaying raises no new hold;
    // a second unique ingest after a pause usually does.
    for _attempt in 0..2 {
        ingest_telemetry(live);
        for _ in 0..60 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            if let Some(hold) = pick(notified_holds(webview)) {
                return hold;
            }
        }
    }
    let seen = call(webview, "perch_list_holds", serde_json::json!({}))
        .map(|h| {
            h["holds"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|h| format!("{}={}", h["hold_id"].as_str().unwrap_or("?"), h["state"]))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|e| e);
    panic!(
        "no notified hold within 60 s of ingesting {}; the daemon lists: [{seen}]; decided this run: {decided:?}",
        ingest_files().join(", ")
    );
}

/// The renderer's two legs for one hold, forwarding leg 1 verbatim into leg 2.
fn decide(
    webview: &tauri::WebviewWindow<MockRuntime>,
    hold_id: &str,
    decision: &str,
    rationale: &str,
) -> (serde_json::Value, serde_json::Value) {
    let leg1 = call(
        webview,
        "perch_record_hold_verdict",
        serde_json::json!({"input": {"holdId": hold_id, "decision": decision, "rationale": rationale}}),
    )
    .expect("leg 1 publishes");
    for key in [
        "nostr_intent_event_id",
        "decided_at_ms",
        "signature",
        "hold_id",
        "case_channel",
    ] {
        assert!(!leg1[key].is_null(), "leg 1 lacks {key}: {leg1}");
    }
    assert_eq!(leg1["hold_id"], hold_id);
    let leg2 = call(
        webview,
        "perch_decide_hold",
        serde_json::json!({"input": {
            "holdId": hold_id,
            "decision": decision,
            "nostrIntentEventId": leg1["nostr_intent_event_id"],
            "decidedAtMs": leg1["decided_at_ms"],
            "signature": leg1["signature"],
            "rationale": rationale,
            "armedAtMs": null
        }}),
    )
    .expect("leg 2 reaches the daemon");
    (leg1, leg2)
}

/// The operator's card as the relay stored it, read back the way the
/// console reads a case channel: kind 9, `h` = the case, this author.
fn relay_card(
    live: &Live,
    case_channel: &str,
    author_hex: &str,
    event_id: &str,
) -> serde_json::Value {
    let base = live
        .relay_url
        .replace("ws://", "http://")
        .replace("wss://", "https://");
    let filter = serde_json::json!([{"kinds": [9], "#h": [case_channel], "authors": [author_hex], "limit": 50}]);
    let body: serde_json::Value = tauri::async_runtime::block_on(async {
        reqwest::Client::new()
            .post(format!("{base}/query"))
            .header("X-Pubkey", author_hex)
            .json(&filter)
            .send()
            .await
            .expect("relay query")
            .json()
            .await
            .expect("relay query body")
    });
    body.as_array()
        .and_then(|events| events.iter().find(|e| e["id"] == event_id).cloned())
        .unwrap_or_else(|| panic!("card {event_id} not in case {case_channel}: {body}"))
}

#[test]
#[ignore = "needs a running relay and daemon; see the module doc"]
fn the_console_half_of_the_walking_skeleton_against_the_live_stack() {
    let Some(live) = live() else {
        eprintln!("PERCH_LIVE_DAEMON_URL unset; nothing to drive");
        return;
    };
    seed_keyring(&live);
    let webview = webview(&live);

    // The key the daemon pins is the key this console signs with.
    let identity =
        call(&webview, "perch_operator_identity", serde_json::json!({})).expect("identity");
    assert_eq!(
        identity["public_key_hex"], live.verdict_public_key_hex,
        "the console's Ed25519 key is not the one the hold-dev profile pins: {identity}"
    );
    let operator = crate::app_state::build_app_state()
        .signing_keys()
        .expect("AMBUSH_PRIVATE_KEY is the operator's nsec")
        .public_key()
        .to_hex();

    let mut evidence = Vec::new();
    let mut decided: Vec<String> = Vec::new();

    // Grant first, on the freshest scope: the daemon's per-scope rate limit
    // counts actions per minute, and a refusal is an action too.
    for (decision, rationale) in [
        ("grant", "walking skeleton: contain it"),
        ("refuse", "walking skeleton: not our host"),
    ] {
        let hold = next_notified_hold(&webview, &live, &decided);
        let hold_id = hold["hold_id"].as_str().expect("hold id").to_string();
        decided.push(hold_id.clone());
        if decision == "grant" {
            // The daemon's per-scope rate limit counts the hold creations of
            // the ingest that raised this hold as actions in the same minute;
            // a grant inside that minute is a legitimate `refused_late`, but
            // the executed path is the one this driver is here to walk.
            let age_ms = now_ms() - hold["held_at_ms"].as_i64().unwrap_or(0);
            if age_ms < 65_000 {
                std::thread::sleep(std::time::Duration::from_millis((65_000 - age_ms) as u64));
            }
        }
        let (leg1, leg2) = decide(&webview, &hold_id, decision, rationale);
        assert_eq!(leg2["replayed"], false);
        // The daemon's word is one of the six. `refused_late` names its rule —
        // seen live as `policy.scope_rate_limit` on a scope this stack had
        // already acted on five times in a minute — and is carried, not hidden.
        let late = leg2["outcome"] == "refused_late";
        if late {
            assert!(
                leg2["rule"].is_string(),
                "a late refusal names its rule: {leg2}"
            );
            assert_eq!(leg2["dispatched"], false);
        } else {
            assert_eq!(leg2["outcome"], "dispatched", "leg 2 outcome: {leg2}");
            assert_eq!(
                leg2["dispatched"],
                decision == "grant",
                "dispatched flag: {leg2}"
            );
            if decision == "grant" {
                assert!(
                    !leg2["receipt_id"].is_null(),
                    "a grant carries a receipt: {leg2}"
                );
            } else {
                assert!(
                    leg2["receipt_id"].is_null(),
                    "a refusal carries no receipt: {leg2}"
                );
            }
        }

        // The daemon's record, re-read through the console's own read command.
        let detail = call(
            &webview,
            "perch_get_hold",
            serde_json::json!({"holdId": hold_id}),
        )
        .expect("hold re-read");
        let hold_now = if detail["hold"].is_object() {
            &detail["hold"]
        } else {
            &detail
        };
        let expected_state = if decision == "grant" && !late {
            "executed"
        } else {
            "refused"
        };
        assert_eq!(
            hold_now["state"], expected_state,
            "hold after leg 2: {detail}"
        );

        // The same leg 2 again is a replay, never a second decision.
        let again = call(
            &webview,
            "perch_decide_hold",
            serde_json::json!({"input": {
                "holdId": hold_id, "decision": decision,
                "nostrIntentEventId": leg1["nostr_intent_event_id"],
                "decidedAtMs": leg1["decided_at_ms"], "signature": leg1["signature"],
                "rationale": rationale, "armedAtMs": null
            }}),
        )
        .expect("replay");
        assert_eq!(again["replayed"], true, "replay: {again}");

        // The relay holds the operator's own card in the case channel.
        let case_channel = leg1["case_channel"].as_str().expect("case channel");
        let card = relay_card(
            &live,
            case_channel,
            &operator,
            leg1["nostr_intent_event_id"].as_str().expect("id"),
        );
        assert_eq!(
            card["content"].as_str().and_then(|c| c.lines().next()),
            Some("<!-- swarm:verdict:v1 -->")
        );

        evidence.push(serde_json::json!({
            "hold_id": hold_id, "decision": decision, "case_channel": case_channel,
            "leg1_event_id": leg1["nostr_intent_event_id"], "decided_at_ms": leg1["decided_at_ms"],
            "leg2": leg2, "state_after": hold_now["state"], "decision_record": hold_now["decision"],
        }));
    }
    // The conflict is a RACE, not a late second decision: the console's own
    // leg 1 refuses to publish an intent for a hold that is already decided
    // ("this hold is `refused` and cannot be decided"). So two consoles each
    // publish an intent card while the hold is still open; the daemon takes
    // the first leg 2 and answers the second with a 409, which the command
    // turns into `superseded` — the winning intent and its word from a
    // re-read — and the losing console publishes the supersession update
    // against its own card.
    let contested = next_notified_hold(&webview, &live, &decided);
    let contested_id = contested["hold_id"].as_str().expect("hold id").to_string();
    decided.push(contested_id.clone());
    let first = call(
        &webview,
        "perch_record_hold_verdict",
        serde_json::json!({"input": {"holdId": contested_id, "decision": "refuse", "rationale": "walking skeleton: the first console"}}),
    )
    .expect("the first console's leg 1 publishes");
    let second = call(
        &webview,
        "perch_record_hold_verdict",
        serde_json::json!({"input": {"holdId": contested_id, "decision": "grant", "rationale": "walking skeleton: the second console"}}),
    )
    .expect("the second console's leg 1 publishes while the hold is open");
    // Leg 2 carries leg 1's rationale verbatim: the signature covers its
    // hash, and the daemon answered `422 Invalid signature` to a leg 2 whose
    // rationale differed — a tampered rationale never reaches a decision.
    let leg2_for = |leg1: &serde_json::Value, decision: &str, rationale: &str| {
        serde_json::json!({"input": {
            "holdId": contested_id,
            "decision": decision,
            "nostrIntentEventId": leg1["nostr_intent_event_id"],
            "decidedAtMs": leg1["decided_at_ms"],
            "signature": leg1["signature"],
            "rationale": rationale,
            "armedAtMs": null
        }})
    };
    let tampered = call(
        &webview,
        "perch_decide_hold",
        leg2_for(&first, "refuse", "a different rationale"),
    )
    .expect_err("a leg 2 whose rationale is not the signed one is refused");
    assert!(
        tampered.contains("422"),
        "the daemon refuses a tampered rationale: {tampered}"
    );
    let won = call(
        &webview,
        "perch_decide_hold",
        leg2_for(&first, "refuse", "walking skeleton: the first console"),
    )
    .expect("the first leg 2 reaches the daemon");
    assert_eq!(
        won["outcome"], "dispatched",
        "the first decision stands: {won}"
    );
    let lost = call(
        &webview,
        "perch_decide_hold",
        leg2_for(&second, "grant", "walking skeleton: the second console"),
    )
    .expect("the second leg 2 is answered, not errored");
    assert_eq!(
        lost["outcome"], "superseded",
        "a different decision after the first: {lost}"
    );
    let winner = first["nostr_intent_event_id"]
        .as_str()
        .expect("winner")
        .to_string();
    assert_eq!(
        lost["superseded_by"], winner,
        "the winner is the first intent: {lost}"
    );
    assert_eq!(
        lost["winning_decision"], "refuse",
        "the winning word is the first decision: {lost}"
    );
    assert_eq!(lost["dispatched"], false);
    let update = call(
        &webview,
        "perch_publish_verdict_update",
        serde_json::json!({"input": {
            "holdId": contested_id,
            "ownIntentEventId": second["nostr_intent_event_id"],
            "supersededBy": winner,
            "supersededAtMs": lost["decided_at_ms"]
        }}),
    )
    .expect("the supersession update publishes");
    let update_id = update["nostr_intent_event_id"]
        .as_str()
        .expect("update id")
        .to_string();
    let case_channel = first["case_channel"].as_str().expect("case");
    let stored = relay_card(&live, case_channel, &operator, &update_id);
    assert_eq!(
        stored["content"].as_str().and_then(|c| c.lines().next()),
        Some("<!-- swarm:verdict:v1 -->")
    );
    let conflict = serde_json::json!({
        "hold_id": contested_id,
        "first_intent_event_id": first["nostr_intent_event_id"],
        "second_intent_event_id": second["nostr_intent_event_id"],
        "tampered_rationale_refusal": tampered,
        "first_leg2": won,
        "second_leg2": lost,
        "update_event_id": update_id,
    });

    println!(
        "PERCH_LIVE_EVIDENCE {}",
        serde_json::json!({
            "operator_nostr_pubkey": operator,
            "operator_ed25519": identity,
            "decisions": evidence,
            "conflict": conflict,
        })
    );
}

// ── The finding path: First card's walking skeleton, Task 24 steps 4 and 5 ──

const FINDING_MARKER: &str = "<!-- swarm:finding:v1 -->";

/// Finding cards on the relay by admitted authors, newest first, read the
/// way `perch_record_verdict` reads them: through the app's own relay query.
fn admitted_finding_cards(
    webview: &tauri::WebviewWindow<MockRuntime>,
    issuers: &[String],
) -> Vec<nostr::Event> {
    use tauri::Manager;
    let state = webview.state::<crate::app_state::AppState>();
    let filter = serde_json::json!({"kinds": [9], "authors": issuers, "limit": 200});
    let mut cards: Vec<nostr::Event> =
        tauri::async_runtime::block_on(crate::relay::query_relay(&state, &[filter]))
            .expect("relay query")
            .into_iter()
            .filter(|e| e.content.starts_with(FINDING_MARKER))
            .collect();
    cards.sort_by_key(|e| std::cmp::Reverse(e.created_at.as_secs()));
    cards
}

/// The card's JSON block, as the wire crate delimits it.
fn card_json(event: &nostr::Event) -> serde_json::Value {
    let parts = swarm_perch_wire::marker::parse_content(&event.content).expect("a parseable card");
    serde_json::from_str(parts.json).expect("the card's JSON block parses")
}

fn reviewed_entries_for(
    webview: &tauri::WebviewWindow<MockRuntime>,
    finding_id: &str,
) -> Vec<serde_json::Value> {
    let body = call(
        webview,
        "perch_reviewed_findings",
        serde_json::json!({"sinceMs": null, "limit": 500}),
    )
    .expect("reviewed findings");
    body["reviewed"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r["finding_id"] == finding_id)
        .collect()
}

#[test]
#[ignore = "needs a running relay and daemon; see the module doc"]
fn the_finding_path_of_the_walking_skeleton_against_the_live_stack() {
    use tauri::Manager;
    let Some(live) = live() else {
        eprintln!("PERCH_LIVE_DAEMON_URL unset; nothing to drive");
        return;
    };
    seed_keyring(&live);
    let webview = webview(&live);
    let state = webview.state::<crate::app_state::AppState>();
    let keys = state
        .signing_keys()
        .expect("AMBUSH_PRIVATE_KEY is the operator's nsec");
    let operator = keys.public_key().to_hex();

    // The admitted set comes from the daemon, and the card must be by one of them.
    let admitted =
        call(&webview, "perch_admitted_issuers", serde_json::json!({})).expect("issuers");
    let issuers: Vec<String> = admitted["issuers"]
        .as_array()
        .expect("issuers array")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    let cards = admitted_finding_cards(&webview, &issuers);
    let card = cards
        .first()
        .expect("one finding card by an admitted author on the relay")
        .clone();
    let lane = card
        .tags
        .iter()
        .find_map(|t| {
            let v = t.as_slice();
            (v.first().map(String::as_str) == Some("h")).then(|| v[1].clone())
        })
        .expect("the card is in a lane channel");
    // The JSON block is a B6 spine envelope; the finding card is its `fact`.
    let envelope = card_json(&card);
    assert_eq!(
        envelope["schema"], "swarm.spine.envelope.v1",
        "card block: {envelope}"
    );
    let body = envelope["fact"].clone();
    let finding_id = body["finding"]["finding_id"]
        .as_str()
        .or_else(|| body["locator"]["finding_id"].as_str())
        .expect("the card names its finding")
        .to_string();

    // E — promote. `hunt_id` is derived, as first-card.md records.
    let mint = call(
        &webview,
        "perch_mint_incident",
        serde_json::json!({"input": {
            "findingId": finding_id,
            "huntId": format!("swarm:finding:{finding_id}"),
            "eventId": body["locator"]["event_id"],
            "strategyId": body["locator"]["strategy_id"],
            "threatClass": body["finding"]["threat_class"],
            "severity": body["finding"]["severity"],
            "createdAtMs": body["emitted_at_ms"],
            "summary": swarm_perch_wire::marker::parse_content(&card.content).expect("card").human_line,
            "hostId": body["locator"]["host_id"],
            "correlationKeys": []
        }}),
    )
    .expect("E mints the incident");
    let incident_id = mint["incident_id"]
        .as_str()
        .expect("incident id")
        .to_string();
    let case_id = mint["case_id"].as_str().expect("case id").to_string();
    // The daemon keeps ONE review per finding and incident and updates it in
    // place, so an earlier run of this driver may already be on record: the
    // claim below is that the record's timestamp moves only on the
    // acknowledged leg 2.
    let latest_review_at = |webview: &tauri::WebviewWindow<MockRuntime>| {
        reviewed_entries_for(webview, &finding_id)
            .iter()
            .filter_map(|r| r["reviewed_at_ms"].as_i64())
            .max()
            .unwrap_or(0)
    };
    let reviewed_before = latest_review_at(&webview);

    // D, leg 1 — the signed intent card, built from the relay's admitted card.
    let rationale = "walking skeleton: looked like the backup job";
    let leg1 = call(
        &webview,
        "perch_record_verdict",
        serde_json::json!({"input": {
            "findingCardId": card.id.to_hex(),
            "caseChannel": case_id,
            "incidentId": incident_id,
            "decision": "dismiss",
            "rationale": rationale
        }}),
    )
    .expect("leg 1 publishes");
    let verdict_event_id = leg1["nostr_intent_event_id"]
        .as_str()
        .expect("verdict id")
        .to_string();
    assert_eq!(leg1["finding_id"], finding_id);
    assert_eq!(
        latest_review_at(&webview),
        reviewed_before,
        "leg 1 alone changes no daemon record"
    );

    // Control: the daemon is unreachable between the legs. Leg 2 fails, leg 1
    // is not re-signed, and the retry carries the SAME verdict event id.
    let store = crate::secret_store::SecretStore::shared(crate::app_state::keyring_service());
    store
        .store(
            crate::perch::daemon_client::PERCH_DAEMON_URL_KEY,
            "http://127.0.0.1:9",
        )
        .expect("redirect");
    let feedback = serde_json::json!({
        "findingId": finding_id, "incidentId": incident_id, "action": "dismiss",
        "verdictEventId": verdict_event_id, "reason": rationale
    });
    let down = call(&webview, "perch_finding_feedback", feedback.clone())
        .expect_err("leg 2 cannot reach a dead port");
    store
        .store(
            crate::perch::daemon_client::PERCH_DAEMON_URL_KEY,
            &live.daemon_url,
        )
        .expect("restore");
    assert_eq!(
        latest_review_at(&webview),
        reviewed_before,
        "a failed leg 2 records nothing"
    );
    let leg2 = call(&webview, "perch_finding_feedback", feedback)
        .expect("leg 2 reaches the daemon on retry");
    let reviewed = reviewed_entries_for(&webview, &finding_id);
    assert!(
        latest_review_at(&webview) > reviewed_before,
        "the daemon acknowledgement is what changes the report: {reviewed:?}"
    );
    let newest = reviewed
        .iter()
        .max_by_key(|r| r["reviewed_at_ms"].as_i64().unwrap_or(0))
        .expect("one review");
    assert_eq!(newest["action"], "dismiss");
    assert_eq!(newest["analyst_id"], live.operator_id);

    // Control: the same marker under an unadmitted key stays prose. The
    // operator's own key is not a bridge identity, so a card it signs is not
    // one `perch_record_verdict` will build a verdict from.
    let forged = nostr::EventBuilder::new(nostr::Kind::Custom(9), card.content.clone())
        .tags([nostr::Tag::parse(["h", lane.as_str()]).expect("h tag")])
        .sign_with_keys(&keys)
        .expect("the forgery signs");
    let submitted = tauri::async_runtime::block_on(crate::relay::submit_signed_event_at_with_keys(
        &forged,
        &state,
        &crate::relay::relay_api_base_url_with_override(&state),
        &keys,
    ))
    .expect("the relay admits any authenticated key");
    assert!(
        submitted.accepted,
        "forged card refused by the relay: {}",
        submitted.message
    );
    let refused = call(
        &webview,
        "perch_record_verdict",
        serde_json::json!({"input": {
            "findingCardId": forged.id.to_hex(),
            "caseChannel": case_id,
            "incidentId": incident_id,
            "decision": "dismiss",
            "rationale": "must not be accepted"
        }}),
    )
    .expect_err("an unadmitted signer's card never enters the action flow");
    assert!(
        refused.contains("not an admitted bridge identity"),
        "got: {refused}"
    );

    println!(
        "PERCH_LIVE_EVIDENCE_FINDING {}",
        serde_json::json!({
            "operator_nostr_pubkey": operator,
            "card_event_id": card.id.to_hex(), "card_author": card.pubkey.to_hex(), "lane": lane,
            "finding_id": finding_id, "incident_id": incident_id, "case_id": case_id, "mint_created": mint["created"],
            "verdict_event_id": verdict_event_id, "leg1_decided_at_ms": leg1["decided_at_ms"],
            "leg2_down_error": down, "leg2": leg2, "reviewed": newest, "reviews_before": reviewed_before,
            "forged_card_event_id": forged.id.to_hex(), "forged_refusal": refused,
        })
    );
}
