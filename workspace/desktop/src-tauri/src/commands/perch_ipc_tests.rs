//! The hold commands' argument shape through Tauri's OWN IPC layer.
//!
//! The mapping tests and the TypeScript guards each pin half of the contract.
//! This is the layer between them: a request shaped exactly as the renderer
//! sends it, deserialized by Tauri's invoke pipeline rather than by a test
//! calling the function. Sent flat, Tauri refuses with "missing required key
//! input" before the command runs — the defect the client carried through
//! forty-five green E2E specs, because the mock accepted whatever it was
//! handed. A wrapped request reaches the command's own validation, which is
//! how the positive case is told apart from the negative one.

use tauri::ipc::{CallbackFn, InvokeBody, InvokeResponseBody};
use tauri::test::{get_ipc_response, mock_builder, MockRuntime, INVOKE_KEY};
use tauri::webview::InvokeRequest;

fn webview() -> tauri::WebviewWindow<MockRuntime> {
    let app = mock_builder()
        .manage(crate::app_state::build_app_state())
        .invoke_handler(tauri::generate_handler![
            super::perch_decide_hold,
            crate::commands::perch_verdict_hold::perch_record_hold_verdict
        ])
        // The app's own generated context, as Tauri's `get_ipc_response`
        // example does: `mock_context` carries no capabilities, so under it
        // every app command is "not allowed" and the test would prove nothing
        // about argument shapes.
        .build(crate::app_context())
        .expect("app builds headless on the mock runtime");
    tauri::WebviewWindowBuilder::new(&app, "main", tauri::WebviewUrl::default())
        .build()
        .expect("mock webview builds")
}

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

fn invoke(
    webview: &tauri::WebviewWindow<MockRuntime>,
    cmd: &str,
    body: serde_json::Value,
) -> Result<InvokeResponseBody, serde_json::Value> {
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
}

/// The fields as the renderer's `perchDecideHold` sends them, minus the wrapper.
fn decide_fields() -> serde_json::Value {
    serde_json::json!({
        "holdId": "hold_0123456789",
        "decision": "refuse",
        "nostrIntentEventId": "ab".repeat(32),
        "decidedAtMs": 1_700_000_000_000_i64,
        // Leg 1's signature is forwarded verbatim, and it serializes snake_case
        // (`WireDetachedSignature` carries no rename).
        "signature": {
            "algorithm": "ed25519",
            "key_id": "kid",
            "public_key_hex": "cd".repeat(32),
            "signature_hex": "ef".repeat(64)
        },
        "rationale": null,
        "armedAtMs": null
    })
}

fn error_text(err: serde_json::Value) -> String {
    err.as_str()
        .map(str::to_string)
        .unwrap_or_else(|| err.to_string())
}

#[test]
fn a_flat_decide_request_is_refused_by_tauri_before_the_command_runs() {
    let webview = webview();
    let err = invoke(&webview, "perch_decide_hold", decide_fields())
        .expect_err("flat arguments are an error");
    let text = error_text(err);
    assert!(
        text.contains("missing required key input"),
        "expected Tauri's own argument error, got: {text}"
    );
}

#[test]
fn a_flat_record_request_is_refused_the_same_way() {
    let webview = webview();
    let err = invoke(
        &webview,
        "perch_record_hold_verdict",
        serde_json::json!({"holdId": "hold_0123456789", "decision": "refuse", "rationale": null}),
    )
    .expect_err("flat arguments are an error");
    let text = error_text(err);
    assert!(text.contains("missing required key input"), "got: {text}");
}

#[test]
fn a_wrapped_record_request_reaches_the_command_s_own_validation() {
    // A hold id the wire rule rejects: the command's first check, before any
    // daemon or keyring access. Reaching it proves Tauri parsed `{ input }`.
    let webview = webview();
    let err = invoke(
        &webview,
        "perch_record_hold_verdict",
        serde_json::json!({"input": {"holdId": "x", "decision": "refuse", "rationale": null}}),
    )
    .expect_err("a malformed hold id is refused");
    let text = error_text(err);
    assert!(text.starts_with("holdId must match"), "got: {text}");
    assert!(!text.contains("missing required key"), "got: {text}");
}
