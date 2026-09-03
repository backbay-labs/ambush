// Target path in BUZZ: desktop/src-tauri/src/perch_marker_guard.rs
// (this skeleton file keeps its original name; the Buzz-side module is named
// for what it guards, not for the one command the first draft guarded.)
//
// INV-29's implementation.
//
// ── WHAT THE FIRST DRAFT GOT WRONG, AND HOW IT WAS CAUGHT ──────────────────
//
// The first draft called this guard on the first line of `sign_event`
// (BUZZ desktop/src-tauri/src/commands/identity.rs:107-135) and stopped there,
// on the reasoning that `sign_event` is the renderer's arbitrary signer. That
// reasoning is true and incomplete: `sign_event` is not the only
// renderer-reachable path to a signature over renderer-chosen bytes.
//
//   `send_channel_message` (BUZZ desktop/src-tauri/src/commands/messages.rs:409)
//   is a separate `#[tauri::command]` the renderer calls for EVERY message. It
//   takes `channel_id`, an arbitrary `content: String` and `kind: Option<u32>`;
//   it reads the operator's key with `state.signing_keys()` at :445, builds
//   through `events::build_message` at :505, signs inside
//   `submit_event_at_created_at` at :527 and POSTs the event to the relay's
//   `/events`. Nothing in that path consulted the first draft's gate. So a
//   renderer bug -- or a compromised renderer -- publishes a
//   `<!-- swarm:verdict:v1 -->` kind:9 card into a case channel signed by the
//   operator's own key: the exact identity the admission rule (INV-15) treats as
//   authoritative for verdict cards, fabricating the one artifact the product
//   exists to produce.
//
//   Worse in detail: `build_message` is handed `content.trim()`
//   (messages.rs:505), which strips the leading whitespace the first draft's
//   own test relied on to make a marker un-sniffable. A gate placed BEFORE that
//   trim would sign `" <!-- swarm:verdict:v1 -->"` as harmless and the relay
//   would carry `"<!-- swarm:verdict:v1 -->"`, which the renderer parses as a
//   card. Placement therefore has to be after every transform the content
//   undergoes, not before.
//
// ── THE PLACEMENT, AND WHY IT IS THE COMPLETE ONE ──────────────────────────
//
// A forged card only matters once it reaches a relay. Buzz already has a
// fail-closed guard at every relay-bound egress boundary, with its boundary
// list written down and a test that fails the build when a ninth appears:
// `crate::egress_guard` (desktop/src-tauri/src/egress_guard.rs:1-58, table at
// :7-17) and `egress_guard_tests.rs`'s `events_url_inventory_is_fully_guarded`
// (:371-380), which scans every `.rs` under `src-tauri/src` and compares each
// file's `/events` URL-construction count AND its guard-call count against a
// site-granular inventory. `[V]` -- all counts in this file were re-measured
// against BUZZ @ eed74bde2.
//
// So this guard is wired at EXACTLY the boundaries `egress_guard` is wired at,
// and `perch_marker_guard_call_sites_match_egress_guard` (in the test sibling)
// asserts that set equality file by file. Two consequences worth stating:
//
//   1. A NEW submission path fails `events_url_inventory_is_fully_guarded`
//      first -- an existing, in-tree test nobody has to remember -- and then
//      fails this one. The completeness of this guard rides on a completeness
//      test that already exists and is already enforced.
//   2. The guard reads the FINAL signed event: `event.kind` and
//      `event.content`, after `content.trim()` and after every builder. There
//      is no gap between what is checked and what the relay stores.
//
// The eight egress sites, measured (`egress_guard::assert_no_key_backup*`
// occurrences per file, excluding the guard module and its tests):
//
//     src/relay.rs                              2   boundaries 2, 4
//     src/relay/submit.rs                       1   boundaries 1 + 3 (shared funnel)
//     src/huddle/pipeline.rs                    1   boundary 5
//     src/commands/team_snapshot.rs             1   boundary 6
//     src/commands/personas/snapshot/import.rs  1   boundary 7
//     src/native_websocket.rs                   2   boundary 8 (text + binary frames)
//
// Plus ONE site that is not an egress boundary and is guarded anyway:
//
//     src/commands/identity.rs                  1   `sign_event`, pre-sign
//
// `sign_event` hands signed JSON back to the RENDERER; the renderer may then
// publish it over the native websocket (boundary 8) or hold it. Guarding it
// pre-sign means the refusal happens before `state.signing_keys()` is read at
// identity.rs:115, so a refusal never touches the key, and the renderer gets a
// typed error instead of a signature it must be trusted to discard.
//
// ── WHAT THIS DOES NOT CLAIM ───────────────────────────────────────────────
//
//   It does not stop a compromised renderer signing an ordinary `kind:9` case
//   message. That is the product. It stops the renderer minting a governance
//   artifact. INV-01 and the two-legged write are what stop a forged card from
//   causing anything to happen: leg 2 is a separate POST to the daemon, which
//   re-derives authority from scratch.
//
//   It does not cover a marker published by a process that is not this one --
//   the bridge, `buzz-cli`, a raw `POST /events` with the operator's key. Those
//   are outside the Tauri process and outside any client-side gate; the relay
//   fork and the admission rule are what bound them.
//
// One added line at each of seven sites; the logic lives here. `identity.rs` is
// 790 lines `[V]` and `relay/submit.rs` is 125 `[V]`, so both take a line
// without approaching the 1000-line ratchet.

/// `kind:46010` -- `KIND_WORKFLOW_APPROVAL_REQUESTED`, the one stored kind the
/// relay fork admits (`BUZZ crates/buzz-core/src/kind.rs:578`) `[V]`. The
/// daemon-fed bridge publishes it; this process never does.
const KIND_WORKFLOW_APPROVAL_REQUESTED: u16 = 46010;

/// One sentence, said the same way everywhere. It names the alternative,
/// because a refusal that does not is a bug report.
pub const PERCH_SIGN_REFUSAL: &str =
    "refused: a governance artifact cannot be signed through the generic signer. \
     Use perch_record_verdict, which builds the card from daemon-fetched hold state.";

/// True when `content`'s first line is exactly an `ambush:<slug>:v<n>` marker.
///
/// This must agree, in both directions, with the renderer's
/// `parseAmbushMarker` (17-COMPONENT-SPECS.md section 3.4): line 0 only,
/// `trimEnd()` and never `trimStart()`, any slug, any version. Anything the
/// renderer will treat as a card, this refuses; anything it will not, this
/// signs. Disagreement in either direction is a defect -- see the test named
/// `the_gate_matches_the_renderers_parse_exactly`.
///
/// The `trimStart` asymmetry is only safe because the guard runs on the FINAL
/// content. `send_channel_message` calls `content.trim()` before building
/// (messages.rs:505); a guard running before that transform would see a leading
/// space the relay never stores.
fn first_line_is_ambush_marker(content: &str) -> bool {
    let line0 = content.split('\n').next().unwrap_or("").trim_end();
    let Some(inner) = line0
        .strip_prefix("<!--")
        .and_then(|rest| rest.strip_suffix("-->"))
    else {
        return false;
    };
    let inner = inner.trim();
    let Some(rest) = inner.strip_prefix("ambush:") else {
        return false;
    };
    let Some((slug, version)) = rest.rsplit_once(":v") else {
        return false;
    };
    !slug.is_empty()
        && slug.chars().all(|c| c.is_ascii_lowercase() || c == '-')
        && !version.is_empty()
        && version.chars().all(|c| c.is_ascii_digit())
}

/// Refuse to sign or publish a governance artifact through a generic path.
///
/// Deliberately narrow: it refuses `kind:46010` outright and refuses any kind
/// whose first line is an `ambush:*:v<n>` marker. Every other kind and every
/// other `kind:9` message passes exactly as before -- a gate that broke
/// reactions or DMs would be reverted within a day, and then the hole is open
/// again.
///
/// `context` names the boundary, matching `egress_guard`'s convention, so a
/// refusal in a bug report says which of the seven sites fired.
pub fn perch_marker_guard(kind: u16, content: &str, context: &'static str) -> Result<(), String> {
    if kind == KIND_WORKFLOW_APPROVAL_REQUESTED || first_line_is_ambush_marker(content) {
        return Err(format!("blocked {context}: {PERCH_SIGN_REFUSAL}"));
    }
    Ok(())
}

/// The pure predicate, without the boundary context. Kept as its own function
/// because the agreement test compares it against the renderer's parse and a
/// formatted prefix would be noise there.
pub fn perch_sign_gate(kind: u16, content: &str) -> Result<(), String> {
    if kind == KIND_WORKFLOW_APPROVAL_REQUESTED || first_line_is_ambush_marker(content) {
        return Err(PERCH_SIGN_REFUSAL.to_string());
    }
    Ok(())
}

/// Boundary form for the five sites that hold an already-signed `nostr::Event`.
///
/// Placed beside `egress_guard::assert_no_key_backup_bytes` at each of them, so
/// the two guards are wired and unwired together and the parity test can assert
/// it. Reads the event the relay will actually store.
///
/// Not compiled in this skeleton (no `nostr` dependency here); the real module
/// takes `&nostr::Event` and reads `event.kind.as_u16()` and `&event.content`.
#[cfg(feature = "perch-boundary")]
pub fn assert_no_perch_marker_event(
    event: &nostr::Event,
    context: &'static str,
) -> Result<(), String> {
    perch_marker_guard(event.kind.as_u16(), &event.content, context)
}

/// Boundary form for `native_websocket::send_message`, which holds a frame, not
/// an event. A renderer-signed `["EVENT", {…}]` frame is the one publish path
/// that never touches a Rust builder, so the frame text is parsed for an EVENT
/// envelope and the guard runs on its `kind` and `content`. A frame that is not
/// a well-formed EVENT is passed through untouched -- this guard's job is
/// markers, not framing.
#[cfg(feature = "perch-boundary")]
pub fn assert_no_perch_marker_frame(text: &str, context: &'static str) -> Result<(), String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Ok(());
    };
    let Some(array) = value.as_array() else {
        return Ok(());
    };
    if array.first().and_then(|v| v.as_str()) != Some("EVENT") {
        return Ok(());
    }
    // ["EVENT", <event>] from a client; ["EVENT", <sub-id>, <event>] from a
    // relay. Only the first shape is ever sent by this process, but reading
    // both costs nothing and a future framing change should not silently
    // disable the guard.
    for candidate in array.iter().skip(1) {
        let Some(object) = candidate.as_object() else {
            continue;
        };
        let kind = object.get("kind").and_then(serde_json::Value::as_u64);
        let content = object.get("content").and_then(serde_json::Value::as_str);
        if let (Some(kind), Some(content)) = (kind, content) {
            perch_marker_guard(kind as u16, content, context)?;
        }
    }
    Ok(())
}

#[path = "identity_perch_gate_tests.rs"]
#[cfg(test)]
mod tests;
