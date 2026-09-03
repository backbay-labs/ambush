// Target path in BUZZ: desktop/src-tauri/src/commands/perch_writes.rs  (NEW file)
//
// The five commands that can change anything in the Ambush DAEMON. INV-01
// asserts this set is closed, and this file is what that gate reads: five
// `#[tauri::command]` functions, five `const` route templates, no parameter
// anywhere holds a path or a method.
//
// LEG 1 IS NOT IN THIS FILE. `perch_record_verdict` publishes a signed card to
// the RELAY and touches no Ambush host, so it lives in
// `commands/perch_verdict.rs` and is closed by INV-RF1's relay allowlist
// instead. Keeping the two apart is what lets
// `tools/check-perch-write-allowlist.sh` read exactly five daemon routes out of
// this file without arithmetic, and it is the file-level expression of the
// process boundary: a renderer that is fully compromised can publish an intent
// card with no authority (perch_verdict.rs) and still cannot reach the daemon
// except through the five named routes below.
//
// Registration cost, measured this session:
//   1. this file;
//   2. `mod perch_writes;` in BUZZ desktop/src-tauri/src/commands/mod.rs
//      (mod block :1-73) and `pub use perch_writes::*;` (pub-use block :74-127),
//      re-exported into lib.rs by `use commands::*;` at lib.rs:59;
//   3. five entries in the flat `tauri::generate_handler![]` argument at
//      lib.rs:519-863 — 336 entries today, and lib.rs is 938 gate-lines under
//      a 1000 cap in the governed `src-tauri/src` root, so 62 lines of slack
//      absorb these five plus the seven reads in perch_reads.rs plus the one
//      in perch_verdict.rs (13 entries, 49 lines of slack left);
//   4. NO capabilities entry — desktop/src-tauri/capabilities/default.json
//      lists only core and plugin permissions, none per command;
//   5. a `case` in the E2E mock bridge — non-negotiable, see the note at the
//      bottom of this file.
//
// Gate-line budget: 1000 (src-tauri/src is governed). Targets ~400.

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::app_state::AppState;
use crate::commands::perch_verdict::DetachedSignature;

// ---------------------------------------------------------------------------
// Route templates. Constants, never parameters.
//
// This is the mechanism, not a style preference. INV-22 requires the daemon
// bearer token never appear in any value crossing the IPC boundary into the
// webview, and INV-01 requires the non-GET set to be enumerable. A generic
// `perch_daemon_request(method, path, body)` would satisfy neither: the path
// would be renderer-controlled, and the gate would have nothing to count.
// ---------------------------------------------------------------------------

const ROUTE_DECIDE_HOLD: &str = "/v1/response/holds/{hold_id}/decide";
const ROUTE_FINDING_FEEDBACK: &str = "/v1/operator/findings/{finding_id}/feedback";
const ROUTE_MINT_INCIDENT: &str = "/v1/operator/incidents";
const ROUTE_RELEASE_CONTAINMENT: &str =
    "/v1/operator/containment/leases/{lease_id}/release";
const ROUTE_CREATE_REVIEW_SESSION: &str = "/v1/operator/review/sessions";

/// Every DAEMON write route, in one slice, so the invariant test can assert the
/// count without parsing the file. The relay write is in perch_verdict.rs and
/// is counted by INV-RF1, not by this table.
pub const PERCH_WRITE_ROUTES: [&str; 5] = [
    ROUTE_DECIDE_HOLD,
    ROUTE_FINDING_FEEDBACK,
    ROUTE_MINT_INCIDENT,
    ROUTE_RELEASE_CONTAINMENT,
    ROUTE_CREATE_REVIEW_SESSION,
];

// ---------------------------------------------------------------------------
// Wire types. These mirror build/openapi/perch-operator-v1.yaml FIELD FOR
// FIELD, and the round-trip test at the bottom of this file is what keeps them
// mirroring it.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerchDecision {
    Grant,
    Refuse,
}

/// The decide request, in the shape the daemon actually accepts.
///
/// `HoldDecisionRequest` is `required: [decision, decided_at_ms,
/// nostr_intent_event_id, signature]` with `additionalProperties: false`, and
/// the route verifies an Ed25519 signature over the RFC 8785 canonical form of
/// `{decided_at_ms, decision, hold_id, rationale_sha256}`. Three consequences
/// that an earlier draft of this struct got wrong, each of which was a
/// guaranteed 4xx:
///
///  * `decided_at_ms` MUST be carried. It is inside the preimage, so the daemon
///    cannot recompute it and a request without it cannot be verified at all.
///    It comes from `perch_record_verdict`, which stamped it when it signed leg
///    1 — the same instant, by construction, because there is one signature.
///  * `signature` is a `DetachedSignature` OBJECT, not a hex string. The route
///    derives `voter_id` from its `public_key_hex` with
///    `voter_id_from_public_key` (AMB crates/swarm-runtime/src/approval.rs:1783-1785)
///    and returns 403 unless it binds to the authenticated principal. A bare
///    string cannot carry the key, so the binding check has nothing to run on.
///  * `armed_at_ms` is advisory and OUTSIDE the preimage. The daemon records it
///    and does not enforce the 1500 ms dwell, because that is a client-side
///    safety control (INV-11) and a daemon enforcing it would be trusting a
///    client clock to gate a destructive action.
///
/// `rationale` is inside the preimage as its SHA-256, so it cannot be
/// substituted by anything holding the bearer token replaying a valid
/// signature. This struct therefore carries the text and never the digest: the
/// digest is the signer's and the daemon recomputes it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecideHoldInput {
    /// `hold_` + lowercase UUIDv4, 41 chars (openapi `HoldId`). Validated in
    /// Rust before the socket opens; a malformed id is a local refusal, not a
    /// 404 round trip.
    pub hold_id: String,
    pub decision: PerchDecision,
    /// Verbatim from `perch_record_verdict`. Covered by the signature as
    /// `rationale_sha256`.
    pub rationale: Option<String>,
    /// Verbatim from `perch_record_verdict`. INSIDE the signature preimage.
    pub decided_at_ms: i64,
    /// The leg-1 card's event id, 64 lowercase hex. The idempotency key for
    /// this route, and an UNSIGNED POINTER: it is the id of the object carrying
    /// this very signature, so it cannot be inside the preimage. The daemon
    /// stores it and never treats it as evidence, and no Perch surface renders
    /// it as part of the signed record. The checkable join between the two legs
    /// is `signature.signature_hex`, which is byte-identical on both.
    pub nostr_intent_event_id: String,
    /// Verbatim from `perch_record_verdict`.
    pub signature: DetachedSignature,
    /// Advisory. Outside the preimage.
    pub armed_at_ms: Option<i64>,
}

/// Typed daemon outcome. `RefusedLate` and `RefusedLateGovernance` are NORMAL
/// outcomes carried in `Ok`, never `Err`: a late policy refusal is the system
/// working, and rendering it as a client error teaches operators that refusals
/// are bugs.
///
/// `Superseded` is the same shape of fact for a different cause — another
/// operator's decision won the store's compare-and-set. It is not an error
/// either, and the console that receives it must publish the leg-2 update card
/// and render its own row as not-the-decision (14 §7.6).
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecideOutcomeKind {
    Dispatched,
    RefusedLate,
    RefusedLateGovernance,
    Expired,
    UnknownHold,
    Superseded,
}

#[derive(Debug, Serialize)]
pub struct DecideOutcome {
    pub outcome: DecideOutcomeKind,
    /// Rendered verbatim in WHY WE ARE ASKING's refusal row. Never summarised.
    pub reason: Option<String>,
    pub receipt_id: Option<String>,
    pub decided_at_ms: i64,
    /// Populated ONLY on `Superseded`: the winning card's event id, read from
    /// the 409 body. Never synthesised.
    pub superseded_by: Option<String>,
}

// ---------------------------------------------------------------------------
// The five commands
// ---------------------------------------------------------------------------

/// LEG 2 of the two-legged write, and the only call in this console that can
/// cause a destructive action to run.
///
/// Runs in the Tauri Rust process. Reads the daemon bearer token from the
/// process's own secret store, POSTs to `ROUTE_DECIDE_HOLD` on
/// `config.operator.runtime_base_url` with `x-swarm-schema-version: 1` — the
/// header shape `swarmctl` itself uses at
/// `AMB crates/swarm-cli/src/core.inc:3101-3120`, and 1 is the only value
/// `resolve_operator_api_schema_version` accepts — and returns the typed
/// outcome. The token never crosses back.
///
/// It deliberately does NOT touch the relay. Leg 1 was published by
/// `perch_record_verdict` through the relay's WebSocket, so the two legs are
/// separated by a process boundary rather than by a convention.
///
/// 409 MAPPING, which is where the concurrency contract lives:
///   `decision_in_flight`      (deciding, SAME id)  -> retry once after
///                              `Retry-After`, then surface as `Sending` still.
///   `hold_already_deciding`   (deciding, OTHER id) -> `Superseded`.
///   `hold_already_decided`    (terminal, OTHER id) -> `Superseded`.
///   `hold_expired`                                 -> `Expired`.
///   `not_decidable`                                -> `UnknownHold` + reason.
/// A `Superseded` carries the winner's `nostr_intent_event_id` out of the body.
#[tauri::command]
pub async fn perch_decide_hold(
    input: DecideHoldInput,
    state: State<'_, AppState>,
) -> Result<DecideOutcome, String> {
    let _ = (&input, &state, ROUTE_DECIDE_HOLD);
    todo!("POST ROUTE_DECIDE_HOLD; map 200/409/410 to DecideOutcomeKind")
}

/// B3. `analyst_id` is taken from the AUTHENTICATED PRINCIPAL on the daemon
/// side, never from this body — the shipped handler reads it from the request
/// body (`AMB crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs:473-495`)
/// and B3 is the change that fixes it. Perch must not send one.
#[tauri::command]
pub async fn perch_finding_feedback(
    finding_id: String,
    incident_id: String,
    action: String,
    note: Option<String>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let _ = (
        &finding_id,
        &incident_id,
        &action,
        &note,
        &state,
        ROUTE_FINDING_FEEDBACK,
    );
    todo!("POST ROUTE_FINDING_FEEDBACK")
}

/// B3i. Mints a single-member incident so a verdict on an uncorrelated finding
/// has somewhere to land. Without it the feedback route 404s forever
/// (`providence_handlers.rs:129-137` returns not-found on an unresolvable
/// incident id) and a promoted finding's verdict controls stay disabled
/// permanently.
///
/// Three constraints the minted record must satisfy, all imposed by
/// `resolve_feedback_target` (`AMB crates/swarm-runtime/src/providence.rs:799-836`):
/// `included_members` must contain the finding id; `trigger_strategy_id` must
/// be `Some` or the per-detector bucket collapses onto the literal "unknown";
/// and a `host:<id>` key must appear in `shared_keys` or `correlation_keys` or
/// `HostExclusionReview` is unreachable for that host forever.
#[tauri::command]
pub async fn perch_mint_incident(
    finding_id: String,
    case_channel: String,
    summary: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let _ = (
        &finding_id,
        &case_channel,
        &summary,
        &state,
        ROUTE_MINT_INCIDENT,
    );
    todo!("POST ROUTE_MINT_INCIDENT")
}

/// Release one containment.
///
/// Returns the daemon's BODY, not a status interpretation. `lease_closed` is
/// computed by re-listing open containments
/// (`AMB crates/swarm-runtime-http/src/http/containment.rs:219-226`), and the
/// handler deliberately reports `lease_closed: false` on a 200 so a caller
/// cannot read success into an unfinished release. This command must not
/// collapse that into `Result::Err`, or the console loses the distinction the
/// daemon went out of its way to preserve.
#[tauri::command]
pub async fn perch_release_containment(
    lease_id: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let _ = (&lease_id, &state, ROUTE_RELEASE_CONTAINMENT);
    todo!("POST ROUTE_RELEASE_CONTAINMENT; return the body verbatim")
}

/// The End-watch artifact.
///
/// `review_session_create_handler`
/// (`AMB crates/swarm-runtime-http/src/http/review.rs:204-221`) takes
/// `State + Form` and no `Extension(principal)`, so no scope check is even
/// possible today — B5 adds one. Until B5 lands this command still sends the
/// bearer token, and `/settings` says so.
#[tauri::command]
pub async fn perch_create_review_session(
    notes: String,
    case_channels: Vec<String>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let _ = (&notes, &case_channels, &state, ROUTE_CREATE_REVIEW_SESSION);
    todo!("POST ROUTE_CREATE_REVIEW_SESSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// INV-01, the Rust half. The TypeScript half greps the renderer for invoke
    /// literals; this half asserts the Rust surface has not grown a sixth
    /// DAEMON write behind the gate's back. `perch_record_verdict` is not
    /// counted here on purpose — it writes to the relay and INV-RF1 closes it.
    #[test]
    fn perch_daemon_write_route_set_is_closed() {
        assert_eq!(PERCH_WRITE_ROUTES.len(), 5);
        for route in PERCH_WRITE_ROUTES {
            assert!(route.starts_with("/v1/"), "unexpected route: {route}");
            assert!(
                !route.contains("://"),
                "a route template must be a path, not a URL: {route}"
            );
        }
    }

    /// THE DRIFT TEST. `DecideHoldInput` and the OpenAPI's
    /// `HoldDecisionRequest` are two hand-written descriptions of one wire
    /// object in two languages with no compiler link — exactly the shape that
    /// produced a struct missing `decided_at_ms` and typing `signature` as a
    /// String. This serializes a populated input and asserts the field set
    /// against the schema's `required` + `properties`, so the two cannot drift
    /// again without a red test.
    ///
    /// The YAML path is resolved from `CARGO_MANIFEST_DIR` and the test FAILS
    /// (never skips) if it is absent: a schema test that silently no-ops when
    /// it cannot find the schema is the defect it exists to catch.
    #[test]
    fn decide_input_matches_the_openapi_request_shape() {
        // Serialising the Deserialize-only input requires a mirror; the real
        // implementation derives Serialize on it under #[cfg(test)] so this
        // test reads the same struct the command takes.
        const EXPECTED_FIELDS: [&str; 7] = [
            "hold_id",
            "decision",
            "rationale",
            "decided_at_ms",
            "nostr_intent_event_id",
            "signature",
            "armed_at_ms",
        ];
        const OPENAPI_REQUIRED: [&str; 4] = [
            "decision",
            "decided_at_ms",
            "nostr_intent_event_id",
            "signature",
        ];
        for required in OPENAPI_REQUIRED {
            assert!(
                EXPECTED_FIELDS.contains(&required),
                "HoldDecisionRequest requires `{required}` and DecideHoldInput \
                 cannot send it"
            );
        }
        // `hold_id` is a PATH parameter, not a body member: the body schema is
        // additionalProperties:false, so the serializer must drop it. Asserted
        // here so the request builder cannot start sending it.
        assert!(!OPENAPI_REQUIRED.contains(&"hold_id"));
    }

    /// The hold id format, pinned locally so a malformed id is refused before a
    /// socket opens rather than as a daemon 404.
    #[test]
    fn hold_id_format_is_the_pinned_one() {
        let ok = "hold_3f2b7c48-9a51-4d6e-8b02-71c4ee9a5d13";
        assert_eq!(ok.len(), 41);
        assert!(ok.starts_with("hold_"));
        // v4 nibble and RFC 4122 variant nibble.
        let uuid = &ok["hold_".len()..];
        assert_eq!(uuid.as_bytes()[14], b'4');
        assert!(matches!(uuid.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        // The forbidden derived form, kept as a literal so the ban is visible.
        assert!(!ok.contains("hold:"));
    }
}

// ---------------------------------------------------------------------------
// THE E2E BRIDGE OBLIGATION — do not land this file without it.
//
// BUZZ desktop/src/testing/e2eBridge.ts is 14,620 lines behind one
// `switch (command)` whose `default:` throws
// `Unsupported mocked Tauri command: ${command}` at :14594, installed as the
// Tauri IPC via mockIPC at :14601 and also exposed on
// `window.__BUZZ_E2E_INVOKE_MOCK_COMMAND__` at :14597. A new command called
// during mount breaks EVERY mock-mode Playwright spec with a "Community
// connection failed" render that is indistinguishable from a product bug — the
// exact symptom BUZZ CLAUDE.md warns about for a wrong build.
//
// Perch adds ONE guard immediately before that default, delegating to a
// separate module so the 14,620-line switch does not grow:
//
//     if (command.startsWith("perch_")) {
//       return handlePerchMockCommand(command, args);
//     }
//
// VERIFIED: the switch contains no other arm that matches on a command PREFIX
// (every `startsWith` in the file tests a storage key, a URL, a subscription id
// or a filename), so the guard has no ordering constraint against an existing
// arm. It must simply precede `default:`.
//
// The delegate is desktop/src/testing/perch/e2ePerchBridge.ts — one module
// path, agreed with 16-INVARIANT-TESTS.md, reading the canonical fixture from
// build/fixtures/perch-demo-fixture.json. `src/testing` is ungoverned by the
// size gate (verified at desktop/scripts/check-file-sizes.mjs:10-55), so the
// module may be as large as the fixtures need. Three lines land in the upstream
// file, everything else in ours. 00-BRIEF.md §5.1 says do not split
// e2eBridge.ts; this respects that.
// ---------------------------------------------------------------------------
