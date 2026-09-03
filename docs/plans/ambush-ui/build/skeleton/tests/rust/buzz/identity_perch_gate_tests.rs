//! INV-29 -- no generic path in this process can sign or publish a governance
//! artifact.
//!
//! Target path in BUZZ: `desktop/src-tauri/src/perch_marker_guard_tests.rs`,
//! included from the bottom of `perch_marker_guard.rs` with
//! `#[path = "perch_marker_guard_tests.rs"] #[cfg(test)] mod tests;` -- the same
//! shape as `commands/agent_config.rs:577` + `commands/agent_config_tests.rs`,
//! which exists precisely to keep a file under the 1000-line ratchet `[V]`.
//!
//! Run by `cargo test --manifest-path desktop/src-tauri/Cargo.toml`. NOTE: the
//! desktop crate is EXCLUDED from the root workspace, so a bare `cargo test` at
//! the Buzz repo root does not run this (BUZZ CLAUDE.md, gotcha 5). It must be
//! named in the Tauri test lane explicitly.
//!
//! WHAT THIS FILE ASSERTS, IN THREE GROUPS
//!   1. THE PREDICATE (four tests). Runs standalone under
//!      `rustc --edition 2021 --test`, needs no Tauri runtime, no `nostr`, no
//!      `AppState`.
//!   2. CALL-SITE COMPLETENESS (one test, `#[cfg(feature = "perch-boundary")]`).
//!      A filesystem scan asserting the marker guard is wired at exactly the
//!      boundaries `egress_guard` is wired at. This is the test that answers
//!      "what would still pass?" -- it is the reason `send_channel_message`
//!      cannot be forgotten, because `send_channel_message` publishes through
//!      `relay/submit.rs`, which the scan pins.
//!   3. THE BUILDER (one test, `#[cfg(feature = "perch-writes")]`). Asserts that
//!      `perch_record_verdict` produces a card from daemon-fetched state. It is
//!      feature-gated because `commands::perch_writes` DOES NOT EXIST -- it is
//!      14-CLIENT-ARCHITECTURE.md's B2 work. See the honest note above it.
//!
//! VERIFICATION STATUS, STATED EXACTLY
//!   `rustc --edition 2021 --test identity_perch_gate.rs` compiles and runs the
//!   four group-1 tests: 4 passed, 0 failed. Groups 2 and 3 are cfg'd out of
//!   that run by design, because neither can compile outside the Buzz crate.
//!   An earlier draft of this file put group 3 behind a bare `#[test]`, which
//!   made the file fail to compile (E0433 twice, `could not find `commands` in
//!   the crate root`, plus an E0282) -- and the "4/4 green" figure was measured
//!   on a four-test file that was not the one in the tree. Both are fixed: the
//!   number is 4 of 6, the other two name their blockers, and the whole file
//!   compiles.
//!
//! WHY THE PREDICATE IS PURE
//!   `sign_event` takes `State<'_, AppState>` and an `AppState` cannot be built
//!   in a unit test without a Tauri runtime. The gate is therefore a pure
//!   `fn perch_sign_gate(kind: u16, content: &str) -> Result<(), String>` plus
//!   two thin boundary wrappers, and these tests drive the pure function. A test
//!   that needs a webview is a test that gets `#[ignore]`d.

use super::{perch_marker_guard, perch_sign_gate, PERCH_SIGN_REFUSAL};

/// `kind:46010` -- the forked hold kind. Only the bridge's key may publish one,
/// and the bridge is a different process with a different key.
const KIND_WORKFLOW_APPROVAL_REQUESTED: u16 = 46010;
const KIND_CHAT: u16 = 9;

fn marker(slug: &str) -> String {
    format!("<!-- ambush:{slug}:v1 -->\n{{\"hold_id\":\"h_a07aeacf\"}}")
}

// ── GROUP 1: THE PREDICATE ────────────────────────────────────────────────────

#[test]
fn the_forked_hold_kind_is_refused_outright() {
    let error = perch_sign_gate(KIND_WORKFLOW_APPROVAL_REQUESTED, "anything at all")
        .expect_err("46010 is the daemon's to publish, never this process's");
    assert_eq!(error, PERCH_SIGN_REFUSAL);
}

#[test]
fn a_message_whose_first_line_is_an_ambush_marker_is_refused() {
    // All seven markers, because a gate that knows six of them is a gate that
    // ships the seventh. APPENDIX-NORMATIVE.md section 3 closes the set.
    for slug in [
        "finding",
        "escalation",
        "hold",
        "verdict",
        "receipt",
        "lease",
        "rollback",
    ] {
        let error = perch_sign_gate(KIND_CHAT, &marker(slug))
            .expect_err("a card-shaped kind:9 must be refused");
        assert_eq!(error, PERCH_SIGN_REFUSAL, "slug {slug}");
    }
}

#[test]
fn the_gate_matches_the_renderers_parse_exactly() {
    // The parse contract is `line0.trimEnd()`, never `trimStart()`
    // (17-COMPONENT-SPECS.md section 3.4). If this gate and that parser disagree
    // in EITHER direction the disagreement is exploitable: a string this gate
    // signs and the renderer treats as a card is a forgery channel, and a string
    // this gate refuses and the renderer ignores is a bug report.
    //
    // The leading-space case is only safe because of WHERE the guard runs. It
    // runs on the final event content, AFTER `send_channel_message`'s
    // `content.trim()` (BUZZ desktop/src-tauri/src/commands/messages.rs:505) --
    // so a renderer that submits " <!-- swarm:verdict:v1 -->" through that
    // command is checked on the trimmed bytes and refused there. If this guard
    // is ever moved earlier in that path, this case becomes a hole and the
    // `passes_only_because_the_guard_runs_after_trim` case below is what fails.
    let signable = [
        " <!-- swarm:verdict:v1 -->\nnot a card",
        "here is what I saw\n<!-- swarm:verdict:v1 -->",
        "<!-- buzz:wave:v1 -->\n{}",
        "the swarm:verdict:v1 card is missing from this case",
        // Uppercase in the slug is not the renderer's grammar, so it is not a
        // card and must not be refused.
        "<!-- ambush:Verdict:v1 -->\n{}",
    ];
    for content in signable {
        assert!(
            perch_sign_gate(KIND_CHAT, content).is_ok(),
            "the gate refused a string the renderer will never treat as a card: {content:?}"
        );
    }

    let refused = [
        "<!-- swarm:verdict:v1 -->",
        "<!-- swarm:verdict:v1 -->\n",
        "<!-- swarm:verdict:v1 -->\r\n{}",
        // Trailing whitespace only: `trimEnd()` makes this line-0-exact.
        "<!-- swarm:verdict:v1 -->   \n{}",
        // An unknown slug still refuses. The renderer answers it with the
        // unknown-kind refusal card, which means it is still a Perch artifact;
        // the renderer must never be the thing that decides what may be signed.
        "<!-- ambush:teapot:v1 -->\n{}",
        // A future version, same reasoning.
        "<!-- swarm:verdict:v9 -->\n{}",
    ];
    for content in refused {
        assert_eq!(
            perch_sign_gate(KIND_CHAT, content),
            Err(PERCH_SIGN_REFUSAL.to_string()),
            "the gate signed a string the renderer will treat as a card: {content:?}"
        );
    }

    // THE TRIM CASE, asserted rather than assumed. `send_channel_message` hands
    // `content.trim()` to the builder, so the leading-space string above reaches
    // the relay WITHOUT its space. The guard must refuse the trimmed form, which
    // is what makes placing it at the submit boundary (not at the command's
    // entry) the load-bearing choice.
    let submitted = " <!-- swarm:verdict:v1 -->\nnot a card".trim();
    assert_eq!(
        perch_sign_gate(KIND_CHAT, submitted),
        Err(PERCH_SIGN_REFUSAL.to_string()),
        "the bytes send_channel_message actually publishes must be refused"
    );
}

#[test]
fn ordinary_signing_is_untouched_and_the_boundary_form_names_its_site() {
    // The gate must be narrow. Every other kind the app signs today keeps
    // working; a gate that broke reactions or DMs would be reverted in a day and
    // then the hole is open again.
    for kind in [0u16, 1, 7, 9, 20002, 40002, 43001, 48100] {
        assert!(
            perch_sign_gate(kind, "hello, this is an ordinary message").is_ok(),
            "kind {kind} must still be signable"
        );
        assert!(
            perch_marker_guard(kind, "hello, this is an ordinary message", "test boundary").is_ok(),
            "kind {kind} must still be publishable"
        );
    }

    // egress_guard's convention: the refusal names the boundary, so a bug report
    // says which of the seven sites fired
    // (BUZZ desktop/src-tauri/src/egress_guard_tests.rs:64-68 asserts the same
    // property for its own guard).
    let error = perch_marker_guard(KIND_CHAT, &marker("verdict"), "relay event submit")
        .expect_err("a card-shaped kind:9 must be refused at a boundary too");
    assert!(error.contains("relay event submit"), "{error}");
    assert!(error.contains(PERCH_SIGN_REFUSAL), "{error}");
}

// ── GROUP 2: CALL-SITE COMPLETENESS ──────────────────────────────────────────
//
// `#[cfg(feature = "perch-boundary")]` because it reads the Buzz crate's own
// source tree through `CARGO_MANIFEST_DIR` and asserts against
// `crate::egress_guard`'s wiring. It cannot run outside the Buzz crate and does
// not pretend to.

/// The one guarded site that is NOT an egress boundary, with its reason. Any
/// other file carrying a marker-guard call and no egress-guard call fails the
/// scan below, which is what stops the two guards drifting apart.
#[cfg(feature = "perch-boundary")]
const NON_EGRESS_GUARDED_SITES: &[(&str, usize, &str)] = &[(
    "src/commands/identity.rs",
    1,
    "sign_event hands signed JSON back to the RENDERER rather than to a relay, \
     so egress_guard has nothing to guard here. The marker guard runs pre-sign, \
     before state.signing_keys() at identity.rs:115, so a refusal never touches \
     the key.",
)];

/// INV-29's completeness half. The marker guard must be called at exactly the
/// boundaries `egress_guard` is called at, plus the declared non-egress sites.
///
/// WHY SET EQUALITY AGAINST ANOTHER GUARD RATHER THAN A HAND-WRITTEN LIST
///   A hand-written list of publish paths is a second registry that drifts. The
///   egress inventory is not: `events_url_inventory_is_fully_guarded`
///   (BUZZ desktop/src-tauri/src/egress_guard_tests.rs:371-380) already fails
///   the build when a new `/events` URL-construction site appears anywhere under
///   `src-tauri/src`, in a new file OR an already-listed one, and again when a
///   guard call is deleted while its egress site remains. Anchoring to it means
///   a ninth submission path fails an EXISTING test first and this one second.
///   The measured baseline at BUZZ eed74bde2 is eight guard calls across six
///   files: relay.rs 2, relay/submit.rs 1, huddle/pipeline.rs 1,
///   commands/team_snapshot.rs 1, commands/personas/snapshot/import.rs 1,
///   native_websocket.rs 2.
#[cfg(feature = "perch-boundary")]
#[test]
fn perch_marker_guard_call_sites_match_egress_guard() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    // Needles are assembled at runtime so this scan file contains no contiguous
    // match of either and needs no self-referential exemption -- the same device
    // egress_guard_tests.rs uses at :295-302.
    let egress_needle = ["egress_guard::", "assert_no_key_backup"].concat();
    let marker_needle = ["perch_marker_guard::", "assert_no_perch_marker"].concat();

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&root, &mut files);

    let mut violations: Vec<String> = Vec::new();
    let mut egress_total = 0usize;
    let mut marker_total = 0usize;

    for path in files {
        let rel = path
            .strip_prefix(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        // The two guard modules and their test siblings define and exercise the
        // needles; they are not call sites.
        if rel.ends_with("src/egress_guard.rs")
            || rel.ends_with("src/egress_guard_tests.rs")
            || rel.ends_with("src/perch_marker_guard.rs")
            || rel.ends_with("src/perch_marker_guard_tests.rs")
        {
            continue;
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let egress = content.matches(&egress_needle).count();
        let marker = content.matches(&marker_needle).count();
        egress_total += egress;
        marker_total += marker;

        let declared = NON_EGRESS_GUARDED_SITES
            .iter()
            .find(|(suffix, _, _)| rel.ends_with(suffix));

        match declared {
            Some((_, expected, reason)) => {
                if marker != *expected {
                    violations.push(format!(
                        "{rel}: declared non-egress guarded site expects {expected} marker-guard \
                         call(s), found {marker}. Reason on record: {reason}"
                    ));
                }
            }
            None => {
                if marker != egress {
                    violations.push(format!(
                        "{rel}: {egress} egress-guard call(s) but {marker} marker-guard call(s). \
                         The two guards are wired and unwired together; a relay-bound egress path \
                         that does not also refuse an ambush marker lets the renderer publish a \
                         forged verdict card, and a marker guard on a path with no egress is \
                         either dead or an undeclared publish path."
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Perch marker-guard call sites have drifted from egress-guard call sites:\n{}\n\n\
         Fix: add crate::perch_marker_guard beside crate::egress_guard at the new \
         boundary, or -- if the site genuinely hands bytes to something that is not \
         a relay -- add a row to NON_EGRESS_GUARDED_SITES with a written reason.",
        violations.join("\n")
    );

    // Refuse to pass silently. A scan that matched nothing would satisfy every
    // assertion above; egress_guard's own inventory pins eight calls across six
    // files at eed74bde2, so zero means the needle broke, not that the tree is
    // clean.
    assert!(
        egress_total >= 8,
        "found {egress_total} egress-guard call(s); the measured baseline is 8. \
         The needle is broken and this test asserted nothing."
    );
    assert!(
        marker_total >= egress_total,
        "found {marker_total} marker-guard call(s) against {egress_total} egress-guard \
         call(s); the marker guard is wired at fewer sites than the guard it shadows."
    );
}

// ── GROUP 3: THE BUILDER ─────────────────────────────────────────────────────
//
// BLOCKED ON B2. `crate::commands::perch_writes` does not exist in block/buzz at
// eed74bde2; it is 14-CLIENT-ARCHITECTURE.md's `perch_writes.rs` and
// 12-BACKEND-BILL-API.md's B2 decide route. `build_verdict_card_for_test` and
// `VerdictDecision` are PROPOSED symbols on that module.
//
// It is behind `#[cfg(feature = "perch-writes")]` rather than deleted because
// the assertion is the POSITIVE half of INV-29 -- the guard says what cannot
// mint a verdict card; this says what can -- and losing it would leave the
// invariant half-tested. The feature is enabled in the same PR that lands
// perch_writes.rs, and until then this test does not compile into any build and
// does not appear in any count.

#[cfg(feature = "perch-writes")]
#[test]
fn perch_record_verdict_is_the_only_producer_of_a_verdict_card() {
    use crate::commands::perch_writes::{build_verdict_card_for_test, VerdictDecision};

    // `perch_record_verdict` builds its body from DAEMON-FETCHED hold state --
    // it takes a hold_id and a decision, not a content string -- so a renderer
    // cannot choose what the card says. It signs through the same key by calling
    // the signer directly, BELOW the gate.
    let card = build_verdict_card_for_test(
        "h_a07aeacf",
        VerdictDecision::Grant,
        /* daemon-fetched */ "isolate_host",
        "CRITICAL",
        "27799e23-ab25-4659-b381-3de47ea7ca4d",
        1_773_738_979_000,
    );

    // It is a card the gate would refuse if it came from the renderer...
    assert_eq!(
        perch_sign_gate(KIND_CHAT, &card.content),
        Err(PERCH_SIGN_REFUSAL.to_string())
    );
    // ...and the body is the daemon's facts, not the caller's prose.
    assert!(card.content.starts_with("<!-- swarm:verdict:v1 -->\n"));
    assert!(card.content.contains("\"action_kind\":\"isolate_host\""));
    assert!(card.content.contains("\"hold_id\":\"h_a07aeacf\""));
    // The `h` tag is the case channel UUID. INV-12 asserts the same thing at the
    // relay; this asserts the builder, which is where it can be got wrong.
    let tags: &[Vec<String>] = &card.tags;
    assert!(tags.iter().any(|tag| {
        tag.first().map(String::as_str) == Some("h")
            && tag.get(1).map(String::as_str) == Some("27799e23-ab25-4659-b381-3de47ea7ca4d")
    }));
}
