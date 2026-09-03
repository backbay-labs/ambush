//! INV-01 and INV-22 on the client side — the two halves of "Perch never
//! authorizes" that a grep cannot reach.
//!
//! Target path in BUZZ: `desktop/src-tauri/src/perch/client_tests.rs`, included
//! from the bottom of `desktop/src-tauri/src/perch/client.rs` with
//! `#[path = "client_tests.rs"] mod tests;` (the `agent_config.rs:577`
//! precedent `[V]`). Run by
//! `cargo test --manifest-path desktop/src-tauri/Cargo.toml`.
//!
//! INV-01: the console's Ambush-bound write surface is EXACTLY five routes.
//!   `tools/check-perch-write-allowlist.sh` asserts the shape of the source. It
//!   cannot assert behaviour, and the behaviour is what matters: a path built at
//!   runtime from a config value would satisfy the grep and violate the
//!   invariant. So the dispatcher consults `PERCH_DAEMON_WRITES` at call time
//!   and refuses an unlisted pair BEFORE opening a socket, and that refusal is
//!   what these tests drive.
//!
//! INV-22: the daemon bearer token never crosses the Tauri IPC boundary.
//!   The token is read from the environment in the Tauri process
//!   (`OperatorAuthConfig`'s `token_env`, `AMB swarm-core/src/config/operator.rs:118-129`)
//!   and attached as an `Authorization: Bearer` header there. The webview never
//!   sees it. The subtle failure is not passing it deliberately — nobody does
//!   that — it is an ERROR BODY. A daemon 401 whose body echoes the credential,
//!   or a `reqwest::Error` whose `Display` includes a redacted-but-present URL
//!   with the token in a query string, reaches the renderer through
//!   `invokeTauri`'s error normalisation
//!   (`BUZZ desktop/src/shared/api/tauri.ts:259-282`) and lands in a console
//!   log, a Sentry breadcrumb or a screenshot. So the test drives the ERROR
//!   paths, not the happy one.

use super::{
    perch_daemon_request, redact_for_ipc, PerchClientError, PerchMethod, PERCH_DAEMON_WRITES,
};

const TOKEN: &str = "swarm-operator-token-6f2a9c11b7e34d80";

/// The five, from APPENDIX-NORMATIVE.md section 5 and 08 INV-01. Written out
/// again here ON PURPOSE: if this list and `PERCH_DAEMON_WRITES` are edited
/// together by the same careless hand the test still passes, but the diff shows
/// two files, and a reviewer looking at a PR that touches the write surface in
/// two places is exactly the outcome INV-01 wants.
const EXPECTED_WRITES: [(PerchMethod, &str); 5] = [
    (PerchMethod::Post, "/v1/response/holds/{hold_id}/decide"),
    (PerchMethod::Post, "/v1/operator/findings/{finding_id}/feedback"),
    (PerchMethod::Post, "/v1/operator/incidents"),
    (
        PerchMethod::Post,
        "/v1/operator/containment/leases/{lease_id}/release",
    ),
    (PerchMethod::Post, "/v1/operator/review/sessions"),
];

#[test]
fn the_write_table_is_exactly_the_five_inv_01_routes() {
    let mut declared: Vec<_> = PERCH_DAEMON_WRITES.iter().copied().collect();
    let mut expected: Vec<_> = EXPECTED_WRITES.iter().copied().collect();
    declared.sort_by_key(|(_, path)| *path);
    expected.sort_by_key(|(_, path)| *path);
    assert_eq!(
        declared, expected,
        "the console's write surface moved. Adding a sixth route is a change to \
         INV-01 and to APPENDIX-NORMATIVE.md section 5, not to this file."
    );

    // B3i was missing from 08's first draft of the allowlist and would have
    // failed the build on the first promote-to-case. Named explicitly so a
    // future trim cannot quietly drop it again.
    assert!(
        PERCH_DAEMON_WRITES
            .iter()
            .any(|(_, path)| *path == "/v1/operator/incidents"),
        "B3i's incident-minting write is part of the allowlist"
    );
}

#[tokio::test]
async fn an_unlisted_write_is_refused_before_a_socket_is_opened() {
    // A route that exists on the daemon and that the console may not call.
    // `swarmctl` can do this; the console may not, and the difference is the
    // whole product claim.
    let error = perch_daemon_request(
        PerchMethod::Post,
        "/v1/operator/control/mode",
        "{}",
        // A base URL pointing at a closed port: if the guard ever regressed to
        // "try it and see", this test would fail with a connection error rather
        // than the typed refusal, which is a distinguishable and honest failure.
        "http://127.0.0.1:1",
        TOKEN,
    )
    .await
    .expect_err("an unlisted non-GET must be refused");

    assert!(
        matches!(error, PerchClientError::NotOnWriteAllowlist { .. }),
        "expected a typed allowlist refusal, got {error:?}"
    );
}

#[tokio::test]
async fn a_path_assembled_at_runtime_is_matched_against_the_template() {
    // The dispatcher takes a TEMPLATE plus params, never a pre-built path, so a
    // caller cannot smuggle `/v1/operator/control/mode` in through a `{hold_id}`
    // substitution. This is the grep's blind spot, closed.
    let error = perch_daemon_request(
        PerchMethod::Post,
        "/v1/response/holds/../../operator/control/mode/decide",
        "{}",
        "http://127.0.0.1:1",
        TOKEN,
    )
    .await
    .expect_err("a traversal is not a template match");
    assert!(matches!(error, PerchClientError::NotOnWriteAllowlist { .. }));
}

#[test]
fn a_get_is_not_on_the_write_allowlist_and_does_not_need_to_be() {
    // INV-01 gates non-GET only. Asserting the negative keeps a future author
    // from "fixing" reads by adding them to the write table, which would make
    // the write table meaningless.
    assert!(
        !PERCH_DAEMON_WRITES
            .iter()
            .any(|(method, _)| *method != PerchMethod::Post),
        "every entry on the write allowlist is a POST; a PUT/PATCH/DELETE would \
         be a new capability, not a new route"
    );
}

#[test]
fn the_bearer_token_never_survives_redaction_for_ipc() {
    // Every shape the token can arrive in. Each one has been a real incident in
    // some product; the last two are the ones people forget.
    let leaky = [
        format!("401 Unauthorized: bearer {TOKEN} was rejected"),
        format!("Authorization: Bearer {TOKEN}"),
        format!("error sending request for url (http://127.0.0.1:9090/v1/x?token={TOKEN})"),
        format!("{{\"error\":\"invalid_token\",\"presented\":\"{TOKEN}\"}}"),
        // A token split across a wrapped log line still contains the prefix.
        format!("hint: SWARM_OPERATOR_TOKEN={TOKEN}"),
    ];

    for message in leaky {
        let redacted = redact_for_ipc(&message, TOKEN);
        assert!(
            !redacted.contains(TOKEN),
            "the token survived redaction in: {redacted}"
        );
        // Redaction must not erase the DIAGNOSIS. An error the operator cannot
        // act on gets worked around by turning redaction off.
        assert!(
            redacted.contains("[redacted]"),
            "redaction must be visible so nobody thinks the field was empty: {redacted}"
        );
    }
}

#[test]
fn redaction_does_not_depend_on_the_token_being_known_to_the_formatter() {
    // The guard is applied at the ONE place a value crosses back into the
    // webview, not at each call site, because a call site added next year will
    // not remember. Anything that looks like a bearer credential is stripped
    // even when it is not this process's token — a daemon that echoes a
    // DIFFERENT operator's token is still a disclosure.
    let other = "swarm-operator-token-0000000000000000";
    let redacted = redact_for_ipc(&format!("rejected: bearer {other}"), TOKEN);
    assert!(!redacted.contains(other));
}
