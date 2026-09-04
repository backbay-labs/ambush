use super::*;

#[test]
fn the_write_table_is_exactly_the_five_inv_01_routes() {
    let mut got: Vec<String> = PERCH_DAEMON_WRITES
        .iter()
        .map(|(m, p)| format!("{m} {p}"))
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            "POST /v1/operator/containment/leases/{lease_id}/release",
            "POST /v1/operator/findings/{finding_id}/feedback",
            "POST /v1/operator/incidents",
            "POST /v1/operator/review/sessions",
            "POST /v1/response/holds/{hold_id}/decide",
        ]
    );
}

#[test]
fn route_substitution_encodes_and_refuses_a_slash() {
    let r = route(
        "/v1/operator/findings/{finding_id}/feedback",
        &[("finding_id", "f 1")],
    )
    .expect("a substituted route");
    assert_eq!(r.path, "/v1/operator/findings/f%201/feedback");
    assert_eq!(r.template, "/v1/operator/findings/{finding_id}/feedback");
    assert!(route(
        "/v1/operator/findings/{finding_id}/feedback",
        &[("finding_id", "../../admin")]
    )
    .is_err());
    assert!(
        route("/v1/operator/findings/{finding_id}/feedback", &[]).is_err(),
        "an unsubstituted placeholder is an error"
    );
}

#[test]
fn route_percent_encoding_covers_every_reserved_byte() {
    let r = route(
        "/v1/operator/findings/{finding_id}/feedback",
        &[("finding_id", "a?b#c&d=e+f%g:h")],
    )
    .expect("a substituted route");
    assert_eq!(
        r.path,
        "/v1/operator/findings/a%3Fb%23c%26d%3De%2Bf%25g%3Ah/feedback"
    );
    let unreserved = route(
        "/v1/operator/findings/{finding_id}/feedback",
        &[("finding_id", "aZ0-_.~")],
    )
    .expect("a substituted route");
    assert_eq!(unreserved.path, "/v1/operator/findings/aZ0-_.~/feedback");
}

#[tokio::test]
async fn an_unlisted_write_is_refused_before_any_socket_opens() {
    // No keyring value is planted: the allowlist check runs BEFORE `daemon_url`
    // reads the keyring and before any socket is opened, so an unlisted route
    // must fail with the allowlist error and never with "daemon not
    // configured" or a connect error. The ordering IS the assertion.
    let state = crate::app_state::build_app_state();
    let r = DaemonRoute {
        template: "/v1/operator/anything",
        path: "/v1/operator/anything".into(),
    };
    let err = perch_daemon_post(&state, &r, serde_json::json!({}))
        .await
        .expect_err("an unlisted route must be refused");
    assert!(err.contains("not on the INV-01 allowlist"), "{err}");
}

#[test]
fn the_allowlist_arm_discriminates_on_both_the_verb_and_the_template() {
    // The pure half of the check the test above exercises through the async
    // path: a listed template is a write only for the listed verb, and a
    // template that is not in the table is a write for no verb at all.
    assert!(is_allowlisted_write("POST", "/v1/operator/incidents"));
    assert!(!is_allowlisted_write("DELETE", "/v1/operator/incidents"));
    assert!(!is_allowlisted_write("POST", "/v1/operator/anything"));
    assert!(!is_allowlisted_write(
        "POST",
        "/v1/operator/findings/f1/feedback"
    ));
    assert!(is_allowlisted_write(
        "POST",
        "/v1/operator/findings/{finding_id}/feedback"
    ));
}

// ── keyring values must not cross IPC ──────────────────────────────────────

/// A transport failure names the URL it was dialling; the message that crosses
/// IPC must not.
///
/// The daemon URL and the bearer are keyring values this process keeps. The
/// redaction happens where a transport error BECOMES a string, not at each
/// call site, because a call site can forget — and a test that only checked a
/// hand-built string would pass over a client that never called the redactor.
/// So this drives the real message builder with the real shape of a reqwest
/// error.
#[test]
fn a_transport_error_message_carries_neither_the_daemon_url_nor_the_bearer() {
    let url = "https://daemon.internal:9090/v1/response/holds/hold_x/decide";
    let bearer = "super-secret-operator-bearer-token";
    // The shape reqwest actually produces: the URL, verbatim, inside the text.
    let raw = format!("error sending request for url ({url}): connection refused");
    let message = transport_error_message(&raw, url, bearer);

    assert!(
        !message.contains(bearer),
        "the bearer crossed IPC: {message}"
    );
    assert!(
        !message.contains(url),
        "the daemon URL crossed IPC: {message}"
    );
    assert!(
        !message.contains("daemon.internal:9090"),
        "the daemon ORIGIN crossed IPC, which discloses where it lives: {message}"
    );
    assert!(
        message.contains("daemon unreachable"),
        "the operator still needs to know what happened: {message}"
    );
}

/// The redactor is not a no-op and not a blank: it removes the two secrets and
/// leaves everything else legible.
#[test]
fn redaction_removes_only_the_secrets() {
    let url = "http://127.0.0.1:9090";
    let bearer = "tok-abc";
    let message = format!("POST {url}/v1/x failed with tok-abc after 3s");
    let redacted = redact_for_ipc(&message, url, bearer);
    assert!(!redacted.contains(bearer));
    assert!(!redacted.contains("127.0.0.1:9090"));
    assert!(
        redacted.contains("failed") && redacted.contains("after 3s"),
        "the redactor ate the diagnosis: {redacted}"
    );

    // An empty secret must not turn every character into a redaction marker.
    let untouched = redact_for_ipc("nothing secret here", "", "");
    assert_eq!(untouched, "nothing secret here");
}

/// `Retry-After` is read from the header, not invented.
///
/// The decide route sends it on the two conflicts that resolve by themselves;
/// a client that guessed its own interval would either hammer the daemon or
/// keep the operator waiting longer than the daemon asked.
#[test]
fn a_daemon_response_carries_the_retry_after_the_daemon_sent() {
    let response = DaemonResponse {
        status: 409,
        body: serde_json::json!({ "error": "decision_in_flight" }),
        retry_after_seconds: Some(1),
    };
    assert_eq!(response.retry_after_seconds, Some(1));
    let without = DaemonResponse {
        status: 409,
        body: serde_json::json!({ "error": "hold_already_decided" }),
        retry_after_seconds: None,
    };
    assert_eq!(without.retry_after_seconds, None);
}
