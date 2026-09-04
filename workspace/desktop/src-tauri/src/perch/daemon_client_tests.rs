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
