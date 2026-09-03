#![allow(clippy::unwrap_used, clippy::expect_used)]
//! INV-18, INV-26, INV-27 and INV-35 on the daemon side.
//!
//! Target path in AMBUSH: `crates/swarm-ingest-runtime/tests/perch_hold_lifecycle.rs`.
//! Run by `cargo test -p swarm-ingest-runtime`, i.e. by the existing `test` job.
//!
//! STATUS: THIS FILE DOES NOT COMPILE AGAINST THE TREE AT eed74bde2/HEAD.
//!   Every type it names comes from B1 and B2 (12-BACKEND-BILL-API.md sections 3
//!   and 4) and none of them exists yet. It is written now, in full, because the
//!   four invariants it carries are the ones a UI cannot assert about itself:
//!
//!     INV-18  a hold that reaches its TTL undecided DISPATCHES NOTHING. The
//!             console can only show that it stopped offering the control; only
//!             the daemon can prove no `ResponseReceipt` was produced.
//!     INV-26  an export bundle's receipts are BYTE-identical to the daemon's
//!             stored bodies. A round trip through the console's JSON is exactly
//!             what would break it, so the comparison must start here.
//!     INV-27  no override path exists. The strongest possible form of this is
//!             not "the console renders no button" but "the daemon exposes no
//!             route", which is a fact about the router.
//!     INV-35  a `kind:46010` the relay carries and `GET /v1/response/holds` does
//!             not renders UNRECONCILED. (It was `FORGED` in an earlier draft;
//!             the word is struck, because a rendered card is admitted by
//!             construction and the shipped default's in-memory hold store
//!             produces exactly this state on any ordinary restart --
//!             12-BACKEND-BILL-API.md section 4.3 calls that *unreconcilable*.
//!             16-INVARIANT-TESTS.md section 5.35 carries the split.) The daemon
//!             half is unchanged and is what this file asserts: an unknown hold
//!             id answers a typed `unknown_hold`, never a 500 and never a
//!             synthesised record.
//!
//!   The `RequireHuman` path today is a REFUSAL, not a queue: under
//!   `RuntimeMode::LiveResponse` `audit_authorize_and_execute` returns
//!   `ApprovalError::Denied` (crates/swarm-runtime/src/lib.rs:975-983) and the
//!   instrumented path writes `AuditResponseRecord::Skipped` with lease `None`
//!   and `response_attempted: false` (`:1133-1146`). The action is dropped and no
//!   row is created anywhere. So there is nothing to expire, nothing to export
//!   and nothing to look up, and these tests have no subject until B1 lands.
//!
//!   ONE SYMBOL HERE IS A NEW ASK, not just an unbuilt B1 type:
//!   `HeldActionStore::is_durable() -> bool`, addendum B1-d
//!   (16-INVARIANT-TESTS.md section 8). `12-BACKEND-BILL-API.md` already commits
//!   `store_durable` on the list response; this names where the value comes from
//!   so two store implementations cannot disagree about it. It is the field
//!   INV-35's two `UNRECONCILED` reasons key on, and without it the console has
//!   to render one reason for two causes -- which is how the earlier `FORGED`
//!   wording came to accuse on every ordinary restart.
//!
//! WHY IT IS CHECKED IN ANYWAY
//!   09's exit criteria are met by demonstration, and "we will write the tests
//!   when the store lands" is how a store lands without them. A test that names
//!   its blocker in its own header is an artifact; a TODO is not.

use std::sync::Arc;

use swarm_ingest_runtime::ingest::perch_ops::{
    decide_hold, HoldDecision, HoldDecisionError, HoldDecisionRequest,
};
use swarm_runtime::held_action::{HeldActionStore, HoldRecord, HoldState};

/// A frozen clock: every assertion below is about an instant, and a test that
/// sleeps for an hour is a test nobody runs.
///
/// The value is the canonical scenario's `now`, 2026-03-17T09:20:00Z
/// (`build/fixtures/perch-demo-fixture.json`, 22-DEMO-FIXTURE.md's
/// `hellcat-office`). Bound rather than invented, because the wave-2 review
/// found five artifacts using five different clocks for one scenario.
const T0: i64 = 1_773_739_200_000;
/// APPENDIX-NORMATIVE.md section 6. Sixty minutes, configurable per threat class.
const PERCH_HOLD_TTL_MS: i64 = 3_600_000;

async fn store_with_one_hold() -> (Arc<dyn HeldActionStore>, HoldRecord) {
    let store = swarm_runtime::held_action::memory_store();
    let record = store
        .create(HoldRecord::fixture_isolate_host(T0, T0 + PERCH_HOLD_TTL_MS))
        .await
        .expect("a fresh store accepts a new hold");
    (store, record)
}

/// INV-18. The sweep is the only thing that may move a hold to `Expired`, and
/// moving it there must produce no receipt, no `AuditTrail` and no
/// `RuntimeEvent::ResponseExecution` -- only `ResponseHeld { state: expired }`.
#[tokio::test]
async fn a_hold_that_reaches_its_ttl_expires_and_dispatches_nothing() {
    let (store, record) = store_with_one_hold().await;

    // One millisecond BEFORE the TTL the hold is still decidable. Asserting the
    // near side matters: a sweep that expires everything would also pass a test
    // that only checks the far side.
    let swept = store.sweep_expired(T0 + PERCH_HOLD_TTL_MS - 1).await.expect("sweep runs");
    assert_eq!(swept, 0);
    assert_eq!(
        store.get(&record.hold_id).await.expect("hold is present").state,
        HoldState::Notified
    );

    let swept = store.sweep_expired(T0 + PERCH_HOLD_TTL_MS).await.expect("sweep runs");
    assert_eq!(swept, 1);

    let expired = store.get(&record.hold_id).await.expect("an expired hold is still stored");
    assert_eq!(expired.state, HoldState::Expired);
    assert!(
        expired.receipt_id.is_none(),
        "expiry must not produce a ResponseReceipt; got {:?}",
        expired.receipt_id
    );
    assert!(
        expired.audit_trail_id.is_none(),
        "expiry must not produce an AuditTrail"
    );
    assert!(
        expired.capability_lease.is_none(),
        "no capability lease is minted for an action nobody authorized"
    );

    // And it is still LISTED, because /handoff counts expired-undecided holds
    // (INV-19) and a row that vanishes cannot be counted.
    let listed = store.list(true).await.expect("list runs");
    assert!(listed.iter().any(|hold| hold.hold_id == record.hold_id));
}

/// INV-18's other half: an expired hold is not decidable, and the refusal is
/// TYPED. A 500 here would be rendered by the console as a client error, which
/// is exactly what INV-28 forbids.
#[tokio::test]
async fn deciding_an_expired_hold_is_a_typed_refusal_not_an_error() {
    let (store, record) = store_with_one_hold().await;
    store.sweep_expired(T0 + PERCH_HOLD_TTL_MS).await.expect("sweep runs");

    let error = decide_hold_for_test(&store, &record.hold_id, HoldDecision::Grant, T0 + PERCH_HOLD_TTL_MS + 1)
        .await
        .expect_err("an expired hold cannot be granted");

    assert!(
        matches!(error, HoldDecisionError::HoldExpired { .. }),
        "expected a typed hold_expired refusal, got {error:?}"
    );
}

/// INV-35, daemon half. An unknown hold id answers a typed `unknown_hold`. The
/// console turns that into the UNRECONCILED render, and it can only do so if the
/// daemon distinguishes "I never held this" from "something went wrong" -- a 500
/// or a synthesised record would make the two indistinguishable, and the console
/// would then have to guess which of them to show an operator at 02:41.
///
/// The response must ALSO carry `store_durable`, because the console's two
/// UNRECONCILED reasons differ on exactly that field: a non-durable store means
/// the daemon restarted, and a durable one means it did not.
#[tokio::test]
async fn an_unknown_hold_id_answers_unknown_hold_and_never_synthesises_a_record() {
    // The id below satisfies `common.schema.json#/$defs/HoldId`
    // (`^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`, no colon) so the negative case is
    // "well-formed and unknown" rather than "malformed", which is a different
    // failure the route must not conflate with this one.
    let (store, _record) = store_with_one_hold().await;

    let error = decide_hold_for_test(&store, "h_neverexisted1", HoldDecision::Grant, T0)
        .await
        .expect_err("a hold the daemon never created cannot be decided");
    assert!(matches!(error, HoldDecisionError::UnknownHold { .. }));

    // And the lookup did not create one as a side effect.
    assert!(store.get("h_neverexisted1").await.is_err());

    // INV-35's split needs one more fact from the daemon, and this is the
    // cheapest place to assert it: whether the store is DURABLE. Without it the
    // console cannot tell "the daemon restarted and forgot every open hold" (the
    // shipped default -- `hold_store_path` is `None`) from "the daemon has a
    // durable store and no record of this hold". Those render different reasons
    // in different registers; a console that cannot tell them apart has to pick
    // one, and picking the alarming one accuses on every ordinary restart, which
    // is exactly the defect that made `FORGED` wrong.
    //
    // `is_durable()` is a property of the STORE, not of a list response --
    // `store_durable` on the wire is derived from it -- so the trait is where it
    // belongs, and one implementation cannot then disagree with another.
    assert!(
        !store.is_durable(),
        "an in-memory store must report store_durable: false; \
         12-BACKEND-BILL-API.md section 4.3 makes this the field the two \
         UNRECONCILED reasons key on"
    );
}

/// INV-26. The console's export must ship the daemon's bytes. This asserts the
/// read path returns the stored body unchanged rather than a re-serialization,
/// because `serde_json::to_string` of a round-tripped value reorders nothing but
/// normalises everything -- float formatting, escape sequences, absent-vs-null --
/// and any of those breaks a hash comparison an auditor runs six months later.
#[tokio::test]
async fn a_stored_receipt_body_is_returned_byte_for_byte() {
    let (store, record) = store_with_one_hold().await;
    let canonical = br#"{"receipt_id":"r-1","status":"executed","details":{"n":1.0}}"#;

    store
        .attach_receipt_bytes(&record.hold_id, canonical)
        .await
        .expect("the store keeps the daemon's own bytes");

    let read_back = store
        .receipt_bytes(&record.hold_id)
        .await
        .expect("the receipt is present");
    assert_eq!(
        read_back.as_slice(),
        canonical,
        "the store re-serialized the receipt; an export built from this cannot be byte-identical"
    );
    // `1.0` is the canary: a JSON round trip renders it `1` and the hash moves.
    assert!(String::from_utf8_lossy(&read_back).contains("1.0"));
}

/// INV-27, in its strongest form. Not "the console renders no override button"
/// but "the router exposes no route that could serve one". The perch operator
/// router is built in one function (12-BACKEND-BILL-API.md section 1.3) and this
/// enumerates it.
#[test]
fn the_perch_operator_router_exposes_no_override_path() {
    let routes = swarm_ingest_runtime::ingest::perch_ops::declared_routes();
    assert!(!routes.is_empty(), "an empty route table would pass vacuously");

    for (method, path) in &routes {
        let lowered = path.to_ascii_lowercase();
        for forbidden in ["override", "force", "break-glass", "breakglass", "bypass"] {
            assert!(
                !lowered.contains(forbidden),
                "{method} {path} names `{forbidden}`; a PolicyVerdict::Deny has no override path"
            );
        }
    }

    // The write surface is closed at exactly the routes INV-01 names as reachable
    // from the console. `swarmctl` may of course do more; the console may not.
    let writes: Vec<&str> = routes
        .iter()
        .filter(|(method, _)| *method != "GET")
        .map(|(_, path)| *path)
        .collect();
    assert_eq!(
        writes,
        vec!["/v1/response/holds/{hold_id}/decide"],
        "the perch router's only non-GET route is the decide route; every other \
         INV-01 write lives on a router that already existed"
    );
}

// --- test-local helper -------------------------------------------------------
// Wraps `decide_hold` with the four arguments every test above shares, so a
// signature change shows up in one place rather than five.
async fn decide_hold_for_test(
    store: &Arc<dyn HeldActionStore>,
    hold_id: &str,
    decision: HoldDecision,
    now_ms: i64,
) -> Result<swarm_ingest_runtime::ingest::perch_ops::HoldDecisionOutcome, HoldDecisionError> {
    decide_hold(
        &swarm_ingest_runtime::ingest::perch_ops::test_state_with_store(store.clone(), now_ms),
        hold_id,
        "operator-primary",
        HoldDecisionRequest::fixture(decision, now_ms),
    )
    .await
}
