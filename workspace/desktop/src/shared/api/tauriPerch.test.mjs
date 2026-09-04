// The console's hold types against the daemon's real bytes.
//
// `src/testing/perch/daemonHoldFixture.json` was produced by serialising
// `HoldListResponse` and `HeldActionView` from
// `crates/swarm-runtime-http/src/http/perch/holds.rs` at d6b0c6eb3, through
// the mounted axum route for the list and through `HeldActionView::from_hold`
// for the decided view. It is not a hand-written sample: a field that appears
// on one side and not the other fails here rather than at 3am on a hold
// nobody can read.

import assert from "node:assert/strict";
import test from "node:test";

import fixture from "../../testing/perch/daemonHoldFixture.json" with {
  type: "json",
};
import {
  PERCH_HOLD_DTO_KEYS,
  PERCH_READ_COMMANDS,
  PERCH_TAURI_COMMANDS,
} from "./tauriPerch.ts";

const listResponse = fixture.list;
const openHold = fixture.list.holds[0];
const decidedHold = fixture.decided_hold;

function assertSameKeys(actual, expected, label) {
  assert.deepEqual(
    [...actual].sort(),
    [...expected].sort(),
    `${label}: the console's type and the daemon's body disagree`,
  );
}

test("HoldListResponse carries exactly the fields the console types", () => {
  assertSameKeys(
    Object.keys(listResponse),
    PERCH_HOLD_DTO_KEYS.HoldListResponse,
    "HoldListResponse",
  );
  // The two the wave-2 drafts omitted, named so a later edit cannot quietly
  // drop them: `truncated` says the page is short of the store, and
  // `store_durable` is the difference between "no holds" and "no memory".
  assert.equal(typeof listResponse.truncated, "boolean");
  assert.equal(typeof listResponse.store_durable, "boolean");
  assert.equal(typeof listResponse.open_count, "number");
});

test("HeldActionView carries exactly the fields the console types", () => {
  assertSameKeys(
    Object.keys(openHold),
    PERCH_HOLD_DTO_KEYS.HeldActionView,
    "HeldActionView (open)",
  );
  assertSameKeys(
    Object.keys(decidedHold),
    PERCH_HOLD_DTO_KEYS.HeldActionView,
    "HeldActionView (decided)",
  );
  // W3-26: leg 1 is built from daemon state, so all three relay pointers must
  // be on the view or the console would have to guess one of them.
  for (const field of ["case_channel", "notice_event_id", "card_event_id"]) {
    assert.ok(field in decidedHold, `HeldActionView lost ${field}`);
  }
});

test("remaining_ms and expired are two separate facts", () => {
  assert.equal(typeof openHold.remaining_ms, "number");
  assert.equal(typeof openHold.expired, "boolean");
  assert.notEqual(
    openHold.state,
    openHold.expired,
    "state and expired are different questions and must stay different fields",
  );
});

test("HoldDecisionRecord and HoldRationale carry exactly what the console types", () => {
  assertSameKeys(
    Object.keys(decidedHold.decision),
    PERCH_HOLD_DTO_KEYS.HoldDecisionRecord,
    "HoldDecisionRecord",
  );
  assertSameKeys(
    Object.keys(decidedHold.rationale),
    PERCH_HOLD_DTO_KEYS.HoldRationale,
    "HoldRationale",
  );
  assert.equal(decidedHold.decision.decision, "grant");
  assert.equal(
    decidedHold.decision.governance_clearance,
    "not_required",
    "no clearance variant is named `verified`; nothing here establishes one",
  );
});

test("severity is SCREAMING_SNAKE and state is snake_case on the wire", () => {
  assert.equal(openHold.severity, "CRITICAL");
  assert.equal(openHold.state, "notified");
  assert.equal(decidedHold.state, "executed");
});

test("inverse_resolution names its producing function and omits an absent reason", () => {
  const steps = decidedHold.inverse_resolution;
  assert.ok(steps.length >= 2);
  for (const step of steps) {
    assert.equal(step.derived_by, "swarm_response::rollback::resolve_inverse");
    assert.ok(
      ["executable", "irreversible", "unmapped"].includes(step.verdict),
    );
  }
  assert.ok(
    !("reason" in steps[0]),
    "an absent reason is ABSENT, not null: the type marks it optional",
  );
});

test("inverse_resolution step_kind is the Debug name, not the rollback slug", () => {
  // The daemon builds `step_kind` with `format!("{:?}")` while the same enum
  // serialises as snake_case inside `rehearsal.rollback.steps[].kind`. Joining
  // the two lists on the raw string is the obvious bug; this locks the fact
  // that they are spelled differently so nothing derives one from the other.
  assert.equal(
    decidedHold.inverse_resolution[0].step_kind,
    "RestoreHostConnectivity",
  );
  assert.equal(
    decidedHold.rehearsal.rollback.steps[0].kind,
    "restore_host_connectivity",
  );
});

test("the action carries its discriminator and the request carries its origin", () => {
  assert.equal(openHold.action_request.action.type, "isolate_host");
  assert.equal(openHold.action_kind, "isolate_host");
  assert.equal(typeof openHold.action_request.hunt_id, "string");
  assert.equal(typeof openHold.action_request.requested_by, "string");
});

test("policy_decision carries the verdict the wave-2 draft omitted", () => {
  assert.deepEqual(Object.keys(openHold.policy_decision).sort(), [
    "reason",
    "rule_name",
    "verdict",
  ]);
  assert.equal(openHold.policy_decision.verdict, "require_human");
});

test("the two hold reads are registered read commands, not writes", () => {
  for (const command of ["perch_list_holds", "perch_get_hold"]) {
    assert.ok(
      PERCH_READ_COMMANDS.includes(command),
      `${command} is missing from PERCH_READ_COMMANDS`,
    );
    assert.ok(PERCH_TAURI_COMMANDS.includes(command));
  }
  assert.equal(
    new Set(PERCH_TAURI_COMMANDS).size,
    PERCH_TAURI_COMMANDS.length,
    "a command listed twice would let the E2E bridge answer one and miss one",
  );
});
