import assert from "node:assert/strict";
import { test } from "node:test";

import {
  caseChannelsOf,
  caseFromHold,
  containmentsForShift,
  expiredAfterMinutes,
  expiredUndecidedHolds,
} from "./shiftInputs.ts";

const hold = (over = {}) => ({
  hold_id: "h1",
  state: "notified",
  notified_at_ms: 1,
  deciding_intent_event_id: null,
  case_channel: "c1",
  notice_event_id: null,
  card_event_id: null,
  action_kind: "isolate_host",
  severity: "high",
  held_at_ms: 0,
  expires_at_ms: 900_000,
  remaining_ms: 0,
  expired: true,
  action_request: {
    hunt_id: "x",
    requested_by: "y",
    action: { type: "isolate_host" },
    severity: "high",
    evidence: {},
  },
  policy_decision: { verdict: "require_human", reason: "r" },
  rationale: {
    rule_name: "r",
    reason: "r",
    threat_class: "lateral_movement",
    severity: "high",
    request_carried_fields: [],
    concentration_at_hold: null,
    escalation_level: null,
    governance_receipt_present: false,
  },
  leases_a_containment: true,
  rehearsal: null,
  inverse_resolution: [],
  decision: null,
  ...over,
});

test("expired-undecided is the expired flag AND no decision, not a clock reading", () => {
  const rows = [
    hold(),
    hold({ hold_id: "h2", decision: { state: "refused" } }),
    hold({ hold_id: "h3", expired: false, remaining_ms: 0 }),
  ];
  assert.deepEqual(
    expiredUndecidedHolds(rows).map((h) => h.hold_id),
    ["h1"],
    "a decided hold is not undecided, and remaining_ms saturates at zero for both",
  );
});

test("the expiry window is minutes, never negative", () => {
  assert.equal(expiredAfterMinutes(hold()), 15);
  assert.equal(expiredAfterMinutes(hold({ expires_at_ms: -1_000 })), 0);
});

test("case channels are distinct and first-seen, and a hold without one is skipped", () => {
  const rows = [
    hold(),
    hold({ hold_id: "h2" }),
    hold({ hold_id: "h3", case_channel: "c2" }),
    hold({ hold_id: "h4", case_channel: null }),
  ];
  assert.deepEqual(caseChannelsOf(rows), ["c1", "c2"]);
});

test("a custom threat class renders its text, not [object Object]", () => {
  const c = caseFromHold(
    hold({
      rationale: { ...hold().rationale, threat_class: { custom: "beaconing" } },
    }),
  );
  assert.equal(c.threatClass, "beaconing");
});

test("a hold with no case channel produces no case", () => {
  assert.equal(caseFromHold(hold({ case_channel: null })), null);
});

test("the containment carries the daemon's own scope value as the host", () => {
  const [c] = containmentsForShift([
    { leaseId: "cl_1", scopeValue: "web-04", remainingMs: 0, expired: true },
  ]);
  assert.deepEqual(c, {
    leaseId: "cl_1",
    host: "web-04",
    remainingMs: 0,
    expired: true,
  });
});
