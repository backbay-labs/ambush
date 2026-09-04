import assert from "node:assert/strict";
import { test } from "node:test";

import {
  acknowledgeHold,
  acknowledgedHolds,
  beginShift,
  resetShiftLedger,
  shiftStartMs,
} from "./shiftLedger.ts";

test("the shift start is set once and never moves", () => {
  resetShiftLedger();
  assert.equal(shiftStartMs(), null);
  assert.equal(beginShift(1_000), 1_000);
  assert.equal(
    beginShift(9_000),
    1_000,
    "a later visit must not shorten the shift",
  );
  assert.equal(shiftStartMs(), 1_000);
});

test("acknowledgement is a set, and reset clears both halves", () => {
  resetShiftLedger();
  beginShift(1_000);
  acknowledgeHold("h1");
  acknowledgeHold("h1");
  assert.equal(acknowledgedHolds().size, 1);
  resetShiftLedger();
  assert.equal(shiftStartMs(), null);
  assert.equal(acknowledgedHolds().size, 0);
});

test("reset replaces the set rather than clearing a shared reference", () => {
  resetShiftLedger();
  acknowledgeHold("h1");
  const captured = acknowledgedHolds();
  resetShiftLedger();
  acknowledgeHold("h2");
  assert.equal(
    captured.has("h2"),
    false,
    "a stale reader must not see the new community's acks",
  );
});
