import assert from "node:assert/strict";
import test from "node:test";

import {
  armGrant,
  disarmGrant,
  isGrantArmed,
  noteHoldSelected,
  resetKeymapArmingState,
} from "./keymapArmingState.ts";

test("arming is per hold and resets on selection change and on community reset", () => {
  resetKeymapArmingState();
  noteHoldSelected("h_a07aeacf");
  armGrant("h_a07aeacf");
  assert.equal(isGrantArmed("h_a07aeacf"), true);

  noteHoldSelected("h_b18bfbd0");
  assert.equal(
    isGrantArmed("h_a07aeacf"),
    false,
    "an armed grant must not follow the cursor onto another hold",
  );

  armGrant("h_b18bfbd0");
  resetKeymapArmingState();
  assert.equal(isGrantArmed("h_b18bfbd0"), false);
});

test("an armed hold is armed for that id only, never for whatever is selected", () => {
  resetKeymapArmingState();
  noteHoldSelected("h_a07aeacf");
  armGrant("h_a07aeacf");
  assert.equal(isGrantArmed("h_b18bfbd0"), false);
  assert.equal(isGrantArmed(""), false);
});

test("re-selecting the same hold does not disarm", () => {
  // A queue refetch re-renders the row and re-reports the same selection. If
  // that disarmed, the second stroke would land on nothing and the operator
  // would press Enter twice for one decision.
  resetKeymapArmingState();
  noteHoldSelected("h_a07aeacf");
  armGrant("h_a07aeacf");
  noteHoldSelected("h_a07aeacf");
  assert.equal(isGrantArmed("h_a07aeacf"), true);
});

test("deselecting disarms", () => {
  resetKeymapArmingState();
  noteHoldSelected("h_a07aeacf");
  armGrant("h_a07aeacf");
  noteHoldSelected(null);
  assert.equal(isGrantArmed("h_a07aeacf"), false);
});

test("disarming is explicit and does not need a selection change", () => {
  resetKeymapArmingState();
  noteHoldSelected("h_a07aeacf");
  armGrant("h_a07aeacf");
  disarmGrant();
  assert.equal(isGrantArmed("h_a07aeacf"), false);
});
