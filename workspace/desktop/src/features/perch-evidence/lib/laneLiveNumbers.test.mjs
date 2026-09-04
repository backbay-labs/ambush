import assert from "node:assert/strict";
import { test } from "node:test";

import {
  LANE_STALE_AFTER_MS,
  laneLiveNumbers,
  laneTelemetryIsStale,
} from "./laneLiveNumbers.ts";

const POLICY = { alertThreshold: 2, incidentThreshold: 5 };

function entry(receivedAtMs, concentrations) {
  return {
    kind: 26001,
    pubkey: "ab".repeat(32),
    receivedAtMs,
    body: { concentrations },
  };
}

test("no frame is null, which is not the same as a concentration of zero", () => {
  assert.equal(laneLiveNumbers(undefined, "execution", POLICY, 1_000), null);
  const present = laneLiveNumbers(
    entry(1_000, [{ threat_class: "execution", total_strength: 0 }]),
    "execution",
    POLICY,
    1_000,
  );
  assert.equal(
    present?.totalStrength,
    0,
    "a real zero is a reading, and reads as one",
  );
});

test("a class the frame does not carry is null, never another class's number", () => {
  const numbers = laneLiveNumbers(
    entry(1_000, [{ threat_class: "defense_evasion", total_strength: 9 }]),
    "execution",
    POLICY,
    1_000,
  );
  assert.equal(numbers, null);
});

test("above-alert is decided against the served threshold, inclusive at the boundary", () => {
  const at = laneLiveNumbers(
    entry(0, [{ threat_class: "execution", total_strength: 2 }]),
    "execution",
    POLICY,
    0,
  );
  assert.equal(at?.aboveAlert, true);
  const below = laneLiveNumbers(
    entry(0, [{ threat_class: "execution", total_strength: 1.99 }]),
    "execution",
    POLICY,
    0,
  );
  assert.equal(below?.aboveAlert, false);
});

test("age is carried so a frozen reading cannot be presented as a live one", () => {
  const numbers = laneLiveNumbers(
    entry(1_000, [{ threat_class: "execution", total_strength: 3 }]),
    "execution",
    POLICY,
    1_000 + LANE_STALE_AFTER_MS + 1,
  );
  assert.ok(numbers);
  assert.equal(numbers.ageMs, LANE_STALE_AFTER_MS + 1);
  assert.equal(laneTelemetryIsStale(numbers), true);
});

test("a clock that runs backwards reads zero age, never negative", () => {
  const numbers = laneLiveNumbers(
    entry(9_000, [{ threat_class: "execution", total_strength: 3 }]),
    "execution",
    POLICY,
    1_000,
  );
  assert.equal(numbers?.ageMs, 0);
});
