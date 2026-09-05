import assert from "node:assert/strict";
import { test } from "node:test";

import {
  deriveContainmentState,
  EXPIRING_UNDER_MS,
  remainingMsAt,
} from "./containmentState.ts";

test("remaining_ms and expired are two facts: 0/false and 0/true differ", () => {
  assert.equal(
    deriveContainmentState({
      remainingMs: 0,
      expired: false,
      daemonReachable: true,
    }),
    "expiring",
  );
  assert.equal(
    deriveContainmentState({
      remainingMs: 0,
      expired: true,
      daemonReachable: true,
    }),
    "expired-still-listed",
  );
});

test("expiring is strictly under fifteen seconds", () => {
  assert.equal(EXPIRING_UNDER_MS, 15_000);
  assert.equal(
    deriveContainmentState({
      remainingMs: 15_000,
      expired: false,
      daemonReachable: true,
    }),
    "open",
  );
  assert.equal(
    deriveContainmentState({
      remainingMs: 14_999,
      expired: false,
      daemonReachable: true,
    }),
    "expiring",
  );
});

test("daemon down splits by the same fact", () => {
  assert.equal(
    deriveContainmentState({
      remainingMs: 40_000,
      expired: false,
      daemonReachable: false,
    }),
    "daemon-down-open",
  );
  assert.equal(
    deriveContainmentState({
      remainingMs: 0,
      expired: true,
      daemonReachable: false,
    }),
    "daemon-down-expired",
  );
});

test("an unreachable daemon outranks expiry-soon: the board cannot offer release at all", () => {
  assert.equal(
    deriveContainmentState({
      remainingMs: 1,
      expired: false,
      daemonReachable: false,
    }),
    "daemon-down-open",
    "with the daemon down there is no early release to offer, whatever the clock says",
  );
});

test("remaining is recomputed from the daemon's expiry and saturates at zero", () => {
  assert.equal(remainingMsAt(1_000, 400), 600);
  assert.equal(remainingMsAt(1_000, 1_000), 0);
  assert.equal(
    remainingMsAt(1_000, 9_999),
    0,
    "a passed expiry reads zero, never negative",
  );
});
