import assert from "node:assert/strict";
import test from "node:test";

import {
  getVerdictWriteState,
  resetPerchWriteStates,
  setVerdictWriteState,
  subscribeVerdictWriteStates,
} from "./verdictWriteState.ts";

test("write state is per finding, observable, and resets", () => {
  setVerdictWriteState("f1", { phase: "sending" });
  setVerdictWriteState("f1", { phase: "recorded", atMs: 5 });
  assert.deepEqual(getVerdictWriteState("f1"), { phase: "recorded", atMs: 5 });
  assert.deepEqual(getVerdictWriteState("f2"), { phase: "idle" });
  resetPerchWriteStates();
  assert.deepEqual(getVerdictWriteState("f1"), { phase: "idle" });
});

test("an unknown finding reads a frozen, reference-stable idle state", () => {
  resetPerchWriteStates();
  const first = getVerdictWriteState("unknown");
  assert.equal(first, getVerdictWriteState("unknown"));
  assert.ok(Object.isFrozen(first));
  assert.equal(first, getVerdictWriteState("another"));
});

test("listeners fire on every set and on reset, and stop after unsubscribe", () => {
  resetPerchWriteStates();
  const seen = [];
  const unsubscribe = subscribeVerdictWriteStates(() =>
    seen.push(getVerdictWriteState("f1").phase),
  );
  setVerdictWriteState("f1", { phase: "sending" });
  setVerdictWriteState("f1", {
    phase: "daemon-unreachable",
    reason: "refused",
  });
  setVerdictWriteState("f1", { phase: "not-yet-correlated" });
  setVerdictWriteState("f1", {
    phase: "acknowledged",
    atMs: 9,
    feedbackId: "fb-1",
  });
  resetPerchWriteStates();
  assert.deepEqual(seen, [
    "sending",
    "daemon-unreachable",
    "not-yet-correlated",
    "acknowledged",
    "idle",
  ]);
  unsubscribe();
  setVerdictWriteState("f1", { phase: "failed", reason: "x" });
  assert.equal(seen.length, 5);
  resetPerchWriteStates();
});
