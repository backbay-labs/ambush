import assert from "node:assert/strict";
import test from "node:test";

import {
  getVerdictWriteState,
  isDaemonLegRetryable,
  VERDICT_PHASE_LABEL,
  verdictLegLabels,
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

test("the six rendered phases are exactly the six literals the plan fixes", () => {
  assert.deepEqual(Object.values(VERDICT_PHASE_LABEL), [
    "sending",
    "recorded on Ambush",
    "acknowledged by the daemon",
    "daemon unreachable — the Ambush record remains",
    "not yet correlated",
    "failed",
  ]);
  assert.ok(Object.isFrozen(VERDICT_PHASE_LABEL));
});

test("no leg-1 success ever produces a leg-2 success", () => {
  const recorded = true;
  const everyState = [
    { phase: "idle" },
    { phase: "sending" },
    { phase: "recorded", atMs: 1 },
    { phase: "acknowledged", atMs: 1, feedbackId: "fb" },
    { phase: "daemon-unreachable", reason: "refused" },
    { phase: "not-yet-correlated" },
    { phase: "failed", reason: "422" },
  ];
  for (const state of everyState) {
    const { daemon } = verdictLegLabels(state, recorded);
    if (state.phase !== "acknowledged") {
      assert.notEqual(
        daemon,
        VERDICT_PHASE_LABEL.acknowledged,
        `${state.phase} must not read as an acknowledged daemon leg`,
      );
    }
  }
  assert.deepEqual(verdictLegLabels({ phase: "recorded", atMs: 1 }, true), {
    ambush: "recorded on Ambush",
    daemon: "sending",
  });
  assert.deepEqual(
    verdictLegLabels({ phase: "acknowledged", atMs: 1, feedbackId: "f" }, true),
    { ambush: "recorded on Ambush", daemon: "acknowledged by the daemon" },
  );
  assert.deepEqual(
    verdictLegLabels({ phase: "daemon-unreachable", reason: "x" }, true),
    {
      ambush: "recorded on Ambush",
      daemon: "daemon unreachable — the Ambush record remains",
    },
  );
});

test("a phase reachable before leg 1 claims no Ambush record", () => {
  assert.deepEqual(verdictLegLabels({ phase: "not-yet-correlated" }, false), {
    ambush: null,
    daemon: "not yet correlated",
  });
  assert.deepEqual(verdictLegLabels({ phase: "failed", reason: "x" }, false), {
    ambush: null,
    daemon: null,
  });
  assert.deepEqual(verdictLegLabels({ phase: "idle" }, false), {
    ambush: null,
    daemon: null,
  });
  assert.deepEqual(verdictLegLabels({ phase: "sending" }, false), {
    ambush: "sending",
    daemon: null,
  });
});

test("only a leg-2 outcome with a leg-1 record behind it is retryable", () => {
  for (const phase of ["daemon-unreachable", "not-yet-correlated", "failed"]) {
    assert.equal(
      isDaemonLegRetryable({ phase, reason: "x" }, true),
      true,
      phase,
    );
    assert.equal(
      isDaemonLegRetryable({ phase, reason: "x" }, false),
      false,
      `${phase} with nothing published is not a retry`,
    );
  }
  for (const phase of ["idle", "sending", "recorded", "acknowledged"]) {
    assert.equal(isDaemonLegRetryable({ phase, atMs: 1 }, true), false, phase);
  }
});
