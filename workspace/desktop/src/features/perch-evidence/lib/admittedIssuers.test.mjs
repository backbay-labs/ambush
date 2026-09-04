import assert from "node:assert/strict";
import test from "node:test";

import {
  admittedIssuersKnown,
  countUnadmittedMarker,
  ensureAdmittedIssuersLoaded,
  isAdmittedIssuer,
  perchLaneChannelIds,
  readPerchCounter,
  resetPerchAdmittedIssuers,
  setAdmittedIssuers,
  subscribePerchCounters,
} from "./admittedIssuers.ts";

test("the predicate is reference-stable across set updates and false when empty", () => {
  const before = isAdmittedIssuer;
  assert.equal(isAdmittedIssuer("ab".repeat(32)), false);
  setAdmittedIssuers(["AB".repeat(32)], {
    execution: "a30249d7-446b-4135-8e9f-8704a5a052b1",
  });
  assert.equal(isAdmittedIssuer("ab".repeat(32)), true, "lowercased on set");
  assert.equal(before, isAdmittedIssuer);
  assert.deepEqual(perchLaneChannelIds(), [
    "a30249d7-446b-4135-8e9f-8704a5a052b1",
  ]);
  countUnadmittedMarker("e1");
  countUnadmittedMarker("e1");
  countUnadmittedMarker("e2");
  assert.equal(
    readPerchCounter("perch_marker_unadmitted_total"),
    2,
    "one count per event id",
  );
  resetPerchAdmittedIssuers();
  assert.equal(isAdmittedIssuer("ab".repeat(32)), false);
  assert.equal(readPerchCounter("perch_marker_unadmitted_total"), 0);
});

test("lane ids are reference-stable until the set changes, deduplicated, and empty after reset", () => {
  resetPerchAdmittedIssuers();
  const empty = perchLaneChannelIds();
  assert.deepEqual(empty, []);
  assert.equal(empty, perchLaneChannelIds());
  setAdmittedIssuers([], { a: "lane-1", b: "lane-2", c: "lane-1" });
  const lanes = perchLaneChannelIds();
  assert.deepEqual(lanes, ["lane-1", "lane-2"]);
  assert.equal(lanes, perchLaneChannelIds());
  assert.ok(Object.isFrozen(lanes));
  resetPerchAdmittedIssuers();
  assert.deepEqual(perchLaneChannelIds(), []);
});

test("listeners fire on a set update, on a new unadmitted event id, and on reset", () => {
  resetPerchAdmittedIssuers();
  let fired = 0;
  const unsubscribe = subscribePerchCounters(() => {
    fired += 1;
  });
  setAdmittedIssuers(["cd".repeat(32)], {});
  assert.equal(fired, 1);
  countUnadmittedMarker("e9");
  countUnadmittedMarker("e9");
  assert.equal(fired, 2, "a repeated event id is not a change");
  resetPerchAdmittedIssuers();
  assert.equal(fired, 3);
  unsubscribe();
  setAdmittedIssuers([], {});
  assert.equal(fired, 3);
  resetPerchAdmittedIssuers();
});

test("the loader runs at most once per window, applies its result, and a failure keeps the previous set", async () => {
  resetPerchAdmittedIssuers();
  let calls = 0;
  const loader = async () => {
    calls += 1;
    return { issuers: ["EF".repeat(32)], lanes: { execution: "lane-x" } };
  };
  await ensureAdmittedIssuersLoaded(loader);
  await ensureAdmittedIssuersLoaded(loader);
  assert.equal(calls, 1, "a second call inside the window does not reload");
  assert.equal(isAdmittedIssuer("ef".repeat(32)), true);
  assert.deepEqual(perchLaneChannelIds(), ["lane-x"]);

  resetPerchAdmittedIssuers();
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => warnings.push(args);
  try {
    setAdmittedIssuers(["01".repeat(32)], { a: "lane-a" });
    await ensureAdmittedIssuersLoaded(async () => {
      throw new Error("daemon unreachable");
    });
  } finally {
    console.warn = originalWarn;
  }
  assert.equal(isAdmittedIssuer("01".repeat(32)), true, "previous set kept");
  assert.deepEqual(perchLaneChannelIds(), ["lane-a"]);
  assert.equal(warnings.length, 1);
  resetPerchAdmittedIssuers();
});

test("nothing is counted until the console has an authoritative set", () => {
  resetPerchAdmittedIssuers();
  assert.equal(admittedIssuersKnown(), false);
  // The cold-start window: every marker looks unadmitted because the daemon
  // has not answered yet. Counting it would make the counter a launch count.
  countUnadmittedMarker("event-before-the-answer");
  assert.equal(readPerchCounter("perch_marker_unadmitted_total"), 0);
  setAdmittedIssuers([], {});
  assert.equal(admittedIssuersKnown(), true, "an empty answer is an answer");
  countUnadmittedMarker("event-before-the-answer");
  countUnadmittedMarker("event-before-the-answer");
  assert.equal(
    readPerchCounter("perch_marker_unadmitted_total"),
    1,
    "counted once, and only after the set is known",
  );
  resetPerchAdmittedIssuers();
  assert.equal(admittedIssuersKnown(), false, "a community switch un-knows it");
});

test("a failed load leaves the set unknown, so nothing is refused on no answer", async () => {
  resetPerchAdmittedIssuers();
  await ensureAdmittedIssuersLoaded(async () => {
    throw new Error("daemon unreachable");
  });
  assert.equal(admittedIssuersKnown(), false);
  countUnadmittedMarker("event-after-a-failed-load");
  assert.equal(readPerchCounter("perch_marker_unadmitted_total"), 0);
  resetPerchAdmittedIssuers();
});
