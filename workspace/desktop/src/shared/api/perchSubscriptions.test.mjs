import assert from "node:assert/strict";
import test from "node:test";

import {
  assertPerchRepairKindsCovered,
  buildPerchSubscriptions,
  closePerchGap,
  isPerchEphemeralKind,
  observeIssuerSeq,
  PERCH_CASE_REPAIR_KINDS,
  perchCaseLiveKinds,
  perchOpenGaps,
  perchStreamFor,
  perchSteadyStateReqFrames,
  resetPerchSeqTracking,
  resetPerchSubscriptions,
  setPerchEventSink,
  subscribePerchGaps,
  syncPerchSubscriptions,
} from "./perchSubscriptions.ts";

const ME = "a".repeat(64);

function build(overrides = {}) {
  return buildPerchSubscriptions({
    myPubkey: ME,
    laneChannelIds: [],
    activeCaseIds: [],
    openCaseId: null,
    telemetryWanted: false,
    nowSecs: 1,
    ...overrides,
  });
}

test("twelve lanes ride ONE REQ, and the steady state is at most seven", () => {
  const lanes = Array.from({ length: 12 }, (_, i) => `lane-${i}`);
  const specs = build({ laneChannelIds: lanes });
  const lane = specs.find((s) => s.id === "lane-movement");
  assert.deepEqual(lane.filter, { kinds: [9], "#h": lanes, limit: 1 });
  assert.ok(perchSteadyStateReqFrames(specs) <= 7);
  assert.equal(specs.find((s) => s.id === "watch-alarm").priority, true);
});

test("the worst-case inventory is exactly seven, and this milestone's is four", () => {
  const lanes = Array.from({ length: 12 }, (_, i) => `lane-${i}`);
  const everything = build({
    laneChannelIds: lanes,
    activeCaseIds: ["case-1", "case-2"],
    openCaseId: "case-1",
    telemetryWanted: true,
  });
  assert.equal(everything.length, 7);
  assert.equal(perchSteadyStateReqFrames(everything), 7);
  assert.equal(
    new Set(everything.map((s) => s.id)).size,
    7,
    "every id is distinct",
  );

  const firstCard = build({ laneChannelIds: lanes });
  assert.equal(perchSteadyStateReqFrames(firstCard), 4);
  for (const id of ["case-activity", "case-live", "telemetry"]) {
    assert.equal(firstCard.find((s) => s.id === id).filter, null, id);
  }
  assert.equal(build().find((s) => s.id === "lane-movement").filter, null);
});

test("the alarm REQ is global and selected by #p = me; the case REQ supersets the channel kinds", () => {
  const specs = build({ openCaseId: "case-1" });
  const alarm = specs.find((s) => s.id === "watch-alarm");
  assert.deepEqual(alarm.filter, { kinds: [26006], "#p": [ME], limit: 0 });
  assert.equal("#h" in alarm.filter, false);

  const live = specs.find((s) => s.id === "case-live");
  assert.deepEqual(live.filter["#h"], ["case-1"]);
  assert.equal(live.filter.since, 1);
  for (const kind of PERCH_CASE_REPAIR_KINDS) {
    assert.ok(live.filter.kinds.includes(kind), `case-live carries ${kind}`);
  }
  assert.equal(new Set(perchCaseLiveKinds()).size, perchCaseLiveKinds().length);
});

test("the repair-kind assertion throws in dev and returns prose in production", () => {
  assert.equal(
    assertPerchRepairKindsCovered([46010, 40100, 39005, 9], false),
    null,
  );
  assert.throws(
    () => assertPerchRepairKindsCovered([9], true),
    /46010, 40100, 39005/,
  );
  const message = assertPerchRepairKindsCovered([46010, 40100], false);
  assert.match(message, /missing 39005/);
});

test("the ephemeral block is 26000-26006 and only 26005/26006 are the alarm class", () => {
  assert.ok(isPerchEphemeralKind(26000));
  assert.ok(isPerchEphemeralKind(26006));
  assert.ok(!isPerchEphemeralKind(25999));
  assert.ok(!isPerchEphemeralKind(26007));
  assert.equal(perchStreamFor(26003), "telemetry");
  assert.equal(perchStreamFor(26005), "alarm");
  assert.equal(perchStreamFor(26006), "alarm");
});

test("a forward seq jump opens a gap; a late or duplicate seq does not", () => {
  resetPerchSeqTracking();
  assert.equal(observeIssuerSeq("i", 1, 0), null);
  assert.equal(observeIssuerSeq("i", 2, 0), null);
  assert.equal(observeIssuerSeq("i", 2, 0), null);
  assert.equal(observeIssuerSeq("i", 1, 0), null);
  const gap = observeIssuerSeq("i", 5, 99);
  assert.deepEqual(gap, {
    issuer: "i",
    expectedSeq: 3,
    receivedSeq: 5,
    missing: 2,
    firstNoticedAtMs: 99,
  });
  assert.equal(perchOpenGaps().length, 1);
  closePerchGap("i", 3);
  assert.equal(perchOpenGaps().length, 0);
});

test("gaps are per issuer, the first seq never opens one, and listeners fire only on a change", () => {
  resetPerchSeqTracking();
  const fired = [];
  const unsubscribe = subscribePerchGaps(() =>
    fired.push(perchOpenGaps().length),
  );
  assert.equal(
    observeIssuerSeq("a", 7, 0),
    null,
    "the first seq is the baseline",
  );
  assert.equal(observeIssuerSeq("b", 1, 0), null);
  assert.equal(observeIssuerSeq("a", 8, 0), null);
  assert.deepEqual(fired, [], "no gap, no notification");
  assert.ok(observeIssuerSeq("a", 10, 5));
  assert.ok(observeIssuerSeq("b", 4, 6));
  assert.deepEqual(fired, [1, 2]);
  closePerchGap("a", 9);
  closePerchGap("a", 9);
  assert.deepEqual(fired, [1, 2, 1], "closing a closed gap is silent");
  resetPerchSeqTracking();
  assert.deepEqual(fired, [1, 2, 1, 0]);
  unsubscribe();
  observeIssuerSeq("c", 1, 0);
  observeIssuerSeq("c", 9, 0);
  assert.deepEqual(fired, [1, 2, 1, 0], "unsubscribed");
  resetPerchSeqTracking();
});

test("an empty sync is a no-op, a failed open is reported and never thrown, and reset clears the sink", async () => {
  await resetPerchSubscriptions();
  const seen = [];
  setPerchEventSink((id, event) => seen.push([id, event.id]));
  assert.deepEqual(await syncPerchSubscriptions([]), {
    opened: 0,
    closed: 0,
    failed: [],
  });
  // No relay socket exists under node: every open fails at ensureConnected,
  // which the manager must report per subscription rather than reject.
  const result = await syncPerchSubscriptions(
    build({ laneChannelIds: ["lane-1"] }),
  );
  assert.equal(result.opened, 0);
  assert.deepEqual([...result.failed].sort(), [
    "lane-movement",
    "watch-alarm",
    "watch-named-you",
    "watch-snoozes",
  ]);
  assert.deepEqual(await syncPerchSubscriptions([]), {
    opened: 0,
    closed: 0,
    failed: [],
  });
  await resetPerchSubscriptions();
  assert.deepEqual(seen, []);
});
