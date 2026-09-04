import assert from "node:assert/strict";
import test from "node:test";

import { buildPerchSubscriptions } from "./perchSubscriptions.ts";
import {
  applyPerchEphemeralFrame,
  drainPerchAlarms,
  getPerchEphemeralSnapshot,
  PERCH_ALARM_QUEUE_CAP,
  perchLatestTelemetry,
  perchUnadmittedFrameCount,
  resetPerchEphemeralStore,
  setPerchAdmittedIssuers,
  subscribePerchEphemeral,
} from "./perchEphemeralStore.ts";
import { holdIdsToRefetch } from "./perchHoldAlarm.ts";

const ADMITTED = "20".repeat(32);
const STRANGER = "68".repeat(32);
const ME = "95".repeat(32);

test("a 26006 from an admitted issuer is queued and drained into one refetch", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers(new Set([ADMITTED]));
  assert.equal(
    applyPerchEphemeralFrame({
      kind: 26006,
      pubkey: ADMITTED,
      receivedAtMs: 1,
      body: { hold_id: "h_a07aeacf" },
    }),
    true,
  );
  assert.equal(
    applyPerchEphemeralFrame({
      kind: 26006,
      pubkey: ADMITTED,
      receivedAtMs: 2,
      body: { hold_id: "h_a07aeacf" },
    }),
    true,
  );
  const ids = holdIdsToRefetch(drainPerchAlarms());
  assert.deepEqual(
    [...ids],
    ["h_a07aeacf"],
    "two alarms for one hold collapse into one re-read",
  );
  assert.equal(drainPerchAlarms().length, 0);
});

test("a 26006 from an unadmitted issuer is counted and dropped", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers(new Set([ADMITTED]));
  assert.equal(
    applyPerchEphemeralFrame({
      kind: 26006,
      pubkey: STRANGER,
      receivedAtMs: 1,
      body: { hold_id: "h_1c28ae79" },
    }),
    false,
  );
  assert.equal(perchUnadmittedFrameCount(), 1);
  assert.equal(drainPerchAlarms().length, 0);
});

test("with no admitted set loaded nothing is admitted, and the drop is counted", () => {
  // The default must be "admit nothing", not "admit everything": the set
  // arrives asynchronously from the daemon, and a console that trusts frames
  // before it knows who to trust is a console that renders an attacker's
  // alarm during boot.
  resetPerchEphemeralStore();
  assert.equal(
    applyPerchEphemeralFrame({
      kind: 26006,
      pubkey: ADMITTED,
      receivedAtMs: 1,
      body: { hold_id: "h_a07aeacf" },
    }),
    false,
  );
  assert.equal(perchUnadmittedFrameCount(), 1);
});

test("the admitted comparison is case-insensitive on both sides", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers(new Set([ADMITTED.toUpperCase()]));
  assert.equal(
    applyPerchEphemeralFrame({
      kind: 26006,
      pubkey: ADMITTED,
      receivedAtMs: 1,
      body: { hold_id: "h_a07aeacf" },
    }),
    true,
  );
});

test("a frame outside 26000-26006 is refused outright", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers(new Set([ADMITTED]));
  for (const kind of [9, 46010, 25999, 26007]) {
    assert.equal(
      applyPerchEphemeralFrame({
        kind,
        pubkey: ADMITTED,
        receivedAtMs: 1,
        body: {},
      }),
      false,
      `kind ${kind} must not enter the ephemeral store`,
    );
  }
  assert.equal(
    perchUnadmittedFrameCount(),
    0,
    "a wrong kind is not an unadmitted ISSUER; the counters mean different things",
  );
});

test("telemetry coalesces to the latest per kind and never enters the alarm queue", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers(new Set([ADMITTED]));
  applyPerchEphemeralFrame({
    kind: 26001,
    pubkey: ADMITTED,
    receivedAtMs: 1,
    body: { concentration: 1 },
  });
  applyPerchEphemeralFrame({
    kind: 26001,
    pubkey: ADMITTED,
    receivedAtMs: 2,
    body: { concentration: 2 },
  });
  assert.equal(drainPerchAlarms().length, 0);
  assert.deepEqual(perchLatestTelemetry(26001)?.body, { concentration: 2 });
  // 26005 is the OTHER alarm kind and must queue like 26006 does.
  applyPerchEphemeralFrame({
    kind: 26005,
    pubkey: ADMITTED,
    receivedAtMs: 3,
    body: { detail: "tamper" },
  });
  assert.equal(drainPerchAlarms().length, 1);
});

test("the alarm queue is bounded and drops the oldest, never the newest", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers(new Set([ADMITTED]));
  for (let i = 0; i < PERCH_ALARM_QUEUE_CAP + 5; i += 1) {
    applyPerchEphemeralFrame({
      kind: 26006,
      pubkey: ADMITTED,
      receivedAtMs: i,
      body: { hold_id: `h_${String(i).padStart(6, "0")}` },
    });
  }
  const drained = drainPerchAlarms();
  assert.equal(drained.length, PERCH_ALARM_QUEUE_CAP);
  assert.equal(
    drained.at(-1)?.hold_id,
    `h_${String(PERCH_ALARM_QUEUE_CAP + 4).padStart(6, "0")}`,
    "the newest alarm survives a flood; an alarm is not a log line",
  );
});

test("the snapshot is reference-stable until something changes", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers(new Set([ADMITTED]));
  const first = getPerchEphemeralSnapshot();
  assert.equal(getPerchEphemeralSnapshot(), first, "no change, same object");
  let notified = 0;
  const unsubscribe = subscribePerchEphemeral(() => {
    notified += 1;
  });
  applyPerchEphemeralFrame({
    kind: 26006,
    pubkey: ADMITTED,
    receivedAtMs: 1,
    body: { hold_id: "h_a07aeacf" },
  });
  assert.equal(notified, 1);
  assert.notEqual(getPerchEphemeralSnapshot(), first);
  unsubscribe();
  applyPerchEphemeralFrame({
    kind: 26006,
    pubkey: ADMITTED,
    receivedAtMs: 2,
    body: { hold_id: "h_b07aeacf" },
  });
  assert.equal(notified, 1, "an unsubscribed listener stops hearing");
});

test("holdIdsToRefetch keeps order, dedupes, and ignores a bodyless alarm", () => {
  const ids = holdIdsToRefetch([
    { hold_id: "h_second00" },
    { hold_id: "h_first000" },
    { hold_id: "h_second00" },
    { hold_id: "" },
    { detail: "no hold id at all" },
    { hold_id: 7 },
  ]);
  assert.deepEqual([...ids], ["h_second00", "h_first000"]);
});

test("the 26006 REQ is global and p-gated: no #h, #p is me, and no other REQ can carry it", () => {
  // R-1: 26006 is in the relay's P_GATED_KINDS, so a REQ for it without a
  // `#p` equal to the reader is CLOSED. The console must therefore never
  // depend on a frame it is not addressed by, and no OTHER subscription may
  // smuggle 26006 in on a filter that would be refused.
  const specs = buildPerchSubscriptions({
    myPubkey: ME,
    laneChannelIds: ["27799e23-ab25-4659-b381-3de47ea7ca4d"],
    activeCaseIds: ["27799e23-ab25-4659-b381-3de47ea7ca4d"],
    openCaseId: "27799e23-ab25-4659-b381-3de47ea7ca4d",
  });
  const alarm = specs.find((spec) => spec.id === "watch-alarm");
  assert.ok(alarm, "the alarm REQ exists");
  assert.deepEqual(alarm.filter, { kinds: [26006], "#p": [ME], limit: 0 });
  assert.equal(alarm.filter["#h"], undefined, "26006 is global; it has no h");
  assert.equal(alarm.priority, true, "the alarm class is re-established first");
  for (const spec of specs) {
    if (!spec.filter?.kinds.includes(26006)) continue;
    assert.deepEqual(
      spec.filter["#p"],
      [ME],
      `${spec.id} carries 26006 without #p = me; the relay would CLOSE it`,
    );
  }
});
