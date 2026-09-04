// The reconciliation reducer, against the daemon's real bytes.
//
// The hold fixture is the daemon's own serialisation (see
// `shared/api/tauriPerch.test.mjs`), overridden field by field, so a reducer
// that only works on a hand-simplified view fails here.

import assert from "node:assert/strict";
import test from "node:test";

import fixture from "../../../testing/perch/daemonHoldFixture.json" with {
  type: "json",
};
import {
  PERCH_QUEUE_DEPTH_ALARM,
  reconcileHoldQueue,
  UNRECONCILED_DURABLE_REASON,
  UNRECONCILED_NON_DURABLE_REASON,
} from "./holdRows.ts";

const BRIDGE = "20".repeat(32);
const STRANGER = "68".repeat(32);
const CASE = "27799e23-ab25-4659-b381-3de47ea7ca4d";
const NOW = 1_773_739_200_000;

const hold = (id, extra = {}) => ({
  ...fixture.list.holds[0],
  hold_id: id,
  state: "notified",
  notified_at_ms: NOW - 100,
  case_channel: CASE,
  held_at_ms: NOW - 1000,
  expires_at_ms: NOW + 3_600_000,
  remaining_ms: 3_600_000,
  expired: false,
  ...extra,
});

const daemon = (holds, extra = {}) => ({
  schema_version: 1,
  observed_at_ms: NOW,
  holds,
  open_count: holds.filter((h) =>
    ["created", "notified", "armed", "deciding"].includes(h.state),
  ).length,
  truncated: false,
  deciding_stalled_count: 0,
  store_durable: false,
  ...extra,
});

const notice = (holdId, pubkey = BRIDGE, extra = {}) => ({
  id: "0".repeat(64),
  kind: 46010,
  pubkey,
  content: `hold ${holdId} · isolate_host · CRITICAL · host h · expires x`,
  createdAt: 1,
  channelId: CASE,
  channelName: "case",
  tags: [
    ["h", CASE],
    ["p", "68".repeat(32)],
    ["hold", holdId],
  ],
  category: "needs_action",
  ...extra,
});

test("a daemon hold with a relay notice is one ordinary row and no divergence", () => {
  const out = reconcileHoldQueue({
    daemon: daemon([hold("h_a07aeacf")]),
    relayNotices: [notice("h_a07aeacf")],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  assert.equal(out.rows.length, 1);
  assert.equal(out.rows[0].kind, "hold");
  assert.equal(out.rows[0].noticed, true);
  assert.equal(out.divergences, 0);
});

test("a relay notice with no daemon record renders UNRECONCILED, keyed on store durability", () => {
  const nonDurable = reconcileHoldQueue({
    daemon: daemon([], { store_durable: false }),
    relayNotices: [notice("h_1c28ae79")],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  assert.equal(nonDurable.rows[0].kind, "unreconciled");
  assert.equal(nonDurable.rows[0].register, "ordinary");
  assert.match(nonDurable.rows[0].reason, /store_durable/);
  assert.equal(nonDurable.rows[0].reason, UNRECONCILED_NON_DURABLE_REASON);
  assert.equal(nonDurable.divergences, 1);

  const durable = reconcileHoldQueue({
    daemon: daemon([], { store_durable: true }),
    relayNotices: [notice("h_1c28ae79")],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  assert.equal(durable.rows[0].register, "destructive");
  assert.match(durable.rows[0].reason, /durable hold store and no record/);
  assert.equal(durable.rows[0].reason, UNRECONCILED_DURABLE_REASON);
  assert.equal(durable.divergences, 1);
});

test("an unadmitted notice renders nothing of its own and increments a separate counter", () => {
  const out = reconcileHoldQueue({
    daemon: daemon([]),
    relayNotices: [notice("h_1c28ae79", STRANGER)],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  assert.equal(out.rows.length, 0);
  assert.equal(out.divergences, 0);
  assert.equal(out.unadmittedFrames, 1);
});

test("an expired hold stays in the queue as an expired row, oldest first, and 12 open holds trip the alarm", () => {
  const holds = Array.from({ length: PERCH_QUEUE_DEPTH_ALARM }, (_, i) =>
    hold(`h_open${String(i).padStart(4, "0")}`, { held_at_ms: NOW - i }),
  );
  holds.push(
    hold("h_expired01", {
      state: "expired",
      expired: true,
      remaining_ms: 0,
      held_at_ms: NOW - 99_999,
    }),
  );
  const out = reconcileHoldQueue({
    daemon: daemon(holds, { store_durable: true }),
    relayNotices: [],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  assert.equal(out.rows[0].kind, "expired");
  assert.equal(out.rows.length, PERCH_QUEUE_DEPTH_ALARM + 1);
  assert.equal(out.queueDepthAlarm, true);
  assert.equal(out.openCount, PERCH_QUEUE_DEPTH_ALARM);
});

// ---------------------------------------------------------------------------
// The daemon is the authority. These are the disagreement cases.
// ---------------------------------------------------------------------------

test("a daemon hold with NO relay notice still renders: the daemon does not need the relay's permission", () => {
  const out = reconcileHoldQueue({
    daemon: daemon([hold("h_a07aeacf", { notified_at_ms: null })]),
    relayNotices: [],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  assert.equal(out.rows.length, 1);
  assert.equal(out.rows[0].kind, "hold");
  assert.equal(
    out.rows[0].noticed,
    false,
    "undelivered is a fact about the notice, not a reason to hide the hold",
  );
  assert.equal(out.divergences, 0);
});

test("a notice that contradicts the daemon changes nothing the operator reads", () => {
  // The relay notice claims a different action and severity from the record.
  // The row must carry the DAEMON's hold object verbatim; the notice
  // contributes exactly one bit, whether delivery happened.
  const record = hold("h_a07aeacf", { action_kind: "isolate_host" });
  const lying = notice("h_a07aeacf", BRIDGE, {
    content: "hold h_a07aeacf · delete_everything · LOW · expires never",
  });
  const out = reconcileHoldQueue({
    daemon: daemon([record]),
    relayNotices: [lying],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  assert.equal(out.rows.length, 1);
  assert.equal(out.rows[0].kind, "hold");
  assert.equal(out.rows[0].hold, record, "the row IS the daemon's record");
  assert.equal(out.rows[0].hold.action_kind, "isolate_host");
  assert.equal(out.rows[0].hold.severity, "CRITICAL");
});

test("an UNRECONCILED row carries no content the relay supplied", () => {
  // The whole point: a hold the daemon has never heard of must not be
  // rendered AS a hold. The row may name the id and the event that claimed it
  // and nothing else — no severity, no action kind, no expiry, all of which
  // the notice's content string offers and none of which is a fact.
  const out = reconcileHoldQueue({
    daemon: daemon([], { store_durable: true }),
    relayNotices: [notice("h_1c28ae79")],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  const row = out.rows[0];
  assert.deepEqual(Object.keys(row).sort(), [
    "holdId",
    "kind",
    "noticeEventId",
    "reason",
    "register",
  ]);
  assert.equal(row.holdId, "h_1c28ae79");
  assert.equal(row.noticeEventId, "0".repeat(64));
});

test("a notice for a hold the daemon has DECIDED is not a divergence and adds no row", () => {
  // `build_needs_action_query` has no status join, so a decided hold stays in
  // the relay feed forever. The daemon knowing about it is what makes this
  // reconciled; the absent row is the reconciliation, not a divergence.
  const decided = {
    ...fixture.decided_hold,
    hold_id: "h_a07aeacf",
    held_at_ms: NOW - 1000,
  };
  const out = reconcileHoldQueue({
    daemon: daemon([decided], { open_count: 0, store_durable: true }),
    relayNotices: [notice("h_a07aeacf")],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  assert.equal(out.rows.length, 0);
  assert.equal(out.divergences, 0);
  assert.equal(out.queueDepthAlarm, false);
});

test("a null daemon answer produces no rows and no divergence: unknown is not empty", () => {
  // An unreachable daemon cannot say a notice is unreconciled — it cannot say
  // anything. Inventing a divergence here would turn every offline moment
  // into a governance alert.
  const out = reconcileHoldQueue({
    daemon: null,
    relayNotices: [notice("h_1c28ae79")],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  assert.equal(out.rows.length, 0);
  assert.equal(out.divergences, 0);
  assert.equal(out.openCount, 0);
  assert.equal(out.storeDurable, false);
  assert.equal(out.queueDepthAlarm, false);
});

test("a hold past its expiry renders expired even when the stored state has not caught up", () => {
  // The sweep runs every 5 s; between the expiry and the sweep the record
  // still says `notified`. `remaining_ms` and `expired` are two facts and the
  // clock is the one that decides whether a verdict can still land.
  const out = reconcileHoldQueue({
    daemon: daemon([
      hold("h_a07aeacf", { state: "notified", expires_at_ms: NOW - 1 }),
    ]),
    relayNotices: [],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  assert.equal(out.rows[0].kind, "expired");
});

test("the admitted comparison is case-insensitive and duplicate notices collapse", () => {
  const out = reconcileHoldQueue({
    daemon: daemon([], { store_durable: true }),
    relayNotices: [
      notice("h_1c28ae79", BRIDGE.toUpperCase()),
      notice("h_1c28ae79", BRIDGE, { id: "1".repeat(64) }),
    ],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  assert.equal(out.rows.length, 1, "one unknown hold is one row, not two");
  assert.equal(out.divergences, 1);
  assert.equal(out.unadmittedFrames, 0);
});

test("a feed item that is not a 46010, or carries no hold tag, is ignored entirely", () => {
  const out = reconcileHoldQueue({
    daemon: daemon([], { store_durable: true }),
    relayNotices: [
      { ...notice("h_1c28ae79"), kind: 9 },
      { ...notice("h_1c28ae79"), tags: [["h", CASE]] },
    ],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  assert.equal(out.rows.length, 0);
  assert.equal(out.divergences, 0);
  assert.equal(out.unadmittedFrames, 0);
});

test("rows sort oldest first and unreconciled rows sort last", () => {
  const out = reconcileHoldQueue({
    daemon: daemon(
      [
        hold("h_newer000", { held_at_ms: NOW - 10 }),
        hold("h_older000", { held_at_ms: NOW - 5000 }),
      ],
      { store_durable: true },
    ),
    relayNotices: [notice("h_unknown0")],
    admitted: new Set([BRIDGE]),
    nowMs: NOW,
  });
  assert.deepEqual(
    out.rows.map((row) =>
      row.kind === "unreconciled" ? row.holdId : row.hold.hold_id,
    ),
    ["h_older000", "h_newer000", "h_unknown0"],
  );
});
