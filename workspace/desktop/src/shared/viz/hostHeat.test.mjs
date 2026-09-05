import assert from "node:assert/strict";
import { test } from "node:test";

import { hostHeatRows, unattributedLabel } from "./hostHeat.ts";

const deposit = (over = {}) => ({
  agent_id: "swarm:ed25519:aa:s1",
  strategy_id: "s1",
  threat_class: "execution",
  severity: "HIGH",
  confidence: 1,
  timestamp: 0,
  decay_half_life: 3600,
  indicator: { host_id: "web-04" },
  event_id: "e1",
  ...over,
});

test("hosts are summed and sorted by strength", () => {
  const rows = hostHeatRows(
    [
      deposit(),
      deposit({ indicator: { host_id: "db-01" }, confidence: 0.5 }),
      deposit({ indicator: { host_id: "web-04" } }),
    ],
    0,
  );
  assert.deepEqual(
    rows.map((r) => [r.host, r.strength]),
    [
      ["web-04", 2],
      ["db-01", 0.5],
    ],
  );
});

test("deposits with no host land in one row that is always last", () => {
  const rows = hostHeatRows(
    [
      deposit({ indicator: {}, confidence: 10 }),
      deposit({ indicator: { host_id: "db-01" }, confidence: 0.1 }),
    ],
    0,
  );
  assert.equal(rows[rows.length - 1].host, "host unattributed");
  assert.equal(rows[rows.length - 1].unattributed, true);
  assert.equal(
    unattributedLabel(rows[rows.length - 1]),
    "host unattributed · no host_id on 1 deposit",
  );
});

test("an empty host_id is unattributed, not a host named empty string", () => {
  const rows = hostHeatRows([deposit({ indicator: { host_id: "" } })], 0);
  assert.equal(rows[0].host, "host unattributed");
});

test("a non-string host_id is unattributed rather than stringified", () => {
  const rows = hostHeatRows([deposit({ indicator: { host_id: 42 } })], 0);
  assert.equal(rows[0].host, "host unattributed");
});

test("the dominant class breaks ties on the name, so the label does not flicker", () => {
  const rows = hostHeatRows(
    [
      deposit({ threat_class: "persistence" }),
      deposit({ threat_class: "execution" }),
    ],
    0,
  );
  assert.equal(rows[0].dominantThreatClass, "execution");
});

test("strength decays, so the same deposits read lower later", () => {
  const now = hostHeatRows([deposit()], 0)[0].strength;
  const later = hostHeatRows([deposit()], 3600)[0].strength;
  assert.equal(later, now / 2);
});

test("equal strengths sort by host name, so the order is stable", () => {
  const rows = hostHeatRows(
    [
      deposit({ indicator: { host_id: "b" } }),
      deposit({ indicator: { host_id: "a" } }),
    ],
    0,
  );
  assert.deepEqual(
    rows.map((r) => r.host),
    ["a", "b"],
  );
});

test("no deposits means no rows, not a zero row for a host nobody named", () => {
  assert.deepEqual(hostHeatRows([], 0), []);
});
