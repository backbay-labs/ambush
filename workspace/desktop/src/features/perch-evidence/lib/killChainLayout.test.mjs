import assert from "node:assert/strict";
import { test } from "node:test";

import {
  DRAWN_NODE_CAP,
  drawnMembers,
  edgeDash,
  killChainLayout,
  nodeReason,
  NODE_HEIGHT,
  NODE_WIDTH,
} from "./killChainLayout.ts";

const member = (id, strategyId, over = {}) => ({
  findingId: id,
  strategyId,
  host: "web-04",
  confidence: 0.8,
  reason: "matched",
  ...over,
});

test("members sharing a strategy stack in one column", () => {
  const layout = killChainLayout(
    [member("f1", "s1"), member("f2", "s1"), member("f3", "s2")],
    [],
  );
  assert.deepEqual(layout.nodes, [
    { findingId: "f1", x: 0, y: 0 },
    { findingId: "f2", x: 0, y: NODE_HEIGHT + 24 },
    { findingId: "f3", x: NODE_WIDTH + 48, y: 0 },
  ]);
  assert.equal(layout.width, 2 * (NODE_WIDTH + 48) - 48);
  assert.equal(layout.height, 2 * (NODE_HEIGHT + 24) - 24);
});

test("the same input twice produces the identical layout", () => {
  const members = [member("f1", "s1"), member("f2", "s2"), member("f3", "s1")];
  assert.deepEqual(killChainLayout(members, []), killChainLayout(members, []));
});

test("an empty incident has no nodes and no negative dimensions", () => {
  const layout = killChainLayout([], []);
  assert.deepEqual(layout.nodes, []);
  assert.equal(layout.width, 0);
  assert.equal(layout.height, 0);
});

test("over the cap the drawing keeps the seed and its direct links; the rest are omitted, not dropped", () => {
  const members = [
    member("seed", "s0", { seed: true }),
    ...Array.from({ length: DRAWN_NODE_CAP }, (_, i) => member(`f${i}`, "s1")),
  ];
  const edges = [
    { from: "seed", to: "f0", dimension: "causal" },
    { from: "f1", to: "seed", dimension: "temporal" },
    { from: "f2", to: "f3", dimension: "entity" },
  ];
  const { drawn, omitted } = drawnMembers(members, edges);
  assert.deepEqual(
    drawn.map((m) => m.findingId),
    ["seed", "f0", "f1"],
    "an edge in either direction counts as a direct link",
  );
  assert.equal(
    drawn.length + omitted.length,
    members.length,
    "nothing is lost",
  );
});

test("at exactly the cap every member is drawn", () => {
  const members = Array.from({ length: DRAWN_NODE_CAP }, (_, i) =>
    member(`f${i}`, "s1"),
  );
  assert.equal(drawnMembers(members, []).omitted.length, 0);
});

test("with no marked seed the first member is the seed", () => {
  const members = Array.from({ length: DRAWN_NODE_CAP + 1 }, (_, i) =>
    member(`f${i}`, "s1"),
  );
  const { drawn } = drawnMembers(members, [
    { from: "f0", to: "f9", dimension: "causal" },
  ]);
  assert.deepEqual(
    drawn.map((m) => m.findingId),
    ["f0", "f9"],
  );
});

test("a reason is cut with an ellipsis at 33 characters, counted in code points", () => {
  assert.equal(nodeReason("short"), "short");
  assert.equal(nodeReason("a".repeat(33)), "a".repeat(33));
  assert.equal(nodeReason("a".repeat(34)), `${"a".repeat(32)}…`);
  assert.equal([...nodeReason("🐝".repeat(40))].length, 33);
});

test("four dimensions get four dash patterns, and no two are the same", () => {
  const dashes = ["temporal", "causal", "entity", "semantic"].map(edgeDash);
  assert.deepEqual(dashes, [undefined, "4 2", "2 2", "6 3"]);
  assert.equal(new Set(dashes.map(String)).size, 4);
});
