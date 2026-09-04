import assert from "node:assert/strict";
import test from "node:test";

import {
  PERCH_COUNT_UNAVAILABLE,
  PERCH_QUEUE_HIDE_WHEN_EMPTY,
  PERCH_QUEUE_LABELS,
  PERCH_QUEUE_ORDER,
  queueForFeedItem,
} from "./watchQueues.ts";

const item = (extra = {}) => ({
  id: "0".repeat(64),
  kind: 9,
  pubkey: "20".repeat(32),
  content: "a message",
  createdAt: 1,
  channelId: "27799e23-ab25-4659-b381-3de47ea7ca4d",
  channelName: "case",
  tags: [],
  category: "activity",
  ...extra,
});

test("the four queues render in reading order with the ratified labels", () => {
  assert.deepEqual(
    [...PERCH_QUEUE_ORDER],
    ["holds", "named-you", "findings", "case-activity"],
  );
  assert.deepEqual(
    PERCH_QUEUE_ORDER.map((id) => PERCH_QUEUE_LABELS[id]),
    ["Holds", "Named you", "Findings to review", "Case activity"],
  );
});

test("no queue label uses a verdict verb or a banned word", () => {
  // APPENDIX §7: no rendered `Perch`, no `Approve`/`Approved`, no `Deny`.
  const banned = /perch|approv|\bdeny\b|denied/i;
  for (const label of Object.values(PERCH_QUEUE_LABELS)) {
    assert.doesNotMatch(label, banned, `"${label}" uses a banned word`);
  }
  assert.doesNotMatch(PERCH_COUNT_UNAVAILABLE, /all clear|caught up|no data/i);
});

test("HOLDS is never hidden and NAMED YOU is absent rather than zero", () => {
  assert.equal(PERCH_QUEUE_HIDE_WHEN_EMPTY.has("holds"), false);
  assert.equal(PERCH_QUEUE_HIDE_WHEN_EMPTY.has("named-you"), true);
});

test("a 46010 routes to holds on its KIND, whatever category the relay assigned", () => {
  // The relay's needs-action query has no status join, so a decided hold stays
  // in that category forever. Routing on category alone would put a settled
  // hold in front of a human again.
  assert.equal(
    queueForFeedItem(item({ kind: 46010, category: "needs_action" })),
    "holds",
  );
  assert.equal(
    queueForFeedItem(item({ kind: 46010, category: "activity" })),
    "holds",
  );
});

test("a mention routes to NAMED YOU and a finding card to FINDINGS", () => {
  assert.equal(queueForFeedItem(item({ category: "mention" })), "named-you");
  assert.equal(
    queueForFeedItem(
      item({
        content:
          "<!-- swarm:finding:v1 -->\nfinding\n\n```swarm:finding:v1\n{}\n```",
      }),
    ),
    "findings",
  );
});

test("a verdict card is case activity, not a finding to review", () => {
  assert.equal(
    queueForFeedItem(item({ content: "<!-- swarm:verdict:v1 -->\nverdict" })),
    "case-activity",
  );
  assert.equal(queueForFeedItem(item()), "case-activity");
});

test("the marker match uses line 0 with trailing whitespace trimmed, never leading", () => {
  // ADR 0014 C1: `trimEnd`, never `trimStart`. A leading space means the line
  // is not the marker, and treating it as one is how an unsigned card gets
  // rendered as a governance card.
  assert.equal(
    queueForFeedItem(item({ content: "<!-- swarm:finding:v1 -->   \nbody" })),
    "findings",
  );
  assert.equal(
    queueForFeedItem(item({ content: " <!-- swarm:finding:v1 -->\nbody" })),
    "case-activity",
  );
});
