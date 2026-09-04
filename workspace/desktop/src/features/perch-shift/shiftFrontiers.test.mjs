import assert from "node:assert/strict";
import { test } from "node:test";

import { foldReadFrontiers } from "./useShiftFrontiers.ts";

const seed = {
  channelId: "c1",
  slug: "case-0001",
  threatClass: "execution",
  canvasLines: 3,
  archivedAtMs: null,
  handoffNotes: null,
  threadRoots: [
    { rootId: "r1", lastReplyAtSeconds: 1_000 },
    { rootId: "r2", lastReplyAtSeconds: 2_000 },
  ],
};

test("seconds from the shell become milliseconds in the block", () => {
  const [c] = foldReadFrontiers(
    [seed],
    () => 1_700_000_000,
    () => 9_999,
  );
  assert.equal(c.readToMs, 1_700_000_000_000);
});

test("an unknown channel frontier stays null rather than becoming epoch zero", () => {
  const [c] = foldReadFrontiers(
    [seed],
    () => null,
    () => 9_999,
  );
  assert.equal(c.readToMs, null);
});

test("a thread never opened counts as unread", () => {
  const [c] = foldReadFrontiers(
    [seed],
    () => null,
    () => null,
  );
  assert.equal(c.openThreadsUnread, 2);
});

test("a frontier behind the last reply counts, one at or past it does not", () => {
  const frontiers = { r1: 999, r2: 2_000 };
  const [c] = foldReadFrontiers(
    [seed],
    () => null,
    (rootId) => frontiers[rootId],
  );
  assert.equal(c.openThreadsUnread, 1);
});

test("the thread roots do not leak into the composed case", () => {
  const [c] = foldReadFrontiers(
    [seed],
    () => null,
    () => null,
  );
  assert.equal("threadRoots" in c, false);
});
