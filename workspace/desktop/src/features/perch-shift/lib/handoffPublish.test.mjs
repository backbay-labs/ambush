import assert from "node:assert/strict";
import { test } from "node:test";

import { publishHandoff } from "./handoffPublish.ts";

test("a partial publish reports which channels took it and which did not", async () => {
  const outcome = await publishHandoff(["a", "b", "c"], "block", async (id) => {
    if (id === "b") throw new Error("relay refused");
  });
  assert.deepEqual(outcome.published, ["a", "c"]);
  assert.deepEqual(outcome.failed, [
    { channelId: "b", reason: "relay refused" },
  ]);
});

test("one failure does not stop the rest, and does not undo what published", async () => {
  const sent = [];
  const outcome = await publishHandoff(["a", "b", "c"], "block", async (id) => {
    sent.push(id);
    if (id === "a") throw new Error("down");
  });
  assert.deepEqual(sent, ["a", "b", "c"]);
  assert.deepEqual(outcome.published, ["b", "c"]);
});

test("every channel gets the same bytes", async () => {
  const bodies = new Set();
  await publishHandoff(
    ["a", "b"],
    "END WATCH — connor",
    async (_id, content) => {
      bodies.add(content);
    },
  );
  assert.equal(bodies.size, 1);
});

test("a non-Error rejection still names a reason", async () => {
  const outcome = await publishHandoff(["a"], "block", async () => {
    throw "socket closed";
  });
  assert.deepEqual(outcome.failed, [
    { channelId: "a", reason: "socket closed" },
  ]);
});
