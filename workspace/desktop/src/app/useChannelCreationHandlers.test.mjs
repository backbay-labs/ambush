import assert from "node:assert/strict";
import test from "node:test";

import { routeBrowseChannelCreate } from "./useChannelCreationHandlers.ts";

const INPUT = {
  description: "Operational discussion",
  name: "watch",
  templateId: "operator",
  ttlSeconds: 3_600,
  visibility: "private",
};

test("browse creation routes forums only to the forum handler", async () => {
  const calls = [];
  const onCreated = () => calls.push(["callback"]);

  await routeBrowseChannelCreate({
    browseDialogType: "forum",
    getCreateSuccess: () => onCreated,
    handleCreateChannel: async (...args) => calls.push(["stream", ...args]),
    handleCreateForum: async (...args) => calls.push(["forum", ...args]),
    input: INPUT,
  });

  assert.deepEqual(calls, [["forum", INPUT]]);
});

test("browse creation routes streams with the success callback unchanged", async () => {
  const calls = [];
  const onCreated = () => calls.push(["callback"]);

  await routeBrowseChannelCreate({
    browseDialogType: "stream",
    getCreateSuccess: () => onCreated,
    handleCreateChannel: async (...args) => calls.push(["stream", ...args]),
    handleCreateForum: async (...args) => calls.push(["forum", ...args]),
    input: INPUT,
  });

  assert.deepEqual(calls, [["stream", INPUT, onCreated]]);
});
