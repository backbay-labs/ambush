import assert from "node:assert/strict";
import test from "node:test";

import { selectAfterFilterChange } from "./useHomeInboxFilterChange.ts";

const items = [
  { categories: ["mention"], conversationId: "first", id: "first-event" },
  {
    categories: ["mention", "needs_action"],
    conversationId: "second",
    id: "second-event",
  },
];

function previousSelection(overrides = {}) {
  return {
    effectiveDoneSet: new Set(),
    isNarrow: false,
    ownedAgentPubkeys: new Set(),
    selectedConversationId: null,
    unreadOnly: false,
    ...overrides,
  };
}

test("selection is preserved when its conversation remains visible", () => {
  assert.deepEqual(
    selectAfterFilterChange(
      items,
      "mention",
      previousSelection({ selectedConversationId: "second" }),
    ),
    { autoSelectedEventId: null, preserveSelection: true },
  );
});

test("selection moves to the first visible item when the old row is filtered out", () => {
  assert.deepEqual(
    selectAfterFilterChange(
      items,
      "needs_action",
      previousSelection({ selectedConversationId: "first" }),
    ),
    { autoSelectedEventId: "second-event", preserveSelection: false },
  );
});

test("an empty filtered list clears selection", () => {
  assert.deepEqual(
    selectAfterFilterChange(
      items,
      "agent_activity",
      previousSelection({ selectedConversationId: "first" }),
    ),
    { autoSelectedEventId: null, preserveSelection: false },
  );
});
