import assert from "node:assert/strict";
import { test } from "node:test";

import {
  agentIdOfSource,
  attributionText,
  sourceCounts,
} from "./sourceAttribution.ts";

const key =
  "swarm:ed25519:18085f16811dba240c5bf9ef0c0d0bc6f359e7812cdedf86e7519852307ce470";

test("two strategies under one key are two sources and one agent", () => {
  assert.equal(
    attributionText({ kind: "ids", sourceIds: [`${key}:a`, `${key}:b`] }),
    "2 sources / 1 agent",
  );
});

test("the split is the LAST colon, because an agent key contains colons", () => {
  assert.equal(agentIdOfSource(`${key}:suspicious_process_tree`), key);
});

test("a bare id with no colon is its own agent, never zero agents", () => {
  // Operator feedback arrives as a bare id. Counting it as no agent would make
  // the denominator smaller than the numerator.
  assert.equal(agentIdOfSource("operator-feedback"), "operator-feedback");
  assert.equal(
    attributionText({ kind: "ids", sourceIds: ["operator-feedback"] }),
    "1 source / 1 agent",
  );
});

test("duplicate ids are one source", () => {
  assert.deepEqual(
    sourceCounts({ kind: "ids", sourceIds: [`${key}:a`, `${key}:a`] }),
    { sources: 1, agents: 1 },
  );
});

test("an attribution carrying only a count says the agent count is not carried", () => {
  assert.equal(
    attributionText({ kind: "count", distinctSources: 12 }),
    "12 sources / agent count not carried",
  );
  assert.equal(
    attributionText({ kind: "count", distinctSources: 1 }),
    "1 source / agent count not carried",
  );
});

test("no attribution text is ever a bare number", () => {
  for (const attribution of [
    { kind: "ids", sourceIds: [] },
    { kind: "ids", sourceIds: [`${key}:a`] },
    { kind: "count", distinctSources: 0 },
  ]) {
    assert.match(attributionText(attribution), /source/);
    assert.match(attributionText(attribution), /agent/);
  }
});
