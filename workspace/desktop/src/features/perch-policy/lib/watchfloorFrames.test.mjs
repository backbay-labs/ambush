import assert from "node:assert/strict";
import { test } from "node:test";

import {
  appendSample,
  colonyAgents,
  colonyMode,
  frameAgeSeconds,
  sampleForClass,
} from "./watchfloorFrames.ts";

const entry = (body, receivedAtMs = 5_000) => ({
  kind: 26001,
  pubkey: "aa",
  receivedAtMs,
  body,
});

test("a class absent from the frame is null, never zero", () => {
  assert.equal(
    sampleForClass(
      entry({
        concentrations: [{ threat_class: "execution", total_strength: 1 }],
      }),
      "impact",
    ),
    null,
  );
});

test("no frame at all is null", () => {
  assert.equal(sampleForClass(undefined, "execution"), null);
  assert.equal(colonyAgents(undefined), null);
  assert.equal(colonyMode(undefined), null);
  assert.equal(frameAgeSeconds(undefined, 1_000), null);
});

test("a row with a non-numeric strength is null rather than coerced", () => {
  assert.equal(
    sampleForClass(
      entry({
        concentrations: [{ threat_class: "execution", total_strength: "2" }],
      }),
      "execution",
    ),
    null,
  );
});

test("missing companions default to zero, but only once the strength is real", () => {
  const sample = sampleForClass(
    entry({
      concentrations: [{ threat_class: "execution", total_strength: 2.5 }],
    }),
    "execution",
  );
  assert.deepEqual(sample, {
    at: 5,
    total_strength: 2.5,
    distinct_sources: 0,
    peak_confidence: 0,
  });
});

test("the ring drops the oldest, never the newest", () => {
  let history = [];
  for (let i = 0; i < 10; i += 1) {
    history = appendSample(
      history,
      { at: i, total_strength: i, distinct_sources: 0, peak_confidence: 0 },
      3,
    );
  }
  assert.deepEqual(
    history.map((s) => s.at),
    [7, 8, 9],
  );
});

test("a repeated timestamp does not grow the ring", () => {
  const sample = {
    at: 1,
    total_strength: 1,
    distinct_sources: 0,
    peak_confidence: 0,
  };
  const once = appendSample([], sample, 5);
  const twice = appendSample(once, sample, 5);
  assert.equal(twice.length, 1);
});

test("frame age never goes negative when the clock steps back", () => {
  assert.equal(frameAgeSeconds(entry({}, 10_000), 5_000), 0);
});

test("an agent row with no id is dropped rather than rendered as unknown", () => {
  const agents = colonyAgents(
    entry({
      agents: [
        { role: "detector" },
        { agent_id: "a1", role: "detector", healthy: true },
      ],
    }),
  );
  assert.deepEqual(agents, [
    { agentId: "a1", role: "detector", healthy: true },
  ]);
});

test("healthy is true only when the frame says exactly true", () => {
  const agents = colonyAgents(
    entry({ agents: [{ agent_id: "a1", healthy: "yes" }] }),
  );
  assert.equal(agents[0].healthy, false);
  assert.equal(agents[0].role, "unknown role");
});

test("an empty agents array is zero agents KNOWN, which is not null", () => {
  assert.deepEqual(colonyAgents(entry({ agents: [] })), []);
});
