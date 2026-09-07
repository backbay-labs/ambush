import assert from "node:assert/strict";
import test from "node:test";

import {
  getPerchEphemeralSnapshot,
  perchDroppedFrameCount,
  perchLatestTelemetry,
  perchUnadmittedFrameCount,
  resetPerchEphemeralStore,
  setPerchAdmittedIssuers,
} from "./perchEphemeralStore.ts";
import {
  perchActiveCaseIds,
  perchDesiredSpecs,
  perchEventSink,
  readLaneMovementEnvelope,
  resetPerchSubscriptionManager,
} from "./perchSubscriptionManager.ts";

const ME = "a".repeat(64);
const BRIDGE = "20".repeat(32);
const STRANGER = "68".repeat(32);
const LANES = Object.freeze(["lane-a", "lane-b"]);

function inputs(overrides = {}) {
  return {
    mounted: true,
    myPubkey: ME,
    laneChannelIds: LANES,
    activeCaseIds: [],
    openCaseId: null,
    telemetryWanted: false,
    nowSecs: 1_700_000_000,
    ...overrides,
  };
}

function filterFor(specs, id) {
  const spec = specs.find((candidate) => candidate.id === id);
  assert.ok(spec, `no spec for ${id}`);
  return spec.filter;
}

// ---------------------------------------------------------------------------
// The inventory, built from what is actually true of the console
// ---------------------------------------------------------------------------

test("with nothing mounted and no identity there is no REQ at all", () => {
  assert.deepEqual(perchDesiredSpecs(inputs({ mounted: false })), []);
  assert.deepEqual(perchDesiredSpecs(inputs({ myPubkey: null })), []);
});

test("no telemetry consumer, no telemetry REQ; one consumer opens it", () => {
  assert.equal(filterFor(perchDesiredSpecs(inputs()), "telemetry"), null);
  assert.deepEqual(
    filterFor(
      perchDesiredSpecs(inputs({ telemetryWanted: true })),
      "telemetry",
    ),
    { kinds: [26000, 26001, 26002, 26003, 26004, 26005], limit: 0 },
  );
});

test("the case channels the operator is in become one case-activity REQ", () => {
  const specs = perchDesiredSpecs(
    inputs({ activeCaseIds: ["case-1", "case-2"] }),
  );
  assert.deepEqual(filterFor(specs, "case-activity"), {
    kinds: [9, 46010],
    "#h": ["case-1", "case-2"],
    limit: 1,
  });
  assert.equal(
    filterFor(perchDesiredSpecs(inputs()), "case-activity"),
    null,
    "no cases, no REQ",
  );
});

test("an open case opens case-live from now, and nothing else moves", () => {
  const closed = perchDesiredSpecs(inputs());
  const open = perchDesiredSpecs(inputs({ openCaseId: "case-1" }));
  assert.equal(filterFor(closed, "case-live"), null);
  const live = filterFor(open, "case-live");
  assert.deepEqual(live["#h"], ["case-1"]);
  assert.equal(live.since, 1_700_000_000);

  for (const id of [
    "watch-alarm",
    "watch-snoozes",
    "watch-named-you",
    "lane-movement",
    "case-activity",
    "telemetry",
  ]) {
    assert.deepEqual(filterFor(open, id), filterFor(closed, id), id);
  }
});

test("the inventory stays the closed seven whatever the inputs say", () => {
  const everything = perchDesiredSpecs(
    inputs({
      activeCaseIds: ["case-1"],
      openCaseId: "case-1",
      telemetryWanted: true,
    }),
  );
  assert.equal(everything.length, 7);
  assert.equal(new Set(everything.map((spec) => spec.id)).size, 7);
});

// ---------------------------------------------------------------------------
// Which case channels count, and in what order
// ---------------------------------------------------------------------------

test("a case channel is one the operator joined whose name says so, newest first", () => {
  const channels = [
    {
      id: "c-old",
      name: "case-old",
      isMember: true,
      lastMessageAt: "2026-09-01T00:00:00Z",
    },
    {
      id: "lane",
      name: "lane-execution",
      isMember: true,
      lastMessageAt: "2026-09-05T00:00:00Z",
    },
    {
      id: "c-new",
      name: "case-new",
      isMember: true,
      lastMessageAt: "2026-09-04T00:00:00Z",
    },
    {
      id: "c-out",
      name: "case-not-mine",
      isMember: false,
      lastMessageAt: "2026-09-06T00:00:00Z",
    },
    { id: "c-quiet", name: "case-quiet", isMember: true, lastMessageAt: null },
    {
      id: "random",
      name: "casement",
      isMember: true,
      lastMessageAt: "2026-09-06T00:00:00Z",
    },
  ];
  assert.deepEqual(perchActiveCaseIds(channels), ["c-new", "c-old", "c-quiet"]);
});

test("the case list is capped at the 128 values one filter may carry", () => {
  const channels = Array.from({ length: 200 }, (_, index) => ({
    id: `c-${index}`,
    name: `case-${index}`,
    isMember: true,
    lastMessageAt: new Date(1_700_000_000_000 + index * 1_000).toISOString(),
  }));
  const ids = perchActiveCaseIds(channels);
  assert.equal(ids.length, 128);
  assert.equal(ids[0], "c-199", "the newest survives the cap");
  assert.equal(ids[127], "c-72");
});

// ---------------------------------------------------------------------------
// The sink: which REQ carried the event decides what happens to it
// ---------------------------------------------------------------------------

function frameEvent(kind, pubkey, content) {
  return {
    id: "e".repeat(64),
    pubkey,
    created_at: 1,
    kind,
    tags: [],
    content,
    sig: "0".repeat(128),
  };
}

test("a telemetry frame from an admitted bridge lands in the store", () => {
  resetPerchEphemeralStore();
  resetPerchSubscriptionManager();
  setPerchAdmittedIssuers([BRIDGE]);
  perchEventSink(
    "telemetry",
    frameEvent(
      26004,
      BRIDGE,
      JSON.stringify({
        partition_state: "healthy",
        total_governors: 1,
        healthy_governors: 1,
      }),
    ),
  );
  assert.deepEqual(perchLatestTelemetry(26004)?.body, {
    partition_state: "healthy",
    total_governors: 1,
    healthy_governors: 1,
  });
});

test("an alarm frame rides the same path and reaches the alarm queue", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers([BRIDGE]);
  perchEventSink(
    "watch-alarm",
    frameEvent(26006, BRIDGE, JSON.stringify({ hold_id: "hold_e826b510" })),
  );
  assert.deepEqual(getPerchEphemeralSnapshot().alarms, [
    { hold_id: "hold_e826b510" },
  ]);
});

test("a frame from a signer the console does not admit is counted, not rendered", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers([BRIDGE]);
  perchEventSink(
    "telemetry",
    frameEvent(26004, STRANGER, JSON.stringify({ partition_state: "healthy" })),
  );
  assert.equal(perchUnadmittedFrameCount(), 1);
  assert.equal(perchLatestTelemetry(26004), undefined);
});

test("a frame that arrives before the admitted set is applied after it", () => {
  resetPerchEphemeralStore();
  perchEventSink(
    "telemetry",
    frameEvent(26001, BRIDGE, JSON.stringify({ concentration: 4 })),
  );
  assert.equal(perchLatestTelemetry(26001), undefined);
  assert.equal(perchUnadmittedFrameCount(), 0);
  setPerchAdmittedIssuers([BRIDGE]);
  assert.deepEqual(perchLatestTelemetry(26001)?.body, { concentration: 4 });
});

test("content that is not JSON is undecodable and never throws", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers([BRIDGE]);
  perchEventSink("telemetry", frameEvent(26004, BRIDGE, "{not json"));
  perchEventSink("telemetry", frameEvent(26004, BRIDGE, ""));
  assert.equal(perchDroppedFrameCount(), 2);
  assert.equal(perchLatestTelemetry(26004), undefined);
});

test("a kind:9 arriving on a durable REQ is never fed to the frame store", () => {
  resetPerchEphemeralStore();
  setPerchAdmittedIssuers([BRIDGE]);
  perchEventSink(
    "case-live",
    frameEvent(9, BRIDGE, JSON.stringify({ partition_state: "healthy" })),
  );
  perchEventSink(
    "watch-named-you",
    frameEvent(9, BRIDGE, JSON.stringify({ partition_state: "healthy" })),
  );
  assert.equal(perchLatestTelemetry(26004), undefined);
  assert.equal(perchUnadmittedFrameCount(), 0);
  assert.equal(perchDroppedFrameCount(), 0);
});

// ---------------------------------------------------------------------------
// The lane-movement envelope, read through the wire mirror's own grammar
// ---------------------------------------------------------------------------

const ISSUER =
  "swarm:ed25519:6f1b8c2e4a9d7f3b1e5c0a8d2f4b6e9c1a3d5f7b9e1c3a5d7f9b1e3c5a7d9f1b";

function card(
  kind,
  envelope,
  { version = 1, humanLine = "One sentence." } = {},
) {
  return `<!-- swarm:${kind}:v${version} -->\n${humanLine}\n\n\`\`\`swarm:${kind}:v${version}\n${JSON.stringify(envelope)}\n\`\`\``;
}

test("a well-formed card of any admitted kind yields its issuer and seq", () => {
  assert.deepEqual(
    readLaneMovementEnvelope(
      card("finding", { issuer: ISSUER, seq: 7, fact: {} }),
    ),
    { issuer: ISSUER, seq: 7 },
  );
  assert.deepEqual(
    readLaneMovementEnvelope(card("hold", { issuer: ISSUER, seq: 0 })),
    {
      issuer: ISSUER,
      seq: 0,
    },
  );
  assert.deepEqual(
    readLaneMovementEnvelope(
      `<!-- swarm:finding:v1 -->\r\nline\r\n\n\`\`\`swarm:finding:v1\n{"issuer":"${ISSUER}","seq":3}\n\`\`\``,
    ),
    { issuer: ISSUER, seq: 3 },
  );
});

test("the wire mirror's grammar decides: prose, a foreign marker, another version, a partial line-0 match, and a missing fence read as null", () => {
  assert.equal(readLaneMovementEnvelope("hello"), null);
  assert.equal(readLaneMovementEnvelope("<!-- ambush:wave:v1 -->\nx"), null);
  assert.equal(readLaneMovementEnvelope(" <!-- swarm:finding:v1 -->\nx"), null);
  assert.equal(
    readLaneMovementEnvelope("<!-- swarm:finding:v1 --> x\nx"),
    null,
  );
  assert.equal(readLaneMovementEnvelope("<!-- swarm:finding:v1 -->"), null);
  assert.equal(
    readLaneMovementEnvelope("<!-- swarm:finding:v1 -->\nno fence"),
    null,
  );
  assert.equal(
    readLaneMovementEnvelope(
      card("hold", { issuer: ISSUER, seq: 1 }, { version: 12 }),
    ),
    null,
    "the mirror routes v1 markers only, so a v12 card is not a lane movement",
  );
  assert.equal(
    readLaneMovementEnvelope(card("teapot", { issuer: ISSUER, seq: 1 })),
    null,
    "the marker vocabulary is the closed seven",
  );
  assert.equal(
    readLaneMovementEnvelope(
      card("finding", { issuer: ISSUER, seq: 1 }, { humanLine: "   " }),
    ),
    null,
    "the human fallback line is part of the grammar",
  );
  assert.equal(
    readLaneMovementEnvelope(
      "<!-- swarm:finding:v1 -->\nx\n\n```swarm:hold:v1\n{}\n```",
    ),
    null,
    "the fence must carry the marker's own info string",
  );
  assert.equal(
    readLaneMovementEnvelope(
      '<!-- swarm:finding:v1 -->\nx\n\n```swarm:finding:v1\n{"issuer":"a","seq":1}',
    ),
    null,
    "an unclosed fence",
  );
});

test("a malformed or ill-typed envelope never throws", () => {
  assert.equal(
    readLaneMovementEnvelope(
      card("finding", "not json").replace('"not json"', "{not json"),
    ),
    null,
  );
  assert.equal(
    readLaneMovementEnvelope(card("finding", { issuer: ISSUER })),
    null,
  );
  assert.equal(
    readLaneMovementEnvelope(card("finding", { issuer: ISSUER, seq: "7" })),
    null,
  );
  assert.equal(
    readLaneMovementEnvelope(card("finding", { issuer: ISSUER, seq: 1.5 })),
    null,
  );
  assert.equal(
    readLaneMovementEnvelope(card("finding", { issuer: ISSUER, seq: -1 })),
    null,
  );
  assert.equal(
    readLaneMovementEnvelope(card("finding", { issuer: "", seq: 1 })),
    null,
  );
  assert.equal(readLaneMovementEnvelope(card("finding", [1, 2])), null);
  assert.equal(readLaneMovementEnvelope(card("finding", null)), null);
});
