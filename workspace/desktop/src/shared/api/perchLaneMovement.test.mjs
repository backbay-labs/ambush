import assert from "node:assert/strict";
import test from "node:test";

import { readLaneMovementEnvelope } from "./perchLaneMovement.ts";

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
