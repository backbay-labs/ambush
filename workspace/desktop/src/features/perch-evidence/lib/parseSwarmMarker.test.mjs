import assert from "node:assert/strict";
import test from "node:test";

import { parseSwarmMarker } from "./parseSwarmMarker.ts";

const ADMITTED =
  "207176338a897b2379564322033e86ed7197600499ba348e6c6c898b8139b586";
const admit = (pk) => pk === ADMITTED;
// `undefined` must reach the parser as an ABSENT signer, so the default is
// applied on arity rather than through a default parameter (which `undefined`
// would trigger).
const parse = (content, ...signer) =>
  parseSwarmMarker({
    content,
    signerPubkey: signer.length === 0 ? ADMITTED : signer[0],
    channelTag: "h1",
    eventId: "e1",
    isAdmittedIssuer: admit,
  });

test("the marker fires only when it is the whole of line 0 (trimEnd, never trimStart)", () => {
  assert.equal(parse("<!-- swarm:finding:v1 -->\nx").status, "ok");
  assert.equal(parse("<!-- swarm:finding:v1 -->\r\nx").status, "ok");
  assert.equal(parse(" <!-- swarm:finding:v1 -->\nx").status, "not-a-marker");
  assert.equal(
    parse("<!-- swarm:finding:v1 --> hello\nx").status,
    "not-a-marker",
  );
  assert.equal(
    parse("hello\n<!-- swarm:finding:v1 -->").status,
    "not-a-marker",
  );
  assert.equal(parse("<!-- ambush:wave:v1 -->\nx").status, "not-a-marker");
});

test("an unadmitted signer is reported with its slug, never as a card", () => {
  const r = parse(
    "<!-- swarm:hold:v1 -->\nx",
    "684949a3287973d209a80c63057ff9e099ede5996b18288936db5e318fafbde5",
  );
  assert.deepEqual(r, {
    status: "unadmitted-issuer",
    slug: "hold",
    issuerPubkey:
      "684949a3287973d209a80c63057ff9e099ede5996b18288936db5e318fafbde5",
  });
  assert.equal(
    parse("<!-- swarm:hold:v1 -->\nx", undefined).status,
    "unadmitted-issuer",
  );
  assert.equal(
    parse("<!-- swarm:hold:v1 -->\nx", "NOT-HEX").status,
    "unadmitted-issuer",
  );
});

test("unknown kinds and other versions are named refusals, and rawBody is byte-exact", () => {
  assert.equal(parse("<!-- swarm:teapot:v1 -->\n{}").status, "unknown-kind");
  const v2 = parse("<!-- swarm:hold:v2 -->\n  body  \n");
  assert.equal(v2.status, "unsupported-version");
  assert.equal(v2.card.rawBody, "  body  \n");
  const ok = parse(
    "<!-- swarm:finding:v1 -->\nline1\n\n```swarm:finding:v1\n{}\n```",
  );
  assert.equal(ok.card.issuerPubkey, ADMITTED);
  assert.equal(ok.card.channelTag, "h1");
});

test("the parser and the Rust sign gate agree on line 0", () => {
  // Pairs taken from perch_sign_gate.rs's tests (Ground Task 5): what the gate
  // refuses, this parses; what it signs, this ignores.
  for (const line of [
    "<!-- swarm:verdict:v1 -->",
    "<!-- swarm:finding:v1 -->",
    "<!-- swarm:hold:v12 -->   ",
  ]) {
    assert.notEqual(parse(`${line}\n{}`).status, "not-a-marker", line);
  }
  for (const line of [
    "<!-- ambush:wave:v1 -->",
    "hello <!-- swarm:verdict:v1 -->",
    " <!-- swarm:verdict:v1 -->",
  ]) {
    assert.equal(parse(`${line}\n{}`).status, "not-a-marker", line);
  }
});

test("an admitted signer's hex case does not decide admission, and the card carries it lowercased", () => {
  const upper = parseSwarmMarker({
    content: "<!-- swarm:finding:v1 -->\nx",
    signerPubkey: ADMITTED.toUpperCase(),
    channelTag: null,
    eventId: "e2",
    isAdmittedIssuer: admit,
  });
  assert.equal(upper.status, "ok");
  assert.equal(upper.card.issuerPubkey, ADMITTED);
  assert.equal(upper.card.channelTag, null);
  assert.equal(upper.card.eventId, "e2");
  assert.equal(upper.card.kind, "finding");
  assert.equal(upper.card.version, 1);
});
