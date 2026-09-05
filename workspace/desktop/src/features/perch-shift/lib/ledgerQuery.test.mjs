import assert from "node:assert/strict";
import { test } from "node:test";

import { buildLedgerQuery } from "./ledgerQuery.ts";

test("keeps the four inherited operators and turns four more into FTS terms", () => {
  const query = buildLedgerQuery(
    "from:whisker-7a3f in:case-0042 after:2026-08-01 class:command_and_control action:block_egress host:web-04 agent:pouncer-2b18 beacon",
  );
  assert.equal(query.from, "whisker-7a3f");
  assert.equal(query.in, "case-0042");
  assert.equal(typeof query.since, "number");
  assert.deepEqual(query.ftsTerms, {
    class: "command_and_control",
    action: "block_egress",
    host: "web-04",
    agent: "pouncer-2b18",
  });
  // The values stay in the text: these fields live inside a signed card body
  // and are reachable through full-text search alone.
  assert.equal(
    query.text,
    "command_and_control block_egress web-04 pouncer-2b18 beacon",
  );
});

test("a token that is not at a token boundary stays literal", () => {
  const query = buildLedgerQuery("built-in:react class:execution");
  assert.equal(
    query.in,
    null,
    "a word boundary would fire after the hyphen and eat the user's text",
  );
  assert.equal(query.ftsTerms.class, "execution");
  assert.equal(query.text, "built-in:react execution");
});

test("trailing punctuation belongs to the sentence, not the identifier", () => {
  const query = buildLedgerQuery("host:web-04, and then some");
  assert.equal(query.ftsTerms.host, "web-04");
  assert.equal(query.text, "web-04 and then some");
});

test("a bare query carries no operators and no terms", () => {
  const query = buildLedgerQuery("beacon over dns");
  assert.equal(query.from, null);
  assert.equal(query.in, null);
  assert.deepEqual(query.ftsTerms, {});
  assert.equal(query.text, "beacon over dns");
});

test("the same operator twice keeps the last, and both values stay searchable", () => {
  const query = buildLedgerQuery("host:web-04 host:web-09");
  assert.equal(query.ftsTerms.host, "web-09");
  assert.equal(
    query.text,
    "web-04 web-09",
    "dropping the first value would silently narrow what the operator asked for",
  );
});
