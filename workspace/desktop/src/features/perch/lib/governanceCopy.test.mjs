import assert from "node:assert/strict";
import { test } from "node:test";

import {
  fillGovernanceCopy,
  formatGovernanceAge,
  GOVERNANCE,
  GOVERNANCE_BY_MODE,
} from "./governanceCopy.ts";

/** Every string leaf of the copy map, however deeply the `mode` group nests. */
function stringLeaves(node) {
  if (typeof node === "string") return [node];
  return Object.values(node).flatMap(stringLeaves);
}

// The full set of names any GOVERNANCE copy can carry. A placeholder added to
// the map without a value here makes `fillGovernanceCopy` throw, which is what
// keeps a raw `{x}` off the strip.
const EVERY_VALUE = {
  ago: "5s",
  lastSeen: "never",
  n: 3,
  unauthorized: 2,
  mode: "normal",
  seconds: 300,
  holder: "op-7",
  since: "12:00",
};

test("no placeholder survives any governance copy the strip can render", () => {
  const templated = stringLeaves(GOVERNANCE).filter((s) => s.includes("{"));
  assert.ok(templated.length > 0, "expected some copy to carry a placeholder");
  for (const template of templated) {
    const rendered = fillGovernanceCopy(template, EVERY_VALUE);
    assert.ok(
      !rendered.includes("{"),
      `a placeholder survived rendering: ${rendered}`,
    );
  }
});

// The exact four-value object GovernanceStrip builds — no wider. EVERY_VALUE
// above is a superset (it carries mode/seconds/holder/since for the unrendered
// copies), so it would pass a copy edit that added `{holder}` to a rendered
// register while that register threw uncaught in production. This pins the real
// runtime contract: every register the strip paints must fill from these four.
const STRIP_VALUES = { ago: "5s", lastSeen: "never", n: 1, unauthorized: 0 };

test("every rendered register fills from exactly the four values the strip supplies", () => {
  const rendered = Object.values(GOVERNANCE_BY_MODE);
  assert.ok(rendered.length > 0, "expected some rendered register");
  for (const template of rendered) {
    let filled;
    assert.doesNotThrow(() => {
      filled = fillGovernanceCopy(template, STRIP_VALUES);
    }, `a rendered register reached for a value the strip does not supply: ${template}`);
    assert.ok(!filled.includes("{"), `a placeholder survived: ${filled}`);
  }
});

test("fillGovernanceCopy throws on a placeholder the values do not cover", () => {
  // The throw is the guard: a value the strip forgot to supply fails a test
  // here rather than reaching the window as a literal `{lastSeen}`.
  assert.throws(
    () => fillGovernanceCopy(GOVERNANCE.bridgeDown, {}),
    /lastSeen/,
  );
});

test("the bridge-down line names the last envelope as never on a fresh mount", () => {
  assert.equal(
    fillGovernanceCopy(GOVERNANCE.bridgeDown, { lastSeen: "never" }),
    "bridge: down (last envelope never) · holds may not be reaching the console",
  );
});

test("age under a minute reads as whole seconds", () => {
  assert.equal(formatGovernanceAge(0), "0s");
  assert.equal(formatGovernanceAge(42_000), "42s");
  assert.equal(formatGovernanceAge(59_999), "59s");
});

test("age under an hour reads as minutes and seconds", () => {
  assert.equal(formatGovernanceAge(60_000), "1m 0s");
  assert.equal(formatGovernanceAge(305_000), "5m 5s");
  assert.equal(formatGovernanceAge(3_599_000), "59m 59s");
});

test("age past an hour reads as hours and minutes", () => {
  assert.equal(formatGovernanceAge(3_600_000), "1h 0m");
  assert.equal(formatGovernanceAge(8_100_000), "2h 15m");
});
