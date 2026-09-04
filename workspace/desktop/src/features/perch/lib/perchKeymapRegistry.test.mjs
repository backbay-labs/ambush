// The ratified row keymap, as a table test.
//
// Run by `pnpm test` in desktop/, which is
// `node --import ./test-loader.mjs --experimental-strip-types --test "src/**/*.test.mjs"`
// (desktop/package.json) — so a `.test.mjs` beside a `.ts` file that it imports
// directly is the house pattern.
//
// Covers INV-31 and INV-32, plus the appendix section 2 keymap as a whole.
//
// WHY A TABLE TEST AND NOT A UI CRAWL
//   INV-32 says no single key is bound to two different verdict verbs across row
//   types in the same list. Crawling the DOM for that would only ever prove it
//   for the lists a spec happened to open. The registry is data
//   (17-COMPONENT-SPECS.md section 6.1), so the assertion is exhaustive over the
//   binding set and runs in milliseconds. `tools/check-copy-banned-terms.sh`
//   asserts the same two things lexically from the Ambush side, because the
//   appendix names that script; the two are deliberate belt and braces and the
//   fixtures in each are written to catch the same shapes.
//
// THE STRICTER READING, DECIDED
//   INV-32's letter is "in the same list". Every Perch list interleaves at least
//   two row types — the needs-action queue carries holds AND findings, which is
//   the whole reason `D` cannot mean both Refuse and Dismiss — and no surface
//   shows a row type in isolation. Enumerating which pairs co-occur would be a
//   second registry that can drift from the first. So this asserts the STRICT
//   form: one key, one verdict verb, globally. Recorded as a commitment.

import assert from "node:assert/strict";
import test from "node:test";

import { PERCH_BINDINGS } from "./perchKeymapRegistry.ts";

/** The five verbs. APPENDIX-NORMATIVE.md section 2, brief amendment A1. */
const VERDICT_VERBS = ["confirm", "dismiss", "investigate", "grant", "refuse"];

/** The five row types the registry may name. */
const ROW_TYPES = ["finding", "hold", "case", "lane", "containment"];

test("the registry is not empty and every verdict verb is bound", () => {
  // A gutted registry would make every assertion below vacuously true. This is
  // the "refusing to pass silently" rule, in JavaScript.
  assert.ok(PERCH_BINDINGS.length > 0, "PERCH_BINDINGS is empty");

  const bound = new Set(
    PERCH_BINDINGS.filter((binding) => binding.verb).map(
      (binding) => binding.verb,
    ),
  );
  for (const verb of VERDICT_VERBS) {
    assert.ok(bound.has(verb), `the verdict verb "${verb}" is bound to no key`);
  }
  assert.equal(
    bound.size,
    VERDICT_VERBS.length,
    `unexpected verdict verb(s): ${[...bound].filter((v) => !VERDICT_VERBS.includes(v)).join(", ")}`,
  );
});

test("INV-31 — no verdict control binds A", () => {
  for (const binding of PERCH_BINDINGS) {
    if (!binding.verb) continue;
    assert.notEqual(
      binding.key.toLowerCase(),
      "a",
      `"${binding.verb}" is bound to "${binding.key}". A is banned as a verdict key: ` +
        "the key survives a relabelled button, which is the failure render law 6 " +
        "exists to prevent.",
    );
  }
});

test("INV-32 — no key is bound to two different verdict verbs", () => {
  const byKey = new Map();
  for (const binding of PERCH_BINDINGS) {
    if (!binding.verb) continue;
    const key = binding.key.toLowerCase();
    const verbs = byKey.get(key) ?? new Set();
    verbs.add(binding.verb);
    byKey.set(key, verbs);
  }

  for (const [key, verbs] of byKey) {
    assert.equal(
      verbs.size,
      1,
      `key "${key}" is bound to ${[...verbs].join(" and ")}. Holds and findings ` +
        "interleave in the needs-action queue, so a key whose meaning depends on " +
        "which row is selected is a mis-verdict waiting for a tired operator.",
    );
  }
});

test("the appendix section 2 keymap is bound exactly as ratified", () => {
  // Pinned pairs, not a shape check. Amendment A1 replaced A/D/E/S with this
  // set for reasons written down in the brief; a silent re-map is a brief
  // amendment and must read as one in the diff.
  const expected = {
    c: "confirm",
    d: "dismiss",
    i: "investigate",
    g: "grant",
    r: "refuse",
  };
  for (const [key, verb] of Object.entries(expected)) {
    const binding = PERCH_BINDINGS.find(
      (candidate) =>
        candidate.key.toLowerCase() === key && candidate.verb === verb,
    );
    assert.ok(binding, `"${key}" is no longer bound to "${verb}"`);
  }
});

test("D is Dismiss on a finding and is bound to no verb on a hold", () => {
  // The sharpest single consequence of A1. Dismiss retroactively removes every
  // deposit at or before the marker, keyed on (threat_class, event_id)
  // (AMB swarm-pheromone/src/substrate.rs:345-348, applied at :1286) — it reaches
  // detectors the operator never reviewed. Refuse does nothing of the kind. One
  // key meaning both, in a list where the two row types interleave, is the
  // highest-cost keymap error available.
  const dBindings = PERCH_BINDINGS.filter(
    (binding) => binding.key.toLowerCase() === "d",
  );
  for (const binding of dBindings) {
    assert.equal(binding.verb, "dismiss");
    assert.ok(
      !binding.rowTypes.includes("hold"),
      "D must not be offered on a hold row at all — not even as a no-op",
    );
  }
});

test("snooze is declared disabled on holds rather than omitted", () => {
  // INV-34's registry half. A control that is absent teaches nothing; a control
  // that is present, disabled and states its reason teaches the rule once.
  const snooze = PERCH_BINDINGS.find(
    (binding) => binding.key.toLowerCase() === "s",
  );
  assert.ok(snooze, "S is unbound");
  assert.ok(snooze.rowTypes.includes("finding"), "S is enabled on findings");
  assert.ok(
    (snooze.disabledOn ?? []).includes("hold"),
    "S must be declared disabled on holds, not merely left off their row types",
  );
  assert.ok(!snooze.verb, "snooze is not a verdict");
});

test("E means promote-to-a-case on every row type that offers it", () => {
  // One meaning, always. Not "route to another operator": no operator directory
  // exists in either tree, so that meaning could never have been implemented.
  const promote = PERCH_BINDINGS.filter(
    (binding) => binding.key.toLowerCase() === "e",
  );
  assert.equal(promote.length, 1, "E is declared more than once");
  assert.ok(!promote[0].verb, "promote is not a verdict verb");
  assert.match(promote[0].meaning.toLowerCase(), /promote/);
});

test("every binding names only known row types and a single-character or named key", () => {
  for (const binding of PERCH_BINDINGS) {
    assert.ok(
      binding.key.length === 1 || ["Enter", "Escape"].includes(binding.key),
      `"${binding.key}" is neither a single character nor Enter/Escape`,
    );
    assert.ok(
      binding.rowTypes.length > 0,
      `"${binding.key}" names no row type`,
    );
    for (const rowType of [
      ...binding.rowTypes,
      ...(binding.disabledOn ?? []),
    ]) {
      assert.ok(ROW_TYPES.includes(rowType), `unknown row type "${rowType}"`);
    }
    assert.ok(
      binding.meaning.trim().length > 0,
      `"${binding.key}" has no meaning string`,
    );
  }
});
