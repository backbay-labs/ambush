import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const SOURCE = readFileSync(
  new URL("./PartitionSection.tsx", import.meta.url),
  "utf8",
);

test("the section is absent while governance is healthy", () => {
  // Always present with zeroes would train an operator to skip the one place
  // the console reports actions taken without authorization.
  assert.match(SOURCE, /partitionState === "healthy"\) return null/);
});

test("a contingency lease's missing receipt is stated as expected, not as a fault", () => {
  assert.match(SOURCE, /UNATTESTED here is\s*\n?\s*expected, not a fault/);
});

test("unauthorized actions render in the destructive register", () => {
  assert.match(SOURCE, /data-perch-register="destructive"/);
});

test("neither number is rounded", () => {
  // "about a dozen" is not a thing to say about actions taken without
  // authority, so the values render verbatim with no formatter.
  assert.doesNotMatch(SOURCE, /toFixed|Intl\.NumberFormat|Math\.round/);
});

test("an absent reconciliation report is not a reconcile that found nothing", () => {
  assert.match(SOURCE, /the reconcile has not run, which is not the same as/);
});
