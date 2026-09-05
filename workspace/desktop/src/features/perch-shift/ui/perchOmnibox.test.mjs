import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const SOURCE = readFileSync(
  new URL("./PerchOmnibox.tsx", import.meta.url),
  "utf8",
);

test("the omnibox performs no write of its own", () => {
  // A destructive verb one keystroke from every screen is what the render
  // laws forbid. The registry has no `run` field; this asserts the UI did not
  // grow one either.
  for (const banned of [
    "perchReleaseContainment",
    "perchRecordVerdict",
    "perchDecideHold",
    "perchRecordHoldVerdict",
    "perchMintIncident",
    "perchFindingFeedback",
  ]) {
    assert.equal(
      SOURCE.includes(banned),
      false,
      `${banned} must not be reachable from the omnibox`,
    );
  }
});

test("release containment navigates rather than releasing", () => {
  assert.match(SOURCE, /SURFACE_ROUTES\.leases/);
  assert.match(SOURCE, /REQUESTED, never performed/);
});

test("every openable surface has a route", () => {
  // A surface in the registry with no route here would be a command that
  // silently does nothing.
  for (const surface of [
    "watch",
    "leases",
    "policy",
    "watchfloor",
    "ledger",
    "tuning",
    "handoff",
    "gaps",
    "settings",
  ]) {
    assert.match(
      SOURCE,
      new RegExp(`\\b${surface}:\\s*"`),
      `${surface} has no route`,
    );
  }
});

test("a match shows its consequence before the operator commits", () => {
  assert.match(SOURCE, /perch-omnibox-consequence/);
  assert.match(SOURCE, /match\.spec\.consequence/);
});
