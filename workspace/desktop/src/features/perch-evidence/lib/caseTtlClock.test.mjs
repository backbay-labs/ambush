import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CASE_TTL_CAVEAT,
  readCaseTtl,
  remainingLabel,
} from "./caseTtlClock.ts";

const NOW = Date.UTC(2026, 2, 18, 3, 0, 0);

test("a channel with no TTL is not scheduled, which is not the same as far away", () => {
  assert.deepEqual(readCaseTtl(null, NOW), { kind: "none" });
});

test("an unparseable deadline reads as none rather than as epoch zero", () => {
  assert.deepEqual(readCaseTtl("not a date", NOW), { kind: "none" });
});

test("a future deadline reads as a wall clock plus a remaining span", () => {
  const reading = readCaseTtl(
    new Date(NOW + 5 * 3_600_000 + 12 * 60_000).toISOString(),
    NOW,
  );
  assert.deepEqual(reading, {
    kind: "due",
    atLabel: "08:12",
    inLabel: "5h 12m",
  });
});

test("a deadline already past reads archived, never a negative span", () => {
  const reading = readCaseTtl(new Date(NOW - 60_000).toISOString(), NOW);
  assert.equal(reading.kind, "archived");
  assert.equal(reading.atLabel, "02:59");
});

test("the remaining label drops the hour when there is none and never goes below zero", () => {
  assert.equal(remainingLabel(12 * 60_000), "12m");
  assert.equal(remainingLabel(0), "0m");
  assert.equal(remainingLabel(-90_000), "0m");
  assert.equal(remainingLabel(60 * 60_000), "1h 0m");
});

test("the caveat states the failure the clock cannot show", () => {
  assert.match(CASE_TTL_CAVEAT, /downgraded to a warning/);
  assert.match(CASE_TTL_CAVEAT, /open cases are read from the daemon/);
});
