import assert from "node:assert/strict";
import test from "node:test";

import {
  acquirePerchTelemetryConsumer,
  perchTelemetryWanted,
  resetPerchTelemetryWanted,
  subscribePerchTelemetryWanted,
} from "./perchTelemetryWanted.ts";

test("telemetry is wanted while any consumer is mounted, and only then", () => {
  resetPerchTelemetryWanted();
  assert.equal(perchTelemetryWanted(), false, "nothing mounted, nothing asked");

  const strip = acquirePerchTelemetryConsumer();
  assert.equal(perchTelemetryWanted(), true);
  const wall = acquirePerchTelemetryConsumer();
  assert.equal(perchTelemetryWanted(), true);

  strip();
  assert.equal(
    perchTelemetryWanted(),
    true,
    "one consumer left is still a consumer",
  );
  wall();
  assert.equal(perchTelemetryWanted(), false);
});

test("a release never takes the count below zero, so a reset survives the unmounts that follow it", () => {
  // A community switch runs the resetters and THEN React unmounts the old
  // subtree. Without the floor, those unmounts would drive the count negative
  // and the next community's first consumer would leave it at zero — the REQ
  // silently never opening again.
  resetPerchTelemetryWanted();
  const stale = acquirePerchTelemetryConsumer();
  resetPerchTelemetryWanted();
  assert.equal(perchTelemetryWanted(), false);
  stale();
  stale();
  assert.equal(perchTelemetryWanted(), false);
  const fresh = acquirePerchTelemetryConsumer();
  assert.equal(perchTelemetryWanted(), true, "the next community is served");
  fresh();
});

test("one release releases once, however many times it is called", () => {
  resetPerchTelemetryWanted();
  const first = acquirePerchTelemetryConsumer();
  const second = acquirePerchTelemetryConsumer();
  first();
  first();
  first();
  assert.equal(
    perchTelemetryWanted(),
    true,
    "a repeated unmount is not three unmounts",
  );
  second();
  assert.equal(perchTelemetryWanted(), false);
});

test("listeners see every change and nothing else", () => {
  resetPerchTelemetryWanted();
  const seen = [];
  const unsubscribe = subscribePerchTelemetryWanted(() =>
    seen.push(perchTelemetryWanted()),
  );
  const one = acquirePerchTelemetryConsumer();
  const two = acquirePerchTelemetryConsumer();
  one();
  two();
  assert.deepEqual(seen, [true, true, true, false]);

  resetPerchTelemetryWanted();
  assert.deepEqual(seen, [true, true, true, false], "already zero, no change");
  const three = acquirePerchTelemetryConsumer();
  resetPerchTelemetryWanted();
  assert.deepEqual(seen, [true, true, true, false, true, false]);

  unsubscribe();
  three();
  acquirePerchTelemetryConsumer();
  assert.deepEqual(
    seen,
    [true, true, true, false, true, false],
    "unsubscribed",
  );
  resetPerchTelemetryWanted();
});
