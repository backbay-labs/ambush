import assert from "node:assert/strict";
import { test } from "node:test";

import { linearScale, sparkScale } from "./scales.ts";

test("a linear scale maps the domain onto the range", () => {
  const scale = linearScale([0, 10], [0, 100]);
  assert.equal(scale(0), 0);
  assert.equal(scale(5), 50);
  assert.equal(scale(10), 100);
});

test("a degenerate domain maps to the middle of the range, never to zero or NaN", () => {
  const scale = linearScale([7, 7], [0, 100]);
  assert.equal(scale(7), 50);
  assert.equal(scale(0), 50);
});

test("an inverted range works, which is how SVG's downward y is expressed", () => {
  const scale = linearScale([0, 10], [100, 0]);
  assert.equal(scale(0), 100);
  assert.equal(scale(10), 0);
});

test("a sparkline scale is window min-max, never zero-based", () => {
  const scale = sparkScale([900, 950, 1000], 20);
  assert.equal(scale(1000), 0, "the window maximum reaches the top");
  assert.equal(scale(900), 20, "the window minimum reaches the bottom");
  assert.equal(scale(950), 10);
});

test("a flat series is centred rather than flattened onto the axis", () => {
  const scale = sparkScale([5, 5, 5], 20);
  assert.equal(scale(5), 10);
});

test("an empty series centres too rather than dividing by zero", () => {
  assert.equal(sparkScale([], 20)(0), 10);
});
