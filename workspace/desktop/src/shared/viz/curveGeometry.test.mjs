import assert from "node:assert/strict";
import { test } from "node:test";

import {
  CURVE_MAX_POINTS,
  CURVE_PLOT_BOTTOM,
  CURVE_PLOT_LEFT,
  CURVE_PLOT_RIGHT,
  CURVE_PLOT_TOP,
  clockSkewed,
  curvePoints,
  curveYDomain,
  depositDot,
  polylinePoints,
  resampleCurve,
  rulePlacement,
} from "./curveGeometry.ts";

const policy = {
  half_life_secs: 3600,
  evaporation_threshold: 0.01,
  min_sources_for_escalation: 2,
  alert_threshold: 2,
  incident_threshold: 5,
};

test("the y domain always starts at zero", () => {
  assert.equal(curveYDomain(policy, 100)[0], 0);
  assert.equal(curveYDomain(policy, 0)[0], 0);
});

test("the top leaves headroom above whichever is larger, threshold or peak", () => {
  assert.equal(curveYDomain(policy, 0.1)[1], 2 * 1.35 * 1.08);
  assert.equal(curveYDomain(policy, 10)[1], 10 * 1.08);
});

test("resampling always keeps the newest sample", () => {
  const samples = Array.from({ length: 1000 }, (_, i) => ({
    at: i,
    total_strength: i,
    distinct_sources: 1,
    peak_confidence: 1,
  }));
  const kept = resampleCurve(samples);
  assert.ok(kept.length <= CURVE_MAX_POINTS + 1);
  assert.equal(
    kept[kept.length - 1].at,
    999,
    "the curve must not end in the past",
  );
});

test("a series under the cap is passed through unchanged, as a copy", () => {
  const samples = [
    { at: 1, total_strength: 1, distinct_sources: 1, peak_confidence: 1 },
  ];
  const kept = resampleCurve(samples);
  assert.deepEqual(kept, samples);
  assert.notEqual(kept, samples, "the caller's array must not be aliased");
});

test("points span the plot horizontally and invert y for SVG", () => {
  const samples = [
    { at: 0, total_strength: 0, distinct_sources: 1, peak_confidence: 1 },
    { at: 100, total_strength: 10, distinct_sources: 1, peak_confidence: 1 },
  ];
  const { points, yDomain } = curvePoints(samples, policy);
  assert.equal(points[0].x, CURVE_PLOT_LEFT);
  assert.equal(points[1].x, CURVE_PLOT_RIGHT);
  assert.equal(points[0].y, CURVE_PLOT_BOTTOM, "zero sits on the baseline");
  assert.ok(points[1].y < points[0].y, "a larger value is higher on screen");
  assert.equal(yDomain[0], 0);
});

test("an empty series produces no points and never NaN", () => {
  const { points } = curvePoints([], policy);
  assert.deepEqual(points, []);
  assert.equal(polylinePoints(points), "");
});

test("a threshold above the domain is pinned to the top AND reported off-scale", () => {
  const onScale = rulePlacement(2, [0, 10]);
  assert.equal(onScale.kind, "on-scale");
  const offScale = rulePlacement(50, [0, 10]);
  assert.deepEqual(offScale, { kind: "off-scale", y: CURVE_PLOT_TOP });
});

test("a threshold exactly at the top of the domain is on-scale", () => {
  assert.equal(rulePlacement(10, [0, 10]).kind, "on-scale");
});

test("a deposit dot's radius reads confidence and its opacity reads remaining strength", () => {
  const d = { confidence: 1, timestamp: 0, decay_half_life: 3600 };
  const fresh = depositDot(d, 0);
  const old = depositDot(d, 3600);
  assert.equal(fresh.radius.toFixed(2), "4.80");
  assert.equal(fresh.opacity.toFixed(2), "0.90");
  assert.equal(
    old.opacity.toFixed(2),
    "0.63",
    "0.35 + 0.55 x 0.5 after one half-life",
  );
  assert.ok(old.opacity < fresh.opacity);
});

test("a zero-confidence deposit does not divide by zero", () => {
  const dot = depositDot(
    { confidence: 0, timestamp: 0, decay_half_life: 3600 },
    3600,
  );
  assert.equal(Number.isFinite(dot.opacity), true);
  assert.equal(dot.opacity.toFixed(2), "0.35");
});

test("clock skew trips above thirty seconds, in either direction", () => {
  assert.equal(clockSkewed(1000, 1000), false);
  assert.equal(clockSkewed(1000, 1030), false);
  assert.equal(clockSkewed(1000, 1031), true);
  assert.equal(clockSkewed(1031, 1000), true);
});
