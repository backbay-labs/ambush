import assert from "node:assert/strict";
import { test } from "node:test";

import {
  concentrationAt,
  forwardSegmentNote,
  interpolate,
  snapshotDisagrees,
  snapshotEpsilon,
  strengthAt,
} from "./concentration.ts";

const policy = {
  half_life_secs: 3600,
  evaporation_threshold: 0.01,
  min_sources_for_escalation: 2,
  alert_threshold: 2,
  incident_threshold: 5,
};
const key =
  "swarm:ed25519:18085f16811dba240c5bf9ef0c0d0bc6f359e7812cdedf86e7519852307ce470";
const deposit = (strategy, timestamp, eventId) => ({
  agent_id: `${key}:${strategy}`,
  strategy_id: strategy,
  threat_class: "execution",
  severity: "CRITICAL",
  confidence: 0.9,
  timestamp,
  decay_half_life: 3600,
  indicator: {},
  event_id: eventId,
});
const deposits = [
  deposit("suspicious_process_tree", 1773738872, "hunt-evt-1"),
  deposit("suspicious_scripting", 1773738872, "hunt-evt-1"),
  deposit("suspicious_process_tree", 1773738881, "hunt-evt-2"),
];

test("the closed form reproduces the canonical checkpoints to six decimals", () => {
  assert.equal(
    concentrationAt(
      deposits.slice(0, 2),
      1773738872,
      policy,
    ).total_strength.toFixed(6),
    "1.800000",
  );
  assert.equal(
    concentrationAt(deposits, 1773738881, policy).total_strength.toFixed(6),
    "2.696884",
  );
  assert.equal(
    concentrationAt(deposits, 1773738965, policy).total_strength.toFixed(6),
    "2.653617",
  );
  assert.equal(
    concentrationAt(deposits, 1773738965, policy).distinct_sources,
    2,
  );
});

test("CR-4: a sample at t excludes deposits with timestamp > t", () => {
  assert.equal(
    concentrationAt(deposits, 1773738875, policy).total_strength.toFixed(6),
    (2 * strengthAt(deposits[0], 1773738875)).toFixed(6),
  );
});

test("the tolerance is the evaporation floor, served, and >= trips", () => {
  assert.equal(snapshotEpsilon(policy, 2.65), 0.01);
  assert.equal(snapshotDisagrees(2.65, 2.66, policy), true);
  assert.equal(snapshotDisagrees(2.65, 2.659, policy), false);
});

test("regime B interpolation is exponential, never linear", () => {
  const s0 = {
    at: 1773738881,
    total_strength: 2.696884,
    distinct_sources: 2,
    peak_confidence: 0.9,
  };
  assert.equal(
    interpolate(s0, 1773738881 + 3600, 3600).toFixed(6),
    (2.696884 / 2).toFixed(6),
  );
});

test("a deposit before its own timestamp is at confidence, never amplified", () => {
  const d = deposits[0];
  assert.equal(strengthAt(d, d.timestamp - 10_000), d.confidence);
  assert.equal(strengthAt(d, d.timestamp), d.confidence);
});

test("a deposit under the evaporation floor contributes nothing and no source", () => {
  // Ten half-lives puts 0.9 at ~0.00088, below the 0.01 floor.
  const at = deposits[0].timestamp + 10 * 3600;
  const result = concentrationAt([deposits[0]], at, policy);
  assert.equal(result.total_strength, 0);
  assert.equal(result.distinct_sources, 0);
  assert.equal(result.peak_confidence, 0);
});

test("distinct sources counts agent_id, so one strategy depositing twice is one source", () => {
  assert.equal(
    concentrationAt([deposits[0], deposits[2]], 1773738881, policy)
      .distinct_sources,
    1,
  );
});

test("the epsilon floor wins until the served number is astronomically large", () => {
  assert.equal(snapshotEpsilon(policy, 0), 0.01);
  assert.equal(snapshotEpsilon(policy, -2.65), 0.01);
  assert.equal(snapshotEpsilon(policy, 1e9), 1);
});

test("the forward segment names itself an extrapolation and a lower bound", () => {
  const note = forwardSegmentNote();
  assert.match(note, /extrapolation/);
  assert.match(note, /lower bound/);
  assert.match(note, /suppression, which subtracts retroactively/);
});
