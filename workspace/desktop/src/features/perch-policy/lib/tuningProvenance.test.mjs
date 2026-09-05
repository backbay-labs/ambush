import assert from "node:assert/strict";
import { test } from "node:test";

import { deriveTuningProvenance, incidentOrigin } from "./tuningProvenance.ts";

test("the two id schemes cannot collide, and an unknown one is unresolved", () => {
  assert.equal(
    incidentOrigin({ incident_id: "incident:hunt-evt-1:1773738882400" }),
    "correlation-produced",
  );
  assert.equal(
    incidentOrigin({
      incident_id: "perch-case:27799e23-ab25-4659-b381-3de47ea7ca4d",
    }),
    "analyst-promoted",
  );
  assert.equal(
    incidentOrigin({ incident_id: "something-else" }),
    "unresolved",
    "naming an origin the id does not support would invent provenance",
  );
});

test("the this-week fraction counts verdicts inside the window and invents none", () => {
  const weekStartMs = 1_773_100_000_000;
  const recommendation = {
    kind: "detector_rule_review",
    strategy_id: "suspicious_process_tree",
    host_id: null,
  };
  const incidents = [
    {
      incident_id: "perch-case:a",
      false_positive_measurements: [
        {
          finding_id: "f1",
          strategy_id: "suspicious_process_tree",
          reviewed_at_ms: weekStartMs + 1,
          false_positive: true,
        },
        {
          finding_id: "f2",
          strategy_id: "suspicious_process_tree",
          reviewed_at_ms: weekStartMs - 1,
          false_positive: true,
        },
        {
          finding_id: "f3",
          strategy_id: "suspicious_process_tree",
          reviewed_at_ms: weekStartMs + 2,
          false_positive: false,
        },
      ],
    },
  ];
  const provenance = deriveTuningProvenance(
    recommendation,
    incidents,
    weekStartMs,
  );
  assert.equal(provenance.origin, "analyst-promoted");
  assert.equal(provenance.totalVerdicts, 3);
  assert.equal(provenance.thisWeekVerdicts, 2);
  assert.equal(provenance.fractionThisWeek, 2 / 3);
  assert.equal(
    deriveTuningProvenance(recommendation, [], weekStartMs).fractionThisWeek,
    null,
    "no denominator, no fraction",
  );
});

test("a measurement for another strategy is not this recommendation's evidence", () => {
  const provenance = deriveTuningProvenance(
    { kind: "k", strategy_id: "a", host_id: null },
    [
      {
        incident_id: "perch-case:x",
        false_positive_measurements: [
          {
            finding_id: "f",
            strategy_id: "b",
            reviewed_at_ms: 10,
            false_positive: true,
          },
        ],
      },
    ],
    0,
  );
  assert.equal(provenance.totalVerdicts, 0);
  assert.equal(provenance.fractionThisWeek, null);
});

test("a verdict exactly at the window start is inside it", () => {
  const provenance = deriveTuningProvenance(
    { kind: "k", strategy_id: "a", host_id: null },
    [
      {
        incident_id: "perch-case:x",
        false_positive_measurements: [
          {
            finding_id: "f",
            strategy_id: "a",
            reviewed_at_ms: 100,
            false_positive: true,
          },
        ],
      },
    ],
    100,
  );
  assert.equal(provenance.thisWeekVerdicts, 1);
});
