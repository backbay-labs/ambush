import assert from "node:assert/strict";
import { test } from "node:test";

import { groupGaps } from "./gapsCatalog.ts";

const SNAPSHOT = {
  generated_at_ms: 1,
  suite_name: "evasion-breadth-v1",
  suite_path: "scenario-suites/evasion-breadth-v1.yaml",
  corpus_version: "1",
  detectors: [
    {
      detector: "suspicious_process_tree",
      intentionally_uncovered: [
        {
          technique: "T1204.001",
          threat_class: "initial_access",
          rationale:
            "The detector only sees normalized process starts after execution and cannot reason about phishing-link delivery or attachment-open provenance.",
        },
        {
          technique: "T1036.005",
          threat_class: "defense_evasion",
          rationale:
            "Legitimate-name or path-masquerading requires richer signer and file-origin telemetry than the current process-start payload carries.",
        },
      ],
    },
    {
      detector: "dns_exfiltration",
      intentionally_uncovered: [
        {
          technique: "T1071.001",
          threat_class: "command_and_control",
          rationale:
            "DNS-over-HTTPS and other application-layer tunneling over web protocols bypass the DNS-query-specific normalization.",
        },
      ],
    },
    { detector: "covered_everywhere", intentionally_uncovered: [] },
  ],
};

test("groups by detector, counts distinct techniques, keeps the rationale verbatim", () => {
  const grouped = groupGaps(SNAPSHOT);
  assert.equal(grouped.techniqueCount, 3);
  assert.equal(
    grouped.detectorCount,
    2,
    "a detector with no declared gap is not a row; an empty row would read as an undescribed gap",
  );
  assert.equal(
    grouped.detectors[0].gaps[0].rationale,
    SNAPSHOT.detectors[0].intentionally_uncovered[0].rationale,
    "the catalog's own prose, not a summary of it",
  );
});

test("filtering by threat class keeps only matching techniques and recounts", () => {
  const grouped = groupGaps(
    {
      generated_at_ms: 1,
      suite_name: "",
      suite_path: "",
      corpus_version: "",
      detectors: [
        {
          detector: "a",
          intentionally_uncovered: [
            { technique: "T1", threat_class: "initial_access", rationale: "r" },
            { technique: "T2", threat_class: "impact", rationale: "r" },
          ],
        },
      ],
    },
    "impact",
  );
  assert.equal(grouped.techniqueCount, 1);
  assert.equal(grouped.detectors[0].gaps[0].technique, "T2");
});

test("one technique blind across two detectors counts once", () => {
  const grouped = groupGaps({
    generated_at_ms: 1,
    suite_name: "",
    suite_path: "",
    corpus_version: "",
    detectors: [
      {
        detector: "a",
        intentionally_uncovered: [
          { technique: "T1", threat_class: "impact", rationale: "r" },
        ],
      },
      {
        detector: "b",
        intentionally_uncovered: [
          { technique: "T1", threat_class: "impact", rationale: "r" },
        ],
      },
    ],
  });
  assert.equal(grouped.techniqueCount, 1, "distinct techniques, not rows");
  assert.equal(grouped.detectorCount, 2);
});

test("a filter that matches nothing yields no rows and no counts", () => {
  const grouped = groupGaps(SNAPSHOT, "exfiltration");
  assert.deepEqual(grouped.detectors, []);
  assert.equal(grouped.techniqueCount, 0);
  assert.equal(grouped.detectorCount, 0);
});
