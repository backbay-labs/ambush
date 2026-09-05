import assert from "node:assert/strict";
import { test } from "node:test";

import { caseIncidentId, killChainFromIncident } from "./caseIncident.ts";

const member = (findingId, extra = {}) => ({
  finding_id: findingId,
  hunt_id: `hunt-${findingId}`,
  investigation_id: `inv-${findingId}`,
  reason: `reason for ${findingId}`,
  confidence_score: 0.5,
  host_id: "host-ops-1",
  strategy_id: "suspicious_process_tree",
  shared_keys: [],
  evidence_links: [],
  ...extra,
});

const read = (overrides = {}) => ({
  schema_version: 1,
  incident_id: "incident:perch-case:c-1",
  case_id: "c-1",
  summary: "",
  created_at_ms: 0,
  window_start_ms: 0,
  window_end_ms: 0,
  trigger_finding_id: "f-seed",
  trigger_strategy_id: "suspicious_process_tree",
  threat_class: "execution",
  severity: "HIGH",
  confidence_score: 0.8,
  graph_dimensions: ["temporal"],
  correlation_keys: [],
  included_members: [
    member("f-seed"),
    member("f-2", {
      evidence_links: [
        {
          dimension: "temporal",
          explanation: "",
          shared_values: [],
          weight: 1,
        },
        {
          dimension: "temporal",
          explanation: "again",
          shared_values: [],
          weight: 1,
        },
        { dimension: "entity", explanation: "", shared_values: [], weight: 2 },
      ],
    }),
  ],
  rejected_members: [member("f-out", { host_id: null, strategy_id: null })],
  false_positive_measurements: [],
  ...overrides,
});

test("the case's incident id is the daemon's minted form", () => {
  assert.equal(caseIncidentId("27799e23"), "incident:perch-case:27799e23");
});

test("the trigger is the seed, edges are one per member and dimension, and rejected members get none", () => {
  const chain = killChainFromIncident(read());
  assert.deepEqual(
    chain.included.map((m) => [m.findingId, m.seed]),
    [
      ["f-seed", true],
      ["f-2", false],
    ],
  );
  assert.deepEqual(chain.edges, [
    { from: "f-seed", to: "f-2", dimension: "temporal" },
    { from: "f-seed", to: "f-2", dimension: "entity" },
  ]);
  assert.equal(chain.rejected.length, 1);
});

test("a host or strategy the daemon did not record renders as a dash, never a guess", () => {
  const chain = killChainFromIncident(read());
  assert.equal(chain.rejected[0].host, "—");
  assert.equal(chain.rejected[0].strategyId, "—");
  assert.equal(chain.included[0].host, "host-ops-1");
});

test("without a trigger the first joined member seeds; with no members there are no edges", () => {
  const chain = killChainFromIncident(read({ trigger_finding_id: null }));
  assert.equal(chain.included[0].seed, true);
  const empty = killChainFromIncident(
    read({
      trigger_finding_id: null,
      included_members: [],
      rejected_members: [],
    }),
  );
  assert.deepEqual(empty, { included: [], rejected: [], edges: [] });
});
