import assert from "node:assert/strict";
import { test } from "node:test";

import { evaluateTripleLocally, SEVERITY_ORDER } from "./policyEvaluation.ts";

const shipped = [
  {
    index: 0,
    name: "execution-after-hours-autorespond",
    decision: "allow",
    threat_class: "execution",
    actions: ["deploy_decoy", "escalate"],
    min_severity: "HIGH",
    max_severity: "CRITICAL",
  },
  {
    index: 1,
    name: "command-and-control-emergency-block",
    decision: "allow",
    threat_class: "command_and_control",
    actions: ["block_egress", "escalate"],
    min_severity: "CRITICAL",
    max_severity: "CRITICAL",
  },
  {
    index: 2,
    name: "credential-access-destructive-deny",
    decision: "deny",
    threat_class: "credential_access",
    actions: ["revoke_credential"],
    min_severity: "LOW",
    max_severity: "HIGH",
  },
];

test("the display mirror agrees with the daemon on the shipped ruleset", () => {
  const verdicts = evaluateTripleLocally(shipped, {
    threat_class: "command_and_control",
    severity: "CRITICAL",
    action: "block_egress",
  });
  assert.deepEqual(
    verdicts.map((rule) => rule.verdict),
    ["not_matched", "decides", "not_reached"],
  );
  assert.deepEqual(SEVERITY_ORDER, ["LOW", "MEDIUM", "HIGH", "CRITICAL"]);
});

test("shadowing is per triple, never static: one rule decides one and not another", () => {
  const withinRange = evaluateTripleLocally(shipped, {
    threat_class: "credential_access",
    severity: "HIGH",
    action: "revoke_credential",
  });
  const aboveRange = evaluateTripleLocally(shipped, {
    threat_class: "credential_access",
    severity: "CRITICAL",
    action: "revoke_credential",
  });
  assert.equal(withinRange[2].verdict, "decides");
  assert.equal(
    aboveRange[2].verdict,
    "not_matched",
    "CRITICAL is above max_severity HIGH",
  );
});

test("severity is compared by rank, not by string order", () => {
  // "CRITICAL" < "HIGH" alphabetically; by rank it is above.
  const verdicts = evaluateTripleLocally(
    [
      {
        index: 0,
        name: "r",
        decision: "allow",
        threat_class: "execution",
        actions: [],
        min_severity: "HIGH",
        max_severity: "CRITICAL",
      },
    ],
    { threat_class: "execution", severity: "CRITICAL", action: "anything" },
  );
  assert.equal(verdicts[0].verdict, "decides");
});

test("an empty action list is a wildcard, not an empty set", () => {
  const verdicts = evaluateTripleLocally(
    [
      {
        index: 0,
        name: "catch-all",
        decision: "deny",
        threat_class: "impact",
        actions: [],
        min_severity: "LOW",
        max_severity: "CRITICAL",
      },
    ],
    { threat_class: "impact", severity: "LOW", action: "isolate_host" },
  );
  assert.equal(
    verdicts[0].verdict,
    "decides",
    "a rule naming no action would otherwise match nothing and never decide",
  );
});

test("an unknown severity matches nothing rather than sorting to the bottom", () => {
  const verdicts = evaluateTripleLocally(
    [
      {
        index: 0,
        name: "r",
        decision: "allow",
        threat_class: "execution",
        actions: [],
        min_severity: "LOW",
        max_severity: "CRITICAL",
      },
    ],
    { threat_class: "execution", severity: "NONSENSE", action: "escalate" },
  );
  assert.equal(verdicts[0].verdict, "not_matched");
});
