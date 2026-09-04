import assert from "node:assert/strict";
import test from "node:test";

import goldenFinding from "../../perch/wire/golden/card-swarm-finding-v1.json" with {
  type: "json",
};

import {
  caseFor,
  rememberCase,
  resetPerchCaseIndex,
} from "./perchCaseIndex.ts";
import {
  findingVerdictIntent,
  pendingFindingVerdicts,
  promoteFinding,
  recordFindingVerdict,
  resetFindingVerdictFlow,
  retryFindingFeedback,
} from "./findingVerdictFlow.ts";
import {
  getVerdictWriteState,
  resetPerchWriteStates,
} from "./verdictWriteState.ts";

const CARD_EVENT_ID =
  "5f1c3b9a204e7d68c1a4b0937e25fd8146ac9b3e70d25f81cc4a6b93e017d2af";
const FINDING_ID = goldenFinding.fact.locator.finding_id;
const CASE_ID = "27799e23-ab25-4659-b381-3de47ea7ca4d";
const INCIDENT_ID = `incident:perch-case:${CASE_ID}`;
const INTENT_ID = "a".repeat(64);

const subject = () => ({
  cardEventId: CARD_EVENT_ID,
  fact: structuredClone(goldenFinding.fact),
});

/** A dependency set whose every call is recorded, and whose answers are set per test. */
function fakes(overrides = {}) {
  const calls = [];
  const record = (name, value) => {
    calls.push(name);
    return value;
  };
  const deps = {
    calls,
    mintIncident: async (input) => {
      calls.push("mintIncident");
      deps.mintInput = input;
      return {
        schema_version: 1,
        incident_id: INCIDENT_ID,
        case_id: CASE_ID,
        created: true,
        degraded: [],
        record: {},
      };
    },
    recordVerdict: async (input) => {
      calls.push("recordVerdict");
      deps.verdictInput = input;
      return {
        nostr_intent_event_id: INTENT_ID,
        decided_at_ms: 1_787_754_972_123,
        signature: {
          algorithm: "ed25519",
          key_id: "local-operator",
          public_key_hex: "b".repeat(64),
          signature_hex: "c".repeat(128),
        },
        finding_id: FINDING_ID,
      };
    },
    findingFeedback: async (input) => {
      calls.push("findingFeedback");
      deps.feedbackInputs = [...(deps.feedbackInputs ?? []), input];
      return {
        schema_version: 1,
        feedback_id: "fb-1",
        action: input.action,
        incident_id: input.incidentId,
        finding_id: input.findingId,
        analyst_id: "local-operator",
        false_positive: input.action === "dismiss",
        replayed: false,
        outcome: {},
      };
    },
    invalidate: (keys) => record("invalidate", keys),
    navigate: (caseId) => {
      calls.push("navigate");
      deps.navigatedTo = caseId;
    },
    ...overrides,
  };
  return deps;
}

test.beforeEach(() => {
  resetFindingVerdictFlow();
  resetPerchCaseIndex();
  resetPerchWriteStates();
});

test("promotion mints one incident, remembers the daemon's ids, and publishes no verdict", async () => {
  const deps = fakes();
  const ref = await promoteFinding(subject(), deps);

  assert.deepEqual(ref, { caseId: CASE_ID, incidentId: INCIDENT_ID });
  assert.deepEqual(
    caseFor(FINDING_ID),
    ref,
    "the console remembers, it does not mint",
  );
  assert.equal(
    deps.calls.filter((c) => c === "mintIncident").length,
    1,
    "one promotion, one B3i call",
  );
  assert.equal(
    deps.calls.includes("recordVerdict"),
    false,
    "promotion is not a verdict",
  );
  assert.equal(deps.calls.includes("findingFeedback"), false);
  assert.equal(
    deps.navigatedTo,
    CASE_ID,
    "the console opens the case it was given",
  );
  // The B3i request is built from the admitted card's own fact.
  assert.equal(deps.mintInput.findingId, FINDING_ID);
  assert.equal(deps.mintInput.eventId, goldenFinding.fact.locator.event_id);
  assert.equal(
    deps.mintInput.strategyId,
    goldenFinding.fact.locator.strategy_id,
  );
  assert.equal(deps.mintInput.hostId, goldenFinding.fact.locator.host_id);
  assert.equal(deps.mintInput.severity, goldenFinding.fact.finding.severity);
  assert.deepEqual(
    deps.mintInput.threatClass,
    goldenFinding.fact.finding.threat_class,
  );
  assert.equal(deps.mintInput.createdAtMs, goldenFinding.fact.emitted_at_ms);
  assert.ok(deps.mintInput.summary.includes(FINDING_ID));
  assert.ok(
    deps.mintInput.correlationKeys.some((k) => k.includes(FINDING_ID)),
    "the finding is reachable as a correlation key",
  );
  // Promotion refreshes what promotion changed, and nothing else.
  const invalidated = JSON.stringify(deps.calls);
  assert.ok(invalidated.includes("invalidate"));
});

test("a dismissal before promotion calls neither leg", async () => {
  const deps = fakes();
  await recordFindingVerdict(subject(), "dismiss", null, deps);

  assert.deepEqual(getVerdictWriteState(FINDING_ID), {
    phase: "not-yet-correlated",
  });
  assert.equal(deps.calls.includes("recordVerdict"), false);
  assert.equal(deps.calls.includes("findingFeedback"), false);
  assert.equal(findingVerdictIntent(FINDING_ID), null);
});

test("after promotion, leg 1 resolves before leg 2 starts", async () => {
  const order = [];
  let releaseLegOne;
  const gate = new Promise((resolve) => {
    releaseLegOne = resolve;
  });
  const deps = fakes({
    recordVerdict: async () => {
      order.push("leg1:start");
      await gate;
      order.push("leg1:end");
      return {
        nostr_intent_event_id: INTENT_ID,
        decided_at_ms: 1,
        signature: {
          algorithm: "ed25519",
          key_id: "local-operator",
          public_key_hex: "b".repeat(64),
          signature_hex: "c".repeat(128),
        },
        finding_id: FINDING_ID,
      };
    },
    findingFeedback: async (input) => {
      order.push("leg2:start");
      return {
        schema_version: 1,
        feedback_id: "fb-1",
        action: input.action,
        incident_id: input.incidentId,
        finding_id: input.findingId,
        analyst_id: "local-operator",
        false_positive: true,
        replayed: false,
        outcome: {},
      };
    },
  });
  rememberCase(FINDING_ID, { caseId: CASE_ID, incidentId: INCIDENT_ID });

  const running = recordFindingVerdict(subject(), "dismiss", null, deps);
  await Promise.resolve();
  assert.deepEqual(getVerdictWriteState(FINDING_ID), { phase: "sending" });
  assert.deepEqual(order, ["leg1:start"], "leg 2 has not started");
  releaseLegOne();
  await running;
  assert.deepEqual(order, ["leg1:start", "leg1:end", "leg2:start"]);
  assert.equal(getVerdictWriteState(FINDING_ID).phase, "acknowledged");
  assert.equal(getVerdictWriteState(FINDING_ID).feedbackId, "fb-1");
});

test("a leg-1 failure never reaches the daemon", async () => {
  const deps = fakes({
    recordVerdict: async () => {
      throw new Error("relay refused the verdict card: restricted");
    },
  });
  rememberCase(FINDING_ID, { caseId: CASE_ID, incidentId: INCIDENT_ID });

  await recordFindingVerdict(subject(), "dismiss", null, deps);

  assert.equal(getVerdictWriteState(FINDING_ID).phase, "failed");
  assert.match(getVerdictWriteState(FINDING_ID).reason, /relay refused/);
  assert.equal(
    deps.calls.includes("findingFeedback"),
    false,
    "no signed record, nothing to tell the daemon about",
  );
  assert.equal(findingVerdictIntent(FINDING_ID), null);
});

test("a leg-2 network failure keeps the exact intent, and retry re-sends only leg 2", async () => {
  let reachable = false;
  const deps = fakes({
    findingFeedback: async (input) => {
      deps.calls.push("findingFeedback");
      deps.feedbackInputs = [...(deps.feedbackInputs ?? []), input];
      if (!reachable) {
        throw new Error("daemon unreachable: error sending request for url");
      }
      return {
        schema_version: 1,
        feedback_id: "fb-2",
        action: input.action,
        incident_id: input.incidentId,
        finding_id: input.findingId,
        analyst_id: "local-operator",
        false_positive: true,
        replayed: false,
        outcome: {},
      };
    },
  });
  rememberCase(FINDING_ID, { caseId: CASE_ID, incidentId: INCIDENT_ID });

  await recordFindingVerdict(subject(), "dismiss", "backup job", deps);
  assert.equal(getVerdictWriteState(FINDING_ID).phase, "daemon-unreachable");
  const kept = findingVerdictIntent(FINDING_ID);
  assert.equal(kept.verdictEventId, INTENT_ID);
  assert.equal(kept.reason, "backup job");
  assert.deepEqual(pendingFindingVerdicts(), [kept]);

  reachable = true;
  await retryFindingFeedback(FINDING_ID, deps);

  assert.equal(getVerdictWriteState(FINDING_ID).phase, "acknowledged");
  assert.equal(
    deps.calls.filter((c) => c === "recordVerdict").length,
    1,
    "a retry re-signs nothing and republishes nothing",
  );
  assert.equal(deps.calls.filter((c) => c === "findingFeedback").length, 2);
  assert.equal(
    deps.feedbackInputs[1].verdictEventId,
    deps.feedbackInputs[0].verdictEventId,
    "leg 2 is retried with the SAME intent event id",
  );
  assert.deepEqual(deps.feedbackInputs[1], deps.feedbackInputs[0]);
  assert.deepEqual(
    pendingFindingVerdicts(),
    [],
    "an acknowledged leg 2 is not pending",
  );
});

test("B3's 404 is not-yet-correlated, and every other refusal is failed", async () => {
  const cases = [
    [
      "not-yet-correlated: no incident carries this finding yet",
      "not-yet-correlated",
    ],
    ["daemon unreachable: error sending request for url", "daemon-unreachable"],
    ["daemon not configured: perch.daemon_url is unset", "daemon-unreachable"],
    ["daemon answered 422: unknown action", "failed"],
    ["daemon answered 500: incident store is not durable", "failed"],
  ];
  for (const [message, phase] of cases) {
    resetFindingVerdictFlow();
    resetPerchCaseIndex();
    resetPerchWriteStates();
    const deps = fakes({
      findingFeedback: async () => {
        deps.calls.push("findingFeedback");
        throw new Error(message);
      },
    });
    rememberCase(FINDING_ID, { caseId: CASE_ID, incidentId: INCIDENT_ID });
    await recordFindingVerdict(subject(), "confirm", null, deps);
    assert.equal(
      getVerdictWriteState(FINDING_ID).phase,
      phase,
      `${message} must render as ${phase}`,
    );
    assert.equal(
      findingVerdictIntent(FINDING_ID).verdictEventId,
      INTENT_ID,
      "the Ambush record survives every leg-2 outcome",
    );
  }
});

test("retrying a finding with no leg-1 record does nothing at all", async () => {
  const deps = fakes();
  const retried = await retryFindingFeedback("never-recorded", deps);
  assert.equal(retried, false);
  assert.deepEqual(deps.calls, []);
});

test("a community switch clears every remembered leg", async () => {
  const deps = fakes({
    findingFeedback: async () => {
      deps.calls.push("findingFeedback");
      throw new Error("daemon unreachable: error sending request for url");
    },
  });
  rememberCase(FINDING_ID, { caseId: CASE_ID, incidentId: INCIDENT_ID });
  await recordFindingVerdict(subject(), "dismiss", null, deps);
  assert.equal(pendingFindingVerdicts().length, 1);
  resetFindingVerdictFlow();
  assert.deepEqual(pendingFindingVerdicts(), []);
  assert.equal(findingVerdictIntent(FINDING_ID), null);
});
