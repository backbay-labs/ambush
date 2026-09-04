import assert from "node:assert/strict";
import test from "node:test";

import { PERCH_TAURI_COMMANDS } from "@/shared/api/tauriPerch";

import {
  assertEveryPerchCommandHandled,
  PERCH_ADMITTED_ISSUER,
  PERCH_DAEMON_UNREACHABLE_PREFIX,
  PERCH_CASE_CHANNEL,
  PERCH_FINDING_CARD_EVENT_ID,
  PERCH_FINDING_ID,
  PERCH_HANDLED_COMMANDS,
  PERCH_INCIDENT_ID,
  PERCH_LANE_CHANNEL,
  PERCH_NOW_MS,
  handlePerchMockCommand,
  isPerchMockCommand,
  perchMockLog,
  resetPerchMock,
  seedPerchFixture,
} from "./e2ePerchBridge.ts";

const HEX64 = /^[0-9a-f]{64}$/;
/** Any RFC 4122 shape: the mock channel ids the lanes point at are v5. */
const UUID_SHAPE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** The mock daemon mints v4, so a minted case id is checked strictly. */
const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

test.beforeEach(() => {
  resetPerchMock();
});

test("every command the console can call has an explicit handler", () => {
  assert.deepEqual(
    [...PERCH_HANDLED_COMMANDS].sort(),
    [...PERCH_TAURI_COMMANDS].sort(),
    "the mock's closed set and the console's command list must be the same set",
  );
  // The negative control: the module-scope assertion is what turns a new
  // command with no mock into an import-time failure, so it has to actually
  // refuse one.
  assert.throws(
    () =>
      assertEveryPerchCommandHandled([...PERCH_TAURI_COMMANDS, "perch_new"]),
    /perch_new/,
  );
  assert.doesNotThrow(() =>
    assertEveryPerchCommandHandled([...PERCH_TAURI_COMMANDS]),
  );
});

test("the prefix guard claims every perch command and nothing else", () => {
  for (const command of PERCH_TAURI_COMMANDS) {
    assert.equal(isPerchMockCommand(command), true, command);
  }
  assert.equal(isPerchMockCommand("get_channels"), false);
  assert.equal(isPerchMockCommand("sign_event"), false);
});

test("a perch command with no fixture fails by name, not as 'unsupported'", () => {
  assert.throws(
    () => handlePerchMockCommand("perch_unlisted", null),
    /perch_unlisted/,
  );
});

test("perch_reviewed_findings answers the fixture's typed window", () => {
  const reviewed = [
    {
      finding_id: PERCH_FINDING_ID,
      reviewed_at_ms: PERCH_NOW_MS,
      action: "dismiss",
      analyst_id: "local-operator",
      false_positive: true,
      incident_id: PERCH_INCIDENT_ID,
      strategy_id: "dns_exfil_beaconing",
      host_id: "web-04",
    },
  ];
  seedPerchFixture({ reviewed, storeDurable: true });
  const answer = handlePerchMockCommand("perch_reviewed_findings", {});
  assert.equal(answer.schema_version, 1);
  assert.deepEqual(answer.reviewed, reviewed);
  assert.equal(answer.window_incident_count, 1);
  assert.equal(answer.window_is_truncated, false);
  assert.equal(answer.store_durable, true);
  assert.equal(answer.observed_at_ms, PERCH_NOW_MS);
  // The honest empty window is the default, not an omission.
  resetPerchMock();
  const empty = handlePerchMockCommand("perch_reviewed_findings", {});
  assert.deepEqual(empty.reviewed, []);
  assert.equal(empty.window_incident_count, 0);
  assert.equal(empty.store_durable, false);
});

test("perch_admitted_issuers answers public ids and lane UUIDs only", () => {
  const answer = handlePerchMockCommand("perch_admitted_issuers", null);
  assert.deepEqual(Object.keys(answer).sort(), [
    "colony_id",
    "issuers",
    "lanes",
  ]);
  assert.ok(answer.issuers.includes(PERCH_ADMITTED_ISSUER));
  for (const issuer of answer.issuers) {
    assert.match(issuer, HEX64, "an issuer is a public key, in lowercase hex");
  }
  const laneIds = Object.values(answer.lanes);
  assert.ok(laneIds.includes(PERCH_LANE_CHANNEL));
  for (const laneId of laneIds) {
    assert.match(laneId, UUID_SHAPE, "a lane is a channel UUID");
  }
  // Nothing secret may ride this answer: it is unauthenticated on the daemon.
  const serialized = JSON.stringify(answer);
  for (const secret of ["bearer", "token", "secret", "private", "nsec"]) {
    assert.equal(
      serialized.toLowerCase().includes(secret),
      false,
      `the identities answer must not carry a ${secret}`,
    );
  }
});

test("perch_mint_incident mints one case per finding and replays it", () => {
  const first = handlePerchMockCommand("perch_mint_incident", {
    input: { findingId: PERCH_FINDING_ID },
  });
  assert.match(first.case_id, UUID_V4);
  assert.ok(first.incident_id.startsWith("incident:perch-case:"));
  assert.equal(first.created, true);
  const replay = handlePerchMockCommand("perch_mint_incident", {
    input: { findingId: PERCH_FINDING_ID },
  });
  assert.equal(replay.case_id, first.case_id, "the case id is stable");
  assert.equal(replay.incident_id, first.incident_id);
  assert.equal(replay.created, false, "a replay creates nothing");
  const other = handlePerchMockCommand("perch_mint_incident", {
    input: { findingId: "some-other-finding" },
  });
  assert.notEqual(
    other.case_id,
    first.case_id,
    "a second finding, a second case",
  );
});

test("perch_finding_feedback records one row per finding and verdict event", () => {
  const send = (verdictEventId) =>
    handlePerchMockCommand("perch_finding_feedback", {
      findingId: PERCH_FINDING_ID,
      incidentId: PERCH_INCIDENT_ID,
      action: "dismiss",
      verdictEventId,
      reason: null,
    });
  const intent = "a".repeat(64);
  const first = send(intent);
  assert.equal(first.replayed, false);
  assert.equal(first.finding_id, PERCH_FINDING_ID);
  assert.equal(first.action, "dismiss");
  const replay = send(intent);
  assert.equal(replay.replayed, true, "the same intent is idempotent");
  assert.equal(replay.feedback_id, first.feedback_id);
  send("b".repeat(64));
  assert.equal(
    handlePerchMockCommand("perch_reviewed_findings", {}).reviewed.length,
    2,
    "two intent ids are two rows; one intent id replayed is one",
  );
});

test("the offline daemon speaks the Rust command's own error prefix", () => {
  // The console keys `daemon-unreachable` off this exact prefix. A mock that
  // said "perch daemon unreachable" would drive the `failed` branch instead
  // and the spec would be testing a state the product never reaches.
  assert.equal(PERCH_DAEMON_UNREACHABLE_PREFIX, "daemon unreachable:");
  seedPerchFixture({ daemonReachable: false });
  assert.throws(
    () =>
      handlePerchMockCommand("perch_mint_incident", {
        input: { findingId: "x" },
      }),
    (error) => error.message.startsWith(PERCH_DAEMON_UNREACHABLE_PREFIX),
  );
});

test("leg 2 can be taken offline and restored without touching leg 1", () => {
  seedPerchFixture({ daemonReachable: false });
  assert.throws(
    () =>
      handlePerchMockCommand("perch_finding_feedback", {
        findingId: PERCH_FINDING_ID,
        incidentId: PERCH_INCIDENT_ID,
        action: "dismiss",
        verdictEventId: "c".repeat(64),
        reason: null,
      }),
    /unreachable/,
  );
  // Leg 1 is a relay write and does not go through the daemon at all.
  const verdict = handlePerchMockCommand("perch_record_verdict", {
    input: {
      findingCardId: PERCH_FINDING_CARD_EVENT_ID,
      caseChannel: PERCH_CASE_CHANNEL,
      incidentId: PERCH_INCIDENT_ID,
      decision: "dismiss",
      rationale: null,
    },
  });
  assert.match(verdict.nostr_intent_event_id, HEX64);
  assert.equal(verdict.finding_id, PERCH_FINDING_ID);
  seedPerchFixture({ daemonReachable: true });
  const acked = handlePerchMockCommand("perch_finding_feedback", {
    findingId: PERCH_FINDING_ID,
    incidentId: PERCH_INCIDENT_ID,
    action: "dismiss",
    verdictEventId: verdict.nostr_intent_event_id,
    reason: null,
  });
  assert.equal(acked.replayed, false);
});

test("perch_record_verdict reads the finding id off the named card", () => {
  assert.throws(
    () =>
      handlePerchMockCommand("perch_record_verdict", {
        input: {
          findingCardId: "d".repeat(64),
          caseChannel: PERCH_CASE_CHANNEL,
          incidentId: PERCH_INCIDENT_ID,
          decision: "dismiss",
          rationale: null,
        },
      }),
    /finding card not found/,
  );
  const one = handlePerchMockCommand("perch_record_verdict", {
    input: {
      findingCardId: PERCH_FINDING_CARD_EVENT_ID,
      caseChannel: PERCH_CASE_CHANNEL,
      incidentId: PERCH_INCIDENT_ID,
      decision: "dismiss",
      rationale: "backup job",
    },
  });
  const two = handlePerchMockCommand("perch_record_verdict", {
    input: {
      findingCardId: PERCH_FINDING_CARD_EVENT_ID,
      caseChannel: PERCH_CASE_CHANNEL,
      incidentId: PERCH_INCIDENT_ID,
      decision: "dismiss",
      rationale: "backup job",
    },
  });
  assert.notEqual(
    one.nostr_intent_event_id,
    two.nostr_intent_event_id,
    "every relay publish is its own event; a retry that re-signs is visible here",
  );
  assert.equal(one.signature.algorithm, "ed25519");
  assert.match(one.signature.public_key_hex, HEX64);
  assert.equal(
    Object.keys(one.signature).includes("private_key_hex"),
    false,
    "no secret half crosses IPC",
  );
});

test("the command log records order, which is the two-leg proof", () => {
  handlePerchMockCommand("perch_record_verdict", {
    input: {
      findingCardId: PERCH_FINDING_CARD_EVENT_ID,
      caseChannel: PERCH_CASE_CHANNEL,
      incidentId: PERCH_INCIDENT_ID,
      decision: "dismiss",
      rationale: null,
    },
  });
  handlePerchMockCommand("perch_finding_feedback", {
    findingId: PERCH_FINDING_ID,
    incidentId: PERCH_INCIDENT_ID,
    action: "dismiss",
    verdictEventId: "e".repeat(64),
    reason: null,
  });
  assert.deepEqual(perchMockLog(), [
    "perch_record_verdict",
    "perch_finding_feedback",
  ]);
  resetPerchMock();
  assert.deepEqual(perchMockLog(), []);
});

test("leg 2 can be made to refuse with an exact message", () => {
  // The console classifies on the prefix and renders the message, so a spec
  // needs to control it verbatim — including a message that quotes a wire
  // identifier carrying a bidi override.
  const message = "daemon answered 422: unknown finding ‮f2c9a1b4";
  seedPerchFixture({ feedbackFailureMessage: message });
  assert.throws(
    () =>
      handlePerchMockCommand("perch_finding_feedback", {
        findingId: PERCH_FINDING_ID,
        incidentId: PERCH_INCIDENT_ID,
        action: "dismiss",
        verdictEventId: "f".repeat(64),
        reason: null,
      }),
    (error) => error.message === message,
  );
  seedPerchFixture({ feedbackFailureMessage: null });
  assert.equal(
    handlePerchMockCommand("perch_finding_feedback", {
      findingId: PERCH_FINDING_ID,
      incidentId: PERCH_INCIDENT_ID,
      action: "dismiss",
      verdictEventId: "f".repeat(64),
      reason: null,
    }).replayed,
    false,
  );
});
