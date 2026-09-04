// The two-legged write, as a state machine.
//
// The property is that no terminal state is reachable except through
// `recorded`, and `recorded` is reachable only from a relay OK. A machine that
// could reach `daemon-dispatched` from `sending` would be an optimistic write
// wearing a state machine's clothes, so the ordering tests below matter more
// than the transition ones.

import assert from "node:assert/strict";
import test from "node:test";

import { verdictWriteReducer } from "./verdictWrite.ts";

const idle = { phase: "idle" };
const INTENT = "aa".repeat(32);
const WINNER = "bb".repeat(32);

const outcome = (over = {}) => ({
  outcome: "dispatched",
  rule: null,
  reason: null,
  receipt_id: null,
  decided_at_ms: 6,
  superseded_by: null,
  winning_decision: null,
  replayed: false,
  ...over,
});

const recorded = () =>
  verdictWriteReducer(verdictWriteReducer(idle, { type: "start" }), {
    type: "leg1-ok",
    atMs: 5,
    intentEventId: INTENT,
  });

test("the terminal states are reached only through recorded, never optimistically", () => {
  let state = verdictWriteReducer(idle, { type: "start" });
  assert.equal(state.phase, "sending");
  state = verdictWriteReducer(state, {
    type: "leg1-ok",
    atMs: 5,
    intentEventId: INTENT,
  });
  assert.equal(state.phase, "recorded");

  assert.equal(
    verdictWriteReducer(state, { type: "leg2-ok", outcome: outcome() }).phase,
    "daemon-dispatched",
  );
  assert.deepEqual(
    verdictWriteReducer(state, {
      type: "leg2-ok",
      outcome: outcome({
        outcome: "refused_late",
        rule: "runtime.containment_refused",
        reason: "no containment lease store is configured",
      }),
    }),
    {
      phase: "refused-late",
      ruleName: "runtime.containment_refused",
      reason: "no containment lease store is configured",
    },
  );
  assert.equal(
    verdictWriteReducer(state, {
      type: "leg2-ok",
      outcome: outcome({
        outcome: "refused_late_governance",
        rule: "governance.receipt_veto",
        reason: "the attested decision is a veto",
      }),
    }).phase,
    "refused-late-governance",
  );
  assert.equal(
    verdictWriteReducer(state, {
      type: "leg2-unreachable",
      reason: "daemon unreachable: connection refused",
    }).phase,
    "daemon-unreachable",
  );

  const superseded = verdictWriteReducer(state, {
    type: "leg2-ok",
    outcome: outcome({
      outcome: "superseded",
      rule: "hold_already_decided",
      reason: "another operator's decision was recorded first",
      superseded_by: WINNER,
      winning_decision: "grant",
      decided_at_ms: 7,
    }),
  });
  assert.equal(superseded.phase, "superseded");
  assert.equal(superseded.winningIntentEventId, WINNER);
  assert.equal(superseded.winningDecision, "grant");
  assert.equal(superseded.decidedAtMs, 7);
});

// ---------------------------------------------------------------------------
// THE ORDERING. Each of these is an event an optimistic machine would accept.
// ---------------------------------------------------------------------------

test("a leg-2 outcome cannot arrive before leg 1 was recorded", () => {
  const state = verdictWriteReducer(
    { phase: "sending" },
    { type: "leg2-ok", outcome: outcome() },
  );
  assert.deepEqual(
    state,
    { phase: "sending" },
    "ignored: there is no intent record to acknowledge",
  );
});

test("a leg-2 outcome cannot arrive from idle", () => {
  for (const event of [
    { type: "leg2-ok", outcome: outcome() },
    { type: "leg2-unreachable", reason: "x" },
    { type: "leg2-rejected", reason: "x" },
  ]) {
    assert.deepEqual(verdictWriteReducer(idle, event), idle, event.type);
  }
});

test("a second start does not restart a write already in flight", () => {
  const sending = verdictWriteReducer(idle, { type: "start" });
  assert.deepEqual(verdictWriteReducer(sending, { type: "start" }), sending);
  const state = recorded();
  assert.deepEqual(verdictWriteReducer(state, { type: "start" }), state);
});

test("a terminal state is terminal: a later leg-2 event does not move it", () => {
  const dispatched = verdictWriteReducer(recorded(), {
    type: "leg2-ok",
    outcome: outcome({ receipt_id: "r-1" }),
  });
  assert.deepEqual(
    verdictWriteReducer(dispatched, {
      type: "leg2-ok",
      outcome: outcome({ outcome: "superseded", superseded_by: WINNER }),
    }),
    dispatched,
    "a decision that already ran cannot be superseded after the fact",
  );
});

test("leg 1 failing is a refusal to write at all, not a half-written decision", () => {
  const state = verdictWriteReducer(
    verdictWriteReducer(idle, { type: "start" }),
    { type: "leg1-failed", reason: "relay refused the verdict card" },
  );
  assert.equal(state.phase, "daemon-unreachable");
  assert.match(state.reason, /intent card could not be published/);
  assert.match(state.reason, /relay refused the verdict card/);
});

test("an expired hold is a refusal naming the expiry, never a transport error", () => {
  const state = verdictWriteReducer(recorded(), {
    type: "leg2-ok",
    outcome: outcome({ outcome: "expired" }),
  });
  assert.equal(state.phase, "daemon-refused");
  assert.equal(state.ruleName, "hold_expired");
  assert.match(state.reason, /never taken/);
});

test("an unknown hold is a refusal, and says the daemon has no record", () => {
  const state = verdictWriteReducer(recorded(), {
    type: "leg2-ok",
    outcome: outcome({ outcome: "unknown_hold" }),
  });
  assert.equal(state.phase, "daemon-refused");
  assert.equal(state.ruleName, "unknown_hold");
});

test("the winning decision comes from a typed field, never from parsing prose", () => {
  // The daemon's `reason` is free text. A reducer that decided the winner by
  // searching it for the word "refuse" would flip the whole meaning of the
  // sentence the operator reads on any reason that happened to contain it —
  // for instance "the other operator did not refuse".
  const misleading = verdictWriteReducer(recorded(), {
    type: "leg2-ok",
    outcome: outcome({
      outcome: "superseded",
      reason: "the other operator did not refuse; they granted it",
      superseded_by: WINNER,
      winning_decision: "grant",
    }),
  });
  assert.equal(misleading.winningDecision, "grant");
});

test("a superseded outcome with no winner named is still superseded and says so", () => {
  const state = verdictWriteReducer(recorded(), {
    type: "leg2-ok",
    outcome: outcome({ outcome: "superseded", superseded_by: null }),
  });
  assert.equal(state.phase, "superseded");
  assert.equal(state.winningIntentEventId, "");
  assert.equal(
    state.winningDecision,
    "unknown",
    "the console does not guess which way the winning decision went",
  );
});

test("a rejected request is a refusal that names the request, not the policy", () => {
  const state = verdictWriteReducer(recorded(), {
    type: "leg2-rejected",
    reason: "nostr_intent_event_id must be 64 lowercase hex characters",
  });
  assert.equal(state.phase, "daemon-refused");
  assert.equal(state.ruleName, "request_rejected");
});

test("reset returns to idle from every phase, so one hold's outcome never renders against the next", () => {
  const phases = [
    idle,
    { phase: "sending" },
    recorded(),
    verdictWriteReducer(recorded(), { type: "leg2-ok", outcome: outcome() }),
    verdictWriteReducer(recorded(), {
      type: "leg2-unreachable",
      reason: "x",
    }),
  ];
  for (const phase of phases) {
    assert.deepEqual(verdictWriteReducer(phase, { type: "reset" }), idle);
  }
});

test("reset is the ONLY way back to idle", () => {
  // `leg1-failed` used to be the nearest thing to a reset and lands in
  // `daemon-unreachable`, which would have rendered a transport error every
  // time the operator selected a different hold.
  const state = verdictWriteReducer(recorded(), {
    type: "leg1-failed",
    reason: "",
  });
  assert.notEqual(state.phase, "idle");
});
