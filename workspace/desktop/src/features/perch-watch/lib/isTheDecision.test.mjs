// Which of several signed verdict cards is THE decision.
//
// Several can exist for one hold and all of them are genuine: every
// Approve-scoped principal is p-tagged on the notice, the relay has no
// compare-and-set, and a kind:9 is immutable, so two consoles that both decided
// leave two signed cards in the case channel forever. Only the daemon's
// compare-and-set says which one ran.

import assert from "node:assert/strict";
import test from "node:test";

import { isTheDecision } from "./isTheDecision.ts";

const SIG = "dd".repeat(64);
const OTHER = "ee".repeat(64);

const record = (over = {}) => ({
  hold_id: "h_a07aeacf",
  decision: { signature: { signature_hex: SIG } },
  ...over,
});

test("a card is the decision iff its signature bytes are on the daemon record for its hold", () => {
  assert.equal(
    isTheDecision({ holdId: "h_a07aeacf", signatureHex: SIG }, record()),
    "decision",
  );
  assert.equal(
    isTheDecision({ holdId: "h_a07aeacf", signatureHex: OTHER }, record()),
    "not-the-decision",
  );
  assert.equal(
    isTheDecision(
      { holdId: "h_a07aeacf", signatureHex: SIG },
      record({ decision: null }),
    ),
    "not-the-decision",
  );
  assert.equal(
    isTheDecision({ holdId: "h_a07aeacf", signatureHex: SIG }, null),
    "unresolved",
  );
});

test("the join is the SIGNATURE, never the event id", () => {
  // C13/C16. The relay event id is chosen by the publisher and is not in the
  // signed preimage, so joining on it would let a card claim to be the
  // decision by naming the winner's id. The signature bytes are the daemon's
  // own record of what it verified.
  const record_ = record();
  assert.equal(
    isTheDecision(
      { holdId: "h_a07aeacf", signatureHex: SIG, eventId: "ff".repeat(32) },
      record_,
    ),
    "decision",
    "a different event id does not change the answer",
  );
});

test("a record for a different hold resolves nothing rather than guessing", () => {
  assert.equal(
    isTheDecision(
      { holdId: "h_b18bfbd0", signatureHex: SIG },
      record({ hold_id: "h_a07aeacf" }),
    ),
    "unresolved",
  );
});

test("a decision record with no signature is not a match for anything", () => {
  // A replayed record, or one the daemon wrote without a detached signature,
  // proves nothing about which card ran.
  assert.equal(
    isTheDecision(
      { holdId: "h_a07aeacf", signatureHex: SIG },
      record({ decision: { signature: null } }),
    ),
    "not-the-decision",
  );
});

test("comparison is exact: case and length both matter", () => {
  // Signature hex is lowercase on the wire from both sides. A
  // case-insensitive compare would be a looser join than the daemon's own,
  // and a truncated one would let a prefix collide.
  assert.equal(
    isTheDecision(
      { holdId: "h_a07aeacf", signatureHex: SIG.toUpperCase() },
      record(),
    ),
    "not-the-decision",
  );
  assert.equal(
    isTheDecision(
      { holdId: "h_a07aeacf", signatureHex: SIG.slice(0, 32) },
      record(),
    ),
    "not-the-decision",
  );
});

test("an empty signature never matches, including an empty record signature", () => {
  assert.equal(
    isTheDecision({ holdId: "h_a07aeacf", signatureHex: "" }, record()),
    "not-the-decision",
  );
  assert.equal(
    isTheDecision(
      { holdId: "h_a07aeacf", signatureHex: "" },
      record({ decision: { signature: { signature_hex: "" } } }),
    ),
    "not-the-decision",
    "two absences are not a match",
  );
});
