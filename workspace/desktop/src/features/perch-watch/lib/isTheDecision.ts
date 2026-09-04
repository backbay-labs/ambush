// Which of several signed verdict cards on one hold is THE decision.
//
// The question is real and unavoidable. Layer 1 p-tags every Approve-scoped
// principal, so two consoles can hold the same open hold; leg 1 is published
// BEFORE leg 2 is POSTed; the relay has no compare-and-set; and a kind:9 is
// immutable. Two genuine, correctly signed verdict cards for one hold therefore
// sit in the case channel forever, and the case timeline cannot tell them apart
// on its own.
//
// The join is the SIGNATURE, never the event id (C13/C16). A relay event id is
// chosen by whoever publishes it and is not inside the signed preimage, so a
// card could name the winner's id and claim to be the decision. The signature
// bytes are what the daemon actually verified before it wrote the record.

/** The card being judged. `eventId` is accepted and deliberately unused. */
export type VerdictCardIdentity = {
  holdId: string;
  /** The `signature_hex` inside the card's signed body. */
  signatureHex: string;
  /** Present for callers' convenience. NEVER part of the comparison. */
  eventId?: string;
};

/** As much of the daemon's hold record as this predicate reads. */
export type DecisionRecord = {
  hold_id: string;
  decision: { signature: { signature_hex: string } | null } | null;
} | null;

/**
 * `decision` | `not-the-decision` | `unresolved`.
 *
 * `unresolved` is the honest answer with no daemon record, and it is a
 * different claim from `not-the-decision`: one says the console cannot reach
 * the authority, the other says the authority named someone else. Collapsing
 * them would let an unreachable daemon read as "your decision lost".
 */
export function isTheDecision(
  card: VerdictCardIdentity,
  record: DecisionRecord,
): "decision" | "not-the-decision" | "unresolved" {
  if (record === null) return "unresolved";
  if (record.hold_id !== card.holdId) return "unresolved";
  const recorded = record.decision?.signature?.signature_hex ?? null;
  if (recorded === null || recorded.length === 0) return "not-the-decision";
  if (card.signatureHex.length === 0) return "not-the-decision";
  return recorded === card.signatureHex ? "decision" : "not-the-decision";
}
