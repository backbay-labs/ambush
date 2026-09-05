// Leg 2, kept until the daemon answers.
//
// Leg 1 is on the relay and cannot be taken back. If leg 2 never reaches the
// daemon, a signed decision exists that the daemon has never heard of — the
// hold sits open, the operator believes they answered, and the two states drift
// apart silently. So a leg 2 that could not be delivered is HELD here and
// re-sent on the next reconnect.
//
// What is spooled is the leg-2 CALL, never the decision. A retry re-sends the
// same `nostr_intent_event_id`, which is the daemon's idempotency key, so a
// duplicate delivery replays the existing record rather than deciding twice.
// Nothing here can re-sign leg 1: the entry carries an intent id that already
// exists and no signing material at all.

/** One undelivered leg 2. */
import type { PerchDetachedSignature } from "@/shared/api/tauriPerch";

export type SpooledLeg2 = {
  readonly holdId: string;
  readonly decision: "grant" | "refuse";
  /** Leg 1's card id. The idempotency key, and the reason a retry is safe. */
  readonly nostrIntentEventId: string;
  /**
   * Leg 1's stamp and signature, carried so a retry can complete leg 2
   * without re-signing. Without them a reconnect replay had nothing to send,
   * and the "never re-signs" rule made the spool a dead letter.
   */
  readonly decidedAtMs: number;
  readonly signature: PerchDetachedSignature;
  readonly rationale: string | null;
  readonly armedAtMs: number | null;
  readonly firstAttemptAtMs: number;
};

/** Keyed by hold: one operator has at most one undelivered decision per hold. */
const spool = new Map<string, SpooledLeg2>();

/** Hold an undelivered leg 2, replacing any earlier attempt for the same hold. */
export function spoolLeg2(entry: SpooledLeg2): void {
  spool.set(entry.holdId, entry);
}

/** Forget one hold's entry, once the daemon has answered about it. */
export function clearSpooledLeg2(holdId: string): void {
  spool.delete(holdId);
}

/** Everything still undelivered, oldest attempt first. */
export function spooledLeg2Entries(): readonly SpooledLeg2[] {
  return [...spool.values()].sort(
    (a, b) => a.firstAttemptAtMs - b.firstAttemptAtMs,
  );
}

/** How many decisions this console has recorded and not yet delivered. */
export function spooledLeg2Count(): number {
  return spool.size;
}

/**
 * Community-switch fence, registered in the typed reset registry
 * (`features/communities/communityScopedRegistry.ts`). A spooled leg 2 names a
 * hold on one colony's daemon; re-sending it to the next colony's daemon would
 * be a decision aimed at a hold that does not exist there.
 */
export function resetVerdictSpool(): void {
  spool.clear();
}
