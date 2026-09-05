/**
 * The shift ledger: when this watch began, and which expired-undecided holds
 * the operator has looked at.
 *
 * Module-level and community-scoped, so it is reset in
 * `communityScopedRegistry.ts`. Carrying one community's shift start into
 * another would date every case in the handoff to a shift that happened
 * somewhere else.
 *
 * Acknowledgement lives here rather than on the daemon on purpose: it is a
 * statement that a person read the row, not a change to the hold. Nothing
 * about the hold moves, and INV-19 forbids the count going down.
 */

type ShiftLedger = {
  startedAtMs: number | null;
  acknowledged: Set<string>;
};

const ledger: ShiftLedger = { startedAtMs: null, acknowledged: new Set() };

/**
 * The instant this shift began: the first perch surface visited, or the moment
 * the watch was taken. Idempotent — a later call does not move the start, so
 * navigating between perch surfaces cannot silently shorten the shift.
 */
export function beginShift(nowMs: number): number {
  if (ledger.startedAtMs === null) {
    ledger.startedAtMs = nowMs;
  }
  return ledger.startedAtMs;
}

export function shiftStartMs(): number | null {
  return ledger.startedAtMs;
}

export function acknowledgeHold(holdId: string): void {
  ledger.acknowledged.add(holdId);
}

export function acknowledgedHolds(): ReadonlySet<string> {
  return ledger.acknowledged;
}

export function resetShiftLedger(): void {
  ledger.startedAtMs = null;
  ledger.acknowledged = new Set();
}
