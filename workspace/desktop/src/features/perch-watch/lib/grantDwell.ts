// The dwell gate: a grant cannot be recorded until the blast radius has been
// FULLY VISIBLE for a continuous total of 1.5 seconds.
//
// The property that matters is what the gate refuses, not what it allows.
// Wall-clock time is not dwell: a control that started a timer when the pane
// opened would pass every happy-path test and would also let an operator grant
// a host isolation without the blast radius ever having been on screen. So
// nothing accrues except between a `visible` and the ticks that follow it, and
// a `hidden` FREEZES the accrual rather than resetting it — an operator who
// looked, scrolled away to check something, and came back has read it, and
// making them start over would teach them to sit still rather than to read.

/** APPENDIX-NORMATIVE.md §2, the strict reading. */
export const GRANT_DWELL_MS = 1500;

/** How much of the blast radius has been read, and whether it is on screen. */
export type DwellState = {
  accruedMs: number;
  visible: boolean;
  /** When the accrual was last credited. `null` while hidden. */
  lastTickMs: number | null;
  /** The hold this accrual belongs to. Dwell is never transferable. */
  holdId: string;
};

export type DwellEvent =
  | { type: "visible" | "hidden"; atMs: number }
  | { type: "tick"; atMs: number }
  | { type: "reset"; holdId: string };

/** A fresh, unread accrual for one hold. */
export function initialDwell(holdId: string): DwellState {
  return { accruedMs: 0, visible: false, lastTickMs: null, holdId };
}

export function dwellReducer(state: DwellState, event: DwellEvent): DwellState {
  switch (event.type) {
    case "reset":
      // A new hold is a new question. Banking the last hold's reading against
      // this one is the single most valuable thing an attacker could get from
      // this reducer.
      return initialDwell(event.holdId);
    case "visible":
      return { ...state, visible: true, lastTickMs: event.atMs };
    case "hidden":
      // `lastTickMs` goes null so the interval spent hidden can never be
      // credited by the next tick.
      return { ...state, visible: false, lastTickMs: null };
    case "tick": {
      if (!state.visible || state.lastTickMs === null) return state;
      // `max(0, …)` because a system clock can step backwards; a negative
      // delta must credit nothing rather than refund accrual.
      const delta = Math.max(0, event.atMs - state.lastTickMs);
      return {
        ...state,
        accruedMs: Math.min(GRANT_DWELL_MS, state.accruedMs + delta),
        lastTickMs: event.atMs,
      };
    }
  }
}

/** Whether the gate is open. The only predicate a control may consult. */
export function dwellComplete(state: DwellState): boolean {
  return state.accruedMs >= GRANT_DWELL_MS;
}

/** The accrual as a percentage, for the control's own progress text. */
export function dwellPercent(state: DwellState): number {
  return Math.floor((state.accruedMs / GRANT_DWELL_MS) * 100);
}
