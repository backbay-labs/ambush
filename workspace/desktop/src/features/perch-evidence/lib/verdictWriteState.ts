import { useCallback, useSyncExternalStore } from "react";

/**
 * Where one finding verdict is on its two-leg path. Governance writes are
 * never optimistic (14-CLIENT-ARCHITECTURE.md §4.4): the phases render
 * distinctly, and `recorded` — the relay accepted the signed intent card,
 * the daemon has not answered — is never collapsed into a checkmark.
 */
export type VerdictWriteState =
  | { phase: "idle" }
  | { phase: "sending" }
  | { phase: "recorded"; atMs: number }
  | { phase: "acknowledged"; atMs: number; feedbackId: string }
  | { phase: "daemon-unreachable"; reason: string }
  | { phase: "not-yet-correlated" }
  | { phase: "failed"; reason: string };

const IDLE: VerdictWriteState = Object.freeze({ phase: "idle" } as const);
const states = new Map<string, VerdictWriteState>();
const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of listeners) listener();
}

/** Subscribe to any write-state change. Returns the unsubscribe function. */
export function subscribeVerdictWriteStates(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * The write state of one finding. Unknown findings read the same frozen
 * idle object every time, so a row that has never been acted on is
 * reference-stable.
 */
export function getVerdictWriteState(findingId: string): VerdictWriteState {
  return states.get(findingId) ?? IDLE;
}

/** Record the write state of one finding and notify subscribers. */
export function setVerdictWriteState(
  findingId: string,
  state: VerdictWriteState,
): void {
  if (state.phase === "idle") {
    states.delete(findingId);
  } else {
    states.set(findingId, Object.freeze({ ...state }));
  }
  emit();
}

const getServerSnapshot = (): VerdictWriteState => IDLE;

/** The write state of one finding, for React. */
export function useVerdictWriteState(findingId: string): VerdictWriteState {
  const getSnapshot = useCallback(
    () => getVerdictWriteState(findingId),
    [findingId],
  );
  return useSyncExternalStore(
    subscribeVerdictWriteStates,
    getSnapshot,
    getServerSnapshot,
  );
}

/** Community-switch fence. Registered in the typed reset registry. */
export function resetPerchWriteStates(): void {
  states.clear();
  emit();
}

/**
 * The six literals a write state may render. Nothing else reaches the screen
 * for this row: a phrase not in this table is a phrase nobody reviewed.
 */
export const VERDICT_PHASE_LABEL = Object.freeze({
  sending: "sending",
  recorded: "recorded on Ambush",
  acknowledged: "acknowledged by the daemon",
  "daemon-unreachable": "daemon unreachable — the Ambush record remains",
  "not-yet-correlated": "not yet correlated",
  failed: "failed",
} as const);

/** What each leg says, or null when that leg has nothing to report yet. */
export type VerdictLegLabels = {
  /** The relay write: the operator's signed intent card. */
  readonly ambush: string | null;
  /** The daemon write: the tuning consequence. */
  readonly daemon: string | null;
};

/**
 * Split one write state into its two legs.
 *
 * The whole point of this function is that no leg-2 label can be produced by
 * a leg-1 success. `recorded` — leg 1 landed, the daemon has not answered —
 * says "recorded on Ambush" on the left and "sending" on the right, and there
 * is no state in which the right-hand side reads as done because the
 * left-hand side did. `recordedOnAmbush` is the caller's own fact (it holds
 * the stored leg-1 intent), because two of the phases are reachable both
 * before leg 1 and after it.
 */
export function verdictLegLabels(
  state: VerdictWriteState,
  recordedOnAmbush: boolean,
): VerdictLegLabels {
  switch (state.phase) {
    case "idle":
      return { ambush: null, daemon: null };
    case "sending":
      return { ambush: VERDICT_PHASE_LABEL.sending, daemon: null };
    case "recorded":
      return {
        ambush: VERDICT_PHASE_LABEL.recorded,
        daemon: VERDICT_PHASE_LABEL.sending,
      };
    case "acknowledged":
      return {
        ambush: VERDICT_PHASE_LABEL.recorded,
        daemon: VERDICT_PHASE_LABEL.acknowledged,
      };
    case "daemon-unreachable":
      return {
        ambush: VERDICT_PHASE_LABEL.recorded,
        daemon: VERDICT_PHASE_LABEL["daemon-unreachable"],
      };
    case "not-yet-correlated":
      return {
        ambush: recordedOnAmbush ? VERDICT_PHASE_LABEL.recorded : null,
        daemon: VERDICT_PHASE_LABEL["not-yet-correlated"],
      };
    case "failed":
      return {
        ambush: recordedOnAmbush ? VERDICT_PHASE_LABEL.recorded : null,
        daemon: recordedOnAmbush ? VERDICT_PHASE_LABEL.failed : null,
      };
  }
}

/**
 * Whether the daemon leg may be re-sent. Only leg 2 is ever retried, and only
 * when leg 1 left a record to retry against: a `failed` row with no Ambush
 * record failed before anything was published, and re-sending nothing is not
 * a retry.
 */
export function isDaemonLegRetryable(
  state: VerdictWriteState,
  recordedOnAmbush: boolean,
): boolean {
  if (!recordedOnAmbush) return false;
  return (
    state.phase === "daemon-unreachable" ||
    state.phase === "not-yet-correlated" ||
    state.phase === "failed"
  );
}
