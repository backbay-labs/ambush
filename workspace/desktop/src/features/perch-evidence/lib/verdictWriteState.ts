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
