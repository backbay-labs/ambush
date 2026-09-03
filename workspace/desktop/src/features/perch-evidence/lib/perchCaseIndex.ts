import { useCallback, useSyncExternalStore } from "react";

/** The case and incident the daemon minted when a finding was promoted. */
export type PerchCaseRef = {
  readonly caseId: string;
  readonly incidentId: string;
};

const cases = new Map<string, PerchCaseRef>();
const listeners = new Set<() => void>();

function emit(): void {
  for (const listener of listeners) listener();
}

/** Subscribe to any index change. Returns the unsubscribe function. */
export function subscribePerchCaseIndex(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * Remember which case a finding was promoted into. The daemon mints both
 * ids (W3-14); the console only records the answer so the finding card can
 * link to its case. An identical re-remember is silent.
 */
export function rememberCase(findingId: string, ref: PerchCaseRef): void {
  const existing = cases.get(findingId);
  if (
    existing &&
    existing.caseId === ref.caseId &&
    existing.incidentId === ref.incidentId
  ) {
    return;
  }
  cases.set(
    findingId,
    Object.freeze({ caseId: ref.caseId, incidentId: ref.incidentId }),
  );
  emit();
}

/** The case a finding was promoted into, or null when it has not been. */
export function caseFor(findingId: string): PerchCaseRef | null {
  return cases.get(findingId) ?? null;
}

const getServerSnapshot = (): PerchCaseRef | null => null;

/** The case a finding was promoted into, for React. */
export function useCaseFor(findingId: string): PerchCaseRef | null {
  const getSnapshot = useCallback(() => caseFor(findingId), [findingId]);
  return useSyncExternalStore(
    subscribePerchCaseIndex,
    getSnapshot,
    getServerSnapshot,
  );
}

/** Community-switch fence. Registered in the typed reset registry. */
export function resetPerchCaseIndex(): void {
  cases.clear();
  emit();
}
