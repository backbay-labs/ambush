import * as React from "react";

/**
 * Which case a newly spawned terminal pins to.
 *
 * A store rather than a route read, for two reasons. The pin has to be
 * available at spawn time inside a component that mounts outside any route
 * subtree — the dock is app-level — and reading the router from there couples
 * the terminal to a router being present, which it is not in every mount.
 * More importantly the pin belongs to the case SURFACE, not to the URL: the
 * surface sets it when it mounts and clears it when it unmounts, so a shell's
 * banner can never name a case that is no longer on screen.
 *
 * Module-level and cleared by its own setter, so it needs no community
 * resetter: unmounting the case screen is what clears it, and a community
 * switch unmounts every screen.
 */
export type TerminalCaseScope = { caseId?: string; caseSlug?: string };

const EMPTY: TerminalCaseScope = {};

let snapshot: TerminalCaseScope = EMPTY;
const listeners = new Set<() => void>();

/**
 * Set or clear the pin. Passing `null` clears it.
 *
 * Identity-stable when nothing changed: `useSyncExternalStore` compares
 * snapshots by reference, and publishing a fresh object on every case render
 * would re-render every subscriber for no change.
 */
export function setTerminalCaseScope(scope: TerminalCaseScope | null): void {
  if (!scope?.caseId) {
    if (snapshot === EMPTY) return;
    snapshot = EMPTY;
  } else {
    if (
      snapshot.caseId === scope.caseId &&
      snapshot.caseSlug === scope.caseSlug
    ) {
      return;
    }
    snapshot = { caseId: scope.caseId, caseSlug: scope.caseSlug };
  }
  for (const listener of listeners) listener();
}

export function terminalCaseScope(): TerminalCaseScope {
  return snapshot;
}

export function useTerminalCaseScope(): TerminalCaseScope {
  return React.useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => snapshot,
    () => snapshot,
  );
}

/** Pin the terminal to this case while the calling surface is mounted. */
export function useCaseTerminalPin(
  caseId: string | null,
  caseSlug?: string,
): void {
  React.useEffect(() => {
    if (!caseId) return;
    setTerminalCaseScope({ caseId, caseSlug });
    return () => setTerminalCaseScope(null);
  }, [caseId, caseSlug]);
}
