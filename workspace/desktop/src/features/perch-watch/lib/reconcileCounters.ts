// The reconciler's counters, as a module-level singleton with a fence.
//
// Separate from `useHoldQueue` so the community-switch resetter imports a
// module with no React in it: a resetter that has to import a hook file drags
// the whole query stack into the teardown path.
//
// These are rendered as `data-perch-counter` nodes, not logged. A divergence
// that only ever reached a console log would be a divergence nobody sees.

let reconcileDivergences = 0;

/** Total divergences observed since the last community switch. */
export function readReconcileDivergenceCounter(): number {
  return reconcileDivergences;
}

/**
 * Record the divergences one reconciliation found.
 *
 * Called with the whole reconciliation's count rather than incremented per
 * row, so a re-render that reconciles the same two inputs again does not
 * inflate the number — the caller passes a delta it computed against the
 * previous reconciliation of the same inputs.
 */
export function addReconcileDivergences(delta: number): void {
  if (delta > 0) reconcileDivergences += delta;
}

/**
 * Community-switch fence, registered in the typed reset registry
 * (`features/communities/communityScopedRegistry.ts`). A divergence belongs to
 * the colony whose daemon and relay disagreed; carrying the count into the
 * next colony would attribute one deployment's disagreement to another.
 */
export function resetReconcileDivergenceCounter(): void {
  reconcileDivergences = 0;
}
