// Whether any mounted surface is reading the 26xxx telemetry frames.
//
// The `telemetry` REQ is one of the seven (`perchSubscriptions.ts` §3) and it
// is declared by SEVERAL features at once — the governance strip, the
// Watchfloor, a lane header, the containment board's partition section. None of
// them may open a REQ of its own (the inventory is closed and the frame budget
// is global), and none of them can know whether one of the others is also
// mounted. So the answer is a refcount here, and the subscription manager reads
// it while it builds the inventory.
//
// A mount count rather than a boolean, for the reason every refcount exists: a
// lane and the strip are mounted together far more often than either is mounted
// alone, and a boolean set by whichever unmounted last would tear the REQ down
// underneath the one still rendering.
//
// This module knows nothing about the manager. It publishes a change; the
// manager subscribes and schedules its own sync. That direction is deliberate —
// the reverse would be an import cycle between the two files that most need to
// stay readable.
//
// Gate-line budget: 1000 (src/shared/api is a governed root).

import * as React from "react";

let consumers = 0;
const listeners = new Set<() => void>();

function publish(): void {
  for (const listener of listeners) listener();
}

/** True while at least one telemetry consumer is mounted. */
export function perchTelemetryWanted(): boolean {
  return consumers > 0;
}

/**
 * Take a telemetry consumer's claim, returning the release.
 *
 * The release is idempotent and floors the count at zero, which is what makes
 * a community switch survivable: `runResetters` clears this store and React
 * unmounts the old subtree AFTERWARDS, so the resetter is always followed by
 * unmounts for consumers this count has already forgotten. Without the floor
 * those would drive it negative and the next community's first consumer would
 * leave it at zero — the telemetry REQ silently never opening again.
 */
export function acquirePerchTelemetryConsumer(): () => void {
  consumers += 1;
  publish();
  let released = false;
  return () => {
    if (released) return;
    released = true;
    if (consumers === 0) return;
    consumers -= 1;
    publish();
  };
}

/**
 * Declare the calling surface a telemetry consumer for as long as it is
 * rendered. Every surface that reads `getPerchEphemeralSnapshot().telemetry`
 * calls this; a surface that does not, does not get the frames.
 */
export function usePerchTelemetryConsumer(): void {
  React.useEffect(() => acquirePerchTelemetryConsumer(), []);
}

/**
 * Subscribe to any change in the count. Fires on every mount and unmount, not
 * only on the false/true edges: the manager's sync is coalesced per microtask
 * and idempotent, so an extra notification costs nothing, while a missed edge
 * costs the REQ.
 */
export function subscribePerchTelemetryWanted(
  listener: () => void,
): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * Community-switch fence, registered in the typed reset registry
 * (`features/communities/communityScopedRegistry.ts`).
 *
 * The count itself is not community data, but the REQ it opens is: the
 * telemetry frames of one colony's bridge have no meaning on the next one's
 * relay, and the switch tears the whole REQ set down. Resetting here is what
 * stops a stale claim from re-opening it against the wrong socket before the
 * new community's surfaces have mounted and asked for themselves.
 */
export function resetPerchTelemetryWanted(): void {
  if (consumers === 0) return;
  consumers = 0;
  publish();
}
