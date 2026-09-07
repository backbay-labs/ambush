import * as React from "react";

import { usePerchSubscriptionShell } from "@/shared/api/perchSubscriptionManager";
import { useFeatureEnabled } from "@/shared/features/useFeatureEnabled";

const GovernanceStrip = React.lazy(async () => {
  const module = await import("./GovernanceStrip");
  return { default: module.GovernanceStrip };
});

const PerchNav = React.lazy(async () => {
  const module = await import("./PerchNav");
  return { default: module.PerchNav };
});

/**
 * The one mount point for S14, the surface navigation, and the REQ set.
 *
 * Gated on the feature and lazy, so a build with perch off pays nothing and a
 * build with it on loads the strip once for the whole shell rather than once
 * per route. `Suspense` falls back to nothing rather than a placeholder: a
 * shimmer where the governance state goes would read as a state.
 *
 * The subscription shell is mounted HERE, eagerly, rather than inside the lazy
 * strip below. This slot is present on every perch surface — that is what makes
 * it the right place to hold the REQ set open for a session — and it renders
 * before the strip's chunk has loaded, so the frames the strip is made of are
 * already arriving by the time it paints.
 */
export function PerchGovernanceStripSlot(): React.ReactElement | null {
  const enabled = useFeatureEnabled("perch");
  usePerchSubscriptionShell(enabled);
  if (!enabled) return null;
  return (
    <React.Suspense fallback={null}>
      <GovernanceStrip />
      <PerchNav />
    </React.Suspense>
  );
}
