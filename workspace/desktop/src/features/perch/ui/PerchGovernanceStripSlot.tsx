import * as React from "react";

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
 * The one mount point for S14 and the surface navigation.
 *
 * Gated on the feature and lazy, so a build with perch off pays nothing and a
 * build with it on loads the strip once for the whole shell rather than once
 * per route. `Suspense` falls back to nothing rather than a placeholder: a
 * shimmer where the governance state goes would read as a state.
 */
export function PerchGovernanceStripSlot(): React.ReactElement | null {
  const enabled = useFeatureEnabled("perch");
  if (!enabled) return null;
  return (
    <React.Suspense fallback={null}>
      <GovernanceStrip />
      <PerchNav />
    </React.Suspense>
  );
}
