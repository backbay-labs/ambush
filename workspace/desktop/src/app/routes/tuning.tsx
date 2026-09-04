import * as React from "react";
import { createFileRoute } from "@tanstack/react-router";

import {
  useFeatureEnabled,
  usePreviewFeatureWarning,
} from "@/shared/features/useFeatureEnabled";
import { ViewLoadingFallback } from "@/shared/ui/ViewLoadingFallback";

const TuningScreen = React.lazy(async () => {
  const module = await import("@/features/perch-policy/ui/TuningScreen");
  return { default: module.TuningScreen };
});

/** Monday 00:00 UTC of the current week, which is what "this week" means here. */
function weekStartMs(nowMs: number): number {
  const d = new Date(nowMs);
  const day = (d.getUTCDay() + 6) % 7;
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - day);
}

export const Route = createFileRoute("/tuning")({
  component: TuningRouteComponent,
});

function TuningRouteComponent() {
  const enabled = useFeatureEnabled("perch");
  usePreviewFeatureWarning("perch");
  if (!enabled) {
    return null;
  }
  return (
    <React.Suspense fallback={<ViewLoadingFallback kind="containments" />}>
      <TuningScreen
        recommendations={[]}
        incidents={[]}
        weekStartMs={weekStartMs(Date.now())}
      />
    </React.Suspense>
  );
}
