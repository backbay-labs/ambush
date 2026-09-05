import * as React from "react";
import { createFileRoute } from "@tanstack/react-router";

import {
  useFeatureEnabled,
  usePreviewFeatureWarning,
} from "@/shared/features/useFeatureEnabled";
import { ViewLoadingFallback } from "@/shared/ui/ViewLoadingFallback";

const LaneScreen = React.lazy(async () => {
  const module = await import("@/features/perch-evidence/ui/LaneScreen");
  return { default: module.LaneScreen };
});

/**
 * Thresholds until the daemon's per-class policy reaches the console. Labelled
 * in the screen as the served numbers they will become; a rule drawn from
 * these is never presented as configured.
 */
const FALLBACK_POLICY = { alertThreshold: 2, incidentThreshold: 5 };

export const Route = createFileRoute("/lanes/$laneId")({
  component: LaneRouteComponent,
});

function LaneRouteComponent() {
  const { laneId } = Route.useParams();
  const enabled = useFeatureEnabled("perch");
  usePreviewFeatureWarning("perch");
  if (!enabled) {
    return null;
  }
  return (
    <React.Suspense fallback={<ViewLoadingFallback kind="containments" />}>
      <LaneScreen
        laneId={laneId}
        threatClass={laneId}
        policy={FALLBACK_POLICY}
      />
    </React.Suspense>
  );
}
