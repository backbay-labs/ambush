import * as React from "react";
import { createFileRoute } from "@tanstack/react-router";

import {
  useFeatureEnabled,
  usePreviewFeatureWarning,
} from "@/shared/features/useFeatureEnabled";
import { ViewLoadingFallback } from "@/shared/ui/ViewLoadingFallback";

const WatchfloorScreen = React.lazy(async () => {
  const module = await import("@/features/perch-policy/ui/WatchfloorScreen");
  return { default: module.WatchfloorScreen };
});

export const Route = createFileRoute("/watch-floor")({
  component: WatchFloorRouteComponent,
});

function WatchFloorRouteComponent() {
  const enabled = useFeatureEnabled("perch");
  usePreviewFeatureWarning("perch");
  if (!enabled) {
    return null;
  }
  return (
    <React.Suspense fallback={<ViewLoadingFallback kind="containments" />}>
      <WatchfloorScreen />
    </React.Suspense>
  );
}
