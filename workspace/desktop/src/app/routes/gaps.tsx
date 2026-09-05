import * as React from "react";
import { createFileRoute } from "@tanstack/react-router";

import {
  useFeatureEnabled,
  usePreviewFeatureWarning,
} from "@/shared/features/useFeatureEnabled";
import { ViewLoadingFallback } from "@/shared/ui/ViewLoadingFallback";

const GapsScreen = React.lazy(async () => {
  const module = await import("@/features/perch-policy/ui/GapsScreen");
  return { default: module.GapsScreen };
});

export const Route = createFileRoute("/gaps")({
  component: GapsRouteComponent,
});

function GapsRouteComponent() {
  const enabled = useFeatureEnabled("perch");
  usePreviewFeatureWarning("perch");
  if (!enabled) {
    return null;
  }
  return (
    <React.Suspense fallback={<ViewLoadingFallback kind="containments" />}>
      <GapsScreen />
    </React.Suspense>
  );
}
