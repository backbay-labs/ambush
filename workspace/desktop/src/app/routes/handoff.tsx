import * as React from "react";
import { createFileRoute } from "@tanstack/react-router";

import {
  useFeatureEnabled,
  usePreviewFeatureWarning,
} from "@/shared/features/useFeatureEnabled";
import { ViewLoadingFallback } from "@/shared/ui/ViewLoadingFallback";

const HandoffScreen = React.lazy(async () => {
  const module = await import("@/features/perch-shift/ui/HandoffScreen");
  return { default: module.HandoffScreen };
});

export const Route = createFileRoute("/handoff")({
  component: HandoffRouteComponent,
});

function HandoffRouteComponent() {
  const enabled = useFeatureEnabled("perch");
  usePreviewFeatureWarning("perch");
  if (!enabled) {
    return null;
  }
  return (
    <React.Suspense fallback={<ViewLoadingFallback kind="containments" />}>
      <HandoffScreen />
    </React.Suspense>
  );
}
