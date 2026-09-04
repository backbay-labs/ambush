import * as React from "react";
import { createFileRoute } from "@tanstack/react-router";

import {
  useFeatureEnabled,
  usePreviewFeatureWarning,
} from "@/shared/features/useFeatureEnabled";
import { ViewLoadingFallback } from "@/shared/ui/ViewLoadingFallback";

const ContainmentBoard = React.lazy(async () => {
  const module = await import(
    "@/features/perch-containment/ui/ContainmentBoard"
  );
  return { default: module.ContainmentBoard };
});

export const Route = createFileRoute("/leases")({
  component: LeasesRouteComponent,
});

function LeasesRouteComponent() {
  const enabled = useFeatureEnabled("perch");
  usePreviewFeatureWarning("perch");
  if (!enabled) {
    return null;
  }
  return (
    <React.Suspense fallback={<ViewLoadingFallback kind="containments" />}>
      <ContainmentBoard />
    </React.Suspense>
  );
}
