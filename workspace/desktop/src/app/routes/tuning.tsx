import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import * as React from "react";

import { perchKeys } from "@/shared/api/perchKeys";
import {
  type PerchOperatorStatus,
  perchOperatorStatus,
} from "@/shared/api/tauriPerch";
import {
  useFeatureEnabled,
  usePreviewFeatureWarning,
} from "@/shared/features/useFeatureEnabled";
import { ViewLoadingFallback } from "@/shared/ui/ViewLoadingFallback";

const TuningScreen = React.lazy(async () => {
  const module = await import("@/features/perch-policy/ui/TuningScreen");
  return { default: module.TuningScreen };
});

export const Route = createFileRoute("/tuning")({
  component: TuningRouteComponent,
});

function TuningRouteComponent() {
  const enabled = useFeatureEnabled("perch");
  usePreviewFeatureWarning("perch");
  // On demand only: the report changes when verdicts do, not by the second.
  const status = useQuery<PerchOperatorStatus>({
    queryKey: perchKeys.operatorStatus(),
    queryFn: () => perchOperatorStatus(),
    enabled,
    staleTime: 60_000,
  });
  if (!enabled) {
    return null;
  }
  return (
    <React.Suspense fallback={<ViewLoadingFallback kind="containments" />}>
      <TuningScreen status={status.data ?? null} />
    </React.Suspense>
  );
}
