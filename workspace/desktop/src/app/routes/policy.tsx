import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import * as React from "react";
import { perchKeys } from "@/shared/api/perchKeys";
import { type PerchPolicyResponse, perchPolicy } from "@/shared/api/tauriPerch";

import {
  useFeatureEnabled,
  usePreviewFeatureWarning,
} from "@/shared/features/useFeatureEnabled";
import { ViewLoadingFallback } from "@/shared/ui/ViewLoadingFallback";

const PolicyScreen = React.lazy(async () => {
  const module = await import("@/features/perch-policy/ui/PolicyScreen");
  return { default: module.PolicyScreen };
});

export const Route = createFileRoute("/policy")({
  component: PolicyRouteComponent,
});

function PolicyRouteComponent() {
  const enabled = useFeatureEnabled("perch");
  usePreviewFeatureWarning("perch");
  const policy = useQuery<PerchPolicyResponse>({
    queryKey: perchKeys.policy(null),
    queryFn: () => perchPolicy(),
    enabled,
    staleTime: 60_000,
  });
  if (!enabled) {
    return null;
  }
  return (
    <React.Suspense fallback={<ViewLoadingFallback kind="containments" />}>
      <PolicyScreen policy={policy.data ?? null} />
    </React.Suspense>
  );
}
