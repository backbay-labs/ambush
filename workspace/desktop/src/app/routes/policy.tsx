import * as React from "react";
import { createFileRoute } from "@tanstack/react-router";

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
  if (!enabled) {
    return null;
  }
  return (
    <React.Suspense fallback={<ViewLoadingFallback kind="containments" />}>
      {/* The daemon's rules are not served to the console yet (Task 16's
          route). Until they are, the screen renders an empty rule list, which
          says "no rule matches" rather than inventing a decision. */}
      <PolicyScreen rules={[]} />
    </React.Suspense>
  );
}
