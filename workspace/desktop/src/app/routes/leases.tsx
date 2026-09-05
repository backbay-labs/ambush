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

/**
 * `?lease=cl_…` focuses one row.
 *
 * Declared because the omnibox's `release containment` command navigates here
 * with the lease in focus rather than releasing anything itself. Without the
 * param the command's stated consequence — "opens Containments with the row
 * focused" — would be a claim the code does not honour.
 *
 * Validated to the containment-lease shape: `cap-` names a capability lease,
 * a different object with a different lifetime, and focusing one because it
 * looked like the other is a confusion this route can refuse cheaply.
 */
type LeasesRouteSearch = { lease?: string };

function validateLeasesSearch(
  search: Record<string, unknown>,
): LeasesRouteSearch {
  const lease = search.lease;
  return typeof lease === "string" && /^cl_[A-Za-z0-9_-]{4,}$/.test(lease)
    ? { lease }
    : {};
}

export const Route = createFileRoute("/leases")({
  validateSearch: validateLeasesSearch,
  component: LeasesRouteComponent,
});

function LeasesRouteComponent() {
  const enabled = useFeatureEnabled("perch");
  const { lease } = Route.useSearch();
  usePreviewFeatureWarning("perch");
  if (!enabled) {
    return null;
  }
  return (
    <React.Suspense fallback={<ViewLoadingFallback kind="containments" />}>
      <ContainmentBoard focusLeaseId={lease ?? null} />
    </React.Suspense>
  );
}
