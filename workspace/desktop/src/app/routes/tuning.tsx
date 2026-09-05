import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import * as React from "react";

import { perchKeys } from "@/shared/api/perchKeys";
import {
  type TuningIncident,
  tuningIncidentFrom,
} from "@/features/perch-policy/lib/tuningProvenance";
import {
  type PerchIncidentRead,
  type PerchIncidentSummary,
  type PerchOperatorStatus,
  perchGetIncident,
  perchListIncidents,
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
  // On demand only: the report changes when verdicts do, not by the second.
  const status = useQuery<PerchOperatorStatus>({
    queryKey: perchKeys.operatorStatus(),
    queryFn: () => perchOperatorStatus(),
    enabled,
    staleTime: 60_000,
  });
  // The verdicts behind the provenance line: the first page of incidents,
  // then each incident's persisted measurements through the perch read.
  const page = useQuery<readonly PerchIncidentSummary[]>({
    queryKey: perchKeys.incidentsPage(),
    queryFn: () => perchListIncidents(50),
    enabled,
    staleTime: 60_000,
  });
  const ids = React.useMemo(
    () => (page.data ?? []).map((row) => row.incident_id).sort(),
    [page.data],
  );
  const incidents = useQuery<readonly TuningIncident[]>({
    queryKey: perchKeys.incident(`page:${ids.join(",")}`),
    queryFn: async () => {
      const reads = await Promise.all(ids.map((id) => perchGetIncident(id)));
      return reads
        .filter((read): read is PerchIncidentRead => read !== null)
        .map(tuningIncidentFrom);
    },
    enabled: enabled && page.data !== undefined,
    staleTime: 60_000,
  });
  if (!enabled) {
    return null;
  }
  return (
    <React.Suspense fallback={<ViewLoadingFallback kind="containments" />}>
      <TuningScreen
        status={status.data ?? null}
        incidents={incidents.data ?? null}
        weekStartMs={weekStartMs(Date.now())}
      />
    </React.Suspense>
  );
}
