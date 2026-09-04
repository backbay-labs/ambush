import * as React from "react";
import { createFileRoute } from "@tanstack/react-router";

import {
  useFeatureEnabled,
  usePreviewFeatureWarning,
} from "@/shared/features/useFeatureEnabled";
import { ViewLoadingFallback } from "@/shared/ui/ViewLoadingFallback";

const LedgerScreen = React.lazy(async () => {
  const module = await import("@/features/perch-shift/ui/LedgerScreen");
  return { default: module.LedgerScreen };
});

export const Route = createFileRoute("/ledger")({
  component: LedgerRouteComponent,
});

function LedgerRouteComponent() {
  const enabled = useFeatureEnabled("perch");
  usePreviewFeatureWarning("perch");
  const [rows, setRows] = React.useState<null>(null);
  if (!enabled) {
    return null;
  }
  return (
    <React.Suspense fallback={<ViewLoadingFallback kind="containments" />}>
      {/* `rows: null` until a search runs: "no search has run" and "the record
          is empty" are different claims and the screen makes only the first. */}
      <LedgerScreen rows={rows} onSearch={() => setRows(null)} />
    </React.Suspense>
  );
}
