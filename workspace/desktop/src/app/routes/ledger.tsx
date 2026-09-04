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

/**
 * `?q=` seeds the query box.
 *
 * Declared because the omnibox emits a query and this surface owns the search
 * — routing the text here rather than searching in the omnibox is what keeps
 * the console to ONE search path. Without the param the omnibox's query mode
 * would navigate and drop what the operator typed.
 */
type LedgerRouteSearch = { q?: string };

function validateLedgerSearch(
  search: Record<string, unknown>,
): LedgerRouteSearch {
  return typeof search.q === "string" && search.q.length > 0
    ? { q: search.q }
    : {};
}

export const Route = createFileRoute("/ledger")({
  validateSearch: validateLedgerSearch,
  component: LedgerRouteComponent,
});

function LedgerRouteComponent() {
  const enabled = useFeatureEnabled("perch");
  usePreviewFeatureWarning("perch");
  const { q } = Route.useSearch();
  const [rows, setRows] = React.useState<null>(null);
  if (!enabled) {
    return null;
  }
  return (
    <React.Suspense fallback={<ViewLoadingFallback kind="containments" />}>
      {/* `rows: null` until a search runs: "no search has run" and "the record
          is empty" are different claims and the screen makes only the first. */}
      <LedgerScreen
        initialQuery={q ?? ""}
        rows={rows}
        onSearch={() => setRows(null)}
      />
    </React.Suspense>
  );
}
