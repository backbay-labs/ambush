import * as React from "react";

import {
  getPerchEphemeralServerSnapshot,
  getPerchEphemeralSnapshot,
  subscribePerchEphemeral,
} from "@/shared/api/perchEphemeralStore";

import type { PartitionFacts } from "./ui/PartitionSection";

/**
 * The governance facts the containment board's partition section reads, from
 * the `26004` frame.
 *
 * An absent frame reports `healthy`, and that is safe HERE and only here: the
 * section renders nothing on `healthy`, so "not told" produces no claim rather
 * than a false all-clear. The governance strip, which must say something in
 * every state, reads `bridge-down` from the same absence.
 */
export function usePartitionFacts(): PartitionFacts {
  const snapshot = React.useSyncExternalStore(
    subscribePerchEphemeral,
    getPerchEphemeralSnapshot,
    getPerchEphemeralServerSnapshot,
  );
  const body = (snapshot.telemetry.get(26004)?.body ?? {}) as Record<
    string,
    unknown
  >;
  const state = body.partition_state;
  return {
    partitionState:
      state === "degraded" || state === "partitioned" || state === "healing"
        ? state
        : "healthy",
    activeContingencyLeases: asCount(body.active_contingency_leases),
    unauthorizedPartitionActions: asCount(body.unauthorized_partition_actions),
    lastReconciliationReportId:
      typeof body.last_reconciliation_report_id === "string"
        ? body.last_reconciliation_report_id
        : null,
  };
}

/** A missing count is zero only because the section shows nothing when healthy. */
function asCount(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}
