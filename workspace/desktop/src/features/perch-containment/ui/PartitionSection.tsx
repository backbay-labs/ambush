import type * as React from "react";

export type PartitionFacts = {
  partitionState: "healthy" | "degraded" | "partitioned" | "healing";
  activeContingencyLeases: number;
  unauthorizedPartitionActions: number;
  lastReconciliationReportId: string | null;
};

/**
 * What happened while governance could not be reached.
 *
 * Renders ONLY while the partition state is not healthy. A section that was
 * always present with zeroes would train an operator to skip it, and this is
 * the one place the console reports actions taken without authorization.
 *
 * Two numbers that look alike and are not. A contingency lease redeemed during
 * a partition carries no governance receipt BY DESIGN — `UNATTESTED` on one is
 * expected and the note says so, because an operator who read it as a fault
 * would go looking for a break that is not there. An unauthorized partition
 * action is the opposite: it is the fault, and it renders in the destructive
 * register with no rounding, because "about a dozen" is not a thing to say
 * about actions taken without authority.
 */
export function PartitionSection({
  partitionState,
  activeContingencyLeases,
  unauthorizedPartitionActions,
  lastReconciliationReportId,
}: PartitionFacts): React.ReactElement | null {
  if (partitionState === "healthy") return null;

  return (
    <section
      data-testid="perch-partition-section"
      data-partition-state={partitionState}
      className="mt-4 rounded-md border border-border p-3"
    >
      <h3 className="text-sm font-medium">
        {partitionState === "healing"
          ? "HEALING — governance is reconciling partition-era activity"
          : `GOVERNANCE ${partitionState.toUpperCase()}`}
      </h3>

      <p className="mt-2 text-sm">
        <span>contingency leases redeemed during the partition</span>{" "}
        <span className="tabular-nums">{activeContingencyLeases}</span>
      </p>
      <p className="text-xs text-muted-foreground">
        these carry no governance receipt by design — UNATTESTED here is
        expected, not a fault
      </p>

      <p
        data-testid="perch-unauthorized-actions"
        data-perch-register="destructive"
        className="mt-2 text-sm"
      >
        <span>unauthorized partition actions recorded</span>{" "}
        <span className="tabular-nums">{unauthorizedPartitionActions}</span>
      </p>

      <p className="mt-2 text-xs text-muted-foreground">
        {lastReconciliationReportId === null
          ? "no reconciliation report yet — the reconcile has not run, which is not the same as a reconcile that found nothing"
          : `reconciliation report  ${lastReconciliationReportId}`}
      </p>
    </section>
  );
}
