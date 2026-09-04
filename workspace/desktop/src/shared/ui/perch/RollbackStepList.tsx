import type * as React from "react";

import {
  ROLLBACK_STATUS,
  ROLLBACK_SUMMARY,
} from "@/features/perch-containment/lib/copy";
import { AdversaryString } from "@/shared/ui/perch/AdversaryString";

/**
 * Exactly five. Only `reversed` restored anything; the other four are ways a
 * step can finish having changed nothing about the world.
 */
export type RollbackStepStatus =
  | "reversed"
  | "simulated"
  | "irreversible"
  | "unsupported"
  | "failed";

export type RollbackStepListProps = {
  steps: readonly {
    label: string;
    status: RollbackStepStatus;
    reason?: string;
  }[];
  /** From the release response's BODY, never the HTTP status. */
  fullyReversed: boolean;
};

/**
 * A read-only outcome list.
 *
 * No undo control lives here. This says what already happened; the release
 * control belongs to the row, and putting one here would offer to re-run an
 * inverse against a record of a past run.
 */
export function RollbackStepList({
  steps,
  fullyReversed,
}: RollbackStepListProps): React.ReactElement {
  const counts = new Map<RollbackStepStatus, number>();
  for (const step of steps) {
    counts.set(step.status, (counts.get(step.status) ?? 0) + 1);
  }
  const breakdown = [...counts.entries()]
    .map(
      ([status, n]) =>
        `${n} ${ROLLBACK_STATUS[status as RollbackStepStatus].label}`,
    )
    .join(", ");
  const reversed = steps.filter((step) => step.status === "reversed").length;
  return (
    <div className="flex flex-col gap-1">
      <ol className="flex flex-col gap-1">
        {steps.map((step, index) => (
          <li
            // The label and status together identify the step; a bare index
            // would reorder the DOM under a list that only ever appends.
            key={`${step.label}:${step.status}:${step.reason ?? ""}`}
            data-testid={`perch-rollback-step-${index}`}
            data-perch-rollback-status={step.status}
            className="flex items-baseline gap-2 text-sm"
          >
            <span className="font-medium text-[hsl(var(--perch-foreground))]">
              {ROLLBACK_STATUS[step.status].label}
            </span>
            <span className="font-mono text-xs text-[hsl(var(--perch-foreground-muted))]">
              {step.label}
            </span>
            {step.reason ? (
              <AdversaryString
                field="reason"
                value={step.reason}
                layout="inline"
                className="text-xs"
              />
            ) : null}
          </li>
        ))}
      </ol>
      <p
        data-testid="perch-rollback-fully-reversed"
        data-perch-fully-reversed={String(fullyReversed)}
        className="text-xs text-[hsl(var(--perch-foreground-muted))]"
      >
        {fullyReversed
          ? ROLLBACK_SUMMARY.fullyReversed
          : ROLLBACK_SUMMARY.notFullyReversed
              .replace("{n}", String(reversed))
              .replace("{total}", String(steps.length))
              .replace("{breakdown}", breakdown)}
      </p>
    </div>
  );
}
