import * as React from "react";

import {
  useContainmentsQuery,
  useReleaseContainment,
} from "@/features/perch-containment/hooks";
import { CONTAINMENT } from "@/features/perch-containment/lib/copy";
import { useLeaseClock } from "@/features/perch-containment/useLeaseClock";
import { RollbackStepList } from "@/shared/ui/perch/RollbackStepList";
import type { RollbackStepStatus } from "@/shared/ui/perch/RollbackStepList";

import { ContainmentRow } from "./ContainmentRow";

/**
 * S6, `/leases`. Every containment the daemon still holds open.
 *
 * The board distinguishes three absences that look alike and mean different
 * things: no store configured (a setting), no open containments (the world is
 * clear), and an unreachable daemon (rows still readable, release withheld).
 * Collapsing any two of them would tell an operator the world is clear when
 * the console simply cannot see it.
 */
export function ContainmentBoard(): React.ReactElement {
  const nowMs = useLeaseClock();
  const query = useContainmentsQuery();
  const release = useReleaseContainment();
  const [released, setReleased] = React.useState<string | null>(null);

  const daemonReachable = !query.isError;
  const leases = query.data?.leases ?? [];
  const noStore =
    query.isError && /lease store/i.test(String(query.error?.message ?? ""));

  const onRelease = React.useCallback(
    (leaseId: string) => {
      setReleased(leaseId);
      release.mutate(leaseId);
    },
    [release.mutate],
  );

  const outcome = release.data;
  return (
    <section
      data-testid="perch-containments"
      className="flex flex-col gap-3 p-4"
    >
      <h1 className="text-base font-medium text-[hsl(var(--perch-foreground))]">
        Containments
      </h1>

      {query.isPending ? (
        <p
          data-testid="perch-containments-loading"
          className="text-sm text-[hsl(var(--perch-foreground-muted))]"
        >
          Reading the daemon's containment lease store…
        </p>
      ) : null}

      {noStore ? (
        <div
          data-testid="perch-containments-no-store"
          role="status"
          className="flex flex-col gap-1"
        >
          <p className="text-sm font-medium text-[hsl(var(--perch-foreground))]">
            {CONTAINMENT.noStore.title}
          </p>
          <p className="text-sm text-[hsl(var(--perch-foreground-muted))]">
            {CONTAINMENT.noStore.body}
          </p>
        </div>
      ) : null}

      {query.isError && !noStore ? (
        <p
          data-testid="perch-containments-daemon-unreachable"
          role="alert"
          className="text-sm text-[hsl(var(--perch-foreground))]"
        >
          {CONTAINMENT.daemonDownOpen.replace(
            "{expiresAt}",
            "each lease's own expiry",
          )}
        </p>
      ) : null}

      {!query.isPending && !query.isError && leases.length === 0 ? (
        <div
          data-testid="perch-containments-empty"
          className="flex flex-col gap-1"
        >
          <p className="text-sm font-medium text-[hsl(var(--perch-foreground))]">
            {CONTAINMENT.none.title}
          </p>
          <p className="text-sm text-[hsl(var(--perch-foreground-muted))]">
            {CONTAINMENT.none.body.replace("{n}", String(0))}
          </p>
        </div>
      ) : null}

      {leases.length > 0 ? (
        <table className="w-full border-collapse text-left">
          <thead>
            <tr className="text-xs uppercase tracking-wide text-[hsl(var(--perch-foreground-muted))]">
              <th className="px-3 py-2 font-normal">Action</th>
              <th className="px-3 py-2 font-normal">Scope</th>
              <th className="px-3 py-2 font-normal">Remaining</th>
              <th className="px-3 py-2 font-normal">If you undo</th>
              <th className="px-3 py-2 font-normal">Release</th>
            </tr>
          </thead>
          <tbody>
            {leases.map((lease) => (
              <ContainmentRow
                key={lease.leaseId}
                lease={lease}
                nowMs={nowMs}
                daemonReachable={daemonReachable}
                onRelease={onRelease}
              />
            ))}
          </tbody>
        </table>
      ) : null}

      {outcome && released ? (
        <div
          data-testid="perch-containment-release-outcome"
          data-perch-register={
            outcome.leaseClosed === false ? "error" : "ordinary"
          }
          role={outcome.leaseClosed === false ? "alert" : "status"}
          className="flex flex-col gap-1 border-l-4 border-[hsl(var(--perch-border-strong))] px-3 py-2"
        >
          <p className="text-sm text-[hsl(var(--perch-foreground))]">
            {outcome.leaseClosed === false
              ? CONTAINMENT.releasedNotClosed
              : outcome.attestationVerified === false
                ? CONTAINMENT.releasedUnattested
                : CONTAINMENT.releasedClosed.replace(
                    "{fullyReversed}",
                    String(outcome.fullyReversed ?? "unreported"),
                  )}
          </p>
          <RollbackStepList
            steps={outcome.steps.map((step) => ({
              label: step.label,
              status: step.status as RollbackStepStatus,
              ...(step.reason ? { reason: step.reason } : {}),
            }))}
            fullyReversed={outcome.fullyReversed === true}
          />
        </div>
      ) : null}
    </section>
  );
}
