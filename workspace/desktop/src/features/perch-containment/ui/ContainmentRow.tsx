import type * as React from "react";

import type { ContainmentLeaseView } from "@/features/perch-containment/lib/containmentList";
import { CONTAINMENT } from "@/features/perch-containment/lib/copy";
import { remainingMsAt } from "@/features/perch-containment/lib/containmentState";
import { AdversaryString } from "@/shared/ui/perch/AdversaryString";
import { ContainmentTimer } from "@/shared/ui/perch/ContainmentTimer";

/**
 * Which of the four leased actions can be undone.
 *
 * Twelve destructive actions exist, four take a containment lease, and three
 * of those four have an executable inverse. Naming the rung on the row is the
 * point: an operator deciding whether to wait for the TTL needs to know
 * whether waiting ever ends in restoration.
 */
function undoRung(actionKind: string): string {
  return actionKind === "terminate_user_session"
    ? "irreversible"
    : "executable inverse";
}

export type ContainmentRowProps = {
  /** Deep-linked from `?lease=`. Outlined only; never pre-armed. */
  focused?: boolean;
  lease: ContainmentLeaseView;
  /** The board's single clock. Rows never run their own interval. */
  nowMs: number;
  daemonReachable: boolean;
  onRelease: (leaseId: string) => void;
};

export function ContainmentRow({
  focused = false,
  lease,
  nowMs,
  daemonReachable,
  onRelease,
}: ContainmentRowProps): React.ReactElement {
  // Recomputed from the daemon's own expiry against the board clock, never
  // from a configured TTL: that is what the lease was granted under, not what
  // is left of it.
  const remainingMs = remainingMsAt(lease.expiresAtMs, nowMs);
  const releaseBlocked = !daemonReachable;
  const blockedReason = lease.expired
    ? CONTAINMENT.daemonDownExpired
    : CONTAINMENT.daemonDownOpen.replace(
        "{expiresAt}",
        new Date(lease.expiresAtMs).toLocaleTimeString(),
      );
  return (
    <tr
      data-testid={`perch-containment-row-${lease.leaseId}`}
      data-focused={focused ? "1" : undefined}
      data-perch-lease-id={lease.leaseId}
      className="border-b border-[hsl(var(--perch-border-strong))]"
    >
      <td className="px-3 py-2 align-top">
        <span className="font-mono text-xs text-[hsl(var(--perch-foreground))]">
          {lease.actionKind}
        </span>
      </td>
      <td className="px-3 py-2 align-top">
        <AdversaryString
          field="scope"
          value={lease.scopeValue}
          layout="inline"
        />
      </td>
      <td className="px-3 py-2 align-top">
        <ContainmentTimer
          remainingMs={remainingMs}
          expired={lease.expired}
          expiresAtMs={lease.expiresAtMs}
          daemonReachable={daemonReachable}
        />
      </td>
      <td
        className="px-3 py-2 align-top text-xs text-[hsl(var(--perch-foreground-muted))]"
        data-testid={`perch-containment-undo-${lease.leaseId}`}
      >
        {`${lease.actionKind} → ${undoRung(lease.actionKind)}`}
      </td>
      <td className="px-3 py-2 align-top">
        <button
          type="button"
          data-perch-role="containment-release"
          data-testid={`perch-containment-release-${lease.leaseId}`}
          disabled={releaseBlocked}
          title={releaseBlocked ? blockedReason : undefined}
          onClick={() => onRelease(lease.leaseId)}
          className="rounded border border-[hsl(var(--perch-border-strong))] px-2 py-1 text-xs text-[hsl(var(--perch-foreground))] disabled:opacity-50"
        >
          Release — requires Maintenance scope
        </button>
        {releaseBlocked ? (
          <p
            data-testid={`perch-containment-release-blocked-${lease.leaseId}`}
            className="mt-1 text-xs text-[hsl(var(--perch-foreground-muted))]"
          >
            {blockedReason}
          </p>
        ) : null}
      </td>
    </tr>
  );
}
