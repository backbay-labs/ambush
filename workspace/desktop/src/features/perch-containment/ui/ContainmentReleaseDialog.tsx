import type * as React from "react";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/shared/ui/alert-dialog";
import { RollbackStepList } from "@/shared/ui/perch/RollbackStepList";
import type { RollbackStepStatus } from "@/shared/ui/perch/RollbackStepList";

import { CONTAINMENT } from "../lib/copy";
import type { ReleaseOutcome } from "../lib/containmentList";

/** Substitute `{name}`; an unknown key stays visible rather than blanking. */
function fill(template: string, values: Record<string, string>): string {
  return template.replace(/\{(\w+)\}/g, (whole, key: string) =>
    key in values ? values[key] : whole,
  );
}

export type ContainmentReleaseDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  host: string;
  inverseKind: string;
  target: string;
  /** `null` while the operator has not confirmed, or the write is in flight. */
  outcome: ReleaseOutcome | null;
  sending: boolean;
  onConfirm: () => void;
};

/**
 * Asking the daemon to release a containment early.
 *
 * The settled branch is where this surface earns its keep. `lease_closed:
 * false` on an HTTP 200 is the outcome that must never render as success: the
 * daemon answered, the inverse failed, and the host is still contained. It
 * lands in the error register REGARDLESS of status, because the status says
 * the request was handled and says nothing about whether anything was undone.
 *
 * `UNATTESTED` is a third state again, and not a failure: the release
 * proceeded without a governor's co-signature because refusing to undo a
 * containment over a bookkeeping failure inverts the safety argument. The
 * receipt says so, and so does this.
 */
export function ContainmentReleaseDialog({
  open,
  onOpenChange,
  host,
  inverseKind,
  target,
  outcome,
  sending,
  onConfirm,
}: ContainmentReleaseDialogProps): React.ReactElement {
  const notClosed = outcome !== null && outcome.leaseClosed === false;
  const unattested =
    outcome !== null &&
    outcome.attestationVerified === false &&
    (outcome.attestationError ?? "").toLowerCase().includes("unattested");

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent data-testid="perch-release-dialog">
        <AlertDialogHeader>
          <AlertDialogTitle>
            {fill(CONTAINMENT.releaseConfirmTitle, { host })}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {fill(CONTAINMENT.releaseConfirmBody, { inverseKind, target })}
          </AlertDialogDescription>
        </AlertDialogHeader>

        {outcome !== null ? (
          <div className="space-y-2">
            {notClosed ? (
              <p
                data-testid="perch-release-not-closed"
                data-perch-register="error"
                role="alert"
                className="text-sm"
              >
                {CONTAINMENT.releasedNotClosed}
              </p>
            ) : (
              <p data-testid="perch-release-closed" className="text-sm">
                {fill(CONTAINMENT.releasedClosed, {
                  // `null` is not `false`: the daemon did not say, and saying
                  // "false" would be this console answering for it.
                  fullyReversed:
                    outcome.fullyReversed === null
                      ? "not reported"
                      : String(outcome.fullyReversed),
                })}
              </p>
            )}
            {unattested ? (
              <p data-testid="perch-release-unattested" className="text-sm">
                {CONTAINMENT.releasedUnattested}
              </p>
            ) : null}
            <RollbackStepList
              steps={outcome.steps.map((step) => ({
                label: step.label,
                status: step.status as RollbackStepStatus,
                reason: step.reason,
              }))}
              fullyReversed={outcome.fullyReversed}
            />
          </div>
        ) : null}

        <AlertDialogFooter>
          <AlertDialogCancel>Close</AlertDialogCancel>
          {outcome === null ? (
            <AlertDialogAction
              variant="outline"
              data-testid="perch-release-confirm"
              disabled={sending}
              onClick={(event) => {
                // The dialog stays open: the settled branch above is the whole
                // point, and a dialog that closed on confirm would hide the
                // one outcome an operator must not miss.
                event.preventDefault();
                onConfirm();
              }}
            >
              {CONTAINMENT.releaseConfirmCta}
            </AlertDialogAction>
          ) : null}
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
