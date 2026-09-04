import * as React from "react";
import { useQuery } from "@tanstack/react-query";

import { useContainmentsQuery } from "@/features/perch-containment/hooks";
import { useHoldQueue } from "@/features/perch-watch/useHoldQueue";
import {
  PERCH_FRESHNESS,
  PERCH_NO_RETRY,
  perchKeys,
} from "@/shared/api/perchKeys";
import { perchReviewedFindings } from "@/shared/api/tauriPerch";
import type { PerchReviewedFindingsResponse } from "@/shared/api/tauriPerch";

import { HANDOFF } from "../lib/handoffCopy";
import { composeReviewSession } from "../lib/reviewSession";
import type { ShiftCase } from "../lib/reviewSession";
import { beginShift } from "../lib/shiftLedger";
import {
  caseFromHold,
  containmentsForShift,
  expiredAfterMinutes,
  expiredUndecidedHolds,
} from "../lib/shiftInputs";
import { useWatchClaim } from "../useWatchClaim";

import { EndWatchSummary } from "./EndWatchSummary";
import { WatchClaimPanel } from "./WatchClaimPanel";

/**
 * S8, `/handoff`. What this watch did, and what the next one inherits.
 *
 * The shift start is taken on first mount and never moves, so navigating back
 * here mid-shift does not silently redate the summary to now — which would
 * make the block report a shift that covered nothing.
 *
 * Every number below is read from a source the console already has. The two
 * facts with no source yet — a case's canvas line count and its `## Handoff
 * notes` section — are absent rather than zero (see `shiftInputs.ts`).
 */
export function HandoffScreen(): React.ReactElement {
  const shiftStartMs = React.useMemo(() => beginShift(Date.now()), []);
  const nowMs = Date.now();

  const queue = useHoldQueue();
  const containments = useContainmentsQuery();
  const claim = useWatchClaim();
  const reviewed = useQuery<PerchReviewedFindingsResponse>({
    queryKey: perchKeys.reviewedFindings(shiftStartMs),
    queryFn: () => perchReviewedFindings(shiftStartMs),
    staleTime: PERCH_FRESHNESS.reviewedFindings.staleTime,
    ...PERCH_NO_RETRY,
  });

  const holds = React.useMemo(
    () =>
      (queue.data?.rows ?? []).flatMap((row) =>
        row.kind === "hold" || row.kind === "expired" ? [row.hold] : [],
      ),
    [queue.data],
  );

  const cases = React.useMemo<ShiftCase[]>(() => {
    const seen = new Set<string>();
    return holds.flatMap((hold) => {
      const shiftCase = caseFromHold(hold);
      if (!shiftCase || seen.has(shiftCase.channelId)) return [];
      seen.add(shiftCase.channelId);
      return [shiftCase];
    });
  }, [holds]);

  const expired = React.useMemo(() => expiredUndecidedHolds(holds), [holds]);

  const draft = React.useMemo(
    () =>
      composeReviewSession({
        operator: "you",
        shiftStartMs,
        nowMs,
        cases,
        findings: {
          reviewed: reviewed.data?.reviewed.length ?? 0,
          total: reviewed.data?.window_incident_count ?? 0,
        },
        holds: { expiredUndecided: expired.length },
        containments: containmentsForShift(containments.data?.leases ?? []),
        snoozes: [],
        verdicts: { confirm: 0, dismiss: 0, grant: 0, refuse: 0 },
        promotion: { promoted: 0, suppressed: 0 },
      }),
    [
      shiftStartMs,
      nowMs,
      cases,
      reviewed.data,
      expired.length,
      containments.data,
    ],
  );

  return (
    <section data-testid="perch-handoff" className="p-4">
      <h2 className="text-base font-medium">{HANDOFF.title}</h2>
      <div className="mt-3">
        <WatchClaimPanel claim={claim.data ?? null} nowMs={nowMs} />
      </div>
      <EndWatchSummary
        draft={draft}
        caseChannelIds={cases.map((c) => c.channelId)}
        expiredUndecided={expired.map((hold) => ({
          holdId: hold.hold_id,
          expiredAfterMinutes: expiredAfterMinutes(hold),
        }))}
      />
    </section>
  );
}
