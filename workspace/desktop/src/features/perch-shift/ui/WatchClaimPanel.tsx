import type * as React from "react";

import { fillHandoff, HANDOFF } from "../lib/handoffCopy";
import {
  claimState,
  type WatchClaim,
  type WatchClaimState,
} from "../lib/watchClaim";
import { WATCH_CLAIM_SOURCE_DECIDED } from "../useWatchClaim";

type WatchClaimPanelProps = {
  claim: WatchClaim | null;
  nowMs: number;
};

const hhmm = (ms: number) => {
  const d = new Date(ms);
  return `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
};

const ago = (ms: number) => {
  const hours = Math.floor(ms / 3_600_000);
  return hours >= 1 ? `${hours}h` : `${Math.floor(ms / 60_000)}m`;
};

function headline(
  state: WatchClaimState,
  claim: WatchClaim | null,
  nowMs: number,
): string {
  if (state === "none" || claim === null) return HANDOFF.noClaim.title;
  if (state === "held") {
    return fillHandoff(HANDOFF.claimHeld, {
      holder: claim.holderLabel,
      since: hhmm(claim.sinceMs),
    });
  }
  return fillHandoff(HANDOFF.claimStale, {
    holder: claim.holderLabel,
    ago: ago(nowMs - claim.sinceMs),
  });
}

/**
 * Who holds the watch.
 *
 * The panel's whole job is to stop an operator concluding that a claimed watch
 * narrows delivery. Both standing sentences say so, in every state, including
 * the one where a claim is held — that is the state in which the misreading is
 * most tempting and most expensive.
 *
 * The take control is ABSENT, not disabled, while the claim's record has no
 * decided source: a disabled button asserts the action exists.
 */
export function WatchClaimPanel({
  claim,
  nowMs,
}: WatchClaimPanelProps): React.ReactElement {
  const state = claimState(claim, nowMs);
  return (
    <section
      data-testid="perch-watch-claim"
      data-claim-state={state}
      className="rounded-md border border-border p-4"
    >
      <h3 className="text-sm font-medium">{headline(state, claim, nowMs)}</h3>
      {state === "none" ? (
        <p className="mt-1 text-sm text-muted-foreground">
          {HANDOFF.noClaim.body}
        </p>
      ) : null}
      <p className="mt-2 text-xs text-muted-foreground">
        {HANDOFF.claimDoesNot}
      </p>
      <p className="mt-1 text-xs text-muted-foreground">{HANDOFF.takeover}</p>
      {WATCH_CLAIM_SOURCE_DECIDED ? (
        <button
          type="button"
          data-testid="perch-take-watch"
          className="mt-3 rounded border border-border px-2 py-1 text-sm"
        >
          {HANDOFF.takeCta}
        </button>
      ) : (
        <p
          data-testid="perch-watch-claim-undecided"
          className="mt-3 text-xs text-muted-foreground"
        >
          {HANDOFF.claimUndecided}
        </p>
      )}
    </section>
  );
}
