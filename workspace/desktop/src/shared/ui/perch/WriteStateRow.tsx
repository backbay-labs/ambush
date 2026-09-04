import type * as React from "react";

import {
  isDaemonLegRetryable,
  verdictLegLabels,
  type VerdictWriteState,
} from "@/features/perch-evidence/lib/verdictWriteState";

/**
 * Where a two-legged governance write actually is, rendered as two legs.
 *
 * # Why there is no single status here
 *
 * A verdict is a relay write and a daemon write, and they fail independently.
 * One combined indicator can only be wrong: green after leg 1 claims the
 * detector's behaviour changed when nothing was told to the daemon, and red
 * after leg 2 hides the durable record the operator does have. So this row
 * renders one line per leg, never a checkmark, and never a phrase outside
 * `VERDICT_PHASE_LABEL`.
 *
 * The retry control re-sends LEG 2 ONLY. Re-running leg 1 would put a second
 * signed decision on the relay for one human act, which is why the intent id
 * this row displays is expected to be identical after a retry.
 */
export type WriteStateRowProps = {
  /** The finding this row is about, for its testids. */
  findingId: string;
  state: VerdictWriteState;
  /**
   * Leg 1's published event id, or null when nothing has been published. Its
   * presence is the ONLY thing that entitles this row to say "recorded on
   * Ambush", and it is rendered so a retry can be seen not to change it.
   */
  intentEventId: string | null;
  /** Re-send leg 2 with the stored intent. Absent when nothing is retryable. */
  onRetry?: () => void;
};

function Leg({
  testId,
  term,
  label,
}: {
  testId: string;
  term: string;
  label: string;
}) {
  return (
    <span
      data-testid={testId}
      className="inline-flex items-baseline gap-1 text-2xs text-[hsl(var(--perch-foreground-muted))]"
    >
      <span className="uppercase tracking-wide">{term}</span>
      <span className="text-[hsl(var(--perch-foreground))]">{label}</span>
    </span>
  );
}

/** How much of a refusal's own words this row shows before cutting it off. */
const REASON_MAX = 200;

/**
 * The refusal's own words, when it has any.
 *
 * "failed" on its own tells an operator nothing they can act on. The text
 * comes from the relay or from the daemon rather than from telemetry, and it
 * is rendered as a plain text node and capped, never parsed as markup.
 */
function reasonOf(state: VerdictWriteState): string | null {
  if (state.phase !== "daemon-unreachable" && state.phase !== "failed") {
    return null;
  }
  const reason = state.reason.trim();
  if (!reason) return null;
  return reason.length > REASON_MAX
    ? `${reason.slice(0, REASON_MAX)}…`
    : reason;
}

export function WriteStateRow({
  findingId,
  state,
  intentEventId,
  onRetry,
}: WriteStateRowProps): React.ReactElement | null {
  const recorded = intentEventId !== null;
  const legs = verdictLegLabels(state, recorded);
  if (legs.ambush === null && legs.daemon === null) return null;
  const retryable = isDaemonLegRetryable(state, recorded) && onRetry;
  const reason = reasonOf(state);
  return (
    <div
      data-testid="perch-write-state"
      data-perch-finding-id={findingId}
      data-perch-phase={state.phase}
      data-perch-intent-event-id={intentEventId ?? ""}
      role="status"
      className="mt-1 flex flex-wrap items-baseline gap-x-3 gap-y-1"
    >
      {legs.ambush === null ? null : (
        <Leg
          testId="perch-write-state-ambush"
          term="ambush"
          label={legs.ambush}
        />
      )}
      {legs.daemon === null ? null : (
        <Leg
          testId="perch-write-state-daemon"
          term="daemon"
          label={legs.daemon}
        />
      )}
      {reason === null ? null : (
        <span
          data-testid="perch-write-state-reason"
          className="text-2xs text-[hsl(var(--perch-foreground-muted))]"
        >
          {reason}
        </span>
      )}
      {retryable ? (
        <button
          type="button"
          data-testid="perch-write-state-retry"
          onClick={onRetry}
          className="text-2xs underline text-[hsl(var(--perch-foreground-muted))]"
        >
          Retry the daemon leg
        </button>
      ) : null}
    </div>
  );
}
