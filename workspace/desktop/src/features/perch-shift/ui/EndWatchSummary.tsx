import * as React from "react";

import { sendChannelMessage } from "@/shared/api/tauriMessages";

import { fillHandoff, HANDOFF } from "../lib/handoffCopy";
import { publishHandoff } from "../lib/handoffPublish";
import type { ReviewSessionDraft } from "../lib/reviewSession";
import { acknowledgeHold, acknowledgedHolds } from "../lib/shiftLedger";

export type ExpiredUndecidedHold = {
  holdId: string;
  expiredAfterMinutes: number;
};

type EndWatchSummaryProps = {
  draft: ReviewSessionDraft;
  caseChannelIds: string[];
  expiredUndecided: ExpiredUndecidedHold[];
};

type PublishState =
  | { phase: "idle" }
  | { phase: "sending" }
  | { phase: "settled"; published: number; failed: number };

/**
 * The end of a watch.
 *
 * Three rules the surface exists to enforce.
 *
 * Acknowledging an expired-undecided hold does not decide it, does not touch
 * the daemon, and does not reduce the count of expired holds (INV-19). It
 * records that a person read the row. The gate on ending the watch is that
 * every such row has been read — not that the queue is empty, which nothing
 * here can make true.
 *
 * The block renders as its own bytes in a `<pre>`. It is the artifact: the same
 * text goes to every case channel, and restyling it here would mean the thing
 * the operator reviewed and the thing that published were different.
 *
 * And there is no daemon-side shift record to promise (W3-36), so the copy
 * names the case channels and nothing else.
 */
export function EndWatchSummary({
  draft,
  caseChannelIds,
  expiredUndecided,
}: EndWatchSummaryProps): React.ReactElement {
  const [acknowledged, setAcknowledged] = React.useState<ReadonlySet<string>>(
    () => new Set(acknowledgedHolds()),
  );
  const [state, setState] = React.useState<PublishState>({ phase: "idle" });

  const outstanding = expiredUndecided.filter(
    (hold) => !acknowledged.has(hold.holdId),
  ).length;
  const blocked = outstanding > 0;

  const onAcknowledge = React.useCallback((holdId: string) => {
    acknowledgeHold(holdId);
    setAcknowledged(new Set(acknowledgedHolds()));
  }, []);

  const onEndWatch = React.useCallback(async () => {
    setState({ phase: "sending" });
    const outcome = await publishHandoff(
      caseChannelIds,
      draft.notes,
      (channelId, content) => sendChannelMessage(channelId, content),
    );
    setState({
      phase: "settled",
      published: outcome.published.length,
      failed: outcome.failed.length,
    });
  }, [caseChannelIds, draft.notes]);

  return (
    <section data-testid="perch-end-watch" className="mt-4">
      <pre
        data-testid="perch-end-watch-block"
        className="overflow-x-auto rounded-md border border-border p-3 text-sm font-mono"
      >
        {draft.notes}
      </pre>
      <p className="mt-2 text-xs text-muted-foreground">
        {HANDOFF.noDaemonRecord}
      </p>

      {expiredUndecided.length > 0 ? (
        <div className="mt-3">
          <p data-testid="perch-end-watch-blocked" className="text-sm">
            {fillHandoff(HANDOFF.blocked, { n: expiredUndecided.length })}
          </p>
          <ul className="mt-2 space-y-1">
            {expiredUndecided.map((hold) => (
              <li
                key={hold.holdId}
                data-testid={`perch-handoff-ack-${hold.holdId}`}
                data-acknowledged={acknowledged.has(hold.holdId) ? "1" : "0"}
                className="flex items-center justify-between gap-3 text-sm"
              >
                <span>
                  {fillHandoff(HANDOFF.ackRow, {
                    minutes: hold.expiredAfterMinutes,
                  })}
                </span>
                <button
                  type="button"
                  className="rounded border border-border px-2 py-1 text-xs"
                  disabled={acknowledged.has(hold.holdId)}
                  onClick={() => onAcknowledge(hold.holdId)}
                >
                  {HANDOFF.ackCta}
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <button
        type="button"
        data-testid="perch-end-watch-cta"
        className="mt-3 rounded border border-border px-3 py-1 text-sm"
        disabled={blocked || state.phase === "sending"}
        onClick={() => {
          void onEndWatch();
        }}
      >
        {HANDOFF.endCta}
      </button>

      {state.phase === "settled" ? (
        <p data-testid="perch-end-watch-result" className="mt-2 text-sm">
          {state.failed === 0
            ? fillHandoff(HANDOFF.published, { n: state.published })
            : fillHandoff(HANDOFF.publishFailed, {
                published: state.published,
                n: state.published + state.failed,
                failed: state.failed,
              })}
        </p>
      ) : null}
    </section>
  );
}
