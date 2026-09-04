import * as React from "react";

import { readPerchCounter } from "@/features/perch-evidence/lib/admittedIssuers";
import { perchUnadmittedFrameCount } from "@/shared/api/perchEphemeralStore";
import { usePerchRelayFeed } from "@/shared/api/perchRelayFeed";

import type { PerchHoldRow } from "../lib/holdRows";
import { readReconcileDivergenceCounter } from "../lib/reconcileCounters";
import {
  PERCH_QUEUE_ORDER,
  queueForFeedItem,
  type PerchQueueId,
} from "../lib/watchQueues";
import { useHoldQueue } from "../useHoldQueue";
import { VerdictQueueRow } from "./VerdictQueueRow";
import { WatchQueueSection } from "./WatchQueueSection";

/**
 * The Watch: four queues over one relay feed and one daemon read.
 *
 * Only the first queue has an authority. HOLDS is reconciled against
 * `GET /v1/response/holds` and renders the daemon's answer; the other three
 * are relay views and are labelled as the nudges they are. That asymmetry is
 * the screen's whole shape, and it is why the daemon's failure does not empty
 * the other three and the relay's failure does not empty HOLDS.
 */
export type WatchScreenProps = {
  /** The signed-in operator, for the surfaces that need to say who is asking. */
  currentPubkey?: string;
  /** Navigate to a case channel. Supplied by the route. */
  onOpenCase?: (caseId: string) => void;
};

function rowKey(row: PerchHoldRow): string {
  return row.kind === "unreconciled" ? row.holdId : row.hold.hold_id;
}

export function WatchScreen({ currentPubkey, onOpenCase }: WatchScreenProps) {
  const queue = useHoldQueue();
  const feed = usePerchRelayFeed();
  const [selected, setSelected] = React.useState<string | null>(null);

  const relayQueues = React.useMemo(() => {
    const buckets = new Map<PerchQueueId, number>([
      ["named-you", 0],
      ["findings", 0],
      ["case-activity", 0],
    ]);
    const items = feed.data?.feed;
    if (!items) return null;
    for (const item of [
      ...items.mentions,
      ...items.needsAction,
      ...items.activity,
      ...items.agentActivity,
    ]) {
      const id = queueForFeedItem(item);
      if (id === "holds") continue;
      buckets.set(id, (buckets.get(id) ?? 0) + 1);
    }
    return buckets;
  }, [feed.data]);

  const rows = queue.data?.rows ?? [];
  const holdCount = queue.status === "ready" ? rows.length : null;
  // Every open hold, and not one of them was ever announced: nobody is
  // configured to receive holds. Said out loud, because a queue full of holds
  // no operator was told about is worse than an empty one. Expired and
  // unreconciled rows are excluded — neither is waiting on a delivery.
  const openRows = rows.filter((row) => row.kind === "hold");
  const undeliverable =
    openRows.length > 0 && openRows.every((row) => !row.noticed);

  return (
    <div
      data-testid="perch-watch"
      data-perch-queue-reconciled={queue.reconciled ? "true" : "false"}
      className="flex h-full flex-col overflow-y-auto bg-[hsl(var(--perch-surface-raised))] text-[hsl(var(--perch-foreground))]"
    >
      <WatchQueueSection
        queue="holds"
        count={holdCount}
        unavailableNote={
          queue.status === "not-configured"
            ? "no daemon is configured, so this console cannot say what is held"
            : `the daemon did not answer, so this console cannot say what is held: ${queue.error ?? ""}`
        }
        emptyState="No held actions. Every destructive action in this window ran without one — see /policy for which rules can hold."
      >
        {undeliverable ? (
          <p
            data-testid="perch-holds-undeliverable"
            className="px-3 text-xs text-[hsl(var(--perch-foreground-muted))]"
          >
            no operator is configured to receive holds — set nostr_pubkey on an
            operator principal in the ruleset
          </p>
        ) : null}
        <ul className="flex flex-col gap-1 px-1">
          {rows.map((row) => (
            <li key={rowKey(row)}>
              <VerdictQueueRow
                row={row}
                selected={selected === rowKey(row)}
                onSelect={() => setSelected(rowKey(row))}
              />
            </li>
          ))}
        </ul>
      </WatchQueueSection>

      {PERCH_QUEUE_ORDER.filter((id) => id !== "holds").map((id) => (
        <WatchQueueSection
          key={id}
          queue={id}
          count={relayQueues?.get(id) ?? null}
          unavailableNote="the relay did not answer, so this queue is not a count of anything"
          emptyState={
            id === "findings"
              ? "No findings waiting on a reading."
              : "No case has moved in this window."
          }
        />
      ))}

      <PerchCounterStrip
        openCount={queue.data?.openCount ?? 0}
        storeDurable={queue.data?.storeDurable ?? false}
        queueDepthAlarm={queue.data?.queueDepthAlarm ?? false}
      />
      {/* Placeholder for the detail pane. Task 25 owns the Verdict Row; until
          it lands, the selection is recorded and named rather than acted on,
          so nothing here can look like a control that decides. */}
      <div
        data-testid="perch-detail-pane"
        data-perch-selected-row={selected ?? ""}
        data-perch-current-pubkey={currentPubkey ?? ""}
        hidden={selected === null}
      >
        <button
          type="button"
          className="px-3 py-2 text-xs underline"
          onClick={() => {
            const row = rows.find(
              (candidate) => rowKey(candidate) === selected,
            );
            const caseId =
              row && row.kind !== "unreconciled" ? row.hold.case_channel : null;
            if (caseId) onOpenCase?.(caseId);
          }}
        >
          Open the case channel
        </button>
      </div>
    </div>
  );
}

/**
 * The three numbers the governance strip renders, as data attributes.
 *
 * Rendered rather than logged: a divergence that only ever reached a console
 * log would be a divergence nobody sees.
 */
function PerchCounterStrip({
  openCount,
  storeDurable,
  queueDepthAlarm,
}: {
  openCount: number;
  storeDurable: boolean;
  queueDepthAlarm: boolean;
}) {
  // The divergence total is read from the counter module, not added to the
  // current reconciliation's number: `useHoldQueue` already folded this
  // reconciliation in, and adding it again would double every divergence.
  const divergences = readReconcileDivergenceCounter();
  const unadmitted =
    perchUnadmittedFrameCount() +
    readPerchCounter("perch_marker_unadmitted_total");
  return (
    <div
      data-testid="perch-counter-strip"
      data-perch-queue-depth-alarm={queueDepthAlarm ? "true" : "false"}
      className="flex flex-wrap items-baseline gap-3 px-3 py-2 text-2xs tabular-nums text-[hsl(var(--perch-foreground-muted))]"
    >
      <span
        data-perch-counter="perch_queue_reconcile_divergences_total"
        data-perch-counter-value={divergences}
      >
        divergences {divergences}
      </span>
      <span
        data-perch-counter="perch_frame_unadmitted_total"
        data-perch-counter-value={unadmitted}
      >
        unadmitted frames {unadmitted}
      </span>
      <span
        data-perch-counter="perch_queue_open_count"
        data-perch-counter-value={openCount}
      >
        open holds {openCount}
      </span>
      {storeDurable ? null : (
        <span data-testid="perch-store-not-durable">
          the daemon's hold store is not durable: a restart forgets every open
          hold
        </span>
      )}
    </div>
  );
}
