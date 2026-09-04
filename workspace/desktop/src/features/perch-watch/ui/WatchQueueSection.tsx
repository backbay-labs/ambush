import type * as React from "react";

import { cn } from "@/shared/lib/cn";

import {
  PERCH_COUNT_UNAVAILABLE,
  PERCH_QUEUE_HIDE_WHEN_EMPTY,
  PERCH_QUEUE_LABELS,
  type PerchQueueId,
} from "../lib/watchQueues";

/**
 * One queue: a header carrying a count that may be unknown, and its rows.
 *
 * The count is `null`, never `0`, when the backing read failed. Zero is a
 * claim that there is nothing, and a console that could not reach its daemon
 * is not in a position to make it — so the header says `count unavailable`
 * and the section says why (INV-35).
 *
 * `emptyState` is required for a queue that stays visible while empty, and
 * `PERCH_QUEUE_HIDE_WHEN_EMPTY` decides which those are. A queue is either
 * worth a sentence when it is empty or it should not be on the screen.
 */
export type WatchQueueSectionProps = {
  queue: PerchQueueId;
  /** `null` means the count is not knowable right now. */
  count: number | null;
  /** Rendered under the header when `count` is 0 and the queue stays visible. */
  emptyState?: React.ReactNode;
  /** Rendered instead of rows when the backing read failed. */
  unavailableNote?: React.ReactNode;
  children?: React.ReactNode;
};

export function WatchQueueSection({
  queue,
  count,
  emptyState,
  unavailableNote,
  children,
}: WatchQueueSectionProps) {
  const unknown = count === null;
  if (!unknown && count === 0 && PERCH_QUEUE_HIDE_WHEN_EMPTY.has(queue)) {
    return null;
  }
  return (
    <section
      data-testid={`perch-queue-${queue}`}
      data-perch-queue={queue}
      className="flex flex-col gap-1 border-b border-[hsl(var(--perch-border-strong))] pb-3"
    >
      <header className="flex items-baseline justify-between gap-2 px-3 pt-3">
        <h2 className="text-sm font-medium text-[hsl(var(--perch-foreground))]">
          {PERCH_QUEUE_LABELS[queue]}
        </h2>
        <span
          data-testid={`perch-queue-count-${queue}`}
          data-perch-count-known={unknown ? "false" : "true"}
          className={cn(
            "text-2xs tabular-nums text-[hsl(var(--perch-foreground-muted))]",
            unknown && "uppercase tracking-wide",
          )}
        >
          {unknown ? PERCH_COUNT_UNAVAILABLE : count}
        </span>
      </header>
      {unknown && unavailableNote ? (
        <p
          data-perch-role="unavailable-note"
          className="px-3 text-xs text-[hsl(var(--perch-foreground-muted))]"
        >
          {unavailableNote}
        </p>
      ) : null}
      {!unknown && count === 0 && emptyState ? (
        <p
          data-perch-role="empty-state"
          data-perch-empty-kind="governing-number"
          className="px-3 text-xs text-[hsl(var(--perch-foreground-muted))]"
        >
          {emptyState}
        </p>
      ) : null}
      {children}
    </section>
  );
}
