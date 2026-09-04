// The Watch's four queues, as data.
//
// Order is the operator's reading order and is not a preference: holds are
// the only rows where not deciding is itself a decision, so they are first
// and they are the only queue that renders an empty state (the others hide).
// 17-COMPONENT-SPECS.md §6.2.

import type { FeedItem } from "@/shared/api/types";

/** The four queues, in render order. */
export type PerchQueueId = "holds" | "named-you" | "findings" | "case-activity";

/** Render order. The array, not the union, is what components iterate. */
export const PERCH_QUEUE_ORDER = [
  "holds",
  "named-you",
  "findings",
  "case-activity",
] as const satisfies readonly PerchQueueId[];

/**
 * The ratified labels. No queue is called "Approvals" and none uses a verdict
 * verb: naming a queue after the answer prejudges it (APPENDIX §7).
 */
export const PERCH_QUEUE_LABELS: Record<PerchQueueId, string> = {
  holds: "Holds",
  "named-you": "Named you",
  findings: "Findings to review",
  "case-activity": "Case activity",
};

/**
 * Queues that vanish rather than render an empty state.
 *
 * A solo deployment has nobody to name you, and a queue reading "Named you 0"
 * forever is a permanent reminder of a fact about the deployment rather than
 * about the work. HOLDS is never hidden: an empty holds queue is a claim worth
 * making, and it makes it with a governing number rather than a reassurance.
 */
export const PERCH_QUEUE_HIDE_WHEN_EMPTY: ReadonlySet<PerchQueueId> =
  new Set<PerchQueueId>(["named-you"]);

/** The `46010` hold notice. */
const KIND_HOLD_NOTICE = 46010;

/** Line 0 of a bridge-authored finding card. */
const FINDING_MARKER = "<!-- swarm:finding:v1 -->";

/**
 * Which queue a relay feed item belongs to.
 *
 * A `46010` is a hold notice wherever it arrives, so it is routed on its kind
 * and not on the feed category the relay assigned it: the relay's
 * `needs_action` query has no status join, so a decided hold stays in that
 * category forever, and routing on category alone would put a settled hold in
 * front of a human again.
 */
export function queueForFeedItem(item: FeedItem): PerchQueueId {
  if (item.kind === KIND_HOLD_NOTICE) return "holds";
  if (item.category === "mention") return "named-you";
  // Line 0 first, THEN `trimEnd` — never `trimStart` (ADR 0014 C1). A leading
  // space means the line is not the marker, and treating it as one is how an
  // unsigned card gets read as a governance card.
  if (item.content.split("\n", 1)[0]?.trimEnd() === FINDING_MARKER) {
    return "findings";
  }
  return "case-activity";
}

/**
 * What a queue header shows when the count is not knowable.
 *
 * Never `0`: zero is a claim that there is nothing, and a console that cannot
 * reach its daemon is not in a position to make it (INV-35). Not "all clear"
 * or "caught up" either — both are reassurance, and reassurance is the thing
 * this console is least entitled to offer.
 */
export const PERCH_COUNT_UNAVAILABLE = "count unavailable";
