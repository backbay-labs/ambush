// Layer 3 of the hold path: reconcile the daemon's holds against the relay's
// notices, and render every way they can disagree.
//
// The daemon is the AUTHORITY. `GET /v1/response/holds` says what a hold is;
// a `46010` notice is the delivery record and says only that a notice reached
// the relay. Where they disagree this reducer shows the daemon's answer and
// never presents a relay-derived state as settled — which is why an
// `unreconciled` row carries an id and a pointer and no content at all. The
// notice's `content` string offers a severity, an action kind and an expiry;
// none of them is a fact about a hold this daemon has never heard of, and
// rendering them would be the console telling the operator a story the engine
// cannot back.
//
// INV-35 (W3-18): the honest word is UNRECONCILED, never FORGED. The store may
// simply be non-durable, in which case a restart forgot every open hold and
// nothing was forged at all.

import type { FeedItem } from "@/shared/api/types";
import type {
  PerchHeldActionView,
  PerchHoldListResponse,
} from "@/shared/api/tauriPerch";

/** APPENDIX-NORMATIVE.md §6: open holds at or above this trip the alarm. */
export const PERCH_QUEUE_DEPTH_ALARM = 12;

/** The `46010` hold notice. Its tag set carries exactly one `hold`. */
const KIND_HOLD_NOTICE = 46010;

/** Hold states the queue still asks a human about. */
const OPEN_STATES: ReadonlySet<string> = new Set([
  "created",
  "notified",
  "armed",
  "deciding",
]);

/**
 * Why an unreconciled row is in the ORDINARY register: the daemon admits its
 * store forgets, so a notice with no record is the expected consequence of a
 * restart rather than evidence of anything.
 */
export const UNRECONCILED_NON_DURABLE_REASON =
  "no daemon record: store_durable is false, so a restart forgot every open hold";

/**
 * Why an unreconciled row is in the DESTRUCTIVE register: the daemon claims a
 * durable store and still has no record of a hold something published a notice
 * for. One of those two statements is wrong and the console cannot tell which.
 */
export const UNRECONCILED_DURABLE_REASON =
  "the daemon has a durable hold store and no record of this hold";

/**
 * One row of the HOLDS queue.
 *
 * The `unreconciled` arm deliberately has no `hold`: there is no hold to show.
 * A test asserts its key set, because the tempting fix for a sparse row is to
 * fill it from the notice, and that is the one thing this queue must not do.
 */
export type PerchHoldRow =
  | {
      kind: "hold";
      hold: PerchHeldActionView;
      /** Whether a notice for this hold reached the relay. Not a gate. */
      noticed: boolean;
      register: "ordinary";
    }
  | {
      kind: "unreconciled";
      holdId: string;
      noticeEventId: string;
      register: "ordinary" | "destructive";
      reason: string;
    }
  | { kind: "expired"; hold: PerchHeldActionView };

/** The reconciled queue plus the three numbers the strip renders. */
export type HoldQueueReconciliation = {
  rows: PerchHoldRow[];
  /** Notices naming a hold the daemon has no record of. */
  divergences: number;
  /** Notices from an issuer this console does not admit (INV-15). */
  unadmittedFrames: number;
  /** Open holds across the STORE, not this page. */
  openCount: number;
  storeDurable: boolean;
  queueDepthAlarm: boolean;
};

function holdTag(item: FeedItem): string | null {
  const tag = item.tags.find((entry) => entry[0] === "hold");
  const value = tag?.[1];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function rowAge(row: PerchHoldRow): number {
  // An unreconciled row has no `held_at_ms` to sort by — the daemon never
  // recorded one — so it sorts last rather than being given a made-up age.
  return row.kind === "unreconciled"
    ? Number.MAX_SAFE_INTEGER
    : row.hold.held_at_ms;
}

/**
 * Reconcile one daemon answer against one batch of relay notices.
 *
 * `daemon: null` means the console does not know, and unknown is not empty: no
 * rows, no divergences, and the caller renders the unreachable state. Counting
 * a divergence against a daemon that answered nothing would turn every offline
 * moment into a governance alert.
 */
export function reconcileHoldQueue(input: {
  daemon: PerchHoldListResponse | null;
  relayNotices: readonly FeedItem[];
  admitted: ReadonlySet<string>;
  nowMs: number;
}): HoldQueueReconciliation {
  const { daemon, relayNotices, admitted, nowMs } = input;
  const rows: PerchHoldRow[] = [];
  let unadmittedFrames = 0;
  let divergences = 0;

  const noticedIds = new Set<string>();
  const firstNoticePerHold = new Map<string, FeedItem>();
  for (const item of relayNotices) {
    if (item.kind !== KIND_HOLD_NOTICE) continue;
    if (!admitted.has(item.pubkey.toLowerCase())) {
      unadmittedFrames += 1;
      continue;
    }
    const id = holdTag(item);
    if (!id) continue;
    noticedIds.add(id);
    if (!firstNoticePerHold.has(id)) firstNoticePerHold.set(id, item);
  }

  const daemonIds = new Set<string>();
  for (const hold of daemon?.holds ?? []) {
    daemonIds.add(hold.hold_id);
    // The sweep runs on an interval, so between the expiry instant and the
    // sweep the stored state still reads `notified`. The clock decides whether
    // a verdict can still land, so it decides which row this is.
    const expired =
      hold.state === "expired" || hold.expired || nowMs >= hold.expires_at_ms;
    if (expired) {
      rows.push({ kind: "expired", hold });
      continue;
    }
    if (!OPEN_STATES.has(hold.state)) {
      // Granted, refused, executed or failed: a human already answered, and
      // the case timeline carries what happened. Leaving it in the queue would
      // ask the same question twice.
      continue;
    }
    rows.push({
      kind: "hold",
      hold,
      noticed: noticedIds.has(hold.hold_id) || hold.notified_at_ms !== null,
      register: "ordinary",
    });
  }

  const storeDurable = daemon?.store_durable ?? false;
  if (daemon) {
    for (const [id, item] of firstNoticePerHold) {
      if (daemonIds.has(id)) continue;
      divergences += 1;
      rows.push({
        kind: "unreconciled",
        holdId: id,
        noticeEventId: item.id,
        register: storeDurable ? "destructive" : "ordinary",
        reason: storeDurable
          ? UNRECONCILED_DURABLE_REASON
          : UNRECONCILED_NON_DURABLE_REASON,
      });
    }
  }

  rows.sort((a, b) => rowAge(a) - rowAge(b));
  const openCount = daemon?.open_count ?? 0;
  return {
    rows,
    divergences,
    unadmittedFrames,
    openCount,
    storeDurable,
    queueDepthAlarm: openCount >= PERCH_QUEUE_DEPTH_ALARM,
  };
}
