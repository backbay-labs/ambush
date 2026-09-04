import * as React from "react";
import { type QueryClient, useQueryClient } from "@tanstack/react-query";

import { channelMessagesKey } from "@/features/messages/lib/messageQueryKeys";
import { usePerchLaneChannelIds } from "@/features/perch-evidence/lib/admittedIssuers";
import { parseCardContent } from "@/features/perch/wire";
import { getChannelIdFromTags } from "@/features/messages/lib/threading";
import { useIdentityQuery } from "@/shared/api/hooks";

import {
  buildPerchSubscriptions,
  observeIssuerSeq,
  type PerchEventSink,
  setPerchEventSink,
  syncPerchSubscriptions,
} from "./perchSubscriptions";

/**
 * The lane-movement path: one hook that mounts the perch REQ set while any
 * perch surface is rendered, and the sink that turns a lane's kind:9 into a
 * sequence observation plus a timeline nudge.
 *
 * Refcounted, so the many `useSwarmCardSurface` callers in a timeline are
 * one REQ set; syncs are coalesced per tick, so a hundred rows mounting at
 * once reconcile once.
 */

/** The two envelope members the lane-movement sink reads. */
export type LaneMovementEnvelope = {
  readonly issuer: string;
  readonly seq: number;
};

/**
 * Read `issuer` and `seq` out of a swarm card body, through the wire
 * mirror's own parser so the console has exactly one card grammar.
 *
 * Returns null for prose, for a marker that is not the whole of line 0, for
 * a kind or version the mirror does not know, for a fence whose info string
 * is not the marker's own, and for a malformed or ill-typed envelope. Never
 * throws: this runs on every lane event.
 */
export function readLaneMovementEnvelope(
  content: string,
): LaneMovementEnvelope | null {
  const parts = parseCardContent(content);
  if (!parts) return null;
  let envelope: unknown;
  try {
    envelope = JSON.parse(parts.json);
  } catch {
    return null;
  }
  if (typeof envelope !== "object" || envelope === null) return null;
  const { issuer, seq } = envelope as { issuer?: unknown; seq?: unknown };
  if (typeof issuer !== "string" || issuer.length === 0) return null;
  if (typeof seq !== "number" || !Number.isInteger(seq) || seq < 0) return null;
  return { issuer, seq };
}

const RETRY_BASE_MS = 1_000;
const RETRY_MAX_MS = 30_000;
const NO_LANES: readonly string[] = Object.freeze([]);

let queryClientForSink: QueryClient | null = null;
let mountCount = 0;
let desired: { myPubkey: string | null; laneChannelIds: readonly string[] } = {
  myPubkey: null,
  laneChannelIds: NO_LANES,
};
let syncScheduled = false;
let retryTimer: ReturnType<typeof setTimeout> | null = null;
let retryDelayMs = RETRY_BASE_MS;

/**
 * The sink for every perch REQ. This milestone consumes `lane-movement`
 * only: the envelope's `seq` feeds gap tracking and the lane's timeline is
 * invalidated so an open lane re-reads its head. The alarm, snooze and
 * named-you REQs are declared for the queue (The hold) and their events are
 * dropped here rather than cached for nobody.
 */
const laneMovementSink: PerchEventSink = (id, event) => {
  if (id !== "lane-movement") return;
  const envelope = readLaneMovementEnvelope(event.content);
  if (envelope) observeIssuerSeq(envelope.issuer, envelope.seq, Date.now());
  const channelId = getChannelIdFromTags(event.tags);
  if (channelId && queryClientForSink) {
    void queryClientForSink.invalidateQueries({
      queryKey: channelMessagesKey(channelId),
    });
  }
};

function cancelRetry(): void {
  if (retryTimer !== null) {
    clearTimeout(retryTimer);
    retryTimer = null;
  }
}

function desiredSpecs() {
  if (mountCount === 0 || !desired.myPubkey) return [];
  return buildPerchSubscriptions({
    myPubkey: desired.myPubkey,
    laneChannelIds: desired.laneChannelIds,
    activeCaseIds: [],
    openCaseId: null,
    telemetryWanted: false,
    nowSecs: Math.floor(Date.now() / 1_000),
  });
}

async function runSync(): Promise<void> {
  const result = await syncPerchSubscriptions(desiredSpecs());
  if (result.failed.length > 0 && mountCount > 0) {
    // Bounded retry, as useLiveChannelUpdates does: a failed open is usually
    // a socket that is not up yet.
    cancelRetry();
    retryTimer = setTimeout(() => {
      retryTimer = null;
      scheduleSync();
    }, retryDelayMs);
    retryDelayMs = Math.min(retryDelayMs * 2, RETRY_MAX_MS);
  } else {
    retryDelayMs = RETRY_BASE_MS;
  }
}

function scheduleSync(): void {
  if (syncScheduled) return;
  syncScheduled = true;
  queueMicrotask(() => {
    syncScheduled = false;
    void runSync();
  });
}

/**
 * Mount the perch REQ set for as long as the caller is rendered and
 * `enabled`. The first mount installs the sink and opens the REQs, the last
 * unmount closes them; identity or lane changes re-sync. Many callers cost
 * one REQ set.
 */
export function usePerchSubscriptionsMount(enabled = true): void {
  const queryClient = useQueryClient();
  const identity = useIdentityQuery();
  const myPubkey = identity.data?.pubkey ?? null;
  const laneChannelIds = usePerchLaneChannelIds();

  React.useEffect(() => {
    if (!enabled) return;
    mountCount += 1;
    queryClientForSink = queryClient;
    setPerchEventSink(laneMovementSink);
    scheduleSync();
    return () => {
      mountCount -= 1;
      if (mountCount === 0) {
        setPerchEventSink(null);
        queryClientForSink = null;
        cancelRetry();
        scheduleSync();
      }
    };
  }, [enabled, queryClient]);

  React.useEffect(() => {
    if (!enabled) return;
    desired = { myPubkey, laneChannelIds };
    scheduleSync();
  }, [enabled, myPubkey, laneChannelIds]);
}

/**
 * Community-switch fence, run by the `perchSubscriptions` registry entry
 * beside `resetPerchSubscriptions`. Clears the identity and lanes the next
 * sync would use and the retry timer; the mount count is React's and stays.
 */
export function resetPerchLaneMovement(): void {
  cancelRetry();
  retryDelayMs = RETRY_BASE_MS;
  desired = { myPubkey: null, laneChannelIds: NO_LANES };
  queryClientForSink = null;
}
