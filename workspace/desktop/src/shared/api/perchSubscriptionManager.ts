import * as React from "react";
import { type QueryClient, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "@tanstack/react-router";

import { derivePerchShellRoute } from "@/app/perchViews";
import { useChannelsQuery } from "@/features/channels/hooks";
import { channelMessagesKey } from "@/features/messages/lib/messageQueryKeys";
import {
  admittedIssuersKnown,
  ensureAdmittedIssuersLoaded,
  perchAdmittedIssuerSet,
  usePerchLaneChannelIds,
} from "@/features/perch-evidence/lib/admittedIssuers";
import { parseCardContent } from "@/features/perch/wire";
import { perchAdmittedIssuers } from "@/shared/api/tauriPerch";
import { getChannelIdFromTags } from "@/features/messages/lib/threading";
import { useIdentityQuery } from "@/shared/api/hooks";

import {
  applyPerchEphemeralFrame,
  setPerchAdmittedIssuers,
} from "./perchEphemeralStore";
import { perchKeys } from "./perchKeys";
import {
  buildPerchSubscriptions,
  observeIssuerSeq,
  type PerchEventSink,
  type PerchSubscriptionSpec,
  setPerchEventSink,
  syncPerchSubscriptions,
} from "./perchSubscriptions";
import {
  perchTelemetryWanted,
  subscribePerchTelemetryWanted,
} from "./perchTelemetryWanted";

/**
 * The perch subscription manager's React side: the inputs
 * `buildPerchSubscriptions` is fed from, the hooks that gather them, and the
 * one sink every open REQ delivers into.
 *
 * The file was `perchLaneMovement.ts` until it took the rest of the inventory;
 * the lane-movement envelope reader below keeps its name because the card
 * grammar it reads did not change.
 *
 * Two hooks, and the difference between them is the whole of this file's shape:
 *
 *   `usePerchSubscriptionsMount`  refcounted, called by every rendered swarm
 *                                 card surface. Cheap on purpose — a timeline
 *                                 row calls it, and there are hundreds.
 *   `usePerchSubscriptionShell`   called ONCE, from the shell's perch mount
 *                                 point. It reads the channel list and the
 *                                 router location, which no timeline row should
 *                                 pay for and which no timeline row can see the
 *                                 whole of anyway.
 *
 * Syncs are coalesced per tick, so a hundred rows mounting at once reconcile
 * once, and `syncPerchSubscriptions` is idempotent, so a sync that changes
 * nothing sends no frame.
 *
 * Gate-line budget: 1000 (src/shared/api is a governed root).
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
const NO_IDS: readonly string[] = Object.freeze([]);

/**
 * `MAX_EXPLICIT_CHANNEL_VALUES`, the relay's ceiling on `#h` values across one
 * REQ's filters (BUZZ crates/buzz-relay/src/handlers/req.rs:42). A 129th case
 * channel does not widen the filter; it closes the REQ.
 */
const MAX_CASE_CHANNELS = 128;

/** A case channel is named for its case. The bridge creates them; W3-5 routes them. */
const CASE_CHANNEL_PREFIX = "case-";

// ===========================================================================
// §1  The inputs, and where each one comes from
// ===========================================================================

/** Everything `buildPerchSubscriptions` needs, plus whether anything is mounted. */
export type PerchSubscriptionInputs = {
  /** False when no perch surface is rendered: the whole set closes. */
  readonly mounted: boolean;
  readonly myPubkey: string | null;
  readonly laneChannelIds: readonly string[];
  readonly activeCaseIds: readonly string[];
  readonly openCaseId: string | null;
  readonly telemetryWanted: boolean;
  readonly nowSecs: number;
};

/**
 * The REQ inventory this console should have open right now.
 *
 * Pure, so what the console asks the relay for is a function of what is true
 * of the console rather than of the order its effects happened to run in.
 *
 * Two ways to want nothing, and they are different: no perch surface is
 * rendered at all, or the identity has not resolved yet. The second is a
 * cold-start window rather than a decision — every REQ here is either selected
 * by the operator's own pubkey or read as the operator — so it opens nothing
 * and the next sync retries.
 */
export function perchDesiredSpecs(
  inputs: PerchSubscriptionInputs,
): PerchSubscriptionSpec[] {
  if (!inputs.mounted) return [];
  if (!inputs.myPubkey) return [];
  return buildPerchSubscriptions({
    myPubkey: inputs.myPubkey,
    laneChannelIds: inputs.laneChannelIds,
    activeCaseIds: inputs.activeCaseIds,
    openCaseId: inputs.openCaseId,
    telemetryWanted: inputs.telemetryWanted,
    nowSecs: inputs.nowSecs,
  });
}

/** The shape of a channel this file reads. `Channel` satisfies it. */
export type PerchCaseChannel = {
  readonly id: string;
  readonly name: string;
  readonly isMember: boolean;
  readonly lastMessageAt: string | null;
};

/** `lastMessageAt` as a sortable instant; a channel nobody has posted in is oldest. */
function activityInstant(channel: PerchCaseChannel): number {
  if (!channel.lastMessageAt) return Number.NEGATIVE_INFINITY;
  const parsed = Date.parse(channel.lastMessageAt);
  return Number.isNaN(parsed) ? Number.NEGATIVE_INFINITY : parsed;
}

/**
 * The case channels the `case-activity` REQ should carry: the ones the operator
 * is actually a member of, newest first, capped at what one filter may hold.
 *
 * Derived from the channel list the sidebar already renders rather than fetched
 * again — there is one list of the operator's channels and this is a view of
 * it. The bridge's naming (`case-<uuid prefix>`) is the only marker a channel
 * record carries; a relay channel has no case flag, and inventing one here
 * would be a second source for a fact the bridge already publishes.
 *
 * Newest first is what makes the cap safe. A long-lived console accumulates
 * closed cases, and the ceiling is the relay's (128 `#h` values across one
 * REQ, req.rs:42) — so if it is ever reached, the cases that fall off the end
 * are the quiet old ones and never the case raised a minute ago.
 */
export function perchActiveCaseIds(
  channels: readonly PerchCaseChannel[],
): string[] {
  return channels
    .filter(
      (channel) =>
        channel.isMember && channel.name.startsWith(CASE_CHANNEL_PREFIX),
    )
    .sort((left, right) => {
      const byActivity = activityInstant(right) - activityInstant(left);
      // Ties broken by id so the serialization the manager diffs on is stable:
      // an unstable order would CLOSE and re-open the REQ on every rebuild.
      return byActivity !== 0 ? byActivity : left.id.localeCompare(right.id);
    })
    .slice(0, MAX_CASE_CHANNELS)
    .map((channel) => channel.id);
}

// ===========================================================================
// §2  The sink
// ===========================================================================

let queryClientForSink: QueryClient | null = null;
let mountCount = 0;
let inputs: {
  myPubkey: string | null;
  laneChannelIds: readonly string[];
  activeCaseIds: readonly string[];
  openCaseId: string | null;
} = {
  myPubkey: null,
  laneChannelIds: NO_IDS,
  activeCaseIds: NO_IDS,
  openCaseId: null,
};
let syncScheduled = false;
let retryTimer: ReturnType<typeof setTimeout> | null = null;
let retryDelayMs = RETRY_BASE_MS;

/**
 * A frame's content as it decoded, or `undefined` when it did not.
 *
 * The store decides what that means and counts it (`droppedFrames`); this only
 * refuses to throw, because it runs on every frame of a 1 Hz stream published
 * by a process the console does not control.
 */
function decodeFrameContent(content: string): unknown {
  try {
    return JSON.parse(content);
  } catch {
    return undefined;
  }
}

/** Re-read the channel this event landed in. The event itself is the nudge. */
function invalidateChannelTimeline(event: { tags: string[][] }): void {
  const channelId = getChannelIdFromTags(event.tags);
  if (!channelId || !queryClientForSink) return;
  void queryClientForSink.invalidateQueries({
    queryKey: channelMessagesKey(channelId),
  });
}

/**
 * The sink for every perch REQ, routed by the id of the REQ that carried the
 * event and never by the event's own kind.
 *
 * That distinction is the point. The relay makes NO client-side distinction
 * between an ephemeral 26xxx and a stored kind:9 — both arrive as
 * ["EVENT", subId, event] on one socket — so the subscription is the only thing
 * that says which of the two consumption paths an event belongs on
 * (`perchSubscriptions.ts` §2). Keying on the kind instead would let a forged
 * kind number on a durable REQ walk into the ephemeral store.
 *
 * Exported so its routing can be tested without a socket. It is installed by
 * `usePerchSubscriptionsMount` and called by nothing else.
 */
export const perchEventSink: PerchEventSink = (id, event) => {
  switch (id) {
    // The two ephemeral REQs. Held outside the query cache: an ephemeral has
    // no authority to reconcile against and is never replayed on reconnect.
    case "watch-alarm":
    case "telemetry":
      applyPerchEphemeralFrame({
        kind: event.kind,
        pubkey: event.pubkey,
        body: decodeFrameContent(event.content),
        receivedAtMs: Date.now(),
      });
      return;

    // A lane's own movement: the envelope's `seq` feeds gap tracking and the
    // lane's timeline re-reads its head.
    case "lane-movement": {
      const envelope = readLaneMovementEnvelope(event.content);
      if (envelope) observeIssuerSeq(envelope.issuer, envelope.seq, Date.now());
      invalidateChannelTimeline(event);
      return;
    }

    // The open case. Its timeline is a cache-as-store, so an arrival is a
    // re-read of that one channel and nothing wider.
    case "case-live":
      invalidateChannelTimeline(event);
      return;

    // Every case taken this shift. A 46010 is a hold NOTICE, which is what the
    // Watch's needs-action queue is built from — so it re-reads that too. The
    // notice is a delivery record and never the authority; `reconcileHoldQueue`
    // still checks the daemon.
    case "case-activity":
      invalidateChannelTimeline(event);
      if (event.kind === 46010 && queryClientForSink) {
        void queryClientForSink.invalidateQueries({
          queryKey: perchKeys.needsAction(),
        });
      }
      return;

    // Declared so the REQ exists and the relay is delivering; read from the
    // query cache by the queue that owns them, not from here. Caching them at
    // the sink would put a second writer on a key with an owner.
    case "watch-snoozes":
    case "watch-named-you":
      return;
  }
};

// ===========================================================================
// §3  The reconcile loop
// ===========================================================================

function cancelRetry(): void {
  if (retryTimer !== null) {
    clearTimeout(retryTimer);
    retryTimer = null;
  }
}

/** The inventory for the console as it is right now. */
function currentDesiredSpecs(): PerchSubscriptionSpec[] {
  return perchDesiredSpecs({
    mounted: mountCount > 0,
    myPubkey: inputs.myPubkey,
    laneChannelIds: inputs.laneChannelIds,
    activeCaseIds: inputs.activeCaseIds,
    openCaseId: inputs.openCaseId,
    telemetryWanted: perchTelemetryWanted(),
    nowSecs: Math.floor(Date.now() / 1_000),
  });
}

async function runSync(): Promise<void> {
  const result = await syncPerchSubscriptions(currentDesiredSpecs());
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

// A telemetry consumer mounting or unmounting changes the inventory, and the
// count lives in a module that knows nothing about this one — the dependency
// points this way on purpose, because the reverse would be a cycle between the
// two files a reader most needs to follow. Registered once, never removed: it
// holds no state, and a sync with nothing mounted builds an empty inventory.
subscribePerchTelemetryWanted(scheduleSync);

/**
 * Mirror the daemon's admitted-issuer set into the frame store.
 *
 * `shared/` may not import `features/` for the SET — the store says so at its
 * own gate — so the two are joined here, at the mount that already reads the
 * daemon's answer. Guarded on `admittedIssuersKnown()` because a FAILED load
 * leaves the feature module's set empty: mirroring that would tell the store it
 * has an answer, and every frame of the session would then be counted as
 * unadmitted on the strength of a read that never returned.
 */
function mirrorAdmittedIssuers(): void {
  if (!admittedIssuersKnown()) return;
  setPerchAdmittedIssuers(perchAdmittedIssuerSet());
}

// ===========================================================================
// §4  The two mounts
// ===========================================================================

/**
 * Mount the perch REQ set for as long as the caller is rendered and
 * `enabled`. The first mount installs the sink and opens the REQs, the last
 * unmount closes them; identity or lane changes re-sync. Many callers cost
 * one REQ set.
 *
 * Deliberately cheap: `useSwarmCardSurface` calls it from every timeline row.
 * The inputs that cost something to read are `usePerchSubscriptionShell`'s.
 */
export function usePerchSubscriptionsMount(enabled = true): void {
  const queryClient = useQueryClient();
  const identity = useIdentityQuery();
  const myPubkey = identity.data?.pubkey ?? null;
  const laneChannelIds = usePerchLaneChannelIds();

  React.useEffect(() => {
    if (!enabled) return;
    // The admitted set and the lane ids arrive together (D-FC-2), and the
    // REQ set cannot be built without the lanes. Rate-limited inside
    // `ensureAdmittedIssuersLoaded`, so many mounted rows cost one read.
    void ensureAdmittedIssuersLoaded(async () => {
      const answer = await perchAdmittedIssuers();
      return { issuers: [...answer.issuers], lanes: { ...answer.lanes } };
    }).then(mirrorAdmittedIssuers);
    mountCount += 1;
    queryClientForSink = queryClient;
    setPerchEventSink(perchEventSink);
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
    inputs = { ...inputs, myPubkey, laneChannelIds };
    scheduleSync();
  }, [enabled, myPubkey, laneChannelIds]);
}

/**
 * Mount the REQ set for the whole shell and feed it the two inputs only the
 * shell can see: which cases the operator is in, and which one is open.
 *
 * Call this EXACTLY ONCE, from the shell's perch mount point. Two reasons it is
 * not folded into `usePerchSubscriptionsMount`:
 *
 *  - `useChannelsQuery` inspects a persisted snapshot and sorts the channel
 *    list per mounted component. That is nothing once and a measurable cost on
 *    a timeline of rows, each of which calls the refcounted mount.
 *  - The surfaces that need the REQ set most render no timeline at all. The
 *    Watch and the Watchfloor have no `MessageBody`, so before this hook the
 *    whole inventory was open only while a channel timeline happened to be on
 *    screen — the governance strip and the wall were starved by construction.
 */
export function usePerchSubscriptionShell(enabled = true): void {
  usePerchSubscriptionsMount(enabled);
  const channels = useChannelsQuery({ enabled });
  const pathname = useLocation({ select: (location) => location.pathname });

  const channelList = channels.data;
  const activeCaseIds = React.useMemo(
    () => (channelList ? perchActiveCaseIds(channelList) : NO_IDS),
    [channelList],
  );
  // W3-5: a case renders as a case at `/cases/$caseId` and nowhere else, so
  // that route is the only thing that opens the case-live REQ. A case channel
  // opened as a plain channel is a channel.
  const route = derivePerchShellRoute(pathname);
  const openCaseId =
    route.selectedView === "case" ? route.selectedCaseId : null;

  React.useEffect(() => {
    if (!enabled) return;
    inputs = { ...inputs, activeCaseIds, openCaseId };
    scheduleSync();
  }, [enabled, activeCaseIds, openCaseId]);
}

/**
 * Community-switch fence, run by the `perchSubscriptions` registry entry
 * beside `resetPerchSubscriptions`. Clears the inputs the next sync would use
 * and the retry timer; the mount count is React's and stays.
 */
export function resetPerchSubscriptionManager(): void {
  cancelRetry();
  retryDelayMs = RETRY_BASE_MS;
  inputs = {
    myPubkey: null,
    laneChannelIds: NO_IDS,
    activeCaseIds: NO_IDS,
    openCaseId: null,
  };
  queryClientForSink = null;
}
