// Target path in BUZZ: desktop/src/shared/api/perchSubscriptions.ts  (NEW file)
//
// One reconciling subscription manager for every Perch REQ. Modelled on the
// Map-based `syncSubs` reconciler at BUZZ
// desktop/src/features/channels/useLiveChannelUpdates.ts:364-419 (renderer;
// holds a Map<channelId, dispose> in a ref, diffs it against the target set,
// disposes what left and opens what arrived, with bounded retry) — but hoisted
// out of a hook, because Perch's REQs are declared by six different features
// and the frame budget below is global, not per-feature.
//
// Every REQ goes through BUZZ relayClientSession.subscribeLive
// (`shared/api/relayClientSession.ts:410-417` -> private `subscribe` at
// :599-650, renderer): it generates a `live-${uuid}` subId, registers
// {mode:"live", filter, onEvent, resolveReady}, sends ["REQ", subId, filter]
// through sendRawWithReconnectRetry, resolves readiness on EOSE or a 250 ms
// timeout, and returns an async disposer that CLOSEs. Perch needs no new
// client method and no new Tauri command for relay work: sendRaw (:652-664)
// hands the frame to the native socket via invoke("plugin:websocket|send"), so
// the socket lives in Rust and all Nostr framing is TypeScript.
//
// Gate-line budget: 1000 (src/shared/api is governed). Targets ~660. If it
// grows further the split line is between the manager (§5) and gap detection
// (§6): they share no state and gap detection has no relay dependency at all,
// so it is a pure file move.

import { relayClient } from "./relayClient";
import type { RelayEvent } from "./types";

// ===========================================================================
// §1  Relay ceilings this file is written against (all read from source)
// ===========================================================================
//
//  MAX_SUBSCRIPTIONS = 1024, enforced per connection at
//    BUZZ crates/buzz-relay/src/handlers/req.rs:25 and :73-76 (relay process;
//    a REQ past the cap is answered "error: too many subscriptions").
//  MAX_EXPLICIT_CHANNEL_VALUES = 128 `#h` values across one REQ's filters,
//    req.rs:42.
//  max_filters = 10 is ADVERTISED in NIP-11 (nip11.rs:133) but I found no
//    enforcement site by grep over handlers/req.rs and connection.rs. Treat it
//    as a contract, not a fence — do not build a design that needs 11.
//  WS admission: every inbound EVENT/REQ/COUNT frame is charged against a
//    50-frames-per-rolling-5s budget per pubkey, with NO agent exemption —
//    connection.rs:652-706 calls ws_admission_budget(human_ws_events_per_sec)
//    with WS_BURST_WINDOW_SECS = 5 (admission.rs:9,40-45) and
//    human_ws_events_per_sec defaulting to 10. This is the budget §4 sizes.

export const PERCH_WS_FRAME_BUDGET = 50;
export const PERCH_WS_BURST_WINDOW_MS = 5_000;

// ===========================================================================
// §2  The two consumption paths, kept apart on purpose
// ===========================================================================
//
// The relay makes NO client-side distinction: an ephemeral 26xxx and a stored
// kind:9 both arrive as ["EVENT", subId, event] on the same socket and land in
// the same onEvent (verified — `subscribe` at relayClientSession.ts:599-650
// has one dispatch path). The divergence is entirely ours, and it is
// load-bearing:
//
//   STORED   -> React Query cache. Replayable, reconcilable, has an authority.
//   EPHEMERAL-> a module-level snapshot store read with useSyncExternalStore.
//               NEVER the query cache: an ephemeral has no authority to
//               reconcile against, is not replayed on reconnect, and putting
//               it in a cache that reconnect healing invalidates would make
//               `invalidateQueries` look like it can recover telemetry. It
//               cannot. A Perch that is disconnected when an alarm fires
//               MISSES it; that is why every ephemeral consumer also names its
//               authoritative re-read.

/**
 * `stream` is a ruled word (APPENDIX-NORMATIVE.md §7): it means one of the
 * BRIDGE's four transport classes — evidence / telemetry / alarm /
 * dropped-at-source — and nothing else. 11-BRIDGE-CRATE.md owns the four and
 * their policies.
 *
 * Exactly two of the four can reach a console over an ephemeral frame:
 * `evidence` is durable `kind:9`, and `dropped-at-source` by definition never
 * leaves the daemon. So this union is two members, not four, and it is named
 * for the bridge's word rather than inventing a second vocabulary for the same
 * partition.
 *
 * The client uses it for one thing: the alarm class is never coalesced, never
 * shed, and is re-established FIRST on reconnect.
 */
export type PerchFrameStream = "telemetry" | "alarm";

export type PerchEphemeralKind =
  | 26000
  | 26001
  | 26002
  | 26003
  | 26004
  | 26005
  | 26006;

/**
 * 26005 (TamperAlert) and 26006 (the hold alarm) are the alarm class. 26003
 * (ModeTransition) is NOT: it is a state frame that the bridge coalesces
 * on-change like the rest of the telemetry class, and a durable
 * `ambush:escalation:v1` card is what survives a transition INTO incident.
 * 11-BRIDGE-CRATE.md owns that assignment; this table mirrors it and must be
 * corrected here if it is corrected there.
 */
const EPHEMERAL_STREAM: Record<PerchEphemeralKind, PerchFrameStream> = {
  26000: "telemetry",
  26001: "telemetry",
  26002: "telemetry",
  26003: "telemetry",
  26004: "telemetry",
  26005: "alarm",
  26006: "alarm",
};

export function isPerchEphemeralKind(kind: number): kind is PerchEphemeralKind {
  return kind >= 26000 && kind <= 26006;
}

export function perchStreamFor(kind: PerchEphemeralKind): PerchFrameStream {
  return EPHEMERAL_STREAM[kind];
}

// ===========================================================================
// §3  The subscription registry — declarative, one row per surface
// ===========================================================================

export type PerchSubscriptionId =
  | "watch-alarm"
  | "watch-snoozes"
  | "watch-named-you"
  | "lane-movement"
  | "case-activity"
  | "case-live"
  | "telemetry";

export type PerchFilter = {
  kinds: number[];
  "#h"?: string[];
  "#p"?: string[];
  authors?: string[];
  limit: number;
  since?: number;
};

export type PerchSubscriptionSpec = {
  id: PerchSubscriptionId;
  /**
   * Non-null only while the surface that needs it is mounted (or, for
   * `watch-alarm` and `telemetry`, for the whole session). Returning null is
   * how a surface tears its REQ down; the manager CLOSEs on the next sync.
   */
  filter: PerchFilter | null;
  /**
   * True when the manager may re-establish this REQ inside the first reconnect
   * batch. Reserved for the alarm path.
   */
  priority: boolean;
};

/**
 * The complete steady-state REQ inventory, built fresh on every sync. Values
 * come from APPENDIX-NORMATIVE.md §3 / the per-surface table in `03` §8 and
 * `07` §6; the shapes below are the buildable form of that table.
 */
export function buildPerchSubscriptions(ctx: {
  myPubkey: string;
  /** All twelve lane channel UUIDs, in `standard_threat_classes()` order. */
  laneChannelIds: readonly string[];
  /** Case channels the operator has taken this shift. */
  activeCaseIds: readonly string[];
  /** The case currently open, if any. */
  openCaseId: string | null;
  /** Whether any mounted surface reads telemetry (Watchfloor, a lane, the strip). */
  telemetryWanted: boolean;
  nowSecs: number;
}): PerchSubscriptionSpec[] {
  const {
    myPubkey,
    laneChannelIds,
    activeCaseIds,
    openCaseId,
    telemetryWanted,
    nowSecs,
  } = ctx;

  return [
    // -----------------------------------------------------------------------
    // THE ONLY LIVE PATH TO A HOLD.
    //
    // Three wave-2 artifacts specified this filter three incompatible ways.
    // RATIFIED in build/00-REGISTRY.md R-1: `26006` is GLOBAL, carries NO `h`
    // tag, and is selected by `#p` = me. Do not re-derive this here; if you
    // believe it is wrong, change R-1 and say so in the PR.
    //
    // Two mechanisms, and it matters which one does what:
    //
    //  DELIVERY is `#p` filter matching, evaluated per frame against that
    //  frame's own `p` tags. A subscription registered with `#p:[me]` can only
    //  ever receive frames that name me — including a stale one that outlived a
    //  config change, because there is no membership state in the path.
    //
    //  DISCLOSURE is the relay's p-gate. Without it, `filter_fanout_by_access`
    //  (BUZZ crates/buzz-relay/src/handlers/event.rs:115-222, relay process)
    //  returns every subscription match unchanged for a channel-less event —
    //  `let Some(channel_id) = stored_event.channel_id else { return matches; }`
    //  at :177 — and nothing before that point consults `p` tags. So any
    //  authenticated member could open `REQ {kinds:[26006]}` and enumerate every
    //  hold's existence, severity, action kind and case channel. Adding 26006 to
    //  `P_GATED_KINDS` (BUZZ crates/buzz-core/src/kind.rs, delivered as
    //  build/patches/relay-26006-pgate.patch) makes
    //  `p_gated_filters_authorized` (handlers/req.rs:1182-1216) require every
    //  `#p` value on every filter to equal the authenticated pubkey, so
    //  `{kinds:[26006]}` unfiltered and `#p:[someone_else]` are both CLOSED.
    //  It is called from four places: handle_req, POST /query (twice) and COUNT.
    //
    // THIS FILTER IS THE ONLY ADMISSIBLE SHAPE, which is why it is written here
    // and nowhere else. In `handle_req` the p-gate runs only inside
    // `if channel_id.is_none()` (req.rs:219, with the comment saying so at
    // :215-218) — so the alarm REQ must stay GLOBAL for the gate to protect it
    // at all, and it must never be merged into a channel-scoped REQ to save a
    // subscription slot. The alarm is one of the seven and may not be merged.
    //
    // UNTIL THE PATCH LANDS the filter still works and the disclosure is open.
    // The client cannot fix that; perchEphemeralStore.ts says so at the gate,
    // and R-1 records that the fork carrying this patch is now load-bearing
    // rather than belt-and-braces.
    //
    // NEITHER MECHANISM COVERS FORGERY. A member with MessagesWrite can publish
    // a 26006 of their own; the ephemeral scope check at event.rs:698-708 admits
    // any such token. The console's admitted-issuer render rule (08 INV-15,
    // ADR 0017 C5) is the whole defence there, and it is a render rule, not a
    // relay rule. Two delivery fences do not imply a third property.
    //
    // THE ALARM IS A NUDGE WITH NO AUTHORITY. It triggers the daemon re-read; a
    // row appears only if `GET /v1/response/holds` confirms it. A console that
    // was disconnected when the alarm fired MISSED it — ephemerals are never
    // replayed — which is why the hold list is re-read on connect, on reconnect
    // and on every alarm.
    // -----------------------------------------------------------------------
    {
      id: "watch-alarm",
      filter: { kinds: [26006], "#p": [myPubkey], limit: 0 },
      priority: true,
    },

    // kind:30300 reminders authored by me. NIP-44-encrypted to self with no p
    // tag, so a due snooze can never enter the needs-action path; due times
    // are computed client-side and merged into queue 1 with a `local` marker.
    {
      id: "watch-snoozes",
      filter: { kinds: [30300], authors: [myPubkey], limit: 100 },
      priority: false,
    },

    // A person's kind:9 naming me. Partitioned client-side on the `k` tag —
    // `k` is a POST-FILTER, never indexed selection (APPENDIX-NORMATIVE.md §3;
    // filter_fully_pushable at BUZZ handlers/req.rs:851-895 pushes only kinds,
    // authors, ids, since/until, #h, a single #p, #d on NIP-33 and #e).
    {
      id: "watch-named-you",
      filter: { kinds: [9], "#p": [myPubkey], limit: 100 },
      priority: false,
    },

    // Twelve lanes on ONE REQ, not twelve. `#h` accepts 128 values
    // (MAX_EXPLICIT_CHANNEL_VALUES, req.rs:42); a REQ per lane spends twelve
    // subscription slots and twelve admission frames on a view nobody is
    // reading.
    {
      id: "lane-movement",
      filter:
        laneChannelIds.length > 0
          ? { kinds: [9], "#h": [...laneChannelIds], limit: 1 }
          : null,
      priority: false,
    },

    // Cases taken this shift, batched. Multi-`#h` means this REQ is NOT
    // eligible for Buzz's paged reconnect repair (see §5.3) — acceptable,
    // because this queue is a nudge whose authority is elsewhere.
    {
      id: "case-activity",
      filter:
        activeCaseIds.length > 0
          ? {
              kinds: [9, 46010],
              "#h": activeCaseIds.slice(0, 128) as string[],
              limit: 1,
            }
          : null,
      priority: false,
    },

    // The open case. See §5.3 for why its kind set is what it is.
    {
      id: "case-live",
      filter: openCaseId
        ? {
            kinds: perchCaseLiveKinds(),
            "#h": [openCaseId],
            limit: 1000,
            since: nowSecs,
          }
        : null,
      priority: false,
    },

    // One global REQ for the whole 26xxx block. No `#h`: an ephemeral with an
    // h tag takes the channel-scoped branch and a membership check
    // (BUZZ handlers/event.rs:850-874); without one it takes the Uuid::nil()
    // global path at :875-903 and reaches every subscribed member.
    {
      id: "telemetry",
      filter: telemetryWanted
        ? { kinds: [26000, 26001, 26002, 26003, 26004, 26005], limit: 0 }
        : null,
      priority: false,
    },
  ];
}

/**
 * The case-live kind set, and the two mechanisms that decide what a reconnect
 * actually recovers. This is the most-corrected block in the file; read all of
 * it before changing a kind.
 *
 * MECHANISM 1 — ELIGIBILITY, decided in the renderer from OUR filter.
 * `shouldPageReconnectReplay` (BUZZ desktop/src/shared/api/relayReconnectReplay.ts:103-111,
 * renderer, called per live subscription by `replayLiveSubscriptions` at :232)
 * returns true only when the filter has `limit > 0`, exactly one `#h`, and
 * `CHANNEL_EVENT_KINDS.every(k => filter.kinds.includes(k))`. An eligible
 * subscription gets its ORIGINAL filter re-sent verbatim (:314-317) AND a paged
 * keyset backfill; an ineligible one degrades to `buildReconnectReplayFilter`
 * (:82-101) — one REQ with `since = lastSeen - RECONNECT_REPLAY_SKEW_SECS (5)`.
 * A five-second lookback is not a repair for a minute-long disconnect, so the
 * naive Perch filter `{kinds:[9,46010,40100,40099]}` must not be written.
 * `perchCaseLiveKinds()` therefore SUPERSETS the constant rather than replacing
 * it, and SPREADS it rather than copying it — 00-BRIEF.md §5.4's huddle
 * deletion removes 48100-48103 from CHANNEL_EVENT_KINDS
 * (BUZZ shared/constants/kinds.ts:100-113) and a copied list would silently
 * desynchronise the eligibility test.
 *
 * MECHANISM 2 — WHAT THE BACKFILL ACTUALLY FETCHES, and it is NOT our filter.
 * `replayReconnectHistoryPages` (:129-178) walks the missed window with a
 * composite `(created_at, id)` cursor by calling `requestRepair({channelId,
 * since, limit, until, beforeId})`. That request type
 * (BUZZ desktop/src/shared/api/channelReconnectRepair.ts:4-10) carries NO
 * KINDS. It invokes the Tauri command `get_channel_reconnect_repair`
 * (desktop/src-tauri/src/commands/channel_reconnect_repair.rs:45-68, the Tauri
 * Rust process), which builds its filter at :10-42 and inserts
 * `CHANNEL_REPAIR_KINDS` — a `[u32; 15]` at :6-8, the Rust mirror of
 * CHANNEL_EVENT_KINDS — then queries the relay. The renderer's kinds never
 * reach it, and `repair_filter_is_fixed_and_keyset_scoped` (:74-96) pins that
 * on purpose.
 *
 * SO: passing `shouldPageReconnectReplay` buys the keyset walk for BUZZ's
 * fifteen kinds and nothing else. 46010, 40100 and 39005 ride only the verbatim
 * live REQ at :314-317 — whose window is this filter's own `since` and whose
 * depth is `limit`, served newest-first (`ORDER BY created_at DESC, id ASC
 * LIMIT`, BUZZ crates/buzz-db/src/store/event.rs:599, clamped by
 * DEFAULT_MAX_PAGE_LIMIT = 1000 at :33). The hole is therefore BOUNDED rather
 * than total: it opens when more than `limit` matching events accumulate in one
 * case channel after the subscription opened, at which point the relay's
 * newest-first truncation drops the OLDEST events in the window — including,
 * potentially, a hold notice.
 *
 * THE FIX, DECIDED: extend `CHANNEL_REPAIR_KINDS` from 15 to 18 in the SAME PR
 * as the relay fork, and update its pinning test's literal. It is one Rust
 * constant and one test line. `PERCH_CASE_REPAIR_KINDS` below is the required
 * value, and `assertPerchRepairKindsCovered` is what stops the two languages
 * drifting again — because a TS constant and a Rust constant describing one
 * wire filter with no compiler link between them is exactly what produced this
 * defect.
 *
 * THE BACKSTOP, if it ever regresses: the per-issuer `seq` gap detector in §6.
 * A marker card lost inside the missed window shows up as a forward jump in its
 * issuer's sequence, and the gap renders. That is an independent mechanism with
 * no shared failure mode, and it is why a silent hole here is a degradation
 * rather than a lie — but it only fires once a LATER card from the same issuer
 * arrives, so it is a backstop and not a substitute for the constant.
 */
export function perchCaseLiveKinds(): number[] {
  // Imported at call time in the real file:
  //   import { CHANNEL_EVENT_KINDS, KIND_CHANNEL_THREAD_SUMMARY }
  //     from "@/shared/constants/kinds";
  // 46010 is the forked hold notice; 40100 is the case canvas; 39005 is the
  // relay-signed thread summary, which rides this subscription only, matching
  // the comment at relayClientSession.ts:334-336.
  return [
    ...CHANNEL_EVENT_KINDS_PLACEHOLDER,
    KIND_CHANNEL_THREAD_SUMMARY_PLACEHOLDER,
    46010,
    40100,
  ];
}

/**
 * The three kinds `CHANNEL_REPAIR_KINDS` must gain, and the assertion that they
 * did.
 *
 * The Rust constant is authoritative for what the keyset walk fetches; this is
 * the TypeScript statement of what Perch needs it to contain. The invariant
 * test reads BOTH — the Rust literal through a small extractor over
 * `channel_reconnect_repair.rs`, and this array — and fails on any Perch kind
 * absent from the Rust side. Handed to 16-INVARIANT-TESTS.md as INV-CR1.
 */
export const PERCH_CASE_REPAIR_KINDS: readonly number[] = [46010, 40100, 39005];

/**
 * Refuse to boot a development or E2E build whose repair coverage is
 * incomplete.
 *
 * `repairKinds` is the Rust constant, surfaced through the mock bridge in E2E
 * and through a one-line read in dev. In production this is a no-op: a shipped
 * build cannot fix the constant, and crashing the console over a backfill gap
 * would be a worse failure than the gap. The point is that the drift is caught
 * where it is cheap — on the machine of whoever changed one of the two lists —
 * rather than as a hole an operator finds after a long disconnect.
 */
export function assertPerchRepairKindsCovered(
  repairKinds: readonly number[],
  isDevBuild: boolean,
): string | null {
  const missing = PERCH_CASE_REPAIR_KINDS.filter((k) => !repairKinds.includes(k));
  if (missing.length === 0) return null;
  const message =
    `CHANNEL_REPAIR_KINDS is missing ${missing.join(", ")}: the reconnect ` +
    `keyset walk will not fetch these kinds, so a case timeline can lose them ` +
    `across a disconnect longer than its own live window. Extend the constant ` +
    `at desktop/src-tauri/src/commands/channel_reconnect_repair.rs:6-8 and its ` +
    `pinning test.`;
  if (isDevBuild) throw new Error(message);
  return message;
}

// Placeholders so this skeleton reads standalone; replace with the real imports.
const CHANNEL_EVENT_KINDS_PLACEHOLDER: readonly number[] = [];
const KIND_CHANNEL_THREAD_SUMMARY_PLACEHOLDER = 39005;

// ===========================================================================
// §4  Frame budget — the arithmetic, not a hope
// ===========================================================================
//
// Steady state, worst case (Watchfloor open, a case open, twelve lanes):
//   7 REQ frames at open, then ZERO REQ frames until navigation.
// Inbound EVENT frames are not charged to us. The operator's own publishes
// are: an `ambush:verdict:v1` card is one EVENT frame, and the human tier is
// human_messages_per_min = 60 (connection.rs:690-695 selects it because
// is_agent = ctx.agent_owner_pubkey.is_some() and the operator key carries no
// owner attestation). Sixty verdicts a minute is not a queue anyone has.
//
// The real exposure is RECONNECT, where all seven REQs go out at once plus one
// paged-history REQ per eligible subscription. Buzz caps that blast at
// REPLAY_BATCH_SIZE = 8 with REPLAY_INTER_BATCH_DELAY_MS = 50
// (relayReconnectReplay.ts:47-62) and re-checks the rate-limit gate before
// every batch (:305-306). Seven subscriptions fit in one batch.
//
// Budget check: 7 REQ + at most 1 paged-history REQ per eligible sub (only
// `case-live` is eligible) = 8 frames inside one 5 s window against a budget
// of 50. Headroom: 42 frames, which is the room the un-shed 26006 alarms and
// the operator's own publishes need.
//
// The paged-history REQ is NOT charged to this budget in the same way: it goes
// out as a Tauri `get_channel_reconnect_repair` invoke, which the Rust process
// turns into an HTTP `POST /query` rather than a WS frame
// (channel_reconnect_repair.rs:63 calls `query_relay`, relay.rs:360 -> :370-389,
// which POSTs `{api_base}/query` with a NIP-98 header after awaiting the same
// rate-limit gate the renderer arms at :375). It is counted here
// anyway, as a deliberate over-estimate — a budget that under-counts is worse
// than one that over-counts, and 42 frames of headroom absorbs the error.
//
// PERCH DOES NOT ADD A SECOND BATCHER. Reusing Buzz's replay path means the
// gate, the ordering and the visible-first sort (relayReconnectReplay.ts:281-296)
// all apply unchanged.

export function perchSteadyStateReqFrames(specs: PerchSubscriptionSpec[]): number {
  return specs.filter((s) => s.filter !== null).length;
}

// ===========================================================================
// §5  The manager
// ===========================================================================

type ActiveEntry = {
  spec: PerchSubscriptionSpec;
  dispose: () => Promise<void>;
  serialized: string;
};

export type PerchEventSink = (
  id: PerchSubscriptionId,
  event: RelayEvent,
) => void;

const active = new Map<PerchSubscriptionId, ActiveEntry>();
let sink: PerchEventSink | null = null;

/** Stable serialization so an unchanged filter does not churn the REQ. */
function serialize(filter: PerchFilter): string {
  return JSON.stringify({
    kinds: [...filter.kinds].sort((a, b) => a - b),
    h: filter["#h"] ? [...filter["#h"]].sort() : undefined,
    p: filter["#p"] ? [...filter["#p"]].sort() : undefined,
    authors: filter.authors ? [...filter.authors].sort() : undefined,
    limit: filter.limit,
    // `since` is deliberately EXCLUDED: it is `now` on every rebuild, and
    // including it would tear down and re-open every live REQ on every render
    // that touches the manager. This is the single most expensive mistake
    // available in this file.
  });
}

export function setPerchEventSink(next: PerchEventSink | null): void {
  sink = next;
}

/**
 * Reconcile the open REQ set against `specs`. Idempotent: calling it with an
 * unchanged input performs no network work. Failures are per-subscription and
 * never reject — a failed open leaves that id absent so the next sync retries
 * it, exactly as useLiveChannelUpdates.ts:389-415 does.
 */
export async function syncPerchSubscriptions(
  specs: PerchSubscriptionSpec[],
): Promise<{ opened: number; closed: number; failed: PerchSubscriptionId[] }> {
  const target = new Map(specs.map((s) => [s.id, s]));
  let opened = 0;
  let closed = 0;
  const failed: PerchSubscriptionId[] = [];

  for (const [id, entry] of active) {
    const next = target.get(id);
    const wanted = next?.filter ?? null;
    if (wanted === null || serialize(wanted) !== entry.serialized) {
      active.delete(id);
      closed += 1;
      void entry.dispose().catch(() => {});
    }
  }

  const additions = specs
    .filter((s) => s.filter !== null && !active.has(s.id))
    .sort((a, b) => Number(b.priority) - Number(a.priority))
    .map(async (spec) => {
      const filter = spec.filter;
      if (!filter) return;
      try {
        const dispose = await relayClient.subscribeLive(filter, (event) =>
          sink?.(spec.id, event),
        );
        // A newer sync may have superseded this open while the invoke was in
        // flight; do not resurrect a disposed entry.
        if (!active.has(spec.id)) {
          active.set(spec.id, {
            spec,
            dispose,
            serialized: serialize(filter),
          });
          opened += 1;
        } else {
          void dispose().catch(() => {});
        }
      } catch {
        failed.push(spec.id);
      }
    });

  await Promise.allSettled(additions);
  return { opened, closed, failed };
}

/** Colony-switch fence. Registered in the typed reset registry (§8). */
export async function resetPerchSubscriptions(): Promise<void> {
  const entries = [...active.values()];
  active.clear();
  sink = null;
  await Promise.allSettled(entries.map((e) => e.dispose()));
}

// ===========================================================================
// §6  Gap detection — per (colony, issuer) sequence, not per subscription
// ===========================================================================
//
// Every published envelope carries a per-issuer monotonic `seq` (07 §5.4,
// §10). The client's job is to notice a hole and REFUSE TO SMOOTH IT.
//
// Namespacing is (colonyId, issuer), never issuer alone: two colonies each
// running a `whisker` both emit seq 1, and merging them under one key produces
// either a false gap or — worse — a false continuity (07 §11.1). In v1 the
// QueryClient is already colony-scoped, so `colonyId` is the store's identity
// rather than a key segment; it is a parameter here so the federated case
// cannot be retrofitted wrongly.
//
// A gap is NEVER healed by re-requesting from the relay. The relay does not
// know what the bridge dropped; only the daemon does. The gap row's affordance
// re-fetches the (issuer, seq-range) from the daemon.

export type PerchSeqGap = {
  readonly issuer: string;
  readonly expectedSeq: number;
  readonly receivedSeq: number;
  readonly missing: number;
  readonly firstNoticedAtMs: number;
};

const lastSeqByIssuer = new Map<string, number>();
const openGaps = new Map<string, PerchSeqGap>();

/**
 * Feed every decoded card body here, in arrival order. Returns a gap when one
 * opens, so the caller can render the row immediately rather than on the next
 * poll.
 *
 * Out-of-order-but-not-missing is NOT a gap: a seq below the high-water mark
 * is a duplicate or a late arrival and is ignored for gap purposes. Only a
 * forward jump opens one.
 */
export function observeIssuerSeq(
  issuer: string,
  seq: number,
  nowMs: number,
): PerchSeqGap | null {
  const previous = lastSeqByIssuer.get(issuer);
  lastSeqByIssuer.set(issuer, Math.max(previous ?? seq, seq));

  if (previous === undefined) return null;
  if (seq <= previous) return null;
  if (seq === previous + 1) return null;

  const gap: PerchSeqGap = {
    issuer,
    expectedSeq: previous + 1,
    receivedSeq: seq,
    missing: seq - previous - 1,
    firstNoticedAtMs: nowMs,
  };
  openGaps.set(`${issuer}:${gap.expectedSeq}`, gap);
  return gap;
}

export function perchOpenGaps(): readonly PerchSeqGap[] {
  return [...openGaps.values()];
}

/** Called only when the daemon has served the missing range. */
export function closePerchGap(issuer: string, expectedSeq: number): void {
  openGaps.delete(`${issuer}:${expectedSeq}`);
}

/** Colony-switch fence. Registered in the typed reset registry (§8). */
export function resetPerchSeqTracking(): void {
  lastSeqByIssuer.clear();
  openGaps.clear();
}
