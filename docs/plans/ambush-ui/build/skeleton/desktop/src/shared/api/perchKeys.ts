// Target path in BUZZ: desktop/src/shared/api/perchKeys.ts  (NEW file)
//
// Replaces BUZZ desktop/src/shared/api/relayQueryInvalidation.ts, a
// hand-maintained Set of exactly 34 relay-dependent key roots (read this
// session at :1-36) consulted as the React Query `predicate` at
// useReconnectRelay.ts:62 and useRelayAutoHeal.ts:113-119 in the renderer, both
// on a degraded->connected transition. A query whose key[0] is not in that Set
// is never invalidated on reconnect and goes permanently stale — silently, and
// only under network churn.
//
// Perch does not keep a registry. The source is the FIRST SEGMENT OF THE KEY,
// so the predicate is a comparison rather than a membership test and there is
// nothing to forget to update. Sketched in 07-REALTIME-AND-DATA.md §7; this
// file is that sketch completed against every server-state read Perch makes.
//
// Gate-line budget: 1000 (src/shared/api is a governed root). Targets ~230.
// It CANNOT live in shared/api/tauri.ts (1108 gate-lines, frozen by
// BUZZ scripts/check-file-sizes-core.mjs:31-33) or shared/api/types.ts
// (exactly 1000). Forty sibling files under shared/api already follow the
// new-file pattern, measured this session.

/**
 * Which backend owns the answer. Perch has two that fail INDEPENDENTLY — the
 * relay can be up while the Ambush daemon is unreachable, and that is exactly
 * the state in which /leases must degrade honestly. Buzz's single-backend
 * assumption does not survive the fork.
 */
export type PerchQuerySource = "relay" | "daemon" | "local";

const key = <const S extends PerchQuerySource, const P extends readonly unknown[]>(
  source: S,
  ...parts: P
) => [source, ...parts] as const;

/**
 * Every server-state read Perch performs. If a surface fetches something that
 * is not in this object, that is the bug — not a missing registry entry.
 *
 * NO COLONY SEGMENT. The QueryClient is itself colony-scoped: BUZZ
 * App.tsx:235 constructs it inside a component that App.tsx:630 remounts with
 * `key={communityKey}` (:407), so two colonies never share one cache. A colony
 * segment inside a colony-scoped client is dead weight that invites the belief
 * that one client holds two colonies. See 14-CLIENT-ARCHITECTURE.md §4.6 for
 * the condition under which this must change (a cross-colony read view, which
 * gets its own client, not a wider key).
 */
export const perchKeys = {
  // ---- daemon (Ambush, over Tauri; see tauriPerch.ts) --------------------
  /** B2r GET /v1/response/holds — the queue's AUTHORITY. */
  holds: () => key("daemon", "holds"),
  /** B2r GET /v1/response/holds/{id}. */
  hold: (holdId: string) => key("daemon", "hold", holdId),
  /** GET /v1/operator/containment/leases. */
  containments: () => key("daemon", "containments"),
  /** B3r GET /v1/operator/findings/reviewed?since_ms= — the served review map. */
  reviewedFindings: (sinceMs: number) =>
    key("daemon", "reviewed-findings", sinceMs),
  /** B4 GET /v1/operator/pheromone/deposits — post-suppression, post-evaporation. */
  deposits: (threatClass: string) => key("daemon", "deposits", threatClass),
  /** GET /v1/operator/status — alert_tuning + false_positive_tracking. */
  operatorStatus: () => key("daemon", "operator-status"),
  /** Re-fetch of one artifact for the PROVENANCE block's byte diff. */
  artifactVerification: (artifactId: string) =>
    key("daemon", "artifact", artifactId),

  // ---- relay (Buzz, over the WebSocket / POST /query) --------------------
  /** The relay's needs-action feed. Kept, but never authoritative — see §5.7. */
  needsAction: () => key("relay", "needs-action"),
  caseTimeline: (caseId: string) => key("relay", "case", caseId, "timeline"),
  caseWindow: (caseId: string) => key("relay", "case", caseId, "window"),
  caseCanvas: (caseId: string) => key("relay", "case", caseId, "canvas"),
  caseMembers: (caseId: string) => key("relay", "case", caseId, "members"),
  caseList: () => key("relay", "cases"),
  laneTopics: () => key("relay", "lane-topics"),
  ledger: (query: string) => key("relay", "ledger", query),
  /** kind:30300 reminders authored by me; due times are computed client-side. */
  snoozes: () => key("relay", "snoozes"),
  /** The standing #watch ops-channel topic that carries the watch claim. */
  watchClaim: () => key("relay", "watch-claim"),
  /** The admitted-issuer set the marker parser and the 26xxx gate consult. */
  admittedIssuers: () => key("relay", "admitted-issuers"),

  // ---- local (no network; cache-mirror or filesystem) --------------------
  /** Bridge spool health, read from the daemon-side counters via Tauri. */
  spoolHealth: () => key("local", "spool-health"),
  /** Client-side reconcile divergences, mirrored for the strip. */
  reconcileDivergences: () => key("local", "reconcile-divergences"),
} as const;

/**
 * Reconnect healing for the RELAY. Passed as the React Query predicate exactly
 * where BUZZ passes `isRelayDependentQuery` today: useReconnectRelay.ts:62 and
 * useRelayAutoHeal.ts:113-119.
 */
export const isRelayDependentQuery = (q: {
  queryKey: readonly unknown[];
}): boolean => q.queryKey[0] === "relay";

/**
 * Reconnect healing for the DAEMON. Two predicates, not one — see the
 * `PerchQuerySource` doc. Fired by the daemon-reachability watcher, never by
 * the relay's connection-state transitions.
 */
export const isDaemonDependentQuery = (q: {
  queryKey: readonly unknown[];
}): boolean => q.queryKey[0] === "daemon";

// ---------------------------------------------------------------------------
// Freshness policy — one row per key, no defaults left implicit.
// ---------------------------------------------------------------------------

export type PerchFreshness = {
  /** React Query `staleTime`, ms. `Infinity` = only invalidation refetches. */
  staleTime: number;
  /**
   * React Query `refetchInterval`, ms, or false. Every polling value here is
   * gated on connection state by the calling hook, copying BUZZ
   * features/home/hooks.ts:19-23 which pauses polling while the relay is not
   * connected because the failed requests consume the quota recovery needs.
   */
  poll: number | false;
  /** What else must be invalidated when this key's underlying fact changes. */
  invalidatesOnWrite: ReadonlyArray<string>;
  /** Prose reason. Kept in the type so a policy change requires an argument. */
  why: string;
};

/**
 * Keyed by the key factory's own name. `satisfies` makes an unlisted key a
 * compile error and a listed non-key a compile error, so the policy table
 * cannot drift from the factory.
 */
export const PERCH_FRESHNESS = {
  holds: {
    staleTime: 0,
    poll: false,
    invalidatesOnWrite: ["needsAction", "reconcileDivergences"],
    why: "Refetched on connect, on reconnect and on every 26006 alarm frame (APPENDIX-NORMATIVE.md §4 layer 3). Never polled: the alarm is the trigger, and a poll would hide a dead alarm path rather than surface it. It is also the ONLY authority for which of several verdict cards on one hold is the decision — the daemon's HoldDecisionRecord names the winning nostr_intent_event_id, and a card whose id it does not name renders as not-the-decision (14 §7.6).",
  },
  hold: {
    staleTime: 0,
    poll: false,
    invalidatesOnWrite: ["holds"],
    why: "The verdict pane reads the hold it is about to act on. A cached hold is a hold whose capability-lease window may already have closed. It is NOT the input to leg 1's card body: perch_record_verdict re-reads the hold in the Tauri process and builds the card from that answer, so a stale renderer cache cannot reach a signed record.",
  },
  containments: {
    staleTime: 2_500,
    poll: 5_000,
    invalidatesOnWrite: ["caseTimeline"],
    why: "PERCH containment poll, 5 s (APPENDIX-NORMATIVE.md §6, proposed). staleTime is half the poll so a navigation inside the window does not double-fetch.",
  },
  reviewedFindings: {
    staleTime: 30_000,
    poll: false,
    invalidatesOnWrite: [],
    why: "The served review-state map. Refetched after every finding verdict and on reconnect; a stale map paints a row unreviewed for seconds, which is the one place the relay may front-run the daemon.",
  },
  deposits: {
    staleTime: 1_000,
    poll: false,
    invalidatesOnWrite: [],
    why: "Fetched when a lane or the Watchfloor opens and after a Dismiss, which retroactively removes deposits. Not polled: the 1 Hz 26001 frame carries the runtime's own totals and is the authority for the header number.",
  },
  operatorStatus: {
    staleTime: 60_000,
    poll: false,
    invalidatesOnWrite: [],
    why: "On-demand only. platform_runtime_status_handler loads incidents with .recent(usize::MAX); polling it is a self-inflicted load problem (04 §2.10 refuses it explicitly).",
  },
  artifactVerification: {
    staleTime: Number.POSITIVE_INFINITY,
    poll: false,
    invalidatesOnWrite: [],
    why: "A byte-for-byte diff of an immutable artifact. Re-running it can only produce the same answer or a new bug.",
  },
  needsAction: {
    staleTime: 0,
    poll: false,
    invalidatesOnWrite: ["reconcileDivergences"],
    why: "Runs beside `holds`, never instead of it. build_needs_action_query has no status join (BUZZ crates/buzz-db/src/store/feed.rs:171-201), so a DECIDED hold stays in it forever; the reconciler removes those against the daemon list.",
  },
  caseTimeline: {
    staleTime: Number.POSITIVE_INFINITY,
    poll: false,
    invalidatesOnWrite: [],
    why: "Inherits Buzz's cache-as-store pattern (features/messages/hooks.ts:247-258 sets staleTime Infinity and reads the cache in the queryFn). Live events mutate the cache directly; a refetch would fight the live merge. Its reconnect repair is NOT this key's problem — it is the subscription's, and it is only as complete as CHANNEL_REPAIR_KINDS (perchSubscriptions.ts, PERCH_CASE_REPAIR_KINDS).",
  },
  caseWindow: {
    staleTime: Number.POSITIVE_INFINITY,
    poll: false,
    invalidatesOnWrite: [],
    why: "Same cache-as-store pattern as caseTimeline.",
  },
  caseCanvas: {
    staleTime: 10_000,
    poll: false,
    invalidatesOnWrite: [],
    why: "Last-writer-wins shared markdown. Optimistic edits are permitted (07 §7); a short stale window keeps a remote edit visible without a poll.",
  },
  caseMembers: {
    staleTime: 60_000,
    poll: false,
    invalidatesOnWrite: [],
    why: "Roster changes are rare and arrive as kind:39002 on the case subscription.",
  },
  caseList: {
    staleTime: 30_000,
    poll: 60_000,
    invalidatesOnWrite: [],
    why: "Matches Buzz's channels cadence (features/channels/hooks.ts:58-60, 60 s poll / 5 min focus stale). /handoff does NOT read open cases from here — it reads the daemon, because a case channel whose TTL refresh silently failed can archive under an active investigation.",
  },
  laneTopics: {
    staleTime: 300_000,
    poll: false,
    invalidatesOnWrite: [],
    why: "Twelve fixed channels whose topic is rewritten only on an escalation-level transition, bounded by deescalation_cooldown_secs: 300. Live numbers come from 26001, not from here.",
  },
  ledger: {
    staleTime: Number.POSITIVE_INFINITY,
    poll: false,
    invalidatesOnWrite: [],
    why: "A NIP-50 search result for one submitted query string. Re-running it silently would change the result set under a reader mid-export.",
  },
  snoozes: {
    staleTime: 60_000,
    poll: false,
    invalidatesOnWrite: [],
    why: "kind:30300 is NIP-44-encrypted to self with no p tag, so a due snooze can never arrive through the needs-action path; the client computes due times from this list on a local ticker.",
  },
  watchClaim: {
    staleTime: 30_000,
    poll: false,
    invalidatesOnWrite: [],
    why: "The topic of a standing ops channel; a change arrives as a kind:40099 system row on that channel's subscription, which invalidates this key.",
  },
  admittedIssuers: {
    staleTime: 300_000,
    poll: false,
    invalidatesOnWrite: [],
    why: "The set every marker parse and every 26xxx frame is checked against (INV-15). Long stale time on purpose: it must be reference-stable or it defeats the memo on every evidence card. Invalidated by an explicit admission change, never by a timer.",
  },
  spoolHealth: {
    staleTime: 5_000,
    poll: 10_000,
    invalidatesOnWrite: [],
    why: "Feeds the governance strip's `bridge: shedding` state. Polled because a stalled bridge produces no events to trigger a refetch — the absence IS the signal.",
  },
  reconcileDivergences: {
    staleTime: Number.POSITIVE_INFINITY,
    poll: false,
    invalidatesOnWrite: [],
    why: "A counter written by the reconciler, read by the strip. Never fetched.",
  },
} as const satisfies Record<keyof typeof perchKeys, PerchFreshness>;

/**
 * Queries that must NEVER retry. A retried governance read against a
 * partitioned daemon is a lie with a delay attached; the operator needs the
 * refusal, not a second attempt. Applied per-hook, because Buzz's client-wide
 * default is `retry: 1` (BUZZ desktop/src/shared/api/queryClient.ts:28).
 */
export const PERCH_NO_RETRY = { retry: 0 } as const;
