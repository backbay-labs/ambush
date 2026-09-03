// Target path in BUZZ: desktop/src/features/perch/colonyScopedRegistry.ts
//
// 14-CLIENT-ARCHITECTURE.md's commitment puts this file in `features/perch/`,
// NOT in a seventh `features/colony/`, and keeps `07`'s name
// `resetColonyState()` over the brief's `resetPerchState`. This file is the
// registry it names; 14 owns the reset ORCHESTRATION (sequential await, the
// conditionals-inside-resetters rule) and this owns the TABLE.
//
// WHY IT SHIPS WITH ITS TEST
//   The review found `perchResetterRegistry.test.mjs` importing
//   `./perchResetterRegistry.ts` from an artifact set that did not contain it:
//   `node --test` exited ERR_MODULE_NOT_FOUND. A test whose subject is missing
//   is not a weaker test, it is no test.
//
// THE GUARANTEE IS THE TYPE, NOT THIS FILE
//   `Record<ColonyScopedSingleton, () => void>` is exhaustive: a union member
//   with no resetter fails `tsc --noEmit`, which already runs on every pre-push
//   (BUZZ CLAUDE.md), and an extra key fails too. That catches a DECLARED
//   singleton with no resetter. It cannot catch a singleton nobody declared,
//   which is what the sibling test's filesystem sweep is for, and which is why
//   that sweep prints its own limits in its failure message.
//
// WHY IT MATTERS MORE HERE THAN IN A CHAT APP
//   React key-remounting (`<AppReady key={communityKey} />`, BUZZ
//   desktop/src/app/App.tsx) clears React state only; module-level values
//   survive. In Buzz a missed reset is a stale channel list. In Perch it is one
//   colony's holds, findings and host ids rendered under another colony's name
//   -- a disclosure, not a cache bug.
//
// STATUS: PROPOSED. None of the fifteen new stores exists in block/buzz at
// eed74bde2; 14-CLIENT-ARCHITECTURE.md commits their NAMES and reset semantics
// and nothing else. The bodies below are deliberately the smallest thing that
// satisfies "callable and idempotent" so the registry can be landed before the
// stores are, and each carries the store it will delegate to.

/**
 * The closed union. 14-CLIENT-ARCHITECTURE.md commits a 27-member
 * `ColonyScopedSingleton`: 12 of Buzz's 21 resetters survive the deletion
 * programme, 9 go with their deleted subsystem, and 15 are new. Only the 15 new
 * ones are named here -- the 12 survivors keep their existing Buzz names and
 * their existing reset functions, and re-listing them would be a second copy of
 * `resetCommunityState`'s inventory, which is the drift this registry exists to
 * end.
 *
 * ADDING A MEMBER IS A ONE-LINE DIFF THAT FAILS `tsc` UNTIL ITS RESETTER EXISTS.
 * That is the whole mechanism.
 */
export type ColonyScopedSingleton =
  | "perchHoldCache"
  | "perchLaneWindows"
  | "perchEphemeralStore"
  | "perchSubscriptionManager"
  | "perchIssuerSeqHighWater"
  | "perchAdmittedIssuers"
  | "perchContainmentClock"
  | "perchDerivedMarkerLog"
  | "perchQueueReconcileCounters"
  | "perchDroppedFrameCounters"
  | "perchCaseChannelIndex"
  | "perchVerdictWriteStates"
  | "perchDaemonHealth"
  | "perchExportManifestDraft"
  | "perchKeymapScopeStack";

/**
 * Every entry must be callable twice with no error: a resetter that throws on a
 * second call turns a double community switch into an error state, and a double
 * switch is what an operator does when the first one looked wrong.
 *
 * Conditionals go INSIDE a resetter, never on a registry entry
 * (14-CLIENT-ARCHITECTURE.md). A conditional entry makes the `Record<>`
 * non-exhaustive at exactly the moment the condition is false, which is the one
 * moment nobody tests.
 */
export const RESETTERS: Record<ColonyScopedSingleton, () => void> = {
  // Holds fetched from GET /v1/response/holds, keyed by hold_id. Colony-scoped
  // by construction: a hold id is meaningless in another colony.
  perchHoldCache: () => {},
  // Per-lane time windows for the twelve concentration curves.
  perchLaneWindows: () => {},
  // The 26xxx last-wins store. Never enters the React Query cache
  // (14-CLIENT-ARCHITECTURE.md); a stale frame from the previous colony would
  // render as this colony's current governance state.
  perchEphemeralStore: () => {},
  // Open REQ subscriptions. Seven maximum, ever.
  perchSubscriptionManager: () => {},
  // (colony, issuer) -> highest seq seen. A seq below the high-water mark is not
  // a gap; carrying the mark across colonies would invent gaps or hide them.
  perchIssuerSeqHighWater: () => {},
  // The admitted bridge identities. Carrying these across colonies is the
  // sharpest disclosure in the list: it would admit another colony's issuer.
  perchAdmittedIssuers: () => {},
  // The single board-level 1 Hz clock (PERCH_CONTAINMENT_CLOCK_HZ).
  perchContainmentClock: () => {},
  // Which rendered values carried a DerivedMarker, for the export's DERIVED.json.
  perchDerivedMarkerLog: () => {},
  // perch_queue_reconcile_divergences_total and its per-case breakdown.
  perchQueueReconcileCounters: () => {},
  // Unadmitted-frame and unadmitted-marker drop counts. These RENDER
  // (14-CLIENT-ARCHITECTURE.md), so a carried-over count is a visible lie.
  perchDroppedFrameCounters: () => {},
  // case_id -> channel UUID. They are the same value, but the index is built
  // from this colony's channel list.
  perchCaseChannelIndex: () => {},
  // hold_id -> sending/recorded/acknowledged. INV-33's four-phase union.
  perchVerdictWriteStates: () => {},
  // Last daemon reachability probe and its timestamp.
  perchDaemonHealth: () => {},
  // A partially built Ledger export bundle. Colony-scoped and, if carried,
  // would put one colony's holds/ directory in another colony's export.
  perchExportManifestDraft: () => {},
  // The Escape-surface acquire stack. A leaked acquire disables
  // Escape-to-mark-read for the whole session (17-COMPONENT-SPECS.md).
  perchKeymapScopeStack: () => {},
};
