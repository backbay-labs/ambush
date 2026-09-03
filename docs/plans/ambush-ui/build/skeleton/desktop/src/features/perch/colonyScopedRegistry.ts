// Target path in BUZZ: desktop/src/features/perch/colonyScopedRegistry.ts  (NEW file)
//
// Replaces `resetCommunityState` — 21 hand-written calls in one function at
// BUZZ desktop/src/features/communities/useCommunityInit.ts:54-84 (body
// :59-83), read line by line this session: three of the 21 sit behind two
// conditionals (`clearTrayAgentActivity` behind isTauri() && isMacPlatform();
// `resetAvatarProfileSync` and `resetAvatarPresentations` behind the
// `resetAvatarState` argument), exactly one is awaited
// (`resetNavigationDeepLinkDrain`), and the whole function is skipped on first
// mount (hasInitializedRef at :143/:249/:283). It runs in the renderer from
// one useEffect, at :149 (leaving a community) and :260-266 (switching), and a
// throw renders an explicit error state rather than proceeding.
//
// The mechanism it lacks is a type. React key-remount (App.tsx:407 builds
// `communityKey`; :630 and :640 apply it) clears React state only — module
// level Maps, class instances and cached promises survive. For Buzz a missed
// reset is a stale cache. For Perch, colonies are separate monitored estates:
// a missed reset renders one colony's security findings under another
// colony's name. That is the whole reason this file is typed.
//
// Gate-line budget: 1000 (src/features is governed). Targets ~200.

// ---------------------------------------------------------------------------
// §1 The union. Adding a member without a resetter is a compile error;
//    an extra key is a compile error. No lint rule, no review checklist.
// ---------------------------------------------------------------------------

export type ColonyScopedSingleton =
  // --- inherited from Buzz, still colony-scoped in Perch ------------------
  | "relayClient"
  | "rateLimitGate"
  | "deepLinkDrain"
  | "drafts"
  | "mediaCaches"
  | "markdownNodeCache"
  | "messageLinkMetadataCache"
  | "searchHitEventCache"
  | "sidebarRelayConnectionCard"
  | "renderScopedReactions"
  | "backgroundMediaUploads"
  | "trayActivity"
  // --- new in Perch --------------------------------------------------------
  | "perchSubscriptions"
  | "perchSeqTracking"
  | "perchEphemeralStore"
  | "holdListMirror"
  | "reviewStateMirror"
  | "containmentClock"
  | "depositSuppressionCache"
  | "admittedIssuerSet"
  | "verdictDraftStore"
  | "verdictSpool"
  | "snoozeTicker"
  | "keymapArmingState"
  | "escapeSurfaceLease"
  | "reconcileDivergenceCounter"
  | "derivedMarkerLedger";

// ---------------------------------------------------------------------------
// §2 The registry. `Record<Union, …>` is the exhaustiveness mechanism.
// ---------------------------------------------------------------------------

type Resetter = () => void | Promise<void>;

export const COLONY_RESETTERS: Record<ColonyScopedSingleton, Resetter> = {
  // --- inherited -----------------------------------------------------------
  relayClient: () => relayClient.disconnect(),
  rateLimitGate: resetRateLimitGate,
  deepLinkDrain: resetNavigationDeepLinkDrain, // the one genuinely async entry
  drafts: clearAllDrafts,
  mediaCaches: resetMediaCaches,
  markdownNodeCache: clearMarkdownNodeCache,
  messageLinkMetadataCache: resetMessageLinkMetadataCache,
  searchHitEventCache: clearSearchHitEventCache,
  sidebarRelayConnectionCard: resetSidebarRelayConnectionCardState,
  renderScopedReactions: resetRenderScopedReactionHydration,
  backgroundMediaUploads: resetBackgroundMediaUploads,
  // Buzz guards this on `isTauri() && isMacPlatform()` at useCommunityInit.ts:66.
  // Perch moves the guard INSIDE the resetter so the registry has no
  // conditional entries — a conditional entry is an entry a reader can talk
  // themselves out of.
  trayActivity: () => {
    if (isTauri() && isMacPlatform()) void clearTrayAgentActivity();
  },

  // --- new in Perch --------------------------------------------------------
  perchSubscriptions: resetPerchSubscriptions,
  perchSeqTracking: resetPerchSeqTracking,
  perchEphemeralStore: resetPerchEphemeralStore,
  holdListMirror: resetHoldListMirror,
  reviewStateMirror: resetReviewStateMirror,
  containmentClock: resetContainmentClock,
  depositSuppressionCache: resetDepositSuppressionCache,
  admittedIssuerSet: resetAdmittedIssuerSet,
  verdictDraftStore: resetVerdictDraftStore,
  verdictSpool: resetVerdictSpool,
  snoozeTicker: resetSnoozeTicker,
  keymapArmingState: resetKeymapArmingState,
  escapeSurfaceLease: releasePerchEscapeSurface,
  reconcileDivergenceCounter: resetReconcileDivergenceCounter,
  derivedMarkerLedger: resetDerivedMarkerLedger,
};

/**
 * Called from the same place Buzz calls `resetCommunityState` — inside
 * useCommunityInit's single useEffect, before `applyCommunity`, at
 * useCommunityInit.ts:149 and :260-266.
 *
 * Sequential, not Promise.all: `relayClient.disconnect()` must land before the
 * subscription manager tears its REQs down, or the CLOSE frames race a dead
 * socket and log noise that looks like a bug.
 */
export async function resetColonyState(): Promise<void> {
  for (const reset of Object.values(COLONY_RESETTERS)) {
    await reset();
  }
}

// ---------------------------------------------------------------------------
// §3 What this registry deliberately does NOT cover
// ---------------------------------------------------------------------------
//
// Buzz's own doc comment (useCommunityInit.ts:47-53) records that
// hook-managed singletons — ChannelMuteSyncManager, ChannelSectionSyncManager —
// are destroyed by effect cleanup and need no entry. Perch inherits that limit
// verbatim and the paired test must NOT claim otherwise: anything colony-scoped
// living inside a hook is fenced by the `key={colonyKey}` remount boundary and
// by nothing else.
//
// Two Buzz entries are absent because their subsystem is deleted
// (00-BRIEF.md §5.4), not because they were forgotten:
//   resetAgentObserverStore / resetActiveAgentTurnsStore / resetAgentWorkingSignal
//     — the ACP subprocess harness goes; Ambush's AgentRole is a closed
//       eight-variant in-process enum with no subprocesses to observe.
//   resetAvatarProfileSync / resetAvatarPresentations
//     — animated avatars go, and with them the storage.googleapis.com model
//       fetch that INV-30's CSP pin would otherwise pin in place.
//   resetLinkPreviewMetadataCache / resetLinkPreviewPreparations
//     — remote link-preview fetching goes; egress from an analyst workstation
//       is a threat-model question.
//   resetVideoPlayerState — video review goes with huddle.
// Twelve of Buzz's twenty-one survive. Deleting a subsystem WITHOUT deleting
// its registry entry is a compile error here, which is the point: the registry
// is also the delete checklist.

// --- placeholder imports, so the skeleton reads standalone -----------------
declare const relayClient: { disconnect(): void };
declare function resetRateLimitGate(): void;
declare function resetNavigationDeepLinkDrain(): Promise<void>;
declare function clearAllDrafts(): void;
declare function resetMediaCaches(): void;
declare function clearMarkdownNodeCache(): void;
declare function resetMessageLinkMetadataCache(): void;
declare function clearSearchHitEventCache(): void;
declare function resetSidebarRelayConnectionCardState(): void;
declare function resetRenderScopedReactionHydration(): void;
declare function resetBackgroundMediaUploads(): void;
declare function clearTrayAgentActivity(): Promise<void>;
declare function isTauri(): boolean;
declare function isMacPlatform(): boolean;
declare function resetPerchSubscriptions(): Promise<void>;
declare function resetPerchSeqTracking(): void;
declare function resetPerchEphemeralStore(): void;
declare function resetHoldListMirror(): void;
declare function resetReviewStateMirror(): void;
declare function resetContainmentClock(): void;
declare function resetDepositSuppressionCache(): void;
declare function resetAdmittedIssuerSet(): void;
declare function resetVerdictDraftStore(): void;
declare function resetVerdictSpool(): void;
declare function resetSnoozeTicker(): void;
declare function resetKeymapArmingState(): void;
declare function releasePerchEscapeSurface(): void;
declare function resetReconcileDivergenceCounter(): void;
declare function resetDerivedMarkerLedger(): void;
