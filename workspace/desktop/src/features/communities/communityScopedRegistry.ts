import { clearSearchHitEventCache } from "@/app/navigation/searchHitEventCache";
import { resetActiveAgentTurnsStore } from "@/features/agents/activeAgentTurnsStore";
import { resetAgentWorkingSignal } from "@/features/agents/agentWorkingSignal";
import { resetAgentObserverStore } from "@/features/agents/observerRelayStore";
import { resetBackgroundMediaUploads } from "@/features/messages/lib/backgroundMediaUploadStore";
import { resetLinkPreviewPreparations } from "@/features/messages/lib/linkPreviewPreparationStore";
import { resetPersistentAgentAudienceStore } from "@/features/messages/lib/persistentAgentAudience";
import { resetRenderScopedReactionHydration } from "@/features/messages/lib/renderScopedReactions";
import { clearAllDrafts } from "@/features/messages/lib/useDrafts";
import { resetAvatarPresentations } from "@/features/profile/avatarPresentationStore";
import { resetAvatarProfileSync } from "@/features/profile/avatarProfileSync";
import { resetSidebarRelayConnectionCardState } from "@/features/sidebar/ui/useSidebarRelayConnectionCard";
import { relayClient } from "@/shared/api/relayClient";
import { resetRateLimitGate } from "@/shared/api/relayRateLimitGate";
import { clearTrayAgentActivity } from "@/shared/api/trayMenu";
import { resetNavigationDeepLinkDrain } from "@/shared/deep-link";
import { resetMediaCaches } from "@/shared/lib/mediaUrl";
import { resetLinkPreviewMetadataCache } from "@/shared/lib/useResolvedLinkPreviews";
import { clearMarkdownNodeCache } from "@/shared/ui/markdown/nodeCache";
import { resetMessageLinkMetadataCache } from "@/shared/ui/markdown/useMessageLinkMetadata";
import { resetVideoPlayerState } from "@/shared/ui/videoPlayerState";

/**
 * The canonical inventory of module-level singletons that hold
 * community-scoped data, in the order they are torn down on a community
 * switch.
 *
 * React key-based remounting only clears React state; module-level Maps,
 * class instances, and cached promises survive it. Every such singleton
 * must appear here **and** in {@link RESETTERS} — the `Record` type makes a
 * missing or extra resetter a compile error, and
 * `communityScopedRegistry.test.mjs` checks the two agree at runtime.
 * Hook-managed singletons (e.g. `ChannelMuteSyncManager`,
 * `ChannelSectionSyncManager`) are destroyed via effect cleanup and do not
 * need entries. See CLAUDE.md "Community Switching" for the full contract.
 *
 * Order matters: the relay is disconnected first so nothing can re-populate
 * a store while it is being cleared, and the deep-link drain is awaited
 * before any later store is reset.
 */
export const COMMUNITY_SCOPED_SINGLETONS = [
  "relayClient",
  "navigationDeepLinkDrain",
  "rateLimitGate",
  "drafts",
  "agentObserverStore",
  "activeAgentTurnsStore",
  "agentWorkingSignal",
  "trayAgentActivity",
  "avatarProfileSync",
  "avatarPresentations",
  "sidebarRelayConnectionCard",
  "mediaCaches",
  "linkPreviewMetadataCache",
  "videoPlayerState",
  "renderScopedReactionHydration",
  "backgroundMediaUploads",
  "linkPreviewPreparations",
  "persistentAgentAudienceStore",
  "searchHitEventCache",
  "markdownNodeCache",
  "messageLinkMetadataCache",
] as const;

/** The name of one community-scoped singleton in {@link COMMUNITY_SCOPED_SINGLETONS}. */
export type CommunityScopedSingleton =
  (typeof COMMUNITY_SCOPED_SINGLETONS)[number];

/**
 * What a community switch knows about the boundary being crossed.
 *
 * - `resetAvatarState`: true when the relay or the signing identity changed,
 *   so deferred avatar work queued for the old boundary must be discarded.
 *   A same-relay, same-identity reconnect keeps it.
 * - `isMacTauri`: true only inside the native macOS shell, the one place a
 *   tray menu exists to clear.
 */
export type ResetContext = {
  resetAvatarState: boolean;
  isMacTauri: boolean;
};

/**
 * Tears down one singleton. Synchronous resetters return `void`; a resetter
 * that must finish before the next one starts returns a promise, and
 * {@link runResetters} awaits it.
 */
export type Resetter = (ctx: ResetContext) => void | Promise<void>;

/** Resetters that only run when the avatar boundary moved. */
const AVATAR_ONLY: ReadonlySet<CommunityScopedSingleton> =
  new Set<CommunityScopedSingleton>([
    "avatarProfileSync",
    "avatarPresentations",
  ]);

/** Resetters that only run inside the native macOS shell. */
const MAC_TAURI_ONLY: ReadonlySet<CommunityScopedSingleton> =
  new Set<CommunityScopedSingleton>(["trayAgentActivity"]);

/**
 * One resetter per named singleton. Adding a singleton without a resetter,
 * or a resetter without a singleton, is a type error here and a failing
 * exhaustiveness test.
 */
export const RESETTERS: Record<CommunityScopedSingleton, Resetter> = {
  relayClient: () => relayClient.disconnect(),
  navigationDeepLinkDrain: () => resetNavigationDeepLinkDrain(),
  rateLimitGate: () => resetRateLimitGate(),
  drafts: () => clearAllDrafts(),
  agentObserverStore: () => resetAgentObserverStore(),
  activeAgentTurnsStore: () => resetActiveAgentTurnsStore(),
  agentWorkingSignal: () => resetAgentWorkingSignal(),
  // Fire-and-forget: the tray clear is an IPC round trip whose result the
  // switch never needed to wait for.
  trayAgentActivity: () => {
    void clearTrayAgentActivity();
  },
  avatarProfileSync: () => resetAvatarProfileSync(),
  avatarPresentations: () => resetAvatarPresentations(),
  sidebarRelayConnectionCard: () => resetSidebarRelayConnectionCardState(),
  mediaCaches: () => resetMediaCaches(),
  linkPreviewMetadataCache: () => resetLinkPreviewMetadataCache(),
  videoPlayerState: () => resetVideoPlayerState(),
  renderScopedReactionHydration: () => resetRenderScopedReactionHydration(),
  backgroundMediaUploads: () => resetBackgroundMediaUploads(),
  linkPreviewPreparations: () => resetLinkPreviewPreparations(),
  persistentAgentAudienceStore: () => resetPersistentAgentAudienceStore(),
  searchHitEventCache: () => clearSearchHitEventCache(),
  markdownNodeCache: () => clearMarkdownNodeCache(),
  messageLinkMetadataCache: () => resetMessageLinkMetadataCache(),
};

/**
 * Runs every applicable resetter in {@link COMMUNITY_SCOPED_SINGLETONS}
 * order, one at a time, awaiting each before starting the next. Avatar
 * resetters are skipped unless `ctx.resetAvatarState`; the tray resetter is
 * skipped unless `ctx.isMacTauri`. The first rejection aborts the run and
 * propagates, so a caller can refuse to render the new community on top of
 * a half-cleared one.
 *
 * `resetters` defaults to {@link RESETTERS}; tests inject fakes to observe
 * ordering without touching the real singletons.
 */
export async function runResetters(
  ctx: ResetContext,
  resetters: Record<CommunityScopedSingleton, Resetter> = RESETTERS,
): Promise<void> {
  for (const key of COMMUNITY_SCOPED_SINGLETONS) {
    if (AVATAR_ONLY.has(key) && !ctx.resetAvatarState) continue;
    if (MAC_TAURI_ONLY.has(key) && !ctx.isMacTauri) continue;
    await resetters[key](ctx);
  }
}
