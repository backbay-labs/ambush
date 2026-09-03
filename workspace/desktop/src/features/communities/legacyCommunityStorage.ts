import { invokeTauri } from "@/shared/api/tauri";
import { getStorageItem } from "@/shared/lib/safeStorage";
import { migrateLegacyCommunityStorage } from "./communityStorage";

const AMBUSH_COMMUNITIES_KEY = "ambush-communities";
const AMBUSH_ACTIVE_COMMUNITY_KEY = "ambush-active-community-id";
const AMBUSH_ONBOARDING_COMPLETION_STORAGE_KEY_PREFIX =
  "ambush-onboarding-complete.v1:";
const LOCAL_DEV_RELAY_URLS = new Set([
  "ws://localhost:3000",
  "ws://127.0.0.1:3000",
]);

type LegacyCommunityStorageSnapshot = {
  workspaces: string | null;
  activeWorkspaceId: string | null;
  onboardingCompletions: Array<{
    pubkey: string;
    value: string;
  }>;
};

type StoredCommunity = {
  relayUrl?: unknown;
};

function parseCommunityList(raw: string | null): StoredCommunity[] | null {
  if (!raw) {
    return null;
  }

  try {
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as StoredCommunity[]) : null;
  } catch {
    return null;
  }
}

function normalizeRelayUrl(relayUrl: string) {
  return relayUrl.trim().replace(/\/$/, "");
}

function hasOnlyLocalDevCommunity(raw: string | null): boolean {
  const communities = parseCommunityList(raw);
  return (
    communities?.length === 1 &&
    typeof communities[0]?.relayUrl === "string" &&
    LOCAL_DEV_RELAY_URLS.has(normalizeRelayUrl(communities[0].relayUrl))
  );
}

function hasNonLocalCurrentCommunities(raw: string | null): boolean {
  const communities = parseCommunityList(raw);
  return (
    communities !== null &&
    communities.length > 0 &&
    !hasOnlyLocalDevCommunity(raw)
  );
}

function shouldWriteLegacyCommunities({
  currentCommunitiesRaw,
  legacyCommunitiesRaw,
}: {
  currentCommunitiesRaw: string | null;
  legacyCommunitiesRaw: string | null;
}) {
  const legacyCommunities = parseCommunityList(legacyCommunitiesRaw);
  if (!legacyCommunities || legacyCommunities.length === 0) {
    return false;
  }

  return !hasNonLocalCurrentCommunities(currentCommunitiesRaw);
}

export function applyLegacyCommunityStorage(
  legacyStorage: LegacyCommunityStorageSnapshot,
  storage: Storage = window.localStorage,
): void {
  const currentCommunitiesRaw = storage.getItem(AMBUSH_COMMUNITIES_KEY);
  const shouldWriteCommunities = shouldWriteLegacyCommunities({
    currentCommunitiesRaw,
    legacyCommunitiesRaw: legacyStorage.workspaces,
  });

  if (shouldWriteCommunities && legacyStorage.workspaces) {
    storage.setItem(AMBUSH_COMMUNITIES_KEY, legacyStorage.workspaces);
  }

  const currentActiveCommunityId = storage.getItem(AMBUSH_ACTIVE_COMMUNITY_KEY);
  if (
    legacyStorage.activeWorkspaceId &&
    (!currentActiveCommunityId || shouldWriteCommunities)
  ) {
    storage.setItem(
      AMBUSH_ACTIVE_COMMUNITY_KEY,
      legacyStorage.activeWorkspaceId,
    );
  }

  for (const completion of legacyStorage.onboardingCompletions) {
    const key = `${AMBUSH_ONBOARDING_COMPLETION_STORAGE_KEY_PREFIX}${completion.pubkey}`;
    if (storage.getItem(key) === null) {
      storage.setItem(key, completion.value);
    }
  }
}

/**
 * Seed Ambush localStorage from legacy Sprout WebKit localStorage before the app
 * renders providers that read community state. The native command reads the old
 * app identifier's WebKit SQLite database; this frontend step writes only when
 * Ambush does not already have community state, except for the known broken
 * Sprout→Ambush first-run handoff that created a single localhost community.
 */
export async function migrateLegacyCommunityStorageBeforeRender(): Promise<void> {
  if (typeof window === "undefined") {
    return;
  }

  migrateLegacyCommunityStorage(window.localStorage);
  // block/ambush#5078 — read through the throw-safe accessor so a denied-storage
  // origin degrades to "no community state" instead of crashing pre-render.
  const currentCommunitiesRaw = getStorageItem(AMBUSH_COMMUNITIES_KEY);
  const hasCurrentActiveCommunity = getStorageItem(AMBUSH_ACTIVE_COMMUNITY_KEY);
  if (
    currentCommunitiesRaw &&
    hasCurrentActiveCommunity &&
    !hasOnlyLocalDevCommunity(currentCommunitiesRaw)
  ) {
    return;
  }

  try {
    applyLegacyCommunityStorage(
      await invokeTauri<LegacyCommunityStorageSnapshot>(
        "get_legacy_workspace_storage",
      ),
    );
  } catch (error) {
    console.warn("Failed to read legacy Sprout community storage.", error);
  }
}
