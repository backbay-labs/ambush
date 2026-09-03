// PROPOSED — lands at BUZZ desktop/src/app/useCommunityDestinationRestore.ts
//
// Commit AS-2 of 15-FILE-SPLIT-PLAN.md. Pure extraction: the effect body below
// is AppShell.tsx:277-324 at eed74bde2, verbatim, comments included. The only
// change is that `hasRestoredCommunityDestinationRef` and the effect move
// together into this file, and the five closure values arrive as arguments.

import * as React from "react";
import {
  consumePendingCommunityRestore,
  loadCommunityDestination,
  saveCommunityDestination,
} from "@/features/communities/communityNavigationStorage";
import type { AppView } from "@/app/AppShell.helpers";
import type { Channel } from "@/shared/api/types";

/**
 * Restores the channel a community was last viewed on, exactly once per mount,
 * and only for an explicit community transition.
 */
export function useCommunityDestinationRestore({
  activeCommunityId,
  channelsQuery,
  goChannel,
  goHome,
  selectedView,
  sidebarChannels,
}: {
  activeCommunityId: string | undefined;
  channelsQuery: { dataUpdatedAt: number; isSuccess: boolean };
  goChannel: (
    channelId: string,
    options?: { replace?: boolean },
  ) => Promise<unknown>;
  goHome: (options?: { replace?: boolean }) => Promise<unknown>;
  selectedView: AppView;
  sidebarChannels: ReadonlyArray<Channel>;
}) {
  const hasRestoredCommunityDestinationRef = React.useRef(false);
  React.useEffect(() => {
    const activeCommunityId = activeCommunityId;
    if (
      hasRestoredCommunityDestinationRef.current ||
      !channelsQuery.isSuccess ||
      channelsQuery.dataUpdatedAt === 0 ||
      !activeCommunityId
    ) {
      return;
    }
    hasRestoredCommunityDestinationRef.current = true;

    // Restoration belongs to an explicit community transition. Cold boot and
    // reconnect remounts must preserve the route the user explicitly opened.
    if (!consumePendingCommunityRestore(activeCommunityId)) {
      return;
    }

    const destination = loadCommunityDestination(activeCommunityId);
    if (!destination || destination.kind === "home") {
      return;
    }

    const channelIsAvailable = sidebarChannels.some(
      (channel) => channel.id === destination.channelId,
    );
    if (!channelIsAvailable) {
      saveCommunityDestination(activeCommunityId, { kind: "home" });
      void goHome({ replace: true });
      return;
    }

    // The normal switch path writes the remembered channel into the hash before
    // the target community mounts, so no intermediate Inbox frame is painted.
    // Older transition callers may still arrive at neutral Home; repair those.
    if (selectedView === "home") {
      void goChannel(destination.channelId, { replace: true });
    }
  }, [
    channelsQuery.dataUpdatedAt,
    channelsQuery.isSuccess,
    activeCommunityId,
    goChannel,
    goHome,
    selectedView,
    sidebarChannels,
  ]);
}
