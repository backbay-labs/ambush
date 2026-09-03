import * as React from "react";
import { useLocation } from "@tanstack/react-router";

import { derivePerchShellRoute } from "@/app/perchViews";
import { usePerchSubscriptionsMount } from "@/shared/api/perchLaneMovement";
import { useFeatureEnabled } from "@/shared/features/useFeatureEnabled";

/**
 * Where a swarm card is being rendered, and whether the perch feature is on.
 *
 * `surface` decides which cards are at home (a finding card belongs in a
 * case or a lane; a hold card in a case only) and `caseChannelId` is what a
 * card's `h` tag is checked against on a case surface.
 */
export type SwarmCardSurface = {
  enabled: boolean;
  surface: "case" | "lane" | "other";
  caseChannelId: string | null;
};

const Ctx = React.createContext<Omit<SwarmCardSurface, "enabled"> | null>(null);

/**
 * Pins the surface for everything rendered below it. The `/cases/$caseId`
 * route mounts one around its channel screen; lane channels have no provider
 * and derive their surface from the router location instead.
 */
export function SwarmCardSurfaceProvider({
  surface,
  caseChannelId,
  children,
}: {
  surface: "case" | "lane";
  caseChannelId: string | null;
  children: React.ReactNode;
}) {
  const value = React.useMemo(
    () => ({ surface, caseChannelId }),
    [surface, caseChannelId],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/**
 * The surface a swarm card is rendered on. Without a provider the surface is
 * derived from the router location (`/cases/` is a case, `/channels/` a
 * lane, anything else other) and `enabled` from the `perch` preview feature,
 * so the `MessageBody` seam works in lane channels with no provider and
 * `MessageRow`'s parents are untouched.
 *
 * The returned object is memoised per input so the memoised timeline rows
 * above the seam are not defeated by a fresh identity every render
 * (CLAUDE.md gotcha 6).
 */
export function useSwarmCardSurface(): SwarmCardSurface {
  const enabled = useFeatureEnabled("perch");
  // Any rendered swarm card surface keeps the perch REQ set open; the mount
  // is refcounted, so a timeline of rows is one REQ set.
  usePerchSubscriptionsMount(enabled);
  const provided = React.useContext(Ctx);
  const pathname = useLocation({ select: (l) => l.pathname });
  return React.useMemo<SwarmCardSurface>(() => {
    if (provided) return { enabled, ...provided };
    const route = derivePerchShellRoute(pathname);
    if (route.selectedView === "case") {
      return { enabled, surface: "case", caseChannelId: route.selectedCaseId };
    }
    return {
      enabled,
      surface: pathname.startsWith("/channels/") ? "lane" : "other",
      caseChannelId: null,
    };
  }, [enabled, provided, pathname]);
}
