import { useQuery } from "@tanstack/react-query";

import { perchKeys } from "@/shared/api/perchKeys";

import type { WatchClaim } from "./lib/watchClaim";

/**
 * The watch claim, as the console reads it.
 *
 * THIS IS THE DECISION SEAM. Where the claim is recorded is an open owner
 * decision (a standing topic on the ops channel, a NIP-33 addressable event,
 * or a daemon field). Until it is ruled, this returns `null` — which is the
 * "no claim" state, and the *safe* one: no claim pages everyone.
 *
 * The source plugs in here and nowhere else. Every consumer already reads the
 * claim through this hook, so the decision costs one `queryFn`.
 */
export function useWatchClaim() {
  return useQuery<WatchClaim | null>({
    queryKey: perchKeys.watchClaim(),
    queryFn: async () => null,
    staleTime: Number.POSITIVE_INFINITY,
  });
}

/** True while the claim's record has no decided source. */
export const WATCH_CLAIM_SOURCE_DECIDED = false;
