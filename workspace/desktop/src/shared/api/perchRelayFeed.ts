// The relay's needs-action feed, read WITHOUT importing `features/home`.
//
// A perch feature that imported the home feature would inherit its hooks, its
// polling cadence and its notion of what an unread row is — none of which is
// perch's. This wrapper is deliberately thin: it reads the same Tauri command
// through the same converter and hands back the typed response, so there is
// one raw→camel mapping in the app and it is not this one.
//
// The feed is a DELIVERY RECORD, never an authority (perchKeys' `needsAction`
// row says why): `build_needs_action_query` has no status join, so a hold that
// was decided an hour ago is still in it. `reconcileHoldQueue` is what removes
// those, against the daemon.

import { useQuery } from "@tanstack/react-query";

import { PERCH_FRESHNESS, PERCH_NO_RETRY, perchKeys } from "./perchKeys";
import { getHomeFeed } from "./tauri";
import type { HomeFeedResponse } from "./types";

/** How much history the queue asks for. `0` means the relay's own default. */
const PERCH_FEED_SINCE = 0;

/**
 * The relay feed behind `perchKeys.needsAction()`.
 *
 * `retry: 0` for the reason every perch read carries it: a retried governance
 * read against a partitioned relay is a lie with a delay attached, and the
 * operator needs the refusal rather than a second attempt.
 */
export function usePerchRelayFeed() {
  return useQuery<HomeFeedResponse>({
    queryKey: perchKeys.needsAction(),
    queryFn: () => getHomeFeed({ since: PERCH_FEED_SINCE }),
    staleTime: PERCH_FRESHNESS.needsAction.staleTime,
    ...PERCH_NO_RETRY,
  });
}
