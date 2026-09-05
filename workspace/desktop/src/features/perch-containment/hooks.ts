// The containment board's reads and its one write.
//
// The daemon and the relay fail INDEPENDENTLY here: the relay can be up while
// the daemon is unreachable, and that is exactly the state in which this board
// must keep rendering rows while refusing to offer release.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  PERCH_FRESHNESS,
  PERCH_NO_RETRY,
  perchKeys,
} from "@/shared/api/perchKeys";
import {
  perchListContainments,
  perchReleaseContainment,
} from "@/shared/api/tauriPerch";

import {
  parseContainmentList,
  parseReleaseOutcome,
  type ContainmentList,
  type ReleaseOutcome,
} from "./lib/containmentList";

/**
 * The open containment leases.
 *
 * Polled while the daemon answers and stopped while it does not: a poll
 * against an unreachable daemon produces a stream of identical failures and
 * tells an operator nothing the first one did not.
 */
export function useContainmentsQuery() {
  return useQuery<ContainmentList>({
    queryKey: perchKeys.containments(),
    queryFn: async () => parseContainmentList(await perchListContainments()),
    staleTime: PERCH_FRESHNESS.containments.staleTime,
    refetchInterval: PERCH_FRESHNESS.containments.poll,
    ...PERCH_NO_RETRY,
  });
}

/**
 * Ask the daemon to release one containment early.
 *
 * The list is invalidated on SETTLE rather than on success, because a release
 * whose inverse failed still answers 200 and still changes what the daemon
 * will report next.
 */
export function useReleaseContainment() {
  const queryClient = useQueryClient();
  return useMutation<ReleaseOutcome, Error, string>({
    mutationFn: async (leaseId) =>
      parseReleaseOutcome(await perchReleaseContainment(leaseId)),
    onSettled: () => {
      void queryClient.invalidateQueries({
        queryKey: perchKeys.containments(),
      });
    },
  });
}
