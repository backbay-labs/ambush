// The HOLDS queue: the daemon's list, the relay's notices, and the honest
// state when the two cannot be compared.
//
// Three things drive a re-read of the daemon, and none of them is a poll:
// mount, a drained `26006` alarm, and every relay reconnect edge. A poll would
// hide a dead alarm path rather than surface it — the whole point of layer 3
// is that the console notices when the delivery path has stopped working.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import * as React from "react";

import { useAdmittedIssuerSet } from "@/features/perch-evidence/lib/admittedIssuers";
import { useHoldAlarmRefetch } from "@/shared/api/perchHoldAlarm";
import {
  PERCH_FRESHNESS,
  PERCH_NO_RETRY,
  perchKeys,
} from "@/shared/api/perchKeys";
import { usePerchRelayFeed } from "@/shared/api/perchRelayFeed";
import { perchListHolds } from "@/shared/api/tauriPerch";
import { useRelayConnection } from "@/shared/api/useRelayConnection";

import {
  reconcileHoldQueue,
  type HoldQueueReconciliation,
} from "./lib/holdRows";
import { addReconcileDivergences } from "./lib/reconcileCounters";

/**
 * How the console is doing at knowing what the daemon holds.
 *
 * `not-configured` and `daemon-unreachable` are separate states because the
 * operator's next action differs: one is a setting, the other is an incident.
 */
export type HoldQueueStatus =
  | "loading"
  | "ready"
  | "daemon-unreachable"
  | "not-configured";

export type HoldQueueResult = {
  data: HoldQueueReconciliation | null;
  status: HoldQueueStatus;
  error: string | null;
  /** True only when BOTH sides answered. Drives `data-perch-queue-reconciled`. */
  reconciled: boolean;
};

/** The Tauri command's phrasing when neither keyring key nor env var is set. */
const NOT_CONFIGURED = "daemon not configured";

export function useHoldQueue(): HoldQueueResult {
  useHoldAlarmRefetch();
  const queryClient = useQueryClient();
  const connection = useRelayConnection();
  // Reference-stable until the daemon's identities answer replaces it, so it
  // is a sound memo dependency and a changed admission recomputes the queue.
  const admitted = useAdmittedIssuerSet();
  const feed = usePerchRelayFeed();
  const holds = useQuery({
    queryKey: perchKeys.holds(),
    queryFn: perchListHolds,
    staleTime: PERCH_FRESHNESS.holds.staleTime,
    ...PERCH_NO_RETRY,
  });

  // Re-read the daemon on every relay reconnect edge. A reconnect means the
  // console was away, and away is exactly when an ephemeral alarm was missed.
  const previousConnection = React.useRef(connection);
  React.useEffect(() => {
    if (
      previousConnection.current !== "connected" &&
      connection === "connected"
    ) {
      void queryClient.invalidateQueries({ queryKey: perchKeys.holds() });
    }
    previousConnection.current = connection;
  }, [connection, queryClient]);

  const notices = feed.data?.feed.needsAction;
  const data = React.useMemo(() => {
    if (!holds.data) return null;
    return reconcileHoldQueue({
      daemon: holds.data,
      relayNotices: notices ?? [],
      admitted,
      nowMs: Date.now(),
    });
    // The admitted set loads asynchronously, after the first render. Without
    // it as a dependency every notice would stay counted unadmitted forever.
  }, [holds.data, notices, admitted]);

  // Counted in an effect, not in the memo: a memo may run twice under
  // StrictMode and a governance number that double-counts on a re-render is
  // worse than no number.
  const countedRef = React.useRef(0);
  React.useEffect(() => {
    if (!data) return;
    addReconcileDivergences(data.divergences - countedRef.current);
    countedRef.current = data.divergences;
  }, [data]);

  const errorText = holds.error ? String(holds.error) : null;
  const status: HoldQueueStatus = holds.isPending
    ? "loading"
    : errorText
      ? errorText.includes(NOT_CONFIGURED)
        ? "not-configured"
        : "daemon-unreachable"
      : "ready";

  return {
    data,
    status,
    error: errorText,
    reconciled: status === "ready" && !feed.isPending && !feed.isError,
  };
}
