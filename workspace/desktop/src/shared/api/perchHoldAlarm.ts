// The 26006 hold alarm, and the re-read it is only ever a nudge toward.
//
// Layer 3 of the hold path (APPENDIX-NORMATIVE.md §4): the daemon's
// `GET /v1/response/holds` is the authority for what a hold IS, the relay's
// 46010 notice is the delivery record, and the 26006 alarm is a hint that
// something changed. This file is the whole of the alarm's authority: it can
// cause a re-read and it can cause nothing else. A row never appears because
// an alarm said so.
//
// The alarm is p-gated and GLOBAL (R-1): the relay CLOSEs a REQ for kind 26006
// that does not carry `#p` equal to the reader, so a console is delivered only
// the alarms it is addressed by. That is a delivery guarantee, not a
// completeness one — an operator who was disconnected when the alarm fired
// never receives it, and ephemerals are not replayed — which is why the hold
// list is also re-read on connect and on every relay reconnect edge.

import { useQueryClient } from "@tanstack/react-query";
import * as React from "react";

import {
  drainPerchAlarms,
  getPerchEphemeralServerSnapshot,
  getPerchEphemeralSnapshot,
  subscribePerchEphemeral,
  type PerchAlarmBody,
} from "./perchEphemeralStore";
import { perchKeys } from "./perchKeys";

const NO_ALARMS: readonly PerchAlarmBody[] = Object.freeze([]);

/**
 * The distinct hold ids named by a batch of drained alarms, in the order they
 * were first seen.
 *
 * A `Set`, so several alarms for one hold collapse into one re-read: the
 * daemon's answer is the same either way and the second request would only
 * cost the operator latency. An alarm with no usable `hold_id` names no hold
 * and contributes nothing — the frame is still evidence the bridge is alive,
 * which the caller decides what to do with.
 */
export function holdIdsToRefetch(
  alarms: readonly PerchAlarmBody[],
): ReadonlySet<string> {
  const ids = new Set<string>();
  for (const alarm of alarms) {
    const id = alarm.hold_id;
    if (typeof id === "string" && id.length > 0) ids.add(id);
  }
  return ids;
}

const readAlarms = (): readonly PerchAlarmBody[] =>
  getPerchEphemeralSnapshot().alarms;
const readServerAlarms = (): readonly PerchAlarmBody[] =>
  getPerchEphemeralServerSnapshot().alarms ?? NO_ALARMS;

/**
 * Drain every queued 26006 and invalidate the daemon hold list.
 *
 * Mount ONCE, at The Watch. Draining is destructive — a second mounted copy
 * would race this one for the same frames and each would see half of them —
 * and there is nothing to gain from a second: the invalidation is global to
 * the query cache, so one drainer serves every surface that reads holds.
 *
 * It invalidates rather than merges. The alarm's payload carries a severity
 * and an action kind, and rendering a row from them would be presenting a
 * relay-supplied claim as a hold; the only honest response to an alarm is to
 * go and ask the daemon.
 */
export function useHoldAlarmRefetch(): void {
  const queryClient = useQueryClient();
  const alarms = React.useSyncExternalStore(
    subscribePerchEphemeral,
    readAlarms,
    readServerAlarms,
  );
  React.useEffect(() => {
    if (alarms.length === 0) return;
    const drained = drainPerchAlarms();
    if (drained.length === 0) return;
    void queryClient.invalidateQueries({ queryKey: perchKeys.holds() });
  }, [alarms, queryClient]);
}
