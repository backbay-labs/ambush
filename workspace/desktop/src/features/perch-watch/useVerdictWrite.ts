import { useQueryClient } from "@tanstack/react-query";
import * as React from "react";

import { perchKeys } from "@/shared/api/perchKeys";
import {
  perchDecideHold,
  perchPublishVerdictUpdate,
  perchRecordHoldVerdict,
  type PerchDetachedSignature,
  type PerchHoldVerdict,
} from "@/shared/api/tauriPerch";
import { useRelayConnection } from "@/shared/api/useRelayConnection";
import type { DecisionWriteState } from "@/shared/ui/perch/DecisionStateRow";

import { verdictWriteReducer } from "./lib/verdictWrite";
import {
  clearSpooledLeg2,
  spoolLeg2,
  spooledLeg2Entries,
} from "./lib/verdictSpool";

/**
 * Drives one hold's decision through both legs, and never optimistically.
 *
 * Leg 1 publishes the operator's signed intent to the relay. Only when the
 * relay accepts it does leg 2 POST to the daemon. The order is the whole
 * design: a decision that reached the daemon without a signed record on the
 * case would be an act with no evidence of who asked for it, and the reverse —
 * a record with no daemon call — is recoverable, which is what the spool is for.
 *
 * On `superseded` this publishes the update card so the losing leg-1 card,
 * which is genuine and permanent, reads as superseded to anyone who finds it
 * later. It does not retry and does not re-sign.
 */
export type VerdictWriteResult = {
  state: DecisionWriteState;
  record: (
    decision: PerchHoldVerdict,
    rationale: string | null,
    armedAtMs: number | null,
  ) => Promise<void>;
};

/** The transport-failure prefix the Tauri client produces. */
const UNREACHABLE_PREFIX = "daemon unreachable";

export function useVerdictWrite(holdId: string): VerdictWriteResult {
  const queryClient = useQueryClient();
  const connection = useRelayConnection();
  const [state, dispatch] = React.useReducer(verdictWriteReducer, {
    phase: "idle",
  } as DecisionWriteState);

  // A new hold is a new write. Without this the previous hold's terminal state
  // would render against the new one's Verdict Row.
  // biome-ignore lint/correctness/useExhaustiveDependencies: hold_id is the identity that resets the machine.
  React.useEffect(() => {
    dispatch({ type: "reset" });
  }, [holdId]);

  const invalidate = React.useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: perchKeys.holds() });
    void queryClient.invalidateQueries({ queryKey: perchKeys.hold(holdId) });
    void queryClient.invalidateQueries({ queryKey: perchKeys.needsAction() });
  }, [queryClient, holdId]);

  /** Leg 2 only. Never re-signs; the intent id is already minted. */
  const sendLeg2 = React.useCallback(
    async (
      decision: PerchHoldVerdict,
      nostrIntentEventId: string,
      decidedAtMs: number,
      signature: PerchDetachedSignature,
      rationale: string | null,
      armedAtMs: number | null,
    ) => {
      try {
        const outcome = await perchDecideHold({
          holdId,
          decision,
          nostrIntentEventId,
          decidedAtMs,
          signature,
          rationale,
          armedAtMs,
        });
        clearSpooledLeg2(holdId);
        dispatch({ type: "leg2-ok", outcome });
        if (outcome.outcome === "superseded" && outcome.superseded_by) {
          // The losing card is signed and permanent. Saying so on the case is
          // the only way a later reader can tell which of two genuine verdicts
          // ran, without asking the daemon themselves.
          await perchPublishVerdictUpdate({
            holdId,
            ownIntentEventId: nostrIntentEventId,
            supersededBy: outcome.superseded_by,
            supersededAtMs: Date.now(),
          }).catch((error) => {
            console.warn("[perch] the supersession update failed", error);
          });
        }
        invalidate();
      } catch (error) {
        const reason = String(error);
        if (reason.includes(UNREACHABLE_PREFIX)) {
          // Held, not lost: the decision is already on the relay, and a hold
          // the daemon never heard about would sit open while the operator
          // believes they answered.
          spoolLeg2({
            holdId,
            decision,
            nostrIntentEventId,
            decidedAtMs,
            signature,
            rationale,
            armedAtMs,
            firstAttemptAtMs: Date.now(),
          });
          dispatch({ type: "leg2-unreachable", reason });
          return;
        }
        dispatch({ type: "leg2-rejected", reason });
      }
    },
    [holdId, invalidate],
  );

  const record = React.useCallback(
    async (
      decision: PerchHoldVerdict,
      rationale: string | null,
      armedAtMs: number | null,
    ) => {
      dispatch({ type: "start" });
      let leg1: Awaited<ReturnType<typeof perchRecordHoldVerdict>>;
      try {
        leg1 = await perchRecordHoldVerdict({ holdId, decision, rationale });
      } catch (error) {
        dispatch({ type: "leg1-failed", reason: String(error) });
        return;
      }
      dispatch({
        type: "leg1-ok",
        atMs: leg1.decided_at_ms,
        intentEventId: leg1.nostr_intent_event_id,
      });
      await sendLeg2(
        decision,
        leg1.nostr_intent_event_id,
        leg1.decided_at_ms,
        leg1.signature,
        rationale,
        armedAtMs,
      );
    },
    [holdId, sendLeg2],
  );

  // Drain the spool on every relay reconnect edge. Re-sends LEG 2 only, with
  // the intent id leg 1 already minted, so a duplicate delivery replays the
  // daemon's record rather than deciding a second time.
  const previousConnection = React.useRef(connection);
  React.useEffect(() => {
    const reconnected =
      previousConnection.current !== "connected" && connection === "connected";
    previousConnection.current = connection;
    if (!reconnected) return;
    for (const entry of spooledLeg2Entries()) {
      if (entry.holdId !== holdId) continue;
      void sendLeg2(
        entry.decision,
        entry.nostrIntentEventId,
        entry.decidedAtMs,
        entry.signature,
        entry.rationale,
        entry.armedAtMs,
      );
    }
  }, [connection, holdId, sendLeg2]);

  return { state, record };
}
