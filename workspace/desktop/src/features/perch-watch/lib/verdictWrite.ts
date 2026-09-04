// The two-legged write.
//
// Leg 1 is a signed card on the relay. Leg 2 is a POST to the daemon. They are
// separate facts and the machine below never collapses them: `recorded` means
// the relay accepted the operator's signed intent, and it is true whatever the
// daemon says next. Every terminal state is reachable ONLY from `recorded`, so
// there is no path by which the console reports an outcome for a decision that
// was never written down.
//
// A LATE REFUSAL IS AN OUTCOME. The daemon re-derives policy and governance at
// the decision instant (ADR 0014), so a recorded decision can still be refused,
// and rendering that as a failed request would tell the operator to retry
// something that already happened.
//
// Nothing here retries and nothing re-signs. A retry re-sends LEG 2 with the
// same `nostr_intent_event_id`, which is the daemon's idempotency key; re-signing
// leg 1 would mint a second signed intent for one decision and leave two cards
// on the case claiming to be the same act.

import type { PerchDecideOutcome } from "@/shared/api/tauriPerch";
import type { DecisionWriteState } from "@/shared/ui/perch/DecisionStateRow";

export type VerdictWriteEvent =
  /** A new hold is a new write. The only way back to `idle`. */
  | { type: "reset" }
  | { type: "start" }
  | { type: "leg1-ok"; atMs: number; intentEventId: string }
  | { type: "leg1-failed"; reason: string }
  | { type: "leg2-ok"; outcome: PerchDecideOutcome }
  | { type: "leg2-unreachable"; reason: string }
  | { type: "leg2-rejected"; reason: string };

export function verdictWriteReducer(
  state: DecisionWriteState,
  event: VerdictWriteEvent,
): DecisionWriteState {
  switch (event.type) {
    case "reset":
      // Deliberately unconditional: the previous hold's terminal state must not
      // render against the next hold's Verdict Row, and there is nothing to
      // preserve — the decision it described is on the relay, not in here.
      return { phase: "idle" };

    case "start":
      // Only from idle. A second start while a write is in flight would let a
      // double-press mint a second signature for one decision.
      return state.phase === "idle" ? { phase: "sending" } : state;

    case "leg1-ok":
      return state.phase === "sending"
        ? { phase: "recorded", atMs: event.atMs }
        : state;

    case "leg1-failed":
      // Nothing was written, so nothing needs an outcome. The operator is told
      // the intent never landed rather than that the daemon refused.
      return {
        phase: "daemon-unreachable",
        reason: `the intent card could not be published: ${event.reason}`,
      };

    case "leg2-unreachable":
      return state.phase === "recorded"
        ? { phase: "daemon-unreachable", reason: event.reason }
        : state;

    case "leg2-rejected":
      return state.phase === "recorded"
        ? {
            phase: "daemon-refused",
            ruleName: "request_rejected",
            reason: event.reason,
          }
        : state;

    case "leg2-ok": {
      if (state.phase !== "recorded") return state;
      const result = event.outcome;
      switch (result.outcome) {
        case "dispatched":
          return {
            phase: "daemon-dispatched",
            atMs: result.decided_at_ms,
            receiptId: result.receipt_id,
          };
        case "refused_late":
          return {
            phase: "refused-late",
            ruleName: result.rule ?? "unknown",
            reason: result.reason ?? "",
          };
        case "refused_late_governance":
          return {
            phase: "refused-late-governance",
            reason: `${result.rule ?? ""}: ${result.reason ?? ""}`,
          };
        case "superseded":
          return {
            phase: "superseded",
            winningIntentEventId: result.superseded_by ?? "",
            // From a TYPED field, which the Tauri command fills by RE-READING
            // `GET /v1/response/holds/{id}` after a 409 (W3-17) — never by
            // searching the daemon's free-text reason, which would flip the
            // sentence on a reason like "they did not refuse; they granted it".
            winningDecision: result.winning_decision ?? "unknown",
            decidedAtMs: result.decided_at_ms,
          };
        case "expired":
          return {
            phase: "daemon-refused",
            ruleName: "hold_expired",
            reason:
              "the hold expired before the decision arrived; the action was never taken",
          };
        case "unknown_hold":
          return {
            phase: "daemon-refused",
            ruleName: "unknown_hold",
            reason: "the daemon has no record of this hold",
          };
      }
    }
  }
}
