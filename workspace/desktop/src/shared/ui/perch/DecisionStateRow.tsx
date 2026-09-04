import { cn } from "@/shared/lib/cn";

/**
 * A HOLD decision's two-legged write, as distinct states with no undo
 * (INV-33, INV-28).
 *
 * Distinct from `WriteStateRow`, which renders the same two legs inline on a
 * FINDING card. They are not one component with a variant: a finding verdict
 * has four phases and a retry control, and a hold decision has nine phases,
 * no retry, and outcomes — superseded, refused late — that a finding verdict
 * has no equivalent of. Collapsing them would put the union of both state
 * machines behind one prop and let a hold render a phase it cannot reach.
 *
 * Every governance write renders `sending → recorded → acknowledged` or one of
 * the four ways it can end otherwise, and each is its own state rather than a
 * spinner that resolves into a toast. A LATE REFUSAL IS AN OUTCOME, NOT AN
 * ERROR: the operator's decision was recorded, the daemon re-derived policy at
 * the decision instant, and the answer was no. Rendering that as a failed
 * request would tell the operator to retry something that already happened.
 *
 * There is no undo control anywhere in this file, and a test counts
 * `perch-decision-undo` nodes at zero. A recorded decision is a signed event on
 * a relay and, once granted, a lease the daemon minted; nothing this console
 * can render takes any of that back.
 */
export type DecisionWriteState =
  | { phase: "idle" }
  | { phase: "sending" }
  | { phase: "recorded"; atMs: number }
  | { phase: "daemon-dispatched"; atMs: number; receiptId: string | null }
  | { phase: "daemon-refused"; ruleName: string; reason: string }
  | { phase: "refused-late"; ruleName: string; reason: string }
  | { phase: "refused-late-governance"; reason: string }
  | { phase: "daemon-unreachable"; reason: string }
  | {
      phase: "superseded";
      winningIntentEventId: string;
      /**
       * `unknown` when the daemon named a winner it could not classify. The
       * console does not guess which way another operator decided.
       */
      winningDecision: "grant" | "refuse" | "unknown";
      decidedAtMs: number;
    };

/** The six values `data-perch-decision-state` can take. */
export type PerchDecisionState =
  | "sending"
  | "recorded"
  | "acknowledged"
  | "refused_late"
  | "superseded"
  | "unreachable";

function decisionState(state: DecisionWriteState): PerchDecisionState | null {
  switch (state.phase) {
    case "idle":
      return null;
    case "sending":
      return "sending";
    case "recorded":
      return "recorded";
    case "daemon-dispatched":
      return "acknowledged";
    case "daemon-refused":
    case "refused-late":
    case "refused-late-governance":
      return "refused_late";
    case "daemon-unreachable":
      return "unreachable";
    case "superseded":
      return "superseded";
  }
}

function formatTime(atMs: number): string {
  return new Date(atMs).toLocaleTimeString();
}

export function DecisionStateRow({ state }: { state: DecisionWriteState }) {
  const decision = decisionState(state);
  if (state.phase === "idle" || decision === null) return null;
  // A refusal is announced; progress is not. A screen reader that interrupted
  // on every step would make the two indistinguishable.
  const isRefusal = decision === "refused_late";
  return (
    <div
      data-testid={`perch-write-state-${state.phase}`}
      data-perch-decision-state={decision}
      role={isRefusal ? "alert" : "status"}
      className={cn(
        "flex flex-col gap-0.5 border-l-4 px-3 py-2 text-xs",
        "bg-[hsl(var(--perch-card))] text-[hsl(var(--perch-foreground))]",
        isRefusal
          ? "border-[hsl(var(--perch-foreground))]"
          : "border-[hsl(var(--perch-border-strong))]",
      )}
    >
      <DecisionStateBody state={state} />
    </div>
  );
}

function DecisionStateBody({ state }: { state: DecisionWriteState }) {
  switch (state.phase) {
    case "idle":
      return null;
    case "sending":
      return <span>Signing your decision and publishing it to the case…</span>;
    case "recorded":
      return (
        <>
          <span>
            Recorded on the case at {formatTime(state.atMs)}. Asking the daemon
            to act on it.
          </span>
          <span className="text-[hsl(var(--perch-foreground-muted))]">
            The decision exists whatever the daemon answers next.
          </span>
        </>
      );
    case "daemon-dispatched":
      return (
        <>
          <span>The daemon acted on it at {formatTime(state.atMs)}.</span>
          <span className="text-[hsl(var(--perch-foreground-muted))]">
            {state.receiptId === null
              ? "No response receipt was minted."
              : `Response receipt ${state.receiptId}.`}
          </span>
        </>
      );
    case "daemon-refused":
    case "refused-late":
      return (
        <>
          <span>
            The daemon refused after your decision was recorded. The action was
            never taken.
          </span>
          <span
            data-testid="perch-write-state-refusal-rule"
            className="font-mono text-[hsl(var(--perch-foreground-muted))]"
          >
            {state.ruleName}: {state.reason}
          </span>
        </>
      );
    case "refused-late-governance":
      return (
        <>
          <span>
            Governance refused after your decision was recorded. The action was
            never taken.
          </span>
          <span className="font-mono text-[hsl(var(--perch-foreground-muted))]">
            {state.reason}
          </span>
        </>
      );
    case "daemon-unreachable":
      return (
        <>
          <span>
            Your decision is recorded on the case. The daemon did not answer, so
            this console cannot say whether it ran.
          </span>
          <span className="font-mono text-[hsl(var(--perch-foreground-muted))]">
            {state.reason}
          </span>
        </>
      );
    case "superseded":
      return (
        <>
          <span>
            {state.winningDecision === "unknown"
              ? "Another operator's decision was the one that ran"
              : `Another operator's decision was the one that ran: ${state.winningDecision}`}{" "}
            at {formatTime(state.decidedAtMs)}. Your decision is recorded on
            this case and did not run.
          </span>
          <span
            data-testid="perch-write-state-superseded-winner"
            className="truncate font-mono text-[hsl(var(--perch-foreground-muted))]"
          >
            {state.winningIntentEventId}
          </span>
        </>
      );
  }
}
