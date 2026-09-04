import { Button } from "@/shared/ui/button";
import type { DecisionWriteState } from "@/shared/ui/perch/DecisionStateRow";

/**
 * Refuse. One keypress, no dialog, no dwell, no undo.
 *
 * The asymmetry with the grant is the design, not an oversight. A refusal
 * dispatches nothing: the held action is not taken, no capability lease is
 * minted, no containment lease reaches the board. There is nothing an operator
 * needs to have understood before refusing is safe, so putting a gate in front
 * of it would only make the safe answer the slower one — and a console that
 * makes refusing slower than granting is a console that nudges toward granting.
 *
 * `R` is the key, through `usePerchKeymap`. `D` is never offered on a hold: it
 * means Dismiss on a finding, dismissal retroactively removes pheromone
 * deposits, and holds and findings interleave in the same queue.
 */
export type RefuseControlProps = {
  writeState: DecisionWriteState;
  selectionCount: number;
  onRefuse: () => void;
};

export function RefuseControl({
  writeState,
  selectionCount,
  onRefuse,
}: RefuseControlProps) {
  if (selectionCount !== 1 || writeState.phase === "superseded") return null;
  const disabled = writeState.phase !== "idle";
  return (
    <div data-perch-role="refuse" className="flex items-center gap-3">
      <Button
        type="button"
        variant="verdict"
        aria-disabled={disabled}
        data-testid="perch-refuse-record"
        onClick={() => {
          if (!disabled) onRefuse();
        }}
      >
        Refuse
      </Button>
      <span className="text-xs text-[hsl(var(--perch-foreground-muted))]">
        R · nothing is dispatched, and there is no undo
      </span>
    </div>
  );
}
